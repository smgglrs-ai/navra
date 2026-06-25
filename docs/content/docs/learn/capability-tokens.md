+++
title = "12. Capability Tokens"
description = "CBOR-encoded capability tokens — structure, lifecycle, and why navra chose CBOR over JWT for compact, unambiguous security tokens."
weight = 120
template = "docs/page.html"

[extra]
part = "crypto"
toc = true
+++

## What you already know

From Chapter 10, you know that digital signatures let the gateway stamp data that anyone can verify. From Chapter 11, you know that `did:key` gives every agent a self-verifying identity. Now we combine them: a **capability token** is a signed data structure that says "agent X is allowed to do Y, until time Z."

If Part II's capability concept was the theory, this chapter is the implementation.

## What's in a token

A navra capability token is a string that looks like this:

```
navra_cap_v1.qWNjYXCkZW9wc4....<base64url>....RoYXQ.<base64url signature>
```

Three parts, dot-separated:

| Part | Content | Purpose |
|------|---------|---------|
| `navra_cap_v1` | Version prefix | Identifies the token format |
| Middle | Base64url-encoded CBOR | The payload — permissions, expiry, identity |
| Last | Base64url-encoded signature | Ed25519 signature over the CBOR bytes |

The payload, when decoded, is a `CapabilityPayload`:

```rust
pub struct CapabilityPayload {
    pub v: u8,              // version: 1
    pub iss: String,        // issuer DID (who signed this token)
    pub sub: String,        // subject DID (who this token is for)
    pub cap: CapabilitySet, // what this agent can do
    pub ring: u8,           // privilege ring (0 = most privileged)
    pub iat: u64,           // issued-at (Unix timestamp)
    pub exp: u64,           // expiry (Unix timestamp)
    pub nonce: [u8; 16],    // unique ID (prevents replay)
    pub parent: Option<[u8; 16]>,     // parent token nonce (for delegation)
    pub obo: Option<OboIdentity>,     // human identity (for audit trails)
    pub sandbox: Option<SandboxProfile>, // per-tool restrictions
    pub aud: Option<String>,          // intended server (prevents cross-server replay)
}
```

And the `CapabilitySet` spells out exactly what's allowed:

```rust
pub struct CapabilitySet {
    pub paths: Vec<String>,       // path globs: "/home/user/projects/**"
    pub operations: Vec<String>,  // operations: "read", "write", "git.status"
    pub tools: Vec<String>,       // tool globs: "file_*", "git_*"
    pub credentials: Vec<String>, // credential labels: "github.pat"
}
```

Every field serves a purpose. Paths restrict *where* an agent can operate. Operations restrict *what kinds of actions* it can perform. Tools restrict *which specific tools* it can call. Credentials restrict which stored secrets it can access. The ring determines the agent's privilege level. The expiry limits the token's lifetime.

## Creating a token

Building and signing a token is a three-step process:

**Step 1: Build the payload.**

```rust
let cap = CapabilitySet {
    paths: vec!["/home/user/projects/navra/**".to_string()],
    operations: vec!["read".to_string(), "write".to_string()],
    tools: vec!["file_*".to_string(), "git_status".to_string()],
    credentials: vec![],
};

let payload = build_payload(
    signer.did(),            // issuer: the gateway
    "did:key:z6MkSubject",   // subject: the agent
    cap,                     // what's allowed
    1,                       // ring level
    3600,                    // TTL: 1 hour
);
```

The `build_payload` helper fills in the current time for `iat`, computes `exp` from the TTL, and generates a random 16-byte nonce.

**Step 2: Serialize and sign.**

```rust
let token_string = encode_token(&payload, &signer)?;
// => "navra_cap_v1.qWNjYXCk....<cbor>....RoYXQ.<sig>"
```

Inside `encode_token`:

```rust
pub fn encode_token(
    payload: &CapabilityPayload,
    signer: &dyn CapSigner,
) -> Result<String, CapabilityError> {
    let cbor_bytes = cbor_encode(payload)?;       // serialize to CBOR
    let sig = signer.sign(&cbor_bytes);           // sign the raw bytes

    let cbor_b64 = URL_SAFE_NO_PAD.encode(&cbor_bytes);
    let sig_b64 = URL_SAFE_NO_PAD.encode(&sig);

    Ok(format!("{TOKEN_PREFIX}.{cbor_b64}.{sig_b64}"))
}
```

The signature covers the CBOR bytes, not the base64 encoding. This means the signature is computed over the canonical binary representation.

**Step 3: Hand the token string to the agent.** The agent includes it in the `Authorization` header of every request to the gateway.

## Verifying a token

When the gateway receives a request with a token, verification runs in strict order:

```rust
pub fn decode_token(
    token: &str,
    verifier: &dyn CapSigner,
) -> Result<CapabilityPayload, CapabilityError> {
    // 1. Split into parts
    let parts: Vec<&str> = token.splitn(3, '.').collect();
    if parts.len() != 3 { return Err(InvalidFormat); }
    if parts[0] != "navra_cap_v1" { return Err(InvalidFormat); }

    // 2. Decode from base64
    let cbor_bytes = URL_SAFE_NO_PAD.decode(parts[1])?;
    let sig_bytes = URL_SAFE_NO_PAD.decode(parts[2])?;

    // 3. Verify signature BEFORE deserializing
    if !verifier.verify(&cbor_bytes, &sig_bytes) {
        return Err(InvalidSignature);
    }

    // 4. Deserialize the CBOR payload
    let payload: CapabilityPayload = cbor_decode(&cbor_bytes)?;

    // 5. Check expiry
    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    if payload.exp < now {
        return Err(Expired { expired: payload.exp, now });
    }

    // 6. Check version
    if payload.v != 1 { return Err(UnsupportedVersion); }

    Ok(payload)
}
```

The order matters. Signature verification happens *before* deserialization. This means a forged or tampered token is rejected without ever parsing its contents — no risk of confused-deputy attacks from maliciously crafted payloads.

With revocation checking enabled, there's an additional step:

```rust
if let Some(rl) = revocation_list {
    if rl.is_revoked(&payload.nonce) {
        return Err(Revoked);
    }
}
```

The `TokenRevocationList` is a set of 16-byte nonces. Revoking a token adds its nonce to the set. Any future use of that token is rejected.

## Why CBOR, not JWT

JWT (JSON Web Token) is the standard choice for security tokens. navra deliberately chose CBOR (Concise Binary Object Representation) instead. Here's why:

### Size

JWTs are JSON text, base64-encoded, with a separate JSON header. A typical navra-equivalent JWT would be 1,000+ bytes. The same information in CBOR is 375-773 bytes depending on the number of permissions.

```rust
#[test]
fn cbor_is_compact() {
    let signer = Ed25519Signer::generate();
    let payload = test_payload(&signer);
    let token = encode_token(&payload, &signer).unwrap();
    assert!(token.len() < 500); // typical tokens well under 500 bytes
}
```

This matters because tokens travel with every request. In a multi-agent system where agents make hundreds of tool calls per minute, saving 500 bytes per request adds up.

### No header ambiguity

JWT has a header (`{"alg": "EdDSA", "typ": "JWT"}`) that tells the verifier which algorithm to use. This has caused a notorious class of vulnerabilities:

- **Algorithm confusion attacks**: an attacker changes the header to `"alg": "none"`, and a buggy verifier skips signature checking entirely.
- **RSA/HMAC confusion**: an attacker changes the header from `"alg": "RS256"` to `"alg": "HS256"`, causing the verifier to use the public key as an HMAC secret — which the attacker knows.

navra's tokens have no algorithm header. The token format is `navra_cap_v1`, and the verifier knows which key to use because it *is* the gateway. There's no negotiation, no algorithm field to manipulate.

### Canonical encoding

JSON has multiple valid encodings for the same data: `{"a":1,"b":2}` and `{"b":2,"a":1}` are semantically identical but produce different byte sequences, which means different signatures. JWT works around this with base64url encoding of the raw JSON, but the underlying ambiguity remains a source of implementation bugs.

CBOR with deterministic encoding (which `ciborium` provides) produces exactly one byte sequence for a given data structure. Same input, same bytes, same signature, every time.

### What JWT does better

JWT has one advantage: universality. Every programming language has JWT libraries. CBOR is less common, though well-supported in Rust via `ciborium` and `serde`. For navra, this trade-off is acceptable — tokens are produced and consumed by the gateway, not by third-party services.

## Audience validation

Tokens can optionally include an `aud` (audience) field that specifies which server they're intended for:

```rust
payload.aud = Some("https://server-a.example.com".to_string());
```

When a server receives a token with an audience claim, it must match:

```rust
let result = decode_token_with_audience(
    &token, &signer, "https://server-b.example.com"
);
// Err: audience mismatch
```

This prevents cross-server replay attacks: a token issued for server A cannot be used against server B, even if both servers share the same signing key.

## The nonce: preventing replay

Every token contains a random 16-byte nonce:

```rust
pub fn generate_nonce() -> [u8; 16] {
    let mut nonce = [0u8; 16];
    OsRng.fill_bytes(&mut nonce);
    nonce
}
```

The nonce serves two purposes:

1. **Uniqueness**: no two tokens have the same nonce, even if all other fields are identical.
2. **Revocation target**: to revoke a token, you add its nonce to the revocation list.

```rust
let rl = TokenRevocationList::new();

// Token works before revocation
assert!(decode_token_with_revocation(&token, &signer, Some(&rl)).is_ok());

// Revoke by nonce
rl.revoke(payload.nonce);

// Token rejected after revocation
assert!(decode_token_with_revocation(&token, &signer, Some(&rl)).is_err());
```

The nonce also links parent and child tokens in delegation chains, which Chapter 13 covers.

## On-behalf-of identity

Capability tokens can carry an `obo` (on-behalf-of) field that identifies the human who authorized the agent:

```rust
pub struct OboIdentity {
    pub sub: String,         // "alice@example.com"
    pub iss: String,         // "https://idp.example.com"
    pub auth_time: Option<i64>, // when the human authenticated
}
```

This human identity propagates through the entire delegation chain. If Alice authorizes a leader agent, and the leader delegates to a specialist, the specialist's token still carries `obo: alice@example.com`. Every tool call the specialist makes is attributable to Alice in the audit log.

The obo field has strict rules: it can only be set in the root token (during OAuth token exchange). Agents cannot add, change, or remove it during delegation. This is enforced by `validate_delegation`, covered in the next chapter.

## What's next

You now understand what capability tokens contain, how they're encoded, signed, verified, and revoked. But we've been looking at single tokens — one issuer, one subject. Chapter 13 shows what happens when agents delegate to other agents, creating chains of progressively narrower permissions.
