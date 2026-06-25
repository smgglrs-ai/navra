+++
title = "11. Decentralized Identifiers"
description = "DIDs and did:key — how navra identifies agents without a central authority, and why the identifier is derived from the public key itself."
weight = 110
template = "docs/page.html"

[extra]
part = "crypto"
toc = true
+++

## What you already know

From Chapter 10, you know that every agent (and the gateway itself) has an Ed25519 key pair. The private key signs capability tokens. The public key verifies them. But a 32-byte public key is just a blob of bytes. How do you refer to an agent? How do you write "this token was issued by agent X" in a way that both humans and machines can parse?

You need an identifier — a stable name derived from the key.

## The problem with centralized identity

Consider the alternatives:

**DNS names** require a domain registrar. You can't assign `agent-reader.example.com` without owning `example.com`, paying a registrar, and running a DNS server. AI agents spawned for a 30-minute task don't need domain names.

**X.509 certificates** require a Certificate Authority. The CA signs a certificate binding a name to a public key. But CAs charge money, take time, and introduce a trust dependency — if the CA is compromised, all identities it issued are suspect. For agents that live for minutes, the overhead is absurd.

**OAuth client IDs** require an authorization server. Every agent would need to be pre-registered with an OAuth provider. This works for long-lived services, not for ephemeral agents that a leader spawns on demand.

**UUIDs** are random, so two systems can generate them independently. But a UUID has no cryptographic relationship to a key. If an agent claims to be `550e8400-e29b-41d4-a716-446655440000`, how do you verify that? You'd need a separate registry mapping UUIDs to public keys — and now you're back to a central authority.

What navra needs is an identifier that:

1. Can be generated locally, with no network call or registration.
2. Is cryptographically bound to the public key — you can verify the binding without contacting anyone.
3. Is a stable string that works in logs, configs, and token fields.

## did:key

The W3C Decentralized Identifiers (DID) specification defines a URI scheme for identifiers that don't depend on a central registry. There are many DID "methods" — `did:web` uses DNS, `did:ion` uses Bitcoin, `did:peer` uses peer exchange.

navra uses `did:key`, the simplest method. A `did:key` identifier is derived entirely from the public key. No network. No registry. No third party.

Here's a real `did:key` string from navra:

```
did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK
```

Let's break it apart:

```
did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK
|   |   | |
|   |   | └── base58-encoded bytes (multicodec prefix + public key)
|   |   └──── 'z' = multibase prefix meaning "base58btc encoding"
|   └──────── method name: this DID uses the "key" method
└──────────── scheme: this is a Decentralized Identifier
```

### The encoding pipeline

Starting from an Ed25519 public key (32 bytes), the `did:key` is built in three steps:

**Step 1: Prepend the multicodec prefix.** Multicodec is a self-describing format that identifies the type of data that follows. For Ed25519 public keys, the prefix is `0xed 0x01` (two bytes). This makes the identifier self-describing — any parser can look at the first two bytes and know this is an Ed25519 key.

```rust
const ED25519_MULTICODEC: [u8; 2] = [0xed, 0x01];

let mut bytes = Vec::with_capacity(34);  // 2 prefix + 32 key
bytes.extend_from_slice(&ED25519_MULTICODEC);
bytes.extend_from_slice(pubkey.as_bytes());
```

**Step 2: Base58btc encode.** Base58 is like Base64 but without characters that cause confusion: no `0`/`O`, no `I`/`l`, no `+`/`/`. It's the same encoding Bitcoin uses for addresses. The result is a human-readable string of alphanumeric characters.

**Step 3: Prepend the DID URI.** Add `did:key:z` (the `z` is the multibase prefix indicating base58btc).

```rust
format!("did:key:z{}", bs58::encode(&bytes).into_string())
```

In navra's code, the complete function:

```rust
pub fn did_from_pubkey(pubkey: &VerifyingKey) -> String {
    let mut bytes = Vec::with_capacity(34);
    bytes.extend_from_slice(&ED25519_MULTICODEC);
    bytes.extend_from_slice(pubkey.as_bytes());
    format!("did:key:z{}", bs58::encode(&bytes).into_string())
}
```

### The reverse: extracting a key from a DID

Given a `did:key` string, you can recover the public key:

```rust
pub fn pubkey_from_did(did: &str) -> Result<VerifyingKey, IdentityError> {
    let multibase = did.strip_prefix("did:key:z")
        .ok_or_else(|| IdentityError::InvalidDid(did.to_string()))?;

    let decoded = bs58::decode(multibase).into_vec()?;

    // Check length: 2 bytes multicodec + 32 bytes key = 34
    if decoded.len() != 34 {
        return Err(IdentityError::InvalidKeyLength {
            expected: 34, actual: decoded.len(),
        });
    }

    // Check multicodec prefix
    if decoded[0] != 0xed || decoded[1] != 0x01 {
        return Err(IdentityError::UnsupportedCodec(decoded[0], decoded[1]));
    }

    // Extract the 32-byte public key
    let key_bytes: [u8; 32] = decoded[2..34].try_into()?;
    Ok(VerifyingKey::from_bytes(&key_bytes)?)
}
```

This roundtrip is lossless. Given a DID, you can extract the public key and verify signatures directly. Given a public key, you can compute the DID. No database lookup required.

```rust
let signer = Ed25519Signer::generate();
let did = signer.did();
assert!(did.starts_with("did:key:z6Mk"));

let recovered = pubkey_from_did(did).unwrap();
assert_eq!(recovered.as_bytes(), signer.verifying_key.as_bytes());
```

The `z6Mk` prefix is not a coincidence — `6Mk` is what the multicodec bytes `0xed01` encode to in base58btc. Every Ed25519 `did:key` starts with `z6Mk`.

## Why did:key is right for agents

The `did:key` method has a specific property that makes it ideal for AI agents: **the identifier is the key, and the key is the identifier**. There's no gap between "who are you?" and "prove it."

When a capability token says `iss: "did:key:z6Mk..."`, the verifier:

1. Extracts the public key from the DID string.
2. Uses that key to verify the token's signature.
3. If the signature is valid, the issuer is authenticated.

No certificate chain. No OCSP check. No key registry lookup. The DID *is* the public key, encoded as a string.

### Comparison with other approaches

| Property | did:key | OAuth client ID | X.509 CN |
|----------|---------|-----------------|----------|
| Offline generation | Yes | No (needs registration) | No (needs CA) |
| Self-verifying | Yes | No (needs auth server) | No (needs CA cert) |
| Ephemeral-friendly | Yes | No | No |
| Human-readable | Somewhat | Yes | Yes |
| Revocation | No built-in | Yes | Yes (CRL/OCSP) |

The "no built-in revocation" row is honest: `did:key` doesn't have a revocation mechanism because the DID *is* the key. You can't revoke a public key without a registry. navra handles revocation at the token level instead — the `TokenRevocationList` tracks revoked token nonces, not revoked keys.

### Ephemeral identity for ephemeral agents

When a leader agent spawns a specialist, navra generates a fresh key pair for it:

```rust
let specialist = Ed25519Signer::generate();
// specialist.did() => "did:key:z6Mk..."
```

This takes microseconds. No network call. No registration. The specialist now has a unique, cryptographically verifiable identity that will appear in every audit log entry for the duration of its work.

When the specialist finishes and is terminated, the key pair is discarded. The DID will never be reused (the probability of generating the same 32-byte key twice is negligible — about 1 in 2^256).

## Where DIDs appear in navra

DIDs are used throughout the capability token system:

**In the token payload:**
```rust
pub struct CapabilityPayload {
    pub iss: String,  // issuer DID — who signed this token
    pub sub: String,  // subject DID — who this token is for
    // ...
}
```

**In resolved capabilities:**
```rust
pub struct ResolvedCapabilities {
    pub issuer_did: String,
    pub subject_did: String,
    // ...
}
```

**In audit logs:** every tool call is logged with the caller's DID, creating a traceable chain: "did:key:z6Mk... called file_read on /src/main.rs at 14:32:07."

**In delegation chains:** when agent A delegates to agent B, the child token's `iss` field is A's DID and the `sub` field is B's DID. The chain of DIDs tells you exactly who delegated what to whom.

## The `Ed25519Verifier` for remote keys

Sometimes navra needs to verify a signature from an agent whose private key it doesn't hold. The `Ed25519Verifier` handles this:

```rust
let verifier = Ed25519Verifier::from_did(
    "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK"
)?;

let valid = verifier.verify(payload, &signature);
```

This constructs a verifier from any DID string. It extracts the public key from the DID and uses it for verification. No shared secrets, no key exchange protocol — the DID contains everything needed.

## What DIDs don't solve

DIDs answer "who signed this?" They don't answer:

- **"Should I trust this signer?"** — that's authorization, handled by the permission system.
- **"Is this key still valid?"** — that's revocation, handled by `TokenRevocationList`.
- **"Who is the human behind this agent?"** — that's on-behalf-of identity (`obo`), covered in Chapter 12.

DIDs are the naming layer. They give every agent a verifiable address. The next chapters build the permission system on top of that address.

## What's next

You now know how navra turns a public key into a stable, self-verifying identifier. But an identifier alone doesn't grant permissions. Chapter 12 shows how capability tokens bundle an identity with specific permissions — which tools, which paths, for how long — and why navra encodes them in CBOR instead of JWT.
