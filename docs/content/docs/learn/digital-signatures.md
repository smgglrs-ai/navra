+++
title = "10. Digital Signatures"
description = "Ed25519 explained without the math — how signing works, why agents need cryptographic identity, and why navra chose Ed25519 over RSA."
weight = 100
template = "docs/page.html"

[extra]
part = "crypto"
toc = true
+++

## What you already know

You know that AI agents call tools — `file_read`, `git_status`, `shell_exec`. You know that a gateway sits between agents and tools, enforcing permissions. And you know from Part II that capability tokens carry those permissions.

But here's the question we haven't answered: how does the gateway know who sent a request? When an agent presents a capability token, how does the gateway know it wasn't forged, stolen, or tampered with?

The answer is digital signatures.

## The wax seal analogy

Think about a medieval wax seal. A noble presses their signet ring into hot wax on a letter. The recipient can look at the seal and know two things:

1. **The letter came from the noble** — nobody else has that ring.
2. **The letter wasn't tampered with** — breaking the seal would be obvious.

Digital signatures work the same way, but with mathematics instead of wax:

- The **private key** is the signet ring. Only the signer has it. It never leaves their possession.
- The **public key** is a picture of the seal pattern. Anyone can have a copy. Anyone can check whether a seal matches.
- The **signature** is the wax impression itself. It's unique to both the signer and the exact message.

Change one byte of the message, and the signature won't match. Use a different private key, and the signature won't match. There's no way to produce a valid signature without the private key.

## Keys come in pairs

A digital signature scheme starts with key generation. You generate a **key pair**: one private key and one public key. They are mathematically linked — the public key is derived from the private key — but you cannot reverse the process. Knowing the public key tells you nothing about the private key.

In navra, key generation looks like this:

```rust
use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;

let signing_key = SigningKey::generate(&mut OsRng);
let verifying_key = signing_key.verifying_key();
```

`OsRng` draws randomness from the operating system's cryptographically secure random number generator (`/dev/urandom` on Linux). The signing key is 32 bytes of secret randomness. The verifying key (the public key) is another 32 bytes, derived deterministically from the signing key.

The same seed always produces the same key pair:

```rust
let seed = [42u8; 32];
let signer1 = Ed25519Signer::from_seed(&seed);
let signer2 = Ed25519Signer::from_seed(&seed);
assert_eq!(signer1.did(), signer2.did()); // same identity
```

This determinism matters for persistence. navra stores the 32-byte seed (in a file with `0o600` permissions or in the OS keyring) and re-derives the full key pair on startup. The identity survives restarts.

## Sign and verify

Once you have a key pair, two operations become available:

**Signing** takes a message and the private key, and produces a signature:

```rust
let payload = b"allow file_read on /src for 1 hour";
let signature = signer.sign(payload);
// signature is 64 bytes
```

**Verification** takes the message, the signature, and the public key, and returns true or false:

```rust
let valid = signer.verify(payload, &signature);
assert!(valid);

// Tampered message fails
let valid = signer.verify(b"allow shell_exec on /", &signature);
assert!(!valid);

// Tampered signature fails
let mut bad_sig = signature.clone();
bad_sig[0] ^= 0xff;
let valid = signer.verify(payload, &bad_sig);
assert!(!valid);
```

Verification is a pure function. It doesn't need the private key. Anyone with the public key can verify. This is why the public key can be shared freely — it only enables checking, not forging.

## navra's CapSigner trait

navra doesn't hardcode Ed25519 into every function that needs signing. Instead, it defines a trait:

```rust
pub trait CapSigner: Send + Sync {
    fn algorithm(&self) -> &str;
    fn did(&self) -> &str;
    fn sign(&self, payload: &[u8]) -> Vec<u8>;
    fn verify(&self, payload: &[u8], sig: &[u8]) -> bool;
    fn public_key_bytes(&self) -> Vec<u8>;
}
```

`Ed25519Signer` implements this trait today. Tomorrow, a `HybridSigner` could implement it with both Ed25519 and a post-quantum algorithm. The capability token code doesn't change — it calls `signer.sign()` and `signer.verify()` without caring which algorithm runs underneath.

This is algorithm agility, and Chapter 14 explains why it matters.

## How navra uses signatures

When the gateway starts, it loads or generates an identity:

```rust
let signer = load_or_create_file_identity(Path::new(
    "~/.config/navra/identity.key"
));
```

This signer is used for one critical purpose: **signing capability tokens**. When a leader agent requests tokens for its teammates, the gateway:

1. Builds a `CapabilityPayload` with permissions, expiry, and a random nonce.
2. Serializes it to CBOR (compact binary format).
3. Signs the CBOR bytes with the gateway's private key.
4. Encodes the result as `navra_cap_v1.<cbor>.<signature>`.

When an agent later presents that token, the gateway:

1. Splits the token into CBOR and signature parts.
2. Verifies the signature against the CBOR bytes using its own public key.
3. If the signature is valid, deserializes the CBOR to extract permissions.
4. Checks expiry and revocation.

If any step fails — wrong signature, expired token, revoked nonce — the request is denied. No exceptions.

## The trust model

Notice who holds the private key: the **gateway**, not the agents. The gateway signs tokens and verifies them. Agents never see the signing key — they only receive signed tokens and present them back.

This means the gateway is the root of trust. If the gateway's private key is compromised, an attacker can forge tokens with arbitrary permissions. Every security property in navra ultimately depends on the gateway's key remaining secret.

This is a deliberate design choice. In a system where agents are untrusted (they execute LLM-generated code, they process untrusted input, they might be prompt-injected), the signing authority must be separate from the agents. The gateway is a small, auditable, non-LLM process — exactly the kind of component you can harden and monitor.

## Why Ed25519

navra uses Ed25519, an elliptic curve signature scheme designed by Daniel J. Bernstein. Here's why it wins over the alternatives:

**Compared to RSA:**

| Property | Ed25519 | RSA-2048 |
|----------|---------|----------|
| Signature size | 64 bytes | 256 bytes |
| Public key size | 32 bytes | 256 bytes |
| Sign speed | ~15,000/sec | ~1,000/sec |
| Verify speed | ~7,000/sec | ~35,000/sec |
| Key generation | microseconds | milliseconds |

RSA signatures are 4x larger. RSA signing is 15x slower. For a gateway that might issue hundreds of capability tokens per second, this matters.

**Compared to ECDSA (the P-256 curve used in TLS):**

Ed25519 has one critical advantage: **no padding attacks**. ECDSA requires a random nonce during signing. If that nonce is biased or reused, the private key leaks. This has caused real-world key compromises (the PlayStation 3 master key, Bitcoin wallet thefts). Ed25519 derives the nonce deterministically from the private key and message, making this class of attack impossible.

**Compared to doing nothing:**

Some systems use shared secrets (like API keys) instead of signatures. The problem: a shared secret that's shared with 10 agents can be used by any of them to impersonate any other. Digital signatures provide non-repudiation — only the holder of a specific private key can produce a valid signature for that key's public identity.

## Where the private key lives

The security of the entire system depends on the private key staying private. navra stores it in one of two places:

**File storage** (server mode): The 32-byte seed is written to `~/.config/navra/identity.key` with permissions `0o600` (owner read/write only). On startup, navra reads this file and re-derives the full key pair.

**OS keyring** (desktop mode): On systems with a Secret Service implementation (GNOME Keyring, KWallet), the seed is stored in the user's encrypted keyring via the `keyring` crate. This provides hardware-backed protection on systems that support it.

In both cases, the private key never appears in logs, never travels over the network, and never leaves the process that loaded it.

Here's the file storage path in code:

```rust
pub fn load_or_create_file_identity(path: &Path) -> Result<Ed25519Signer, IdentityError> {
    if path.exists() {
        let seed_bytes = std::fs::read(path)?;
        let seed: [u8; 32] = seed_bytes.try_into()?;
        Ok(Ed25519Signer::from_seed(&seed))
    } else {
        let signer = Ed25519Signer::generate();
        std::fs::create_dir_all(path.parent().unwrap())?;
        std::fs::write(path, signer.seed())?;
        // Restrict to owner-only on Unix
        #[cfg(unix)]
        std::fs::set_permissions(path, Permissions::from_mode(0o600))?;
        Ok(signer)
    }
}
```

The first time the gateway starts, it generates a key pair and saves the seed. Every subsequent start loads the same seed and derives the same key pair — the same DID, the same identity. This is why navra's identity survives restarts without a registration server.

## What signatures don't do

Signatures prove authenticity and integrity. They do not provide:

- **Confidentiality** — the signed data isn't encrypted. Anyone who intercepts the token can read its permissions. (This is fine for navra: tokens travel over local Unix domain sockets, not the internet.)
- **Authorization** — a valid signature proves the token came from the gateway, but the gateway still has to check whether the token grants the requested operation.
- **Freshness** — a signature doesn't expire on its own. That's why capability tokens include an `exp` field, checked separately.

Signatures are one layer. Chapters 12-13 build the rest.

## What's next

You now understand how digital signatures let the gateway stamp tokens that anyone can verify but nobody can forge. But we still need a way to identify *who* holds a key — not just "this signature matches this public key," but "this public key belongs to agent X." That's the problem of identity, and Chapter 11 shows how Decentralized Identifiers solve it without a certificate authority.
