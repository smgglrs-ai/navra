+++
title = "14. Post-Quantum Readiness"
description = "Why quantum computers threaten Ed25519, what NIST standardized as replacements, and how navra's algorithm-agile design makes the transition a config change."
weight = 140
template = "docs/page.html"

[extra]
part = "crypto"
toc = true
+++

## What you already know

From the previous three chapters, you know that navra's security model rests on Ed25519 digital signatures. Every capability token is signed with Ed25519. Every agent identity is an Ed25519 public key encoded as a `did:key`. The delegation chain, the revocation system, the audit trail — all of it depends on one assumption: that Ed25519 signatures cannot be forged.

That assumption is safe today. It may not be safe in ten years.

## Why quantum computers are a threat

Ed25519 is based on the elliptic curve discrete logarithm problem: given a public key (a point on a curve) and a base point, find the private key (the scalar multiplier). On a classical computer, this requires roughly 2^128 operations — far beyond what's feasible.

In 1994, Peter Shor published a quantum algorithm that solves this class of problem in polynomial time. A quantum computer with enough stable qubits could:

1. Take any Ed25519 public key (which is embedded in every `did:key`).
2. Compute the corresponding private key.
3. Forge signatures on arbitrary capability tokens.

This breaks everything: token authenticity, delegation chain integrity, identity verification.

### The timeline

Nobody has built a quantum computer large enough to break Ed25519 yet. Current machines have hundreds of noisy qubits; breaking Ed25519 requires thousands of error-corrected logical qubits. Estimates for when this becomes feasible range from 2030 to 2045, depending on whom you ask.

But cryptographic migrations take years. NIST began its post-quantum standardization process in 2016 and published final standards in 2024. Organizations that wait until quantum computers exist will be too late — "harvest now, decrypt later" attacks mean that data signed today with breakable algorithms could be forged retroactively.

navra doesn't need to switch algorithms today. But it needs to be *ready* to switch without rewriting the codebase.

## What NIST standardized

In August 2024, NIST published three post-quantum cryptography standards:

- **ML-KEM** (FIPS 203) — key encapsulation (for encryption). Not relevant to navra's signature use case.
- **ML-DSA** (FIPS 204) — digital signatures, based on lattice problems. Formerly known as Dilithium. This is the primary replacement for Ed25519 in signature applications.
- **SLH-DSA** (FIPS 205) — digital signatures, based on hash functions. Larger signatures but relies on simpler assumptions.

For navra, ML-DSA is the most relevant. It provides the same sign/verify operations as Ed25519, with security based on the hardness of module lattice problems — which no known quantum algorithm can solve efficiently.

### The size problem

ML-DSA works, but its signatures and keys are much larger than Ed25519:

| Property | Ed25519 | ML-DSA-65 (security level 3) |
|----------|---------|------------------------------|
| Public key | 32 bytes | 1,952 bytes |
| Signature | 64 bytes | 3,309 bytes |
| Private key | 32 bytes | 4,032 bytes |

A navra capability token with Ed25519 fits in under 500 bytes. With ML-DSA-65, the signature alone is 3,309 bytes — the token would be 4,000+ bytes.

For tokens traveling over local Unix domain sockets between processes on the same machine, this is manageable. For tokens embedded in HTTP headers to upstream MCP servers, it's less comfortable. The trade-off is real, but security wins over compactness when the alternative is forgeable tokens.

## Algorithm agility: the CapSigner trait

navra's answer to the migration problem is the `CapSigner` trait from Chapter 10:

```rust
pub trait CapSigner: Send + Sync {
    fn algorithm(&self) -> &str;
    fn did(&self) -> &str;
    fn sign(&self, payload: &[u8]) -> Vec<u8>;
    fn verify(&self, payload: &[u8], sig: &[u8]) -> bool;
    fn public_key_bytes(&self) -> Vec<u8>;
}
```

Today, `Ed25519Signer` implements this trait. A future `MlDsaSigner` would implement the same four methods:

```rust
pub struct MlDsaSigner {
    signing_key: ml_dsa::SigningKey,
    verifying_key: ml_dsa::VerifyingKey,
    did: String,
}

impl CapSigner for MlDsaSigner {
    fn algorithm(&self) -> &str { "ml-dsa-65" }

    fn did(&self) -> &str { &self.did }

    fn sign(&self, payload: &[u8]) -> Vec<u8> {
        self.signing_key.sign(payload).to_bytes().to_vec()
    }

    fn verify(&self, payload: &[u8], sig: &[u8]) -> bool {
        // parse sig bytes, verify with verifying_key
        // ...
    }

    fn public_key_bytes(&self) -> Vec<u8> {
        self.verifying_key.to_bytes().to_vec()
    }
}
```

The capability token code — `encode_token`, `decode_token`, `validate_delegation` — calls `signer.sign()` and `signer.verify()`. It never references Ed25519 directly. Swapping algorithms means changing which struct implements `CapSigner`, not rewriting the token system.

## Hybrid signing

The cleanest migration strategy isn't a hard switch from Ed25519 to ML-DSA. It's **hybrid signing**: sign with both algorithms simultaneously. A token is valid only if *both* signatures verify.

Why hybrid? Because post-quantum algorithms are new. They haven't had decades of cryptanalysis. There's a nonzero chance that a weakness is discovered in ML-DSA after deployment. Hybrid signing provides a safety net:

- If ML-DSA is broken, Ed25519 still protects the token (as long as no quantum computer exists).
- If Ed25519 is broken by a quantum computer, ML-DSA still protects the token.
- The token is secure as long as *either* algorithm holds.

A `HybridSigner` would combine both:

```rust
pub struct HybridSigner {
    ed25519: Ed25519Signer,
    ml_dsa: MlDsaSigner,
    did: String,
}

impl CapSigner for HybridSigner {
    fn algorithm(&self) -> &str { "hybrid-ed25519-ml-dsa-65" }

    fn did(&self) -> &str { &self.did }

    fn sign(&self, payload: &[u8]) -> Vec<u8> {
        let sig_ed = self.ed25519.sign(payload);
        let sig_ml = self.ml_dsa.sign(payload);
        // Concatenate with length prefix
        let mut combined = Vec::new();
        combined.extend_from_slice(&(sig_ed.len() as u32).to_le_bytes());
        combined.extend_from_slice(&sig_ed);
        combined.extend_from_slice(&sig_ml);
        combined
    }

    fn verify(&self, payload: &[u8], sig: &[u8]) -> bool {
        // Split the combined signature
        let ed_len = u32::from_le_bytes(sig[..4].try_into().unwrap()) as usize;
        let sig_ed = &sig[4..4 + ed_len];
        let sig_ml = &sig[4 + ed_len..];
        // BOTH must verify
        self.ed25519.verify(payload, sig_ed)
            && self.ml_dsa.verify(payload, sig_ml)
    }

    fn public_key_bytes(&self) -> Vec<u8> {
        // Concatenate both public keys
        let mut combined = Vec::new();
        combined.extend_from_slice(&self.ed25519.public_key_bytes());
        combined.extend_from_slice(&self.ml_dsa.public_key_bytes());
        combined
    }
}
```

The token system doesn't know or care that two algorithms are running. It calls `sign()` and gets bytes back. It calls `verify()` and gets `true` or `false`.

## DID evolution

There's a wrinkle: `did:key` embeds the multicodec prefix, which identifies the key type. Today, Ed25519 keys use the prefix `0xed01`, and every navra DID starts with `z6Mk`.

For ML-DSA keys, a different multicodec prefix would be registered. For hybrid keys, the DID would need to encode both public keys. The `did:key` specification supports this through composite key representations.

The `pubkey_from_did` function already checks the multicodec prefix:

```rust
if decoded[0] != ED25519_MULTICODEC[0] || decoded[1] != ED25519_MULTICODEC[1] {
    return Err(IdentityError::UnsupportedCodec(decoded[0], decoded[1]));
}
```

Adding ML-DSA support means adding a new codec branch, not changing the existing Ed25519 path. Old DIDs continue to work. New DIDs use the new codec. The transition is additive.

## The configuration change

With algorithm agility in place, the migration from Ed25519 to hybrid signing becomes a configuration decision:

```toml
# config.toml — today
[server]
signing_algorithm = "ed25519"

# config.toml — tomorrow
[server]
signing_algorithm = "hybrid-ed25519-ml-dsa-65"
```

The gateway reads this setting, instantiates the appropriate `CapSigner` implementation, and proceeds. Existing Ed25519-only tokens would still verify during a transition period (the gateway could accept both old and new algorithms).

No code changes to the token system. No changes to delegation validation. No changes to the audit trail. The `CapSigner` trait absorbs the complexity at the boundary.

## What navra doesn't do yet

To be clear about the current state: navra uses Ed25519 today. The ML-DSA and hybrid implementations shown above are the planned design, not shipped code. What exists today is the *infrastructure* for the transition:

- The `CapSigner` trait abstracts the algorithm.
- No code outside `identity.rs` references Ed25519 types directly.
- The multicodec prefix check in `pubkey_from_did` is already a match point for new algorithms.
- The `algorithm()` method on `CapSigner` provides runtime identification.

When NIST-compliant ML-DSA crates mature in the Rust ecosystem (several are in development), adding the new signer is a matter of implementing the trait and wiring the configuration.

## The broader lesson

Post-quantum readiness isn't about predicting when quantum computers will arrive. It's about building systems where the answer to "what if the crypto breaks?" is "we change a config option" rather than "we rewrite the security layer."

The `CapSigner` trait is a small piece of code — five methods, no complex generics, no framework. But it's the seam that makes the entire capability token system algorithm-independent. When the time comes to migrate, the trust boundary stays the same, the delegation model stays the same, the audit trail stays the same. Only the bytes that constitute a signature change.

## What's next

Part III is complete. You now understand how navra builds cryptographic identity from first principles: Ed25519 signatures (Chapter 10), self-verifying `did:key` identifiers (Chapter 11), CBOR-encoded capability tokens (Chapter 12), attenuating delegation chains (Chapter 13), and the path to post-quantum readiness (this chapter).

Part IV moves from *identity* to *protocol*: how these tokens travel over JSON-RPC, what the MCP protocol looks like on the wire, and where exactly in the request lifecycle the gateway enforces the security checks you've been reading about.
