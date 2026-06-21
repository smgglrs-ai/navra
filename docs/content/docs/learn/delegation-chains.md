+++
title = "13. Delegation Chains"
description = "The core security model — how leader agents issue narrower tokens to specialists, and why each link in the chain can only attenuate, never escalate."
weight = 130
template = "docs/page.html"

[extra]
part = "crypto"
toc = true
+++

## What you already know

From Chapter 12, you know that a capability token bundles an identity (DID) with permissions (paths, operations, tools) and constraints (expiry, ring, nonce). The gateway signs it, the agent presents it, and the gateway verifies it on every request.

But so far, every token has been issued directly by the gateway to a single agent. Real multi-agent systems are more interesting. A leader agent spawns specialists, each needing their own permissions — and those permissions must be *narrower* than the leader's.

This is the delegation problem, and its solution is the core of navra's security model.

## The scenario

Alice asks her AI assistant to refactor a codebase. The assistant (the "leader") needs to:

1. Read the source code to understand the current structure.
2. Spawn a "reader" specialist to search for patterns across files.
3. Spawn a "writer" specialist to apply the refactoring changes.
4. Spawn a "reviewer" specialist to check the results.

The leader has broad permissions:

```rust
let leader_cap = CapabilitySet {
    paths: vec!["/home/alice/projects/**".to_string()],
    operations: vec![
        "read".to_string(),
        "write".to_string(),
        "git.status".to_string(),
    ],
    tools: vec!["file_*".to_string(), "git_*".to_string()],
    credentials: vec!["github.pat".to_string()],
};
```

The reader specialist only needs to read files. It should not be able to write, access git, or use credentials. The leader creates a **delegated token**:

```rust
let reader_token = build_delegated_payload(
    &leader_payload,                          // parent token
    "did:key:z6MkReaderSpecialist",          // subject DID
    vec!["read".to_string()],                // only read operations
    vec!["file_read".to_string(),            // only file_read and file_grep
         "file_grep".to_string()],
    2,                                        // ring 2 (less privileged than leader's ring 1)
    600,                                      // 10 minutes (shorter than leader's 1 hour)
)?;
```

This child token is **attenuated**: it has fewer operations, fewer tools, a higher ring number (less privilege), and a shorter lifetime than the parent.

## The attenuation invariant

The fundamental rule of delegation in navra:

**Every child token's permissions must be a subset of its parent's. Delegation can only restrict, never expand.**

This is checked by `validate_delegation`, which enforces five constraints:

### 1. Ring can only increase (less privilege)

```rust
if child_ring < parent_ring {
    return Err("ring escalation");
}
```

If the parent is ring 1, the child must be ring 1 or higher. A child at ring 0 would have *more* privilege than its parent — that's escalation, and it's rejected.

### 2. Expiry can only decrease (shorter lifetime)

```rust
if child_exp > parent_exp {
    return Err("expiry extension");
}
```

A child token cannot outlive its parent. If the leader's token expires in 1 hour, a specialist's token cannot last 2 hours. The `build_delegated_payload` helper enforces this automatically:

```rust
let effective_exp = child_exp.min(parent.exp);
```

Even if you request a 24-hour TTL, the child's expiry is capped to the parent's.

### 3. Operations must be a subset

```rust
let parent_ops: HashSet<&str> = parent.cap.operations.iter()
    .map(|s| s.as_str()).collect();
for op in &child.cap.operations {
    if !parent_ops.contains(op.as_str()) {
        return Err(CapabilityError::DelegationViolation(format!(
            "operation escalation: child has '{op}' not in parent"
        )));
    }
}
```

A parent with `["read", "write"]` can delegate `["read"]`, but not `["read", "shell.exec"]`. The `shell.exec` operation was never in the parent's grants — adding it would be escalation.

### 4. Tools must be covered by parent globs

```rust
for child_tool in &child.cap.tools {
    if !is_glob_covered_by(child_tool, &parent.cap.tools) {
        return Err("tool escalation");
    }
}
```

A parent with `["file_*", "git_*"]` can delegate `["file_read"]` (covered by `file_*`) but not `["shell_exec"]` (not covered by any parent glob).

### 5. Paths must be covered by parent globs

```rust
for child_path in &child.cap.paths {
    if !is_glob_covered_by(child_path, &parent.cap.paths) {
        return Err("path escalation");
    }
}
```

A parent with `["/home/alice/projects/**"]` can delegate `["/home/alice/projects/navra/**"]` but not `["/etc/**"]`.

## The parent nonce link

Every child token references its parent by nonce:

```rust
pub struct CapabilityPayload {
    pub nonce: [u8; 16],
    pub parent: Option<[u8; 16]>,  // parent's nonce
    // ...
}
```

The first check in `validate_delegation` confirms this link:

```rust
match child.parent {
    Some(parent_nonce) if parent_nonce == parent.nonce => { /* ok */ }
    _ => return Err("child token does not reference parent nonce"),
}
```

A child token that doesn't reference a parent, or references the wrong parent, is rejected. This prevents an attacker from presenting a legitimately-issued token as a child of a different (more privileged) parent.

## Multi-hop delegation

Delegation chains can have more than two links. If the leader delegates to specialist A, specialist A can delegate further to sub-specialist B — but B's permissions must be a subset of A's, which are already a subset of the leader's.

```
Gateway (ring 0)
  └── Leader (ring 1): read, write, file_*, git_*, /projects/**
        └── Specialist A (ring 2): read, file_*, /projects/navra/**
              └── Sub-specialist B (ring 3): read, file_read, /projects/navra/src/**
```

Each hop narrows. Sub-specialist B can only read files under `/projects/navra/src/` using `file_read`. It cannot write. It cannot use git. It cannot access files outside its narrow path.

navra's `check_attenuation` function is proven correct for transitive chains using Kani:

```rust
#[kani::proof]
fn transitive_attenuation() {
    let r0: u8 = kani::any();
    let r1: u8 = kani::any();
    let r2: u8 = kani::any();
    kani::assume(r0 <= 3 && r1 <= 3 && r2 <= 3);
    let e0: u64 = kani::any();
    let e1: u64 = kani::any();
    let e2: u64 = kani::any();
    kani::assume(e0 <= 1000 && e1 <= 1000 && e2 <= 1000);

    let parent_to_child = check_attenuation(r0, r1, e0, e1);
    let child_to_grandchild = check_attenuation(r1, r2, e1, e2);

    if parent_to_child.is_ok() && child_to_grandchild.is_ok() {
        // If A→B is valid and B→C is valid, then A→C must be valid
        assert!(check_attenuation(r0, r2, e0, e2).is_ok());
    }
}
```

Kani exhaustively verifies this over all possible ring and expiry values within the bounds. If A can legally delegate to B, and B can legally delegate to C, then A could have legally delegated directly to C. The transitive property holds for all inputs.

## Depth limits

Even though each delegation narrows permissions, unlimited chaining could create tokens that are hard to audit. navra supports a `max_depth` parameter:

```rust
if child.parent.is_some() && max_depth == 0 {
    return Err("chain depth exceeded (max_depth=0)");
}
```

When `max_depth` is 0, no further delegation is allowed from this token. When it's 3, three more levels of delegation are permitted.

## What cannot be delegated

Two fields have special rules:

### Credentials are never inherited

```rust
let cap = CapabilitySet {
    // ...
    credentials: vec![], // teammates don't inherit credentials
};
```

When a leader creates a delegated token, credentials are always empty. If a specialist needs a credential, the leader must explicitly grant it. This prevents accidental credential leakage through delegation chains.

### OBO identity cannot be added or changed

The `obo` (on-behalf-of) field carries the human identity through the chain. It can only be set in the root token (during OAuth token exchange). During delegation:

- If the parent has no `obo`, the child cannot add one.
- If the parent has an `obo`, the child must carry the same one.
- Changing the `obo` (different email, different IdP) is rejected as a mismatch.

```rust
#[kani::proof]
fn obo_escalation_rejected() {
    let parent_has: bool = kani::any();
    let child_has: bool = kani::any();
    let matches: bool = kani::any();
    let result = check_obo_attenuation(parent_has, child_has, matches);
    if !parent_has && child_has {
        assert!(result.is_err());  // can't inject obo
    }
    if parent_has && child_has && !matches {
        assert!(result.is_err());  // can't change obo
    }
}
```

This ensures that every tool call in a delegation chain is attributable to the same human who initiated the work.

### Sandbox profiles cannot be removed

If a parent token has a sandbox profile (per-tool restrictions like "simulate writes" or "redact PII"), the child cannot remove it:

```rust
(Some(_parent_sandbox), None) => {
    return Err("sandbox escalation: child removes sandbox profile");
}
```

A child can *add* a sandbox (increasing restrictions) or *keep* the parent's sandbox, but never remove one. This ensures that safety constraints imposed higher in the chain cannot be circumvented by delegation.

## A complete delegation example

Putting it all together:

```rust
// Gateway generates the leader's token
let leader_payload = build_payload(
    gateway_signer.did(),
    leader_did,
    leader_cap,
    1,       // ring 1
    3600,    // 1 hour
);
let leader_token = encode_token(&leader_payload, &gateway_signer)?;

// Leader creates a specialist token
let specialist_payload = build_delegated_payload(
    &leader_payload,
    specialist_did,
    vec!["read".to_string()],           // subset of leader's ops
    vec!["file_read".to_string()],      // subset of leader's tools
    2,                                   // ring 2 >= leader's ring 1
    600,                                 // 10 min <= leader's 1 hour
)?;
let specialist_token = encode_token(&specialist_payload, &gateway_signer)?;

// Gateway verifies the specialist's token on each request
let decoded = decode_token(&specialist_token, &gateway_signer)?;
let caps = resolve_capabilities(&decoded);
// caps.operations = {"read"}
// caps.tools = ["file_read"]
// caps.ring = 2
// caps.paths = ["/home/alice/projects/**"]
// caps.expires_at = leader.exp (capped)
```

## Why this matters

The attenuation invariant means that a compromised specialist cannot escalate its privileges. If a prompt injection tricks an agent into requesting more tools or broader paths, the delegation check rejects it. The specialist is confined to what its parent explicitly granted.

Combined with the ring system from Chapter 7 (deny-wins semantics), the sandbox profile, and the OBO chain, this creates defense in depth: multiple independent mechanisms, each narrowing what an agent can do.

Even if one mechanism has a bug, the others still constrain the agent. This is the microkernel philosophy from Chapter 9, applied to capability delegation.

## What's next

The entire system so far relies on Ed25519 signatures. But Ed25519, like all elliptic curve cryptography, will be broken by a sufficiently large quantum computer. Chapter 14 explains why navra is preparing for this now, and how the `CapSigner` trait makes the transition a configuration change rather than a rewrite.
