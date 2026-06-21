+++
title = "6. Capabilities"
description = "Capability-based security from Dennis and Van Horn to Capsicum to navra — unforgeable tokens that travel with the request."
weight = 60
template = "docs/page.html"

[extra]
part = "os-security"
toc = true
+++

## What you already know

From the previous chapter, you know that navra treats each agent as an untrusted process. You know that every tool call passes through a chokepoint where the kernel checks permissions before executing the handler. You know that agents get sessions, credentials, and capability sets — just like OS processes.

Now the question is: how are those permissions represented? There are two fundamental approaches in security engineering. The one you are probably familiar with is wrong for AI agents. The one navra uses was invented in 1966 and is only now finding its ideal application.


## The ACL model and its problems

Most systems you have used enforce permissions with Access Control Lists. The resource (a file, a database, an API endpoint) maintains a list of who can access it:

```
/etc/shadow:  root:rw,  shadow-group:r
/home/alice:  alice:rwx, alice-group:rx
```

When Alice runs `cat /etc/shadow`, the kernel checks: is Alice on the ACL for `/etc/shadow`? She is not, so access is denied. Simple, intuitive, and universal — every Unix filesystem, every cloud IAM system, every database RBAC model works this way.

ACLs have a structural problem for AI agents: **the permission is on the resource, not on the requester.**

Consider a leader agent that wants to delegate a subtask to a specialist. The leader can read files in `~/Code/**`. It spawns a specialist and says "analyze the test files in `~/Code/project/tests/`." How does the specialist get access?

With ACLs, you have two options:

1. **Give the specialist the same ACL entry.** Now the specialist can read everything the leader can, including files unrelated to its task. You have violated least privilege.

2. **Create a new ACL entry for the specialist.** This means modifying the resource's ACL, which requires admin privileges. The leader agent cannot do this — and should not be able to.

Both options are bad. ACLs bind permissions to resources, so narrowing access requires modifying the resource. In a system where agents spawn sub-agents dynamically, you would need to modify ACLs on the fly for every delegation.


## The capability model

In 1966, Jack Dennis and Earl Van Horn published a paper at MIT describing an alternative: capabilities. The idea is simple but the consequences are profound.

A **capability** is an unforgeable token that combines a reference to a resource with the permissions to access it. The token travels with the request. The holder of the token can use it, pass it to someone else, or create a weaker version of it.

| Property | ACL | Capability |
|----------|-----|-----------|
| Where permissions live | On the resource | On the token |
| Who can narrow access | Resource administrator | Anyone holding the token |
| Delegation | Requires admin action | Token holder passes (attenuated) token |
| Revocation | Remove ACL entry | Revoke the token |
| Ambient authority | Yes (identity implies access) | No (must present token) |

The last row is the critical one. In an ACL system, being Alice is enough to access Alice's files — the identity carries implicit authority. In a capability system, you must present a specific token for each access. No token, no access.


## From theory to practice: Capsicum

Capability-based security remained largely academic until 2010, when Jonathan Anderson, Robert Watson, and others at the University of Cambridge implemented it in FreeBSD as **Capsicum**.

Capsicum takes a Unix file descriptor — already a kind of capability (it references a file with specific access mode) — and adds two critical features:

1. **Capability mode.** Once a process enters capability mode, it can no longer open new files by name. It can only use file descriptors it already has, or receive new ones from a parent process.

2. **Rights restriction.** A file descriptor opened for read+write can be restricted to read-only. The restriction is irrevocable — you cannot add rights back.

This solved the delegation problem elegantly. A parent process opens a directory, restricts the descriptor to read-only, and passes it to a child process in capability mode. The child can read files in that directory but cannot access anything else on the system. No ACLs were modified. The parent made the decision locally.


## navra's capability tokens

navra applies the same principle to AI agents. Instead of file descriptors, the tokens are cryptographically signed CBOR payloads. Here is the structure:

```rust
pub struct CapabilityPayload {
    pub v: u8,               // version (always 1)
    pub iss: String,          // issuer DID (who signed this)
    pub sub: String,          // subject DID (who this is for)
    pub cap: CapabilitySet,   // the permissions
    pub ring: u8,             // privilege ring (0 = most privileged)
    pub iat: u64,             // issued-at timestamp
    pub exp: u64,             // expiry timestamp
    pub nonce: [u8; 16],      // unique nonce (prevents replay)
    pub parent: Option<[u8; 16]>,  // parent token nonce (delegation chain)
    pub obo: Option<OboIdentity>,  // on-behalf-of human identity
    pub sandbox: Option<SandboxProfile>,  // per-tool restrictions
    pub aud: Option<String>,  // audience (target server)
}
```

And the capability set itself:

```rust
pub struct CapabilitySet {
    pub paths: Vec<String>,       // path allow globs
    pub operations: Vec<String>,  // permitted operations
    pub tools: Vec<String>,       // tool name globs
    pub credentials: Vec<String>, // credential labels
}
```

The wire format is: `navra_cap_v1.<base64url(cbor)>.<base64url(signature)>`

Three parts, dot-separated. The first is a version prefix. The second is the CBOR-encoded payload. The third is an Ed25519 signature over the raw CBOR bytes.


## Attenuation: the key property

The defining feature of capabilities is **attenuation**: you can create a weaker version of a token, but never a stronger one.

Suppose a leader agent holds this token:

```
paths:      ["~/Code/**"]
operations: ["read", "write", "git.status", "git.diff", "git.commit"]
tools:      ["file_*", "git_*"]
ring:       1
expires:    2026-06-22T00:00:00Z
```

It needs to delegate a read-only analysis task. It calls `build_delegated_payload()`:

```rust
let specialist_token = build_delegated_payload(
    &leader_token,
    "did:key:z6MkSpecialist",
    vec!["read".to_string()],              // only read
    vec!["file_read".to_string()],         // only file_read
    2,                                      // ring 2 (less privileged)
    600,                                    // 10 minutes
)?;
```

The resulting token:

```
paths:      ["~/Code/**"]        (inherited from parent)
operations: ["read"]              (subset of parent)
tools:      ["file_read"]         (subset of parent)
ring:       2                     (less privileged than parent's 1)
expires:    10 minutes            (capped to not exceed parent)
parent:     <leader's nonce>      (delegation chain reference)
```

Every field is equal to or more restrictive than the parent. navra enforces this with `validate_delegation()`, which checks:

- **Ring**: child ring must be >= parent ring (cannot escalate)
- **Expiry**: child expiry must be <= parent expiry (cannot outlive parent)
- **Operations**: child operations must be a subset of parent's
- **Tools**: child tool globs must be covered by parent's globs
- **Paths**: child path globs must be covered by parent's globs
- **Credentials**: child credentials must be a subset of parent's

If any check fails, the delegation is rejected. The leader cannot grant permissions it does not have. The specialist cannot amplify permissions it receives. The chain can only narrow.

The formal proof of these properties is verified by Kani (a bounded model checker for Rust):

```rust
#[kani::proof]
fn transitive_attenuation() {
    let r0: u8 = kani::any();
    let r1: u8 = kani::any();
    let r2: u8 = kani::any();
    // ... (bounds assumed)

    let parent_to_child = check_attenuation(r0, r1, e0, e1);
    let child_to_grandchild = check_attenuation(r1, r2, e1, e2);

    if parent_to_child.is_ok() && child_to_grandchild.is_ok() {
        assert!(check_attenuation(r0, r2, e0, e2).is_ok());
    }
}
```

This proves: if A can delegate to B, and B can delegate to C, then A's constraints still hold for C. Attenuation is transitive.


## Why not JWTs?

JSON Web Tokens (JWTs) are the standard for bearer tokens on the web. navra uses CBOR instead. The reasons are pragmatic:

| Concern | JWT | navra capability token |
|---------|-----|----------------------|
| **Size** | Base64-encoded JSON. A typical capability JWT would be 400+ bytes | CBOR is a binary format. Same payload encodes in ~200 bytes |
| **Nonce** | Not standard (must add `jti` claim) | 16-byte random nonce in every token |
| **Delegation chain** | No standard way to reference parent | `parent` field links to parent's nonce |
| **Schema** | JSON schema validation is optional | Rust struct enforces schema at compile time |
| **Signature** | Multiple algorithms, algorithm confusion attacks | Ed25519 only, no algorithm negotiation |

The token size matters because agents pass tokens on every request. In a multi-agent flow with nested delegation, a leader's token is included in the specialist's context. CBOR keeps this overhead small.

The signature simplicity matters because algorithm confusion (where an attacker tricks the verifier into using HMAC instead of RSA) is a well-known JWT vulnerability class. navra avoids it entirely by supporting exactly one algorithm.


## Revocation

Capabilities have a traditional weakness: revocation. If you hand someone a capability, how do you take it back? Unlike ACLs, where removing an entry immediately blocks access, a capability holder still has the token.

navra addresses this with three mechanisms:

1. **Short TTLs.** Tokens expire. A 10-minute specialist token becomes useless after 10 minutes, regardless of what happens.

2. **Revocation list.** `TokenRevocationList` is a set of nonces. When a token is revoked, its nonce is added. `decode_token_with_revocation()` checks this list.

3. **Audience binding.** The `aud` field restricts which server can accept the token. A token for `server-a.example.com` is rejected by `server-b.example.com`, even if the signature is valid.

In practice, short TTLs handle most cases. A specialist agent runs for 10 minutes and its token expires. No revocation needed.


## The no-ambient-authority principle

The deepest consequence of capability-based security is the elimination of ambient authority. In an ACL system, being logged in as Alice gives you access to all of Alice's resources. You do not need to name the specific permission — your identity is enough.

In navra, identity alone grants nothing. An agent that authenticates with a valid bearer token but does not hold a capability token with the right tool globs gets denied:

```
Permission denied: tool 'file_write' not in capability token grants
```

This means a compromised agent — one whose system prompt has been overwritten by a prompt injection — still cannot access resources outside its capability set. The attack surface is bounded by the token, not by the agent's identity.

This is the same principle that makes Capsicum processes safe even when they execute untrusted code. The capability bounding set is the security boundary, not the process's behavior.


## What's next

Capability tokens solve the delegation problem, but they do not explain who gets which capabilities in the first place. Chapter 7 introduces [privilege rings](../privilege-rings/) — the hierarchy that determines what each level of agent can do and how the deny-wins principle prevents escalation.
