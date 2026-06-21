+++
title = "7. Privilege Rings"
description = "Intel's protection ring model adapted for AI agents — three rings, deny-wins, and why outer rings cannot escalate."
weight = 70
template = "docs/page.html"

[extra]
part = "os-security"
toc = true
+++

## What you already know

From Chapter 5, you know that navra treats agents as processes with isolated sessions, credentials, and capability sets. From Chapter 6, you know that capabilities can be attenuated — a leader can issue a narrower token to a specialist — and that this attenuation is formally verified to be transitive.

But attenuation alone does not tell you how many layers of delegation exist, or what each layer can do. In practice, agent systems have a natural hierarchy: the human operator at the top, a primary agent in the middle, and specialist sub-agents at the bottom. This chapter maps that hierarchy to a formal model borrowed from CPU architecture.


## The Intel ring model

In 1985, Intel's 80386 processor introduced four privilege levels, numbered 0 through 3:

| Ring | Intended occupant | Access |
|------|------------------|--------|
| 0 | Kernel | Full hardware access |
| 1 | Device drivers | Limited hardware, kernel services |
| 2 | OS services | User-mode with elevated privileges |
| 3 | Applications | Restricted, uses system calls |

The critical rule: a program running in Ring 3 cannot execute Ring 0 instructions. The CPU hardware enforces this — there is no software workaround. If a Ring 3 program tries to access a privileged register, the CPU raises a General Protection Fault, and the kernel kills the process.

In practice, most operating systems only use two rings (0 for the kernel, 3 for everything else), but the model is clean and well-understood.


## navra's three rings

navra adapts the ring model for AI agents with three levels:

| Ring | Occupant | Access | Example |
|------|---------|--------|---------|
| **0** | Gateway operator | Full tool access, all paths, all operations | The human running `navra serve` |
| **1** | Leader agent | Scoped by permission set — specific paths, operations, tools | Claude Code with `developer` permissions |
| **2** | Specialist agent | Attenuated from leader — fewer tools, shorter TTL, narrower paths | A read-only code reviewer spawned by Claude Code |

The ring level is encoded directly in the capability token's `ring` field:

```rust
pub struct CapabilityPayload {
    // ...
    pub ring: u8,  // 0 = most privileged
    // ...
}
```

Ring 0 is special: it is never assigned to an AI agent. Ring 0 represents the gateway itself and the human operator who configured it. When you write a `config.toml` with permission sets and ACLs, you are operating at Ring 0. The gateway enforces your rules at Ring 1 and Ring 2.


## How rings interact with capabilities

The ring level constrains what an agent can do at two points:

**At token creation:** A leader agent (Ring 1) cannot create a token with Ring 0. The `build_delegated_payload()` function rejects this:

```rust
if ring < parent.ring {
    return Err(CapabilityError::DelegationViolation(format!(
        "ring escalation: requested ring {ring} < parent ring {}",
        parent.ring
    )));
}
```

A Ring 1 agent can only create Ring 1 or Ring 2 tokens. A Ring 2 agent can only create Ring 2 (or higher, if the system ever extends to Ring 3).

**At token validation:** The `validate_delegation()` function checks that the child ring is >= the parent ring. This is verified by Kani for all possible ring combinations:

```rust
#[kani::proof]
fn ring_escalation_rejected() {
    let parent_ring: u8 = kani::any();
    let child_ring: u8 = kani::any();
    kani::assume(parent_ring <= 3);
    kani::assume(child_ring <= 3);
    let result = check_attenuation(parent_ring, child_ring, 1000, 1000);
    if child_ring < parent_ring {
        assert!(result.is_err());
    }
}
```

This proof exhaustively checks: for every combination of parent and child rings (0-3), if the child ring is more privileged than the parent, the attenuation check fails.


## The deny-wins principle

Rings create a hierarchy, but hierarchy alone is not enough. Consider this scenario:

- Ring 0 (operator) configures: `deny = ["**/.env"]`
- Ring 1 (leader) has: `allow = ["~/Code/**"]`
- Ring 2 (specialist) inherits Ring 1's allows

Should the specialist be able to read `~/Code/project/.env`? It matches the allow pattern, but it also matches the deny pattern.

navra's answer is unambiguous: **deny wins.** At every ring level, if any deny rule matches, access is denied — regardless of what allow rules say. This is implemented in the permission check order:

```
1. Check deny rules (glob match) → if matched, DENY
2. Check allow rules (glob match) → if matched, ALLOW
3. Default policy (configurable)  → typically DENY
```

The deny-wins principle has an important transitive property across rings. Suppose:

- Ring 0 denies `**/.env`
- Ring 1 allows `~/Code/**`
- Ring 2 inherits from Ring 1

Ring 2 inherits Ring 1's allow rules, but Ring 0's deny rules take precedence over everything. The deny rule at the top of the hierarchy cannot be overridden by any allow rule at a lower ring. This is a form of mandatory access control — the operator's restrictions are enforced regardless of what agents do.


## A concrete example

Here is a complete flow showing all three rings in action.

**Ring 0: Operator configures `config.toml`**

```toml
[[agents]]
name = "claude-code"
token_hash = "20a8c34a..."
permissions = "developer"

[permissions.developer]
allow = ["~/Code/**"]
deny = ["**/.env", "**/*secret*", "**/credentials*"]
operations = ["read", "write", "git.status", "git.diff"]
default_tool_policy = "allow"

[[permissions.developer.tool_rules]]
tool = "git_push"
policy = "deny"
```

**Ring 1: Claude Code connects and gets its permission set**

The leader agent can:
- Read and write files under `~/Code/**`
- Use `git_status` and `git_diff`
- Call most tools (default policy: allow)

The leader agent cannot:
- Access any `.env` file (deny-wins)
- Call `git_push` (tool rule: deny)
- Modify the permission configuration itself (Ring 0 only)

**Ring 2: Claude Code spawns a specialist for code review**

```rust
let reviewer_token = build_delegated_payload(
    &leader_token,
    "did:key:z6MkReviewer",
    vec!["read".to_string(), "git.diff".to_string()],  // no write
    vec!["file_read".to_string(), "git_diff".to_string()],  // only these tools
    2,   // Ring 2
    300, // 5 minutes
)?;
```

The specialist agent can:
- Read files under `~/Code/**` (inherited from parent)
- Call `file_read` and `git_diff` (attenuated tool set)

The specialist agent cannot:
- Write any files (operation "write" was not delegated)
- Call `file_write`, `file_edit`, or any tool not in its grants
- Access `.env` files (Ring 0 deny still applies)
- Create a Ring 1 token (ring escalation rejected)
- Create a token that expires after the leader's (expiry extension rejected)


## Why Ring 2 cannot become Ring 1

The non-escalation guarantee is the most important security property of the ring model. Here is why it holds.

A Ring 2 specialist receives a capability token with `ring: 2`. To escalate to Ring 1, it would need to either:

1. **Forge a new token with `ring: 1`.** Impossible — tokens are signed with Ed25519 by the issuer. The specialist does not have the signing key.

2. **Modify its existing token.** Impossible — changing any byte of the CBOR payload invalidates the signature. The gateway verifies the signature before reading the payload.

3. **Request a Ring 1 token from the leader.** The leader's `build_delegated_payload()` rejects `ring < parent.ring`. Even if the leader wanted to cooperate (e.g., due to prompt injection), the code prevents it.

4. **Call tools outside its grants.** The gateway checks the capability token's tool globs before executing the handler. Tools not in the glob set return "Permission denied."

5. **Modify the gateway's configuration.** The gateway reads `config.toml` at startup. There is no tool to modify the running configuration. Ring 0 changes require restarting the process.

This is defense in depth: multiple independent mechanisms each prevent escalation. Compromising one (e.g., tricking the leader via prompt injection) does not bypass the others (the gateway still enforces the token's ring level).


## Rings and the request pipeline

Looking back at the chokepoint from Chapter 5, you can now see which checks correspond to which rings:

```
handle_call_tool()
    |
    |-- Pause check          (Ring 0: operator can halt everything)
    |-- Rate limit           (Ring 0: operator-set limits)
    |-- Capability token     (Ring 1/2: token-based tool grants)
    |-- Tool permission rules (Ring 0: operator's tool policies)
    |-- Operations check     (Ring 1/2: token's operation list)
    |-- Path ACL             (Ring 0: deny-wins over all rings)
    |-- IFC taint check      (Cross-ring: lattice-based, covered in Ch 8)
    |-- Pre-hooks            (Ring 0: operator-installed hooks)
    |-- >>> Handler <<<
    |-- Post-hooks           (Ring 0: safety filters)
    |-- Blackbox audit       (Ring 0: audit trail)
```

Ring 0 checks (pause, rate limit, tool rules, ACLs, hooks) cannot be bypassed by Ring 1 or Ring 2 agents. They are mandatory. Ring 1/2 checks (capability token, operations) further restrict within the Ring 0 boundaries. Every check that fails short-circuits the pipeline — the handler never runs.

This layering means the operator can set hard boundaries that no agent can cross, while agents can further restrict their own sub-agents. The hierarchy is monotonically restrictive: each ring can only add constraints, never remove them.


## What's next

Rings and capabilities control which tools an agent can call and which paths it can access. But they do not control what happens to data after it has been read. Chapter 8 introduces [information flow control](../information-flow-control/) — the mechanism that prevents an agent from reading a confidential file and then writing its contents to a public location.
