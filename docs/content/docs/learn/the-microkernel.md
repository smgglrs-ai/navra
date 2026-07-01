+++
title = "9. The Microkernel Idea"
description = "From Mach to seL4 to navra — keeping the trusted computing base small, and everything else as replaceable userland."
weight = 90
template = "docs/page.html"

[extra]
part = "os-security"
toc = true
+++

## What you already know

Over the last four chapters, you have seen navra's security mechanisms in detail: process-like isolation for agents (Chapter 5), capability tokens for delegation (Chapter 6), privilege rings for hierarchy (Chapter 7), and information flow control for data tracking (Chapter 8).

These mechanisms are implemented in code. Code has bugs. A buffer overflow in the capability validation function could let an agent forge a token. A logic error in the taint tracker could let sensitive data flow to a public destination.

This creates a question that software security engineers have been asking since the 1970s: how much code do you need to trust? The answer, refined over fifty years of operating system research, is: as little as possible. This chapter explains that principle and how navra's architecture embodies it.


## The monolithic kernel problem

Linux is a monolithic kernel. Device drivers, filesystems, networking, scheduling, memory management — all of it runs in Ring 0, with full hardware access. The kernel is approximately 30 million lines of code.

Every line of that code is in the Trusted Computing Base (TCB). A bug anywhere in the kernel — in a USB driver, in an obscure filesystem, in a rarely-used network protocol — can compromise the entire system. The attack surface is the entire kernel.

This is not a theoretical concern. The majority of Linux CVEs are in drivers and subsystems that most users never invoke directly. But because they run in Ring 0, a vulnerability in any of them gives the attacker full kernel access.


## The microkernel idea

In 1986, Richard Rashid's team at Carnegie Mellon built Mach, a microkernel that moved everything except the most essential services out of the kernel. The kernel handled:

- Process scheduling
- Inter-process communication (IPC)
- Virtual memory management

Everything else — filesystems, device drivers, networking — ran as ordinary user-space processes. If a filesystem crashed, you could restart it without rebooting. If a driver had a vulnerability, it could only compromise its own address space.

The TCB shrank from millions of lines to thousands.

Mach had performance problems (IPC overhead), but the idea survived and evolved:

| System | Year | TCB size | Key contribution |
|--------|------|----------|-----------------|
| **Mach** | 1986 | ~300K LOC | Proved the concept |
| **L4** | 1993 | ~10K LOC | Showed microkernels can be fast |
| **seL4** | 2009 | ~10K LOC | Formally verified — mathematically proven correct |
| **Fuchsia (Zircon)** | 2016 | ~170K LOC | Production microkernel (Google) |

seL4 is the landmark. Its designers mathematically proved that the kernel implementation matches its specification — that it has no bugs of certain classes (buffer overflows, null pointer dereferences, arithmetic errors). This is possible precisely because the kernel is small enough to verify.


## navra's trusted computing base

navra applies the microkernel principle to AI agent security. The question is: which code must be correct for the security guarantees to hold?

The answer is three crates:

| Crate | Role | What it must get right |
|-------|------|----------------------|
| `navra-auth` | Authentication, capability tokens, permissions, IFC labels | Token signing/verification, delegation validation, ring escalation checks, taint tracking |
| `navra-safety` | Content filtering, NER models, hook pipeline | PII detection, secret detection, redaction, safety filter ordering |
| `navra-core` | Server, chokepoint dispatch, session management | Permission check ordering in `handle_call_tool()`, session isolation |

These three crates are the kernel. A bug in `navra-auth`'s `validate_delegation()` could break the attenuation guarantee. A bug in `navra-safety`'s filter pipeline could let PII through. A bug in `navra-core`'s `handle_call_tool()` could skip a permission check.

Everything else is userland:

| Crate | Role | What happens if it has a bug |
|-------|------|------------------------------|
| upstream file server | File read/write/search | Incorrect file operations, but ACLs still enforced by the kernel |
| upstream git server | Git operations | Wrong git output, but tool permissions still checked |
| `navra-cognitive` | Persona loading, prompt assembly | Bad prompts, but security is not affected |
| `navra-memory` | Working memory, knowledge store | Lost context, but no security bypass |
| `navra-flow` | Multi-agent orchestration | Failed workflows, but capability attenuation still holds |
| `navra-rag` | Retrieval-augmented generation | Bad search results, but IFC labels still applied |
| `navra-modal-voice` | Speech I/O | Transcription errors, but content filters still run |

The boundary is clear: **if it requires trust, it is kernel; if it requires intelligence, it is userland.**

A persona that gives bad advice is a quality problem. A capability token that grants escalated privileges is a security problem. navra puts them in different crates with different review standards.


## The Module trait as the syscall interface

In a microkernel OS, user-space processes communicate with the kernel through system calls — a narrow, well-defined interface. The kernel validates every argument before acting on it.

In navra, the equivalent interface is the `Module` trait:

```rust
pub trait Module: Send + Sync + 'static {
    fn name(&self) -> &str;
    fn tools(&self) -> Vec<(ToolDefinition, ToolHandler)>;
    fn prompts(&self) -> Vec<(PromptDefinition, PromptHandler)> { Vec::new() }
    fn resources(&self) -> Vec<(ResourceDefinition, ResourceHandler)> { Vec::new() }
}
```

Every tool module — file operations, git operations, external MCP servers — implements `Module`. The module registers its tools at startup, and the kernel dispatches calls to the registered handlers.

The kernel does not trust the module. When a module's tool handler is called, the kernel has already:

1. Verified the agent's authentication
2. Checked the capability token's tool grants
3. Evaluated per-tool permission rules
4. Checked path ACLs (deny-wins)
5. Run the IFC taint check
6. Executed pre-hooks

The handler receives a `CallContext` with the agent's identity and taint level, but it cannot modify the security state. After the handler returns, the kernel:

7. Labels the result for IFC
8. Runs post-hooks (safety filters)
9. Records the call in the blackbox audit

The module cannot bypass any of these steps. It is sandboxed by the dispatch pipeline, just as a user-space process is sandboxed by the system call interface.


## Why the boundary matters

Consider what happens when a tool module has a vulnerability. Say an upstream file server has a path traversal bug that lets `../../etc/passwd` slip through its own validation.

In a monolithic design (everything in one module), this bug bypasses security.

In navra's microkernel design, the kernel's path ACL check runs before the module's handler. The gateway-level check in `handle_call_tool()` extracts the path from the tool arguments and checks it against the agent's ACLs:

```rust
if let Some(path_str) = params.arguments.get("path").and_then(|v| v.as_str()) {
    if let Some(acl) = self.path_acls.get(&ctx.agent.permissions) {
        match PermissionEngine::check_acl(acl, tool_op, path) {
            PermissionResult::Allowed => {}
            result => {
                return CallToolResult::error(
                    format!("Access denied: path '{}' blocked by ACL policy", path_str)
                );
            }
        }
    }
}
```

Even if the module's internal validation fails, the kernel's check catches the traversal. The attacker needs to bypass both the module's validation and the kernel's ACL — two independent layers written by different code paths.

This is the practical value of the microkernel design: bugs in userland code have limited blast radius because the kernel enforces boundaries independently.


## Upstream MCP servers as userland processes

The microkernel analogy extends to external MCP servers that navra proxies. When you configure an upstream:

```toml
[[upstream]]
name = "github-tools"
transport = "stdio"
command = ["npx", "@modelcontextprotocol/server-github"]
```

navra discovers the upstream's tools, wraps them in an `UpstreamModule`, and registers them like any built-in module. From the kernel's perspective, the upstream is just another userland process. The same enforcement applies:

- Capability token tool globs must match the upstream tool names
- Path ACLs apply to path arguments in upstream tool calls
- IFC labels are assigned to upstream tool results
- Safety filters run on upstream tool output
- The blackbox records upstream tool calls

The upstream server knows nothing about navra's security model. It receives a forwarded JSON-RPC request and returns a result. navra interposes on every interaction, applying the full security stack. This is the gateway pattern: the upstream is untrusted userland; the gateway is the kernel.

A compromised upstream server — one that returns malicious content or tries to probe for sensitive data — is contained by the same mechanisms that contain a compromised agent. The tool results are labeled, filtered, and taint-tracked. The upstream cannot escalate its privileges because it does not even know capabilities exist.


## The size advantage

navra's kernel crates have a combined size that is small enough to audit and verify:

| Crate | Approximate LOC | Kani proofs | Property tests |
|-------|----------------|-------------|----------------|
| `navra-auth` | ~5,000 | 12 proofs (capability, IFC, delegation) | Yes |
| `navra-safety` | ~3,000 | — | Yes |
| `navra-core` | ~8,000 | — | Yes |

Compare this to the full workspace (~40,000+ LOC across 23 crates). The security-critical code is roughly 15-20% of the total codebase. The rest — tools, personas, memory, flows, voice, vision — is userland that can have bugs without breaking security guarantees.

The Kani proofs are concentrated in the kernel crates because that is where formal verification pays off. Proving that `validate_delegation()` cannot allow ring escalation is valuable because that function is in the TCB. Proving that a persona YAML parser handles edge cases correctly is less valuable because a parsing bug does not break security.

This is the microkernel discipline: invest verification effort where it matters most, in the smallest possible code base.


## The boundary test

Here is a simple test for whether something belongs in the kernel or in userland:

> If this component is completely wrong — returns garbage, crashes, or is controlled by an attacker — can the security guarantees still hold?

If yes, it is userland. If no, it is kernel.

| Component | Completely wrong? | Security impact | Verdict |
|-----------|-------------------|-----------------|---------|
| Persona loader | Loads wrong persona | Bad prompts, no security bypass | Userland |
| Capability token verifier | Accepts forged tokens | Full privilege escalation | Kernel |
| File search index | Returns wrong results | Bad search, no security bypass | Userland |
| Taint tracker | Fails to propagate taint | Data exfiltration possible | Kernel |
| Git diff tool | Shows wrong diff | Wrong output, ACLs still enforced | Userland |
| Safety filter | Misses PII | PII exposure | Kernel |
| RAG retriever | Returns irrelevant chunks | Bad context, no security bypass | Userland |
| Path ACL checker | Allows denied paths | Unauthorized file access | Kernel |

This test is not about code quality — all code should be correct. It is about consequence classification: where a bug means a security breach versus where it means a degraded experience.


## What this part covered

Over five chapters, we built from an analogy to a complete security architecture:

| Chapter | OS Concept | navra Implementation |
|---------|-----------|---------------------|
| 5. Agents as Processes | Process isolation | Sessions, credentials, chokepoint dispatch |
| 6. Capabilities | Capability tokens | `CapabilityPayload`, attenuation, delegation validation |
| 7. Privilege Rings | Protection rings | Ring 0/1/2, deny-wins, non-escalation proofs |
| 8. Information Flow Control | Bell-LaPadula | `TaintTracker`, no-write-down, declassification witnesses |
| 9. The Microkernel | Small TCB | navra-auth + navra-safety + navra-core as kernel |

These concepts are not navra-specific. Any system that runs untrusted AI agents on shared infrastructure will need equivalents of capabilities, rings, IFC, and a small TCB. The names may differ, but the problems are the same — because the problems are the same ones operating systems solved decades ago.


## What's next

Part II covered the security primitives borrowed from operating systems. Part III shifts to cryptography: how agent identities are established with [digital signatures](../digital-signatures/), how decentralized identifiers work without a central registry, and how capability tokens are encoded and signed on the wire.
