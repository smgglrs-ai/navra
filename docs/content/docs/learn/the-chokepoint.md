+++
title = "17. The Chokepoint"
description = "Every tool call in navra passes through a single function: handle_call_tool. This is the system call boundary where all security enforcement happens. One function, no bypasses."
weight = 170
template = "docs/page.html"

[extra]
part = "protocol"
toc = true
+++

## What you already know

You know the three MCP primitives: tools, resources, and prompts. You know that tools are where the security risk concentrates -- tools execute code, modify files, and interact with external systems. Now we look at the single function where all tool call enforcement happens.

## One function to rule them all

In navra, every tool call -- local or proxied, from any agent, over any transport -- passes through one function: `handle_call_tool` in `navra-core/src/server/handlers.rs`. This is the chokepoint.

The term is borrowed from network security. A chokepoint is a single point through which all traffic must flow, making it the ideal place to enforce policy. In operating systems, the system call interface is a chokepoint: every user-space program that wants to touch hardware, files, or the network must go through the kernel's syscall boundary. navra applies the same principle to agent tool calls.

The pipeline looks like this:

```
Agent Request
    |
    v
[1] Parse JSON-RPC envelope
    |
    v
[2] Authenticate agent (token or session)
    |
    v
[3] Check pause state
    |
    v
[4] Rate limit check
    |
    v
[5] Per-tool permission check (ACL)
    |
    v
[6] Operations-based enforcement
    |
    v
[7] Domain classification gate
    |
    v
[8] Cedar policy check (if enabled)
    |
    v
[9] Path ACL enforcement
    |
    v
[10] IFC variable resolution
    |
    v
[11] IFC write check (Bell-LaPadula)
    |
    v
[12] Pre-hooks (may modify, simulate, or block)
    |
    v
[13] Execute tool handler
    |
    v
[14] Post-hooks and content filtering
    |
    v
[15] Record to blackbox
    |
    v
[16] Return result to agent
```

Every step is a potential exit point. If any check fails, the function returns an error result and the tool never executes. The remaining steps are skipped. This is fail-closed design: if anything goes wrong, the answer is "no."

## Walking through the pipeline

**Step 1: Parse.** The JSON-RPC envelope has already been validated by the transport layer. At this point, navra extracts the `CallToolParams` -- the tool name and its arguments.

**Step 2: Authenticate.** The `CallContext` arrives pre-authenticated. It carries the agent's identity, permission set, session ID, and IFC taint level. The transport layer resolved these from the bearer token or session state before the request reached the handler.

**Step 3: Pause check.** navra supports a global pause state (controlled from the system tray). When paused, all tool calls are rejected immediately. This gives the operator an emergency stop button.

**Step 4: Rate limiting.** The quota engine checks whether this agent has exceeded its allowed call rate. Rate limits are per-agent and per-permission-set. If the agent is over quota, the request is denied without executing the tool.

**Step 5: ACL check.** This is where navra checks whether the agent is allowed to call this specific tool. There are two paths:

- **Capability tokens** carry their own tool grants -- a list of glob patterns like `["file_*", "search_*"]`. The tool name must match at least one pattern.
- **Legacy permission sets** use configured tool rules that classify each tool as `Allow`, `Deny`, or `Approve` (requires human confirmation).

If the tool is denied, navra records the denial in the process table and returns an error.

**Step 6: Operations enforcement.** If the tool is classified as a write operation but the agent's permission set only allows reads, the call is blocked. This is a coarser check than the per-tool ACL -- it enforces broad read/write boundaries.

**Step 7: Domain classification.** Tools can be classified by domain (e.g., `filesystem:write`, `network:read`, `database:modify`). If domain rules are configured, navra checks whether the agent's permission set is allowed to perform that domain:operation pair.

**Step 8: Cedar policies.** If Cedar (Amazon's authorization language) is enabled, navra evaluates a Cedar policy against the request. Cedar policies can express fine-grained conditions like "agent X can call tool Y only on resources matching pattern Z." Cedar can only further restrict -- it cannot override earlier denials.

**Step 9: Path ACLs.** If the tool arguments include a file path, navra checks it against path-based allow/deny rules. This ensures that even proxied upstream tools respect navra's filesystem boundaries.

**Step 10: IFC variable resolution.** Tool arguments can reference stored values using `var://` URIs. navra resolves these references and computes the effective IFC label -- the combined secrecy and integrity level of all referenced values.

**Step 11: IFC write check.** If the tool is a write operation and the effective label indicates untrusted data, navra enforces Bell-LaPadula no-write-down. An agent whose context has been tainted by untrusted data cannot write to trusted destinations. The policy can be `Deny` (block), `Approve` (require human confirmation), or `Allow` (permit despite taint). The default is deny.

**Step 12: Pre-hooks.** Extension hooks run before the tool executes. A hook can modify arguments (e.g., inject sandbox parameters), simulate the result (return a cached response without execution), block the call (if a custom policy engine denies it), or put it in a pending state awaiting approval.

**Step 13: Execute.** If every check passes, the tool handler runs. This is where the actual work happens -- reading a file, running a command, querying an API. The handler is an async function that receives the resolved arguments and the call context.

**Step 14: Post-processing.** After execution, content filters scan the result for secrets, PII, and prompt injection patterns. The result's IFC label is set based on the tool and the content. Post-hooks can modify or redact the result.

**Step 15: Blackbox.** Every tool call is recorded in the append-only, hash-chained blackbox. The record includes the agent identity, tool name, arguments (truncated), result (truncated), outcome (allowed/denied/error), and duration.

**Step 16: Return.** The result is serialized back into a JSON-RPC response and sent to the agent over whichever transport it used.

## Why one function

You might wonder: why not split this into middleware layers, or separate services, or a plugin pipeline? The answer is auditability. When all enforcement happens in one function, you can read that function and understand the entire security model. There is no question about ordering -- step 5 always runs before step 13. There is no question about bypass -- if you reach step 13, you passed steps 1 through 12.

Distributed enforcement is harder to reason about. If ACL checks are in one module, IFC checks in another, and content filtering in a third, you need to verify that all three are wired correctly for every code path. A new transport or a new handler could miss a check. The chokepoint pattern eliminates this class of bugs by construction.

The tradeoff is that `handle_call_tool` is a large function. In navra's codebase, it runs several hundred lines. That's intentional -- a security-critical function should be readable in one sitting, not spread across a dozen files.

## What the chokepoint cannot do

The chokepoint enforces policy at the tool call level. It cannot enforce policy at the semantic level. If an agent asks "read file A, then use its contents to write file B," the chokepoint sees two separate tool calls. It can check ACLs on each call individually, and IFC labels propagate taint between calls, but it cannot reason about the agent's *intent* across calls.

This is the fundamental limitation of gateway-level security. It is also the honest thing to say. navra makes every individual operation safe. It makes the system safer than running agents without a gateway. But it does not make agents safe in the way that a formally verified microkernel makes system calls safe.

## What's next

navra is not just a local tool server -- it can proxy tool calls to external MCP servers. In the next chapter, we look at how upstream proxying works and why the full security pipeline applies to proxied calls too.
