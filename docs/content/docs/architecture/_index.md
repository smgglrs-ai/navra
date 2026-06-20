+++
title = "Architecture"
description = "Microkernel design, crate layering, and dependency boundaries."
weight = 20
template = "docs/section.html"

[extra]
toc = true
+++

## Design Principles

1. **Gateway, not framework** — Security is enforced at the infrastructure
   layer. Agents interact with resources exclusively through the kernel's
   mediation.

2. **Microkernel separation** — The kernel provides mechanism: identity,
   capability verification, resource mediation, IPC transport. Tool modules
   and orchestration logic are userland.

3. **Deny-wins** — In all permission checks, deny rules take absolute
   precedence over allow rules. No exception, no override.

4. **Agents are untrusted processes** — The gateway never trusts agent
   self-reports. Identity comes from cryptographic tokens, not system prompts.

## Microkernel Boundary

The boundary follows one rule: **if it requires trust, it's kernel;
if it requires intelligence, it's userland.**

| Concern | Layer | Crate | Why |
|---------|-------|-------|-----|
| Token verification | Kernel | navra-auth | Must not be bypassable |
| Tool permission check | Kernel | navra-auth | Agent cannot grant itself access |
| Credential injection | Kernel | navra-auth | Agent must never see raw secrets |
| Content safety filtering | Kernel | navra-safety | Mandatory access control |
| IFC taint tracking | Kernel | navra-safety | Bell-LaPadula enforcement |
| Rate limiting | Kernel | navra-core | Agent cannot increase its quota |
| Audit blackbox | Kernel | navra-core | Append-only, hash-chained |
| Persona selection | Userland | navra-cognitive | Policy, not mechanism |
| Task decomposition | Userland | navra-agent | Requires LLM reasoning |
| Flow orchestration | Userland | navra-flow | DAG execution, not security |

The crate dependency graph enforces this boundary at compile time.
Userland crates depend on `navra-core` (which re-exports the kernel's
public API) but cannot access kernel internals marked `pub(crate)`.

## Module System

All tool functionality is implemented behind the `Module` trait:

```rust
#[async_trait]
pub trait Module: Send + Sync {
    fn name(&self) -> &str;
    fn tools(&self) -> Vec<ToolDef>;
    async fn call(&self, ctx: CallContext, name: &str, args: Value)
        -> CallToolResult;
}
```

Modules can run:
- **In-process** — compiled into the navra binary, zero-overhead
- **Out-of-process** — standalone MCP servers connected via upstream config

The kernel enforces security identically in both modes.

## Formal Verification

- **146 Kani proofs** — Property-level verification of capability
  attenuation, IFC lattice monotonicity, token roundtrip correctness
- **6 TLA+ specifications** — Protocol-level model checking
- **2,800+ tests** — Unit, integration, security evaluation
