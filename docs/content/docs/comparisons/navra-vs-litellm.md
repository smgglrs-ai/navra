+++
title = "navra vs LiteLLM"
description = "LiteLLM governs model traffic and spend; navra contains what autonomous agents are allowed to do. Different chokepoints, different threat models — and how they compose."
weight = 10
template = "docs/page.html"

[extra]
part = "comparisons"
toc = true
+++

Both navra and [LiteLLM](https://litellm.ai) are called "AI gateways," but they
secure **different traffic** against **different threat models**:

- **LiteLLM** sits between your *application* and *model providers*. It is
  about unified model access, cost governance, and routing uptime.
- **navra** sits between an *AI agent* and *the tools and systems that agent
  can touch*. It is about containing what an autonomous agent is permitted
  to do — enforced by infrastructure, not by trusting the model.

The two compose cleanly: navra's OpenAI-compatible model proxy can point at
a LiteLLM deployment as one of its model backends, giving you LiteLLM's
provider fleet behind navra's enforcement pipeline.

## At a glance

| | **navra** | **LiteLLM** |
|---|---|---|
| **One-liner** | Secure agentic AI framework: MCP gateway + agent SDK + multi-agent flow engine (24-crate Rust workspace) | LLM gateway/proxy: one OpenAI-format API over 100+ providers |
| **Primary job** | Enforce policy on *tool calls and data flows* made by agents | Normalize *model calls* and govern spend and keys |
| **Core protocols** | MCP 2026-07-28, ACP v0.2.0, OpenAI-compatible proxy, OpenAPI-to-MCP bridge | OpenAI-compatible REST API (Python SDK + proxy server) |
| **Runtime** | Rust — memory-safe, single static binary, ONNX Runtime bundled | Python (a Rust migration was announced mid-2026, staged through December 2026) |
| **Deployment** | Container or bare metal: distroless images, Podman/OpenShell isolation, systemd socket activation. Stateless gateway — replicate behind any load balancer to scale. Desktop tray/D-Bus integration is a default UX, not a deployment limit | Server-side, multi-tenant, Postgres/Redis-backed, designed for horizontal scale |
| **License** | Apache 2.0 | MIT (core) with an enterprise tier |

## Security model — the biggest difference

navra's reason to exist is infrastructure-level enforcement:

- **Information Flow Control** — 2×4 product lattice, Bell-LaPadula
  no-write-down, taint labels tracked across tool calls
- **Deny-wins ACLs** — path rules, domain rules, per-tool policies,
  privilege rings, path canonicalization
- **22 hook types** — pre/post tool-call and model-call, safety, and egress
  hooks forming a pipeline that cannot be bypassed
- **Content safety** — regex + NER + ML filters, pseudonymization, canary
  tokens
- **Tool scanner** — 8 threat categories for upstream MCP supply-chain
  defense
- **Credential brokering** — secrets injected at call time; agent sessions
  never see raw credentials
- **Audit blackbox** — SHA-256 hash chain, tamper-evident
- **Human-in-the-loop approval** — MCP, D-Bus, system tray, CLI channels
- **Formal verification** — Kani proofs, Verus, and TLA+ specs for
  critical safety invariants

LiteLLM's security is *governance-shaped*, not *containment-shaped*:

- Virtual keys mapped to provider keys, with allowed-model lists
- Budgets per key/team/project, RPM/TPM rate limits, spend tracking
- Guardrails exist as hooks and plugins you wire up — LiteLLM does not
  ship built-in content filters, and has no equivalent of IFC or taint
  tracking
- JWT auth, RBAC, SSO in the enterprise tier

## Where navra goes beyond

LiteLLM has no equivalent for most of navra's agent platform surface:

- **Agent SDK** (`navra-agent`) — ReAct tool-use loop, circuit breakers,
  pause/resume/interrupt/terminate signals, hibernation, deterministic
  replay, Podman/OpenShell sandboxed execution
- **Flow engine** (`navra-flow`) — DAG orchestration with dynamic task
  generation, handoff routing, mesh communication (mailbox, blackboard
  with IFC), event-driven triggers (cron, webhook, file-watch),
  checkpoint/recovery
- **Model serving** — embedded llama.cpp, hardware auto-detection
  (NVIDIA/AMD/Intel GPU, Intel NPU), model hub (`ollama://`, `hf://`,
  `oci://`, `file://`), KV-cache quantization, speculative decoding
- **Built-in modules** — RAG (hybrid FTS5 + sqlite-vec with reciprocal
  rank fusion), memory/knowledge store, vision, voice, personas

## Where LiteLLM goes beyond

navra has nothing comparable for LiteLLM's operational surface:

- **Provider breadth and routing** — 100+ providers, weighted load
  balancing, health-aware failover chains, retries across deployments
- **Multi-tenant cost management** — per-team/project/user budgets
  enforced at request time, admin dashboard, spend analytics
- **Observability ecosystem** — Langfuse, LangSmith, OpenTelemetry,
  Prometheus integrations, request logs at scale
- **Maturity and adoption** — 40k+ GitHub stars, 1,300+ contributors,
  weekly releases, enterprise support option

## Overlap zone

Both provide: an OpenAI-compatible endpoint, authentication in front of
model calls, rate limiting, audit logging, hot-reloadable configuration,
and local-model support (Ollama and friends). Within that narrow overlap,
LiteLLM is far more battle-tested for high-volume production model
traffic; navra's model proxy is one feature of a security gateway, not a
competing LLM ops platform.

## When to pick which

- **Pick LiteLLM** if your problem is "many teams, many providers, no
  control over cost and keys" — the classic platform-engineering LLM
  gateway use case.
- **Pick navra** if your problem is "autonomous agents with tool access
  need enforced limits on what they may read, write, and exfiltrate" —
  a threat model LiteLLM does not address.
- **Use both** if you want navra's agent containment in front of
  LiteLLM's provider fleet: point a navra OpenAI-compatible model
  backend at your LiteLLM endpoint.
