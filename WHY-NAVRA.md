# Why navra?

The MCP gateway space has over a dozen options in 2026. Here is why
navra exists and what it does differently.

## The Problem

AI agents need tools — file access, git, shell, APIs, databases.
The Model Context Protocol (MCP) gives agents a standard way to
discover and call those tools. But MCP has no built-in security.
Every tool call is trusted. Every agent gets the same access. There
is no audit trail. There is no data sensitivity tracking.

Most MCP setups look like this:

```
Agent → MCP server → filesystem (full access)
```

The agent decides what to read, write, and execute. The human
running it hopes for the best.

## What navra Does

navra is a gateway daemon that sits between agents and tools. It
authenticates every agent, evaluates every tool call against
deny-wins ACLs, runs content safety filters, tracks data
sensitivity with Information Flow Control labels, and records
every action in a hash-chained audit log.

```
Agent → navra (auth + ACLs + safety + IFC + audit) → tools
```

The agent still decides what to do. navra decides what is allowed.

## What Makes navra Different

### 1. Gateway-Enforced Information Flow Control

navra tracks data sensitivity across tool calls with IFC labels.
When an agent reads a file labeled `Sensitive`, that taint
propagates through the session. If it later tries to write that
data to a `Public` destination, the gateway blocks it — not the
agent, not the model, not a prompt instruction.

This is Bell-LaPadula mandatory access control at the gateway
layer, verified with Kani proofs. No other MCP gateway does this.

### 2. Deny-Wins ACLs with Path Canonicalization

Path deny rules always beat allow rules. Before every ACL check,
navra canonicalizes the path — resolving symlinks, collapsing
`..`, and normalizing case — to prevent traversal attacks. This
is not configurable. Deny always wins.

### 3. In-Process ML Safety Filters

Small ONNX models (safety classifiers, NER for PII detection,
embeddings) run directly in the navra process. No GPU required.
No external API calls. No additional services to deploy. The
safety pipeline includes regex patterns (US + EU formats),
ML classification, and NER models — all in a hook pipeline that
runs on every tool call.

### 4. Formal Verification

138 Kani proofs verify core security properties: ACL evaluation,
capability delegation, token verification, IFC lattice operations.
6 TLA+ specifications verify flow concurrency, taint propagation,
and deny-wins semantics. The OWASP ASI framework has 10 controls;
navra covers all 10.

This is not a checklist. These are machine-checked proofs.

### 5. Composable Architecture

navra is a Rust workspace of 22 crates with strict dependency
layering. Crates like `navra-rag` can run as standalone
microservices in their own containers, allowing teams to compose
only the capabilities they need. The gateway enforces security
regardless of deployment topology — monolith or distributed.

### 6. Multi-Agent Orchestration

`navra-flow` provides DAG execution, handoff routing, and mesh
communication (mailbox + blackboard) with IFC-gated channels.
Agent-to-agent messages carry data labels. Taint propagates
through the flow graph. Mandate validation checks that each task's
output actually satisfies its requirements.

## Comparison

| Capability | navra | IBM ContextForge | Microsoft AGT | Envoy AI Gateway | ClawPatrol |
|---|---|---|---|---|---|
| IFC labels | Yes | — | — | — | — |
| Deny-wins ACLs | Yes | Cedar RBAC | — | CEL auth | — |
| In-process ML safety | Yes | — | — | — | Partial |
| Formal proofs | 138 Kani + 6 TLA+ | — | — | — | — |
| Multi-agent flows | DAG + handoff + mesh | — | — | — | — |
| Hash-chained audit | Yes | — | — | — | — |
| PII detection (NER) | Yes (EN + multilingual) | — | — | — | — |
| Capability tokens | Yes (Ed25519 + DID) | — | DID auth | — | — |
| MCP spec coverage | 39/39 | Partial | Partial | MCPRoute only | Partial |
| Language | Rust | Go | .NET | C++ (Envoy) | TypeScript |

## What navra is Not

- **Not an agent framework.** navra does not build agents. It
  secures them. Use any agent SDK (Claude Code, Goose, LangChain,
  custom) — navra sits in front.

- **Not a model server.** navra routes to models but does not
  serve them at scale. Use Ollama, vLLM, or llama.cpp for inference.
  navra's in-process models are small classifiers and embedders.

- **Not a marketplace.** navra discovers tools via AID and MCP
  registries but does not curate or distribute them.

## Getting Started

```bash
git clone https://github.com/smgglrs-ai/navra
cd navra
export ORT_LIB_PATH=/usr/lib64
export ORT_PREFER_DYNAMIC_LINK=1
cargo build && cargo run -- serve
```

Generate a token, add it to `~/.config/navra/config.toml`, and
point your agent's MCP config at the Unix socket. See
[CONFIG.md](CONFIG.md) for the full configuration reference.

## Learn More

- [CONFIG.md](CONFIG.md) — every configuration option
- [DESIGN.md](DESIGN.md) — full architecture and security model
- [Security paper](docs/papers/security-gateway.md) — gateway-enforced IFC with formal proofs
- [OWASP ASI compliance](docs/owasp-asi-compliance.md) — control-by-control mapping
