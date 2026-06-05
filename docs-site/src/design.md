# Design Overview

navra is a Rust workspace of 22 crates organized in strict
dependency layers.

## Architecture

```text
navra-protocol          (no navra deps)
navra-model-hub         (no navra deps)
navra-model-runtime     (no navra deps)
navra-responses         (no navra deps)
navra-cognitive         (no navra deps)
navra-macros            (no navra deps, proc-macro)
    |
navra-model             (responses)
    |
navra-security          (protocol + model)
    |
navra-core              (protocol + model + security)
    |
navra-memory            (core + model, opt: rag)
navra-agent             (protocol + model + security + cognitive)
navra-tools-file  --+
navra-tools-git   --|
navra-tools-exec  --+-- (core)
navra-rag         --|
navra-modal-*     --+
    |
navra-flow              (agent + cognitive + protocol + model + security)
    |
navra-server            (all + hub + runtime)
```

## Key Design Decisions

### Gateway, not framework

navra enforces security at the infrastructure layer. Orchestration
belongs in the agent. Any MCP client (Claude Code, Goose, custom)
connects through navra without changes to the agent code.

### Module trait

All capabilities implement the `Module` trait: `tools()`,
`resources()`, `prompts()`. Upstream MCP servers are wrapped in
`UpstreamModule` and go through the same security pipeline as
built-in tools.

### Composable deployment

Crates like `navra-rag` can run as standalone MCP servers in their
own containers, connected back to navra as upstreams. This enables
microservice-style composition without losing gateway-level security.

### Deny-wins ACLs

Path deny rules always beat allow rules. Canonicalization before
ACL check prevents traversal. This is not configurable.

### Safety is a hook

Content filtering runs as `SafetyHook` in the hook pipeline, not
hardcoded in the request path. This makes it composable with other
hooks (IFC, approval, statistical guardrails, temporal contracts).

### In-process models

Small ONNX models (safety classifiers, NER for PII, embeddings)
load directly into the navra process. No external dependencies
for CPU tier.

## Full Reference

The complete architecture, protocol specification, security model,
and config reference are in
[DESIGN.md](https://github.com/smgglrs-ai/navra/blob/main/DESIGN.md)
on GitHub.
