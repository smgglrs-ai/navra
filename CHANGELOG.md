# Changelog

All notable changes to navra are documented here.

## [Unreleased]

### Added

- **security**: Temporal behavioral contracts — complete implementation
- **security**: Add SandboxProfile types and PreHookOutcome enum
- **security**: SandboxHook with simulate, redact, rate-limit, path-rewrite
- **security**: Extend CapabilityPayload with sandbox profile field
- **security**: Wire sandbox profile into CallContext and handlers
- **flow**: Causal provenance graphs — complete implementation
- **model-runtime**: Add vLLM engine, refactor Engine × Isolation
- **core**: Cedar denial counter + MCP spec compliance tests
- **flow,security**: Kill switch tool, circuit breaker, cross-tool transition tracking
- **cognitive**: Composable skill source pipeline
- **rag**: HyDE retrieval channel — 3-channel RRF fusion (7k)
- **security**: Egress endpoint allowlist hook (9u)
- **protocol,core**: MCP 2026-07-28 additive items — caching, headers, trace context
- **security**: OWASP ASI01-ASI10 compliance mapping + tests (9v)
- **security**: Tool manifest signing with Ed25519 + TOFU (9ab)
- **security**: IFC declassification witness with Ed25519 signing (11k)
- **core,rag**: Dynamic tool routing (8l) + adaptive chunking metrics (7m)
- **security**: ID-JAG agent registration protocol (9y)
- **core**: MCP 2026-07-28 stateless dispatch — runtime config gate (9x)
- **rag**: Agentic RAG L2 — query decomposition + self-correction (7c)
- **cognitive**: MUSE skill lifecycle — registry, testing, IFC labels (1k)
- **security**: Approval gate hook — ASI09 OWASP closure (9ac)
- **memory**: Temporal tree index on SQLite — MemForest architecture (3l)
- **memory**: Intermediate tree levels + is_leaf + child_count
- **memory**: Transaction-batched insert_facts — 3x faster than flat
- **core**: Standalone MCP servers for tool modules — process-level microkernel isolation
- **security,model-runtime**: Privacy-filter ContentFilter, ExecutionMode, roadmap.json
- **security**: Cedar policies for OWASP Agentic Top 10 (TW6)
- **security**: SemanticLeakageHook — L3 defense against paraphrased exfiltration
- **metrics**: Leakage detection counters in Prometheus /metrics
- **cli**: Navra policy suggest — generate policies from denials
- **mcp**: Flip default to 2026-07-28 stateless dispatch
- **rag**: Cascading confidence gates + token reduction metrics
- **rag**: Graphability indexing — skip low-value chunks
- **core**: Tool schema pruning — suppress unused tools per agent
- **agent**: Transparent RAG context retrieval
- **rag**: Standalone MCP server binary
- **rag**: Standalone retrieval service + verified transparent RAG
- **core**: Rewrite ACP transport to spec-compliant v0.2.0 REST API
- **acp**: Agent-driven runs, await/resume, multi-agent routing
- **server**: Wire ACP dispatcher with model and flow discovery
- **acp**: Session-aware runs with history tracking
- **acp**: Run expiration with periodic sweep
- **acp**: Populate AgentStatus with live run metrics
- **model**: Add OGX backend with Llama Guard classification (TW7)
- **flow**: Blackboard-based result delivery for containerized agents

### Changed

- **model-runtime**: Extract HardwareTarget, ModelFormat, Isolation dimensions
- **security**: Rename + add L3 SemanticLeakageJudge

### Documentation

- **roadmap**: Tech watch 2026-05-28 — 18 items, dependency graph
- Agentic AI ecosystem tech watch May 2026
- **roadmap**: MemForest on SQLite (unblocked), Phase 15 → rendra stack
- **roadmap**: Mark Waves 1-3 complete, update execution plan
- Update priorities and stats after rename
- **paper**: Rewrite AI OS paper for Rust-only microkernel architecture
- **papers**: Update stale statistics across all papers
- **paper,eval**: C3 evaluation plan + semantic leakage detection design
- **paper**: Update §8 with complete C3 eval results + references
- **paper**: VFS analogy + tiered isolation model in §3
- **paper**: L3 continuous mode — async leakage detection mid-session
- Policy learning from denials (audit2allow pattern)
- **acp**: Protocol reference, security model, differentiators

### Evaluation

- **agentdojo**: C3 AgentDojo benchmark — IFC defense across 5 models
- **mcptox**: E3a — tool poisoning benchmark against MCPTox (AAAI 2026)
- Semantic leakage benchmark with real embeddings (MiniLM-L6-v2)
- Semantic leakage model comparison — MiniLM vs BGE-large
- Add Stella 1.5B to semantic leakage model comparison
- Semantic leakage benchmark with real embeddings (MiniLM-L6-v2)

### Fixed

- **server**: Propagate transition tracking config fields
- **core**: Handle Pending variant in PreHookOutcome match
- **bench**: Cap sample_size for large-scale benchmarks
- **security**: Address all 10 red team findings
- **rag,core**: Wire token reduction into live code paths
- **tests**: Update e2e + adversarial tests for MCP 2026-07-28 default
- **metrics**: Share Metrics Arc between McpServer and HTTP router
- Ollama runtime, RAG query permissions, shared metrics
- **rag**: Remove path ACL check from rag_status and rag_query
- **flow**: Capability permission inheritance + model name stripping
- **model**: Separate inference name from hub URI
- **flow**: Use {{target_dir}} in scout mandate for absolute paths

### Housekeeping

- Update DESIGN.md, fix warnings

### Maintenance

- Rename smgglrs → navra
- Mark TW2 completed — Glasswing harness evaluated for C3
- Mark TW6 completed in roadmap.json
- Mark TW1 completed
- Mark 13a completed — paper fixes already applied
- Mark C3 completed — 19 adversarial tests, 3 benchmarks
- Mark 10a completed — security paper evaluation complete
- **roadmap**: Mark 15a + 15b completed
- **roadmap**: Mark TW3 + TW12 + TW16 completed
- **roadmap**: Add TW17 navra-core crate split
- **claude**: AI-assisted development setup

### Merge

- Track teammate tasks with JoinHandle, abort on shutdown/timeout
- Protocol-level capability sandboxing
- Causal provenance graphs
- Cedar denial counter + MCP spec compliance tests (9z, 9i)
- Kill switch, circuit breaker, cross-tool transition tracking (2m, 9w)
- Composable skill source pipeline (1j)

### Security

- Complete ACP v0.2.0 implementation

### Tests

- **eval**: C3 adversarial security evaluation — 10/10 attacks blocked
- **eval**: E3b adaptive planner-trust attacks — 5/5 blocked
- **eval**: E3c Shadow Escape + Pale Fire, E3d encoding evasion — 4/4 blocked
- **acp**: Comprehensive test coverage for store and router

### Bench

- **memory**: Temporal tree vs flat KnowledgeStore
- **memory**: Scale temporal tree to 100K/1M facts


