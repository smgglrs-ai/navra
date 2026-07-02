# Changelog

All notable changes to navra are documented here.

## [0.3.0] - 2026-07-02

### Added

- Multi-platform release builds + cargo-binstall (NAVRA-151)
- Embedded llama.cpp runtime (in-process GGUF inference)
- Resolve ollama:// models from local Ollama store
- Per-agent model, upstream, and quota config structs
- Wire per-agent cascade, upstream filtering, model routing
- Enforce max_concurrent per agent with semaphore
- Concurrency limits and model routing for chat proxy
- Hot-swap model pool, GPU offload, model proxy routing
- Add Anthropic Messages API proxy (/v1/messages)
- Add Vertex AI support to /v1/chat/completions proxy
- Add Verus proofs across 10 crates and extend TLA+ session isolation

### Documentation

- Add safety hooks, tool scanner, rate limiting to security page
- Add flow authoring and persona guides
- Add memory, RAG, and OpenAPI bridge guides
- Add agent bundles, model server, and config reference
- Add llms.txt generator and just recipes
- Update NAVRA-151 — bundling friction already resolved
- Add v0.3.0 changelog
- Update CONFIG.md, model-server guide, changelog for v0.3.0
- Fix discrepancies, consolidate, restructure for 5-min setup
- Remove stale design docs
- Strengthen documentation maintenance mandate in CLAUDE.md
- Rewrite model proxy section with step-by-step setup
- Add learn chapter on the model proxy security layer
- Show both global and regional Vertex AI endpoints
- Update CHANGELOG.md for v0.3.0

### Fixed

- Keyring 4 runtime nesting panic, missing test import
- Release profile for embedded builds, wire context_size
- Per-instance socket paths, block test-crate navra-server
- Close IFC bypass for inline injection ≤3 deps (NAVRA-169)
- Simplify Dockerfile.agent and add GHA build cache
- Include benchmarks/ in container build context

### Maintenance

- Edition 2024, Rust 1.96 MSRV, schemars 1.2
- Fix all clippy warnings from edition 2024 + dep upgrades
- Update .lean/project.yml for edition 2024 and bundled ort
- Remove all stale ORT/system-dep references for v0.3.0
- Bump to 0.3.0, remove native-tls, update all docs
- Plan audit — fix NAVRA-160 status, unblock NAVRA-150

### Merge

- Memory, RAG, and OpenAPI bridge guides
- Agent bundles, model server, and config reference

### Deps

- Upgrade reqwest 0.12 → 0.13, unify tree
- Upgrade jsonwebtoken 9 → 10
- Upgrade keyring 3 → 4
- Upgrade tonic 0.12 → 0.14, prost 0.13 → 0.14
- Upgrade rusqlite 0.32 → 0.40
- Bundle ort, switch to rustls, drop all system C deps

### Track

- IFC bypass for ≤3-dep inline injection (NAVRA-169)
- Tech watch 2026-07-01 — 6 new items, ecosystem positioning

## [0.2.0] - 2026-06-25

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
- Add marketing site, docs site, and CI workflows
- **flow**: General-purpose self-review, discover all Ollama models
- Route agent model calls through gateway /v1/chat/completions
- **packaging**: ONNX 1.21 + ORT 1.26 RPM specs for Fedora 44
- **TW27**: Split navra-security into navra-auth + navra-safety
- **safety**: Add PolicyYamlHook for ACS YAML policy ingestion (TW18)
- **rag**: Add negation-aware FTS5 queries and temporal/numeric query router (TW19, TW20)
- **hooks**: Add pre/post model-call hook points in navra-agent (NAVRA-035)
- **NAVRA-075**: Feature-gate ONNX and add container build profile
- **NAVRA-075**: 4.5MB scratch container image for navra-agent
- **NAVRA-077**: Upstream tool ACL enforcement (critical)
- **NAVRA-077**: Upstream tool ACL with auto-classify + overrides
- **NAVRA-081**: Unified semantic permissions for tools, prompts, resources
- **NAVRA-082**: OpenAPI-to-MCP runtime bridge (navra-openapi crate)
- **NAVRA-087**: Signed agent bundles with pre-install permission check
- **NAVRA-036**: VerifierHook with false-pass-rate tracking
- **NAVRA-080**: Upstream transport hardening (error sanitization, stderr rate-limit)
- **NAVRA-033**: Effective tokens (ET) metric in Prometheus
- **NAVRA-067**: Wire ToolBlock into agent tool loop
- **NAVRA-065**: Doc comments on all config fields for schema generation
- **NAVRA-073**: Model refusal detection and gateway-level fallback routing
- **NAVRA-085**: Handle notifications/tools/list_changed from upstream MCP servers
- **NAVRA-078**: MCP authorization SEPs (OAuth 2.1 client for upstream servers)
- **NAVRA-088**: Decouple navra-safety for standalone crates.io publication
- **NAVRA-072**: Remove navra-tools-github crate
- **NAVRA-074**: Sanitize error messages to prevent architecture disclosure
- **NAVRA-032**: Compliance mapping (EU AI Act + OWASP + Microsoft taxonomy)
- **NAVRA-086**: Adoption skills wave 1 (init, diagnose, policy)
- **NAVRA-084**: Response truncation and token budget for OpenAPI upstream
- **NAVRA-034**: Extract navra-mcp crate from navra-core
- **NAVRA-029**: Cross-session fact extraction on session end
- **NAVRA-038**: Incremental mailbox messages in navra-flow
- **NAVRA-037**: SQLite entity-relationship table for navra-memory
- **NAVRA-043**: JSON response compression hook
- **NAVRA-089**: React dashboard scaffolding (@navra/react-hooks)
- **NAVRA-095**: <ApprovalQueue /> component + Storybook → Vite dev
- **NAVRA-096**: <AgentActivity /> component + useToolEvents hook
- **NAVRA-094**: <SecurityDashboard /> component
- **NAVRA-097**: <FlowVisualizer /> component
- **NAVRA-098**: <PermissionEditor /> component
- **NAVRA-024**: IFC adversarial corpus benchmark
- **NAVRA-024**: E2e IFC adversarial benchmark through full server
- **NAVRA-101**: Refuse stateless mode when IFC deny/approve configured
- **NAVRA-102**: IFC enforcement in stateless MCP transport
- **navra-core**: Gateway-level path ACL enforcement for all tools
- **navra-auth**: DeclassificationAuthority type for verified declassify
- **navra-auth**: Audience claim and decode_token_unchecked restriction
- **navra-model-hub**: Digest-pinned model URIs + integrity verification
- **navra-server**: Replace navra-tools-git with upstream MCP git server
- **navra-safety-hooks**: Detect-only monitoring agent (NAVRA-099)
- **eval**: ASSERT integration for compliance evaluation (NAVRA-100)
- **navra-openapi**: OAuth2 Authorization Code + PKCE flow (NAVRA-083)
- **navra-safety**: X-Token Projection for cross-tokenizer KD (NAVRA-030)
- **navra-security**: NeuroTaint offline taint audit (NAVRA-025)
- **navra-model-hub**: Gemma 4 12B multimodal backend (NAVRA-039)
- **navra-model-runtime**: Kubernetes Agent Sandbox backend (NAVRA-027)
- **navra-core**: SEP-2577 deprecation warnings + OTel logging dual-write (NAVRA-141)
- **navra-memory**: Add KnowledgeModule with 4 MCP tools (NAVRA-145)
- **navra-protocol**: Complete WebMCP CDP transport implementation (NAVRA-139)
- **navra-protocol**: Add A2UI declarative UI protocol support (NAVRA-146)
- **navra-react**: AG-UI adapter and AgentChatPanel with PatternFly (NAVRA-026)
- **navra-model**: Nomic Embed v1.5 evaluation with Matryoshka support (NAVRA-064)
- **transport**: Harden WebSocket for agentic loops (NAVRA-070)
- **auth**: MCP Enterprise-Managed Authorization with ID-JAG (NAVRA-147)
- **cognitive**: Negative constraints in persona schema (NAVRA-058)
- **hooks**: HTML-to-markdown conversion post-hook (NAVRA-071)
- **flow**: YAML handoff flow definitions (NAVRA-059)
- **memory**: ONNX-based memory type classification (NAVRA-061)
- **core**: Multi-hypothesis tool routing (NAVRA-069)
- **safety**: PII ONNX sequence classifier pre-filter (NAVRA-049)
- **cognitive**: Lazy-load specialization YAML with cached on-demand access (NAVRA-057)
- **cognitive**: Lazy-load specialization YAML with cached on-demand access (NAVRA-057)
- **config**: Operator libraries — conf.d-style config composition (NAVRA-060)
- **config**: Operator libraries — conf.d-style config composition (NAVRA-060)
- **safety**: PrivacyRouter — unified privacy detection coordinator (NAVRA-063)
- **safety**: PrivacyRouter — unified privacy detection coordinator (NAVRA-063)
- Narwhal logo and Zola documentation site
- **docs**: Polish doc site — hero styling, dark mode, config/CLI pages, CI
- **core**: Add NavraHandler and rmcp client backend for UpstreamModule
- **docs**: Add Learn link to navbar
- **permissions**: Wire domain rules into resource handlers (NAVRA-081)
- **react-hooks**: Add useYamlSync and useFlowValidation hooks
- **react**: Visual flow editor with YAML sync and validation (NAVRA-148)
- **agent**: Wire trace export to tool loop for training data (NAVRA-050)
- **flow**: Add graph HTTP endpoints and serialization (NAVRA-054)
- **cli**: Add navra init interactive setup command
- **flows**: Add deep-research flow with adversarial verification
- **build**: Make ONNX Runtime an optional cargo feature
- **cli**: Add `navra wrap` one-liner secure proxy command
- **cli**: Add --discover, --allow-all, --sandbox to navra wrap
- **wrap**: Network policy discovery and egress enforcement (NAVRA-160)
- **agent**: Adaptive context budgets from model cards
- **model-server**: Create navra-model-server crate with registry, API, hardware detection
- **cli**: Add 'navra model serve' command
- **gateway**: Use ModelRegistry for model loading, add model_server config
- **bundles**: Directory-based agent bundle format (v2) with per-step permissions
- **cli**: Add 'navra agent init' for instance configuration
- **cli**: Add workflow and config flags to 'navra run'
- **credentials**: Inject credentials from keyring into MCP server processes
- **bundles**: Permission intersection and workflow visibility enforcement
- **bundles**: Agent upgrade with permission diff

### Build

- **navra-auth**: Replace hand-rolled constant_time_eq with subtle crate
- **navra-auth**: Replace manual secret zeroization with zeroize crate
- Bump MSRV from 1.75 to 1.91 (NAVRA-132)
- Consolidate rusqlite to workspace dependency (NAVRA-135)

### CI

- **NAVRA-075**: Add container build and verification workflow

### Changed

- **model-runtime**: Extract HardwareTarget, ModelFormat, Isolation dimensions
- **security**: Rename + add L3 SemanticLeakageJudge
- Replace anyhow with typed errors in navra-security and navra-flow
- **NAVRA-091**: Remove navra-tools-file, use upstream Filesystem MCP
- **navra-auth**: Witness canonical encoding to deterministic CBOR
- **navra-core**: Blackbox single mutex, error propagation
- **navra-memory**: Wrap Connection in Mutex for thread safety
- **onnx**: Shared session builder across crates (NAVRA-021)
- **navra-core**: Handle WebSocket send failures instead of silently dropping (NAVRA-130)
- Clean up dead code annotations across 7 files (NAVRA-133)
- **navra-server**: Remove navra-tools-gitlab, use upstream MCP (NAVRA-143)
- **navra-server**: Extract ExecState, inline exec_run, remove navra-tools-exec (NAVRA-144)
- **navra-server**: Extract ExecState, inline exec_run, remove navra-tools-exec (NAVRA-144)
- **deps**: Add rmcp SDK dependency, bump schemars 0.8→1.x
- **protocol**: Replace navra MCP types with rmcp SDK re-exports
- **transport**: Wire stdio transport through NavraHandler + rmcp
- **transport**: Wire HTTP /mcp through rmcp StreamableHttpService
- **cleanup**: Remove dead MCP dispatch handlers, fix unused imports
- **server**: Wire upstream discovery through rmcp client transports
- **agent**: Replace Upstream with rmcp Peer<RoleClient>
- **upstream**: Remove legacy Upstream client, use rmcp exclusively
- **flow**: Migrate navra-flow tests from Upstream to rmcp duplex
- **protocol**: Remove Upstream type from public API
- **protocol**: Extract config types, delete dead upstream transport code
- **transport**: Wire WebSocket through rmcp, delete dispatch.rs
- **protocol**: Delete upstream transport module (3100 lines)

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
- Add governance files and fix license to Apache-2.0
- Add config reference, positioning, AI-friendly docs, and changelog
- Expand crate READMEs and add rustdoc comments
- Update CHANGELOG.md for v0.1.0
- Document /v1/chat/completions model proxy
- Update eval — NAVRA-077 fixes the upstream permission gap
- Update CLAUDE.md, DESIGN.md, remove legacy roadmap files
- **NAVRA-031**: DNS-AID doc update in DISCOVERY.md
- **NAVRA-079**: Map ADR-Bench attack taxonomy to navra defense layers
- **NAVRA-040**: ASSERT integration evaluation for C3
- Formal proof gap analysis + 25 fix items (NAVRA-103..127)
- **eval**: TurboVec evaluation — reject (NAVRA-028)
- **eval**: Delta-mem OSAM evaluation — defer (NAVRA-023)
- **eval**: LFM2.5-Audio evaluation — reject (NAVRA-041)
- **paper**: Expand persona-driven orchestration section (NAVRA-019)
- **paper**: Restructure review paper contributions (NAVRA-020)
- Refresh TESTING.md test counts — 2110 → 2750+ (NAVRA-138)
- **navra-agent,navra-cognitive**: Add missing doc comments (NAVRA-136)
- **paper**: Update stale numbers and architecture references (NAVRA-051)
- **papers**: Add numbered references and related work across all papers (NAVRA-052)
- **papers**: Paper suite restructuring decisions (NAVRA-053)
- **learn**: Part I — The Threat Model (chapters 0-4)
- **learn**: Part III — Cryptographic Identity (chapters 10-14)
- **learn**: Part II — OS Security Primitives (chapters 5-9)
- **learn**: Expand agents-as-processes chapter to meet line target
- **learn**: Parts IV-VI — Protocol, Verification, Privacy (chapters 15-29)
- Align with current codebase — rmcp, removed crates, updated numbers
- **examples**: Add 3 reference agent bundle manifests
- **examples**: Add standalone agent binary example for SDK
- Add Agent SDK guide and update Getting Started with navra init
- Reposition README as agentic framework, add SDK and flow sections
- Update llms.txt — reposition as agentic framework, add SDK section
- Add 5 integration guides (Claude Code, Goose, OpenAI, LangGraph, custom MCP)
- Fix unresolved RemoteRegistry link in navra-model-server
- Fix all unresolved rustdoc link warnings
- Fix all rustdoc warnings, update docs site for new CLI and architecture

### Evaluation

- **agentdojo**: C3 AgentDojo benchmark — IFC defense across 5 models
- **mcptox**: E3a — tool poisoning benchmark against MCPTox (AAAI 2026)
- Semantic leakage benchmark with real embeddings (MiniLM-L6-v2)
- Semantic leakage model comparison — MiniLM vs BGE-large
- Add Stella 1.5B to semantic leakage model comparison
- Semantic leakage benchmark with real embeddings (MiniLM-L6-v2)
- **NAVRA-076**: Adopt rust-mcp-filesystem as upstream MCP server
- **NAVRA-076**: Integration test — upstream tools bypass permissions

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
- **flow**: Filter embedding models from auto-selection
- **proxy**: Support streaming and 10min timeout for model proxy
- Address self-review findings across docs, perf, and CLI
- Adapt bootstrap_identity for IdentityError return type
- **NAVRA-075**: Use UBI 10 glibc-static instead of musl
- **navra-safety**: Fail-closed on ML/NER/privacy inference error
- **navra-tools-exec**: Directory-prefix check with dotdot rejection
- **navra-safety**: Threshold validation and NaN defense
- **navra-rag**: Dimension invariant + transactional indexing
- **navra-safety,navra-protocol**: UTF-8 boundary safety in redact/compress
- **navra-tools-git**: URL-encoded path traversal + git timeout
- **navra-core**: Stop leaking IFC labels to agents in tool results
- **navra-openapi**: Bounded spec download and response body limit
- **navra-auth,navra-core**: IFC config hardening, default-deny
- **navra-auth**: Deny-by-default for unannotated tools
- **navra-tools-gitlab**: Permission checks, input validation, timeout
- **navra-safety-hooks**: Scan all argument fields, not hardcoded set
- **navra-core,navra-safety-hooks**: Block non-text content in safety pipeline
- **adversarial-eval**: Use upstream MCP filesystem container
- **navra-auth**: Enforce path and tool subset in delegation validation
- **navra-protocol,navra-core**: Transport DoS hardening
- **navra-flow**: Global back-edge termination bound
- **navra-server**: Gate NoAuthenticator behind --dev-mode flag
- **navra-server**: Remove unwrap() chains + fix e2e test infrastructure (NAVRA-128)
- **navra-safety-hooks**: Thread tool annotations through hook pipeline (NAVRA-134)
- Formatting, clippy, and IFC e2e test infrastructure
- **protocol**: Gate TLS methods behind native-tls/rustls features
- **docs**: Accessibility — zero critical/serious on 5 of 6 pages
- **infra**: Enforce just for tests, fix hook regex, add process cleanup
- **auth**: Restore CapSigner import in idjag test module
- **docs**: Collapse Learn sidebar on non-Learn pages
- **docs**: Remove duplicate GitHub text link from navbar — icon is sufficient
- **tests**: Adapt adversarial E-H tests for stateless sessions
- **agent**: Key loop detector on all-args hash, not first arg only
- **examples**: Add gitignore to exclude target/ from standalone agent
- **examples**: Remove accidentally committed target/ artifacts
- **deps**: Use crates.io rmcp instead of local path dependency
- **auth**: Wire Bearer token from navra run to server via streamable HTTP
- Resolve all clippy warnings across workspace

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
- Add .gitignore for site and docs-site build artifacts
- Add TW27 navra-security split to roadmap
- Update lockfile, roadmap graph, openvino build parallelism
- Mark TW18, TW19, TW20 as completed in roadmap
- Mark NAVRA-075, NAVRA-076 as done
- Add LTO + strip optimization to mcp-filesystem build
- Mark NAVRA-077 as done — upstream tool ACL verified
- Cargo fmt, lean items, lean commands, docs
- Mark NAVRA-081/082 done, add new lean items, cargo fmt
- Mark NAVRA-087 done, update activity log
- Mark NAVRA-033/036/065/067/073/080/085 done, update activity log
- Mark NAVRA-078 done, update activity log
- Mark NAVRA-088 done, update activity log
- Mark NAVRA-072/074/032 done, update activity log
- Add NAVRA-090/091 — replace git and file modules with upstream MCPs
- Demote NAVRA-041/042 to medium — adoption (086) is the strategic priority
- Mark NAVRA-044/084 done
- Update activity log
- Loop activity log
- Loop activity log
- Groom backlog — split large items, add gates, acceptance criteria
- Loop activity log
- Add NAVRA-099 (ADR detect-only monitoring) and NAVRA-100 (ASSERT compliance eval)
- Loop activity log
- Loop activity log
- Loop activity log
- Mark NAVRA-024 done, update activity log
- Add NAVRA-101 (IFC+stateless guard) and NAVRA-102 (opaque taint token)
- Loop activity log
- Loop activity log
- Loop activity log
- Loop activity log
- Loop activity log
- NAVRA-121 done, loop complete — all 25 proof-gap items resolved
- Regenerate plan, close NAVRA-066 + NAVRA-068
- Loop activity log
- Session summary
- Refine 18 planned items + fix lint status values
- Session summary
- Loop summary
- Loop summary — 13 iterations
- Update Cargo.lock
- Lean-learn cycle — 53 findings applied
- **plan**: Fix 13 stale item statuses + add 15 improvement items
- **plan**: NAVRA-129 no-op — panic is in Kani proof, not production
- **plan**: Cancel NAVRA-137, add NAVRA-143/144 upstream MCP migration
- **plan**: NAVRA-144 blocked — exec module is sandbox infrastructure
- Loop summary — 12 iterations, 11 items completed
- **plan**: Refine NAVRA-144 — unblock with clean split strategy
- **plan**: Mark NAVRA-018 done — MCP 2026-07-28 already default
- **plan**: NAVRA-140 already done — stateless dispatch implemented
- **plan**: NAVRA-142 already done — OAuth iss + credential binding implemented
- Loop summary — 16 iterations, 15 items completed
- Loop summary — 2 iterations, 2 items completed
- **plan**: Add NAVRA-146 A2UI declarative UI support
- **plan**: Revise NAVRA-026 to React+PatternFly AG-UI dashboard
- Loop summary — 2 iterations, NAVRA-146 + NAVRA-026 completed
- Tech watch 2026-06-19 — 11 sources, 1 new item, 1 enriched
- **plan**: Promote 8 backlog items to planned with refined acceptance criteria
- Loop summary — 9 iterations, all approve-scope items completed
- **plan**: Promote 6 backlog items to planned with refined acceptance criteria
- **plan**: Mark 9 items from loop/2026-06-19-3 as done in item files
- Loop summary — 6 iterations, all approve-scope items completed
- **deps**: Remove unused async-stream dependency from navra-core
- **lean**: Add NAVRA-149 (rmcp migration done), NAVRA-150 (backlog)
- **branding**: Align identity across CLI, site, and crate metadata (NAVRA-055)
- Remove obsolete tool crate directories
- **branding**: Replace detailed logo with simplified geometric icon
- **plan**: Mark NAVRA-048, 050, 054, 055, 148 as done
- **plan**: Close NAVRA-062 — navra integrates OpenShell directly, NemoClaw bridge redundant
- **plan**: Add NAVRA-151..159 plan items
- **plan**: Mark NAVRA-156, NAVRA-155, NAVRA-153 done, update activity log
- **plan**: Loop complete — 3 items done
- **plan**: Add NAVRA-160 (network policy for wrap --sandbox), fix item statuses
- **plan**: Add NAVRA-161..168 — daemon, bundles, credential brokering
- **plan**: Mark NAVRA-161, 163, 164, 165 done, update activity log
- **plan**: Mark NAVRA-166, 167, 168 done — loop complete (7/8 items)
- Workspace lint config, rustfmt, clippy fixes across safety/auth/hooks
- Bump version to 0.2.0

### Merge

- Track teammate tasks with JoinHandle, abort on shutdown/timeout
- Protocol-level capability sandboxing
- Causal provenance graphs
- Cedar denial counter + MCP spec compliance tests (9z, 9i)
- Kill switch, circuit breaker, cross-tool transition tracking (2m, 9w)
- Composable skill source pipeline (1j)
- ACS YAML policy ingestion (TW18)
- NAVRA-121 memory stores Mutex refactor
- Loop/2026-06-19-3 — 9 items (NAVRA-064, 070, 147, 058, 071, 059, 061, 069, 049)
- Lazy-load specialization YAML (NAVRA-057)
- Operator libraries — conf.d-style config composition (NAVRA-060)
- PrivacyRouter — unified privacy detection coordinator (NAVRA-063)
- Navra 0.2.0 — model server, agent bundles, credential brokering

### Performance

- **rag**: Reduce key cloning in RRF fusion loops

### Security

- Complete ACP v0.2.0 implementation

### Tests

- **eval**: C3 adversarial security evaluation — 10/10 attacks blocked
- **eval**: E3b adaptive planner-trust attacks — 5/5 blocked
- **eval**: E3c Shadow Escape + Pale Fire, E3d encoding evasion — 4/4 blocked
- **acp**: Comprehensive test coverage for store and router
- **adversarial-eval**: Ignore a5 — upstream ACL gap found
- **security**: Add adversarial categories E-H and aggregate scoring (NAVRA-048)

### Bench

- **memory**: Temporal tree vs flat KnowledgeStore
- **memory**: Scale temporal tree to 100K/1M facts

### Style

- Apply clippy auto-fixes across 20 files in 12 crates (NAVRA-131)
- Rustfmt after clippy fixes


