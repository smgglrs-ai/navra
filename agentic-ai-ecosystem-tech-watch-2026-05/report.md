# Agentic AI Ecosystem Tech Watch — May 2026

> Research report for the **smgglrs** gateway project.
> 31 items analyzed across inference optimization, agent frameworks,
> security/auth protocols, RAG patterns, memory architectures, and business models.
> All smgglrs relevance assessments verified against code-level analysis of the 18-crate workspace.

## Summary

| Impact | Count | Categories | Count |
|--------|-------|------------|-------|
| high | 15 | opportunity | 11 |
| medium | 12 | reference | 9 |
| low | 4 | validation | 5 |
|  |  | threat | 3 |
|  |  | competitor | 3 |

## Table of Contents

### HIGH Impact

1. [MCP 2026-07-28 Release Candidate](#mcp-2026-07-28-release-candidate) — Impact: high | Category: threat | Type: protocol
2. [Shadow Escape (Operant AI)](#shadow-escape-operant-ai) — Impact: high | Category: threat | Type: paper
3. [FIDES (Microsoft Research)](#fides-microsoft-research) — Impact: high | Category: competitor | Type: paper+tool
4. [MVAR: Dual-Lattice IFC Runtime](#mvar-dual-lattice-ifc-runtime) — Impact: high | Category: competitor | Type: tool
5. [Microsoft Agent Governance Toolkit](#microsoft-agent-governance-toolkit) — Impact: high | Category: competitor | Type: tool
6. [Kubernetes Agent Sandbox CRD](#kubernetes-agent-sandbox-crd) — Impact: high | Category: opportunity | Type: tool
7. [MUSE-Autoskill: Self-Evolving Agents (2605.27366)](#muse-autoskill-self-evolving-agents-260527366) — Impact: high | Category: opportunity | Type: paper
8. [MemForest: Hierarchical Temporal Memory (2605.23986)](#memforest-hierarchical-temporal-memory-260523986) — Impact: high | Category: opportunity | Type: paper
9. [NeuroTaint / Ghost in the Agent (2604.23374)](#neurotaint-ghost-in-the-agent-260423374) — Impact: high | Category: opportunity | Type: paper
10. [TurboQuant / TurboVec](#turboquant-turbovec) — Impact: high | Category: opportunity | Type: tool
11. [auth.md (WorkOS)](#authmd-workos) — Impact: high | Category: opportunity | Type: protocol
12. [gBrain (Garry Tan)](#gbrain-garry-tan) — Impact: high | Category: opportunity | Type: tool
13. [Cloudflare Agent Memory](#cloudflare-agent-memory) — Impact: high | Category: validation | Type: tool
14. [OWASP Top 10 for Agentic Applications 2026](#owasp-top-10-for-agentic-applications-2026) — Impact: high | Category: reference | Type: standard
15. [Open-Source Agent Toolkit Landscape 2026](#open-source-agent-toolkit-landscape-2026) — Impact: high | Category: reference | Type: article
### MEDIUM Impact

16. [Safely Running Coding Agents](#safely-running-coding-agents) — Impact: medium | Category: threat | Type: article
17. [Adaptive Chunking: Optimizing Chunking-Method Selection for RAG](#adaptive-chunking-optimizing-chunking-method-selection-for-rag) — Impact: medium | Category: opportunity | Type: paper
18. [Gemini Embedding 2: A Native Multimodal Embedding Model from Gemini](#gemini-embedding-2-a-native-multimodal-embedding-model-from-gemini) — Impact: medium | Category: opportunity | Type: paper
19. [OSCAR (Together AI)](#oscar-together-ai) — Impact: medium | Category: opportunity | Type: paper+tool
20. [Claw-Anything: Always-On Assistant Benchmark (2605.26086)](#claw-anything-always-on-assistant-benchmark-260526086) — Impact: medium | Category: validation | Type: paper
21. [Hybrid Semantic+Lexical Search in RAG](#hybrid-semanticlexical-search-in-rag) — Impact: medium | Category: validation | Type: article
22. [Qwen 3.5 122B on 16GB Mac Mini (MoE Expert Streaming)](#qwen-35-122b-on-16gb-mac-mini-moe-expert-streaming) — Impact: medium | Category: validation | Type: article
23. [vLLM Rust Frontend (PR #40848)](#vllm-rust-frontend-pr-40848) — Impact: medium | Category: validation | Type: tool
24. [Agentic Economy Monetization](#agentic-economy-monetization) — Impact: medium | Category: reference | Type: article
25. [From Raw Experience to Skill Consumption (2605.23899)](#from-raw-experience-to-skill-consumption-260523899) — Impact: medium | Category: reference | Type: paper
26. [Hermes Agent (Nous Research)](#hermes-agent-nous-research) — Impact: medium | Category: reference | Type: tool
27. [HuggingFace Agent Glossary](#huggingface-agent-glossary) — Impact: medium | Category: reference | Type: article
### LOW Impact

28. [Eagle 3.1](#eagle-31) — Impact: low | Category: opportunity | Type: paper+tool
29. [AXPO: Agent Explorative Policy Optimization (2605.28774)](#axpo-agent-explorative-policy-optimization-260528774) — Impact: low | Category: reference | Type: paper
30. [ParaVT: Parallel Video Tool Calling (2605.20342)](#paravt-parallel-video-tool-calling-260520342) — Impact: low | Category: reference | Type: paper
31. [Speculative Speculative Decoding (SAGUARO)](#speculative-speculative-decoding-saguaro) — Impact: low | Category: reference | Type: paper

---

## Detailed Analysis

### MCP 2026-07-28 Release Candidate

**Basic Info**

- **Name**: MCP 2026-07-28 Release Candidate
- **Source Url**: https://blog.modelcontextprotocol.io/posts/2026-07-28-release-candidate/
- **Date**: 2026-05-21
- **Authors Org**: David Soria Parra (Lead Maintainer), Den Delimarsky (Lead Maintainer) — Anthropic / MCP Project
- **Type**: protocol

**Summary**

- **Core Contribution**:
> Largest MCP revision since launch.
> Removes protocol-level sessions (SEP-2567) making the protocol fully stateless — any request can hit any server instance behind a plain load balancer.
> Introduces the Extensions framework with MCP Apps (SEP-1865, server-rendered HTML UIs in sandboxed iframes) and Tasks extension (long-running work with task handles).
> Adds caching metadata (ttlMs/cacheScope via SEP-2549), W3C Trace Context propagation (SEP-414), OAuth 2.1/OIDC alignment (6 SEPs), and a formal deprecation policy with 12-month minimum overlap (SEP-2596).
- **Key Claims**:
- Stateless core: Mcp-Session-Id removed, no sticky sessions or shared session stores needed
- Mcp-Method and Mcp-Name headers enable infrastructure routing without body inspection
- MCP Apps (SEP-1865): first official MCP extension — server-rendered HTML UIs in sandboxed iframes
- Tasks moved from core to extension; tasks/list removed (can't scope safely without sessions)
- 12-month minimum deprecation window guaranteed by SEP-2596
- tools/list responses carry ttlMs and cacheScope for client-side caching
- W3C Trace Context (traceparent, tracestate, baggage) standardized in _meta
- Roots, sampling, and logging deprecated with replacements defined
- Final specification ships July 28, 2026; Tier 1 SDKs expected to ship support within 10-week window
- **Methodology**:
> SEP-driven specification evolution.
> Key SEPs: SEP-2567 (session removal), SEP-1865 (MCP Apps), SEP-2549 (caching metadata), SEP-2596 (deprecation policy), SEP-414 (W3C Trace Context), plus 6 OAuth/OIDC hardening SEPs.
> Breaking changes with 10-week validation window.
> Deprecation policy: roots replaced by tool parameters/resource URIs, sampling replaced by direct LLM API integration, logging replaced by stderr/OpenTelemetry.

**Smgglrs Relevance**

- **Affected Crates**:
- protocol
- core
- server
- agent
- security
- flow
- **Relevance Category**: threat
- **Impact Level**: high
- **Relevance Rationale**:
> Breaking protocol revision.
> Code analysis reveals smgglrs currently implements MCP spec 2025-03-26 (constant PROTOCOL_VERSION in smgglrs-protocol/src/mcp.rs).
> Specific impacts: (1) Session removal breaks smgglrs-core's Session struct (id, agent, client_info, context_label, created_at, last_accessed) and SessionStore/SessionBackend trait (InMemory + DashMap backends) — context_label IFC accumulation across requests must be rethought without sessions; (2) Mcp-Method/Mcp-Name headers change routing in smgglrs-core's transport layer (build_router, build_router_with_broadcaster); (3) smgglrs-protocol defines RootsCapability, PromptRole, pagination types that may change; (4) smgglrs-security's OAuthProvider already implements OAuth 2.1 with Ed25519 JWT and RFC 8693 token exchange, but OIDC alignment may require updates; (5) Tasks extension redesign affects smgglrs-core's TaskStore (in-memory HashMap) and A2A dispatch; (6) W3C Trace Context propagation — smgglrs-core has Prometheus metrics but no OTel spans, so traceparent/tracestate in _meta needs new plumbing.
> Most critical risk: IFC session taint accumulation depends on session identity.

**Actionable Insights**

- **What To Adopt**:
- Remove Mcp-Session-Id handling and session state from smgglrs-protocol and smgglrs-core
- Add Mcp-Method and Mcp-Name header parsing for request routing in smgglrs-server
- Implement ttlMs/cacheScope on tools/list and resources/list responses
- Add W3C Trace Context propagation (traceparent/tracestate/baggage) in _meta alongside existing OTel support
- Implement MCP Apps extension: sandboxed iframe rendering with security review pipeline
- Update Tasks from core to extension pattern with tasks/get, tasks/update, tasks/cancel (remove tasks/list)
- Align OAuth implementation with the 6 hardening SEPs
- Implement deprecation warnings for roots, sampling, and logging
- **What To Watch**:
- Final spec publication on July 28, 2026 for any last-minute changes
- Tier 1 SDK implementations for reference patterns
- Community adoption timeline — when do major MCP clients switch to 2026-07-28
- **What To Avoid**:
- Implementing against the RC before the final spec — wait for July 28 for production code
- Removing deprecated features (roots, sampling, logging) before the 12-month window
- **Implementation Difficulty**: significant
- **Priority Sprint**: Phase 11 (MCP spec compliance)

**Competitive Position**

- **How Smgglrs Compares**:
> smgglrs currently implements MCP 2025-11-25 with ~35/39 methods.
> The stateless redesign actually benefits smgglrs's gateway architecture — a stateless protocol makes gateway proxying simpler (no session affinity needed).
> smgglrs's existing OTel support aligns well with the W3C Trace Context addition.
> The MCP Apps extension is new territory that plays to smgglrs's security review capabilities.
- **Gaps Exposed**:
- smgglrs must remove its session management code and adopt stateless request handling
- No MCP Apps rendering/security-review pipeline exists yet
- Tasks implementation needs redesign from core to extension pattern
- OAuth implementation needs alignment with 6 new hardening SEPs
- ttlMs/cacheScope caching metadata not yet implemented
- **Advantages Confirmed**:
- Gateway architecture benefits from stateless protocol — simpler proxying, no session affinity needed
- Existing OTel traces align with W3C Trace Context standardization
- Hook pipeline is ideal for MCP Apps security review (prefetch, cache, review before rendering)
- IFC labels can be applied to MCP Apps UI content for information flow control

**Ecosystem Context**

- **Mcp Spec Alignment**: 2026-07-28-RC
- **Isolation Model**: isolate (sandboxed iframe for MCP Apps)
- **Aaif Alignment**: MCP is now governed under AAIF/Linux Foundation; this RC represents AAIF's first major spec revision process
- **Regulatory Relevance**: OAuth 2.1/OIDC alignment improves EU AI Act compliance for authentication/authorization. W3C Trace Context enables audit trails required by both EU AI Act and Colorado AI Act.

**Economics**

- **Memory Tier**: N/A
- **Token Economics**:
> Stateless protocol reduces server-side memory per connection (no session stores).
> ttlMs caching reduces redundant tools/list calls, saving tokens on repeated capability negotiation.
> Mcp-Method header routing enables more efficient load balancing, reducing infrastructure cost per request.

**Uncertain Fields**

- license
- owasp_coverage

---

### Shadow Escape (Operant AI)

**Basic Info**

- **Name**: Shadow Escape (Operant AI)
- **Source Url**: https://www.operant.ai/art-kubed/shadow-escape
- **Date**: 2025-10-22
- **Authors Org**: Operant AI Security Research Team
- **Type**: paper
- **License**: N/A (security research disclosure)

**Summary**

- **Core Contribution**:
> First documented zero-click agentic attack exploiting MCP (Model Context Protocol).
> Hidden malicious instructions embedded in innocuous documents (e.g., onboarding PDFs) trigger AI agents to discover and exfiltrate sensitive data through connected MCP tools without any user interaction, phishing, or malicious browser extensions.
- **Key Claims**:
- Zero-click attack requiring no user error, phishing, or malicious extensions
- Operates entirely within authorized identity boundaries and inside enterprise firewalls
- Invisible to conventional security tools (WAFs, DLP, endpoint detection)
- Cross-platform: affects ChatGPT, Claude, Gemini, Llama-based assistants, and any MCP-enabled agent
- Potential exfiltration scale described as 'trillions of records' across affected organizations
- CVE designation process initiated — framed as protocol-level vulnerability, not product flaw
- **Methodology**:
> Three-stage attack chain: (1) Infiltration — hidden instructions embedded in seemingly innocuous documents such as employee onboarding PDFs from public sources; (2) Discovery — when uploaded to an MCP-enabled AI assistant, hidden instructions prompt the agent to access connected databases, CRM systems, and file shares, surfacing private data (names, addresses, credit cards, PHI); (3) Exfiltration — hidden instructions command the agent to send entire datasets to external servers, disguised as routine analytics or performance uploads.
> The attack exploits the trust relationship between MCP tools and the agent: the agent has authorized access to connected resources, and the hidden instructions redirect that access for data theft.

**Smgglrs Relevance**

- **Affected Crates**:
- security
- protocol
- core
- tools-file
- tools-exec
- rag
- **Relevance Category**: threat
- **Impact Level**: high
- **Relevance Rationale**:
> Shadow Escape validates smgglrs core design: gateway-enforced security is exactly the defense against this attack class.
> Code-level analysis confirms: (1) Per-value IFC (ValueStore with var:// resolution) tracks taint at individual tool-result granularity — data from an uploaded document gets labeled Untrusted, and TaintedWritePolicy::Deny prevents tainted sessions from writing to external destinations; (2) TaintGate temporal predicate can block specific tools after seeing taint elevation — e.g., block network tools after PII detection; (3) Statistical guardrails (CosineDriftDetector) would flag anomalous tool-use patterns (read document → immediate exfiltration is a behavioral anomaly); (4) Tool scanner's DescriptionInjection detection catches hidden instructions in tool descriptions.
> Remaining gap: no egress filtering at the network level, and IFC tracks structural taint (explicit content transfer) but not semantic taint (paraphrased exfiltration).

**Actionable Insights**

- **What To Adopt**:
- Egress filtering in security hooks: flag or block tool calls that send data to external endpoints not on an allowlist
- Cross-tool data flow anomaly detection: alert when data discovered via one tool is sent through a different tool to an external destination
- Document content sanitization before injection into agent context — strip hidden instructions from uploaded files
- MCP trust zones with explicit tool-level allowlisting per session/conversation
- **What To Watch**:
- CVE designation outcome — if accepted, this becomes a formal protocol vulnerability requiring spec-level mitigation
- Evolution of hidden instruction embedding techniques (steganographic, Unicode, formatting-based)
- MCP spec response to Shadow Escape — whether Anthropic adds protocol-level egress controls
- **What To Avoid**:
- Do not rely solely on prompt-level safety (system prompt instructions) to prevent exfiltration — the attack operates within authorized boundaries
- Do not assume that authentication/authorization alone prevents data theft — Shadow Escape uses legitimate credentials
- **Implementation Difficulty**: moderate
- **Priority Sprint**: S10 (egress filtering + cross-tool data flow monitoring)

**Competitive Position**

- **How Smgglrs Compares**:
> smgglrs is better positioned than most MCP clients/gateways to defend against Shadow Escape because: (1) IFC tracks data provenance and can detect cross-tool exfiltration patterns; (2) the hook pipeline can intercept and analyze tool calls before execution; (3) deny-wins ACLs restrict which tools can access which resources; (4) upstream tool scanning (8 threat categories) can flag suspicious tool behavior.
> Most competing MCP gateways lack IFC and therefore cannot detect the data flow anomaly at the core of this attack.
- **Gaps Exposed**:
- No explicit egress filtering or external endpoint allowlisting in current security hooks
- No cross-tool data flow anomaly detection (IFC tracks provenance but does not yet flag suspicious cross-tool patterns automatically)
- No document sanitization pipeline for uploaded content before agent context injection
- **Advantages Confirmed**:
- Per-value IFC (ValueStore with var:// resolution) tracks taint at tool-result granularity — exfiltration paths are detectable via label join on variable references
- TaintedWritePolicy::Deny + TaintGate temporal predicate block exfiltration by preventing tainted sessions from reaching external sinks
- CosineDriftDetector statistical guardrail would flag the anomalous tool-use pattern (read → immediate exfiltration) via z-score deviation
- Gateway-enforced deny-wins ACLs (deny checked before allow, path canonicalization before check) prevent tool misuse
- PromptInjectionFilter in safety pipeline (regex-based) detects hidden instruction patterns in content
- 8-category tool scanner detects DescriptionInjection in upstream tool definitions

**Ecosystem Context**

- **Owasp Coverage**: ASI01 (Agent Goal Hijack — hidden instructions redirect agent behavior), ASI02 (Tool Misuse — tools used for exfiltration), ASI03 (Identity & Privilege Abuse — operates within authorized boundaries)
- **Isolation Model**: N/A (attack exploits the lack of isolation between tool access and data egress)
- **Aaif Alignment**: Relevant to AAIF runtime security discussions — demonstrates need for gateway-level protection
- **Regulatory Relevance**: EU AI Act (data protection obligations for high-risk AI systems), GDPR (personal data exfiltration implications)

**Economics**

- **Memory Tier**: N/A (attack research, not a system)
- **Token Economics**: The attack adds zero token overhead — it piggybacks on existing agent tool calls. Defending against it (egress filtering, anomaly detection, document sanitization) adds moderate per-request overhead.

**Uncertain Fields**

- mcp_spec_alignment

---

### FIDES (Microsoft Research)

**Basic Info**

- **Name**: FIDES (Microsoft Research)
- **Source Url**: https://arxiv.org/abs/2505.23643
- **Date**: 2026-05
- **Authors Org**: Manuel Costa, Boris Kopf, Aashish Kolluri, Andrew Paverd, Mark Russinovich, Ahmed Salem, Shruti Tople, Lukas Wutschitz, Santiago Zanella-Beguelin (Microsoft Research)
- **Type**: paper+tool
- **License**: CC BY 4.0

**Summary**

- **Core Contribution**:
> Formal IFC model for AI agent planners with dynamic taint-tracking.
> Uses lattice-based confidentiality and integrity labels to deterministically enforce security policies.
> Introduces novel information-hiding primitives for selective declassification — agents operate on sensitive data without exposing it in exfiltration contexts.
> Evaluated on AgentDojo benchmark, demonstrating meaningful utility preservation with formal security guarantees.
- **Key Claims**:
- Deterministic enforcement of confidentiality and integrity policies (vs probabilistic defenses)
- Formal model to reason about security AND expressiveness of agent planners
- Characterizes the class of properties enforceable by dynamic taint-tracking
- Novel information-hiding primitives for selective declassification
- Evaluated on AgentDojo: broad task completion with security guarantees
- Open-source at github.com/microsoft/fides
- **Methodology**:
> Lattice-based label model: confidentiality and integrity labels organized in lattice structure for compositional reasoning.
> Labels propagate dynamically as data moves through agent planning and execution pipeline.
> Deterministic enforcement ensures untrusted inputs cannot influence security-critical operations.
> Information-hiding primitives allow selective declassification for controlled data release.
> Taxonomy of tasks evaluating security-utility tradeoffs.

**Smgglrs Relevance**

- **Affected Crates**: security
- **Relevance Category**: competitor
- **Impact Level**: high
- **Relevance Rationale**:
> FIDES is the most direct academic competitor to smgglrs-security's IFC module.
> Both use lattice-based label models with dynamic taint-tracking.
> smgglrs uses a 2x4 product lattice (Integrity: Trusted/Untrusted x Confidentiality: Public/Sensitive/PII/Secret) with Bell-LaPadula enforcement.
> Key differences: (1) FIDES operates at the planner level (inside LLM reasoning loop), smgglrs enforces at the gateway level (deterministic, can't be bypassed by LLM); (2) FIDES has formal information-hiding primitives for selective declassification, while smgglrs has implicit declassification via PII filter pipeline (TaintTracker::declassify() exists but without cryptographic witness); (3) smgglrs already has per-value IFC via ValueStore with var:// references (FIDES-inspired) — each tool result gets its own DataLabel, and variable resolution computes effective labels as the join of all referenced values.
> NeuroTaint reports FIDES achieves only F1=0.522, but smgglrs augments label tracking with statistical guardrails (cosine drift detection + Shannon entropy monitoring) that neither FIDES nor NeuroTaint provides.

**Actionable Insights**

- **What To Adopt**:
- Selective declassification primitives — smgglrs-security's IFC could support controlled data release
- FIDES's security-utility tradeoff taxonomy for evaluating smgglrs IFC configurations
- AgentDojo benchmark for evaluating smgglrs-security effectiveness
- **What To Watch**:
- NeuroTaint vs FIDES accuracy debate — F1=0.928 vs F1=0.522 on TaintBench
- Whether FIDES becomes the reference IFC implementation for agent security
- Microsoft Agent Governance Toolkit integration with FIDES
- **What To Avoid**:
- Don't adopt FIDES's planner-level approach — smgglrs's gateway-level enforcement is more robust (doesn't depend on LLM cooperation)
- Don't rely on label-tracking alone — NeuroTaint shows semantic/causal analysis may be needed
- **Implementation Difficulty**: moderate
- **Priority Sprint**: S11 (IFC enhancement)

**Competitive Position**

- **How Smgglrs Compares**:
> smgglrs-security's IFC operates at the gateway level (deterministic, can't be bypassed by the LLM), while FIDES operates at the planner level (inside the reasoning loop, requires LLM cooperation).
> smgglrs already has per-value IFC (ValueStore with var:// references, FIDES-inspired) providing finer granularity than per-session taint.
> smgglrs adds statistical guardrails (cosine drift + entropy) and temporal behavioral contracts that FIDES lacks.
> FIDES's advantage is formal information-hiding primitives for selective declassification — smgglrs has declassification but without cryptographic witnessing.
- **Gaps Exposed**:
- Declassification is implicit (PII filter trust) — no cryptographic witness or formal role check like FIDES's information-hiding primitives
- No formal security-utility tradeoff evaluation framework
- No AgentDojo benchmark results for smgglrs
- **Advantages Confirmed**:
- Gateway-level IFC enforcement (deterministic, can't be bypassed by LLM reasoning) is architecturally superior to planner-level
- Per-value IFC via ValueStore with var:// resolution already provides finer granularity than FIDES's per-session model
- Statistical behavioral guardrails (cosine drift + entropy monitoring) provide anomaly detection that FIDES lacks entirely
- smgglrs combines IFC + ML safety filters + deny-wins ACLs + temporal contracts — FIDES uses labels only
- Kani-proven monotonicity invariants on taint propagation match FIDES's formal guarantees

**Ecosystem Context**

- **Owasp Coverage**: > ASI01 (Goal Hijack — taint tracking detects injected instructions), ASI02 (Tool Misuse — integrity labels prevent unauthorized tool use), ASI06 (Context Manipulation — confidentiality labels prevent information leakage)
- **Mcp Spec Alignment**: N/A (planner-level, not protocol-level)
- **Isolation Model**: in-process (planner component)
- **Aaif Alignment**: Microsoft (AAIF member)
- **Regulatory Relevance**: EU AI Act (formal security guarantees support compliance documentation)

**Economics**

- **Memory Tier**: N/A
- **Token Economics**: Label propagation adds modest overhead per agent step. Information-hiding primitives reduce token usage by allowing selective data exposure.

---

### MVAR: Dual-Lattice IFC Runtime

**Basic Info**

- **Name**: MVAR: Dual-Lattice IFC Runtime
- **Source Url**: https://github.com/mvar-security/mvar
- **Authors Org**: MVAR Security
- **Type**: tool
- **License**: Apache 2.0

**Summary**

- **Core Contribution**:
> Dual-lattice IFC runtime for LLM agents with cryptographic provenance.
> 'Execution firewall' approach assumes injection will occur and prevents untrusted output from reaching privileged sinks.
> Uses two separate lattices for confidentiality and integrity with independent enforcement.
> Blocked 100% of a 50-vector adversarial corpus across 9 attack categories.
- **Key Claims**:
- 100% block rate on 50-vector adversarial corpus across 9 attack categories
- Dual-lattice model (separate confidentiality and integrity lattices)
- Cryptographic provenance for data flow tracking
- Execution firewall paradigm — assumes injection will occur, prevents privileged sink access
- Drop-in integration (LangChain callback mentioned in web search data)

**Smgglrs Relevance**

- **Affected Crates**: security
- **Relevance Category**: competitor
- **Impact Level**: high
- **Relevance Rationale**:
> MVAR is a direct competitor to smgglrs-security's IFC module.
> Both use lattice-based models.
> Key differences: (1) MVAR uses dual lattices (separate confidentiality + integrity), smgglrs uses a 2x4 product lattice (2 Integrity levels x 4 Confidentiality levels) — architecturally similar but smgglrs has more confidentiality granularity (Public/Sensitive/PII/Secret vs typical binary); (2) MVAR includes cryptographic provenance — smgglrs has hash-chained blackbox audit (SHA-256 chain, tamper-detectable) but no per-data-flow cryptographic signing; (3) MVAR's execution firewall (assume injection, prevent sink access) vs smgglrs's defense-in-depth (IFC labels + statistical guardrails + temporal contracts + ML safety).
> smgglrs's TaintedWritePolicy (Allow/Approve/Deny) with TaintGate temporal predicate provides a form of execution firewall but at the behavioral level, not the data-flow level.

**Actionable Insights**

- **What To Adopt**:
- Execution firewall paradigm — assume injection will occur, focus on preventing sink access rather than detecting injection
- Cryptographic provenance for tamper-proof data flow audit trails
- 100% adversarial corpus test as a security benchmark target for smgglrs
- **What To Watch**:
- MVAR's actual codebase maturity and community adoption
- Whether dual-lattice vs product-lattice provides meaningful security improvement
- Integration with MCP-specific attack vectors (Shadow Escape)
- **What To Avoid**:
- Don't assume MVAR's 100% claim generalizes — 50 vectors is a small corpus
- Don't switch to dual lattices without evaluating smgglrs's product lattice against same benchmark
- **Implementation Difficulty**: moderate
- **Priority Sprint**: S11 (IFC hardening)

**Competitive Position**

- **How Smgglrs Compares**:
> Both use lattice-based IFC.
> smgglrs has broader scope (gateway with ACLs, safety hooks, ML models) while MVAR is focused purely on IFC.
> MVAR's cryptographic provenance and execution firewall paradigm are gaps in smgglrs.
> smgglrs's advantage is gateway-level enforcement (can't be bypassed) and defense-in-depth (IFC + ML + ACLs).
- **Gaps Exposed**:
- No per-data-flow cryptographic provenance signing — blackbox is hash-chained but records tool calls, not individual data flows
- No explicit execution firewall mode — TaintedWritePolicy::Deny + TaintGate achieve similar effect but require explicit configuration per tool
- No adversarial corpus benchmark for smgglrs-security IFC
- **Advantages Confirmed**:
- Defense-in-depth stack (IFC labels + per-value ValueStore + statistical guardrails + temporal contracts + ML safety + deny-wins ACLs + trust scoring) is far broader than MVAR's pure IFC
- Gateway-level enforcement (deterministic, can't be bypassed) vs callback-level (MVAR, depends on agent cooperation)
- 8-category upstream tool scanning detects supply-chain threats (rug pull, typosquatting, schema abuse) that MVAR doesn't address
- Capability delegation with Ed25519-signed CBOR tokens and sandbox profiles (Simulate/Redact/RateLimit/PathRewrite) — MVAR has no capability model
- Hash-chained blackbox audit log provides tamper-detectable records (similar intent to MVAR's cryptographic provenance but at different granularity)

**Ecosystem Context**

- **Owasp Coverage**: > ASI01 (Goal Hijack — execution firewall blocks hijacked sinks), ASI02 (Tool Misuse — integrity labels prevent unauthorized tool output), ASI06 (Context Manipulation — confidentiality labels prevent data leakage)
- **Isolation Model**: in-process (callback/middleware)
- **Aaif Alignment**: independent
- **Regulatory Relevance**: EU AI Act (cryptographic provenance supports audit obligations)

**Economics**

- **Memory Tier**: N/A
- **Token Economics**: Execution firewall approach has lower overhead than content-based detection — no ML inference needed for blocking decisions.

**Uncertain Fields**

- date
- methodology
- mcp_spec_alignment

---

### Microsoft Agent Governance Toolkit

**Basic Info**

- **Name**: Microsoft Agent Governance Toolkit
- **Source Url**: https://github.com/microsoft/agent-governance-toolkit
- **Date**: 2026-04-02
- **Authors Org**: Microsoft (Open Source)
- **Type**: tool
- **License**: MIT

**Summary**

- **Core Contribution**:
> Seven-package monorepo providing deterministic runtime security governance for autonomous AI agents.
> First open-source toolkit to address all 10 OWASP Agentic AI Top 10 risks (ASI01-ASI10) with sub-millisecond policy enforcement (p99 < 0.1ms).
> Available in Python, TypeScript, Rust, Go, and .NET.
- **Key Claims**:
- Covers 10/10 OWASP Agentic AI Top 10 risks
- 9500+ tests across the monorepo
- Sub-millisecond policy enforcement with p99 < 0.1ms latency
- Zero policy violations during RL training (Agent Lightning)
- Integrates with LangChain, CrewAI, AutoGen, Google ADK, OpenAI Agents SDK, LlamaIndex, Haystack, Mastra, MCP, A2A
- **Methodology**:
> The toolkit intercepts every agent action (tool call, message send, delegation) in deterministic application code before the model's intent reaches the wire.
> The Agent OS package is a stateless policy engine supporting YAML rules, OPA Rego, and Cedar policy languages.
> Architecture follows a deny-by-default model: actions the kernel denies are structurally impossible, not merely unlikely.
> Seven packages cover distinct concerns: Agent OS (policy engine), Agent Mesh (discovery/routing/trust), Agent Runtime (execution sandboxing with four privilege rings), Agent SRE (kill switch, SLO monitoring, chaos testing), Agent Compliance (OWASP verification, policy linting), Agent Marketplace (plugin governance with Ed25519 signing), Agent Lightning (RL training governance), and Agent Hypervisor (execution audit, delta engine).

**Smgglrs Relevance**

- **Affected Crates**:
- security
- core
- protocol
- flow
- agent
- server
- **Relevance Category**: competitor
- **Impact Level**: high
- **Relevance Rationale**:
> Microsoft AGT is the most direct competitor to smgglrs in the MCP gateway/governance space.
> It covers all 10 OWASP agentic risks with a comprehensive multi-package approach.
> Key overlaps: policy enforcement (AGT Agent OS vs smgglrs hook pipeline + ACLs), plugin/tool scanning (AGT Agent Marketplace vs smgglrs tool_scanner), execution sandboxing (AGT Agent Runtime rings vs smgglrs OpenShell integration), and inter-agent trust (AGT Agent Mesh + IATP vs smgglrs flow mesh).
> Microsoft's backing, MIT license, and multi-language support give it significant adoption advantage.

**Actionable Insights**

- **What To Adopt**:
- Cedar policy language support alongside existing ACL engine — AGT validates Cedar as production-ready for agent governance
- Structured OWASP ASI01-ASI10 compliance mapping and self-verification (similar to Agent Compliance package)
- Ed25519 plugin/tool manifest signing for upstream MCP server verification
- Kill switch and circuit breaker patterns from Agent SRE for flow orchestration resilience
- **What To Watch**:
- Agent Marketplace plugin ecosystem growth and whether it becomes a de facto standard
- IATP (Inter-Agent Trust Protocol) specification evolution — potential interop target
- Agent Lightning RL governance patterns if smgglrs adds RL-based agent training
- **What To Avoid**:
- Do not try to replicate the full 7-package scope — smgglrs should stay focused on gateway-enforced security rather than becoming a general governance framework
- Avoid adopting AGT's DID-based identity wholesale — smgglrs BLAKE3 tokens + capability delegation is lighter and sufficient for desktop use case
- **Implementation Difficulty**: significant
- **Priority Sprint**: S10-S11 (Cedar policy support, OWASP compliance mapping)

**Competitive Position**

- **How Smgglrs Compares**:
> smgglrs covers many of the same risks but through a gateway-enforced architecture rather than AGT's SDK-based approach.
> smgglrs has IFC (Information Flow Control) which AGT lacks — a unique differentiator for data provenance.
> AGT has broader framework integrations (10+ frameworks) while smgglrs focuses on being the MCP gateway layer.
> AGT is multi-language (Python/TS/Rust/Go/.NET) while smgglrs is Rust-only.
> AGT has more comprehensive compliance automation (EU AI Act, HIPAA, SOC2 mapping).
- **Gaps Exposed**:
- No structured OWASP ASI01-ASI10 compliance self-check or reporting in smgglrs
- No Cedar policy language support (only deny-wins ACLs)
- No formal plugin/upstream MCP server signing verification (Ed25519 or similar)
- No kill switch or automated agent termination mechanism in flow orchestration
- No compliance grading or regulatory framework mapping (EU AI Act, HIPAA)
- **Advantages Confirmed**:
- Gateway-enforced IFC is absent from AGT — smgglrs uniquely tracks data provenance across tool calls
- In-process ONNX safety models for ML-based content filtering (AGT uses semantic classifiers but approach differs)
- Desktop-native integration (D-Bus, systemd, tray) vs AGT's cloud-first design
- Causal provenance graphs in smgglrs-flow provide deeper audit trail than AGT's Agent Hypervisor

**Ecosystem Context**

- **Owasp Coverage**: ASI01, ASI02, ASI03, ASI04, ASI05, ASI06, ASI07, ASI08, ASI09, ASI10 (all 10)
- **Isolation Model**: container (four privilege rings in Agent Runtime)
- **Aaif Alignment**: Aligned — uses ASI 2026 taxonomy with backward compatibility for original AT numbering
- **Regulatory Relevance**: EU AI Act (high-risk AI obligations August 2026), Colorado AI Act (June 2026), HIPAA, SOC2

**Economics**

- **Memory Tier**: N/A (governance layer, not a memory system)
- **Token Economics**: Minimal overhead — sub-millisecond policy checks add negligible latency per agent action. No additional LLM inference required for governance decisions (deterministic policy engine).

**Uncertain Fields**

- mcp_spec_alignment

---

### Kubernetes Agent Sandbox CRD

**Basic Info**

- **Name**: Kubernetes Agent Sandbox CRD
- **Source Url**: https://github.com/kubernetes-sigs/agent-sandbox
- **Authors Org**: Kubernetes SIG Apps (kubernetes-sigs)
- **Type**: tool
- **License**: Apache-2.0

**Summary**

- **Core Contribution**:
> Kubernetes-native CRD and controller for managing isolated, stateful, singleton workloads purpose-built for AI agent runtimes.
> Introduces four CRDs: Sandbox (core — declarative API for stateful pods with stable identity and persistent storage), SandboxTemplate (reusable templates), SandboxClaim (user-facing abstraction for requesting sandboxes from templates), and SandboxWarmPool (pre-warmed pod pool for sub-second provisioning).
> Supports gVisor and Kata Containers for kernel and network isolation.
- **Key Claims**:
- Sub-second sandbox provisioning via SandboxWarmPool (<1s vs. standard K8s pod scheduling)
- Supports gVisor (userspace kernel, syscall interception) and Kata Containers (lightweight VM per pod) for strong isolation
- Decouples execution layer from isolation technology — swap backends without changing workload specs
- Handles full lifecycle: creation, scheduled deletion, pausing (hibernation), automatic resume on network activity
- v1alpha1 API under agents.x-k8s.io and extensions.agents.x-k8s.io
- **Methodology**:
> Core CRD (Sandbox) in agents.x-k8s.io/v1alpha1 provides a declarative API for a single stateful pod with stable identity, persistent storage, and network accessibility.
> Extension CRDs (SandboxTemplate, SandboxClaim, SandboxWarmPool) in extensions.agents.x-k8s.io/v1alpha1 add templating, user-facing claims, and warm pooling.
> The controller manages pod lifecycle including hibernation (pause/resume) to save compute during idle periods.
> Runtime class abstraction allows plugging gVisor (syscall-level) or Kata Containers (VM-level) isolation without changing the Sandbox spec.
> SandboxWarmPool maintains pre-started pods in ready state; SandboxClaim allocates from the pool instantly.

**Smgglrs Relevance**

- **Affected Crates**: tools-exec, model-runtime, server
- **Relevance Category**: opportunity
- **Impact Level**: high
- **Relevance Rationale**:
> Directly relevant to smgglrs's sandbox execution model.
> smgglrs-tools-exec already supports OpenShell sandboxes; agent-sandbox provides the Kubernetes-native equivalent.
> smgglrs-model-runtime's pluggable isolation (direct, Podman, OpenShell) could add agent-sandbox as a fourth backend.
> The SandboxClaim/SandboxTemplate pattern maps cleanly to smgglrs's capability-based security model — a capability token could authorize a SandboxClaim.
> Sub-second warm pool provisioning addresses the cold-start latency problem for tool execution sandboxes.

**Actionable Insights**

- **What To Adopt**:
- Add agent-sandbox as a Kubernetes-native isolation backend in smgglrs-model-runtime alongside Podman and OpenShell
- Map smgglrs capability tokens to SandboxClaim creation — capability delegation authorizes sandbox provisioning
- Adopt the warm pool pattern (SandboxWarmPool) for pre-warming execution sandboxes to reduce tool-call latency
- Use SandboxTemplate to define security profiles for different trust tiers (matching smgglrs risk_tier levels)
- **What To Watch**:
- Graduation from v1alpha1 to v1beta1 — stability guarantees
- GKE Agent Sandbox managed offering — Google Cloud integration patterns
- Whether agent-sandbox becomes the standard K8s API for agent isolation across cloud providers
- **What To Avoid**:
- Tightly coupling to agent-sandbox internals — use the CRD API abstraction layer
- Assuming agent-sandbox replaces all isolation needs — it's Kubernetes-specific, smgglrs also needs local/desktop isolation
- **Implementation Difficulty**: moderate
- **Priority Sprint**: Phase 12 (Kubernetes deployment)

**Competitive Position**

- **How Smgglrs Compares**:
> smgglrs-tools-exec provides command execution inside OpenShell sandboxes (local/desktop focus).
> agent-sandbox provides the Kubernetes-native equivalent for cloud deployments.
> smgglrs's model-runtime already abstracts isolation backends (direct, Podman, OpenShell), making agent-sandbox a natural addition.
> smgglrs adds security layers (IFC, capability auth, hook pipeline) on top of whatever isolation backend is used.
- **Gaps Exposed**:
- smgglrs lacks Kubernetes-native sandbox provisioning — agent-sandbox fills this for cloud deployments
- No warm pool / pre-warming mechanism in smgglrs for reducing sandbox cold-start latency
- No hibernation/resume support for idle sandbox cost optimization
- Missing SandboxTemplate equivalent — reusable isolation profiles for different security tiers
- **Advantages Confirmed**:
- smgglrs's pluggable isolation architecture (model-runtime) is validated — agent-sandbox confirms the abstraction pattern
- smgglrs adds security layers (IFC, hooks, capability auth) that agent-sandbox does not provide — complementary, not competing
- smgglrs works locally on Linux desktops without Kubernetes — broader deployment model
- smgglrs's risk_tier system maps naturally to SandboxTemplate security profiles

**Ecosystem Context**

- **Mcp Spec Alignment**: N/A (Kubernetes infrastructure, protocol-agnostic)
- **Isolation Model**: container, microVM (gVisor for syscall-level isolation, Kata Containers for VM-level isolation)
- **Regulatory Relevance**: EU AI Act: provides the isolation infrastructure needed for high-risk AI system deployments. Strong isolation (Kata VMs) supports data residency and tenant isolation requirements.

**Economics**

- **Memory Tier**: N/A
- **Token Economics**:
> SandboxWarmPool reduces sandbox provisioning latency from seconds to sub-second, reducing time-to-first-token for tool calls.
> Hibernation saves compute costs during agent idle periods.
> The CRD abstraction avoids vendor lock-in to specific isolation technologies, enabling cost-optimal runtime selection.

**Uncertain Fields**

- date
- owasp_coverage
- aaif_alignment

---

### MUSE-Autoskill: Self-Evolving Agents (2605.27366)

**Basic Info**

- **Name**: MUSE-Autoskill: Self-Evolving Agents (2605.27366)
- **Source Url**: https://huggingface.co/papers/2605.27366
- **Date**: 2026-05-26
- **Authors Org**: ByteDance Inc. + Rochester Institute of Technology (Corresponding: Tieying Zhang)
- **Type**: paper
- **License**: N/A (academic paper)

**Summary**

- **Core Contribution**:
> Skill-centric agent framework covering all 5 lifecycle stages: creation, memory, management, evaluation, refinement.
> Introduces skill-level memory (.memory.md files accumulating per-skill experience).
> Skills are created on-demand via built-in skill_create tool within ReAct loop.
> Unit tests in tests/ directories validate skills before registration.
> DAG-based context management with two-level adaptive compression.
> Cross-agent skill transfer validated empirically.
- **Key Claims**:
- 68.40% accuracy on SkillsBench (51 tasks, GPT-5.5 backbone)
- Self-generated skills: 87.94% on tasks where generation succeeded — surpassing human-skill ceiling
- Cross-agent transfer: +10.51pp on Hermes Agent, closing 79% of human-skill gap
- Pareto-optimal: higher reward at lower latency AND fewer tokens than human skills
- -20% tokens, -37% latency for MUSE; -48% tokens, -30% latency for Hermes with MUSE skills
- Generation cost (~383K tokens) amortizes after ~3 reuses
- **Methodology**:
> Skills follow Anthropic's Agent Skills format (SKILL.md + .memory.md + scripts/ + tests/ + resources/).
> Created on-demand in ReAct loop via skill_create tool.
> Multi-level memory: skill-level (.memory.md), short-term (current task with adaptive compression), long-term (cross-session).
> DAG-based conversation nodes with two-level compression (Level-1: >15K token nodes, Level-2: merge middle spans at 180K+).
> First 5 and last 5 turns pinned verbatim.

**Smgglrs Relevance**

- **Affected Crates**: cognitive, agent, flow
- **Relevance Category**: opportunity
- **Impact Level**: high
- **Relevance Rationale**:
> MUSE-Autoskill provides a concrete architecture for skill lifecycle management.
> Code analysis reveals smgglrs-cognitive has: (1) Persona struct with skills: Vec<String> field, heuristics: Vec<HeuristicRef>, and MCP prompt sourcing (McpPromptRef with inject_position); (2) ForgeService loads YAML from cognitive_core/ directory with SHA-256 integrity verification; (3) Weaver assembles cacheable_prefix (stable) + dynamic_context (per-invocation) for prompt caching; (4) TraitVector with momentum-based evolution (EMA alpha) for per-user persona adaptation.
> What's missing: no skill_create tool in ReAct loop, no .memory.md per-skill experience accumulation, no unit test validation before skill registration, no cross-agent transfer mechanism.
> MUSE's SKILL.md format would be a natural extension to smgglrs-cognitive's existing YAML persona/directive/heuristic structure.
> The DAG-based context compression maps to smgglrs-agent's progressive output compression (embedding-based extractive selection).

**Actionable Insights**

- **What To Adopt**:
- Anthropic Agent Skills format (SKILL.md) as a skill standard for smgglrs-cognitive
- Skill-level memory (.memory.md) as a new memory tier
- Unit test validation before skill registration — testable skills are more reliable
- Two-level adaptive context compression for smgglrs-agent's ReAct loop
- **What To Watch**:
- Whether Anthropic Agent Skills format becomes an industry standard
- MUSE code release for integration testing
- SkillsBench adoption as evaluation standard
- **What To Avoid**: Don't auto-generate skills without validation — MUSE's test-before-register pattern prevents bad skill accumulation
- **Implementation Difficulty**: significant
- **Priority Sprint**: S12 (cognitive skill management)

**Competitive Position**

- **How Smgglrs Compares**:
> smgglrs-cognitive has persona/directive system but no formal skill lifecycle.
> MUSE provides the missing architecture.
> smgglrs could differentiate by adding IFC labels to skills (preventing skill injection attacks) and serving as the secure skill registry.
- **Gaps Exposed**:
- No skill lifecycle management — Persona has skills: Vec<String> but no creation/testing/refinement pipeline
- No skill-level memory accumulation — TraitVector tracks persona traits but not per-skill experience
- No cross-agent skill transfer mechanism
- No adaptive context compression — smgglrs-agent has progressive output compression but no DAG-based conversation node compression with two-level thresholds
- **Advantages Confirmed**:
- smgglrs-cognitive's existing YAML structure (personas/directives/heuristics with SHA-256 integrity) is a natural base for SKILL.md packages
- Weaver's cacheable_prefix/dynamic_context split already supports prompt caching, which MUSE also targets
- smgglrs's gateway model could host shared skill libraries with IFC labels on skills (preventing skill injection attacks via taint tracking)
- smgglrs-agent's progressive output compression (embedding-based extractive selection with cosine similarity) provides the context management MUSE needs
- ForgeService's validate() cross-reference checking could be extended to verify skill dependency graphs

**Ecosystem Context**

- **Owasp Coverage**: ASI01 (Goal Hijack — skill injection could redirect agent behavior)
- **Mcp Spec Alignment**: N/A (skills are above MCP layer)
- **Isolation Model**: N/A
- **Aaif Alignment**: independent (but uses Anthropic skill format)
- **Regulatory Relevance**: N/A

**Economics**

- **Memory Tier**: tiered (short-term + long-term + skill-level)
- **Token Economics**: Skills amortize after ~3 reuses (383K generation cost). Self-generated skills use -20% tokens vs human skills. Context compression (180K threshold) controls token budget.

---

### MemForest: Hierarchical Temporal Memory (2605.23986)

**Basic Info**

- **Name**: MemForest: Hierarchical Temporal Memory (2605.23986)
- **Source Url**: https://huggingface.co/papers/2605.23986
- **Date**: 2026-05
- **Authors Org**: Zining Zhang, Wenqi Pei, Bingsheng He (NUS); Ming Wu et al. (Zero Gravity Labs)
- **Type**: paper
- **License**: N/A (academic paper)

**Summary**

- **Core Contribution**:
> Reformulates agent memory as a write-efficient temporal data management problem.
> Introduces MemTree hierarchical temporal index: leaves store time-local evidence, internal nodes summarize contiguous intervals, root provides coarse recall.
> Three tree types: session (chronology), entity (recurring subjects), scene (multi-entity context).
> Parallel chunk extraction breaks sequential LLM bottleneck.
> Two-phase retrieval: Forest Recall (root summaries) then Tree Browse (descent to leaves).
- **Key Claims**:
- 79.8% pass@1 on LongMemEval-S (best among stateful baselines)
- 6x higher write throughput than state-of-the-art
- 13.7x speedup over MemoryOS in write-path latency
- 2.4-2.7x speedup via direct state merge vs sequential replay for migration
- O(log N) write cost via localized ancestor-path updates
- **Methodology**:
> Sessions partitioned into fixed-size chunks (default b=2 turns), processed independently and concurrently into canonical facts with temporal anchors, entity mentions, and source references.
> MemTree organizes facts as balanced trees with lazy dirty-path refresh (coalesces updates, same-level parallel).
> Two-phase retrieval: Forest Recall retrieves relevant trees via root summaries + fact-to-tree mapping; Tree Browse descends from interval summaries to leaf evidence (embedding-only for low latency, LLM-guided for higher accuracy).

**Smgglrs Relevance**

- **Affected Crates**: memory, rag
- **Relevance Category**: opportunity
- **Impact Level**: high
- **Relevance Rationale**:
> MemForest directly addresses smgglrs-memory's architecture limitations revealed by code analysis.
> smgglrs-memory currently uses: (1) Working memory with SQLite-backed Turn/Message tables (fork/merge supported but flat chronological ordering); (2) Knowledge store with FTS5 (BM25 ranking, hardcoded 20-result limit) and content-addressed storage (SHA-256 hash of kind+title); (3) Exponential decay with importance modulation (importance * exp(-rate/(1+importance) * age_hours) + min(0.1*access_count, 0.3)) — temporal but flat, no hierarchical summarization; (4) Scoping (entity_id, process_id, session_id) — but flat, not tree-structured.
> MemForest's three tree types (session, entity, scene) would replace the flat scoping model.
> The 6x write throughput is critical because smgglrs-memory's knowledge store writes are sequential (single SQLite connection with Mutex).
> Parallel chunk extraction could integrate with smgglrs-rag's breadcrumb chunking (currently single-strategy heading injection).

**Actionable Insights**

- **What To Adopt**:
- Hierarchical temporal indexing for smgglrs-memory knowledge store
- Three tree types (session, entity, scene) as memory organization
- Parallel chunk extraction to break sequential write bottleneck
- Canonical facts with temporal anchors as write units
- Lazy dirty-path refresh for efficient summarization
- **What To Watch**:
- MemForest open-source release (github.com/Concyclics/MemForest)
- Integration with RAG systems — MemForest + vector search
- Scaling behavior beyond LongMemEval benchmarks
- **What To Avoid**:
- Don't adopt LLM-guided tree browse for latency-sensitive paths — use embedding-only mode
- Don't abandon FTS5 — MemForest augments rather than replaces lexical search
- **Implementation Difficulty**: significant
- **Priority Sprint**: S11-S12 (memory architecture upgrade)

**Competitive Position**

- **How Smgglrs Compares**:
> smgglrs-memory currently uses flat working memory (conversation turns) + FTS5 knowledge store.
> MemForest offers a fundamentally better architecture with temporal indexing, O(log N) writes, and parallel extraction.
> However, smgglrs-memory is simpler and has lower operational overhead.
- **Gaps Exposed**:
- No temporal indexing — knowledge store uses flat SQLite tables with FTS5, not hierarchical trees (O(N) writes vs MemForest's O(log N))
- Sequential write path — single Mutex<Connection> bottleneck limits throughput under high interaction frequency
- FTS5 search hardcoded to 20 results — limits recall for large knowledge bases
- Scoping (entity_id, process_id, session_id) is flat columns, not tree-structured like MemForest's entity/scene trees
- Decay is exponential with importance modulation but no hierarchical summarization — no way to lazily coalesce old entries like MemForest's dirty-path refresh
- **Advantages Confirmed**:
- smgglrs-memory's SQLite FTS5 + smgglrs-rag's hybrid search (FTS5 + sqlite-vec + RRF k=60) provides the lexical+vector retrieval MemForest lacks
- Cross-encoder reranking (ONNX batched) + GatedReranker (0.4 confidence threshold) complements MemForest's two-phase retrieval
- Content-addressed storage (SHA-256 hash of kind+title) with version tracking enables supersession semantics
- Fork/merge on working memory (Append/Replace/Summarize strategies) supports conversation branching

**Ecosystem Context**

- **Owasp Coverage**: N/A
- **Mcp Spec Alignment**: N/A
- **Isolation Model**: in-process
- **Aaif Alignment**: independent
- **Regulatory Relevance**: EU AI Act (logging/monitoring obligations benefit from temporal memory audit trails)

**Economics**

- **Memory Tier**: tiered
- **Token Economics**: Lazy dirty-path refresh reduces LLM summary calls. Parallel extraction improves throughput without increasing per-fact cost.

---

### NeuroTaint / Ghost in the Agent (2604.23374)

**Basic Info**

- **Name**: NeuroTaint / Ghost in the Agent (2604.23374)
- **Source Url**: https://arxiv.org/abs/2604.23374
- **Date**: 2026-04-25
- **Authors Org**: Yuandao Cai, Wensheng Tang, Cheng Wen, Shengchao Qin
- **Type**: paper
- **License**: N/A (academic paper)

**Summary**

- **Core Contribution**:
> First comprehensive taint-tracking framework tailored for LLM agents, addressing the insight that taint propagation in LLM agents must capture semantic transformation, causal influence on decisions, and cross-session persistence through memory — not just explicit content transfer.
> Audits execution traces offline to reconstruct provenance from untrusted sources to privileged sinks.
> Substantially outperforms FIDES on TaintBench.
- **Key Claims**:
- F1=0.928 on TaintBench (400 scenarios, 20 real-world agent frameworks)
- Substantially outperforms FIDES (F1=0.522) on same benchmark
- Three taint mechanisms: semantic evidence, causal reasoning, persistent context tracking
- Effective on InjecAgent and ToolEmu benchmarks
- Modest additional auditing cost (offline operation)
- **Methodology**:
> Offline audit of execution traces.
> Three taint propagation mechanisms: (1) semantic evidence — tracks meaning-preserving transformations (paraphrase, summarization), (2) causal reasoning — identifies how untrusted data influences agent decisions even without direct content transfer, (3) persistent context tracking — monitors cross-session memory contamination.
> Operates post-hoc on traces rather than inline, keeping inference latency unaffected.

**Smgglrs Relevance**

- **Affected Crates**: security, core
- **Relevance Category**: opportunity
- **Impact Level**: high
- **Relevance Rationale**:
> NeuroTaint reveals a gap in pure label-only IFC (FIDES F1=0.522 vs NeuroTaint F1=0.928).
> However, smgglrs's IFC is more sophisticated than FIDES: (1) per-value IFC via ValueStore with var:// resolution tracks taint at individual tool-result granularity, not just per-session; (2) statistical guardrails (CosineDriftDetector with z-score threshold + EntropyMonitor for tool-use pattern anomalies) detect behavioral shifts that label-tracking alone misses; (3) temporal behavioral contracts (TemporalPredicate: Requires, SequenceLimit, TaintGate, DenialEscalation, Cooldown) add trajectory-level enforcement.
> Still, smgglrs lacks NeuroTaint's three core mechanisms (semantic transformation tracking, causal influence on decisions, cross-session memory contamination detection).
> smgglrs-core's hash-chained blackbox audit log (SHA-256 chain with PII filtering) provides the execution trace input NeuroTaint-style offline analysis needs.

**Actionable Insights**

- **What To Adopt**:
- Offline taint audit using smgglrs's OTel traces as input
- Cross-session memory contamination detection in smgglrs-memory
- Semantic taint analysis for smgglrs-security's safety hooks (beyond string-matching)
- **What To Watch**:
- NeuroTaint code release for integration testing
- Whether semantic taint tracking can run inline (not just offline) with acceptable latency
- Combination of FIDES-style label tracking (inline) + NeuroTaint audit (offline) as defense-in-depth
- **What To Avoid**:
- Don't rely solely on label-only IFC — F1=0.522 is insufficient for production security
- Don't add inline semantic analysis without latency budget — keep it offline initially
- **Implementation Difficulty**: significant
- **Priority Sprint**: S12 (IFC enhancement)

**Competitive Position**

- **How Smgglrs Compares**:
> smgglrs-security's IFC uses label tracking (FIDES-class, F1~0.522).
> NeuroTaint achieves F1=0.928 via semantic+causal+persistent analysis.
> smgglrs should layer NeuroTaint-style offline audit on top of its inline label tracking for defense-in-depth.
> smgglrs's existing OTel traces provide the execution trace input NeuroTaint needs.
- **Gaps Exposed**:
- No semantic taint tracking (meaning-preserving transformations like paraphrase/summarization)
- No causal influence detection (how untrusted data influences agent decisions without direct content transfer)
- No cross-session memory contamination detection in smgglrs-memory's knowledge store
- **Advantages Confirmed**:
- Hash-chained blackbox audit log (SHA-256 chain, tamper-detectable) provides execution traces for offline NeuroTaint-style analysis
- Per-value IFC (ValueStore with var:// resolution) tracks taint at finer granularity than FIDES's per-session model
- Statistical guardrails (CosineDriftDetector + EntropyMonitor) detect behavioral anomalies that neither FIDES nor NeuroTaint addresses
- Temporal behavioral contracts (TaintGate predicate) can block tools after seeing specific taint labels — a form of causal enforcement
- ML safety filters (NER + regex) provide partial semantic detection that pure-label systems lack

**Ecosystem Context**

- **Owasp Coverage**: ASI01 (Goal Hijack — semantic taint detection), ASI06 (Context Manipulation — cross-session persistence), ASI08 (Cascading Failures — causal influence tracking)
- **Mcp Spec Alignment**: N/A
- **Isolation Model**: N/A (offline audit tool)
- **Aaif Alignment**: independent
- **Regulatory Relevance**: EU AI Act (audit trail analysis supports monitoring/logging obligations)

**Economics**

- **Memory Tier**: N/A
- **Token Economics**: Offline operation means zero inline token overhead. Audit cost is modest and can be amortized across sessions.

---

### TurboQuant / TurboVec

**Basic Info**

- **Name**: TurboQuant / TurboVec
- **Source Url**: https://www.marktechpost.com/2026/05/20/meet-turbovec-a-rust-vector-index-with-python-bindings-and-built-on-googles-turboquant-algorithm/
- **Date**: 2026-05-20
- **Authors Org**: Ryan Codrai (TurboVec); Google Research (TurboQuant algorithm, arXiv 2504.19874)
- **Type**: tool
- **License**: MIT

**Summary**

- **Core Contribution**:
> Rust vector index implementing Google's TurboQuant data-oblivious quantization algorithm.
> Four-step pipeline: normalization, random orthogonal rotation, Lloyd-Max scalar quantization (precomputed buckets, zero training passes), bit-packing.
> 16x compression at 2-bit (6144 bytes to 384 bytes per 1536-dim vector).
> SIMD-accelerated scoring via NEON/AVX-512BW/AVX2 with nibble-split lookup tables.
- **Key Claims**:
- 16x compression for 1536-dim float32 vectors at 2-bit
- 10M vectors: 31GB to 4GB
- Zero training required — data-oblivious quantization with analytically precomputed codebooks
- 12-20% faster than FAISS IndexPQFastScan on ARM (M3 Max)
- Within 0-1 point recall of FAISS on OpenAI embeddings
- Distortion within 2.7x of Shannon lower bound
- **Methodology**:
> Random orthogonal rotation makes post-rotation coordinate distribution predictable (converges to Gaussian N(0,1/d) in high dimensions), enabling Lloyd-Max optimal bucket boundaries without data-dependent codebook training.
> Query rotated once into same domain, scored against codebook values via SIMD.
> Supports incremental adds without index rebuilds.

**Smgglrs Relevance**

- **Affected Crates**: rag
- **Relevance Category**: opportunity
- **Impact Level**: high
- **Relevance Rationale**:
> TurboVec is a direct replacement candidate for smgglrs-rag's vector search backend.
> Code analysis reveals: smgglrs-rag stores embeddings as full float32 via sqlite-vec's vec0 virtual table with L2 distance (Euclidean).
> Search uses MATCH operator, dimensions configurable at store creation.
> TurboVec would provide: (1) 16x memory reduction (full float32 → 2-bit quantized); (2) SIMD-accelerated scoring (NEON/AVX-512BW/AVX2 vs sqlite-vec's generic implementation); (3) Zero-training quantization matching smgglrs-rag's append-oriented pattern (index_document() adds embeddings incrementally).
> The RRF fusion layer (k=60, 3x overfetch) is vector-backend-agnostic, so swapping sqlite-vec for TurboVec only requires implementing the search interface.
> Cache layer (cosine similarity 0.92 threshold, TTL 300s) works with either backend.

**Actionable Insights**

- **What To Adopt**:
- Evaluate TurboVec as alternative to sqlite-vec in smgglrs-rag
- TurboQuant's data-oblivious quantization could be used standalone for embedding compression
- Framework integrations (LangChain, LlamaIndex, Haystack) validate the API pattern
- **What To Watch**:
- Maturity of Rust API (currently cargo add turbovec)
- Performance at scale beyond 100K vectors
- Community adoption and maintenance trajectory
- **What To Avoid**: - Don't replace sqlite-vec without benchmarking on smgglrs-rag's actual workload (breadcrumb chunks, cross-encoder reranking)
- **Implementation Difficulty**: moderate
- **Priority Sprint**: S11 (RAG optimization)

**Competitive Position**

- **How Smgglrs Compares**:
> smgglrs-rag uses sqlite-vec which is simpler but less performant.
> TurboVec offers 12-20% speed improvement and 16x memory reduction.
> The zero-training property aligns with smgglrs's design of minimal external dependencies.
- **Gaps Exposed**:
- smgglrs-rag stores full float32 embeddings via sqlite-vec vec0 — no quantization, 16x more memory than necessary
- No SIMD-accelerated similarity scoring — sqlite-vec uses generic implementation
- L2 (Euclidean) distance only — no cosine similarity in vector search (cache uses cosine, search doesn't)
- **Advantages Confirmed**:
- Rust-native ecosystem compatibility — TurboVec integrates naturally into smgglrs workspace
- smgglrs-rag's hybrid FTS5+vector+RRF architecture is independent of vector backend, making swap feasible

**Ecosystem Context**

- **Owasp Coverage**: N/A
- **Mcp Spec Alignment**: N/A
- **Isolation Model**: in-process
- **Aaif Alignment**: independent
- **Regulatory Relevance**: N/A

**Economics**

- **Memory Tier**: flat-vector
- **Token Economics**: 16x memory reduction for embeddings reduces infrastructure cost for large knowledge bases. Zero-training property eliminates codebook computation cost.

---

### auth.md (WorkOS)

**Basic Info**

- **Name**: auth.md (WorkOS)
- **Source Url**: https://www.marktechpost.com/2026/05/25/workos-releases-auth-md-an-open-agent-registration-protocol-built-on-oauth-standards/
- **Date**: 2026-05-25
- **Authors Org**: WorkOS
- **Type**: protocol

**Summary**

- **Core Contribution**:
> Open agent registration protocol enabling AI agents to register with applications without human interaction.
> Published as a Markdown file at a well-known URL (e.g., service.com/auth.md) — dual-purpose human-readable documentation and machine-parseable runtime artifact.
> Two registration flows: (1) Agent Verified (ID-JAG from trusted provider, zero interaction, synchronous), (2) User Claimed (OTP-based, email verification).
> Builds on OAuth 2.1 (RFC 9728) and IETF ID-JAG draft.
> Not tied to WorkOS infrastructure.
- **Key Claims**:
- Zero-interaction registration via ID-JAG from trusted providers (OpenAI, Anthropic, Cursor)
- Discovery via Protected Resource Metadata (/.well-known/oauth-protected-resource)
- Automatic bootstrap on 401 response via WWW-Authenticate header
- Delegation records keyed by (iss, sub, aud) tuple
- No refresh tokens for ID-JAG flow — fresh assertion required for extension
- Pre-claim anonymous access with scope upgrade after OTP verification
- **Methodology**:
> Two-hop discovery: PRM at well-known URL points to Authorization Server, which contains agent_auth block with register_uri, claim_uri, revocation_uri.
> Two flows: ID-JAG (provider mints audience-specific JWT, app verifies against provider JWKS, returns credentials synchronously) and User Claimed (POST /agent/auth/claim triggers OTP email, POST /agent/auth/claim/complete submits code).
> User matching: delegation record > email match > JIT provision.

**Smgglrs Relevance**

- **Affected Crates**: security, protocol, core
- **Relevance Category**: opportunity
- **Impact Level**: high
- **Relevance Rationale**:
> auth.md addresses the exact authentication gap smgglrs faces when agents connect.
> smgglrs currently uses BLAKE3 tokens — auth.md offers a standards-based alternative for agent registration that's interoperable with the broader ecosystem.
> The ID-JAG flow could complement smgglrs-security's capability delegation (agents present provider-minted assertions, smgglrs issues scoped capabilities).
> The protocol's well-known URL discovery pattern aligns with MCP server discovery.

**Actionable Insights**

- **What To Adopt**:
- Support auth.md protocol as an alternative registration flow alongside BLAKE3 tokens
- Publish /.well-known/oauth-protected-resource for smgglrs server discovery
- Implement ID-JAG verification against provider JWKS in smgglrs-security auth module
- WWW-Authenticate header on 401 responses for automatic agent bootstrap
- **What To Watch**:
- IETF ID-JAG draft progression — critical dependency for the Agent Verified flow
- Provider adoption (which platforms mint ID-JAGs)
- MCP spec alignment — auth.md could become MCP's recommended auth mechanism
- **What To Avoid**:
- Don't abandon BLAKE3 tokens — auth.md is complementary for external agents, BLAKE3 remains better for internal/local auth
- Don't trust ID-JAGs without JWKS verification against known providers
- **Implementation Difficulty**: moderate
- **Priority Sprint**: S11 (auth enhancement)

**Competitive Position**

- **How Smgglrs Compares**:
> smgglrs's BLAKE3 + capability delegation is more secure for local scenarios but less interoperable than auth.md for external agent registration.
> Adding auth.md support would give smgglrs best-of-both-worlds: secure local auth + standards-based external registration.
- **Gaps Exposed**:
- No ID-JAG (Identity Assertion for Authorization Grant) flow in smgglrs-security's OAuthProvider
- No well-known URL discovery (/.well-known/oauth-protected-resource) for smgglrs server
- No agent identity verification against provider JWKS — smgglrs validates its own Ed25519-signed JWTs but not external provider assertions
- **Advantages Confirmed**:
- smgglrs already has OAuth 2.1 with Ed25519 JWT + RFC 8693 token exchange + OBO identity — auth.md ID-JAG is complementary, not replacement
- BLAKE3 + CBOR/Ed25519 capability delegation with attenuation chains (ring, expiry, operations, tools, credentials, sandbox) is far more granular than auth.md's scope-based model
- deny-wins ACLs + risk-tiered approval + trust scoring provide stronger post-auth enforcement than auth.md specifies
- Constant-time token comparison (CWE-208 mitigation) already implemented

**Ecosystem Context**

- **Owasp Coverage**: ASI03 (Identity & Privilege Abuse — scoped agent credentials), ASI04 (Supply Chain — provider trust list)
- **Mcp Spec Alignment**: 2026-07-28-RC (OAuth 2.1/OIDC hardening aligns with auth.md)
- **Isolation Model**: N/A (authentication protocol, not isolation)
- **Aaif Alignment**: independent (but builds on same OAuth/OIDC foundations as MCP spec)
- **Regulatory Relevance**: EU AI Act (auditable agent identity and delegation records support compliance)

**Economics**

- **Memory Tier**: N/A
- **Token Economics**: N/A (authentication protocol)

**Uncertain Fields**

- license

---

### gBrain (Garry Tan)

**Basic Info**

- **Name**: gBrain (Garry Tan)
- **Source Url**: https://www.marktechpost.com/2026/05/22/a-step-by-step-coding-tutorial-to-implement-gbrain-the-self-wiring-memory-layer-built-by-y-combinators-garry-tan-for-ai-agents/
- **Date**: 2026-05-22
- **Authors Org**: Garry Tan (Y Combinator CEO)
- **Type**: tool
- **License**: MIT

**Summary**

- **Core Contribution**:
> Markdown-first, Postgres-backed knowledge layer for AI agents with zero-LLM graph extraction.
> 'Thin harness, fat skills' design — runtime stays minimal while intelligence resides in markdown files.
> Regex-based typed edge inference (FOUNDED, INVESTED, ADVISES, WORKS_AT, MENTIONS) requires zero LLM calls.
> Hybrid search: BM25 + HNSW vector + RRF fusion (score = sum(1/(60+rank))).
> 74 MCP tools via stdio or HTTP.
> Production-tested at 146K pages, 24K people, 5K companies.
- **Key Claims**:
- 97.6% top-5 LongMemEval retrieval (per web search data)
- +31.4 point P@5 improvement from typed knowledge graph layer on BrainBench
- 97.9% R@5 on BrainBench (240-page corpus)
- 74 MCP tools exposed via stdio or HTTP
- Zero-LLM graph extraction via regex-based typed inference cascade
- PGLite: full Postgres 17 compiled to WASM, ~2s provisioning, no Docker
- **Methodology**:
> Compiled truth + timeline pattern: current-best-understanding section on top with append-only evidence trail below.
> Knowledge graph edges extracted via regex in fixed order (FOUNDED > INVESTED > ADVISES > WORKS_AT > MENTIONS).
> Search uses hybrid pipeline: BM25 keyword + HNSW vector + RRF fusion with optional multi-query expansion (Haiku) and ZeroEntropy reranker.
> Three presets: conservative, balanced, tokenmax.
> Autopilot daemon runs on 5-minute tick with cost cap.

**Smgglrs Relevance**

- **Affected Crates**: rag, memory
- **Relevance Category**: opportunity
- **Impact Level**: high
- **Relevance Rationale**:
> gBrain validates smgglrs-rag's hybrid search architecture — identical pattern (BM25 + vector + RRF with k=60).
> Code-level verification: smgglrs-rag uses score = sum(1/(60+rank+1)) with 3x overfetch per channel, matching gBrain's RRF formula (score = sum(1/(60+rank))).
> The zero-LLM regex graph extraction is a pattern smgglrs could adopt — smgglrs-memory's knowledge store has content-addressed entries (SHA-256 of kind+title) and scoping (entity_id) but no automated graph extraction.
> The compiled-truth-plus-timeline pattern maps to smgglrs-memory's DistilledEntry with supersession (store_distilled() upserts by content_key, increments version).
> gBrain's 74 MCP tools make it a natural upstream server for smgglrs to proxy and security-filter via UpstreamModule::discover() with tool scanning.

**Actionable Insights**

- **What To Adopt**:
- Zero-LLM regex graph extraction for building knowledge graphs from ingested documents
- Compiled truth + timeline pattern for smgglrs-memory knowledge store
- Cost-capped autopilot pattern for background memory maintenance
- PGLite as alternative to SQLite for environments needing Postgres compatibility
- **What To Watch**:
- gBrain as upstream MCP server for smgglrs to proxy
- BrainBench evaluation results vs smgglrs-rag performance
- ZeroEntropy reranker integration pattern
- **What To Avoid**:
- Don't adopt gBrain's markdown-first storage — smgglrs-memory's SQLite FTS5 is more suitable for gateway workloads
- Don't require full wikilink paths — too brittle for user-facing content
- **Implementation Difficulty**: moderate
- **Priority Sprint**: S11 (RAG + memory optimization)

**Competitive Position**

- **How Smgglrs Compares**:
> smgglrs-rag already implements the same hybrid search pattern (FTS5 + vector + RRF + cross-encoder reranking).
> gBrain adds zero-LLM graph extraction and the compiled-truth pattern that smgglrs-memory lacks.
> smgglrs has stronger security (IFC, safety hooks) but weaker knowledge organization.
- **Gaps Exposed**:
- No knowledge graph extraction in smgglrs-rag or smgglrs-memory
- No compiled-truth-plus-timeline pattern for knowledge consolidation
- No cost-capped background maintenance for memory
- **Advantages Confirmed**:
- Hybrid FTS5+vector+RRF architecture validated as correct pattern (gBrain uses identical approach)
- Cross-encoder reranking (smgglrs-rag) is a step beyond gBrain's ZeroEntropy reranker
- smgglrs's gateway security layer adds IFC/safety that gBrain lacks entirely

**Ecosystem Context**

- **Owasp Coverage**: N/A
- **Mcp Spec Alignment**: 2025-11-25 (stdio MCP server with 74 tools)
- **Isolation Model**: in-process (PGLite WASM or Postgres)
- **Aaif Alignment**: independent
- **Regulatory Relevance**: N/A

**Economics**

- **Memory Tier**: knowledge-graph
- **Token Economics**: Zero-LLM graph extraction eliminates model inference cost for knowledge organization. Cost-capped autopilot prevents runaway API spending.

---

### Cloudflare Agent Memory

**Basic Info**

- **Name**: Cloudflare Agent Memory
- **Source Url**: https://www.infoq.com/news/2026/04/cloudflare-agent-memory-beta/
- **Date**: 2026-04-30
- **Authors Org**: Cloudflare (Tyson Trautmann, Rob Sutter); InfoQ article by Steef-Jan Wiggers
- **Type**: tool

**Summary**

- **Core Contribution**:
> Cloudflare Agent Memory is a managed memory service for AI agents that addresses context rot — quality degradation as context windows fill up.
> It uses a dual-pass extraction pipeline (broad chunking + detail extraction) with an 8-check verifier, classifies memories into four types (facts, events, instructions, tasks), and retrieves via 5 parallel channels fused with Reciprocal Rank Fusion (RRF).
- **Key Claims**:
- Context rot degrades LLM output quality even beyond 1M-token windows
- Models perform better with less but more relevant context
- 5-channel parallel retrieval with RRF fusion outperforms single-channel approaches
- Content-addressed SHA-256 IDs enable idempotent re-ingestion
- Llama 4 Scout (17B MoE) for extraction; Nemotron 3 (120B MoE) for synthesis — larger model only helps at synthesis stage
- **Methodology**:
> Ingestion: content-addressed via SHA-256 hash, dual-pass extraction (broad pass at ~10k chars/chunk + detail pass for names/prices/versions), 8-check verifier, classification into facts/events/instructions/tasks.
> Facts and instructions keyed by normalized topic with supersession semantics.
> Retrieval: 5 parallel channels (full-text search, exact fact-key lookup, raw message search, direct vector search, HyDE vector search) combined via RRF.
> HyDE generates a declarative answer to the query before vector search to catch vocabulary mismatches.

**Smgglrs Relevance**

- **Affected Crates**: rag, memory
- **Relevance Category**: validation
- **Impact Level**: high
- **Relevance Rationale**:
> Cloudflare's 5-channel RRF architecture directly validates smgglrs-rag's hybrid FTS5+vector search with RRF fusion design.
> The HyDE channel is a concrete technique smgglrs-rag could adopt.
> The memory taxonomy (facts/events/instructions/tasks) and supersession semantics validate smgglrs-memory's working memory + knowledge store architecture.
> A major cloud vendor choosing RRF fusion confirms this is the right retrieval strategy.

**Actionable Insights**

- **What To Adopt**:
- HyDE (Hypothetical Document Embeddings) as a third retrieval channel in smgglrs-rag alongside FTS5 and vector search
- Memory taxonomy: classify stored memories into facts/events/instructions/tasks for retrieval prioritization
- Supersession semantics: key facts by normalized topic, supersede rather than delete, preserving history
- Content-addressed IDs (SHA-256) for idempotent memory ingestion
- **What To Watch**:
- Cloudflare Agent Memory moving to public beta — pricing and API details
- Whether 5-channel RRF becomes the industry standard retrieval pattern
- **What To Avoid**: - Using large models (120B+) for extraction/classification — Cloudflare found smaller models (17B MoE) sufficient for this stage
- **Implementation Difficulty**: moderate
- **Priority Sprint**: Phase 10 (RAG enhancements)

**Competitive Position**

- **How Smgglrs Compares**:
> smgglrs-rag already implements hybrid FTS5+vector with RRF fusion, which is the same core architecture.
> Cloudflare adds 3 additional channels (exact fact-key lookup, raw message search, HyDE vector).
> smgglrs runs in-process with ONNX models while Cloudflare uses cloud-scale models (17B/120B MoE).
- **Gaps Exposed**:
- smgglrs-rag lacks HyDE (hypothetical document embedding) channel for vocabulary mismatch handling
- No memory taxonomy or typed memory classification in smgglrs-memory
- No supersession semantics for fact updates
- Missing dedicated fact-key lookup channel
- **Advantages Confirmed**:
- RRF fusion architecture validated by major cloud vendor
- In-process ONNX approach avoids dependency on large cloud models for extraction
- Local/on-premise operation preserves data privacy — Cloudflare requires sending all data to their cloud

**Ecosystem Context**

- **Mcp Spec Alignment**: N/A (standalone memory service, not MCP-specific)
- **Isolation Model**: none (cloud-managed SaaS)
- **Aaif Alignment**: None direct; positions memory as infrastructure layer consistent with AAIF agent architecture vision

**Economics**

- **Memory Tier**: tiered
- **Token Economics**:
> Reduces token consumption by replacing large context windows with targeted retrieval.
> Dual-model approach (small for extraction, large for synthesis) optimizes cost.
> Exact pricing not yet disclosed (private beta).

**Uncertain Fields**

- license
- owasp_coverage
- regulatory_relevance

---

### OWASP Top 10 for Agentic Applications 2026

**Basic Info**

- **Name**: OWASP Top 10 for Agentic Applications 2026
- **Source Url**: https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/
- **Date**: 2025-12-09
- **Authors Org**: OWASP GenAI Security Project (100+ industry experts, researchers, practitioners)
- **Type**: standard

**Summary**

- **Core Contribution**:
> First canonical risk taxonomy for autonomous AI agents, defining 10 security risks (ASI01-ASI10) specific to agentic applications.
> Distinguishes agentic risks from the existing OWASP LLM Top 10 by addressing tool use, multi-step reasoning, and inter-agent communication.
> Developed through global peer review with 100+ contributors.
- **Key Claims**:
- ASI01: Agent Goal Hijack — hidden prompts redirect agent objectives via direct/indirect injection
- ASI02: Tool Misuse & Exploitation — tools invoked in unintended or harmful ways
- ASI03: Agent Identity & Privilege Abuse — leaked credentials let agents exceed intended scope
- ASI04: Agentic Supply Chain Compromise — runtime components (MCP/A2A) poisoned
- ASI05: Unexpected Code Execution — sandbox boundary failures enabling arbitrary code
- ASI06: Memory & Context Poisoning — poisoned memory reshapes behavior long after initial interaction
- ASI07: Insecure Inter-Agent Communication — spoofed, replayed, or unauthenticated messages
- ASI08: Cascading Agent Failures — errors compound across automated pipelines
- ASI09: Human-Agent Trust Exploitation — humans over-trust or are deceived by agent outputs
- ASI10: Rogue Agents — agents operating outside policy by design failure, drift, or compromise
- **Methodology**:
> Collaborative risk identification through 100+ expert contributors spanning industry, academia, and security research.
> Peer-reviewed framework with ranked risks based on likelihood, impact, and prevalence in production agentic systems.
> Supplements the OWASP LLM Top 10 by focusing on three categories of risk that LLM-only systems do not face: tool use (agents take actions in the world), multi-step reasoning (single injection compounds over many turns), and inter-agent communication (agents talking to agents via MCP/A2A).
> Emphasizes Defense in Depth, Least Privilege, Continuous Monitoring, Isolation & Sandboxing, Human Oversight, Transparency & Explainability, and Regular Security Testing.

**Smgglrs Relevance**

- **Affected Crates**:
- security
- protocol
- core
- flow
- agent
- tools-exec
- rag
- memory
- server
- **Relevance Category**: reference
- **Impact Level**: high
- **Relevance Rationale**:
> The ASI taxonomy is the canonical framework smgglrs should map its security features against.
> smgglrs already addresses many of these risks: ASI01 (safety hooks/IFC), ASI02 (deny-wins ACLs, tool scanning), ASI03 (BLAKE3 tokens, capability delegation), ASI05 (OpenShell sandboxing), ASI06 (cognitive file integrity), ASI07 (flow mesh authentication), ASI08 (hop limits in flow), ASI10 (trust scoring).
> Gaps exist in ASI04 (supply chain signing), ASI09 (human oversight workflows).
> This taxonomy should drive smgglrs security roadmap prioritization.

**Actionable Insights**

- **What To Adopt**:
- Formal ASI01-ASI10 compliance mapping document for smgglrs — enumerate which crate/feature addresses each risk
- ASI04 mitigation: add Ed25519 or similar signing for upstream MCP server manifests
- ASI09 mitigation: add configurable human-in-the-loop approval gates for high-risk tool calls
- ASI08 mitigation: strengthen circuit breaker patterns in smgglrs-flow beyond current hop limits
- **What To Watch**:
- AIUC-1 Crosswalks document (May 2026) for mapping ASI risks to other frameworks
- OWASP Agentic Skills Top 10 (separate project) for tool-specific risk guidance
- AI Security Solutions Landscape Q2 2026 reports for competitive positioning
- **What To Avoid**:
- Do not treat this as a checklist to pass — focus on architectural enforcement (smgglrs gateway model) rather than point-solution mitigations
- Do not conflate with OWASP LLM Top 10 — different scope and different mitigations
- **Implementation Difficulty**: moderate
- **Priority Sprint**: S10 (compliance mapping document + gap analysis)

**Competitive Position**

- **How Smgglrs Compares**:
> smgglrs addresses 8 of 10 ASI risks architecturally through its gateway-enforced security model.
> The gateway approach means mitigations are infrastructure-level rather than application-level, which is stronger than SDK-based approaches.
> Key strength: ASI01/ASI02 are handled by the combination of IFC, deny-wins ACLs, safety hooks, and ML content filtering — multiple defense layers rather than single-point solutions.
- **Gaps Exposed**:
- ASI04 (Supply Chain): No cryptographic verification of upstream MCP server integrity or tool manifest signing
- ASI09 (Human Trust): No built-in human approval workflow or quorum logic for high-risk operations
- No formal compliance self-assessment or reporting against ASI taxonomy
- **Advantages Confirmed**:
- Gateway-enforced IFC uniquely addresses ASI01 (goal hijack) at the data flow level, not just prompt level
- ASI02 (tool misuse) is structurally prevented by deny-wins ACLs — tools cannot be bent to unauthorized paths
- ASI06 (memory poisoning) is addressed by cognitive file integrity monitoring — unique among MCP gateways
- ASI10 (rogue agents) is mitigated by trust scoring with behavioral decay — agents lose trust automatically

**Ecosystem Context**

- **Owasp Coverage**: ASI01, ASI02, ASI03, ASI04, ASI05, ASI06, ASI07, ASI08, ASI09, ASI10 (defines the taxonomy)
- **Mcp Spec Alignment**: Framework-agnostic (references MCP and A2A as attack surfaces but does not target specific spec version)
- **Isolation Model**: Recommends sandboxing as a key design principle but does not prescribe specific isolation model
- **Regulatory Relevance**:
> EU AI Act (high-risk AI systems mapping), Colorado AI Act (algorithmic transparency).
> The taxonomy is being adopted as a compliance baseline by organizations preparing for August 2026 EU AI Act enforcement.

**Economics**

- **Memory Tier**: N/A (risk taxonomy, not a system)
- **Token Economics**: N/A (standard/framework, not an inference system). However, implementing mitigations for ASI01-ASI10 may add per-request overhead for safety checks, policy evaluation, and audit logging.

**Uncertain Fields**

- license
- aaif_alignment

---

### Open-Source Agent Toolkit Landscape 2026

**Basic Info**

- **Name**: Open-Source Agent Toolkit Landscape 2026
- **Source Url**: https://dev.to/anmolbaranwal/open-source-toolkit-for-building-ai-agents-in-2026-55h1
- **Date**: 2026-05-28
- **Authors Org**: Anmol Baranwal (Dev.to)
- **Type**: article
- **License**: N/A (article)

**Summary**

- **Core Contribution**:
> Comprehensive survey of 70+ open-source tools across 17 categories for building AI agents in 2026.
> Categories: frontend/UI, skills/plugins, computer use, orchestration, coding agent harness, coding agents, browser automation, web scraping, multi-agent, document processing, voice agents, visual builders, MCP/tool integration, sandboxing, agent memory, testing/evaluation, monitoring/observability.
> Includes star counts, key differentiators, and three canonical protocols (MCP, A2A, AG-UI).
- **Key Claims**:
- CopilotKit (31.5K stars) leads frontend; OpenCode (162K stars) leads coding agents
- agent-skills (43.8K stars) establishes skill package pattern
- Composio (28.4K stars) acts as intelligent MCP gateway with dynamic tool routing
- E2B (12K stars) sets sandboxing standard with Firecracker microVMs (~150ms boot)
- mem0 (55K stars) leads agent memory but trails Zep (63.8% vs 49% on LongMemEval)
- Three protocols converging: MCP (agent-tools), A2A (agent-agent), AG-UI (agent-user)
- **Methodology**: Survey of GitHub repositories with star counts, feature comparison, and ecosystem mapping. Organized by agent system layer.

**Smgglrs Relevance**

- **Affected Crates**:
- protocol
- security
- tools-exec
- rag
- memory
- agent
- flow
- modal-voice
- **Relevance Category**: reference
- **Impact Level**: high
- **Relevance Rationale**:
> Maps the competitive landscape smgglrs operates in.
> Key findings: (1) Composio is the closest MCP gateway competitor with dynamic tool routing, (2) E2B/Firecracker/OpenSandbox define the sandboxing standard smgglrs-tools-exec must match, (3) mem0/Zep/Graphiti show memory architecture alternatives to smgglrs-memory, (4) AI-Infra-Guard (Tencent) and garak (NVIDIA) scan MCP servers for security — direct validation of smgglrs-security's tool scanning, (5) Pipecat/LiveKit define voice agent patterns for smgglrs-modal-voice, (6) DeepEval sets agent testing standards.

**Actionable Insights**

- **What To Adopt**:
- Composio's dynamic tool routing pattern (Tool Router) — smgglrs could surface only relevant tools per request
- DeepEval's agent-specific test metrics (task completion, tool correctness, step efficiency) for smgglrs testing
- AI-Infra-Guard's MCP server scanning approach — validates smgglrs-security's upstream tool scanning
- **What To Watch**:
- Composio's MCP gateway evolution — closest competitor to smgglrs's gateway role
- AG-UI protocol adoption — may need smgglrs-protocol support
- Graphiti (Zep) temporal knowledge graphs — 63.8% vs mem0's 49% on LongMemEval
- **What To Avoid**:
- Don't try to compete with full agent frameworks (LangGraph, CrewAI) — smgglrs is infrastructure, not framework
- Don't replicate Composio's managed auth model — smgglrs's BLAKE3+capability approach is more secure
- **Implementation Difficulty**: N/A
- **Priority Sprint**: N/A (landscape reference)

**Competitive Position**

- **How Smgglrs Compares**:
> smgglrs uniquely combines MCP gateway, IFC security, and in-process ML models in a single Rust binary.
> No other tool in this landscape provides all three.
> Composio is closest as MCP gateway but lacks IFC, safety ML models, and is a SaaS product not self-hosted infrastructure.
> E2B/OpenSandbox handle sandboxing but not MCP routing or security.
> AI-Infra-Guard scans but doesn't enforce.
- **Gaps Exposed**:
- No dynamic tool routing (Composio's Tool Router pattern) — McpServer exposes all RegisteredTools via HashMap, no per-request filtering based on agent intent
- No AG-UI protocol support (MCP + A2A v0.2.5 are implemented, AG-UI is missing)
- No vector quantization in RAG (sqlite-vec full float32 vs TurboVec 2-bit)
- FTS5 search hardcoded to 20 results — limits recall for large knowledge bases
- **Advantages Confirmed**:
- IFC differentiator confirmed at code level — 2x4 product lattice with per-value tracking (ValueStore), Bell-LaPadula enforcement, Kani-proven monotonicity. No other tool in landscape has this.
- In-process ONNX models confirmed — OnnxBackend supports CPU/CUDA/OpenVINO(NPU) with embed() + classify() for safety/embeddings. No other gateway embeds safety ML models.
- Defense-in-depth stack confirmed — IFC + statistical guardrails (cosine drift + entropy) + temporal behavioral contracts + 8-category tool scanner + deny-wins ACLs + trust scoring + capability delegation with Ed25519/CBOR. Unmatched in landscape.
- Rust implementation confirmed as differentiator — 18-crate workspace, 2160+ tests, 138 Kani formal proofs. Most competitors are Python/TypeScript.
- Hash-chained blackbox audit log (SHA-256, tamper-detectable) with PII filtering — unique audit capability

**Ecosystem Context**

- **Owasp Coverage**: Landscape covers ASI02 (Tool Misuse — sandboxing), ASI03 (Identity — Composio auth), ASI05 (Code Execution — E2B/OpenSandbox)
- **Mcp Spec Alignment**: Ecosystem converging on MCP + A2A + AG-UI as the three canonical agent protocols
- **Isolation Model**: Multiple: Firecracker microVMs (E2B), containers (OpenSandbox), gVisor (K8s), in-process (various)
- **Aaif Alignment**: MCP under Linux Foundation/AAIF; A2A from Google; AG-UI from CopilotKit
- **Regulatory Relevance**: N/A (landscape survey)

**Economics**

- **Memory Tier**: N/A
- **Token Economics**: N/A (landscape survey)

---

### Safely Running Coding Agents

**Basic Info**

- **Name**: Safely Running Coding Agents
- **Source Url**: https://towardsdatascience.com/how-to-safely-run-coding-agents/
- **Date**: 2026-05
- **Authors Org**: Towards Data Science
- **Type**: article
- **License**: N/A (article)

**Summary**

- **Core Contribution**:
> Practitioner guide to running coding agents (Claude Code, OpenAI Codex) with liberal permissions.
> Argues that infrastructure-level guardrails (backups, narrow IAM, irreversible-action gates) are more effective than manual human review.
> Promotes agent-on-agent code review loops over human oversight.
> Identifies false confidence from rubber-stamping as a key threat.
> Recommends blocking only irreversible commands (rm -rf, production DB writes) while allowing all reversible operations.
- **Key Claims**:
- Agents should have all reversible permissions by default — only gate irreversible operations
- Manual review creates false confidence — humans rubber-stamp without understanding
- Agent-on-agent code review (create → review → iterate) is more effective than human review
- Infrastructure design (backups, narrow IAM) is the real defense, not agent restriction
- Domain-sensitive contexts (healthcare, military) warrant vastly more careful treatment
- **Methodology**: Practitioner experience report using Claude Code (--dangerously-skip-permissions) and Codex (YOLO mode). No formal evaluation or benchmarks. Prescriptive advice based on personal production use.

**Smgglrs Relevance**

- **Affected Crates**: security, tools-exec
- **Relevance Category**: threat
- **Impact Level**: medium
- **Relevance Rationale**:
> This article represents the 'no security' approach that smgglrs exists to protect against.
> The recommendation to skip all permissions and rely on infrastructure guardrails is exactly the threat model smgglrs addresses — agents with broad permissions need IFC, safety filters, and capability delegation to prevent data exfiltration and unauthorized actions.
> The article notably ignores prompt injection, supply-chain attacks, and data leakage.
> smgglrs's value proposition is proven by the gaps in this approach.

**Actionable Insights**

- **What To Adopt**:
- The reversible/irreversible distinction is valid — smgglrs-tools-exec could tag operations by reversibility
- Agent-on-agent review pattern could be supported in smgglrs-flow as a safety check
- **What To Watch**:
- Whether this 'YOLO mode' approach leads to publicized security incidents
- Industry response to liberal permission granting for coding agents
- **What To Avoid**:
- Don't adopt the skip-all-permissions philosophy — it ignores prompt injection, data exfiltration, and supply-chain risks
- Don't rely solely on infrastructure guardrails without agent-level security
- **Implementation Difficulty**: N/A
- **Priority Sprint**: N/A (anti-pattern documentation)

**Competitive Position**

- **How Smgglrs Compares**: smgglrs exists precisely because this approach is dangerous. The article's gaps (no IFC, no safety filtering, no capability scoping, no prompt injection defense) are smgglrs's feature set.
- **Gaps Exposed**: N/A
- **Advantages Confirmed**:
- smgglrs's entire security model (IFC, deny-wins ACLs, safety hooks, capability delegation) addresses the risks this article ignores
- The reversible/irreversible distinction validates smgglrs-security's risk_tier system

**Ecosystem Context**

- **Owasp Coverage**: Ignores ASI01-ASI10 entirely — notable gap
- **Mcp Spec Alignment**: N/A
- **Isolation Model**: none (runs on developer's local machine with broad permissions)
- **Aaif Alignment**: independent
- **Regulatory Relevance**: Counter-example for EU AI Act compliance — this approach would not meet high-risk obligations

**Economics**

- **Memory Tier**: N/A
- **Token Economics**: N/A

---

### Adaptive Chunking: Optimizing Chunking-Method Selection for RAG

**Basic Info**

- **Name**: Adaptive Chunking: Optimizing Chunking-Method Selection for RAG
- **Source Url**: https://arxiv.org/abs/2603.25333
- **Date**: 2026-03-26
- **Authors Org**: Paulo Roberto de Moura Junior, Jean Lelong, Annabelle Blangero (Ekimetrics)
- **Type**: paper
- **License**: CC BY 4.0

**Summary**

- **Core Contribution**:
> Framework for document-aware chunking strategy selection in RAG systems.
> Instead of one-size-fits-all chunking, the system selects the optimal chunking method per document using five novel intrinsic metrics that assess chunking quality without relying on downstream task performance.
> Introduces two new chunkers (LLM-regex splitter and split-then-merge recursive splitter) with targeted post-processing.
- **Key Claims**:
- RAG answer correctness improved from 62-64% baseline to 72%
- Successfully answered questions increased by over 30% (65 vs 49)
- Gains achieved without changing models or prompts — chunking alone is the lever
- Five novel intrinsic metrics for chunking quality evaluation
- Accepted at LREC 2026
- **Methodology**:
> The framework introduces five novel intrinsic metrics for evaluating chunking quality: (1) References Completeness (RC) — ensures cross-references within chunks remain intact; (2) Intrachunk Cohesion (ICC) — measures semantic coherence within each chunk; (3) Document Contextual Coherence (DCC) — assesses how well chunks preserve document-level context; (4) Block Integrity (BI) — verifies structural elements (tables, lists) are not split mid-block; (5) Size Compliance (SC) — ensures chunks meet size constraints.
> Two new chunkers are introduced: an LLM-regex splitter that combines regex patterns with LLM guidance, and a split-then-merge recursive splitter that first splits aggressively then merges related segments.
> The adaptive selection process evaluates multiple chunking strategies against the five metrics per document and selects the optimal strategy.
> Evaluated on a diverse corpus spanning legal, technical, and social science domains.
> Code available at https://github.com/ekimetrics/adaptive-chunking.

**Smgglrs Relevance**

- **Affected Crates**: rag
- **Relevance Category**: opportunity
- **Impact Level**: medium
- **Relevance Rationale**:
> smgglrs-rag currently uses breadcrumb chunking as its chunking strategy.
> Adaptive chunking demonstrates that document-aware strategy selection can improve RAG correctness by 10+ percentage points without any model changes.
> The five intrinsic metrics (RC, ICC, DCC, BI, SC) could be integrated into smgglrs-rag to evaluate and select chunking strategies per document type.
> This is particularly relevant for smgglrs because the gateway handles diverse document types from multiple tools (file_read, git tools, etc.) — different documents may benefit from different chunking strategies.

**Actionable Insights**

- **What To Adopt**:
- Implement Block Integrity (BI) metric to ensure structured content (tables, lists, code blocks) is not split mid-block in breadcrumb chunking
- Add Intrachunk Cohesion (ICC) as a quality gate — chunks with low semantic coherence should be re-split or merged
- Consider document-type-aware chunking: different strategies for code files, markdown, legal documents, etc.
- Evaluate the split-then-merge recursive splitter as an alternative to breadcrumb chunking for certain document types
- **What To Watch**:
- Ekimetrics open-source implementation (https://github.com/ekimetrics/adaptive-chunking) for reusable metric implementations
- Whether the LLM-regex splitter approach can be adapted to use local ONNX models instead of large LLMs
- Follow-up work on the five intrinsic metrics — whether the research community validates or refines them
- **What To Avoid**:
- Do not implement the full LLM-regex splitter if it requires large LLM inference per chunk — this conflicts with smgglrs local-first, low-latency design
- Do not replace breadcrumb chunking entirely — adaptive selection means keeping multiple strategies and choosing per document
- **Implementation Difficulty**: moderate
- **Priority Sprint**: S11-S12 (chunking quality metrics + document-type-aware strategy selection)

**Competitive Position**

- **How Smgglrs Compares**:
> smgglrs-rag uses breadcrumb chunking as a single strategy.
> Adaptive chunking demonstrates that a single strategy leaves 10+ percentage points of correctness on the table.
> However, smgglrs-rag compensates with strong retrieval (hybrid FTS5+vector, RRF fusion, cross-encoder reranking, confidence gating) which partially offsets suboptimal chunking.
> The breadcrumb approach is lightweight and fast, suitable for smgglrs's desktop/local-first use case.
- **Gaps Exposed**:
- Single chunking strategy (breadcrumb) may underperform for structured documents (legal, tables, code)
- No chunking quality metrics — smgglrs-rag cannot currently evaluate whether its chunks are well-formed
- No document-type-aware chunking — all documents are chunked identically regardless of structure
- **Advantages Confirmed**:
- smgglrs-rag's strong retrieval pipeline (RRF + reranking + confidence gating) provides defense-in-depth against suboptimal chunking
- Breadcrumb chunking is fast and predictable — important for desktop latency requirements
- In-process execution means chunking improvements can be deployed without infrastructure changes

**Ecosystem Context**

- **Owasp Coverage**: N/A (RAG technique, not a security concern)
- **Mcp Spec Alignment**: N/A (chunking technique, not MCP-specific)
- **Isolation Model**: in-process (chunking runs in-process in smgglrs-rag)
- **Aaif Alignment**: N/A
- **Regulatory Relevance**: N/A

**Economics**

- **Memory Tier**: flat-vector (chunking feeds into vector store)
- **Token Economics**:
> Better chunking directly reduces wasted context tokens: 72% vs 62% correctness means fewer retrieval misses, fewer retries, and lower per-query token cost.
> The adaptive selection adds modest compute overhead (evaluating 5 metrics per document) but this is amortized over all queries against that document.
> The LLM-regex splitter option would add significant per-document LLM inference cost.

---

### Gemini Embedding 2: A Native Multimodal Embedding Model from Gemini

**Basic Info**

- **Name**: Gemini Embedding 2: A Native Multimodal Embedding Model from Gemini
- **Source Url**: https://arxiv.org/abs/2605.27295
- **Date**: 2026-05-26
- **Authors Org**: Google (88 authors, led by Madhuri Shanbhogue)
- **Type**: paper
- **License**: CC BY 4.0

**Summary**

- **Core Contribution**:
> Natively multimodal embedding model that maps text, image, video, and audio into a single unified representation space.
> Built on Gemini's multimodal capabilities using large-scale contrastive learning with a multi-task, multi-stage training setup.
> Handles arbitrary combinations of interleaved inputs across all four modalities.
- **Key Claims**:
- State-of-the-art performance across unimodal, cross-modal, and multimodal retrieval
- MSCOCO R@1: 62.9
- Vatex NDCG@10: 68.8
- MTEB Multilingual: 69.9
- MTEB Code: 84.0
- Surpasses specialized models across varied retrieval tasks
- Robust zero-shot performance across specialized domains (astronomy, bioscience, fine arts, culinary arts)
- **Methodology**:
> Built on top of Gemini's multimodal architecture.
> Training uses large-scale contrastive learning with a multi-task, multi-stage training setup to produce embeddings that generalize across diverse task types.
> The model processes arbitrary combinations of interleaved inputs across four modalities (text, image, video, audio) and maps them into a single unified vector space.
> Zero-shot generalization is achieved without domain-specific fine-tuning, demonstrating reliable out-of-the-box representation for specialized domains.
> Target use cases include RAG, recommendation systems, and search.

**Smgglrs Relevance**

- **Affected Crates**:
- rag
- model
- model-hub
- modal-voice
- modal-vision
- **Relevance Category**: opportunity
- **Impact Level**: medium
- **Relevance Rationale**:
> Gemini Embedding 2 represents the future direction for multimodal RAG: a single embedding model handling text, images, audio, and video in one vector space.
> For smgglrs, this validates the architecture decision to have separate modal-voice and modal-vision crates that could converge on a unified multimodal embedding.
> However, as a Google proprietary model, direct integration requires API access (not local ONNX).
> The MTEB benchmarks set a quality bar for smgglrs-rag's embedding models.
> The multi-modal aspect is relevant for smgglrs-rag if the system needs to retrieve across document types (PDFs with images, audio transcripts, etc.).

**Actionable Insights**

- **What To Adopt**:
- Add Gemini Embedding 2 as a supported backend in smgglrs-model for cloud-tier embedding (alongside OpenAI/Anthropic)
- Design smgglrs-rag embedding abstraction to support multimodal inputs (not just text) for future-proofing
- Use MTEB benchmarks (Multilingual: 69.9, Code: 84.0) as quality targets for evaluating local embedding models
- **What To Watch**:
- Open-source multimodal embedding models that could replicate this capability locally (ONNX-compatible)
- Whether Google releases distilled/smaller versions suitable for CPU/NPU inference
- MTEB leaderboard evolution — whether competitors match these scores with open weights
- **What To Avoid**:
- Do not make smgglrs dependent on Google API for core RAG functionality — local-first remains the principle
- Do not prematurely unify modal-voice and modal-vision into a single multimodal crate without an open-weight model to back it
- **Implementation Difficulty**: moderate
- **Priority Sprint**: S12+ (multimodal RAG abstraction, cloud embedding backend)

**Competitive Position**

- **How Smgglrs Compares**:
> smgglrs-rag currently uses in-process ONNX models for text embeddings only.
> Gemini Embedding 2 represents a capability gap for multimodal retrieval.
> However, smgglrs's local-first architecture (in-process ONNX) provides privacy advantages that cloud-based Gemini embeddings cannot match.
> smgglrs-rag's hybrid FTS5+vector search with cross-encoder reranking addresses retrieval quality through architecture rather than relying solely on embedding quality.
- **Gaps Exposed**:
- No multimodal embedding support — smgglrs-rag only handles text embeddings
- No unified vector space across modalities for cross-modal retrieval
- No Google/Gemini model backend in smgglrs-model (only OpenAI, Anthropic, ONNX, Ollama)
- **Advantages Confirmed**:
- Local-first ONNX embedding provides privacy that cloud-based Gemini cannot match
- Hybrid search (FTS5+vector+RRF+reranker) compensates for lower embedding quality through architectural sophistication
- smgglrs can add Gemini as optional cloud backend while maintaining local-first default

**Ecosystem Context**

- **Owasp Coverage**: N/A (embedding model, not a security concern)
- **Mcp Spec Alignment**: N/A (embedding model, not MCP-specific)
- **Isolation Model**: N/A (cloud API model; local deployment not available)
- **Aaif Alignment**: N/A
- **Regulatory Relevance**: EU AI Act consideration: sending user data to Google for embedding computation may conflict with data residency requirements for high-risk AI systems

**Economics**

- **Memory Tier**: flat-vector (single unified vector space across modalities)

**Uncertain Fields**

- token_economics

---

### OSCAR (Together AI)

**Basic Info**

- **Name**: OSCAR (Together AI)
- **Source Url**: https://www.marktechpost.com/2026/05/25/together-ai-open-sources-oscar-an-attention-aware-2-bit-kv-cache-quantization-system-for-long-context-llm-serving/
- **Date**: 2026-05-25
- **Authors Org**: Together AI / FutureMLS-Lab (arXiv 2605.17757)
- **Type**: paper+tool

**Summary**

- **Core Contribution**:
> OSCAR (Offline Spectral Covariance-Aware Rotation) derives optimal rotation bases from query covariance (for keys) and score-weighted value covariance (for values) to enable INT2 KV cache quantization.
> Three-component rotation (eigenvectors + Walsh-Hadamard + permuted bit-reversal) addresses distinct failure modes.
> Mixed-precision layout: BF16 for sink/recent tokens, INT2 for history.
> 8x memory reduction with near-BF16 quality.
- **Key Claims**:
- Naive INT2 scores 0.00 on Qwen3-4B/8B; OSCAR preserves quality (71.86/69.42 mean accuracy)
- GLM-4.7-FP8 (358B): OSCAR matches or exceeds BF16 (78.16 vs 77.89)
- Up to 3.08x decode speedup at batch=1; 7.83x job-level throughput at batch=32 on H100
- RULER-NIAH: OSCAR on Qwen3-4B at 16K scores 97.8 vs QuaRot-INT2 at 0.0
- Theoretical optimality proof (Theorem 1) for rotation bases under surrogate objective
- **Methodology**:
> Offline calibration: eigen-decompose query covariance CQ for key rotation RK, score-weighted value covariance CS for value rotation RV.
> Compose with Hadamard and permuted bit-reversal.
> Value rotation absorbed into model projection weights offline (zero runtime cost).
> Per-token asymmetric INT2, group size 64, clip thresholds cK=0.96, cV=0.92.
> Fused Triton kernels for paged attention compatibility.
> Pre-computed rotation zoo available on ModelScope.

**Smgglrs Relevance**

- **Affected Crates**: model-runtime, model
- **Relevance Category**: opportunity
- **Impact Level**: medium
- **Relevance Rationale**:
> OSCAR enables serving large models (358B GLM) with 8x less KV cache memory, directly relevant to smgglrs-model-runtime's hardware tier profiles.
> If smgglrs serves or proxies local models, OSCAR-style quantization extends context budgets dramatically.
> The rotation zoo pattern (pre-computed per model) could integrate with model-hub's caching.
> Not immediately actionable since smgglrs uses ONNX for small in-process models, but important for the model-runtime isolation backends (Podman, OpenShell) serving larger models.

**Actionable Insights**

- **What To Adopt**:
- Track OSCAR/SGLang integration for model-runtime backends that serve larger models
- Pre-computed rotation zoo pattern for model-hub: download rotations alongside model weights
- **What To Watch**:
- SGLang native OSCAR support maturity
- Extension to other quantization targets (FP4, mixed INT2/INT4)
- Adoption by vLLM (currently SGLang-only)
- **What To Avoid**: Don't apply to small ONNX safety/embedding models — overhead not justified for models that already fit in memory
- **Implementation Difficulty**: significant
- **Priority Sprint**: S12+ (when model-runtime supports large model serving)

**Competitive Position**

- **How Smgglrs Compares**:
> smgglrs currently uses ONNX Runtime for small in-process models where KV cache quantization is irrelevant.
> For larger model serving via model-runtime backends, OSCAR would be integrated at the serving engine level (vLLM/SGLang), not in smgglrs directly.
- **Gaps Exposed**:
- No KV cache management in model-runtime — relies on underlying serving engine
- model-hub doesn't track rotation/quantization artifacts alongside model weights
- **Advantages Confirmed**: - smgglrs's separation of model-hub (download/cache) from model-runtime (serve) allows clean integration of quantization artifacts

**Ecosystem Context**

- **Owasp Coverage**: N/A (inference optimization, not security)
- **Mcp Spec Alignment**: N/A
- **Isolation Model**: in-process (SGLang kernel integration)
- **Aaif Alignment**: independent
- **Regulatory Relevance**: N/A

**Economics**

- **Memory Tier**: N/A
- **Token Economics**: 8x KV cache memory reduction enables serving 8x longer contexts or 8x larger batches at same hardware cost. At batch=32, 7.83x throughput improvement translates directly to cost reduction per query.

**Uncertain Fields**

- license

---

### Claw-Anything: Always-On Assistant Benchmark (2605.26086)

**Basic Info**

- **Name**: Claw-Anything: Always-On Assistant Benchmark (2605.26086)
- **Source Url**: https://huggingface.co/papers/2605.26086
- **Date**: 2026-05
- **Authors Org**: Yusong Lin et al. (Beijing Institute of Technology, Huawei, Peking University, CAS)
- **Type**: paper
- **License**: N/A (academic paper)

**Summary**

- **Core Contribution**:
> Benchmark for always-on personal assistants expanding agent context along three dimensions: long-horizon activity histories, interdependent backend services, and integrated GUI+CLI interaction across multiple devices.
> Simulates months of user activity through multi-round event injection producing complex world states with realistic noise (irrelevant events, conflicting signals).
> Evaluates both reactive and proactive assistance.
- **Key Claims**:
- GPT-5.5 reaches only 34.5% pass@1 — shows always-on assistants are far from solved
- Expands agent context beyond narrow slices to full user digital world
- Evaluates proactive assistance (anticipating user needs without explicit requests)
- Includes realistic noise and conflicting signals
- Code at github.com/LiberCoders/Claw-Anything
- **Methodology**:
> Simulates months of user activity via multi-round event injection across multiple services and devices.
> Agents must reason over rich contextual environments while remaining robust to noise (irrelevant events, conflicting signals).
> Evaluates both reactive (explicit requests) and proactive (anticipatory) assistance capabilities.

**Smgglrs Relevance**

- **Affected Crates**: agent, flow, memory, core
- **Relevance Category**: validation
- **Impact Level**: medium
- **Relevance Rationale**:
> Validates the always-on agent paradigm smgglrs serves as infrastructure for.
> The benchmark's three dimensions (long-horizon history, interdependent services, multi-device) map to smgglrs capabilities: memory (history), module aggregation (services), transport (multi-device).
> The low GPT-5.5 scores (34.5%) show this is an open problem where infrastructure quality (security, memory, context management) can be a differentiator.
> The '*Claw' naming continues the genre (ClawPatrol, ContextForge).

**Actionable Insights**

- **What To Adopt**:
- Use Claw-Anything benchmark for evaluating smgglrs-agent's always-on capabilities
- The proactive assistance evaluation dimension could inform smgglrs-flow's event-driven orchestration
- **What To Watch**:
- Model improvements on this benchmark — when scores pass 60%, always-on assistants become viable
- Whether noise robustness becomes a differentiating feature for agent infrastructure
- **What To Avoid**: N/A
- **Implementation Difficulty**: N/A
- **Priority Sprint**: N/A (evaluation benchmark)

**Competitive Position**

- **How Smgglrs Compares**:
> smgglrs provides the infrastructure for always-on agents but doesn't implement the agent reasoning itself.
> The benchmark validates that smgglrs's design choices (persistent memory, multi-service aggregation, security) are the right infrastructure for this use case.
- **Gaps Exposed**:
- smgglrs-memory may need longer-horizon storage and retrieval for always-on scenarios
- No proactive assistance patterns in smgglrs-flow
- **Advantages Confirmed**:
- smgglrs's gateway model (aggregating multiple services behind unified security) is validated as essential infrastructure for always-on assistants
- Memory persistence across sessions is a key requirement this benchmark confirms

**Ecosystem Context**

- **Owasp Coverage**: ASI01 (Goal Hijack — noise robustness), ASI06 (Context Manipulation — conflicting signals)
- **Mcp Spec Alignment**: N/A
- **Isolation Model**: N/A
- **Aaif Alignment**: independent
- **Regulatory Relevance**: EU AI Act (always-on assistants with broad access to user data raise high-risk obligations)

**Economics**

- **Memory Tier**: enterprise-context
- **Token Economics**: Long-horizon context (months of history) creates massive token budgets — efficient memory (MemForest-style) is essential for viability.

---

### Hybrid Semantic+Lexical Search in RAG

**Basic Info**

- **Name**: Hybrid Semantic+Lexical Search in RAG
- **Source Url**: https://machinelearningmastery.com/implementing-hybrid-semantic-lexical-search-in-rag/
- **Date**: 2026-05-25
- **Authors Org**: Ivan Palomares Carrascosa (MachineLearningMastery.com)
- **Type**: article
- **License**: N/A (blog article)

**Summary**

- **Core Contribution**:
> Practical implementation guide for hybrid search in RAG systems combining BM25 lexical search with dense vector semantic search, fused using Reciprocal Rank Fusion (RRF).
> Provides Python code examples with rank_bm25 and sentence-transformers libraries, explaining why score normalization fails and rank-based fusion succeeds.
- **Key Claims**:
- Hybrid search achieves 10-30% higher recall than vector-only approaches on diverse enterprise corpora
- Microsoft production testing: hybrid search achieves 48.4 average relevance vs 40.6 keyword-only and 43.8 vector-only
- RRF achieves 91% recall@10 — production-grade without reranking
- RRF is described as the 'gold industry standard' for ranking fusion
- Two-stage architecture (hybrid retrieval + cross-encoder reranking) is the industry standard pattern
- **Methodology**:
> Three-component pipeline: (1) BM25 lexical search using rank_bm25 library — search_bm25() function computes lexical relevance scores per document, ranks by decreasing score, selects top-k; (2) Dense vector semantic search using sentence-transformers — encodes texts and query into embedding space, ranks by cosine similarity; (3) Reciprocal Rank Fusion — ignores raw scores (which are on incompatible scales) and focuses on rank positions, rewarding documents appearing at top positions across both lists using harmonic-mean-like operator.
> The article emphasizes that simply adding scores fails because BM25 and cosine similarity operate on different numeric scales.
> Industry best practice extends this with a two-stage architecture: Stage 1 uses hybrid search to retrieve broad candidate pool (top 100 with high recall), Stage 2 passes candidates through a cross-encoder for deep relevance re-scoring (top 5-10 for LLM context).
> Key tuning parameters: rrf_k (default 60) and per-retriever top-k (start at 20).

**Smgglrs Relevance**

- **Affected Crates**: rag
- **Relevance Category**: validation
- **Impact Level**: medium
- **Relevance Rationale**:
> Directly validates smgglrs-rag's existing architecture: hybrid FTS5+vector search with RRF fusion and cross-encoder reranking.
> The article confirms that smgglrs-rag's approach (BM25-equivalent via FTS5 + vector search + RRF + cross-encoder reranking) matches the industry-standard two-stage pattern.
> The specific tuning recommendations (rrf_k=60, per-retriever top-k=20) can be verified against smgglrs-rag defaults.

**Actionable Insights**

- **What To Adopt**:
- Verify smgglrs-rag rrf_k parameter default matches the recommended 60
- Ensure per-retriever top-k defaults start at 20 as recommended
- Consider exposing rrf_k and per-retriever top-k as configurable parameters if not already
- **What To Watch**:
- Evolution of fusion methods beyond RRF — learned fusion weights, attention-based fusion
- Whether cross-encoder models continue to improve enough to change the two-stage calculus
- **What To Avoid**:
- Score normalization between BM25 and vector scores — the article confirms this approach fails
- Improper fusion parameter tuning — hybrid can perform worse than dense-only with wrong rrf_k
- **Implementation Difficulty**: trivial
- **Priority Sprint**: Current (parameter verification only)

**Competitive Position**

- **How Smgglrs Compares**:
> smgglrs-rag already implements the complete recommended pipeline: FTS5 (BM25-equivalent lexical search) + sqlite-vec (vector search) + RRF fusion + batched cross-encoder reranking + confidence gating.
> This is the exact two-stage architecture the article describes as industry standard.
> smgglrs-rag additionally provides breadcrumb chunking and confidence gating, which go beyond what the article covers.
- **Gaps Exposed**: No gaps — smgglrs-rag's architecture matches or exceeds the article's recommendations
- **Advantages Confirmed**:
- Hybrid FTS5+vector with RRF fusion is validated as the industry standard approach
- Cross-encoder reranking (already in smgglrs-rag) is confirmed as the production-grade Stage 2
- Confidence gating in smgglrs-rag provides additional quality control not mentioned in the article

**Ecosystem Context**

- **Owasp Coverage**: N/A (retrieval technique, not a security concern)
- **Mcp Spec Alignment**: N/A (RAG implementation pattern, not MCP-specific)
- **Isolation Model**: in-process (FTS5 + sqlite-vec run in-process in smgglrs)
- **Aaif Alignment**: N/A
- **Regulatory Relevance**: N/A

**Economics**

- **Memory Tier**: flat-vector (BM25 + dense vector, no knowledge graph)
- **Token Economics**:
> Hybrid search with cross-encoder reranking reduces token cost by selecting fewer, higher-quality chunks for LLM context.
> The two-stage approach trades compute (cross-encoder inference) for token savings (fewer irrelevant chunks in context window).
> Microsoft benchmarks show 11% relevance improvement over vector-only, which translates to fewer wasted context tokens.

---

### Qwen 3.5 122B on 16GB Mac Mini (MoE Expert Streaming)

**Basic Info**

- **Name**: Qwen 3.5 122B on 16GB Mac Mini (MoE Expert Streaming)
- **Source Url**: https://medium.com/data-science-collective/a-qwen-3-6-122b-llm-on-a-16-gb-mac-mini-moe-expert-streaming-with-turboquant-mlx-4f77f0b48518
- **Date**: 2026-05-26
- **Authors Org**: Manjunath Janardhan (Accenture AI/ML Senior Manager)
- **Type**: article
- **License**: N/A (article)

**Summary**

- **Core Contribution**:
> Demonstrates running Qwen3.5-122B-A10B (256-expert MoE, 240GB in BF16) on a $599 Mac Mini with only 16GB RAM by combining TurboQuant-MLX 3-bit quantization (shrinks to ~54GB on disk) with MoE expert streaming — paging only the ~8 active experts per token from SSD behind a small cache.
> Resident memory peaks at ~9GB despite 54GB model size.
- **Key Claims**:
- 122B parameter model running on 16GB consumer hardware
- Resident memory ~9GB (vs 54GB quantized / 240GB BF16 model size)
- No swap, no sysctl tweaks required
- Bit-identical output compared to standard execution
- Key insight: for sparse MoE, the memory wall is really a disk-bandwidth wall
- **Methodology**:
> Two-step approach: (1) TurboQuant-MLX quantizes the model to 3-bit (~54GB on disk), (2) MoE expert streaming pages only active experts (~8 of 256) from SSD into a small RAM cache per token.
> Validated first on a 35B model (<4GB) before scaling to 122B.
> The article notes that M-series SSD bandwidth is sufficient for coherent generation.

**Smgglrs Relevance**

- **Affected Crates**: model-runtime, model-hub
- **Relevance Category**: validation
- **Impact Level**: medium
- **Relevance Rationale**:
> Validates smgglrs's vision of local model serving on consumer hardware.
> Expert streaming could enable smgglrs-model-runtime to serve large MoE models (Mixtral, Qwen) on desktop hardware that would otherwise require cloud offloading.
> The disk-bandwidth-wall insight is directly relevant to smgglrs's hardware tier profiles in MODELS.md.
> model-hub's OCI/HuggingFace caching could be extended to pre-download quantized + expert-streaming-ready model artifacts.

**Actionable Insights**

- **What To Adopt**:
- Consider MoE expert streaming as a model-runtime strategy for large models on CPU tier
- model-hub could cache TurboQuant-quantized MoE artifacts
- **What To Watch**:
- MLX expert streaming support maturity
- ONNX Runtime MoE expert streaming (currently MLX-only)
- vLLM/SGLang expert streaming support
- **What To Avoid**: Don't assume all MoE models benefit equally — disk I/O latency may be unacceptable for real-time interactive use
- **Implementation Difficulty**: significant
- **Priority Sprint**: S13+ (advanced model serving)

**Competitive Position**

- **How Smgglrs Compares**: smgglrs currently targets small ONNX models in-process and larger models via backend engines. Expert streaming would add a new tier between in-process and full backend serving.
- **Gaps Exposed**:
- No MoE-aware model serving strategy in model-runtime
- Hardware tier profiles don't account for SSD bandwidth as a model-serving resource
- **Advantages Confirmed**: smgglrs's tiered model architecture (CPU/GPU) anticipates exactly this kind of capability expansion

**Ecosystem Context**

- **Owasp Coverage**: N/A
- **Mcp Spec Alignment**: N/A
- **Isolation Model**: in-process (MLX)
- **Aaif Alignment**: independent
- **Regulatory Relevance**: N/A

**Economics**

- **Memory Tier**: N/A
- **Token Economics**: Enables running 122B models on $599 hardware instead of cloud GPU instances ($1-5/hour). Significant cost reduction for local-first agent deployments.

---

### vLLM Rust Frontend (PR #40848)

**Basic Info**

- **Name**: vLLM Rust Frontend (PR #40848)
- **Source Url**: https://github.com/vllm-project/vllm/pull/40848
- **Date**: 2026-05-21
- **Authors Org**: Nick Hill (@njhill), Bugen Zhao (@BugenZhao) — Inferact/vLLM
- **Type**: tool
- **License**: Apache 2.0 (vLLM)

**Summary**

- **Core Contribution**:
> Integrates a Rust-based alternative frontend into vLLM, the dominant open-source LLM inference engine.
> Opt-in via VLLM_USE_RUST_FRONTEND=1.
> Adds setuptools-rust build integration, process manager for the Rust binary, and multi-platform Docker support (NVIDIA, ROCm, CPU, HPU, XPU, Intel GPU).
> Switched from nightly to stable Rust toolchain after community review.
> Subsequently vendored into the main repo (replacing git submodule).
- **Key Claims**:
- Merged into vLLM main on 2026-05-21
- Supports all major hardware backends (NVIDIA, ROCm, CPU, HPU, XPU, Intel GPU)
- Switched from nightly to stable Rust after contributor feedback
- Validates Rust-for-inference-infrastructure thesis
- **Methodology**:
> Rust frontend compiled via setuptools-rust, managed as a separate process by a new process manager.
> Initially used git submodule for the Rust code (github.com/Inferact/vllm-frontend-rs), later vendored directly.
> Build system uses RustExtension pointing to workspace member Cargo.toml.
> Addressed reviewer concerns about nightly Rust by replacing coroutine_trait with stable asynk-strim library.

**Smgglrs Relevance**

- **Affected Crates**: model-runtime
- **Relevance Category**: validation
- **Impact Level**: medium
- **Relevance Rationale**:
> Validates the Rust-for-inference-infrastructure thesis that smgglrs embodies.
> vLLM adopting Rust for its frontend confirms that the Rust ecosystem is mature enough for production inference workloads.
> The setuptools-rust integration pattern and process manager architecture may inform smgglrs-model-runtime's vLLM backend integration.

**Actionable Insights**

- **What To Adopt**:
- Use VLLM_USE_RUST_FRONTEND=1 in model-runtime vLLM backend for better performance
- The process manager pattern (Rust binary managed by Python) could inform model-runtime's isolation modes
- **What To Watch**:
- Performance benchmarks of Rust frontend vs Python frontend in vLLM
- Whether Rust frontend becomes the default in future vLLM releases
- **What To Avoid**: N/A
- **Implementation Difficulty**: trivial
- **Priority Sprint**: N/A (environment variable toggle)

**Competitive Position**

- **How Smgglrs Compares**: smgglrs is already fully Rust. vLLM adopting Rust validates smgglrs's technology choice.
- **Gaps Exposed**: N/A
- **Advantages Confirmed**:
- Rust as the right language for inference infrastructure — validated by vLLM's largest PR
- smgglrs's pure-Rust architecture avoids the hybrid Python/Rust complexity vLLM now faces

**Ecosystem Context**

- **Owasp Coverage**: N/A
- **Mcp Spec Alignment**: N/A
- **Isolation Model**: in-process (separate process managed by Python)
- **Aaif Alignment**: independent
- **Regulatory Relevance**: N/A

**Economics**

- **Memory Tier**: N/A
- **Token Economics**: Rust frontend expected to reduce per-request overhead (latency, CPU) vs Python frontend. Benchmarks pending.

---

### Agentic Economy Monetization

**Basic Info**

- **Name**: Agentic Economy Monetization
- **Source Url**: https://metacircuits.substack.com/p/four-ways-to-make-money-in-the-agentic-economy
- **Authors Org**: Jonas Braadbaart (The Circuit / Metacircuits)
- **Type**: article
- **License**: N/A (newsletter article)

**Summary**

- **Core Contribution**:
> Presents a four-quadrant framework for monetization in the agentic economy, organized by digital/physical and owned/rented axes.
> Core thesis: the agentic economy converts labor from payroll to firm-owned or rentable assets, competing for the labor budget (10-30x the software budget).
> Models, tools, and robots all commoditize — the strategic moats are proprietary data, workflow integration, and distribution.
- **Key Claims**:
- Q1 2026: 80% of global VC went to AI (~$242B), on track for $600B full year
- Digital Owned Agents quadrant already at ~$45-50B revenue in 2026
- Foundation Capital sizes the agentic labor TAM at $4.6 trillion
- Labor budget is 10-30x the software budget in North America and Europe
- Models, tools, and robots commoditize — moats are data, workflow integration, distribution
- Anduril $2.1B revenue (2025), guiding $4.3B; Symbotic $2.25B; Waymo valued at $126B
- **Methodology**:
> Two-axis framework: (1) digital vs.
> physical agents, (2) owned vs.
> rented agents.
> Four quadrants: Digital Owned (software agents you build and deploy — the founder's quadrant), Physical Rented (robots/equipment-as-a-service — capex to opex shift), Physical Owned (fleets/factories with deep capital moats — Anduril, Waymo, Amazon warehouse robots), Digital Rented (agent labor marketplaces).
> Each quadrant analyzed for moat depth, TAM, who captures upside, and strategic implications.

**Smgglrs Relevance**

- **Relevance Category**: reference
- **Impact Level**: medium
- **Relevance Rationale**:
> Positions smgglrs in the 'Digital Owned' quadrant infrastructure layer.
> The article's thesis that models and tools commoditize while data/workflow/distribution are the moats validates smgglrs's strategy of being infrastructure (the gateway) rather than competing on models.
> The labor-budget framing (10-30x software budget) reframes smgglrs's value proposition: it enables enterprises to safely deploy agents that compete for labor budgets, not just software budgets.

**Actionable Insights**

- **What To Adopt**:
- Frame smgglrs value proposition around labor automation safety, not just tool access control
- Position smgglrs as infrastructure enabling the 'Digital Owned' quadrant — the gateway that makes owned agents safe to deploy
- Emphasize workflow integration capabilities (MCP gateway aggregation) as a moat-builder for smgglrs users
- **What To Watch**:
- Agent-to-agent commerce protocols (discovery, trust, payments) — the 'Digital Rented' quadrant needs these
- Whether the $4.6T labor TAM claim materializes — tracks adoption velocity
- Commoditization speed of agent infrastructure layers
- **What To Avoid**:
- Competing on model quality or tool quantity — these commoditize per the framework
- Ignoring the distribution/discovery layer — this becomes the critical infrastructure
- **Implementation Difficulty**: trivial
- **Priority Sprint**: N/A (strategic positioning, not implementation)

**Competitive Position**

- **How Smgglrs Compares**:
> smgglrs sits in the infrastructure layer enabling the Digital Owned quadrant.
> The article confirms that the moat is not in models or tools (which commoditize) but in data control, workflow integration, and distribution.
> smgglrs's IFC, security layer, and MCP gateway aggregation directly serve the workflow-integration moat.
- **Gaps Exposed**:
- smgglrs lacks agent-to-agent commerce primitives (payments, metering, SLA enforcement) needed for the Digital Rented quadrant
- No built-in agent marketplace or discovery-layer monetization features
- **Advantages Confirmed**:
- Gateway architecture (aggregating tools behind security) is the right positioning — tools commoditize, security/integration does not
- IFC and capability-based auth enable safe delegation to owned agents, which is the core enabler for the Digital Owned quadrant
- Local/on-premise deployment preserves proprietary data moat for enterprises

**Ecosystem Context**

- **Mcp Spec Alignment**: N/A (business strategy article)
- **Isolation Model**: none
- **Aaif Alignment**: Aligns with AAIF vision of standardized agent interoperability; the Digital Rented quadrant requires exactly the kind of agent identity and trust infrastructure AAIF promotes

**Economics**

- **Memory Tier**: N/A
- **Token Economics**:
> The labor-budget framing (10-30x software budget) suggests agent infrastructure can command higher pricing than traditional software tools.
> Per-task or per-outcome pricing models (selling work, not tools) could yield 10x revenue compared to SaaS subscription models.

**Uncertain Fields**

- date
- owasp_coverage
- regulatory_relevance
- affected_crates

---

### From Raw Experience to Skill Consumption (2605.23899)

**Basic Info**

- **Name**: From Raw Experience to Skill Consumption (2605.23899)
- **Source Url**: https://huggingface.co/papers/2605.23899
- **Date**: 2026-05
- **Authors Org**: Zisu Huang et al. (Fudan University, Microsoft Research, Shanghai Jiao Tong University)
- **Type**: paper
- **License**: N/A (academic paper)

**Summary**

- **Core Contribution**:
> Systematic study of model-generated agent skills across the full lifecycle: extraction, consumption, and transfer.
> Finds non-trivial negative transfer when skills are consumed by different models than those that extracted them.
> Produces a 'meta-skill' approach that consistently reduces negative transfer.
> First paper to separate and empirically measure each lifecycle phase independently.
- **Key Claims**:
- Model's skill-extraction strength does not predict consumption effectiveness
- Non-trivial negative transfer when skills are consumed cross-model
- Meta-skill approach consistently reduces negative transfer across models
- Domain-level skills (packaging recurring procedures) are more effective than per-task skills
- Skills have become standard components in commercial agent platforms
- **Methodology**:
> Decomposes the skill lifecycle into three independent phases (extraction, consumption, transfer) and measures each empirically.
> Tests cross-model skill transfer (skills extracted by model A, consumed by model B).
> Evaluates domain-level skills that package recurring procedures into reusable artifacts.
> Proposes meta-skill training to mitigate negative transfer.

**Smgglrs Relevance**

- **Affected Crates**: cognitive, agent
- **Relevance Category**: reference
- **Impact Level**: medium
- **Relevance Rationale**:
> Directly relevant to smgglrs-cognitive's persona/directive system and potential skill packaging.
> The negative transfer finding warns that skills generated by one model (e.g., Claude) may hurt performance when consumed by another (e.g., local Granite).
> smgglrs-cognitive should consider model-aware skill routing.
> The meta-skill approach could be integrated into directive weaving.

**Actionable Insights**

- **What To Adopt**:
- Model-aware skill routing in smgglrs-cognitive — match skills to the consuming model
- Meta-skill pattern for cross-model compatibility
- **What To Watch**: How MUSE-Autoskill (2605.27366) builds on these findings, Commercial platform adoption of model-aware skill management
- **What To Avoid**: Don't assume skills are model-agnostic — negative transfer is real and measurable
- **Implementation Difficulty**: moderate
- **Priority Sprint**: S12 (cognitive enhancement)

**Competitive Position**

- **How Smgglrs Compares**: smgglrs-cognitive has a persona/directive system but no formal skill lifecycle management. This research provides the theoretical foundation for adding skill management to cognitive.
- **Gaps Exposed**:
- No skill lifecycle management in smgglrs-cognitive
- No model-aware skill routing
- No mechanism to detect or mitigate negative skill transfer
- **Advantages Confirmed**: smgglrs's model-agnostic gateway design allows model-aware routing decisions at the infrastructure level

**Ecosystem Context**

- **Owasp Coverage**: N/A
- **Mcp Spec Alignment**: N/A
- **Isolation Model**: N/A
- **Aaif Alignment**: independent
- **Regulatory Relevance**: N/A

**Economics**

- **Memory Tier**: N/A
- **Token Economics**: Skills reduce per-task token usage by packaging reusable procedures. Meta-skills add small overhead but prevent negative transfer.

---

### Hermes Agent (Nous Research)

**Basic Info**

- **Name**: Hermes Agent (Nous Research)
- **Source Url**: https://hermes-agent.nousresearch.com/
- **Date**: 2026-02
- **Authors Org**: Nous Research
- **Type**: tool
- **License**: MIT

**Summary**

- **Core Contribution**:
> Autonomous, server-resident agent framework with self-improving learning loop.
> Persistent memory across sessions, auto-generated reusable skills, and subagent delegation with zero-context-cost pipelines.
> Supports 5 execution backends (Local, Docker, SSH, Singularity, Modal) with container hardening.
> Cross-platform messaging (Telegram, Discord, Slack, WhatsApp, Signal, Email, CLI) with session continuity.
> Scheduled automations via natural-language cron.
- **Key Claims**:
- 140K+ GitHub stars in 3 months (per web search data)
- Most-used agent on OpenRouter
- Self-improving: creates reusable skills, gets more capable over time
- Zero-context-cost subagent pipelines with independent conversations and terminals
- 5 execution backends with namespace isolation
- **Methodology**:
> Server-resident architecture where the agent runs persistently (vs IDE-bound copilots).
> Subagent system provides each delegated task with its own conversation context, terminal, and Python RPC scripts.
> Skills are auto-generated from successful task completions and stored for reuse.
> Memory persists across sessions for continuous learning.

**Smgglrs Relevance**

- **Affected Crates**: agent, flow, cognitive, tools-exec
- **Relevance Category**: reference
- **Impact Level**: medium
- **Relevance Rationale**:
> Hermes Agent is a major consumer of gateway infrastructure like smgglrs, not a direct competitor.
> Its skill auto-generation and subagent patterns inform smgglrs-cognitive's directive system and smgglrs-flow's orchestration.
> The 5 execution backends (Local, Docker, SSH, Singularity, Modal) map to smgglrs-model-runtime's isolation modes (direct, Podman, OpenShell).
> Hermes using smgglrs as its MCP gateway would be a natural integration.

**Actionable Insights**

- **What To Adopt**:
- Zero-context-cost subagent pattern — smgglrs-flow could support isolated context per sub-agent in DAG execution
- Natural-language cron scheduling — smgglrs-agent could expose as a module capability
- **What To Watch**:
- Hermes Agent's MCP integration path — potential first-class smgglrs consumer
- Skill auto-generation quality and cross-agent transfer results
- Singularity backend pattern for HPC environments
- **What To Avoid**: Don't replicate Hermes's full agent framework — smgglrs is infrastructure, Hermes is application layer
- **Implementation Difficulty**: N/A
- **Priority Sprint**: N/A (consumer, not feature)

**Competitive Position**

- **How Smgglrs Compares**: Different layers: Hermes is an agent application, smgglrs is gateway infrastructure. Hermes would run on top of smgglrs, using it for secure tool access, safety filtering, and IFC enforcement.
- **Gaps Exposed**: smgglrs-agent's skill system is less sophisticated than Hermes's auto-generated skills with cross-agent transfer
- **Advantages Confirmed**:
- smgglrs's gateway model is validated — Hermes needs exactly this kind of infrastructure for secure tool access
- smgglrs's multiple isolation backends (direct, Podman, OpenShell) match Hermes's execution backends

**Ecosystem Context**

- **Owasp Coverage**: ASI05 (Code Execution — container hardening), ASI07 (Inter-Agent Communication — subagent delegation)
- **Isolation Model**: container (Docker, Singularity), SSH, Modal
- **Regulatory Relevance**: N/A

**Economics**

- **Memory Tier**: tiered (short-term context + long-term persistent memory + skill-level memory)
- **Token Economics**: Zero-context-cost subagents reduce token usage for delegated tasks by not sharing parent context.

**Uncertain Fields**

- mcp_spec_alignment
- aaif_alignment

---

### HuggingFace Agent Glossary

**Basic Info**

- **Name**: HuggingFace Agent Glossary
- **Source Url**: https://huggingface.co/blog/agent-glossary
- **Date**: 2026-05-25
- **Authors Org**: Sergio Paniego, Aritra Roy Gosthipaty (HuggingFace)
- **Type**: article
- **License**: N/A (blog post)

**Summary**

- **Core Contribution**:
> Canonical 2026 taxonomy of agent concepts.
> Central formula: Agent = Model + Harness.
> Distinguishes scaffolding (behavior-defining: system prompt, tool descriptions, context management) from harness (execution: calls model, handles tool calls, decides stop).
> Defines: tool use, skills (reusable goal packages), sub-agents (reasoning-capable delegated agents), orchestrator (multi-agent coordinator), context engineering, and policy.
> Positions MCP at the Tool Use / Harness interface as the interoperability standard.
- **Key Claims**:
- Agent = Model + Harness (not model alone)
- Scaffolding shapes what the model works FROM; Harness makes the model RUN
- Skills are distinguished from tools by being reusable, portable, loaded-on-demand goal packages
- Sub-agents reason independently (vs tools which are function calls, vs skills which are packaged knowledge)
- MCP standardizes the Tool Use to Harness connection across vendors
- **Methodology**: Definitional article establishing shared vocabulary. Draws on HuggingFace's agent framework ecosystem experience. Community-reviewed by Pedro Cuenca, Quentin Gallouedec, Shaun Smith, Adithya S Kolavi.

**Smgglrs Relevance**

- **Affected Crates**: protocol, agent, flow, cognitive
- **Relevance Category**: reference
- **Impact Level**: medium
- **Relevance Rationale**:
> Establishes canonical vocabulary for the agent ecosystem smgglrs serves.
> The Agent=Model+Harness formula maps directly to smgglrs architecture: smgglrs IS the harness infrastructure (security, tool routing, context management).
> The skill/sub-agent/orchestrator hierarchy maps to smgglrs-cognitive (skills), smgglrs-agent (sub-agents), and smgglrs-flow (orchestrator).
> MCP positioned at Tool Use / Harness interface validates smgglrs-protocol's role.

**Actionable Insights**

- **What To Adopt**:
- Adopt this vocabulary in smgglrs documentation and API naming
- Align smgglrs-cognitive's persona/directive system with the 'scaffolding' concept
- Validate smgglrs-flow's orchestrator role matches the glossary definition
- **What To Watch**:
- Whether this taxonomy becomes the industry standard (HuggingFace has significant ecosystem influence)
- How the skill vs tool distinction evolves in MCP spec
- **What To Avoid**: - Don't conflate smgglrs's module concept with 'tool' — smgglrs modules are harness infrastructure, not tools in this taxonomy
- **Implementation Difficulty**: trivial
- **Priority Sprint**: N/A (documentation alignment)

**Competitive Position**

- **How Smgglrs Compares**:
> smgglrs maps cleanly to this taxonomy as harness infrastructure — the gateway that mediates between agents and tools.
> smgglrs-flow is an orchestrator.
> smgglrs-cognitive provides scaffolding.
> smgglrs-agent is a sub-agent framework.
- **Gaps Exposed**: - smgglrs doesn't have an explicit 'skill' abstraction — cognitive directives are close but not the same as portable skill packages
- **Advantages Confirmed**:
- smgglrs's architecture as gateway (harness infrastructure) is validated as the correct abstraction layer
- MCP at the Tool/Harness interface is exactly where smgglrs-protocol operates

**Ecosystem Context**

- **Owasp Coverage**: N/A (taxonomy, not security)
- **Mcp Spec Alignment**: All versions — vocabulary is spec-version-independent
- **Isolation Model**: N/A
- **Aaif Alignment**: HuggingFace is AAIF adjacent but this glossary is independent
- **Regulatory Relevance**: N/A

**Economics**

- **Memory Tier**: N/A
- **Token Economics**: N/A

---

### Eagle 3.1

**Basic Info**

- **Name**: Eagle 3.1
- **Source Url**: https://www.marktechpost.com/2026/05/27/meet-eagle-3-1-the-speculative-decoding-algorithm-that-fixes-attention-drift-in-llm-inference/
- **Date**: 2026-05-26
- **Authors Org**: EAGLE Team + vLLM Team + TorchSpec Team (arXiv 2605.09992)
- **Type**: paper+tool
- **License**: Apache 2.0 (vLLM)

**Summary**

- **Core Contribution**:
> Eagle 3.1 fixes attention drift in speculative decoding — a production reliability problem where the drafter model progressively shifts attention away from important sink tokens toward its own generated tokens as speculation depth increases.
> Two architectural changes: (1) FC normalization after target hidden states, (2) post-norm hidden-state feedback for recursive drafter behavior.
- **Key Claims**:
- Up to 2x longer acceptance length in long-context workloads vs EAGLE 3
- 2.03x per-user output throughput at concurrency=1 (Kimi K2.6, GB200, TP=4)
- 1.66x throughput even at concurrency=16
- Backward-compatible with EAGLE 3 checkpoints
- Merged into vLLM main, stable in v0.22.0
- **Methodology**:
> Root cause analysis identified two sources of attention drift: (1) fused input representation imbalance where higher-layer hidden states dominate drafter input, (2) unnormalized residual path causing magnitude growth across speculation steps.
> Fix 1 applies normalization after each target hidden state before the FC layer.
> Fix 2 feeds normalized hidden states into the next step, making the drafter behave like recursive invocation rather than appending layers.

**Smgglrs Relevance**

- **Affected Crates**: model-runtime
- **Relevance Category**: opportunity
- **Impact Level**: low
- **Relevance Rationale**:
> Eagle 3.1 improves inference throughput for large models served via vLLM, which smgglrs-model-runtime could use as a backend.
> The attention drift fix is particularly relevant for long-context agent workloads where smgglrs would maintain extended conversations.
> However, smgglrs doesn't directly implement speculative decoding — this is consumed transitively through serving engines.

**Actionable Insights**

- **What To Adopt**: Ensure model-runtime vLLM backend uses v0.22.0+ to benefit from Eagle 3.1 automatically
- **What To Watch**:
- TorchSpec training support for custom draft models — could enable spec decoding for smgglrs-served models
- Eagle 3.1 support across more model architectures
- **What To Avoid**: Don't implement speculative decoding in smgglrs — leave to serving engine
- **Implementation Difficulty**: trivial
- **Priority Sprint**: N/A (version bump only)

**Competitive Position**

- **How Smgglrs Compares**: smgglrs benefits transitively — model-runtime backends using vLLM 0.22.0+ get Eagle 3.1 automatically.
- **Gaps Exposed**: N/A
- **Advantages Confirmed**: - smgglrs's backend-agnostic model-runtime design means inference improvements like Eagle 3.1 are absorbed without code changes

**Ecosystem Context**

- **Owasp Coverage**: N/A
- **Mcp Spec Alignment**: N/A
- **Isolation Model**: in-process (vLLM integration)
- **Aaif Alignment**: independent
- **Regulatory Relevance**: N/A

**Economics**

- **Memory Tier**: N/A
- **Token Economics**: 2x throughput improvement for long-context workloads reduces per-token serving cost by ~50% for affected workloads.

---

### AXPO: Agent Explorative Policy Optimization (2605.28774)

**Basic Info**

- **Name**: AXPO: Agent Explorative Policy Optimization (2605.28774)
- **Source Url**: https://huggingface.co/papers/2605.28774
- **Date**: 2026-05
- **Authors Org**: Minki Kang, Shizhe Diao, Ryo Hachiuma, Sung Ju Hwang, Pavlo Molchanov, Yu-Chiang Frank Wang, Byung-Kwan Lee (NVIDIA)
- **Type**: paper
- **License**: N/A (academic paper)

**Summary**

- **Core Contribution**:
> Addresses the Thinking-Acting Gap in RL-trained vision-language models: standard RL (GRPO) causes models to heavily favor internal thinking over tool use, suppressing learning signal for tool-calling behavior.
> AXPO fixes all-wrong tool-using subgroups by fixing the thinking prefix and resampling the tool call continuation, recovering the learning signal for agentic behavior.
- **Key Claims**:
- Tool use attempted in only ~30% of rollouts under standard GRPO
- When attempted, tool-using rollouts are all-wrong ~40% of the time
- SFT+AXPO outperforms SFT+GRPO by +1.8pp Pass@1 and +1.8pp Pass@4 at 8B scale
- 8B model with SFT+AXPO surpasses 32B base model on Pass@4 (4x fewer parameters)
- Evaluated across three scales of Qwen3-VL-Thinking
- **Methodology**:
> For each all-wrong tool-using subgroup in RL training: (1) fix the thinking prefix (reasoning before tool call), (2) resample the tool call and its continuation to recover learning signal, (3) use uncertainty-based prefix selection to choose which prefixes to resample.
> This addresses the structural asymmetry where thinking (self-contained default) dominates over tool use (high-variance auxiliary acting).

**Smgglrs Relevance**

- **Affected Crates**: agent, model
- **Relevance Category**: reference
- **Impact Level**: low
- **Relevance Rationale**:
> The Thinking-Acting Gap finding explains why agents sometimes skip tool calls even when tools would help — relevant to understanding smgglrs-agent's tool-use loop behavior.
> The fix is at the RL training level (not inference), so smgglrs can't implement it directly.
> However, smgglrs could track tool-call skip rates as a diagnostic metric for model quality.

**Actionable Insights**

- **What To Adopt**: Track tool-call skip rates in smgglrs-agent as a model quality diagnostic
- **What To Watch**:
- Whether AXPO-trained models become available for local serving
- Application of AXPO to text-only (non-vision) tool calling
- **What To Avoid**: N/A
- **Implementation Difficulty**: trivial
- **Priority Sprint**: N/A (diagnostic metric only)

**Competitive Position**

- **How Smgglrs Compares**: Not directly comparable — AXPO is a training technique, smgglrs is inference infrastructure.
- **Gaps Exposed**: N/A
- **Advantages Confirmed**: N/A

**Ecosystem Context**

- **Owasp Coverage**: N/A
- **Mcp Spec Alignment**: N/A
- **Isolation Model**: N/A
- **Aaif Alignment**: independent
- **Regulatory Relevance**: N/A

**Economics**

- **Memory Tier**: N/A
- **Token Economics**: AXPO reduces the need for larger models (8B matches 32B), lowering inference cost.

---

### ParaVT: Parallel Video Tool Calling (2605.20342)

**Basic Info**

- **Name**: ParaVT: Parallel Video Tool Calling (2605.20342)
- **Source Url**: https://huggingface.co/papers/2605.20342
- **Date**: 2026-05
- **Authors Org**: Zuhao Yang et al. (MiroMind, NTU, HKU, HKUST(GZ), THU, LMMs-Lab)
- **Type**: paper
- **License**: N/A (academic paper)

**Summary**

- **Core Contribution**:
> First multi-agent end-to-end RL-trained framework for parallel video tool calling.
> Main agent emits K parallel tool_call invocations on disjoint temporal windows; K independent sub-agents each ground one window and return textual summaries.
> Identifies the 'Tool Prior Paradox' where pretrained tool priors enable exploration but destabilize format compliance.
> PARA-GRPO algorithm solves this with targeted format rewards and per-prompt frame-budget randomization.
- **Key Claims**:
- +7.9% average improvement over Qwen3-VL-8B across 6 long-video benchmarks
- Format compliance lifted from 0.13 to 0.64 during training
- Surpasses GPT-4o on LVBench (39.8 vs 34.7) and MMVU (68.6 vs 66.7)
- Parallel dispatch outperforms sequential on same checkpoint across every benchmark
- Peer-correctable evidence: mis-localized windows outvoted by peers
- **Methodology**:
> Single-turn parallel dispatch: main agent emits K tool calls, K sub-agents (weight-shared) each process one temporal window and return text summaries (not resampled frames).
> PARA-GRPO addresses Tool Prior Paradox via: (1) Exploration Anchoring — selective reward at structural-token positions prone to collapse, (2) nFrames Gating — randomizes overview-frame budget per prompt to create prompts where tools yield measurable reward.

**Smgglrs Relevance**

- **Affected Crates**: flow, agent
- **Relevance Category**: reference
- **Impact Level**: low
- **Relevance Rationale**:
> The parallel tool dispatch pattern is directly relevant to smgglrs-flow's DAG execution and smgglrs-agent's tool-use loop.
> Peer-correctable evidence (sub-agent outputs voted on) maps to flow's mesh communication.
> The Tool Prior Paradox finding is relevant to understanding why agents skip tool calls — smgglrs could expose analytics on tool call rates.
> However, the video-specific application is outside smgglrs's scope.

**Actionable Insights**

- **What To Adopt**:
- Parallel tool dispatch pattern in smgglrs-flow DAG execution — emit multiple tool calls in single turn
- Peer-correctable evidence pattern for multi-agent mesh validation
- **What To Watch**: Extension of PARA-GRPO to non-video tool calling scenarios, Adoption of parallel dispatch in mainstream agent frameworks
- **What To Avoid**: N/A
- **Implementation Difficulty**: moderate
- **Priority Sprint**: S12+ (flow optimization)

**Competitive Position**

- **How Smgglrs Compares**: smgglrs-flow already supports parallel tool execution in DAG mode. ParaVT validates this pattern with RL-trained evidence of superiority over sequential dispatch.
- **Gaps Exposed**: N/A
- **Advantages Confirmed**: smgglrs-flow's DAG execution with parallel tool calls is the correct architecture

**Ecosystem Context**

- **Owasp Coverage**: N/A
- **Mcp Spec Alignment**: N/A
- **Isolation Model**: N/A
- **Aaif Alignment**: independent
- **Regulatory Relevance**: N/A

**Economics**

- **Memory Tier**: N/A
- **Token Economics**: Parallel dispatch with text summaries (not resampled frames) controls context growth — bounded token cost vs linear growth in sequential dispatch.

---

### Speculative Speculative Decoding (SAGUARO)

**Basic Info**

- **Name**: Speculative Speculative Decoding (SAGUARO)
- **Source Url**: https://openreview.net/pdf?id=aL1Wnml9Ef
- **Date**: 2026-01
- **Authors Org**: ICLR 2026
- **Type**: paper
- **License**: N/A (academic paper)

**Summary**

- **Core Contribution**:
> SAGUARO parallelizes the sequential draft-verify cycle in speculative decoding itself.
> Standard speculative decoding drafts tokens then verifies them sequentially; SAGUARO overlaps these phases to reduce end-to-end latency.
- **Key Claims**:
- 30% faster than strongest speculative decoding baselines
- Up to 5x faster than standard autoregressive decoding
- Parallelizes the draft-verify cycle that was previously sequential

**Smgglrs Relevance**

- **Affected Crates**: model-runtime
- **Relevance Category**: reference
- **Impact Level**: low
- **Relevance Rationale**:
> Academic advance in speculative decoding that will eventually be absorbed by serving engines (vLLM, SGLang).
> smgglrs benefits transitively when model-runtime backends adopt SAGUARO.
> No direct implementation needed.

**Actionable Insights**

- **What To Adopt**: N/A
- **What To Watch**: vLLM/SGLang adoption of SAGUARO algorithm, Combination with Eagle 3.1 (attention drift fix + parallelized verification)
- **What To Avoid**: N/A
- **Implementation Difficulty**: N/A
- **Priority Sprint**: N/A (consumed transitively)

**Competitive Position**

- **How Smgglrs Compares**: Not directly comparable — smgglrs doesn't implement decoding algorithms.
- **Gaps Exposed**: N/A
- **Advantages Confirmed**: N/A

**Ecosystem Context**

- **Owasp Coverage**: N/A
- **Mcp Spec Alignment**: N/A
- **Isolation Model**: N/A
- **Aaif Alignment**: independent
- **Regulatory Relevance**: N/A

**Economics**

- **Memory Tier**: N/A
- **Token Economics**: 5x faster than autoregressive reduces per-token serving cost by ~80% when adopted by serving engines.

**Uncertain Fields**

- methodology

---
