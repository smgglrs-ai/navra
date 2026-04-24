# Opportunities — Industry Landscape Analysis (April 2026)

Research from industry developments and their implications
for smgglrs and Myelix. Updated April 10, 2026.

## Sources

1. [Microsoft Agent Framework v1.0](https://devblogs.microsoft.com/agent-framework/microsoft-agent-framework-version-1-0/)
2. [Claude Code Agent Teams](https://www.geeky-gadgets.com/cloud-code-agent-teams/)
3. [Microsoft Agent Governance Toolkit](https://opensource.microsoft.com/blog/2026/04/02/introducing-the-agent-governance-toolkit-open-source-runtime-security-for-ai-agents/)
4. [GitHub Copilot Cloud Agent Commit Signing](https://github.blog/changelog/2026-04-03-copilot-cloud-agent-signs-its-commits/)
5. [IBM Granite 4.0 3B Vision](https://www.marktechpost.com/2026/04/01/ibm-releases-granite-4-0-3b-vision-a-new-vision-language-model-for-enterprise-grade-document-data-extraction/)
6. [Coding Agent Components](https://magazine.sebastianraschka.com/p/components-of-a-coding-agent) — Raschka
7. [AG-UI Multi-Agent Workflow](https://devblogs.microsoft.com/agent-framework/ag-ui-multi-agent-workflow-demo/)
8. [Google SCION](https://github.com/GoogleCloudPlatform/scion) — Multi-agent orchestration
9. [OpenVINO 2026.1](https://www.phoronix.com/news/OpenVINO-2026.1-Released)
10. [GLM-OCR local deployment](https://theneuralmaze.substack.com/p/run-the-worlds-best-ocr-on-your-own)
11. [RamaLama](https://github.com/containers/ramalama) — Container-native model management

## 1. Microsoft Agent Framework v1.0

### What It Is

Production-ready open-source SDK for building AI agents and
multi-agent systems. Unifies Semantic Kernel + AutoGen. Supports
.NET and Python. Pluggable model connectors (Azure, OpenAI,
Anthropic, Bedrock, Gemini, Ollama). MCP support for dynamic
tool discovery. A2A protocol support forthcoming.

### Relevance

MAF is an orchestration SDK — comparable to Myelix, not to smgglrs.
It **uses** MCP servers for tool discovery, meaning it would
connect to smgglrs the same way Myelix does.

Key parallels:

| MAF v1.0 | Myelix | smgglrs |
|---|---|---|
| Multi-agent orchestration patterns | ConcurrentOrchestrator, Leader | N/A (infrastructure) |
| Middleware pipeline (intercept/transform) | Cognitive Immune System | Hook pipeline (pre/post) |
| MCP for tool discovery | MCP client (45+ tools) | MCP server (gateway) |
| Declarative YAML workflows | YAML personas (not workflows) | TOML config |
| A2A protocol (forthcoming) | A2A implemented (JSON-RPC 2.0) | AID + Agent Card endpoints |

### Opportunities

**For smgglrs:**
- smgglrs is already well-positioned as the tool provider MAF would
  consume. No architectural changes needed.
- MAF's A2A direction validates smgglrs's DISCOVERY.md research and
  existing `/.well-known/agent-card.json` endpoint.

**For Myelix:**
- MAF's **declarative workflow YAML** is a pattern Myelix lacks.
  Myelix defines *who* agents are in YAML but hardcodes *how* they
  collaborate in Python. A workflow definition layer could let users
  compose multi-agent flows without code.
- MAF's **DevUI** (browser-based execution debugger) could inspire
  a similar visualization for Myelix's multi-agent orchestration.

## 2. Claude Code Agent Teams

### What It Is

Multi-agent collaboration via Claude Code's settings.json —
orchestrator + 3-5 specialized agents with parallel execution,
direct inter-agent communication, and plan approval mode.

### Relevance

This is the ad-hoc version of what Myelix does natively with
Leader + specialist personas. The article validates the pattern
Myelix chose is becoming mainstream.

### Opportunities

**For smgglrs:**
- Claude Agent Teams with no smgglrs-like gateway means every agent
  has the same filesystem access. smgglrs solves the **security problem**
  this creates: each agent maps to a distinct identity with scoped
  permissions. This is a selling point for smgglrs.

**For Myelix:**
- No direct action items. Myelix already implements this pattern
  with more structure (ReAct loops, task planning, drift detection).

## 3. Agent Governance Toolkit

### What It Is

Microsoft's open-source toolkit addressing all 10 OWASP agentic AI
risks with deterministic, sub-millisecond policy enforcement. Seven
packages: Agent OS (policy engine), Agent Mesh (cryptographic
identity via DIDs), Agent Runtime (execution rings), Agent SRE
(SLOs, circuit breakers), Agent Compliance (regulatory mapping),
Agent Marketplace (signed plugins), Agent Lightning (policy RL).

Integrates with existing frameworks without code rewrites. SDKs
in Python, TypeScript, Rust, Go, .NET.

### Relevance

This is the most strategically important article for smgglrs. Direct
feature mapping:

| Governance Toolkit | smgglrs Status | Gap |
|---|---|---|
| Agent OS (<0.1ms policy engine) | Permission engine (ACLs + tool rules) | None |
| Agent Mesh (DIDs, Ed25519) | BLAKE3 token auth + AID PKA research | **Partial** |
| Agent Runtime (execution rings) | 2-level permissions + Pause/Resume | **Partial** |
| Agent SRE (SLOs, circuit breakers) | Resilient Transports (backoff) | **Partial** |
| Agent Compliance (regulatory mapping) | Content safety profiles | **Gap** |
| Agent Marketplace (signed plugins) | N/A (Myelix has OCI + sigstore) | N/A |
| Agent Lightning (policy RL) | N/A | N/A |

### Opportunities

**For smgglrs (high priority):**

1. **Agent commit signing** — When `git_commit` runs through smgglrs,
   the commit should be signed with the agent's Ed25519 key, not
   the user's GPG key. Config adds `signing_key` to `[[agents]]`.
   Git's SSH signing support (`gpg.format=ssh`) works natively
   with Ed25519. This produces `Verified` commits traceable to a
   specific agent identity.

2. **Compliance tags on permission sets** — Add an optional
   `compliance` field to permission sets mapping operations to
   regulatory frameworks. Logged at startup, queryable via status.
   Example:
   ```toml
   [permissions.developer]
   compliance = ["SOC2-CC6.1", "EU-AI-Act-Art-14"]
   ```

3. **Graduated permission rings** — Extend the current 2-level
   model (allowed/denied) to N-level rings inspired by CPU privilege
   levels. Example: `ring0: admin`, `ring1: developer`, `ring2:
   readonly`, `ring3: sandboxed`. Lower rings inherit restrictions
   from higher rings.

4. **DID-based agent identity** — Extend the existing AID PKA
   research to full DID (Decentralized Identifier) support. Each
   agent gets a DID anchored to its Ed25519 key, enabling
   cryptographic identity verification across systems.

**For Myelix (medium priority):**

5. The Cognitive Immune System could adopt more formal policy
   language (OPA Rego or Cedar) rather than Python-based anomaly
   detection, enabling deterministic policy enforcement.

## 4. Copilot Cloud Agent Commit Signing

### What It Is

GitHub's Copilot cloud agent now automatically signs every commit
it creates. Commits display as `Verified` on GitHub. Previously,
repositories with `Require signed commits` branch protection blocked
the agent entirely.

### Relevance

Directly actionable for smgglrs-tools-git. When an agent commits through
smgglrs, the commit should carry cryptographic proof of which agent
authored it.

### Opportunities

**For smgglrs (high priority):**

1. **Implement agent commit signing in smgglrs-tools-git** — Add an
   optional `signing_key` path to agent config. When present,
   `git_commit` uses Git's SSH signing (`gpg.format=ssh`,
   `user.signingkey`) to sign with the agent's Ed25519 key.

2. **Agent identity in commit trailer** — Add a `Signed-off-by:
   <agent-name> (via smgglrs)` trailer to agent-authored commits,
   making provenance visible in `git log` even without GPG
   verification.

**For Myelix (low priority):**

3. When Myelix's autonomous agent (EPIC-009/EPIC-026) executes
   commits via its own tools (not through smgglrs), it should also
   sign them. This is a Myelix-side concern only when smgglrs is
   not in the path.

## 5. IBM Granite 4.0 3B Vision

### What It Is

3-billion parameter vision-language model optimized for enterprise
document processing. OCR, form recognition, invoice processing,
compliance document analysis. Compact enough for edge deployment.

### Relevance

smgglrs already uses Granite Vision 3.3 2B for OCR/document
understanding (GPU tier). Granite 4.0 3B Vision is the successor.

### Opportunities

**For smgglrs (medium priority):**

1. **Evaluate as Vision 3.3 2B replacement** — Granite 4.0 3B
   Vision (~2GB NVFP4) fits the existing GPU budget. Update
   MODELS.md with benchmarks when available. Add to `smgglrs model
   available` registry.

2. **Document extraction pipeline** — The enterprise document
   focus aligns with `smgglrs-tools-docs` watch directories. A future
   enhancement could run Granite Vision on new PDF/image files
   in watched directories, extracting text and indexing via FTS5
   + sqlite-vec.

**For Myelix (low priority):**

3. A **document analyst persona** that knows when to delegate
   `vision_ocr`/`vision_describe` calls through smgglrs. The model
   runs in smgglrs; the cognitive framing (when to use vision, how
   to interpret results) is a Myelix persona concern.

## Summary: Priority Matrix

| Priority | Item | Project | Source | Status |
|---|---|---|---|---|
| **High** | Agent commit signing in `git_commit` | smgglrs | Copilot signing + Governance | **Done** |
| **High** | Compliance tags on permission sets | smgglrs | Governance Toolkit | **Done** |
| **Medium** | Granite 4.0 3B Vision in model registry | smgglrs | IBM Granite | Planned (awaiting GA) |
| **Medium** | Graduated permission rings | smgglrs | Governance Toolkit | **Done** |
| **Medium** | Declarative workflow YAML | Myelix | MAF v1.0 | |
| **Low** | DID-based agent identity | smgglrs | Governance Toolkit | |
| **Low** | Activate A2A endpoint in smgglrs | smgglrs | MAF + Myelix A2A | **Done** |
| **Low** | Document analyst persona | Myelix | Granite Vision | |
| **Low** | Multi-agent execution debugger | Myelix | MAF DevUI | |

## Validation

smgglrs's architecture is well-aligned with industry direction:

- **MCP gateway pattern**: MAF uses MCP for tool discovery. smgglrs
  is already the canonical MCP tool provider.
- **Security-first**: The Governance Toolkit validates smgglrs's
  defense-in-depth approach (auth, ACLs, safety, hooks, approval).
- **Discovery**: AID, Agent Cards, MCP Server Cards, mDNS — smgglrs
  already implements or plans all four discovery layers.
- **Agent identity**: The industry is converging on Ed25519 for
  agent cryptographic identity (AID PKA, DID, commit signing).
  smgglrs uses BLAKE3 for auth tokens; extending to Ed25519 signing
  keys is natural.

The main remaining gaps are **graduated permission rings** and
**DID-based agent identity**. Agent commit signing, compliance
tags, and the A2A endpoint are all implemented.

## 6. Coding Agent Components (Raschka)

### What It Is

Sebastian Raschka's analysis of the 6 core components of a coding
agent harness: (1) live repository context, (2) prompt cache
separation (stable vs dynamic), (3) structured tool access with
validation, (4) context bloat minimization (clipping + transcript
reduction), (5) dual-layer session memory (full transcript +
distilled working memory), (6) bounded subagent delegation.

### Relevance

Directly informs the design of `smgglrs-agent` SDK. Key insight:
"a lot of apparent model quality is really context quality" — the
harness matters as much as the model.

### Opportunities

1. **Agent SDK context management** — Implement cache-aware prompt
   construction in smgglrs-agent, separating stable infrastructure
   (tool descriptions, system prompt) from dynamic state
   (conversation history). Enables prompt cache reuse.
2. **Bounded subagent spawning** — When smgglrs-agent supports
   delegation, constrain subagent scope via read-only modes, depth
   limits, or explicit task boundaries rather than full access.
3. **Resumable session state** — Store complete transcripts
   separately from operational memory, enabling session recovery
   and audit trails. Maps to smgglrs-core session management.

## 7. AG-UI Multi-Agent Workflow (Microsoft)

### What It Is

AG-UI is an open protocol for streaming agent execution events to
frontends via SSE. The Microsoft Agent Framework integration uses
`HandoffBuilder` for declarative agent topology: directed edges
with natural-language routing descriptions. Includes tool-level
approval (`approval_mode="always_require"`) and information request
interrupts (`HandoffAgentUserRequest`).

### Relevance

Two patterns directly applicable to smgglrs/Myelix:
- HandoffBuilder's declarative agent graph → flow DSL design
- Interrupt/resume model → hook pipeline human-in-the-loop

### Opportunities

1. **Flow DSL design** — Adopt HandoffBuilder's pattern for the
   declarative flow DSL (Priority 2): define agent topology as
   directed edges with routing descriptions, not prompt-based
   routing. Each edge carries IFC constraints.
2. **Hook pipeline interrupts** — Extend the hook pipeline to
   support interrupt/resume for human-in-the-loop approval,
   similar to AG-UI's `TOOL_CALL_*` pause events. The existing
   approval system in smgglrs-core already supports this; AG-UI
   validates the event-streaming approach.
3. **SSE event streaming** — AG-UI's event types (`RUN_STARTED`,
   `STEP_STARTED`, `TEXT_MESSAGE_*`, `TOOL_CALL_*`, `RUN_FINISHED`)
   could inform how Myelix exposes workflow progress to UIs.

## 8. Google SCION — Multi-Agent Orchestration

### What It Is

Experimental orchestration platform from Google Cloud that runs
multiple AI agents (Claude Code, Gemini CLI, Codex) as isolated
concurrent processes. Each agent gets its own container with
separate credentials, config, and git worktrees. Agents coordinate
via shared CLI tool + natural language. Template-based role
specialization. OpenTelemetry observability.

### Relevance

Validates Myelix's multi-agent problem space. Different approach:
SCION is decentralized (agents negotiate), smgglrs/Myelix is
centralized (gateway enforces security). SCION's container
isolation per agent is similar to our model runtime isolation.

### Opportunities

1. **Per-agent isolation** — SCION's model of isolated credentials
   per agent aligns with smgglrs's capability tokens. Consider
   whether smgglrs-agent should support containerized agent
   execution (via smgglrs-model-runtime's Podman backend).
2. **OpenTelemetry** — SCION's normalized telemetry across agent
   harnesses is worth adopting for smgglrs observability.

## 9. OpenVINO 2026.1 — llama.cpp Backend

### What It Is

Intel's OpenVINO 2026.1 adds a preview backend for llama.cpp,
enabling optimized inference on Intel CPUs, GPUs, and NPUs.
Validated on Llama-3.2-1B, Phi-3-mini, Qwen2.5-1.5B, Mistral-7B.
Also adds Wildcat Lake SoC support and Intel Arc Pro B70 (32GB).

### Relevance

This means managed-tier models served via `smgglrs-model-runtime`
(which spawns llama-server) can transparently use Intel NPU
acceleration if OpenVINO is installed. No smgglrs code changes needed.

### Opportunities

1. **Intel NPU for managed models** — Document that llama-server
   with OpenVINO backend enables NPU inference for managed-tier
   models. Test with Granite models on Intel Core Ultra hardware.
2. **OpenVINO EP for ort** — Add `OpenVINOExecutionProvider` option
   to `OnnxBackend::load()` for in-process models (embeddings,
   safety classifier) on Intel hardware.

## 10. GLM-OCR — Local Document Understanding

### What It Is

0.9B parameter OCR model, #1 on OmniDocBench V1.5 (94.62 score).
Runs locally via llama.cpp/Ollama on CPU. Outputs structured
markdown from complex documents (tables, headers, forms).

### Relevance

Fills the document ingestion gap in smgglrs-tools-docs and
smgglrs-rag. Small enough for CPU-tier via managed runtime.

### Opportunities

1. **Document ingestion pipeline** — Add GLM-OCR as a managed model
   (`source = "ollama://glm-ocr"`) for converting PDFs/images to
   searchable text. Feed output into smgglrs-rag for semantic indexing.
2. **Complement Granite Vision** — GLM-OCR for CPU-tier bulk
   ingestion, Granite Vision 3.3 2B for GPU-tier accuracy-critical OCR.

## 11. RamaLama — Prior Art for Model Management

### What It Is

Python CLI from the Containers org (Podman/Buildah/Skopeo team)
that treats AI models like container images. `ramalama serve`
auto-detects GPU, pulls matching container image, runs llama.cpp
or vLLM in rootless Podman with `--network=none` isolation.
Supports `ollama://`, `hf://`, `oci://` URI schemes.

### Relevance

Direct prior art for `smgglrs-model-hub` and `smgglrs-model-runtime`.
We reimplemented the relevant parts in Rust (URI scheme, cache,
GPU detection, container lifecycle) as reusable crates without
the Python dependency.

### Opportunities

1. **URI compatibility** — Our hub uses the same URI scheme as
   RamaLama. If RamaLama evolves its registry format, track it.
2. **OCI model artifacts** — RamaLama's `ramalama convert` creates
   OCI images from models. Our OCI transport could pull these.
3. **Security model alignment** — RamaLama's `--network=none` +
   read-only mounts is the same pattern we use in PodmanRuntime.
