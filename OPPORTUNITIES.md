# Opportunities — Industry Landscape Analysis (April 2026)

Research from five industry developments and their implications
for mcpd and Myelix.

## Sources

1. [Microsoft Agent Framework v1.0](https://devblogs.microsoft.com/agent-framework/microsoft-agent-framework-version-1-0/)
2. [Claude Code Agent Teams](https://www.geeky-gadgets.com/cloud-code-agent-teams/)
3. [Microsoft Agent Governance Toolkit](https://opensource.microsoft.com/blog/2026/04/02/introducing-the-agent-governance-toolkit-open-source-runtime-security-for-ai-agents/)
4. [GitHub Copilot Cloud Agent Commit Signing](https://github.blog/changelog/2026-04-03-copilot-cloud-agent-signs-its-commits/)
5. [IBM Granite 4.0 3B Vision](https://www.marktechpost.com/2026/04/01/ibm-releases-granite-4-0-3b-vision-a-new-vision-language-model-for-enterprise-grade-document-data-extraction/)

## 1. Microsoft Agent Framework v1.0

### What It Is

Production-ready open-source SDK for building AI agents and
multi-agent systems. Unifies Semantic Kernel + AutoGen. Supports
.NET and Python. Pluggable model connectors (Azure, OpenAI,
Anthropic, Bedrock, Gemini, Ollama). MCP support for dynamic
tool discovery. A2A protocol support forthcoming.

### Relevance

MAF is an orchestration SDK — comparable to Myelix, not to mcpd.
It **uses** MCP servers for tool discovery, meaning it would
connect to mcpd the same way Myelix does.

Key parallels:

| MAF v1.0 | Myelix | mcpd |
|---|---|---|
| Multi-agent orchestration patterns | ConcurrentOrchestrator, Leader | N/A (infrastructure) |
| Middleware pipeline (intercept/transform) | Cognitive Immune System | Hook pipeline (pre/post) |
| MCP for tool discovery | MCP client (45+ tools) | MCP server (gateway) |
| Declarative YAML workflows | YAML personas (not workflows) | TOML config |
| A2A protocol (forthcoming) | A2A implemented (JSON-RPC 2.0) | AID + Agent Card endpoints |

### Opportunities

**For mcpd:**
- mcpd is already well-positioned as the tool provider MAF would
  consume. No architectural changes needed.
- MAF's A2A direction validates mcpd's DISCOVERY.md research and
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

**For mcpd:**
- Claude Agent Teams with no mcpd-like gateway means every agent
  has the same filesystem access. mcpd solves the **security problem**
  this creates: each agent maps to a distinct identity with scoped
  permissions. This is a selling point for mcpd.

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

This is the most strategically important article for mcpd. Direct
feature mapping:

| Governance Toolkit | mcpd Status | Gap |
|---|---|---|
| Agent OS (<0.1ms policy engine) | Permission engine (ACLs + tool rules) | None |
| Agent Mesh (DIDs, Ed25519) | BLAKE3 token auth + AID PKA research | **Partial** |
| Agent Runtime (execution rings) | 2-level permissions + Pause/Resume | **Partial** |
| Agent SRE (SLOs, circuit breakers) | Resilient Transports (backoff) | **Partial** |
| Agent Compliance (regulatory mapping) | Content safety profiles | **Gap** |
| Agent Marketplace (signed plugins) | N/A (Myelix has OCI + sigstore) | N/A |
| Agent Lightning (policy RL) | N/A | N/A |

### Opportunities

**For mcpd (high priority):**

1. **Agent commit signing** — When `git_commit` runs through mcpd,
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

Directly actionable for mcpd-mod-git. When an agent commits through
mcpd, the commit should carry cryptographic proof of which agent
authored it.

### Opportunities

**For mcpd (high priority):**

1. **Implement agent commit signing in mcpd-mod-git** — Add an
   optional `signing_key` path to agent config. When present,
   `git_commit` uses Git's SSH signing (`gpg.format=ssh`,
   `user.signingkey`) to sign with the agent's Ed25519 key.

2. **Agent identity in commit trailer** — Add a `Signed-off-by:
   <agent-name> (via mcpd)` trailer to agent-authored commits,
   making provenance visible in `git log` even without GPG
   verification.

**For Myelix (low priority):**

3. When Myelix's autonomous agent (EPIC-009/EPIC-026) executes
   commits via its own tools (not through mcpd), it should also
   sign them. This is a Myelix-side concern only when mcpd is
   not in the path.

## 5. IBM Granite 4.0 3B Vision

### What It Is

3-billion parameter vision-language model optimized for enterprise
document processing. OCR, form recognition, invoice processing,
compliance document analysis. Compact enough for edge deployment.

### Relevance

mcpd already uses Granite Vision 3.3 2B for OCR/document
understanding (GPU tier). Granite 4.0 3B Vision is the successor.

### Opportunities

**For mcpd (medium priority):**

1. **Evaluate as Vision 3.3 2B replacement** — Granite 4.0 3B
   Vision (~2GB NVFP4) fits the existing GPU budget. Update
   MODELS.md with benchmarks when available. Add to `mcpd model
   available` registry.

2. **Document extraction pipeline** — The enterprise document
   focus aligns with `mcpd-mod-docs` watch directories. A future
   enhancement could run Granite Vision on new PDF/image files
   in watched directories, extracting text and indexing via FTS5
   + sqlite-vec.

**For Myelix (low priority):**

3. A **document analyst persona** that knows when to delegate
   `vision_ocr`/`vision_describe` calls through mcpd. The model
   runs in mcpd; the cognitive framing (when to use vision, how
   to interpret results) is a Myelix persona concern.

## Summary: Priority Matrix

| Priority | Item | Project | Source | Status |
|---|---|---|---|---|
| **High** | Agent commit signing in `git_commit` | mcpd | Copilot signing + Governance | **Done** |
| **High** | Compliance tags on permission sets | mcpd | Governance Toolkit | **Done** |
| **Medium** | Granite 4.0 3B Vision in model registry | mcpd | IBM Granite | Planned (awaiting GA) |
| **Medium** | Graduated permission rings | mcpd | Governance Toolkit | **Done** |
| **Medium** | Declarative workflow YAML | Myelix | MAF v1.0 | |
| **Low** | DID-based agent identity | mcpd | Governance Toolkit | |
| **Low** | Activate A2A endpoint in mcpd | mcpd | MAF + Myelix A2A | **Done** |
| **Low** | Document analyst persona | Myelix | Granite Vision | |
| **Low** | Multi-agent execution debugger | Myelix | MAF DevUI | |

## Validation

mcpd's architecture is well-aligned with industry direction:

- **MCP gateway pattern**: MAF uses MCP for tool discovery. mcpd
  is already the canonical MCP tool provider.
- **Security-first**: The Governance Toolkit validates mcpd's
  defense-in-depth approach (auth, ACLs, safety, hooks, approval).
- **Discovery**: AID, Agent Cards, MCP Server Cards, mDNS — mcpd
  already implements or plans all four discovery layers.
- **Agent identity**: The industry is converging on Ed25519 for
  agent cryptographic identity (AID PKA, DID, commit signing).
  mcpd uses BLAKE3 for auth tokens; extending to Ed25519 signing
  keys is natural.

The main remaining gaps are **graduated permission rings** and
**DID-based agent identity**. Agent commit signing, compliance
tags, and the A2A endpoint are all implemented.
