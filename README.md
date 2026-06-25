<p align="center">
  <img src="assets/logo/navra-icon-192.png" alt="navra logo" width="128" />
</p>

<h1 align="center">navra</h1>

<p align="center">
  Secure agentic AI framework for Rust
</p>

<p align="center">
  <a href="#features">Features</a> ·
  <a href="#quickstart">Quickstart</a> ·
  <a href="#agent-sdk">Agent SDK</a> ·
  <a href="#flows">Flows</a> ·
  <a href="#architecture">Architecture</a> ·
  <a href="#security">Security</a> ·
  <a href="#license">License</a>
</p>

---

**navra** is a Rust framework for building secure AI agents. It
combines an MCP gateway, an agent SDK, and a multi-agent flow engine
behind a unified security layer with Information Flow Control,
authentication, path ACLs, content safety filtering, human-in-the-loop
approval, and a hook pipeline.

```
AI Agent (Claude Code, Goose, Rust SDK, ...)
    │
    │  MCP Streamable HTTP + SSE
    ▼
navra gateway
    ├── Auth (BLAKE3 tokens, capability tokens, DID:key)
    ├── Permission engine (path ACLs, domain rules, per-tool policies)
    ├── Information Flow Control (taint tracking, no-write-down)
    ├── Hook pipeline (pre/post tool-call, safety, egress)
    ├── Safety filters (regex + NER + ML classifiers)
    ├── Built-in modules (file, git, RAG, voice, vision)
    ├── Upstream MCP servers (proxied, safety-filtered)
    └── Model proxy (OpenAI-compat, Anthropic, ONNX)

navra-agent (Rust SDK)
    ├── Agent builder with fluent API
    ├── ReAct tool-use loop
    ├── 5 model backends (Ollama, Mistral, Anthropic, OGX, CLI)
    ├── IFC taint tracking per session
    ├── Deterministic replay
    └── Hermes-format trace export

navra-flow (orchestration)
    ├── DAG execution (parallel tasks, dependency resolution)
    ├── Handoff routing (model-driven agent transitions)
    └── Mesh communication (mailbox, blackboard, back-edges)
```

## Features

- **Security at the infrastructure layer** — IFC, ACLs, and safety
  hooks are enforced by the gateway, not by trusting the model.
- **Rust agent SDK** — builder API, 5 model backends, typed actions,
  trace export, signals, hibernation, replay.
- **Multi-agent flows** — DAG and handoff orchestration defined in
  YAML with dynamic task generation.
- **In-process models** — ONNX models (safety classifiers,
  embeddings, PII detection) load directly. No external services
  needed for CPU tier.
- **Agent bundles** — package agents as signed OCI artifacts with
  persona, permissions, and upstream config.
- **Human-in-the-loop** — D-Bus desktop notifications for approval
  requests, with system tray for session control.

## Quickstart

```bash
# Install (Fedora)
sudo dnf install onnxruntime-devel
git clone https://github.com/smgglrs-ai/navra.git && cd navra
ORT_LIB_PATH=/usr/lib64 ORT_PREFER_DYNAMIC_LINK=1 cargo build --release
cp target/release/navra ~/.local/bin/

# Interactive setup
navra init

# Start the gateway
navra serve
```

`navra init` detects your agent (Claude Code, Goose), recommends
MCP servers for your project type, generates a token, writes config,
and optionally installs a systemd service.

### Integration guides

Step-by-step guides for connecting popular agents and clients:

- [navra + Claude Code](docs/content/docs/integrations/claude-code.md)
- [navra + Goose](docs/content/docs/integrations/goose.md)
- [navra + OpenAI clients (Python/Node)](docs/content/docs/integrations/openai-clients.md)
- [navra + LangGraph](docs/content/docs/integrations/langgraph.md)
- [navra + custom MCP client](docs/content/docs/integrations/custom-mcp.md)

## Agent SDK

Build agents in Rust with `navra-agent`:

```rust
use navra_agent::{Agent, OpenAiBackend, Locality};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let model = OpenAiBackend::new(
        "http://localhost:11434/v1", "granite3.3:8b",
        None, Locality::Local,
    );

    let mut agent = Agent::builder()
        .endpoint("http://localhost:9315/mcp").await?
        .model(model)
        .system_prompt("You are a helpful assistant.")
        .auth_token("mcd_your_token_here")
        .max_iterations(20)
        .build().await?;

    let result = agent.run("List the git status").await?;
    println!("{}", result.response);
    Ok(())
}
```

Works with Ollama, Mistral, Anthropic, any OpenAI-compatible API,
or a local CLI command. See [examples/standalone-agent/](examples/standalone-agent/)
for a complete runnable example.

## Flows

Define multi-agent workflows in YAML:

```yaml
kind: dag
name: deep-research
tasks:
  - id: search
    specialist: researcher
    mandate: "Search multiple sources about..."
  - id: verify
    specialist: devils_advocate
    depends_on: [search]
    mandate: "Adversarially verify each claim..."
  - id: synthesize
    specialist: summarizer
    depends_on: [verify]
    mandate: "Produce a cited report with only verified findings..."
```

Included flows: [review](examples/flows/review.yaml),
[deep-research](examples/flows/deep-research.yaml),
[security-audit](examples/flows/security-audit.yaml),
[improve](examples/flows/improve.yaml),
[self-improve](examples/flows/self-improve.yaml).

## Architecture

22-crate Rust workspace organized in strict dependency layers:

```
navra-protocol          (no internal deps)
navra-model             (protocol)
navra-auth              (protocol)
navra-safety-hooks      (auth)
navra-core              (protocol + model + auth + safety)
navra-agent             (protocol + model + auth + cognitive)
navra-flow              (agent + core)
navra-server            (all crates)
```

See [DESIGN.md](DESIGN.md) for the full architecture, protocol details,
and security model.

## Security

- **Information Flow Control** — taint labels track data sensitivity
  across tool calls. Tainted sessions cannot write to lower-classification
  outputs (Bell-LaPadula no-write-down).
- **Deny-wins ACLs** — deny rules always beat allow rules. Path
  canonicalization prevents traversal.
- **34 adversarial tests** — covering ACL bypass, IFC laundering,
  prompt injection, hook pipeline abuse, approval replay, and
  cross-session isolation.
- **Cedar policies** — OWASP Agentic Security Top 10 baseline.
- **PII detection** — regex + NER (English + multilingual ONNX) with
  redaction, pseudonymization, or blocking.

## Agent Bundles

```bash
navra agent install oci://quay.io/navra/researcher:latest
navra agent inspect oci://quay.io/navra/code-reviewer:latest
navra agent list
```

See [examples/agent-bundles/](examples/agent-bundles/) for reference
manifests.

## Documentation

- [SDK Guide](docs/content/docs/sdk/) — building agents with navra-agent
- [CONFIG.md](CONFIG.md) — complete configuration reference
- [DESIGN.md](DESIGN.md) — full architecture and security model
- [CONTRIBUTING.md](CONTRIBUTING.md) — contribution guidelines
- [SECURITY.md](SECURITY.md) — vulnerability disclosure
- [examples/](examples/) — configs, flows, agent bundles, standalone agent

## License

[Apache License 2.0](LICENSE)
