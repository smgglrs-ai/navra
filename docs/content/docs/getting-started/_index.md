+++
title = "Getting Started"
description = "Install and run navra on your Linux desktop."
weight = 10
template = "docs/section.html"

[extra]
toc = true
+++

## Prerequisites

- **Rust** 1.91+ (MSRV)
- **ONNX Runtime** — `onnxruntime-devel` on Fedora
- **Ollama** — for local model execution (optional, needed for agent teams)

## Build

```bash
# Install ONNX Runtime (Fedora)
sudo dnf install onnxruntime-devel

# Build
ORT_LIB_PATH=/usr/lib64 ORT_PREFER_DYNAMIC_LINK=1 cargo build

# Run
ORT_LIB_PATH=/usr/lib64 ORT_PREFER_DYNAMIC_LINK=1 cargo run -- serve
```

## Configuration

Default config path: `~/.config/navra/config.toml`

```toml
[server]
host = "127.0.0.1"
port = 3100

[permissions.default]
operations = ["read", "search", "list"]
tools = ["file_tree", "file_read", "file_grep"]
```

## Connect a Client

Any MCP client can connect to navra over Streamable HTTP:

```json
{
  "mcpServers": {
    "navra": {
      "url": "http://localhost:3100/mcp"
    }
  }
}
```

## Project Structure

navra is a 22-crate Rust workspace (~150K lines of code):

| Layer | Crates | Role |
|-------|--------|------|
| Protocol | navra-protocol, navra-responses | MCP/A2A/JSON-RPC types |
| Security | navra-auth, navra-safety, navra-security | Auth, ACLs, IFC, safety |
| Kernel | navra-core | Server, module trait, session |
| Models | navra-model, navra-model-hub, navra-model-runtime | Backends, registry |
| Cognitive | navra-cognitive | Personas, prompt weaving |
| Agent | navra-agent | ReAct loop, typed actions |
| Orchestration | navra-flow | DAG, handoff, mesh |
| Memory | navra-memory | Working memory, FTS5, decay |
| Tools | navra-mcp, navra-openapi | Upstream MCP, OpenAPI gen |
| Modalities | navra-modal-voice, navra-modal-vision | Speech, image |
| RAG | navra-rag | Hybrid search, chunking |
| Binary | navra-server | CLI, config, wiring |
