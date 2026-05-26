# MCP Tunnel Compatibility

smgglrs works as the private MCP server behind both Anthropic and
OpenAI MCP tunnels. The tunnels handle transport security; smgglrs
handles content-level governance (IFC, ACLs, safety filters, audit).

## Architecture

```
Cloud Provider (Anthropic/OpenAI)
    |
    | MCP tunnel (outbound-only HTTPS)
    v
Tunnel Client (on-premise)
    |
    | HTTP/SSE to localhost
    v
smgglrs (MCP gateway)
    |-- Auth, ACLs, IFC, safety filters
    |-- Tool scanning, integrity monitoring
    v
Local resources (files, git, exec, upstream MCP servers)
```

The tunnel client connects outbound to the cloud provider and
forwards MCP requests to smgglrs on localhost. smgglrs processes
them through its full security pipeline before executing tools.

## Anthropic MCP Tunnel

Anthropic's tunnel (Code with Claude, 2026-05) uses outbound-only
HTTPS via Cloudflare with three encryption layers:

1. mTLS at the Cloudflare tunnel edge
2. Inner TLS from tunnel to customer proxy
3. OAuth on each MCP server

Claude Managed Agents use this in Mode 2: the LLM brain runs on
Anthropic infrastructure, tool execution happens in the customer
sandbox via the tunnel.

### Setup

```bash
# 1. Start smgglrs
smgglrs serve --config config.toml

# 2. Install and configure cloudflared
# (Anthropic provides the tunnel token)
cloudflared tunnel --url http://localhost:9315

# 3. Register the tunnel URL with Anthropic
# (via Claude dashboard or API)
```

### smgglrs config for tunnel mode

```toml
[server]
tcp = "127.0.0.1:9315"

# Auth: tunnel client authenticates with a capability token
[[agents]]
name = "claude-tunnel"
token = "your-blake3-token"
permissions = "developer"
```

No changes to smgglrs config are needed beyond standard agent
setup. The tunnel is transparent to the MCP protocol.

## OpenAI MCP Tunnel

OpenAI's tunnel (`tunnel-client`, 2026-05) uses a long-polling
pattern (Harpoon): the client polls for queued MCP work, forwards
locally, returns responses.

### Setup

```bash
# 1. Start smgglrs
smgglrs serve --config config.toml

# 2. Install OpenAI tunnel client
pip install openai-tunnel-client

# 3. Run tunnel client pointing at smgglrs
openai-tunnel-client \
  --target http://localhost:9315/mcp \
  --api-key $OPENAI_API_KEY
```

### Harpoon pattern alignment

smgglrs's explicit upstream declarations in `config.toml` match
the Harpoon pattern: named targets with bounded request types,
not arbitrary open proxying. Each upstream is declared with its
transport and credentials:

```toml
[[upstream]]
name = "local-tools"
command = ["npx", "@modelcontextprotocol/server-filesystem", "/home"]
```

This means smgglrs never proxies to unknown servers — the set of
reachable backends is fixed in configuration.

## What smgglrs adds beyond tunnels

Tunnels provide **transport security** (encrypted channel between
cloud and on-premise). smgglrs provides **content-level governance**:

| Layer | Tunnel | smgglrs |
|-------|--------|---------|
| Transport encryption | Yes (TLS/mTLS) | N/A (localhost) |
| Tool-level ACLs | No | Deny-wins path ACLs |
| Information flow control | No | Bell-LaPadula IFC with taint |
| Content safety filtering | No | Regex + ML + NER pipeline |
| Tool definition scanning | No | 8-category threat detection |
| Audit trail | No | Hash-chained blackbox |
| Capability delegation | No | Ring-attenuated tokens |
| Cognitive file integrity | No | SHA-256 + semantic drift |

A tunnel + smgglrs combination provides both transport security
and content-level governance. Without smgglrs, the tunnel forwards
MCP requests directly to tools with no inspection.

## MCP method coverage

All MCP methods work through tunnels because the tunnel is
transparent to the JSON-RPC protocol:

| Method | Status |
|--------|--------|
| initialize | Works |
| tools/list | Works |
| tools/call | Works |
| resources/list | Works |
| resources/read | Works |
| resources/subscribe | Works |
| resources/unsubscribe | Works |
| prompts/list | Works |
| prompts/get | Works |
| completion/complete | Works |
| logging/setLevel | Works |
| ping | Works |
| notifications/* | Works (SSE stream) |

SSE notifications require the tunnel to support long-lived HTTP
connections (both Anthropic and OpenAI tunnels do).

## Latency considerations

The tunnel adds one network hop (cloud ↔ on-premise). For
tool-use loops with 10+ calls, expect:

- **Without tunnel**: ~5ms per MCP round-trip (localhost)
- **With tunnel**: ~50-200ms per MCP round-trip (depends on
  geography and tunnel provider)

For latency-sensitive workloads (voice assistant, real-time
coding), prefer direct localhost connections. Tunnels are best
for asynchronous workflows (code review, analysis, research).
