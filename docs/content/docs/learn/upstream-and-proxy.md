+++
title = "18. Upstream and Proxy"
description = "navra acts as a transparent security proxy for external MCP servers. The agent connects to navra; navra connects to upstream servers. The full security pipeline applies to every proxied tool call."
weight = 180
template = "docs/page.html"

[extra]
part = "protocol"
toc = true
+++

## What you already know

You know that every tool call passes through navra's chokepoint, where ACLs, IFC, content filtering, and blackbox recording are enforced. So far, we've focused on tools that navra implements locally. But many useful tools live in external MCP servers -- a code search server, a database connector, a cloud API wrapper. This chapter covers how navra proxies those calls.

## The proxy pattern

Without navra, an agent connects directly to each MCP server:

```
Agent --> GitHub MCP Server
Agent --> Database MCP Server
Agent --> File System MCP Server
```

Each connection is independent. Each server has its own authentication. There is no central point where you can enforce rate limits, check permissions, filter content, or record an audit trail.

With navra, the agent connects to one place:

```
Agent --> navra --> GitHub MCP Server
                --> Database MCP Server
                --> (local tools)
```

The agent sees a single tool list that includes both local tools and tools from upstream servers. When the agent calls a tool that lives on an upstream server, navra forwards the request, applies the full security pipeline, and returns the result. The agent does not know (or care) whether a tool is local or remote.

## Configuring upstream servers

Upstream MCP servers are declared in `config.toml`:

```toml
[[upstream]]
name = "github"
url = "https://github-mcp.example.com/mcp"
transport = "http"
api_key = "ghp_xxxxxxxxxxxxxxxxxxxx"

[[upstream]]
name = "database"
command = "/usr/local/bin/db-mcp-server"
transport = "stdio"
args = ["--readonly"]
```

Each upstream entry specifies a name, a transport type, and connection details. HTTP upstreams connect to a URL. stdio upstreams launch a child process. WebSocket upstreams maintain a persistent connection.

navra connects to each upstream during startup, performs the MCP `initialize` handshake, and fetches the server's tool list. These tools are merged into navra's own tool list, prefixed with the upstream name to avoid collisions: `github.search_code`, `database.query`, etc.

## The security pipeline applies

This is the critical point: when an agent calls `github.search_code`, the request does not go directly to the GitHub MCP server. It enters `handle_call_tool` just like a local tool call. The full pipeline runs:

1. **ACL check**: Is this agent allowed to call `github.search_code`? The tool name includes the upstream prefix, so ACL rules can target upstream tools specifically (`github.*` to allow all GitHub tools, or `github.search_*` to allow only search operations).

2. **IFC check**: If the agent's context is tainted with untrusted data, and `github.create_issue` is classified as a write tool, the IFC no-write-down rule blocks the call.

3. **Content filtering**: The response from the upstream server passes through navra's content filters. If the GitHub search result contains a secret (an API key in a config file), navra's secret filter catches it before the agent sees it.

4. **Blackbox recording**: The proxied call is recorded in the blackbox with the same detail as a local call -- agent identity, tool name, arguments, result, and outcome.

5. **Rate limiting**: Proxied calls count against the agent's rate limit. An agent cannot bypass navra's quota by calling upstream tools instead of local ones.

The upstream server has no idea that navra exists. It receives a standard MCP request and returns a standard MCP response. navra is transparent in both directions.

## Authentication isolation

navra handles authentication to upstream servers independently of agent authentication. The agent authenticates to navra with its own token. navra authenticates to the upstream server with the upstream's configured credentials. The agent never sees the upstream API key.

This matters for security. If an agent's token is compromised, the attacker can make requests through navra -- subject to all ACL and IFC checks -- but cannot extract the upstream credentials. The API key for the GitHub server stays in navra's configuration, not in the agent's context.

## Retry and resilience

Upstream connections can fail. The network might be down, the server might be overloaded, or the request might time out. navra supports configurable retry policies per upstream:

```toml
[[upstream]]
name = "github"
url = "https://github-mcp.example.com/mcp"
transport = "http"

[upstream.retry]
max_retries = 3
initial_backoff_ms = 100
max_backoff_ms = 5000
```

Retries use exponential backoff with jitter. If all retries fail, navra returns a tool error to the agent. The agent sees "tool execution failed" and can decide how to proceed -- retry, try a different approach, or report the failure to the user.

## TLS verification

For HTTP and WebSocket upstreams, navra verifies TLS certificates by default. You can configure custom CA certificates for internal servers:

```toml
[[upstream]]
name = "internal-api"
url = "https://api.internal.corp/mcp"
transport = "http"

[upstream.tls]
ca_cert = "/etc/pki/internal-ca.pem"
```

Disabling TLS verification is possible but logged as a warning. An upstream connection without TLS verification is a potential man-in-the-middle vector -- navra flags this so operators know the risk.

## Tool discovery and notifications

When an upstream server adds or removes tools (signaled via the `notifications/tools/list_changed` notification), navra re-fetches the tool list and updates its merged catalog. Connected agents receive a `tools/list_changed` notification from navra, prompting them to re-discover available tools.

This means the tool list is dynamic. An upstream server can add new capabilities at runtime, and agents connected to navra will discover them without reconnecting.

## Path ACLs on proxied tools

Proxied tools that accept file paths are subject to navra's path ACLs. If an upstream file server offers a `read_file` tool, and the agent's permission set restricts file access to `/home/alice/project/`, navra enforces that restriction before forwarding the request. The upstream server might allow reading any file, but navra does not.

This is gateway-level enforcement: the upstream server is trusted to execute the operation correctly, but navra controls *which* operations are allowed.

## What's next

navra proxies tool calls to external MCP servers. But it also sits between agents and the models they call — applying the same security pipeline to model API requests. In the next chapter, we cover [The Model Proxy](../the-model-proxy/) and why filtering at the local trust boundary matters even when using frontier models with their own safety systems.
