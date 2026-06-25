+++
title = "navra + custom MCP client"
description = "Connect any MCP client to navra using Streamable HTTP."
weight = 50
template = "docs/page.html"

[extra]
toc = true
+++

## Prerequisites

- navra running (`navra serve` or systemd service)
- A bearer token
- An MCP client that supports Streamable HTTP or SSE transport

## Protocol

navra exposes a standard MCP endpoint at:

```
http://localhost:9315/mcp
```

The transport is Streamable HTTP (the default MCP transport for
HTTP-based servers). SSE clients also work against this endpoint.

Authentication uses a bearer token in the `Authorization` header.

## Minimal client example (Python)

Using the `mcp` Python SDK:

```python
import asyncio
from mcp.client.streamable_http import streamablehttp_client
from mcp import ClientSession

async def main():
    headers = {"Authorization": "Bearer mcd_your_token_here"}

    async with streamablehttp_client(
        "http://localhost:9315/mcp",
        headers=headers,
    ) as (read, write, _):
        async with ClientSession(read, write) as session:
            await session.initialize()

            # List available tools
            tools = await session.list_tools()
            for tool in tools.tools:
                print(f"  {tool.name}: {tool.description}")

            # Call a tool
            result = await session.call_tool("file_read", {"path": "/etc/hostname"})
            print(result.content[0].text)

asyncio.run(main())
```

## Minimal client example (TypeScript)

Using the `@modelcontextprotocol/sdk` package:

```typescript
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";

const transport = new StreamableHTTPClientTransport(
  new URL("http://localhost:9315/mcp"),
  {
    requestInit: {
      headers: {
        Authorization: "Bearer mcd_your_token_here",
      },
    },
  }
);

const client = new Client({ name: "my-client", version: "1.0" });
await client.connect(transport);

const tools = await client.listTools();
console.log("Tools:", tools.tools.map(t => t.name));

const result = await client.callTool({
  name: "file_read",
  arguments: { path: "/etc/hostname" },
});
console.log(result.content);

await client.close();
```

## Minimal client example (Rust)

Using the `rmcp` crate:

```rust
use rmcp::service::ServiceExt;
use rmcp::transport::StreamableHttpClientTransport;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let transport = StreamableHttpClientTransport::from_uri(
        "http://localhost:9315/mcp"
    );

    let client = ServiceExt::<rmcp::RoleClient>::serve((), transport).await?;
    let peer = client.peer().clone();

    let tools = peer.list_all_tools().await?;
    for tool in &tools {
        println!("  {}: {:?}", tool.name, tool.description);
    }

    Ok(())
}
```

Note: the Rust client does not yet support header-based auth on
Streamable HTTP. Use the token query parameter or configure
navra with `--dev-mode` for development.

## What the client sees

navra merges tools from all registered upstream MCP servers and its
own built-in modules. The client sees a single flat tool list.
Tool names are prefixed with the module name to avoid collisions
(e.g., `file_read`, `git_status`, `rag_search`).

## Authentication

All requests must include a bearer token:

```
Authorization: Bearer mcd_<token>
```

Tokens are created with `navra token create --name my-client` and
bound to a permission set that controls which tools the client can
call.

## Troubleshooting

### "unauthorized" response

1. Check the token is valid: `navra token list`
2. Verify the `Authorization` header format (must be `Bearer mcd_...`)
3. Check the agent config in `config.toml` has the correct `token_hash`

### Tool call denied

The audit log shows why:

```bash
navra audit --limit 10 --detail
```

Common reasons: tool not in the `allow` list, path outside allowed
directories, or tool requires approval.

### Connection refused

navra defaults to a Unix socket. If your client needs TCP, ensure
`config.toml` has:

```toml
[server]
tcp = "127.0.0.1:9315"
```
