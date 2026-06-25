+++
title = "15. JSON-RPC 2.0 Wire Format"
description = "Every MCP message is a JSON-RPC 2.0 envelope. Understanding the wire format reveals why the protocol is transport-agnostic and how navra normalizes three different transports into a single handler."
weight = 150
template = "docs/page.html"

[extra]
part = "protocol"
toc = true
+++

## What you already know

You know that AI agents call tools through MCP, and that navra sits between agents and tools as a security gateway. You have seen JSON payloads with fields like `"jsonrpc"`, `"method"`, and `"params"`. But you may not know why those fields exist or what protocol defines them.

## JSON-RPC 2.0: the envelope

MCP does not invent its own message format. It uses JSON-RPC 2.0, a specification from 2010 that defines how to make remote procedure calls using JSON. Every MCP message -- whether it's listing tools, calling a function, or reading a resource -- is a JSON-RPC 2.0 envelope.

A JSON-RPC request has four fields:

```json
{
  "jsonrpc": "2.0",
  "id": 42,
  "method": "tools/call",
  "params": {
    "name": "file_read",
    "arguments": { "path": "/etc/hostname" }
  }
}
```

- `jsonrpc` is always `"2.0"`. This is a version marker, not negotiable.
- `id` identifies the request. The server echoes it back so the client can match responses to requests. It can be a number or a string.
- `method` names the operation. MCP defines methods like `initialize`, `tools/list`, `tools/call`, `resources/read`, and `prompts/get`.
- `params` carries the method-specific payload. For `tools/call`, this includes the tool name and its arguments.

The response mirrors the request ID:

```json
{
  "jsonrpc": "2.0",
  "id": 42,
  "result": {
    "content": [
      { "type": "text", "text": "desktop-7x4k" }
    ]
  }
}
```

If something goes wrong, the response carries an `error` object instead of `result`:

```json
{
  "jsonrpc": "2.0",
  "id": 42,
  "error": {
    "code": -32601,
    "message": "Method not found: tools/explode"
  }
}
```

The error codes are standardized. `-32700` means the JSON was unparseable. `-32600` means the request structure was invalid. `-32601` means the method doesn't exist. `-32602` means the parameters were wrong. `-32603` means something broke internally. MCP adds its own codes: `-32001` for cancelled requests, `-32002` for content that exceeds size limits.

## Notifications: fire and forget

Not every message expects a response. JSON-RPC 2.0 defines *notifications* -- messages with no `id` field. The sender doesn't expect a reply. MCP uses notifications for events like "the tool list changed" or "progress update on a long-running operation":

```json
{
  "jsonrpc": "2.0",
  "method": "notifications/tools/list_changed"
}
```

The server sends this when tools are added or removed at runtime. The client can re-fetch the tool list, or ignore the notification entirely. There is no `id`, so there is no response.

## Batching

JSON-RPC 2.0 also supports batching: sending an array of requests in a single message. The server processes them and returns an array of responses. navra supports this -- a client can send up to 100 requests in a batch -- but in practice, most MCP clients send individual requests.

## Three transports, one protocol

JSON-RPC defines the message format but says nothing about how messages travel between client and server. MCP supports three transports:

**Streamable HTTP** is the recommended transport. The client sends JSON-RPC requests as HTTP POST requests to a single endpoint. The server responds with either a JSON body (for simple responses) or a `text/event-stream` body (for streaming results, progress notifications, and long-running operations). This replaced the earlier SSE transport in the 2025-03-26 specification.

**stdio** is the simplest transport. The MCP server runs as a child process. The client writes JSON-RPC messages to the server's stdin and reads responses from its stdout. Each message is a complete JSON object on a single line. This is how tools like Claude Code launch MCP servers locally.

**WebSocket** provides full-duplex communication. Both sides can send messages at any time without waiting for a response. This is useful for servers that need to push notifications proactively or for long-lived connections where HTTP's request-response pattern adds overhead.

Here is the key insight: *navra handles all three transports through the same code path*. The transport layer deserializes incoming bytes into `JsonRpcRequest` structs, and the handler (`handle_call_tool`, `handle_list_tools`, etc.) processes them identically regardless of origin. The security pipeline -- ACL checks, IFC enforcement, content filtering, blackbox recording -- runs the same way whether the request arrived over HTTP, stdio, or WebSocket.

This is not an accident. It is a deliberate design choice. A security gateway that only covers one transport is a security gateway with a bypass.

## navra's validation

Before navra routes a request to its handler, it validates the JSON-RPC envelope:

- The `jsonrpc` field must be exactly `"2.0"`. Any other value is rejected with error code `-32600`.
- The `method` field must be 256 bytes or shorter. This prevents memory exhaustion from absurdly long method names.
- If the `id` is a string, it must be 256 bytes or shorter. Same reason.

These limits exist because navra processes requests from untrusted agents. An agent that sends a method name with 10 million characters is either broken or hostile. Either way, the request should fail fast.

## Protocol versions

MCP has evolved through protocol versions. navra currently supports `2025-03-26` (the version that introduced Streamable HTTP and tool annotations) and `2026-07-28` (which added trace context propagation, cache hints, and enterprise-managed authorization). The version is negotiated during the `initialize` handshake -- the client sends its preferred version, and the server responds with the version it will use.

## What's next

JSON-RPC provides the envelope, but the interesting content is inside `params`. In the next chapter, we look at the three MCP primitives -- tools, resources, and prompts -- and how each one works at the wire level.
