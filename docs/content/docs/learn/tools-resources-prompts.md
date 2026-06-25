+++
title = "16. Tools, Resources, and Prompts"
description = "MCP defines three primitives for agent-server interaction. Tools let agents call functions. Resources let agents read data. Prompts let servers provide templates. Most security enforcement happens on tools."
weight = 160
template = "docs/page.html"

[extra]
part = "protocol"
toc = true
+++

## What you already know

You know that MCP uses JSON-RPC 2.0 as its wire format, and that navra handles requests from three different transports through a single code path. Now we look at what's inside those requests: the three primitives that define what an MCP server can offer.

## The three primitives

MCP organizes server capabilities into three categories:

- **Tools** are functions the agent can call. Reading a file, running a shell command, querying a database, sending an email. The agent provides arguments, the server executes the function, and returns a result.
- **Resources** are data the agent can read. A file's contents, a database record, a configuration value. The agent requests a resource by URI, and the server returns its contents. Resources are read-only by definition.
- **Prompts** are templates the server provides to the agent. A code review template, a debugging persona, a structured analysis format. The agent requests a prompt by name, optionally filling in arguments, and the server returns a sequence of messages.

Each primitive has its own lifecycle: list, then use. The agent first asks "what tools do you have?" (`tools/list`), then calls individual tools (`tools/call`). Same pattern for resources (`resources/list` then `resources/read`) and prompts (`prompts/list` then `prompts/get`).

## Tools: where the action is

A tool definition tells the agent what the tool does and what arguments it accepts:

```json
{
  "name": "file_read",
  "description": "Read the contents of a file",
  "inputSchema": {
    "type": "object",
    "properties": {
      "path": {
        "type": "string",
        "description": "Absolute path to the file"
      }
    },
    "required": ["path"]
  },
  "annotations": {
    "readOnlyHint": true,
    "destructiveHint": false,
    "idempotentHint": true,
    "title": "Read File"
  }
}
```

The `inputSchema` uses JSON Schema to describe arguments. The LLM reads this schema to understand what parameters to provide. The `annotations` give hints about the tool's behavior -- whether it only reads data, whether it could destroy something, whether calling it twice produces the same result.

When the agent calls the tool, the request carries the tool name and arguments:

```json
{
  "jsonrpc": "2.0",
  "id": 7,
  "method": "tools/call",
  "params": {
    "name": "file_read",
    "arguments": { "path": "/home/alice/notes.txt" }
  }
}
```

The response wraps the result in a content array:

```json
{
  "jsonrpc": "2.0",
  "id": 7,
  "result": {
    "content": [
      { "type": "text", "text": "Meeting at 3pm with Bob.\nBring the Q3 report.\n" }
    ]
  }
}
```

Content can be text, images (base64-encoded), audio, or embedded resources. Most tools return text, but an image generation tool might return an image content block, and a file reader might return binary data as a resource.

If the tool fails, it returns `isError: true` with an error message in the content:

```json
{
  "result": {
    "content": [
      { "type": "text", "text": "Permission denied: /etc/shadow" }
    ],
    "isError": true
  }
}
```

This is a tool-level error, not a protocol error. The JSON-RPC response is still a success (it has `result`, not `error`). The distinction matters: protocol errors mean the request was malformed; tool errors mean the request was valid but the operation failed.

## Resources: read-only data

Resources provide a way for agents to access data without executing code. Each resource has a URI:

```json
{
  "uri": "file:///home/alice/config.toml",
  "name": "config.toml",
  "description": "Application configuration",
  "mimeType": "application/toml"
}
```

The agent reads a resource by URI:

```json
{
  "jsonrpc": "2.0",
  "id": 12,
  "method": "resources/read",
  "params": {
    "uri": "file:///home/alice/config.toml"
  }
}
```

The server returns the contents:

```json
{
  "jsonrpc": "2.0",
  "id": 12,
  "result": {
    "contents": [
      {
        "uri": "file:///home/alice/config.toml",
        "mimeType": "application/toml",
        "text": "[server]\nport = 8080\nhost = \"0.0.0.0\"\n"
      }
    ]
  }
}
```

Resources can also return binary data as base64 in a `blob` field instead of `text`. The server can optionally support resource subscriptions -- the client subscribes to a resource URI, and the server sends `notifications/resources/updated` when the resource changes.

MCP also supports resource templates using URI templates (`file:///{path}`), which let agents construct URIs dynamically with completion support.

## Prompts: server-provided templates

Prompts are the least used primitive but serve an important role: they let the server provide structured instructions to the agent.

```json
{
  "name": "code_review",
  "description": "Review code for bugs and style issues",
  "arguments": [
    {
      "name": "language",
      "description": "Programming language",
      "required": true
    },
    {
      "name": "style",
      "description": "Review style: thorough or quick",
      "required": false
    }
  ]
}
```

When the agent requests a prompt, the server fills in the template and returns a sequence of messages:

```json
{
  "jsonrpc": "2.0",
  "id": 15,
  "method": "prompts/get",
  "params": {
    "name": "code_review",
    "arguments": { "language": "rust" }
  }
}
```

```json
{
  "result": {
    "description": "Rust code review prompt",
    "messages": [
      {
        "role": "user",
        "content": {
          "type": "text",
          "text": "Review this Rust code for correctness, safety, and idiomatic style..."
        }
      }
    ]
  }
}
```

The agent can inject these messages into its conversation context, effectively adopting the persona or analysis framework the server provides.

## Where security matters

Of the three primitives, tools are where almost all security enforcement happens. Tools execute code, modify files, send network requests. Resources are read-only, so the risk is data exfiltration rather than system modification. Prompts are informational -- they can influence the agent's behavior but don't directly interact with the system.

navra's security pipeline -- ACL checks, IFC enforcement, content filtering, blackbox recording -- is concentrated on `tools/call`. When you hear "the chokepoint," that's where it is. Resources and prompts pass through lighter checks (disclosure filtering, content scanning on responses), but the full enforcement pipeline runs on every tool call.

This makes sense when you think about what agents actually do. An agent that reads a file might leak data, but an agent that writes a file can destroy data. An agent that reads a database is concerning, but an agent that drops a table is catastrophic. The enforcement is proportional to the risk.

## Capability negotiation

During the `initialize` handshake, the server tells the client which primitives it supports:

```json
{
  "capabilities": {
    "tools": { "listChanged": true },
    "resources": { "subscribe": true, "listChanged": false },
    "prompts": { "listChanged": false }
  }
}
```

If a primitive is absent from `capabilities`, the server doesn't support it. The `listChanged` flag tells the client whether the server will send notifications when the list of tools, resources, or prompts changes at runtime.

## What's next

Every tool call enters navra through a single function. In the next chapter, we look at that function -- the chokepoint -- and trace the full pipeline from request to response.
