+++
title = "Integrations"
description = "Connect popular AI agents and clients to navra."
weight = 10
sort_by = "weight"
template = "docs/section.html"

[extra]
toc = true
+++

navra speaks standard MCP over Streamable HTTP and exposes an
OpenAI-compatible chat endpoint. Any MCP or OpenAI client connects
directly -- no plugins, adapters, or vendor lock-in.

Pick your client:

| Client | Transport | Guide |
|--------|-----------|-------|
| Claude Code | MCP Streamable HTTP | [navra + Claude Code](claude-code/) |
| Goose | MCP SSE | [navra + Goose](goose/) |
| OpenAI Python/Node | OpenAI Chat API | [navra + OpenAI clients](openai-clients/) |
| LangGraph | OpenAI Chat API | [navra + LangGraph](langgraph/) |
| Custom MCP client | MCP Streamable HTTP | [navra + custom client](custom-mcp/) |

All guides assume navra is installed and `navra init` has been run.
See [Getting Started](@/docs/getting-started/_index.md) if you have not set up
navra yet.
