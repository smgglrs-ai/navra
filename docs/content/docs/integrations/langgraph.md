+++
title = "navra + LangGraph"
description = "Use navra as a tool provider for LangGraph agents."
weight = 40
template = "docs/page.html"

[extra]
toc = true
+++

## Prerequisites

- navra running with upstream MCP servers configured
- A bearer token
- Python with `langgraph`, `langchain-openai`, and `openai` installed

## Architecture

LangGraph agents use LLM tool calling to interact with tools. navra
exposes tools through its OpenAI-compatible `/v1/chat/completions`
endpoint, so LangGraph agents can call navra-proxied MCP tools
through the standard OpenAI function calling protocol.

```
LangGraph Agent → OpenAI SDK → navra /v1 → MCP upstream tools
                                    ↓
                              Safety filters
                              ACL enforcement
                              Audit logging
```

## Basic setup

```python
from langchain_openai import ChatOpenAI
from langgraph.prebuilt import create_react_agent

llm = ChatOpenAI(
    base_url="http://localhost:9315/v1",
    api_key="mcd_your_token_here",
    model="granite3.3:8b",
)

agent = create_react_agent(llm, tools=[])
result = agent.invoke({
    "messages": [{"role": "user", "content": "List files in /tmp"}]
})
```

## Using navra's MCP tools

navra automatically exposes upstream MCP tools through its OpenAI
endpoint. The model sees them as function calls. No manual tool
registration is needed -- navra's tool discovery handles it.

If you want to restrict which tools LangGraph can use, configure
ACLs in navra's permission set:

```toml
[permissions.langgraph]
safety = "standard"
ring = 2
allow = ["file_read", "file_list"]
deny = ["file_write", "file_delete"]
operations = ["read"]
```

## With custom LangChain tools alongside navra

You can mix navra-proxied tools with native LangChain tools:

```python
from langchain_core.tools import tool

@tool
def calculate(expression: str) -> str:
    """Evaluate a math expression."""
    return str(eval(expression))

agent = create_react_agent(
    llm,
    tools=[calculate],  # local tools
)
```

The local tools run in-process. navra-proxied tools run through the
gateway with full security enforcement.

## Streaming

```python
for chunk in agent.stream({
    "messages": [{"role": "user", "content": "Analyze README.md"}]
}):
    print(chunk)
```

## Troubleshooting

### LangGraph cannot reach navra

Verify the base URL and token:

```python
from openai import OpenAI
client = OpenAI(base_url="http://localhost:9315/v1", api_key="mcd_...")
print(client.models.list())  # should return available models
```

### Tool calls are not routed through navra

Make sure you are using `ChatOpenAI` with navra's base URL, not a
direct OpenAI or Ollama connection. Tools defined as `@tool`
decorators in LangChain run locally and bypass navra.

### Rate limiting

If running many agent iterations, navra may throttle requests.
Check `navra status` for rate limit counters.
