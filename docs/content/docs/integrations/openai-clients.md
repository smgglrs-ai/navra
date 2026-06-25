+++
title = "navra + OpenAI clients"
description = "Use navra with Python openai, Node openai, or any OpenAI-compatible client."
weight = 30
template = "docs/page.html"

[extra]
toc = true
+++

## Prerequisites

- navra running with at least one model configured (Ollama, Mistral,
  or any OpenAI-compatible backend)
- A bearer token

## How it works

navra exposes an OpenAI-compatible `/v1/chat/completions` endpoint.
Any client that speaks the OpenAI Chat API can connect -- the client
thinks it is talking to OpenAI, but navra routes the request through
its safety pipeline and model backend.

## Python (openai SDK)

```python
from openai import OpenAI

client = OpenAI(
    base_url="http://localhost:9315/v1",
    api_key="mcd_your_token_here",
)

response = client.chat.completions.create(
    model="granite3.3:8b",  # model name from your config.toml
    messages=[
        {"role": "user", "content": "Summarize the key points of IFC."}
    ],
)
print(response.choices[0].message.content)
```

### With tool use

```python
tools = [
    {
        "type": "function",
        "function": {
            "name": "file_read",
            "description": "Read a file from disk",
            "parameters": {
                "type": "object",
                "properties": {
                    "path": {"type": "string"}
                },
                "required": ["path"]
            }
        }
    }
]

response = client.chat.completions.create(
    model="granite3.3:8b",
    messages=[{"role": "user", "content": "Read README.md"}],
    tools=tools,
)
```

navra enforces ACLs and safety filters on every tool call, even
when the request comes through the OpenAI-compatible endpoint.

## Node.js (openai SDK)

```javascript
import OpenAI from "openai";

const client = new OpenAI({
  baseURL: "http://localhost:9315/v1",
  apiKey: "mcd_your_token_here",
});

const response = await client.chat.completions.create({
  model: "granite3.3:8b",
  messages: [{ role: "user", content: "What is navra?" }],
});

console.log(response.choices[0].message.content);
```

## curl

```bash
curl -s http://localhost:9315/v1/chat/completions \
  -H "Authorization: Bearer mcd_your_token_here" \
  -H "Content-Type: application/json" \
  -d '{
    "model": "granite3.3:8b",
    "messages": [{"role": "user", "content": "Hello"}]
  }' | jq .choices[0].message.content
```

## Streaming

All clients support streaming by setting `stream=True` (Python)
or `stream: true` (Node/curl). navra proxies the SSE stream from
the model backend.

## Model routing

The `model` parameter maps to a model name in your `config.toml`:

```toml
[models.granite]
backend = "ollama"
model = "granite3.3:8b"
task = "chat"
```

If no model name matches, navra returns a 404.

## Troubleshooting

### "model not found"

Check `navra status` to see registered models. The model name in
the API call must match a key in `[models.*]` in your config.

### Responses are slow

Model inference runs locally or on a remote backend. Check your
model backend (Ollama, llama-server) is running and responsive.

### Safety filter blocks content

If the response contains `[REDACTED:...]` markers, navra's safety
pipeline detected sensitive content. This is working as intended.
Adjust the safety profile if the redaction is too aggressive for
your use case.
