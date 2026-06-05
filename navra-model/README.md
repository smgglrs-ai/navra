# navra-model

Model inference backends with a unified trait interface.

## Overview

Provides the `ModelBackend` trait using the
[Open Responses](https://openresponses.org) specification as the
canonical model I/O interface. Backends translate to their native
wire format internally.

## Backends

- `OpenAiBackend` -- Chat Completions API (Ollama, vLLM, any
  OpenAI-compatible endpoint)
- `AnthropicBackend` -- Messages API (Claude)
- `OnnxBackend` -- In-process ONNX Runtime (embeddings, safety
  classification)

## ModelBackend trait methods

| Method | Purpose |
|---|---|
| `respond` / `respond_stream` | Multi-turn completion with tools (Open Responses format) |
| `embed` | Text embeddings |
| `classify` | Content safety / moderation |
| `generate` | Simple single-turn text generation |
| `transcribe` / `synthesize` | Audio I/O (ASR / TTS) |

## Key types

`ModelError`, `EmbedRequest`, `EmbedResponse`, `ClassifyRequest`,
`ClassifyResponse`, `GenerateRequest`, `GenerateResponse`,
`Locality` (Local vs Remote), `SafeModelBackend`.

## Configuration

```toml
# In-process ONNX model (CPU, no external dependencies)
[models.safety]
model_path = "~/.local/share/navra/models/safety.onnx"
task = "classification"
labels = ["safe", "unsafe"]
threshold = 0.5

# Remote model via OpenAI-compatible API (Ollama, vLLM)
[models.granite]
source = "ollama://granite-code:3b"
task = "chat"

# Cloud model
[models.claude]
task = "chat"
# Requires ANTHROPIC_API_KEY environment variable
```

## Dependency layer

```
navra-responses  (types only)
    |
navra-model      (no other navra deps)
```

## Reference

See [DESIGN.md](../DESIGN.md) for the full model integration
architecture and hardware profiles.
