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

## Dependency layer

```
navra-responses  (types only)
    |
navra-model      (no other navra deps)
```

## Reference

See [DESIGN.md](../DESIGN.md) for the full model integration
architecture and hardware profiles.
