# navra-responses

Open Responses API types for Rust.

## Overview

Spec-compliant types for the [Open Responses](https://openresponses.org)
specification -- the open standard for multi-provider LLM interfaces.

This crate provides **types only** -- no HTTP client, no async runtime,
no opinions about transport. All types implement `Serialize`,
`Deserialize`, `Clone`, and `Debug`. Provider extensions are supported
via `#[serde(flatten)]` on extra fields.

## Core concepts

- **Items** are the atomic unit of model I/O: messages, function
  calls, function call outputs, and reasoning traces
- **Responses** contain a list of output items plus metadata
- **Streaming events** carry incremental updates and state machine
  transitions

## Key types

- `CreateResponseRequest` -- request with instructions, input items,
  tools, tool choice, reasoning config
- `Response` / `ResponseStatus` / `Usage` -- response envelope
- `InputItem` / `OutputItem` -- message, function call, reasoning
- `MessageItem` / `FunctionCallItem` / `ReasoningItem` -- item types
- `FunctionTool` / `ToolChoice` / `AllowedTools` -- tool definitions
- `StreamEvent` -- streaming response events
- `ResponseError` -- structured API errors

## Dependency layer

```
navra-responses  (standalone -- no navra deps, minimal deps)
    |
navra-model      (uses as canonical model I/O interface)
```

## Reference

See [DESIGN.md](../DESIGN.md) for how Open Responses integrates
into the navra model backend architecture.
