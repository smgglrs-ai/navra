# navra-model-runtime

Serve AI models with pluggable isolation backends.

## Overview

Provides the `ModelRuntime` trait for starting, stopping, and
health-checking model inference servers. Configured via `ServeConfig`,
returns an `Endpoint` with an OpenAI-compatible API URL.

## Isolation backends

| Backend | Feature flag | Description |
|---|---|---|
| `direct` | `direct` | Spawn `llama-server` as a child process (no isolation) |
| `podman` | `podman` | Run inference in a rootless Podman container |
| `libkrun` | `libkrun` | Run inference in a libkrun microVM (future) |

`auto_runtime()` picks the best available backend, preferring Podman
for isolation. GPU detection is provided by `detect_gpus()`.

## Key types

- `ModelRuntime` -- serve/stop/health trait
- `ServeConfig` -- model path, host, port, GPU devices, context size
- `Endpoint` -- running server URL and backend type
- `GpuDevice` / `GpuKind` -- GPU detection
- `RuntimeBackend` -- Direct, Podman, or Libkrun

## Dependency layer

```
navra-model-runtime  (no navra deps -- leaf crate)
```

## Reference

See [DESIGN.md](../DESIGN.md) for the full model serving architecture
and [MODELS.md](../MODELS.md) for hardware profiles.
