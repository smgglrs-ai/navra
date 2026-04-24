# smgglrs-model-hub

Pull and cache AI models from OCI, HuggingFace, and Ollama registries.

## Overview

`ModelHub` downloads models addressed by `ModelUri` and caches them
locally in `$XDG_DATA_HOME/smgglrs/models/`. Each cached model gets
an associated `ModelCard` with vendor metadata, operator-defined
agentic capabilities, and runtime statistics.

## Supported registries

| URI scheme | Example |
|---|---|
| `ollama://` | `ollama://granite-code:3b` |
| `hf://` | `hf://ibm-granite/granite-3.3-8b-instruct-GGUF` |
| `oci://` | `oci://quay.io/myorg/mymodel:latest` |
| `file://` | `file:///path/to/model.gguf` |

## Key types

- `ModelHub` -- pull, cache, list, remove models
- `ModelUri` / `Registry` -- parsed model address
- `ModelCard` -- `VendorMeta` + `AgenticMeta` + `RuntimeMeta`
- `ModelCache` -- content-addressed local storage
- `ModelTransport` / `PullProgress` -- registry transport trait

## Dependency layer

```
smgglrs-model-hub  (no smgglrs deps -- leaf crate)
```

## Reference

See [DESIGN.md](../DESIGN.md) for the full model management
architecture and [MODELS.md](../MODELS.md) for model card details.
