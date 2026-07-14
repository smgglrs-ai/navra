+++
title = "Model Server"
weight = 20
template = "docs/page.html"

[extra]
toc = true
+++

navra includes a model inference server that manages multiple model
backends behind an OpenAI-compatible HTTP API. It can run standalone
or embedded in the gateway process.

## Usage modes

### Embedded (default)

When `model_server` is not set in `config.toml`, navra loads models
directly into the gateway process. ONNX models (embedding,
classification) run in-process. Chat and generate models use the
configured runtime:

- `runtime = "embedded"` — llama.cpp linked into navra itself (no
  external process). Models load on first request and are managed
  in an LRU pool. GPU offloading is automatic: navra probes VRAM
  and offloads all layers when sufficient, falls back to CPU otherwise.
- `runtime = "direct"` — spawns `llama-server` as a child process.
- `runtime = "auto"` — picks the best available (embedded if built
  with the `embedded` feature, else direct/podman).

```toml
[models.chat]
source = "ollama://qwen2.5:0.5b"
task = "chat"
runtime = "embedded"
port = 19316
context_size = 4096
```

The `port` field gives the model a predictable URL (`http://127.0.0.1:19316`).
When omitted, a random port is auto-selected.

**Hot-swap**: when per-agent model routing sends requests to different
models, the embedded runtime loads each model on demand. If memory is
constrained, the least-recently-used model is evicted to free RAM/VRAM.

### navra run

`navra run -m <model>` also supports embedded mode. When the model name
matches a GGUF blob in Ollama's local store (`~/.ollama/models/` or
`$OLLAMA_MODELS`), navra loads it in-process via llama.cpp — no running
Ollama server or `[models.*]` config section required. GPU offloading
is automatic.

```bash
# Pull the model with Ollama once
ollama pull gemma4:26b

# Run with embedded mode (Ollama server not needed)
navra run -m gemma4:26b "Summarise the latest reports"

# Force Ollama API instead
navra run -m gemma4:26b --no-embedded "Summarise the latest reports"
```

If the blob is not found locally or navra was built without the
`embedded` feature, it falls back to the Ollama HTTP API.

### Standalone

Run the model server as a separate process:

```bash
navra model serve --bind 127.0.0.1:9316
```

Then point the gateway at it:

```toml
model_server = "http://127.0.0.1:9316"
```

Standalone mode is useful when multiple gateway instances share models,
or when the model server runs on a different machine with GPU access.

### Hardware auto-detection

Use `--auto` to detect GPUs, NPUs, and system RAM, then propose a
resource allocation:

```bash
navra model serve --auto
```

Output:

```text
Detected resources:
  GPU: NVIDIA RTX 5090 (32GB VRAM) [nvidia]
  NPU: Intel NPU (pci_1234) (/dev/accel/accel0)
  RAM: 64GB

Proposed allocation:
  GPU: 30GB for models (2GB reserved for desktop)
```

Set an explicit VRAM budget:

```bash
navra model serve --budget 24GB
```

## Hardware detection

navra detects hardware without vendor-specific libraries:

| Hardware | Detection method |
|----------|-----------------|
| NVIDIA GPUs | `/proc/driver/nvidia/gpus/` for device info, `fb_memory_usage` for VRAM |
| AMD GPUs | `/sys/class/drm/` with vendor ID `0x1002`, `mem_info_vram_total` for VRAM |
| Intel GPUs | `/sys/class/drm/` with vendor ID `0x8086`, `lmem_total_bytes` for dedicated memory |
| Intel NPUs | `/dev/accel/` device nodes with `INTEL_VPU` driver binding |
| System RAM | `/proc/meminfo` |

VRAM budget defaults to total GPU VRAM minus a 2GB desktop reservation
(configurable via `desktop_reservation`).

## Runtime backends

Models are served through a two-axis system: **engine** (what serves
the model) and **isolation** (how the engine is launched).

### Engines

| Engine | Binary | Formats | GPU required |
|--------|--------|---------|-------------|
| llama.cpp (embedded) | *in-process* | GGUF | No (CPU or GPU) |
| llama.cpp | `llama-server` | GGUF | No (CPU or GPU) |
| vLLM | `vllm serve` | safetensors, GGUF, AWQ, GPTQ | Yes |

The **embedded** engine links llama.cpp statically into navra itself —
no external binary needed. Set `runtime = "embedded"` in the model
config, or let auto-detection fall back to it when no external runtime
is found. Requires navra built with `--features embedded` (included in
prebuilt release binaries).

### Isolation modes

| Mode | Description | Security |
|------|-------------|----------|
| `embedded` | In-process (statically linked llama.cpp) | None (shares navra process) |
| `direct` | Child process, no isolation | None |
| `podman` | Rootless container with `--network=none`, `--no-new-privileges`, read-only model mount | Strong |
| `openshell` | Delegate to OpenShell compute driver via gRPC (libkrun microVM) | Strongest |

### Auto-detection

When `runtime = "auto"` (the default for served models), navra picks
the best available combination:

1. OpenShell (if gateway socket exists)
2. Podman + vLLM (if Podman socket exists and GPU detected)
3. Podman + llama.cpp (if Podman socket exists)
4. Direct + vLLM (if `vllm` binary found and GPU detected)
5. Direct + llama.cpp (if `llama-server` binary found)
6. Embedded llama.cpp (if built with `--features embedded`)

### Podman containers

Podman containers run with hardened defaults:

- `--network=none` -- no network access (no data exfiltration)
- `--no-new-privileges` -- cannot escalate privileges
- `--read-only` -- read-only root filesystem
- Model file mounted at `/model:ro`
- GPU passthrough via CDI (NVIDIA) or device bind (AMD/Intel)
- `--ipc=host` only when the engine requires it (vLLM NCCL)

## Model sources

Models can come from local files or be pulled from registries via
navra-model-hub.

### Hub URIs

| Scheme | Example | Description |
|--------|---------|-------------|
| `ollama://` | `ollama://granite3.3:8b` | Ollama registry |
| `hf://` | `hf://ibm-granite/granite-3.3-8b-instruct-GGUF` | HuggingFace Hub |
| `oci://` | `oci://quay.io/myorg/mymodel:latest` | OCI container registry |
| `file://` | `file:///path/to/model.gguf` | Local file (no pull) |
| bare name | `granite3.3:8b` | Treated as Ollama shorthand |

All schemes support digest pinning for integrity verification:

```text
ollama://granite3.3:8b@sha256:abc123...
```

### Pulling models

```bash
# Pull from the built-in registry
navra model pull guardian-hap

# Pull by hub URI
navra model pull ollama://granite3.3:8b
navra model pull hf://ibm-granite/granite-3.3-8b-instruct-GGUF

# List cached models
navra model list

# Show available registry models
navra model available
```

Pulled models are cached in `~/.local/share/navra/models/`. Each
cached model has an associated model card with vendor metadata,
operator-defined agentic capabilities, and runtime statistics.

## Configuration

### Model entries

Each model is defined under `[models.<name>]`:

```toml
# In-process ONNX embedding model
[models.embed]
model_path = "~/.local/share/navra/models/granite-embed/model.onnx"
tokenizer_path = "~/.local/share/navra/models/granite-embed/tokenizer.json"
task = "embedding"
dimensions = 768
device = "cpu"

# Chat model served via runtime
[models.granite-chat]
source = "ollama://granite3.3:8b"
task = "chat"
runtime = "auto"
context_size = 8192
parallel = 2

# Remote model via OpenAI-compatible API
[models.claude]
base_url = "https://api.anthropic.com/v1"
model_name = "claude-sonnet-4-20250514"
api_key = "${ANTHROPIC_API_KEY}"
task = "chat"
locality = "remote"
```

### Model entry fields

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `model_path` | string | -- | Path to local model file (ONNX, GGUF) |
| `source` | string | -- | Hub URI for pulling (`ollama://`, `hf://`, `oci://`) |
| `tokenizer_path` | string | -- | Path to `tokenizer.json` |
| `task` | string | `"embedding"` | Model task: `embedding`, `classification`, `chat`, `generate` |
| `device` | string | `"cpu"` | ONNX device: `cpu`, `cuda`, `openvino`, `openvino:NPU` |
| `dimensions` | int | 768 | Embedding dimensions |
| `labels` | string[] | `["safe","unsafe"]` | Classification labels |
| `threshold` | float | 0.5 | Classification confidence threshold |
| `format` | string | auto | Model format: `gguf`, `safetensors`, `awq`, `gptq` |
| `execution_mode` | string | auto | `in_process` or `served` (derived from `task` if unset) |
| `runtime` | string | -- | `auto`, `direct`, `podman`, `ollama`, `ogx`, `vllm`, `vllm-podman`, `none` |
| `context_size` | int | 4096 | Context window size for served models |
| `parallel` | int | 1 | Parallel request slots |
| `model_name` | string | config key | Model name for OpenAI-compatible API |
| `cache_type` | string | -- | KV cache quantization: `f16`, `q8_0`, `q4_0` |
| `base_url` | string | -- | Base URL for remote model servers |
| `api_key` | string | -- | API key for authenticated endpoints |
| `locality` | string | `"local"` | `local` or `remote` (remote requires content filtering) |

### Speculative decoding

Enable speculative decoding with a smaller draft model for faster
generation:

```toml
[models.granite-chat.speculative]
draft_model = "~/.local/share/navra/models/granite-1b.gguf"
draft_tokens = 5
draft_min_p = 0.0
```

### Agentic metadata

Annotate models with operator-defined capabilities for cost-aware
routing:

```toml
[models.granite-chat.agentic]
cost_tier = "free"
speed_tier = "fast"
tool_use = "basic"
reasoning = "chain-of-thought"
locality = "local"
strengths = ["code generation", "fast inference"]
weaknesses = ["limited reasoning"]
recommended_tasks = ["code review"]
avoid_tasks = ["multi-step planning"]
```

### Model server settings

```toml
# Point gateway at a standalone model server
model_server = "http://127.0.0.1:9316"
```

When running the standalone server, settings come from the config file
passed via `--config` or from CLI flags:

```bash
navra model serve \
  --config ~/.config/navra/config.toml \
  --bind 127.0.0.1:9316 \
  --budget 24GB
```

## API endpoints

The model server exposes an OpenAI-compatible API:

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/health` | GET | Health check |
| `/hardware` | GET | Detected hardware summary (JSON) |
| `/v1/models` | GET | List loaded models |
| `/v1/chat/completions` | POST | Chat completion |
| `/v1/embeddings` | POST | Text embedding |
| `/v1/classify` | POST | Text classification |
