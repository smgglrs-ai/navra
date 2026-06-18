# navra — Model Integration Architecture

## Goal

Integrate local AI models into navra to support a local voice-first
assistant combining navra (secure tool execution) with navra-flow
(multi-agent orchestration). Models handle RAG, voice I/O, content
safety, and vision — all self-hosted, all open source.

## Model Selection

Granite-first (Apache 2.0, IBM/Red Hat alignment), Gemma 4 for
reasoning/vision (Apache 2.0, massive efficiency gain), Mistral for
TTS. Claude API for orchestration. NVIDIA Nemotron excluded due to
non-OSI license (revocable grant, guardrail termination clause).

Two deployment tiers: a **CPU tier** using small ONNX models with
proven Rust integration, and a **GPU tier** on an RTX 5090 FE
(32GB GDDR7, Blackwell, NVFP4 support) upgrading to larger models
via vLLM for better quality.

### CPU Tier (no GPU required)

Models that run inside the navra process via ONNX Runtime (`ort`
crate) or via whisper.cpp bindings. All Apache 2.0 or MIT.

| Role | Model | Params | Runtime | License | Latency |
|------|-------|--------|---------|---------|---------|
| VAD | silero-vad | ~260K | ONNX (`ort`) | MIT | <1ms/chunk |
| Safety (fast) | Granite Guardian HAP 38M | 38M | ONNX (`ort`) | Apache 2.0 | 1-5ms |
| TTS | Kokoro-82M | 82M | ONNX (`ort`) | Apache 2.0 | ~5x realtime |
| Text embeddings | Granite Embedding R2 149M | 149M | ONNX (`ort`) | Apache 2.0 | 10-30ms |
| ASR | Whisper Large V3 | 1.5B | whisper.cpp (`whisper-rs`) | MIT | ~realtime |

These models total ~2GB RAM (excluding Whisper) or ~4GB with
Whisper. No GPU, no external serving process. navra loads them at
startup.

### GPU Tier (RTX 5090 FE — 32GB GDDR7)

Models served by external processes (vLLM, ollama). navra connects
via OpenAI-compatible API. Higher quality than CPU tier.

The RTX 5090's Blackwell architecture supports **NVFP4** — 4-bit
floating point with micro-block scaling (groups of 16 values sharing
an FP8 scale factor). This gives ~2x throughput over FP8 with <1%
accuracy loss, and halves VRAM vs Q4 integer quantization.

| Role | Model | Params | Runtime | License | VRAM (NVFP4) |
|------|-------|--------|---------|---------|--------------|
| Reasoning + vision | Gemma 4 26B-A4B | 25.2B total / 3.8B active (MoE) | vLLM | Apache 2.0 | ~7GB |
| ↳ _alternative_ | _Gemma 4 12B_ | _12B dense_ | _Ollama / vLLM_ | _Apache 2.0_ | _~5GB_ |
| ASR (upgrade) | Granite 4.0 1B Speech | 1B | vLLM | Apache 2.0 | ~1GB |
| TTS (upgrade) | Voxtral TTS 4B | 4B | vLLM-Omni | CC BY-NC | ~3GB |
| Safety (deep) | Granite Guardian 3.3 8B | 8B | vLLM / ollama | Apache 2.0 | ~3GB |
| Vision/OCR | Granite Vision 3.3 2B | 2B | vLLM / ollama | Apache 2.0 | ~1.5GB |
| ↳ _upgrade_ | _Granite 4.0 3B Vision_ | _3B_ | _vLLM / ollama_ | _Apache 2.0_ | _~2GB_ |
| Visual embeddings | Granite Vision 3.3 2B Embedding | 2B | HF Transformers | Apache 2.0 | ~1.5GB |
| Code specialist | Granite 4.0 Tiny | 7B/1B active | vLLM | Apache 2.0 | ~2GB |
| Document parsing | Docling 258M | 258M | Python service | Apache 2.0 | CPU |
| **Total** | | | | | **~19GB** |

All GPU-tier models fit simultaneously in 32GB with ~13GB free for
KV caches and concurrent inference. No model swapping needed.

Previous strategy used Mistral Large 3 (41B active, ~40GB Q4) which
couldn't fit at all. Gemma 4 26B-A4B delivers comparable or better
reasoning at 3.8B active parameters, fitting in ~7GB with NVFP4.

#### Why Gemma 4 26B-A4B for Reasoning

| Benchmark | Gemma 4 26B-A4B | Mistral Large 3 | Granite 4 Small |
|-----------|----------------|-----------------|-----------------|
| AIME 2026 | **88.3%** | — | — |
| MMLU Pro | **82.6%** | — | — |
| LiveCodeBench v6 | **77.1%** | — | — |
| Active params | 3.8B | 41B | 9B |
| VRAM (NVFP4) | ~7GB | ~20GB | ~5GB |
| Context | 256K | 128K | 128K |
| Multimodal | Image + Video | Text only | Text only |

The 26B-A4B also handles vision natively (image + video input),
reducing dependence on Granite Vision 3.3 2B for general visual QA.
Granite Vision stays for specialized OCR/document understanding
where it ranks #2 on OCRBench.

#### Gemma 4 12B — Dense Alternative

Gemma 4 12B is a dense (non-MoE) multimodal model. Compared to
26B-A4B:

- **All parameters active**: 12B params, no MoE routing overhead
- **Encoder-free vision**: 35M vision embedder (vs 550M encoder)
- **Same capabilities**: text, image, audio understanding (not TTS)
- **Simpler serving**: no MoE expert scheduling, works well on Ollama
- **5GB VRAM** with NVFP4 quantization

Use 12B when you need simpler deployment (single Ollama instance)
or when the 26B-A4B MoE overhead isn't worth the benchmark gains.

Config example:
```toml
[models.vision]
type = "generate"
backend = "openai"
endpoint = "http://localhost:11434/v1"
model = "gemma4:12b"

[models.chat]
type = "generate"
backend = "openai"
endpoint = "http://localhost:11434/v1"
model = "gemma4:12b"
```

Ollama Modelfile for agentic use:
```
FROM gemma4:12b
PARAMETER num_ctx 65536
PARAMETER temperature 0.2
PARAMETER top_p 0.9
PARAMETER repeat_penalty 1.15
PARAMETER num_predict 4096
```

#### Granite 4.0 3B Vision — Upgrade Path

Granite 4.0 3B Vision (April 2026) replaces Granite Vision 3.3 2B
for OCR and enterprise document data extraction. Key improvements:

- 3B parameters (vs 2B) — better document extraction accuracy
- Optimized for invoices, forms, compliance documents
- Apache 2.0 license, same serving stack (vLLM or ollama)
- ~2GB VRAM with NVFP4 (vs ~1.5GB for 3.3 2B) — fits budget

**Current repo:** `ibm-granite/granite-vision-3.3-2b` (production).
**Upgrade repo:** Check HuggingFace for `ibm-granite/granite-4.0-3b-vision`
or similar when GA. Until then, use the 3.3 2B.

This is a GPU-tier model served externally, not an in-process ONNX
model. It does not belong in `navra model pull`. Configure as:

```toml
[models.vision]
backend = "openai"
base_url = "http://localhost:11434/v1"
model = "ibm/granite3.3-vision"           # upgrade to 4.0 when GA
locality = "local"
```

### Why Two Tiers

| | CPU Tier | GPU Tier (RTX 5090) |
|---|---|---|
| **Target** | Laptop, desktop without GPU | Workstation with RTX 5090 FE |
| **Startup** | navra loads models in-process | Separate vLLM/ollama processes |
| **Reasoning** | — | Gemma 4 26B-A4B (88.3% AIME, 256K ctx, multimodal) |
| **ASR quality** | Whisper V3: ~7.5 WER, 30s windows | Granite Speech: 5.52 WER, arbitrary length |
| **TTS quality** | Kokoro: natural, 26 preset voices | Voxtral: best quality, voice cloning |
| **Safety** | Regex + Guardian HAP 38M | + Guardian 3.3 8B (full taxonomy) |
| **RAG** | Text embeddings (768-dim) | + Visual embeddings (charts, tables) |
| **Vision** | — | Gemma 4 (general) + Granite Vision (OCR) |
| **License** | 100% Apache 2.0 / MIT | Voxtral is CC BY-NC (personal use) |

### OCR / Document Understanding Candidates

Models evaluated for document ingestion in navra-tools-docs and
navra-rag (landscape research, April 2026):

| Model | Params | Runtime | Speed | Notes |
|-------|--------|---------|-------|-------|
| GLM-OCR | 0.9B | llama.cpp / Ollama | ~175s first token (CPU) | #1 OmniDocBench (94.62). Structured markdown output. Good CPU-tier candidate for doc ingestion. |
| Nemotron OCR v2 (EN) | 54M | PyTorch (GPU) | 34.7 pages/s (A100) | Traditional detector+recognizer+relational. GPU-only. |
| Nemotron OCR v2 (multi) | 84M | PyTorch (GPU) | 34.7 pages/s (A100) | 5 languages. 37-40GB VRAM full, 24GB with skip_relational. |
| Granite Vision 3.3 2B | 2B | vLLM / ollama | GPU | Already in GPU tier. #2 OCRBench. |

**Recommendation:** GLM-OCR for CPU-tier document ingestion (runs via
Ollama, extracts structured markdown). Granite Vision for GPU-tier
OCR where accuracy matters. Nemotron OCR v2 is fast but requires GPU
and Python — doesn't fit our in-process ONNX or managed runtime model.

### Safety Model Candidates

Beyond the existing Guardian HAP 38M (in-process ONNX) and Guardian
3.3 8B (GPU tier), a new option from NVIDIA:

| Model | Params | Architecture | Accuracy | Modes |
|-------|--------|-------------|----------|-------|
| Guardian HAP 38M | 38M | BERT classifier | Good for HAP | Binary |
| Guardian 3.3 8B | 8B | LLM (Granite) | Full taxonomy | Generative |
| Nemotron Content Safety | 4B | Gemma-3 + adapter | ~84% multimodal | Binary + 23-cat taxonomy toggle |

Nemotron Content Safety is interesting for multimodal safety (text +
images), but at 4B parameters it must run as an external server via
navra-model-runtime (Podman or direct llama-server). Not suitable
for in-process ONNX. The license (NVIDIA Open Model) should be
evaluated against our Granite-first / Apache 2.0 preference.

### Multimodal RAG Upgrade Path

For visual document retrieval (charts, tables, diagrams), NVIDIA's
embedding models (landscape research, April 2026):

| Model | Params | Capability |
|-------|--------|-----------|
| Granite Vision 3.3 2B Embedding | 2B | Current plan. HF Transformers only. |
| Llama Nemotron Embed VL | 1.7B | Visual-semantic embeddings, Matryoshka dimensionality. Pareto-frontier on ViDoRe V3. |
| Llama Nemotron Rerank VL | 1.7B | Cross-encoder reranking for visual docs. Pairs with Embed VL. |

The Nemotron VL pair could replace or complement Granite Vision 2B
Embedding for visual RAG. Both are GPU-tier models. Evaluate when
navra-rag adds multimodal support.

## Model Serving Architecture

### Two-Tier Inference Model

navra uses two distinct inference tiers, each with its own crate:

```
┌─────────────────────────────────────────────────┐
│  Tier 1: In-Process (< 200M params)             │
│  navra-model + ort (ONNX Runtime)              │
│    ├── CPUExecutionProvider  (default)           │
│    ├── OpenVINOExecutionProvider  (Intel NPU)    │
│    └── CUDAExecutionProvider  (NVIDIA GPU)       │
│  Embeddings, classification, safety, VAD, TTS   │
│  Sub-100ms latency, no external dependencies    │
└─────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────┐
│  Tier 2: Managed External (> 1B params)         │
│  navra-model-hub + navra-model-runtime        │
│    ├── direct  (spawn llama-server, no isolation)│
│    ├── podman  (rootless container, --network=none)│
│    └── libkrun  (microVM, future)               │
│  LLMs, VLMs, OCR-VL, voice, deep safety         │
│  OpenAI-compat API, managed lifecycle           │
└─────────────────────────────────────────────────┘
```

**Why two tiers:** ONNX Runtime excels at single-pass encoder models
(embeddings, classifiers) but lacks KV-cache management, speculative
decoding, paged attention, and efficient quantization formats (GGUF
Q4_K_M) needed for autoregressive LLM inference. Models > 1B params
belong in the managed tier, served by llama.cpp or vLLM.

### Model Hub (`navra-model-hub` crate)

Models are addressed by URI, following RamaLama conventions:

- `ollama://granite-code:3b` — Ollama registry (default)
- `hf://ibm-granite/granite-3.3-8b-instruct-GGUF` — HuggingFace Hub
- `oci://quay.io/myorg/mymodel:latest` — OCI container registry
- `file:///path/to/model.gguf` — local file (no pull needed)

Content-addressed cache at `~/.local/share/navra/models/` with
deduplication (same content = same blob, multiple refs).

### Model Runtime (`navra-model-runtime` crate)

Pluggable isolation backends (feature flags):

| Backend | Isolation | GPU Passthrough | Use Case |
|---------|-----------|-----------------|----------|
| `direct` | None (child process) | Native | Development |
| `podman` | Namespace/cgroup, `--network=none` | CDI (NVIDIA), DRM (AMD/Intel) | Default production |
| `libkrun` | MicroVM (~100ms boot) | virtio-gpu | Hardened / untrusted models |

GPU auto-detection via sysfs/procfs (NVIDIA `/proc/driver/nvidia/`,
AMD/Intel `/sys/class/drm/` vendor IDs).

### Managed Model Configuration

```toml
# Managed model — hub pulls, runtime serves, navra connects
[models.reasoning]
source = "ollama://granite3.3:8b"     # navra-model-hub pulls this
runtime = "podman"                     # or "direct" for dev
gpu = "auto"                           # auto-detect, or "cpu", "cuda", "rocm"
context_size = 4096
locality = "local"

# In-process model — no hub/runtime needed
[models.embeddings]
backend = "onnx"
model_path = "~/.local/share/navra/models/granite-embedding-r2-int8.onnx"
tokenizer_path = "~/.local/share/navra/models/granite-embedding-r2/tokenizer.json"
device = "cpu"
```

When `source` is present, navra at startup:
1. Pulls the model via `ModelHub` (if not cached)
2. Starts a server via `ModelRuntime` (Podman or direct)
3. Connects via `OpenAiBackend` to the local endpoint
4. Stops the server on navra shutdown

### In-Process Models (CPU tier, via `ort` crate)

Small models load directly into the navra process. No external
dependencies, no network calls, no separate processes.

```
navra process
├── ort::Session (Guardian HAP 38M)     ← safety pipeline
├── ort::Session (Granite Embedding R2) ← RAG indexing/search
├── ort::Session (Kokoro-82M)           ← TTS
├── ort::Session (silero-vad)           ← voice activity detection
└── whisper_rs::WhisperContext          ← ASR
```

#### ONNX Runtime Integration (`ort` crate)

The `ort` crate (v2.0.0-rc.12, wrapping ONNX Runtime 1.24) provides
the in-process inference path. Used in production by Google (Magika),
SurrealDB, and others.

**Execution provider fallback chain:**

```rust
Session::builder()?
    .with_execution_providers([
        ep::CUDA::default().build(),           // NVIDIA GPU (RTX 5090)
        ep::OpenVINO::default()
            .with_device_type("AUTO")          // Intel NPU > iGPU > CPU
            .with_cache_dir("/tmp/ov_cache")   // cache compiled models
            .build(),
        // CPU is always the implicit final fallback
    ])?
    .commit_from_file("model.onnx")?;
```

The same navra binary automatically uses the best available
accelerator, falling back to CPU:

- **Desktop (RTX 5090):** CUDA EP claims the model
- **Laptop (Core Ultra 7 268V):** OpenVINO `AUTO` picks NPU for
  supported ops, iGPU or CPU for the rest
- **Headless / generic:** CPU EP handles everything

**Thread safety:** `ort::Session` is `Send + Sync` but `run()`
requires `&mut self`. For concurrent access in async Tokio code:

```rust
/// Wrap in std::sync::Mutex (not tokio::sync::Mutex) since
/// inference is CPU-bound and completes in milliseconds.
/// Use spawn_blocking to avoid blocking the Tokio executor.
pub struct OnnxModel {
    session: std::sync::Mutex<ort::Session>,
    tokenizer: tokenizers::Tokenizer,
}

impl OnnxModel {
    pub async fn classify(&self, text: &str) -> Result<Classification> {
        let encoding = self.tokenizer.encode(text, true)?;
        let input_ids = encoding.get_ids().to_vec();
        let attention_mask = encoding.get_attention_mask().to_vec();

        let session = self.session.lock().unwrap();
        tokio::task::spawn_blocking(move || {
            let outputs = session.run(ort::inputs![
                "input_ids" => ndarray::arr2(&[input_ids]),
                "attention_mask" => ndarray::arr2(&[attention_mask]),
            ]?)?;
            // argmax on logits for classification
            // mean pooling on hidden states for embeddings
            Ok(parse_output(&outputs))
        }).await?
    }
}
```

**ONNX model sources:**

| Model | ONNX Source | Quantization |
|-------|------------|--------------|
| Guardian HAP 38M | `KantiArumilli/granite-guardian-hap-38m-onnx` (HF) | FP32 + INT8 |
| Embedding R2 149M | `optimum-cli export onnx --model ibm-granite/granite-embedding-english-r2` | FP32 → INT8 via `onnxruntime.quantization` |
| Kokoro-82M | `onnx-community/Kokoro-82M-v1.0-ONNX` (HF) | FP32, FP16, Q8, Q4, Q4F16 |
| silero-vad | Bundled in `silero-vad-rust` crate | Native ONNX |

**Conversion for models without pre-built ONNX:**

```bash
# Install optimum
pip install optimum[onnxruntime]

# Export Granite Embedding R2 to ONNX
optimum-cli export onnx \
    --model ibm-granite/granite-embedding-english-r2 \
    ./granite-embed-onnx/

# Quantize to INT8 for CPU
python -m onnxruntime.quantization \
    --input ./granite-embed-onnx/model.onnx \
    --output ./granite-embed-onnx/model_int8.onnx \
    --quantize_mode dynamic
```

#### Whisper Integration (`whisper-rs` crate)

Whisper uses `whisper-rs` (Rust bindings to whisper.cpp) rather than
ONNX because whisper.cpp is the most optimized CPU inference path
for Whisper models, with GGUF quantization and SIMD acceleration.

```rust
pub struct WhisperModel {
    ctx: std::sync::Mutex<whisper_rs::WhisperContext>,
}

impl WhisperModel {
    pub async fn transcribe(&self, audio: &[f32]) -> Result<String> {
        let ctx = self.ctx.lock().unwrap();
        tokio::task::spawn_blocking(move || {
            let mut state = ctx.create_state()?;
            let mut params = whisper_rs::FullParams::new(
                whisper_rs::SamplingStrategy::Greedy { best_of: 1 },
            );
            params.set_language(Some("auto"));
            state.full(params, audio)?;
            // Collect segments
            Ok(collect_text(&state))
        }).await?
    }
}
```

**Model files:**

| Variant | Size | WER | Notes |
|---------|------|-----|-------|
| `ggml-large-v3.bin` | 3.1GB | ~7.5 | Best accuracy on CPU |
| `ggml-medium.bin` | 1.5GB | ~8.5 | Good balance |
| `ggml-small.bin` | 466MB | ~10.0 | Fast, lighter |
| `ggml-large-v3-turbo.bin` | 1.6GB | ~8.0 | Faster than large, close quality |

Recommendation: `large-v3-turbo` for the best speed/quality tradeoff
on CPU.

#### Kokoro TTS Integration

Kokoro-82M uses VITS architecture exported to ONNX. The inference
pipeline:

1. Text → phonemes (via `espeak-ng` or built-in G2P)
2. Phonemes → ONNX model → mel spectrogram
3. Mel → audio samples (24kHz mono)

```rust
pub struct KokoroModel {
    session: std::sync::Mutex<ort::Session>,
    // Kokoro uses phoneme IDs, not a tokenizer
    voice_embedding: ndarray::Array2<f32>,  // selected voice
}
```

Existing Rust implementations: `kokoro-onnx` (Python wrapper) and
browser WASM demos. A native Rust wrapper would be needed.

### External Models (GPU tier, managed or manual)

Larger models run as external servers. Two modes:

**Managed (via `navra-model-hub` + `navra-model-runtime`):**
navra pulls the model, starts a containerized llama-server or vLLM,
and connects automatically. No manual setup. Model lifecycle tied
to navra.

**Manual (existing):** User runs vLLM/ollama separately, navra
connects via `OpenAiBackend` to a pre-existing endpoint.

```
Managed mode:
navra ──starts──► Podman container (llama-server + model)
     ──HTTP────► localhost:<auto-port>/v1

Manual mode:
navra ──HTTP──► vLLM instance 1 (Granite Speech 1B, Vision 2B, Guardian 8B)
           ──► vLLM-Omni instance 2 (Voxtral TTS 4B)
           ──► ollama (Granite 4 Tiny, Ministral 3)
```

#### Framework Support Matrix

| Model | vLLM | ollama | llama.cpp | HF TEI/TGI |
|-------|------|--------|-----------|-------------|
| Gemma 4 26B-A4B | **Yes** | **Yes** (`gemma4:26b`) | **Yes** (GGUF) | Likely |
| Granite Guardian 3.3 8B | Yes | **Yes** (`ibm/granite3.3-guardian:8b`) | Yes (GGUF) | TGI yes |
| Granite Vision 3.3 2B | **Yes** | Yes (`ibm/granite3.3-vision`) | Partial | Likely |
| Granite Speech 1B | **Yes** (`granite_speech.py`) | No | No | No |
| Granite 4 Tiny MoE | **Yes** (day-0 support) | Partial (issue #10557) | Yes (GGUF) | Likely |
| Granite Vision 2B Embedding | Unclear | No | No | No |
| Voxtral TTS 4B | **Yes** (vLLM-Omni 0.18+) | No | No | No |

**Key insight:** vLLM is the only framework that supports all GPU-tier
models. ollama covers the LLMs (including Gemma 4) but not speech or
TTS. Gemma 4 has excellent ecosystem support: GGUF, ONNX (edge
models), ollama, TensorRT with NVFP4.

#### GPU Layout (RTX 5090 FE — 32GB GDDR7)

With NVFP4 quantization (Blackwell-exclusive), all models fit
simultaneously with room for KV caches:

| Model | VRAM (NVFP4) | Loaded | Role |
|-------|-------------|--------|------|
| Gemma 4 26B-A4B | ~7GB | Always | Reasoning, general vision |
| Granite Guardian 3.3 8B | ~3GB | Always | Deep safety |
| Granite Vision 3.3 2B | ~1.5GB | Always | OCR, document understanding |
| Granite Speech 1B | ~1GB | Always | ASR (long-form) |
| Granite 4 Tiny MoE | ~2GB | On demand | Code generation |
| Voxtral TTS 4B | ~3GB | On demand | Premium TTS, voice cloning |
| Granite Vision 2B Embedding | ~1.5GB | On demand | Visual RAG |
| **Total** | **~19GB** | | **13GB free for KV cache** |

For comparison, the previous plan with Mistral Large 3 (41B active)
couldn't fit a single model in 24GB at Q4. The combination of
Gemma 4 MoE efficiency + NVFP4 quantization makes the full stack
comfortably fit in 32GB.

The Vision 2B Embedding model (hardest to serve — only HF
Transformers confirmed) can be wrapped in a simple FastAPI service
using Transformers directly, sharing the GPU.

#### vLLM Deployment (RTX 5090)

Multiple vLLM instances, leveraging NVFP4 on Blackwell:

```bash
# Gemma 4 26B-A4B — reasoning + vision (primary model)
vllm serve google/gemma-4-26b-a4b-it \
    --quantization fp4 \
    --gpu-memory-utilization 0.3 \
    --port 8000

# Granite Guardian 3.3 8B — deep safety
vllm serve ibm-granite/granite-guardian-3.3-8b \
    --quantization fp4 \
    --gpu-memory-utilization 0.1 \
    --port 8001

# Granite Speech 1B — ASR
vllm serve ibm-granite/granite-4.0-1b-speech \
    --port 8002

# Voxtral TTS via vLLM-Omni
vllm serve mistralai/Voxtral-4B-TTS-2603 \
    --port 8003
```

Note: `--quantization fp4` uses NVFP4, which is Blackwell-exclusive.
On older GPUs, use `--quantization awq` or `--quantization gptq`
for INT4 quantization instead.

#### ollama Deployment (simpler alternative)

For users who prefer simplicity over maximum throughput:

```bash
ollama pull ibm/granite3.3-guardian:8b
ollama pull ibm/granite3.3-vision
ollama pull granite4:tiny

# Models loaded on demand, shared GPU memory
# OpenAI-compatible API at http://localhost:11434/v1
```

ollama cannot serve Speech or TTS models, so those still need
vLLM or the CPU tier.

### Model Backend Trait (navra-model crate)

The `ModelBackend` trait unifies both in-process (ONNX) and
external (API) backends behind a single interface.

```rust
/// Model inference backend.
///
/// Two implementations:
/// - OnnxBackend: in-process via ort crate (CPU tier)
/// - OpenAiBackend: external via HTTP API (GPU tier)
pub trait ModelBackend: Send + Sync + 'static {
    /// Generate text from a prompt.
    fn generate(
        &self,
        request: &GenerateRequest,
    ) -> BoxFuture<'_, Result<GenerateResponse, ModelError>>;

    /// Generate embeddings for input text or image.
    fn embed(
        &self,
        request: &EmbedRequest,
    ) -> BoxFuture<'_, Result<EmbedResponse, ModelError>>;

    /// Classify content (safety, moderation).
    fn classify(
        &self,
        request: &ClassifyRequest,
    ) -> BoxFuture<'_, Result<ClassifyResponse, ModelError>>;

    /// Transcribe audio to text.
    fn transcribe(
        &self,
        request: &TranscribeRequest,
    ) -> BoxFuture<'_, Result<TranscribeResponse, ModelError>>;

    /// Synthesize text to audio.
    fn synthesize(
        &self,
        request: &SynthesizeRequest,
    ) -> BoxFuture<'_, Result<SynthesizeResponse, ModelError>>;
}
```

#### Backend Implementations

```rust
/// In-process ONNX Runtime inference.
/// Used for: Guardian HAP 38M, Embedding R2 149M, Kokoro TTS,
///           silero-vad.
pub struct OnnxBackend {
    session: std::sync::Mutex<ort::Session>,
    tokenizer: Option<tokenizers::Tokenizer>,
}

/// whisper.cpp inference via whisper-rs bindings.
/// Used for: Whisper Large V3 (CPU ASR).
pub struct WhisperBackend {
    ctx: std::sync::Mutex<whisper_rs::WhisperContext>,
}

/// OpenAI-compatible API client.
/// Used for: vLLM, ollama, litellm, or remote APIs.
pub struct OpenAiBackend {
    client: reqwest::Client,
    base_url: String,        // e.g. "http://localhost:8000/v1"
    api_key: Option<String>,
    locality: Locality,      // Local or Remote (for safety filtering)
}

pub enum Locality {
    /// Model runs on localhost — content flows directly.
    Local,
    /// Model runs on remote API — content filtered before sending.
    Remote,
}
```

### Hardware-Aware Model Router

OpenVINO `AUTO` and `ort`'s EP fallback only select the best device
**per model session** — they don't optimize the layout across all
models. navra needs a **model router** that detects available hardware
at startup and assigns each model to the optimal accelerator.

```rust
pub struct ModelRouter {
    platform: Platform,
}

pub enum Platform {
    /// NVIDIA discrete GPU (RTX 5090, etc.)
    NvidiaGpu {
        vram_mb: u64,
        compute_capability: u32,  // 120 = Blackwell
        has_nvfp4: bool,
    },
    /// Intel Core Ultra with NPU + iGPU
    IntelCoreUltra {
        npu_tops: u32,            // 47 for 268V
        igpu_vram_mb: u64,        // ~16GB shared
    },
    /// CPU only
    CpuOnly {
        has_avx2: bool,
        has_avx512: bool,
    },
}

pub enum WorkloadType {
    /// <5MB, inference faster than EP compilation overhead
    TinyModel,
    /// <500M params, static shapes, encoder-only (classifiers, embeddings)
    SmallEncoder,
    /// Non-autoregressive synthesis (TTS like Kokoro, VITS)
    NonAutoregressive,
    /// Fixed-window ASR (Whisper 30s segments)
    FixedWindowAsr,
    /// Autoregressive token generation (LLMs, dynamic sequence length)
    LlmGeneration,
}

pub enum ExecutionTarget {
    Cpu,
    Cuda,
    OpenVinoNpu,
    OpenVinoGpu,
    ExternalVllm { port: u16 },
}

impl ModelRouter {
    /// Detect hardware at startup via CUDA API, OpenVINO device
    /// enumeration, and CPUID.
    pub fn detect() -> Self { /* ... */ }

    /// Pick the best execution target for a model.
    pub fn route(&self, workload: WorkloadType) -> ExecutionTarget {
        match (&self.platform, workload) {
            // --- NVIDIA GPU ---
            (Platform::NvidiaGpu { .. }, WorkloadType::LlmGeneration) =>
                ExecutionTarget::ExternalVllm { port: 8000 },
            (Platform::NvidiaGpu { .. }, _) =>
                ExecutionTarget::Cpu,  // small models stay in-process

            // --- Intel Core Ultra ---
            (Platform::IntelCoreUltra { .. }, WorkloadType::TinyModel) =>
                ExecutionTarget::Cpu,
            (Platform::IntelCoreUltra { .. }, WorkloadType::SmallEncoder) =>
                ExecutionTarget::OpenVinoNpu,
            (Platform::IntelCoreUltra { .. }, WorkloadType::NonAutoregressive) =>
                ExecutionTarget::OpenVinoNpu,
            (Platform::IntelCoreUltra { .. }, WorkloadType::FixedWindowAsr) =>
                ExecutionTarget::OpenVinoNpu,
            (Platform::IntelCoreUltra { .. }, WorkloadType::LlmGeneration) =>
                ExecutionTarget::OpenVinoGpu,  // iGPU for autoregressive

            // --- CPU only ---
            (Platform::CpuOnly { .. }, _) =>
                ExecutionTarget::Cpu,
        }
    }
}
```

The `device` field in model config is optional — if omitted, the
router auto-selects. Explicit `device` overrides the router.

**Startup log examples:**

```
$ navra serve   # desktop
[INFO] Detected: NvidiaGpu { vram: 32GB, cc: 120, nvfp4: true }
[INFO] guardian-hap → CPU (in-process ONNX, small encoder)
[INFO] embeddings  → CPU (in-process ONNX, small encoder)
[INFO] kokoro-tts  → CPU (in-process ONNX, non-autoregressive)
[INFO] whisper     → CPU (in-process whisper-rs)
[INFO] silero-vad  → CPU (in-process ONNX, tiny model)
[INFO] gemma-4     → vLLM :8000 (LLM generation, NVFP4)
[INFO] guardian-8b → vLLM :8001 (LLM generation, NVFP4)
```

```
$ navra serve   # laptop
[INFO] Detected: IntelCoreUltra { npu: 47 TOPS, igpu: Arc 140V }
[INFO] guardian-hap → NPU (OpenVINO, small encoder)
[INFO] embeddings  → NPU (OpenVINO, small encoder)
[INFO] kokoro-tts  → NPU (OpenVINO, non-autoregressive)
[INFO] whisper     → NPU (OpenVINO GenAI, fixed-window ASR)
[INFO] silero-vad  → CPU (tiny model, <1ms)
[INFO] gemma-4-e4b → iGPU (OpenVINO, LLM generation)
```

### KV Cache Compression: TurboQuant

TurboQuant (Google Research, ICLR 2026) compresses the **KV cache**
— the runtime memory that grows with context length. It is
**complementary** to weight quantization (NVFP4, GPTQ), not a
replacement. Combined, savings stack.

#### How it works

Two-stage, data-oblivious pipeline applied at inference time:

1. **PolarQuant** (AISTATS 2026) — Walsh-Hadamard rotation
   gaussianizes KV vectors, then quantizes in polar coordinates.
   No per-block scales/zero-points needed (unlike q4_0/q5_1 which
   waste 1-2 bits storing their own normalization constants).
2. **QJL** (AAAI 2025) — 1-bit residual sketch via Johnson-
   Lindenstrauss projection. Corrects systematic bias in attention
   scores. Adds 1 bit per coordinate.

#### Optimal configurations

Community implementation (TheTom/llama-cpp-turboquant, tested across
1.5B–104B models on M1-M5, RTX 3090-5090) revealed three critical
insights not in the paper:

1. **V compression is essentially free.** All quality degradation
   comes from Key compression. Values can be compressed to 2-bit
   with zero measurable impact on output quality.

2. **Asymmetric K/V configs are optimal.** Rather than using the
   same bit-width for both, compress Values aggressively and keep
   Keys at higher precision.

3. **Boundary layer protection.** Keeping the first 2 and last 2
   transformer layers at q8_0 (while compressing everything else
   with turbo2) recovers ~91% of quality loss. Just 15 lines of
   code, no speed impact.

**Recommended configurations:**

| Config | Keys | Values | Quality | Savings | Use Case |
|--------|------|--------|---------|---------|----------|
| **Safe** | q8_0 | turbo3 | Zero loss | ~3x | Production, accuracy-critical |
| **Balanced** | turbo4 (3.5b) | turbo3 (3b) | Near-zero | ~4x | General use |
| **Aggressive** | turbo3 + boundary | turbo2 (2.5b) | 91% preserved | ~5x | Max context on constrained HW |
| **V-only** | q8_0 | turbo2 (2.5b) | Zero loss | ~3.5x | Safest aggressive option |

The **Safe** and **V-only** configs are the sweet spots — meaningful
compression with zero quality loss, because V compression is free.

#### Impact on voice assistant: context length unlocked

**RTX 5090 (32GB) — Gemma 4 26B-A4B with NVFP4 weights:**

| Context | Weights | KV (FP16) | KV (TQ safe) | Total | Fits? |
|---------|---------|-----------|-------------|-------|-------|
| 8K | 7GB | ~1GB | ~0.3GB | 8→7.3GB | Both |
| 32K | 7GB | ~4.5GB | ~1.5GB | 11.5→8.5GB | Both |
| 128K | 7GB | ~18GB | ~6GB | **25→13GB** | TQ needed |
| 256K | 7GB | ~36GB | ~12GB | **OOM→19GB** | TQ only |

Without TurboQuant, 128K is tight and 256K is impossible. With
TurboQuant (safe config, zero quality loss), 256K fits comfortably
alongside all other GPU models (19GB weights + 12GB KV = 31GB).

**Intel Core Ultra (iGPU, ~16GB shared) — Gemma 4 E4B:**

| Context | Weights (Q4) | KV (FP16) | KV (TQ safe) | Fits? |
|---------|-------------|-----------|-------------|-------|
| 32K | 5GB | ~2GB | ~0.7GB | Both |
| 64K | 5GB | ~4GB | ~1.3GB | Both |
| 128K | 5GB | ~8GB | ~2.7GB | **TQ only** |

TurboQuant extends the laptop from ~64K to 128K context.

#### Framework status (April 2026)

| Framework | Status |
|-----------|--------|
| llama.cpp | Community fork (TheTom). PR #21089 pending. Metal + CUDA kernels. |
| vLLM | Community forks (0xSero, mitkox). Official integration expected Q2-Q3 2026. |
| ollama | Depends on llama.cpp merge. |
| MLX | Working (`--kv-bits 3.5 --kv-quant-scheme turboquant`). |
| ONNX Runtime | No support. |

**Plan for it, don't depend on it yet.** When vLLM merges support:

```toml
[models.reasoning]
backend = "openai"
base_url = "http://localhost:8000/v1"
model = "google/gemma-4-26b-a4b-it"
locality = "local"
kv_cache = { keys = "q8_0", values = "turbo3" }  # safe config
```

#### References

- Paper: https://arxiv.org/abs/2504.19874 (ICLR 2026)
- PolarQuant: https://arxiv.org/abs/2502.02617 (AISTATS 2026)
- QJL: https://dl.acm.org/doi/10.1609/aaai.v39i24.34773 (AAAI)
- Google blog: https://research.google/blog/turboquant-redefining-ai-efficiency-with-extreme-compression/
- Community impl: https://github.com/TheTom/llama-cpp-turboquant
- Korben article: https://korben.info/turboquant-compression-kv-cache-llm.html

### Configuration

```toml
# --- CPU Tier (in-process, always available) ---

[models.guardian-hap]
backend = "onnx"
model_path = "$XDG_DATA_HOME/navra/models/granite-guardian-hap-38m-int8.onnx"
tokenizer_path = "$XDG_DATA_HOME/navra/models/granite-guardian-hap-38m/tokenizer.json"
device = "cpu"                           # "cpu", "cuda", "openvino"

[models.embeddings]
backend = "onnx"
model_path = "$XDG_DATA_HOME/navra/models/granite-embedding-r2-int8.onnx"
tokenizer_path = "$XDG_DATA_HOME/navra/models/granite-embedding-r2/tokenizer.json"
device = "cpu"

[models.tts]
backend = "onnx"
model_path = "$XDG_DATA_HOME/navra/models/kokoro-82m-q8.onnx"
voice = "af_heart"                       # default voice preset
device = "cpu"

[models.asr]
backend = "whisper"
model_path = "$XDG_DATA_HOME/navra/models/ggml-large-v3-turbo.bin"
language = "auto"

[models.vad]
backend = "onnx"
model_path = "$XDG_DATA_HOME/navra/models/silero-vad.onnx"
device = "cpu"

# --- GPU Tier (external, optional upgrades) ---

[models.asr-gpu]
backend = "openai"
base_url = "http://localhost:8001/v1"
model = "ibm-granite/granite-4.0-1b-speech"
locality = "local"

[models.tts-gpu]
backend = "openai"
base_url = "http://localhost:8002/v1"
model = "mistralai/Voxtral-4B-TTS-2603"
locality = "local"

[models.guardian-deep]
backend = "openai"
base_url = "http://localhost:8000/v1"
model = "ibm-granite/granite-guardian-3.3-8b"
locality = "local"

[models.vision]
backend = "openai"
base_url = "http://localhost:11434/v1"    # ollama
model = "ibm/granite3.3-vision"
locality = "local"

[models.vision-embedding]
backend = "openai"
base_url = "http://localhost:8003/v1"     # custom FastAPI wrapper
model = "ibm-granite/granite-vision-3.3-2b-embedding"
locality = "local"
```

### Model Selection Logic

Modules reference models by role, not by name. navra resolves to
the best available backend at startup:

```toml
[modules.voice]
enabled = true
asr_model = "asr"           # uses Whisper (CPU)
# asr_model = "asr-gpu"     # uncomment to upgrade to Granite Speech
tts_model = "tts"           # uses Kokoro (CPU)
# tts_model = "tts-gpu"     # uncomment to upgrade to Voxtral
vad_model = "vad"
audio_device = "default"
```

This lets users upgrade individual capabilities by uncommenting a
line, without changing module code.

### Rust Crate Dependencies (navra-model)

```toml
[dependencies]
ort = { version = "2.0.0-rc.12", features = ["load-dynamic"] }
tokenizers = "0.21"
whisper-rs = "0.13"
reqwest = { version = "0.12", features = ["json"] }
ndarray = "0.16"
serde = { version = "1", features = ["derive"] }
serde_json = "1"
tokio = { version = "1", features = ["rt"] }
tracing = "0.1"

[features]
default = ["cpu"]
cpu = []                    # ONNX CPU + whisper.cpp
cuda = ["ort/cuda"]         # ONNX CUDA EP
rocm = ["ort/rocm"]         # ONNX ROCm EP (AMD)
openvino = ["ort/openvino"] # ONNX OpenVINO EP (Intel NPU)
```

The `load-dynamic` feature for `ort` avoids bundling the ONNX
Runtime library, using the system-installed version instead. This
keeps the binary small and allows distro packaging.

## Safety Architecture: Local Gateway, Remote Brain

### The Problem

When the reasoning model is remote (e.g. Claude API), the data flow
is:

```
Local files ──► navra ──► navra agent ──► Remote Claude API
                 │                              ▲
                 │ safety filters here     user's data
                 │                         leaves the box
```

navra must ensure that sensitive content never leaves the local
perimeter, even when the agent forwarding tool results to a remote
model is outside navra's control.

### Threat Analysis

| Threat | Direction | Current | Gap |
|--------|-----------|---------|-----|
| Agent reads secrets from files | Outbound (tool → agent) | Regex filters redact before returning | Covered |
| Agent reads PII from documents | Outbound (tool → agent) | PII filters redact | Covered |
| Agent bypasses navra for file I/O | Bypass | Not prevented | **Gap 1** |
| Document content sent to remote embeddings API | Outbound (embed request) | Not filtered | **Gap 2** |
| Remote model injects harmful content via write | Inbound (agent → tool) | Not filtered | **Gap 3** |
| Transcribed speech contains secrets spoken aloud | Outbound (ASR → agent) | Not filtered | **Gap 4** |

### Solution: Bidirectional Safety + Perimeter Enforcement

#### Gap 1 — navra-flow's Own File Tools Bypass navra

navra-flow has 22 built-in MCP tools including file I/O (`file_read`,
`directory_list`, `environment_variable`). If a specialist uses these
instead of `file_read`, navra's safety filters never fire.

**Solution: Tool exclusion in navra-flow config.**

When navra is configured as an MCP server, navra-flow should disable its
overlapping built-in tools for specialists that connect to navra.
This is a navra-flow-side configuration concern, not an navra change:

```yaml
# navra-flow specialist config when navra is the file gateway
mcp_servers:
  navra:
    transport: unix
    socket: "$XDG_RUNTIME_DIR/navra/navra.sock"
    token: "${MCPD_TOKEN}"

# Disable built-in tools that overlap with navra
disabled_tools:
  - file_read
  - file_write
  - file_append
  - directory_list
  - directory_create
  - environment_variable
```

Additionally, navra's systemd hardening (`ProtectHome=read-only`,
`ReadWritePaths` limited to `~/.local/share/navra`) ensures that even
if a process tries to access files outside navra, the OS enforces the
boundary. For navra-flow running in a container (its default deployment),
the container's filesystem view can be restricted to only expose the
navra socket.

#### Gap 2 — Document Content Sent to Remote Embedding APIs

If the embedding model runs on a remote API (not localhost), raw
document content flows to the remote service before any filtering.

**Solution: Safety filter before embedding.**

The `rag_index` tool must run the safety pipeline on document content
*before* sending it to the embedding backend. This is an navra-side
guarantee:

```rust
async fn handle_rag_index(args, ctx, state) -> CallToolResult {
    let content = read_file(&path)?;

    // Apply safety filter BEFORE embedding
    let filtered = state.safety_pipeline.process(&content, &filter_ctx)?;

    // Only the filtered content reaches the embedding model
    let chunks = chunk(&filtered);
    let embeddings = state.embed_backend.embed(&chunks).await?;
    state.vector_store.insert(&chunks, &embeddings)?;

    // ...
}
```

**Config enforcement:** The model backend config uses a `locality`
field. When a backend is `remote`, navra enforces that any content
sent to it passes through the safety pipeline first.

When `locality = "local"` (or `base_url` resolves to `127.0.0.1` /
`::1` / Unix socket), content flows directly — the model is within
the trust perimeter. When `locality = "remote"`, the `ModelBackend`
wrapper applies the agent's safety pipeline before any API call.

For the CPU tier, locality is always `local` — models run inside the
navra process itself.

#### Gap 3 — Inbound Content Filtering

A remote model could instruct an agent to `file_write` content that
includes prompt injection, harmful instructions, or content that
violates policy. Currently navra only filters *outbound* (tool
responses), not *inbound* (tool arguments).

**Solution: Bidirectional filter pipeline.**

```
                    ┌──────────────────┐
Agent request ─────►│ Inbound filters  │──► Tool handler
  (tool args)       │ (content in args)│
                    └──────────────────┘
                              │
                              ▼
                    ┌──────────────────┐
Tool response ◄────│ Outbound filters │◄── Tool handler
  (to agent)        │ (existing)       │     (result)
                    └──────────────────┘
```

Inbound filtering applies to *write-path* operations only:

| Operation | Inbound filter? | Rationale |
|-----------|----------------|-----------|
| `read` | No | Agent sends a path, not content |
| `search` | No | Agent sends a query string |
| `write` | **Yes** | Agent sends file content |
| `edit` | **Yes** | Agent sends replacement content |
| `voice.speak` | **Yes** | Agent sends text for TTS |

The inbound pipeline uses the same `FilterPipeline` but evaluates
different concerns:

- **Guardian HAP**: Detect hate/abuse/profanity in generated content
  before writing to disk
- **Guardian 3.3 8B**: Detect hallucinated PII, harmful instructions,
  or policy violations in content the remote model produced
- **Regex filters**: Less useful inbound (the agent is unlikely to
  write AWS keys), but still catch accidental secret propagation

Implementation in `navra-core`:

```rust
pub struct FilterPipeline {
    filters: Vec<Box<dyn ContentFilter>>,
    model_filters: Vec<Box<dyn ModelFilter>>,
    action: FilterAction,
}

impl FilterPipeline {
    /// Filter outbound content (tool responses → agent).
    /// Existing behavior.
    pub async fn process_outbound(
        &self, content: &str, ctx: &FilterContext,
    ) -> Result<String, String> { /* ... */ }

    /// Filter inbound content (agent → tool write operations).
    /// Only runs model filters (Guardian), not regex secrets.
    pub async fn process_inbound(
        &self, content: &str, ctx: &FilterContext,
    ) -> Result<String, String> { /* ... */ }
}
```

#### Gap 4 — ASR Output Contains Spoken Secrets

If a user dictates "my password is hunter2", the ASR transcription
contains a secret that would flow to the agent unfiltered.

**Solution:** The `voice_listen` tool response passes through the
standard outbound safety pipeline, same as any other tool. The
existing `SecretFilter` and `PiiFilter` will catch "password is
hunter2" patterns. No special handling needed — the framework
already covers this because ASR output is just a tool response.

### Safety Architecture Summary

```
┌─────────────────────────────────────────────────────────────────┐
│                      Trust Perimeter                            │
│                  (local machine / localhost)                     │
│                                                                 │
│  ┌──────────┐    ┌─────────────────────────────────────────┐    │
│  │ In-proc  │    │              navra                        │    │
│  │ Models   │    │                                         │    │
│  │ (ONNX/   │◄──►│  Inbound ──► Tool ──► Outbound          │    │
│  │ whisper) │    │  filters     handler   filters           │    │
│  ├──────────┤    │                                         │    │
│  │ External │    │  ┌───────────────────────────────────┐  │    │
│  │ Models   │◄──►│  │ Model Backend (locality check)     │  │    │
│  │ (vLLM/   │    │  │ local → direct passthrough         │  │    │
│  │  ollama) │    │  │ remote → pre-filter content        │  │    │
│  └──────────┘    │  └───────────────────────────────────┘  │    │
│                  └────────────────┬────────────────────────┘    │
│                                   │ MCP (Unix socket)           │
│                  ┌────────────────▼────────────────────────┐    │
│                  │           navra agent                   │    │
│                  │  (disabled: file_read, file_write, etc.) │    │
│                  └────────────────┬────────────────────────┘    │
│                                   │                             │
└───────────────────────────────────┼─────────────────────────────┘
                                    │ HTTPS (filtered content only)
                          ┌─────────▼──────────┐
                          │   Remote Model     │
                          │   (Claude API)     │
                          │                    │
                          │   Only sees:       │
                          │   - redacted text  │
                          │   - filtered args  │
                          │   - sanitized ctx  │
                          └────────────────────┘
```

**Key invariant:** No unfiltered local content crosses the trust
perimeter. navra enforces this at three points:

1. **Outbound tool responses** — existing safety pipeline (regex +
   Guardian models)
2. **Inbound tool arguments** — new bidirectional pipeline (Guardian
   models on write-path operations)
3. **Model backend calls** — locality-aware pre-filtering (content
   filtered before reaching remote embedding/inference APIs)

## Safety Pipeline Upgrade

### Current State

```
Tool output ──► Regex tier (SecretFilter + PiiFilter) ──► Redact/Block
```

### Target State

```
                        INBOUND (write-path only)
                    ┌────────────────────────────────────┐
Agent request ─────►│ Guardian HAP 38M (hate/abuse)      │──► Tool handler
  (tool args)       │ Guardian 3.3 8B (deep, optional)   │
                    └────────────────────────────────────┘

                        OUTBOUND (all tool responses)
                    ┌────────────────────────────────────┐
Tool response ◄────│ Tier 1: Regex (secrets + PII)       │◄── Tool handler
  (to agent)        │ Tier 2: Guardian HAP 38M (in-proc)  │     (result)
                    │ Tier 3: Guardian 3.3 8B (GPU, opt.) │
                    └────────────────────────────────────┘

                        PRE-SEND (remote model backends)
                    ┌────────────────────────────────────┐
Remote API ◄───────│ Same outbound pipeline applied      │◄── Content to embed/
                    │ before content leaves localhost     │     classify remotely
                    └────────────────────────────────────┘
```

### Implementation

The existing `ContentFilter` trait is synchronous (`fn scan`). The
Guardian models need async inference (even in-process ONNX uses
`spawn_blocking`). Two options:

**Option A: Async ContentFilter (breaking change)**

```rust
pub trait ContentFilter: Send + Sync + 'static {
    fn name(&self) -> &str;
    fn scan(&self, content: &str, ctx: &FilterContext)
        -> BoxFuture<'_, Vec<Finding>>;
}
```

**Option B: Separate ModelFilter trait (additive)**

```rust
/// Async model-based content filter, runs after regex filters.
pub trait ModelFilter: Send + Sync + 'static {
    fn name(&self) -> &str;
    fn scan(&self, content: &str, ctx: &FilterContext)
        -> BoxFuture<'_, Vec<Finding>>;
}

pub struct FilterPipeline {
    filters: Vec<Box<dyn ContentFilter>>,       // sync, regex
    model_filters: Vec<Box<dyn ModelFilter>>,    // async, ML
    action: FilterAction,
}
```

**Recommendation: Option B.** It keeps the regex path fast and
synchronous, avoids breaking changes, and separates concerns. The
pipeline runs sync filters first (sub-microsecond), then async model
filters only if sync filters didn't already block.

### New Safety Profiles

```toml
[permissions.developer]
safety = "standard"          # regex only (existing behavior)

[permissions.sensitive]
safety = "guardian"           # regex + Guardian HAP 38M (in-process)

[permissions.high-security]
safety = "guardian-deep"      # regex + HAP 38M + Guardian 3.3 8B (GPU)

[permissions.admin]
safety = "none"
```

```rust
pub fn build_pipeline(profile: &str, models: &ModelRegistry) -> FilterPipeline {
    match profile {
        "standard" => { /* existing: regex only */ }
        "guardian" => {
            let mut pipeline = FilterPipeline::new(FilterAction::Redact);
            pipeline.add_filter(SecretFilter::new());
            pipeline.add_filter(PiiFilter::new());
            if let Some(hap) = models.get("guardian-hap") {
                pipeline.add_model_filter(GuardianHapFilter::new(hap));
            }
            pipeline
        }
        "guardian-deep" => {
            let mut pipeline = FilterPipeline::new(FilterAction::Redact);
            pipeline.add_filter(SecretFilter::new());
            pipeline.add_filter(PiiFilter::new());
            if let Some(hap) = models.get("guardian-hap") {
                pipeline.add_model_filter(GuardianHapFilter::new(hap));
            }
            if let Some(guardian) = models.get("guardian-deep") {
                pipeline.add_model_filter(GuardianDeepFilter::new(guardian));
            }
            pipeline
        }
        // ...
    }
}
```

## New Modules

### navra-rag — Vector Search & Document Intelligence

Upgrades document search from keyword-only (FTS5) to semantic
similarity + visual document understanding.

```
navra-tools-docs (FTS5, keyword)
        +
navra-rag (vector, semantic)
        =
Hybrid search: keyword recall + semantic precision
```

#### Relationship to navra-flow's Existing RAG

navra-flow already has a RAG system (FAISS + all-MiniLM-L6-v2, 384-dim)
in `/src/navra/cognitive/knowledge/`. The two serve different
purposes:

| | navra-rag | navra-flow Knowledge |
|---|---|---|
| **What it indexes** | User documents (~/Documents, ~/Code, ~/Notes) | Internal knowledge (heuristics, code snippets, personas) |
| **Access control** | Path ACLs, deny-wins, approval workflow | None (internal to navra-flow) |
| **Safety filtering** | Content filtered before embedding + before returning | None (trusted internal data) |
| **Embedding model** | Granite Embedding R2 149M (768-dim, in-process ONNX) | all-MiniLM-L6-v2 (384-dim) |
| **Vector store** | sqlite-vec (single file, aligns with navra's SQLite) | FAISS (in-memory, pre-built indices) |
| **Visual docs** | Granite Vision 3.3 2B Embedding (GPU tier) | Text-only |
| **Persistence** | `$XDG_DATA_HOME/navra/index.db` | `knowledge_index.faiss` |

They are complementary: navra-flow's RAG is the agent's internal memory;
navra-rag is the agent's view of the user's documents, mediated
by permissions and safety filters. navra-flow specialists query navra's
`rag_query` tool for user documents, and their own knowledge system
for heuristics and learned patterns.

#### Dependencies

- `navra-core` — Module trait, permissions
- `navra-model` — ModelBackend for embeddings (ONNX in-process)
- `sqlite-vec` — Vector storage in SQLite (aligns with DESIGN.md)
- `tokenizers` — Text chunking

#### Tools

| Tool | Operation | Description |
|------|-----------|-------------|
| `rag_index` | write | Index document: chunk → embed → store vectors |
| `rag_query` | search | Semantic search: embed query → nearest neighbors |
| `rag_similar` | search | Find documents similar to a given document |
| `rag_index_image` | write | Embed document page image (GPU tier: Granite Vision 2B Embedding) |
| `rag_rerank` | search | Re-rank candidate results by cross-encoder relevance |
| `rag_status` | read | Show index statistics (doc count, chunk count, staleness) |

#### Data Model

```sql
-- Extends the existing navra index.db

CREATE TABLE chunks (
    id          INTEGER PRIMARY KEY,
    document_id INTEGER NOT NULL REFERENCES documents(id) ON DELETE CASCADE,
    chunk_index INTEGER NOT NULL,
    content     TEXT NOT NULL,
    start_byte  INTEGER NOT NULL,
    end_byte    INTEGER NOT NULL
);

-- sqlite-vec virtual table for vector search
CREATE VIRTUAL TABLE chunk_vectors USING vec0(
    chunk_id INTEGER PRIMARY KEY,
    embedding FLOAT[768]           -- matches Granite Embedding R2 149M
);

-- Visual embeddings for document pages (GPU tier only)
CREATE VIRTUAL TABLE page_vectors USING vec0(
    id         INTEGER PRIMARY KEY,
    document_id INTEGER,
    page_num    INTEGER,
    embedding   FLOAT[768]
);
```

#### Chunking Strategy

1. Split by paragraph boundaries (double newline)
2. Merge short paragraphs to reach ~256 tokens
3. Split long paragraphs at sentence boundaries
4. Overlap: 32 tokens between chunks
5. Metadata: source path, byte offsets for highlighting

#### Query Flow

```
User query
    │
    ├──► FTS5 keyword search (navra-tools-docs) ──► candidates_keyword
    │
    ├──► Embed query (Granite R2 149M, in-process ONNX)
    │    └──► sqlite-vec KNN search ──► candidates_semantic
    │
    └──► Merge + deduplicate candidates
         │
         └──► Re-rank (optional, GPU tier)
              │
              └──► Top-K results with scores
```

### navra-modal-voice — Speech I/O

Desktop voice interface: microphone input → ASR → process →
TTS → speaker output.

#### Dependencies

- `navra-core` — Module trait
- `navra-model` — ModelBackend for ASR + TTS
- `cpal` — Cross-platform audio I/O (PipeWire/PulseAudio/ALSA)
- `hound` — WAV encoding for audio buffers

#### Tools

| Tool | Operation | Description |
|------|-----------|-------------|
| `voice_listen` | voice.listen | Record from microphone, transcribe |
| `voice_speak` | voice.speak | Synthesize text, play on speaker |
| `voice_transcribe` | voice.transcribe | Transcribe an audio file (no microphone) |
| `voice_status` | voice.status | Show audio device info, model availability |

#### Audio Pipeline

```
Microphone (cpal)
    │
    ▼
silero-vad (in-process ONNX, <1ms)
    │ speech segments only
    ▼
┌─── CPU tier ──────────────────────┐
│ Whisper Large V3 Turbo            │
│ (whisper.cpp via whisper-rs)      │
│ ~realtime, 30s windows, 99 langs  │
└───────────────┬───────────────────┘
         OR     │
┌─── GPU tier ──┴───────────────────┐
│ Granite 4.0 1B Speech (vLLM)      │
│ WER 5.52, arbitrary length        │
└───────────────┬───────────────────┘
                │ text
                ▼
Outbound safety filter (secrets, PII in spoken words)
    │
    ▼
MCP response to agent
    │
    │ (agent processes, calls voice_speak)
    │
    ▼
Inbound safety filter (Guardian: hate/abuse in TTS input)
    │
    ▼
┌─── CPU tier ──────────────────────┐
│ Kokoro-82M (in-process ONNX)      │
│ ~5x realtime, 26 voices, 9 langs  │
└───────────────┬───────────────────┘
         OR     │
┌─── GPU tier ──┴───────────────────┐
│ Voxtral TTS 4B (vLLM-Omni)       │
│ 70ms latency, voice cloning       │
└───────────────┬───────────────────┘
                │ audio samples (24kHz mono)
                ▼
Speaker (cpal)
```

#### Desktop Integration

- D-Bus signal `org.navra.Voice.Listening` for UI indicators
- System tray shows microphone state (idle / listening / processing)
- PipeWire preferred (Fedora default), fallback to PulseAudio/ALSA
- Keyboard shortcut activation via D-Bus method call

### navra-modal-vision — Document & Screen Understanding

Visual understanding for documents, screenshots, and screen capture.
GPU tier only — no CPU-tier vision model available.

#### Dependencies

- `navra-core` — Module trait
- `navra-model` — ModelBackend for vision models (OpenAI backend)

#### Tools

| Tool | Operation | Description |
|------|-----------|-------------|
| `vision_describe` | vision.describe | Describe an image file |
| `vision_ocr` | vision.ocr | Extract text from image/PDF page |
| `vision_ask` | vision.ask | Answer a question about an image |
| `vision_screen` | vision.screen | Capture screen region, describe or OCR |

#### Screen Capture

- D-Bus `org.freedesktop.portal.Screenshot` (XDG portal, works on
  Wayland + X11)
- Returns screenshot path → pass to Granite Vision 3.3 2B
- Respects approval workflow: `vision.screen` requires approval by
  default
- Vision model response (description text) passes through outbound
  safety filter — redacts any secrets visible on screen

## Crate Structure (updated April 2026)

```
navra/
├── navra-protocol       MCP/A2A/JSON-RPC types, upstream transports
├── navra-model          Model backend trait + ONNX/OpenAI impls
├── navra-model-hub      Pull/cache models (OCI, HuggingFace, Ollama)
├── navra-model-runtime  Serve models (Podman, direct, libkrun)
├── navra-security       Auth, permissions, IFC, safety filters, hooks
├── navra-core           Server, module trait, session, transport
├── navra-tools-docs     Document tools (FTS5, file I/O)
├── navra-tools-git      Git tools (status, diff, log, branch, commit)
├── navra-rag            Vector search, sqlite-vec, semantic chunking
├── navra-modal-voice    Speech I/O (ASR + TTS via ONNX models)
├── navra-modal-vision   Image/screen understanding (GPU tier)
└── navra-server         Binary: CLI, config, module wiring (navra)
```

### Dependency Graph

```
navra-protocol          (no navra deps)
navra-model             (no navra deps) ──► ort, tokenizers, reqwest
navra-model-hub         (no navra deps) ──► reqwest, sha2
navra-model-runtime     (no navra deps) ──► reqwest, libc
    ↓
navra-security          (protocol + model)
    ↓
navra-core              (protocol + model + security)
    ↓
navra-tools-*  ─────┐
navra-rag      ─────┼── (core only)
navra-modal-*  ─────┘
    ↓
navra-server            (all + hub + runtime)
```

The `navra-model-*` crates form a reusable family with no navra
dependencies — usable by navra agents or any Rust project that needs
to pull and serve AI models.

## Full Configuration Example

```toml
[server]
tcp = "127.0.0.1:9315"

# --- Modules ---

[modules.file]
enabled = true

[modules.rag]
enabled = true
embedding_model = "embeddings"
vision_model = "vision-embedding"        # GPU tier, optional
chunk_size = 256
chunk_overlap = 32

[modules.voice]
enabled = true
asr_model = "asr-gpu"                    # Granite Speech (RTX 5090)
# asr_model = "asr"                      # Whisper (CPU fallback)
tts_model = "tts-gpu"                    # Voxtral (RTX 5090)
# tts_model = "tts"                      # Kokoro (CPU fallback)
vad_model = "vad"
audio_device = "default"

[modules.vision]
enabled = true
model = "vision"                         # Granite Vision (RTX 5090)
reasoning_model = "reasoning"           # Gemma 4 26B-A4B for visual QA

# --- CPU Tier Models (in-process) ---

[models.guardian-hap]
backend = "onnx"
model_path = "$XDG_DATA_HOME/navra/models/granite-guardian-hap-38m-int8.onnx"
tokenizer_path = "$XDG_DATA_HOME/navra/models/granite-guardian-hap-38m/tokenizer.json"
device = "cpu"

[models.embeddings]
backend = "onnx"
model_path = "$XDG_DATA_HOME/navra/models/granite-embedding-r2-int8.onnx"
tokenizer_path = "$XDG_DATA_HOME/navra/models/granite-embedding-r2/tokenizer.json"
device = "cpu"

[models.tts]
backend = "onnx"
model_path = "$XDG_DATA_HOME/navra/models/kokoro-82m-q8.onnx"
voice = "af_heart"
device = "cpu"

[models.asr]
backend = "whisper"
model_path = "$XDG_DATA_HOME/navra/models/ggml-large-v3-turbo.bin"
language = "auto"

[models.vad]
backend = "onnx"
model_path = "$XDG_DATA_HOME/navra/models/silero-vad.onnx"
device = "cpu"

# --- GPU Tier Models (RTX 5090 FE, NVFP4) ---

[models.reasoning]
backend = "openai"
base_url = "http://localhost:8000/v1"
model = "google/gemma-4-26b-a4b-it"
locality = "local"

[models.asr-gpu]
backend = "openai"
base_url = "http://localhost:8002/v1"
model = "ibm-granite/granite-4.0-1b-speech"
locality = "local"

[models.tts-gpu]
backend = "openai"
base_url = "http://localhost:8003/v1"
model = "mistralai/Voxtral-4B-TTS-2603"
locality = "local"

[models.guardian-deep]
backend = "openai"
base_url = "http://localhost:8001/v1"
model = "ibm-granite/granite-guardian-3.3-8b"
locality = "local"

[models.vision]
backend = "openai"
base_url = "http://localhost:11434/v1"
model = "ibm/granite3.3-vision"
locality = "local"

# [models.vision-embedding]
# backend = "openai"
# base_url = "http://localhost:8004/v1"
# model = "ibm-granite/granite-vision-3.3-2b-embedding"
# locality = "local"

# --- Agents ---

[[agents]]
name = "navra-leader"
token_hash = "$blake3$..."
permissions = "orchestrator"

[[agents]]
name = "navra-code-specialist"
token_hash = "$blake3$..."
permissions = "developer"

[[agents]]
name = "navra-research-specialist"
token_hash = "$blake3$..."
permissions = "researcher"

# --- Permissions ---

[permissions.orchestrator]
allow = ["~/Documents/**", "~/Code/**", "~/Notes/**"]
deny = ["**/.env", "**/*secret*"]
operations = ["read", "search", "list", "voice.listen", "voice.speak",
              "vision.describe", "vision.ask"]
approve = ["voice.listen", "vision.screen"]
safety = "guardian"

[permissions.developer]
allow = ["~/Code/**"]
deny = ["**/.env", "**/*secret*", "**/credentials*"]
operations = ["read", "write", "search", "list"]
approve = ["write"]
safety = "guardian"

[permissions.researcher]
allow = ["~/Documents/**", "~/Notes/**"]
deny = ["**/.env"]
operations = ["read", "search", "list"]
approve = []
safety = "standard"
```

## navra-flow Integration

### Current navra-flow State (March 2026)

navra-flow is at Phase 5.5+ with:

- **MCP server**: FastMCP-based, 22 production tools (dev, web, data,
  system, file), stdio/SSE/Streamable HTTP transports
- **MCP client**: Both async and sync interfaces for memory/knowledge
- **A2A protocol**: Complete (JSON-RPC 2.0, agent cards, task management)
- **37+ personas**: YAML-defined specialists with per-persona model
  selection (Claude, Gemini, OpenResponses engines)
- **RAG**: FAISS + all-MiniLM-L6-v2 (384-dim) for internal knowledge
  (heuristics, code snippets) — distinct from navra's document RAG
- **Validation**: Multi-judge system (9 judges, 3 dimensions),
  anti-drift detection
- **No voice/speech** — to be provided by navra-modal-voice
- **No vision** — to be provided by navra-modal-vision

### Integration Architecture

navra-flow connects to navra as an MCP client. Each navra-flow specialist
maps to an navra agent identity with scoped permissions.

```
┌──────────────────────────────────────────────────────────────┐
│                        navra-flow                                │
│                                                              │
│  Leader (Claude API, 1M context)                             │
│    │                                                         │
│    ├── Code Specialist ──► navra agent "navra-code"          │
│    │   ops: read, write, search                              │
│    │   disabled_tools: file_read, file_write, directory_list │
│    │                                                         │
│    ├── Research Specialist ──► navra agent "navra-research"  │
│    │   ops: read, search (FTS5 + RAG)                        │
│    │   disabled_tools: file_read, directory_list             │
│    │                                                         │
│    ├── Voice I/O ──► navra agent "navra-leader"              │
│    │   ops: voice.listen, voice.speak                        │
│    │                                                         │
│    └── Vision ──► navra agent "navra-leader"                 │
│        ops: vision.describe, vision.ask, vision.screen       │
│                                                              │
│  Internal Knowledge (FAISS, all-MiniLM-L6-v2):              │
│    Heuristics, code snippets, personas — NOT via navra        │
│                                                              │
└──────────────────────────────────────────────────────────────┘
```

### MCP Client Configuration

navra-flow already has MCP client support. Addition for navra:

```yaml
# navra config
mcp_servers:
  navra:
    transport: unix
    socket: "$XDG_RUNTIME_DIR/navra/navra.sock"
    token: "${MCPD_TOKEN}"

# Per-specialist overrides
specialists:
  code:
    mcp_server: navra
    disabled_tools: [file_read, file_write, file_append,
                     directory_list, directory_create,
                     environment_variable]
  research:
    mcp_server: navra
    disabled_tools: [file_read, directory_list]
```

### A2A Interoperability

navra-flow's A2A implementation and navra's MCP interface are
complementary:

- **MCP** (navra ↔ navra-flow): Tool invocation. navra-flow calls navra tools
  for file access, RAG, voice, vision.
- **A2A** (navra-flow ↔ other agents): Task delegation. Other agents
  on the network discover navra-flow via agent cards and delegate tasks.

Future: navra could expose an A2A endpoint so external agents
discover its tools directly, without going through navra-flow. This
would let any A2A-compatible agent (not just navra-flow) use navra's
secure file access.

## Implementation Order

### Phase 1 — Model backend + safety upgrade

1. Create `navra-model` crate with `ModelBackend` trait
2. Implement `OnnxBackend` (Guardian HAP 38M + Embedding R2 on CPU)
3. Implement `WhisperBackend` (Whisper via whisper-rs)
4. Implement `OpenAiBackend` (for GPU tier models)
5. Add `ModelFilter` trait to `navra-core` safety pipeline
6. Add bidirectional filtering (`process_inbound` for write-path ops)
7. Implement `GuardianHapFilter` using in-process ONNX
8. Add `"guardian"` and `"guardian-deep"` safety profiles
9. Config: `[models.*]` section parsing with `locality` field

### Phase 2 — RAG module

1. Create `navra-rag` crate
2. Add `sqlite-vec` dependency, vector tables
3. Implement chunking (paragraph + sentence boundaries)
4. Implement `rag_index` with pre-embedding safety filter
5. Implement `rag_query` (embed via in-process ONNX → KNN → results)
6. Implement hybrid search (FTS5 + vector merge)
7. Wire into `navra-server`

### Phase 3 — Voice module

1. Create `navra-modal-voice` crate
2. Audio capture via `cpal`
3. VAD via in-process silero-vad ONNX
4. `voice_listen`: record → VAD → transcribe (Whisper or Granite)
5. `voice_speak`: inbound filter → TTS (Kokoro or Voxtral) → play
6. D-Bus signals for UI state
7. System tray microphone indicator

### Phase 4 — Vision module (GPU tier)

1. Create `navra-modal-vision` crate
2. `vision_describe` / `vision_ocr` / `vision_ask`
3. Screen capture via XDG portal
4. Outbound filter on vision model descriptions
5. Wire into approval workflow

### Phase 5 — navra-flow integration

1. Configure navra-flow MCP client to connect to navra
2. Map specialist roles to navra agent identities
3. Disable overlapping navra-flow built-in tools per specialist
4. End-to-end test: voice command → navra-flow → navra → result → voice

## Platform Profiles

### Desktop — RTX 5090 FE (full stack)

**Hardware:**

- 64GB RAM
- **NVIDIA RTX 5090 Founders Edition**
  - 32GB GDDR7, 512-bit bus, ~1.79 TB/s bandwidth
  - Blackwell architecture (GB202), 21,760 CUDA cores
  - 680 5th-gen Tensor Cores with **NVFP4** support
  - ~3.4 PetaFLOPS FP4 Tensor performance
  - 575W TDP

**Execution providers:** CUDA EP (primary), CPU (ONNX fallback)

**What runs where:**

| Model | Where | Runtime | VRAM / RAM |
|-------|-------|---------|------------|
| silero-vad | CPU (in-process) | ONNX `ort` | ~10MB |
| Guardian HAP 38M | CPU (in-process) | ONNX `ort` | ~50MB |
| Embedding R2 149M | CPU (in-process) | ONNX `ort` | ~200MB |
| Kokoro-82M TTS | CPU (in-process) | ONNX `ort` | ~100MB |
| Whisper Large V3 Turbo | CPU (in-process) | whisper-rs | ~1.6GB |
| Gemma 4 26B-A4B | **GPU** | vLLM (NVFP4) | ~7GB |
| Granite Guardian 3.3 8B | **GPU** | vLLM (NVFP4) | ~3GB |
| Granite Vision 3.3 2B | **GPU** | vLLM (NVFP4) | ~1.5GB |
| Granite Speech 1B | **GPU** | vLLM | ~1GB |
| Voxtral TTS 4B | **GPU** | vLLM-Omni | ~3GB |
| Granite 4 Tiny MoE | **GPU** | vLLM (NVFP4) | ~2GB |
| Granite Vision 2B Emb | **GPU** | HF Transformers | ~1.5GB |
| **GPU total** | | | **~19GB / 32GB** |

All GPU models loaded simultaneously. 13GB free for KV caches.
CPU-tier models stay in-process regardless — they're too small
to benefit from GPU and would waste VRAM.

**Capabilities:** Everything — reasoning, multimodal vision, voice
I/O with voice cloning, deep safety, visual RAG, code generation.

### Laptop — Intel Core Ultra 7 268V (mobile stack)

**Hardware:**

- **CPU:** 4 Lion Cove P-cores + 4 Skymont E-cores, up to 4.8 GHz
  - AVX2 (no AVX-512, no AMX)
  - ~5 TOPS INT8
- **NPU:** Intel AI Boost NPU 4, 6 neural compute engines
  - **47 TOPS INT8**, ~24 TOPS FP16
  - 32MB on-die SRAM
  - Supports INT8, FP16, INT4 (symmetric only)
  - Static shapes only (no autoregressive LLM generation)
  - Thermal throttling: clocks drop ~35% after ~90s sustained load
- **iGPU:** Intel Arc 140V (Xe2)
  - 8 Xe2 cores, up to 1,950 MHz
  - ~64 TOPS INT8
  - Shared LPDDR5x-8533, ~16GB usable from 32GB total
  - ~68 GB/s memory bandwidth (shared)
- **RAM:** 32GB LPDDR5x-8533 (on-package, not upgradeable)
- **TDP:** 17W base / 37W max turbo

**Execution providers:** OpenVINO EP with `AUTO` device selection
(NPU > iGPU > CPU), whisper-rs on CPU.

**What runs where:**

| Model | Where | Runtime | Why |
|-------|-------|---------|-----|
| silero-vad | CPU | ONNX `ort` | Too small for NPU overhead, <1ms on CPU |
| Guardian HAP 38M | **NPU** | ONNX `ort` + OpenVINO EP | Ideal NPU workload: small classifier, static shape, FP16 |
| Embedding R2 149M | **NPU** | ONNX `ort` + OpenVINO EP | Encoder model, static shape, benefits from NPU acceleration |
| Kokoro-82M TTS | **NPU** or CPU | ONNX `ort` + OpenVINO EP | Intel-optimized OpenVINO version exists (`magicunicorn/kokoro-tts-intel`) |
| Whisper Large V3 Turbo | **NPU** | OpenVINO GenAI | Pre-converted INT4 models exist (`FluidInference/whisper-large-v3-turbo-int4-ov-npu`) |
| Gemma 4 E4B (4.5B) | **iGPU** | llama.cpp SYCL or vLLM xpu | Multimodal (text+image+audio), ~5GB Q4. iGPU better than NPU for autoregressive generation |

Note: On the laptop, Whisper can run on NPU via OpenVINO GenAI
instead of whisper.cpp. This requires a separate code path (OpenVINO
GenAI's `WhisperPipeline` vs `whisper-rs`). The `ModelBackend` trait
abstracts this — the voice module doesn't need to know which runtime
is used.

**NPU vs iGPU vs CPU decision matrix:**

| Workload | Best Target | Why |
|----------|-------------|-----|
| Small classifiers (<100M, static) | **NPU** | Highest efficiency, 47 TOPS INT8, lowest power |
| Embedding models (<500M, static) | **NPU** | Batch of fixed-length inputs, encoder-only |
| TTS (fixed-length synthesis) | **NPU** | Non-autoregressive architecture fits NPU constraints |
| ASR (Whisper, fixed 30s windows) | **NPU** | OpenVINO GenAI has first-class Whisper NPU support |
| LLM generation (autoregressive) | **iGPU** | NPU can't do dynamic sequence lengths efficiently |
| Tiny models (<5MB) | **CPU** | NPU compilation overhead exceeds inference time |

**Capabilities (laptop):** Text safety (NPU-accelerated), text
embeddings/RAG (NPU), voice I/O (NPU for ASR/TTS), basic
reasoning + vision (iGPU with Gemma 4 E4B). No deep safety
(Guardian 8B too large), no voice cloning (Voxtral GPU-only).

**Laptop-specific config:**

```toml
# CPU tier models with OpenVINO NPU acceleration
[models.guardian-hap]
backend = "onnx"
model_path = "$XDG_DATA_HOME/navra/models/granite-guardian-hap-38m-int8.onnx"
tokenizer_path = "$XDG_DATA_HOME/navra/models/granite-guardian-hap-38m/tokenizer.json"
device = "openvino:AUTO"          # NPU > iGPU > CPU

[models.embeddings]
backend = "onnx"
model_path = "$XDG_DATA_HOME/navra/models/granite-embedding-r2-int8.onnx"
tokenizer_path = "$XDG_DATA_HOME/navra/models/granite-embedding-r2/tokenizer.json"
device = "openvino:NPU"           # force NPU for embeddings

[models.tts]
backend = "onnx"
model_path = "$XDG_DATA_HOME/navra/models/kokoro-82m-fp16.onnx"
voice = "af_heart"
device = "openvino:AUTO"

[models.asr]
backend = "whisper"
model_path = "$XDG_DATA_HOME/navra/models/ggml-large-v3-turbo.bin"
language = "auto"
# Alternative: OpenVINO GenAI on NPU (faster, lower power)
# backend = "openvino-genai"
# model_path = "$XDG_DATA_HOME/navra/models/whisper-large-v3-turbo-int4-ov"
# device = "NPU"

[models.vad]
backend = "onnx"
model_path = "$XDG_DATA_HOME/navra/models/silero-vad.onnx"
device = "cpu"                    # too small for NPU, <1ms on CPU

# Optional: Gemma 4 E4B on iGPU for local reasoning
# [models.reasoning-local]
# backend = "openai"
# base_url = "http://localhost:11434/v1"  # ollama with SYCL
# model = "gemma4:e4b"
# locality = "local"
```

### Headless / Generic (CPU only)

Any machine without GPU or NPU. Pure CPU inference via ONNX Runtime
default EP and whisper.cpp.

- 16GB+ RAM, AVX2 required
- ~4GB disk for model files
- Capabilities: text safety, embeddings/RAG, voice I/O (Whisper +
  Kokoro)
- No reasoning model, no vision, no deep safety

### Platform Comparison

| Capability | Desktop (RTX 5090) | Laptop (Core Ultra 7) | Headless (CPU) |
|-----------|-------------------|----------------------|----------------|
| Safety (fast) | CPU, 1-5ms | **NPU**, <2ms | CPU, 1-5ms |
| Safety (deep) | **GPU** (Guardian 8B) | — | — |
| Embeddings | CPU, 10-30ms | **NPU**, ~5-10ms | CPU, 10-30ms |
| ASR | **GPU** (Granite Speech) | **NPU** (Whisper OpenVINO) | CPU (whisper.cpp) |
| TTS | **GPU** (Voxtral, cloning) | **NPU** (Kokoro) | CPU (Kokoro) |
| Reasoning | **GPU** (Gemma 4 26B-A4B) | iGPU (Gemma 4 E4B) | — |
| Vision | **GPU** (Granite + Gemma 4) | iGPU (Gemma 4 E4B) | — |
| Visual RAG | **GPU** (Vision 2B Emb) | — | — |
| Power budget | 575W (GPU) | 17-37W (SoC) | Varies |

### Alternative GPU Configurations

| GPU | VRAM | What Fits (Q4/NVFP4) |
|-----|------|---------------------|
| RTX 4060 Ti 16GB | 16GB | Guardian 8B + Vision 2B + Speech 1B (no reasoning model) |
| RTX 4090 24GB | 24GB | Above + Gemma 4 26B-A4B (Q4, ~10GB). Tight, no NVFP4. |
| RTX 5090 32GB | 32GB | Full stack with NVFP4 — reference build |
| 2x RTX 5090 64GB | 64GB | Above + Gemma 4 31B dense (30.7B, ~16GB NVFP4) for max quality |
| RX 7900 XTX 24GB | 24GB | Same as RTX 4090 via ROCm. No NVFP4. |
| Intel Arc 140V (iGPU) | ~16GB shared | Gemma 4 E4B (Q4). Limited bandwidth (68 GB/s). |

## Build and Distribution

### Cargo Features

```toml
[dependencies]
ort = { version = "2.0.0-rc.12", features = ["load-dynamic"] }
tokenizers = "0.21"
whisper-rs = "0.13"
reqwest = { version = "0.12", features = ["json"] }
ndarray = "0.16"

[features]
default = ["cpu"]
cpu = []                    # ONNX CPU + whisper.cpp (always works)
cuda = ["ort/cuda"]         # NVIDIA GPU (RTX 5090, etc.)
openvino = ["ort/openvino"] # Intel NPU + iGPU (Core Ultra, etc.)
rocm = ["ort/rocm"]         # AMD GPU (RX 7900 XTX, etc.)
```

The `load-dynamic` feature for `ort` avoids bundling the ONNX
Runtime library, using the system-installed version instead. This
keeps the binary small and allows distro packaging.

**Build matrix:**

| Target | Features | ONNX Runtime |
|--------|----------|-------------|
| Desktop (NVIDIA) | `cpu,cuda` | Prebuilt (download) |
| Laptop (Intel) | `cpu,openvino` | **Must build from source** with OpenVINO EP |
| AMD GPU | `cpu,rocm` | **Must build from source** with ROCm EP |
| Generic / CI | `cpu` | Prebuilt (download) |

**Important:** The CUDA EP has prebuilt binaries via
`ORT_STRATEGY=download`. OpenVINO and ROCm require building ONNX
Runtime from source or providing custom shared libraries. Plan CI/CD
accordingly — ship platform-specific binaries.

### OpenVINO 2026.1 — llama.cpp Backend (Preview)

As of OpenVINO 2026.1 (April 2026), a preview OpenVINO backend for
llama.cpp enables optimized inference on Intel CPUs, GPUs, and NPUs.
Validated on Llama-3.2-1B, Phi-3-mini, Qwen2.5-1.5B, Mistral-7B.

This means managed-tier models served via `navra-model-runtime`
(which spawns llama-server) can transparently use Intel NPU
acceleration if OpenVINO is installed. No navra code changes needed —
llama-server picks up the OpenVINO backend at runtime.

New hardware support: Wildcat Lake SoCs, Intel Arc Pro B70 (32GB).
Also adds Qwen3 VL support (CPU + GPU), GPT-OSS 120B (CPU).

### OpenVINO Setup (Intel Core Ultra)

```bash
# Install OpenVINO toolkit
sudo dnf install openvino-toolkit    # Fedora
# or
pip install openvino openvino-genai

# Install NPU driver (Lunar Lake)
# Requires kernel 6.11+, firmware matched to driver version
sudo dnf install intel-npu-driver

# Build ONNX Runtime with OpenVINO EP
git clone https://github.com/microsoft/onnxruntime
cd onnxruntime
./build.sh --config Release \
    --build_shared_lib \
    --use_openvino AUTO \
    --parallel

# Point navra to the custom build
export ORT_STRATEGY=system
export ORT_LIB_LOCATION=/path/to/onnxruntime/build/Release
```

### OpenVINO Model Optimization for NPU

```bash
# Convert ONNX to OpenVINO IR with INT8 quantization
optimum-cli export openvino \
    --model ibm-granite/granite-guardian-hap-38m \
    --weight-format int8 \
    ./guardian-hap-ov/

# For Whisper on NPU (INT4, pre-converted available)
optimum-cli export openvino \
    --model openai/whisper-large-v3-turbo \
    --weight-format int4_sym \
    ./whisper-v3-turbo-ov-npu/
```

**NPU constraints:**
- INT4 must be **symmetric** (INT4_SYM) — asymmetric not supported
  on Lunar Lake
- Models must have **static shapes** — dynamic sequence lengths
  (autoregressive LLM) won't work on NPU
- Use `cache_dir` in OpenVINO EP to avoid recompilation on startup
