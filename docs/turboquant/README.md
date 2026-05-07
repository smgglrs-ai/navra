# TurboQuant KV Cache Evaluation

Evaluating TurboQuant KV cache quantization for multi-turn tool calling
in llama.cpp, with the goal of contributing fixes upstream.

## Background

TurboQuant (Google DeepMind, ICLR 2026, arXiv 2504.19874) compresses the
KV cache at inference time to 2-4 bits per value using Walsh-Hadamard
transforms and Lloyd-Max optimal scalar quantization. It enables
dramatically longer context windows on consumer GPUs.

**Problem**: Aggressive KV cache quantization breaks multi-turn tool
calling. The model can generate one tool call successfully, but on the
second turn the quantization error in cached structured tokens (JSON,
function names, arguments) corrupts attention routing and the model
fails to generate valid tool calls.

This affects all llama.cpp KV quantization (q4_0, turbo3, turbo2),
not just TurboQuant. TurboQuant's lower bit widths make the problem
more visible.

## Upstream Status (as of 2026-05-07)

TurboQuant is **not merged** into mainline llama.cpp. It exists across
community forks:

| Fork | Focus | Key Features |
|------|-------|-------------|
| [TheTom/llama-cpp-turboquant](https://github.com/TheTom/llama-cpp-turboquant) | Metal/Apple | Base CUDA + Metal port |
| [TheTom/turboquant_plus](https://github.com/TheTom/turboquant_plus) | Research | Upstream requirements tracker |
| [Madreag/turbo3-cuda](https://github.com/Madreag/turbo3-cuda) | CUDA kernels | 13-69% decode speedup at 32K |
| [craftogrammer/llama.cpp-adaptive-turboquant](https://github.com/craftogrammer/llama.cpp-adaptive-turboquant) | Consumer Blackwell | Adaptive layers, VRAM auto-selector, TCQ |
| [Pascal-SAPUI5/llama.cpp-turboquant](https://github.com/Pascal-SAPUI5/llama.cpp-turboquant) | AMD ROCm | ROCm port |
| [animehacker/llama-turboquant](https://github.com/animehacker/llama-turboquant) | V-cache + FA | Extended to V-cache with Flash Attention |

Upstream refs:
- Discussion: https://github.com/ggml-org/llama.cpp/discussions/20969
- Feature request: https://github.com/ggml-org/llama.cpp/issues/20977
- Upstream requirements: https://github.com/TheTom/turboquant_plus/issues/27
- Closed Vulkan PR: https://github.com/ggml-org/llama.cpp/pull/21010 (AI policy violation)

## Root Cause Analysis

The adaptive-turboquant fork has three quality-preservation mechanisms:

1. **Attention sinks** (`TURBO_SINK_SIZE`): First N KV positions stored at
   fp16 instead of quantized. Handles the attention-sink phenomenon.

2. **Thinking anchors** (`ggml_cuda_turbo_register_thinking_anchor`): When
   the model emits `<think>`, the server registers a dynamic fp16 range.
   Up to 3 dynamic anchor ranges supported.

3. **Layer-adaptive quantization** (`TURBO_LAYER_ADAPTIVE`, 16 modes):
   Boundary attention layers promoted to q8_0 while interior layers
   stay compressed.

**The gap**: No equivalent anchoring for tool call boundaries. When a
tool call completes:
- `slot.reset()` clears thinking anchors
- Tool call JSON and tool result tokens remain in the KV cache at
  turbo3/turbo2 precision
- On the next turn, quantization noise in structured tokens prevents
  reliable generation of the next tool call

## Contribution Strategy

We contribute to **upstream llama.cpp directly**, not to any fork.
Creating fork #7 that merges all others is the XKCD 927 trap.

### PR 1: Benchmarks (evidence)

Systematic multi-turn tool calling benchmarks across KV quant types.
Published as a discussion on ggml-org/llama.cpp. No code, just data.

### PR 2: Tool-call-aware KV precision anchoring (fix)

Add `--cache-anchor-tool-calls` to `llama-server`. Mark tool call and
tool result KV positions as precision-critical. Works with existing
quant types (q4_0, q8_0) and future ones (TurboQuant).

## Evaluation Plan

See [BENCHMARKS.md](BENCHMARKS.md) for the full benchmark methodology.

## Hardware

| Machine | GPU | SM Arch | VRAM | Role |
|---------|-----|---------|------|------|
| Workstation | RTX 5090 | sm_120 | 32 GB GDDR7 | Primary eval, NVFP4 weights + TurboQuant KV |
| ASUS Ascent GX10 | GB10 | sm_121 | 128 GB unified | Extended context, large models |

### NVFP4 Weight Quantization

NVFP4 (NVIDIA E2M1 format) is **merged in mainline llama.cpp** since
build b8967 (2026-04-29). It provides hardware-native weight
quantization on Blackwell tensor cores.

The target stack is **W4KV3**: NVFP4 weights + TurboQuant 3-bit KV
cache. NVFP4 handles compute (tensor cores), TurboQuant handles memory
(KV cache compression). They operate at different layers and are
complementary.
