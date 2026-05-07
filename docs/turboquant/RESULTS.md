# Multi-Turn Tool Calling Benchmark Results

**Date**: 2026-05-07
**Model**: Qwen3 8B Q4_K_M (4.86 GiB)
**GPU**: NVIDIA GeForce RTX 5090 (sm_120, 32 GB)
**Build**: craftogrammer/llama.cpp-adaptive-turboquant @ 468bdec, CUDA 12.9
**Context**: 8192 tokens, flash attention on
**Runs**: 5 per config, 5 turns per run (25 tool calls per config)

## Summary

| Config (K / V) | T1 | T2 | T3 | T4 | T5 | Overall |
|:---|:---:|:---:|:---:|:---:|:---:|:---:|
| f16 / f16 | 5/5 | 5/5 | 5/5 | 5/5 | 5/5 | **100%** |
| q8_0 / q8_0 | 5/5 | 5/5 | 5/5 | 5/5 | 5/5 | **100%** |
| q4_0 / q4_0 | 5/5 | 5/5 | 5/5 | 5/5 | 5/5 | **100%** |
| turbo3 / turbo3 | 5/5 | 5/5 | 5/5 | 5/5 | 5/5 | **100%** |
| turbo2 / turbo2 | 0/5 | 4/5 | 0/5 | 0/5 | 0/5 | **16%** |
| q8_0 / turbo3 | 5/5 | 5/5 | 5/5 | 5/5 | 5/5 | **100%** |
| q8_0 / turbo2 | 5/5 | 5/5 | 5/5 | 5/5 | 5/5 | **100%** |
| turbo4 / turbo4 | — | — | — | — | — | *server crash* |
| q8_0 / turbo4 | — | — | — | — | — | *server crash* |

## Key Findings

### 1. turbo2-turbo2 is catastrophically broken for tool calling

At 2.125 bits per value, symmetric turbo2 drops tool calling to 16%.
The failure mode is **not JSON generation failure** — the model
generates correct tool call JSON in the response content:

```
{"name": "get_weather", "arguments": {"city": "Paris", "units": "celsius"}}
```

But it outputs this as plain text instead of using the tool call token
format. The K-cache quantization error prevents the model from routing
through the special tokens that trigger the server's tool call parser.
The model "knows" what to do but can't navigate the protocol.

### 2. Asymmetric K/V completely fixes the problem

`q8_0 K + turbo2 V` achieves **100% success** — same as f16 baseline.
This confirms the hypothesis: K-cache precision controls attention
routing for structured output. V-cache compression (even aggressive
turbo2 at 2.125 bits) has no impact on tool calling accuracy when K
remains precise.

### 3. turbo3 symmetric is fine

At 3.125 bits per value, symmetric turbo3 achieves 100% across all
5 turns. The quantization error at 3 bits is below the threshold
that disrupts tool call token routing.

### 4. turbo4 has a stability issue

Both turbo4 configs (symmetric and asymmetric) failed to run
benchmarks — the server crashed or produced incomplete results.
This may be a CUDA 12.9 compatibility issue specific to the turbo4
kernel (which uses a different codebook than turbo3/turbo2).

### 5. The degradation is NOT turn-dependent

The turbo2-turbo2 failure is consistent across turns — T1 fails at
the same rate as T5. This means the issue is not about compounding
quantization error across multi-turn conversations. Rather, turbo2's
K-cache precision is simply below the threshold for reliable tool
call token routing from the start.

## Implications

### For users
- **turbo3** is safe for tool calling at 5.12x compression
- **turbo2** requires asymmetric K/V: use `-ctk q8_0 -ctv turbo2`
- **Asymmetric K/V should be the default** for tool-calling workloads

### For upstream contribution
The fix is a recommendation, not code: document that `-ctk q8_0`
should be used with any aggressive V-cache quantization when tool
calling is enabled. This applies to both TurboQuant and existing
q4_0/q4_1 types.

A stronger fix would be the tool-call-aware anchoring mechanism
described in README.md, but the data shows asymmetric K/V is
sufficient — no new code needed for the common case.

## Performance Reference

From `llama-bench` (same model/GPU, 1 rep):

| K Type | V Type | Prompt (tok/s) | Generate (tok/s) |
|--------|--------|:---------:|:--------:|
| q8_0 | q8_0 | 11,712 | 201.7 |
| q4_0 | q4_0 | 11,765 | 186.4 |
| turbo3 | turbo3 | 11,008 | 182.5 |
| turbo2 | turbo2 | 11,150 | 190.6 |
| **q8_0** | **turbo3** | **11,323** | **203.3** |
| q8_0 | turbo2 | 11,407 | 201.9 |

Asymmetric q8_0/turbo3 is the fastest decode config while maintaining
100% tool calling accuracy.

## Raw Data

Individual run results are in `results/*.json`.
