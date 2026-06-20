+++
title = "delta-mem OSAM Evaluation for navra"
weight = 10


template = "docs/page.html"
[extra]
toc = true
+++


Evaluation of delta-mem's Online State of Associative Memory (OSAM)
as a working memory mechanism for navra's locally-served small models.

## Verdict: Defer (no ONNX path)

delta-mem adds a fixed-size state matrix (0.12% of backbone params)
that acts as compressed intra-session working memory. Strong results
on memory-heavy benchmarks (1.31x on MemoryAgentBench). However,
integration with navra-model-runtime requires ONNX export, which
does not exist.

## What OSAM Does

- Compresses past interactions into an 8x8 (or larger) state matrix
- Updated each turn via gated delta-rule learning
- Read phase extracts associative signals, generates low-rank
  corrections to the backbone's attention computation
- Three write strategies: TSW (per-token), SSW (per-segment),
  MSW (parallel sub-states)
- Adds only 0.12% parameters to frozen backbone

## Results (from paper)

| Benchmark | Backbone | + delta-mem | Improvement |
|-----------|----------|-------------|-------------|
| MemoryAgentBench | 1.0x | 1.31x | +31% |
| LoCoMo | 1.0x | 1.20x | +20% |
| Average (8 tasks) | 1.0x | 1.10x | +10% |

Tested on Qwen3-4B/8B and SmolLM3-3B.

## Why Defer

1. **No ONNX export**: delta-mem is PyTorch-only. The OSAM module
   modifies the attention computation with low-rank corrections at
   every layer — not a simple post-processing step that can be
   appended to an ONNX graph.

2. **Backbone modification required**: The delta-rule update and
   read operations are interleaved with the transformer's forward
   pass. Exporting to ONNX would require fusing OSAM into the model
   graph, which delta-mem's codebase doesn't support.

3. **Runtime state management**: OSAM requires maintaining and
   updating a state matrix between inference calls. ONNX Runtime's
   session API supports this via IO binding, but the model itself
   must be exported with the state as an input/output tensor.

4. **Alternative**: navra-rag's cross-session retrieval already
   provides long-term memory. OSAM's value is intra-session working
   memory for multi-turn conversations — which could also be
   approximated by context window management (BudgetHook
   truncation strategies).

## Conditions to Re-evaluate

- delta-mem releases ONNX export support
- Someone publishes OSAM-augmented ONNX models on HuggingFace
- ort gains custom operator support making it feasible to implement
  OSAM as a custom node

## References

- Paper: https://arxiv.org/abs/2605.12357
- Code: https://github.com/declare-lab/delta-Mem (232 stars)
- Coverage: https://venturebeat.com/orchestration/a-0-12-parameter-add-on-gives-ai-agents-the-working-memory-rag-cant
