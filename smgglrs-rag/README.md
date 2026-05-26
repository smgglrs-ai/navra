# smgglrs-rag

Retrieval-Augmented Generation module for the smgglrs gateway.

## Overview

Provides hybrid search and semantic chunking for context enrichment.
Uses sqlite-vec + FTS5 for hybrid retrieval backed by SQLite, so
no external vector database is required.

## Key types

- `RagModule` -- implements `Module` trait, registers RAG tools
- `ChunkStore` -- SQLite + sqlite-vec + FTS5 storage for document
  chunks and their embeddings. Supports vector-only, FTS-only, and
  hybrid search with RRF fusion (k=60).
- `ChunkConfig` -- configurable chunking parameters (target size,
  overlap, minimum size)
- `chunk` module -- text chunking engine with breadcrumb injection
  (heading hierarchy prepended to chunks for positional awareness)
- `CrossEncoderReranker` -- ONNX cross-encoder for two-stage
  retrieval with batched scoring (single inference for all candidates)
- `GatedReranker` -- confidence gating wrapper that abstains when
  mean reranker score is below threshold
- `ConfidenceGate` -- configurable threshold + abstain message

## Search modes

- `search()` -- vector-only similarity search via sqlite-vec
- `search_fts()` -- full-text search via FTS5 BM25
- `search_hybrid()` -- FTS5 + vector fused with Reciprocal Rank
  Fusion (k=60). Over-fetches 3x from each channel for better
  coverage. Content-sync FTS5 table avoids doubling storage.

## Chunking strategy

1. Split by paragraph boundaries (double newline)
2. Merge short paragraphs to reach target size
3. Split long paragraphs at sentence boundaries (prose) or
   function boundaries (code)
4. Add configurable overlap between adjacent chunks
5. Optional breadcrumb injection: parse Markdown headings into
   a hierarchical path (e.g., "AMD > Financials > Cash Flows")
   and prepend to chunk content before embedding

## Reranking

Two-stage retrieval: after initial search returns candidates, a
cross-encoder scores each (query, candidate) pair for fine-grained
relevance.

- `CrossEncoderReranker` -- ONNX model (e.g., MiniLM-L6-v2).
  Batched scoring: all candidates in a single ONNX inference call
  (10x speedup vs sequential).
- `GatedReranker` -- wraps any reranker with confidence gating.
  Computes mean score after reranking; abstains (returns empty)
  if below threshold.
- `NoopReranker` -- passthrough for graceful degradation when no
  model is available.

## Dependency layer

```
smgglrs-core
    |
smgglrs-rag
```

## Reference

See [DESIGN.md](../DESIGN.md) for the RAG architecture and
embedding pipeline.
