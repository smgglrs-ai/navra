# smgglrs-rag

Retrieval-Augmented Generation module for the smgglrs gateway.

## Overview

Provides vector search and semantic chunking for context enrichment.
Uses sqlite-vec for vector similarity search backed by SQLite, so
no external vector database is required.

## Key types

- `RagModule` -- implements `Module` trait, registers RAG tools
- `ChunkStore` -- SQLite + sqlite-vec storage for document chunks
  and their embeddings
- `ChunkConfig` -- configurable chunking parameters (target size,
  overlap, minimum size)
- `chunk` module -- text chunking engine that splits documents by
  paragraph boundaries, merges short paragraphs, and splits long
  ones at sentence boundaries

## Chunking strategy

1. Split by paragraph boundaries (double newline)
2. Merge short paragraphs to reach target size
3. Split long paragraphs at sentence boundaries
4. Add configurable overlap between adjacent chunks

## Dependency layer

```
smgglrs-core
    |
smgglrs-rag
```

## Reference

See [DESIGN.md](../DESIGN.md) for the RAG architecture and
embedding pipeline.
