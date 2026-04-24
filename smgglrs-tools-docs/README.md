# smgglrs-tools-docs

Document management module for the smgglrs gateway.

## Overview

Provides MCP tools for reading, searching, and indexing documents.
Uses SQLite FTS5 for full-text search and sqlite-vec for vector
similarity search when an embedding model is available.

## Key types

- `DocsModule` -- implements `Module` trait, registers document tools
- `IndexStore` -- SQLite-backed document index with FTS5 and
  optional vector embeddings
- `start_watcher` / `start_watcher_with_embeddings` -- filesystem
  watcher for automatic re-indexing
- `WatcherHandle` -- handle to stop the filesystem watcher

## Tools provided

All tools are prefixed with `docs_` per project convention.

## Dependency layer

```
smgglrs-core
    |
smgglrs-tools-docs
```

## Reference

See [DESIGN.md](../DESIGN.md) for the module trait design and tool
registration pattern.
