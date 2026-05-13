# smgglrs-tools-docs

Document management module for the smgglrs gateway.

## Overview

Provides MCP tools for reading, searching, and indexing documents.
Uses SQLite FTS5 for full-text search and sqlite-vec for vector
similarity search when an embedding model is available.

## Key types

- `FileModule` -- implements `Module` trait, registers document tools
- `IndexStore` -- SQLite-backed document index with FTS5 and
  optional vector embeddings
- `start_watcher` / `start_watcher_with_embeddings` -- filesystem
  watcher for automatic re-indexing
- `WatcherHandle` -- handle to stop the filesystem watcher

## Tools provided

All tools are prefixed with `file_` per project convention.

| Tool | Description |
|------|-------------|
| `file_search` | Full-text search across indexed documents |
| `file_semantic_search` | Vector similarity search (requires embedding model) |
| `file_read` | Read file content with optional line offset/limit |
| `file_list` | List directory contents |
| `file_tree` | Recursive directory listing with depth control |
| `file_grep` | Text pattern search across files |
| `file_write` | Create or overwrite a file |
| `file_edit` | Replace a unique string within a file |
| `file_info` | File metadata (size, type, lines, indexed status) |
| `file_delete` | Delete a file from disk and index |
| `file_approve` | Approve a pending operation |
| `file_deny` | Deny a pending operation |

## Dependency layer

```
smgglrs-core
    |
smgglrs-tools-docs
```

## Reference

See [DESIGN.md](../DESIGN.md) for the module trait design and tool
registration pattern.
