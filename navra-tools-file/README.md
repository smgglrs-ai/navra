# navra-tools-file

File system tools for the navra gateway.

## Overview

Provides MCP tools for reading, writing, searching, and indexing
files. Uses SQLite FTS5 for full-text search and sqlite-vec for
vector similarity search when an embedding model is available.
Exposes MCP resources for `file://` URIs.

## Tools

All tools are prefixed with `file_` per project convention.

| Tool | Description |
|---|---|
| `file_read` | Read file content with optional line offset/limit |
| `file_write` | Create or overwrite a file |
| `file_edit` | Replace a unique string within a file |
| `file_delete` | Delete a file from disk and index |
| `file_list` | List directory contents |
| `file_tree` | Recursive directory listing with depth control |
| `file_grep` | Text pattern search across files |
| `file_search` | Full-text search across indexed documents (FTS5) |
| `file_semantic_search` | Vector similarity search (requires embedding model) |
| `file_info` | File metadata (size, type, lines, indexed status) |
| `file_approve` | Approve a pending write operation |
| `file_deny` | Deny a pending write operation |

## Key Types

- `FileModule` — implements `Module` trait, registers all file tools
- `IndexStore` — SQLite-backed document index with FTS5 and
  optional vector embeddings via sqlite-vec
- `WatcherHandle` — handle returned by `start_watcher()` to stop
  filesystem monitoring

## File Watcher

Auto-reindex files when they change on disk:

```rust
use navra_tools_file::{start_watcher, IndexStore};

let store = IndexStore::open("~/.local/share/navra/index.db")?;
let handle = start_watcher(&store, vec!["/home/user/projects"])?;

// later: handle.stop() to stop watching
```

## Configuration

```toml
[modules.file]
enabled = true
db = "~/.local/share/navra/index.db"
watch = ["~/Projects"]
```

## Dependency Layer

```
navra-core
    |
navra-tools-file
```
