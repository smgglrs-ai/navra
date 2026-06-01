# navra-memory

Persistent agent memory: working memory and knowledge store.

## Overview

Two SQLite-backed storage layers for conversation persistence and
knowledge retrieval:

- **Working memory** -- conversation turns that survive sessions
- **Knowledge memory** -- categorized entries with FTS5 full-text search

Optional `rag` feature enables vector-based retrieval through
`navra-rag`.

## Key types

- `WorkingMemory` -- session-scoped conversation turn storage
- `KnowledgeStore` -- categorized knowledge entries with FTS5 search
- `MemoryRetriever` / `ScoredEntry` -- ranked retrieval across stores
- `DistillationPipeline` -- compress conversations into knowledge
- `AuditLog` -- tool call and model call audit trail
- `SqliteSessionBackend` -- session persistence
- `effective_score` / `cleanup_decayed` -- memory decay functions

## Usage

```rust
use navra_memory::{WorkingMemory, KnowledgeStore};
use std::path::Path;

let working = WorkingMemory::open(Path::new("memory.db")).unwrap();
let knowledge = KnowledgeStore::open(Path::new("knowledge.db")).unwrap();
```

## Dependency layer

```
navra-core
navra-model
navra-rag (optional, behind "rag" feature)
    |
navra-memory
```

## Reference

See [DESIGN.md](../DESIGN.md) for the memory architecture and
decay/distillation model.
