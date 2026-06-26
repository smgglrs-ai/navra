+++
title = "Memory System"
description = "Persistent agent memory with conversation history, knowledge distillation, and entity graphs."
weight = 20
template = "docs/page.html"

[extra]
toc = true
+++

navra provides persistent memory for agents through the `navra-memory`
crate. Two SQLite-backed storage layers give agents short-term recall
(working memory) and long-term knowledge (knowledge store), with
temporal decay, entity graphs, and a distillation pipeline that
converts conversations into structured knowledge.

## Architecture

The memory system has four components:

| Component | Purpose | Storage |
|-----------|---------|---------|
| **WorkingMemory** | Conversation turns per session/agent | SQLite (WAL) |
| **KnowledgeStore** | Categorized entries with FTS5 search | SQLite (WAL) |
| **EntityGraph** | Relationship triples between entities | SQLite (WAL) |
| **DistillationPipeline** | Converts turns into knowledge entries | In-process |

All components use SQLite with WAL journaling. The memory database
files live alongside the main navra data directory.

## Working memory

Working memory stores conversation turns -- user messages, assistant
responses, and tool call results -- across sessions. Each turn belongs
to a session and agent, and contains one or more messages with roles,
content, and timestamps.

### Forking and merging

Working memory supports branching conversations. Fork a session to
explore an alternative approach without modifying the main timeline:

- **Fork**: copy the main timeline into a named branch
- **Fork from turn**: copy only turns up to a specific point
- **Merge (Append)**: add fork turns after the main timeline
- **Merge (Replace)**: replace main timeline turns from the fork point
- **Merge (Summarize)**: condense the fork into a single summary turn

Forks are isolated -- turns added to a fork do not appear on the main
timeline, and vice versa.

### Decay-scored retrieval

Turns have `importance` and `access_count` fields. The
`get_turns_by_score` method uses exponential decay with
importance-modulated rate to select the most relevant turns:

```text
effective_rate = base_rate / (1 + importance)
score = importance * e^(-effective_rate * age_hours) + relevance_boost
```

High-importance turns decay slower. A turn with importance 0.9 decays
roughly 5x slower than one with importance 0.1. The `access_count`
provides a relevance boost (capped at 0.3) for frequently retrieved
turns.

This follows the FadeMem pattern -- old but important memories survive
while trivial recent ones fade.

## Knowledge store

The knowledge store holds categorized entries with full-text search.
Each entry has a type, title, content, tags, and timestamps.

### Entry types

| Type | Use case |
|------|----------|
| `fact` | Verified statements |
| `event` | Things that happened |
| `instruction` | How-to directives |
| `insight` | Inferred patterns or lessons |
| `user` | User preferences and identity |
| `project` | Project-specific context |

### Full-text search

The knowledge store uses SQLite FTS5 for full-text search across
titles and content. FTS5 triggers keep the search index synchronized
automatically on insert, update, and delete.

### Scoped memory

Entries can be scoped to an entity (user), process (workflow), or
session. Scoped searches return entries matching the specified scope
plus global (unscoped) entries. This enables multi-tenant memory
without separate databases.

### Temporal validity

Entries can have a `valid_until` timestamp. Expired entries are
excluded from scoped searches and can be bulk-deleted with
`expire_stale()`. Use `store_with_ttl()` to set a time-to-live
in seconds.

### PII tracking

Entries can be flagged as containing PII with `store_with_pii()` or
`set_pii_flag()`. PII-flagged entries can be listed, counted, and
expired separately with `expire_pii_older_than()` for compliance
with data retention policies.

### Consent basis

Each entry tracks a GDPR consent basis: `legitimate_interest`,
`consent`, `legal_obligation`, `vital_interest`, `public_task`, or
`not_set`. Filter entries by consent basis with `list_by_consent()`.

## Entity graph

The entity graph stores `(entity1, relation, entity2)` triples with
optional temporal validity and confidence scores. It supports:

- **1-hop queries**: all relationships for an entity
- **2-hop traversal**: entities reachable within 2 hops
- **Filtered queries**: by entity, relation, or both
- **Temporal queries**: only relationships active at a given time

Relationships are ordered by confidence (descending) in active queries,
and by creation time (descending) in general queries.

## Distillation pipeline

The distillation pipeline converts working memory turns into
structured knowledge entries through four stages:

1. **Ingest**: load session turns and group into segments
2. **Synthesize**: extract knowledge using an LLM or stub extraction
3. **Reconcile**: check for conflicts with existing entries
4. **Forge**: persist entries into the knowledge store

### LLM-based extraction

When a model backend is configured, the synthesize stage sends
conversation segments to the LLM with a structured prompt. The model
returns JSON with classified entries (Fact, Event, Instruction,
Insight) with confidence scores and tags.

Without a model, the pipeline falls back to stub extraction: each
user message becomes a `Fact` entry with confidence 0.5.

### Content-addressed supersession

Distilled entries are content-addressed via SHA-256 of `(kind, title)`.
When the pipeline produces an entry with the same content key as an
existing entry, the existing entry is updated in place and its version
is incremented. This prevents duplicate knowledge while tracking how
understanding evolves.

### PII sanitization

An optional content sanitizer can be injected into the pipeline. When
configured, all distilled content is filtered for PII before being
persisted to the knowledge store or exported to Markdown files.

### Markdown export

The pipeline can export distilled entries as Markdown files with YAML
frontmatter, suitable for version control or integration with external
knowledge bases.

## Temporal tree

The `TemporalTree` provides a hierarchical index for temporal data,
following the MemForest architecture. Three tree types -- session,
entity, and scene -- share a single SQLite table. Each tree
auto-grows deeper when intermediate nodes exceed `max_children`,
keeping retrieval balanced.

Use cases:
- Summarize a session's history at different granularities
- Browse entity facts over time
- Search across session summaries (Forest Recall pattern)

## MCP tools

The knowledge module exposes four MCP tools:

### `knowledge_search`

Hybrid FTS5 + vector search with RRF fusion. When a vector store and
embedding model are configured, combines full-text and semantic
similarity results. Falls back to FTS-only search otherwise.

| Parameter | Type | Description |
|-----------|------|-------------|
| `query` | string | Natural language search query |
| `limit` | integer | Max results (default 10) |

### `entity_graph_query`

Traverse the entity-relationship graph.

| Parameter | Type | Description |
|-----------|------|-------------|
| `entity` | string | Entity name to query |
| `hops` | integer | 1 or 2 (default 1) |

### `decay_score`

Compute effective memory scores for knowledge entries.

| Parameter | Type | Description |
|-----------|------|-------------|
| `entry_ids` | string | Comma-separated IDs or `"all"` |

### `distill`

Extract structured knowledge entries from raw text. Supports three
modes:

- **LLM**: sends text to the configured model for structured extraction
- **Classifier**: uses an ONNX classifier for type assignment (set `memory_type` to `"auto"`)
- **Stub**: splits paragraphs into `Fact` entries with confidence 0.5

| Parameter | Type | Description |
|-----------|------|-------------|
| `text` | string | Raw text to distill |
| `source` | string | Source identifier (optional) |
| `memory_type` | string | `"auto"` for classifier, or explicit type |

## Decay and archival

The `cleanup_decayed` function computes effective scores for all
knowledge entries and moves entries below a threshold to a
`memory_archive` table. Archived entries are preserved for audit
but excluded from searches.

Run decay cleanup periodically (e.g., daily) to keep the active
knowledge store focused on relevant entries:

```text
Threshold 0.5: archives entries with low importance that haven't
been accessed recently. High-importance entries survive regardless
of age.
```

## Audit log

The `AuditLog` provides structured logging for agent runs, tool calls,
model calls, and flow task results. All entries are persisted to SQLite
and can be expired by age.

Key features:
- Per-run tracking: prompt, model, timestamps, exit reason
- Tool call logging: name, args, result, duration, ACL decision, IFC label
- Model call logging: tokens, response type, reasoning text
- Flow task tracking: specialist, status, output, iterations, tokens
- Structured findings: security audit findings with severity and remediation
- GPU utilization sampling: per-flow GPU/memory metrics
- PII sanitization: optional sanitizer filters args/results before recording
