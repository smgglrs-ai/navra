# Causal Provenance Graphs — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Track causal relationships across multi-agent flows using a typed DAG with W3C PROV-DM-aligned edge types. Answer "WHY did this happen?" not just "what happened."

**Architecture:** SQLite-backed `CausalGraphStore` in navra-flow for storage/query. `CausalSink` trait in navra-security for hook decoupling (same pattern as `ExtractionStore`). `ProvenanceHook` as observation-only post-hook. Three MCP tools for querying the graph.

**Tech Stack:** Rust, rusqlite (already in navra-flow), uuid, serde_json, async-trait.

**Environment:** `ORT_LIB_PATH=/usr/lib64 ORT_PREFER_DYNAMIC_LINK=1` required for all cargo commands.

---

## File Map

| File | Action | Responsibility |
|------|--------|----------------|
| `navra-flow/src/causal_graph.rs` | Create | CausalNode/Edge types, CausalGraphStore, SQLite schema, BFS queries |
| `navra-security/src/hooks/provenance_hook.rs` | Create | CausalSink trait, ProvenanceHook (post-hook) |
| `navra-security/src/hooks/mod.rs` | Modify | Add module + pub use |
| `navra-flow/src/lib.rs` | Modify | Add `pub mod causal_graph;` |
| `navra-flow/src/blackboard.rs` | Modify (line 18-28) | Add `causal_node_id` field |
| `navra-flow/src/mailbox.rs` | Modify (line 16-25) | Add `causal_node_id` field |
| `navra-server/src/main.rs` | Modify | Wire ProvenanceHook + CausalGraphStore |

---

### Task 1: Causal graph types and SQLite store

**Files:**
- Create: `navra-flow/src/causal_graph.rs`
- Modify: `navra-flow/src/lib.rs`

- [ ] **Step 1: Write failing tests for CausalGraphStore**

Create `navra-flow/src/causal_graph.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn insert_and_retrieve_node() {
        let store = CausalGraphStore::open_memory().unwrap();
        let node = CausalNode {
            id: "node-1".to_string(),
            node_type: CausalNodeType::ToolCall {
                tool_name: "file_read".to_string(),
                agent_id: "agent-a".to_string(),
                session_id: "sess-1".to_string(),
            },
            flow_id: Some("flow-1".to_string()),
            timestamp_ms: 1000,
        };
        store.insert_node(&node).unwrap();
        let graph = store.flow_graph("flow-1").unwrap();
        assert_eq!(graph.nodes.len(), 1);
        assert_eq!(graph.nodes[0].id, "node-1");
    }

    #[test]
    fn insert_edge_and_trace_causes() {
        let store = CausalGraphStore::open_memory().unwrap();
        // A -> B -> C (B was derived from A, C was derived from B)
        for (id, ts) in [("a", 1), ("b", 2), ("c", 3)] {
            store.insert_node(&CausalNode {
                id: id.to_string(),
                node_type: CausalNodeType::FlowNodeOutput {
                    flow_id: "f1".to_string(),
                    task_id: id.to_string(),
                },
                flow_id: Some("f1".to_string()),
                timestamp_ms: ts,
            }).unwrap();
        }
        store.insert_edge(&CausalEdge {
            source_id: "b".to_string(),
            target_id: "a".to_string(),
            edge_type: CausalEdgeType::WasDerivedFrom,
            flow_id: Some("f1".to_string()),
            timestamp_ms: 2,
        }).unwrap();
        store.insert_edge(&CausalEdge {
            source_id: "c".to_string(),
            target_id: "b".to_string(),
            edge_type: CausalEdgeType::WasDerivedFrom,
            flow_id: Some("f1".to_string()),
            timestamp_ms: 3,
        }).unwrap();

        let subgraph = store.trace_causes("c", 10).unwrap();
        assert_eq!(subgraph.nodes.len(), 3);
        assert_eq!(subgraph.edges.len(), 2);
    }

    #[test]
    fn trace_causes_respects_max_depth() {
        let store = CausalGraphStore::open_memory().unwrap();
        for i in 0..5 {
            store.insert_node(&CausalNode {
                id: format!("n{i}"),
                node_type: CausalNodeType::FlowNodeOutput {
                    flow_id: "f1".to_string(),
                    task_id: format!("t{i}"),
                },
                flow_id: Some("f1".to_string()),
                timestamp_ms: i as i64,
            }).unwrap();
        }
        for i in 1..5 {
            store.insert_edge(&CausalEdge {
                source_id: format!("n{i}"),
                target_id: format!("n{}", i - 1),
                edge_type: CausalEdgeType::WasDerivedFrom,
                flow_id: Some("f1".to_string()),
                timestamp_ms: i as i64,
            }).unwrap();
        }
        let subgraph = store.trace_causes("n4", 2).unwrap();
        // depth 2: n4 -> n3 -> n2 (3 nodes, 2 edges)
        assert_eq!(subgraph.nodes.len(), 3);
    }

    #[test]
    fn root_causes_finds_sources() {
        let store = CausalGraphStore::open_memory().unwrap();
        for id in ["root1", "root2", "mid", "leaf"] {
            store.insert_node(&CausalNode {
                id: id.to_string(),
                node_type: CausalNodeType::ToolCall {
                    tool_name: "t".to_string(),
                    agent_id: "a".to_string(),
                    session_id: "s".to_string(),
                },
                flow_id: None,
                timestamp_ms: 0,
            }).unwrap();
        }
        store.insert_edge(&CausalEdge {
            source_id: "mid".to_string(),
            target_id: "root1".to_string(),
            edge_type: CausalEdgeType::Used,
            flow_id: None,
            timestamp_ms: 0,
        }).unwrap();
        store.insert_edge(&CausalEdge {
            source_id: "mid".to_string(),
            target_id: "root2".to_string(),
            edge_type: CausalEdgeType::Used,
            flow_id: None,
            timestamp_ms: 0,
        }).unwrap();
        store.insert_edge(&CausalEdge {
            source_id: "leaf".to_string(),
            target_id: "mid".to_string(),
            edge_type: CausalEdgeType::WasDerivedFrom,
            flow_id: None,
            timestamp_ms: 0,
        }).unwrap();

        let roots = store.root_causes("leaf").unwrap();
        let mut root_ids: Vec<_> = roots.iter().map(|n| n.id.as_str()).collect();
        root_ids.sort();
        assert_eq!(root_ids, vec!["root1", "root2"]);
    }

    #[test]
    fn trace_effects_forward() {
        let store = CausalGraphStore::open_memory().unwrap();
        for id in ["src", "mid", "dst"] {
            store.insert_node(&CausalNode {
                id: id.to_string(),
                node_type: CausalNodeType::ToolCall {
                    tool_name: "t".to_string(),
                    agent_id: "a".to_string(),
                    session_id: "s".to_string(),
                },
                flow_id: None,
                timestamp_ms: 0,
            }).unwrap();
        }
        store.insert_edge(&CausalEdge {
            source_id: "mid".to_string(),
            target_id: "src".to_string(),
            edge_type: CausalEdgeType::WasDerivedFrom,
            flow_id: None,
            timestamp_ms: 0,
        }).unwrap();
        store.insert_edge(&CausalEdge {
            source_id: "dst".to_string(),
            target_id: "mid".to_string(),
            edge_type: CausalEdgeType::WasDerivedFrom,
            flow_id: None,
            timestamp_ms: 0,
        }).unwrap();

        let subgraph = store.trace_effects("src", 10).unwrap();
        assert_eq!(subgraph.nodes.len(), 3);
    }

    #[test]
    fn empty_graph_returns_empty_subgraph() {
        let store = CausalGraphStore::open_memory().unwrap();
        let subgraph = store.trace_causes("nonexistent", 10).unwrap();
        assert!(subgraph.nodes.is_empty());
        assert!(subgraph.edges.is_empty());
    }
}
```

- [ ] **Step 2: Add module to lib.rs**

In `navra-flow/src/lib.rs`, add:

```rust
pub mod causal_graph;
```

- [ ] **Step 3: Run tests to verify compile failure**

Run: `ORT_LIB_PATH=/usr/lib64 ORT_PREFER_DYNAMIC_LINK=1 cargo test -p navra-flow causal_graph -- --nocapture 2>&1 | tail -5`

Expected: Compile error — types not defined.

- [ ] **Step 4: Implement types and CausalGraphStore**

Write the implementation at the top of `causal_graph.rs`:

```rust
//! Causal provenance graphs for multi-agent accountability.
//!
//! Tracks causal relationships across tool calls, agent messages,
//! and flow node outputs using a typed DAG with W3C PROV-DM-aligned
//! edge types. Answers "WHY did this happen?" via BFS traversal.

use rusqlite::Connection;
use std::collections::{HashSet, VecDeque};
use std::path::Path;
use std::sync::Mutex;

/// Types of nodes in the causal graph (W3C PROV-DM aligned).
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum CausalNodeType {
    /// A tool call execution (PROV: Activity).
    ToolCall {
        tool_name: String,
        agent_id: String,
        session_id: String,
    },
    /// An agent reasoning or action step (PROV: Activity).
    AgentAction {
        agent_id: String,
        action_type: String,
    },
    /// Data written to blackboard (PROV: Entity).
    BlackboardWrite { key: String, version: u64 },
    /// Output of a flow node (PROV: Entity).
    FlowNodeOutput { flow_id: String, task_id: String },
    /// A mailbox message (PROV: Entity).
    Message { sender: String, receiver: String },
}

/// Types of causal edges (W3C PROV-DM aligned).
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CausalEdgeType {
    /// Entity was derived from another entity (prov:wasDerivedFrom).
    WasDerivedFrom,
    /// Entity was generated by an activity (prov:wasGeneratedBy).
    WasGeneratedBy,
    /// Activity used an entity (prov:used).
    Used,
    /// Activity was informed by another (prov:wasInformedBy).
    WasInformedBy,
    /// Activity was triggered by another (navra extension).
    WasTriggeredBy,
}

impl CausalEdgeType {
    fn as_str(&self) -> &'static str {
        match self {
            Self::WasDerivedFrom => "was_derived_from",
            Self::WasGeneratedBy => "was_generated_by",
            Self::Used => "used",
            Self::WasInformedBy => "was_informed_by",
            Self::WasTriggeredBy => "was_triggered_by",
        }
    }

    fn from_str(s: &str) -> Option<Self> {
        match s {
            "was_derived_from" => Some(Self::WasDerivedFrom),
            "was_generated_by" => Some(Self::WasGeneratedBy),
            "used" => Some(Self::Used),
            "was_informed_by" => Some(Self::WasInformedBy),
            "was_triggered_by" => Some(Self::WasTriggeredBy),
            _ => None,
        }
    }
}

/// A node in the causal graph.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct CausalNode {
    pub id: String,
    pub node_type: CausalNodeType,
    pub flow_id: Option<String>,
    pub timestamp_ms: i64,
}

/// A directed edge in the causal graph.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct CausalEdge {
    pub source_id: String,
    pub target_id: String,
    pub edge_type: CausalEdgeType,
    pub flow_id: Option<String>,
    pub timestamp_ms: i64,
}

/// A subgraph returned by query operations.
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct CausalSubgraph {
    pub nodes: Vec<CausalNode>,
    pub edges: Vec<CausalEdge>,
}

/// SQLite-backed causal graph storage.
pub struct CausalGraphStore {
    db: Mutex<Connection>,
}

impl CausalGraphStore {
    /// Open a persistent store at the given path.
    pub fn open(path: &Path) -> anyhow::Result<Self> {
        let conn = Connection::open(path)?;
        let store = Self {
            db: Mutex::new(conn),
        };
        store.init_schema()?;
        Ok(store)
    }

    /// Open an in-memory store (for tests).
    pub fn open_memory() -> anyhow::Result<Self> {
        let conn = Connection::open_in_memory()?;
        let store = Self {
            db: Mutex::new(conn),
        };
        store.init_schema()?;
        Ok(store)
    }

    fn init_schema(&self) -> anyhow::Result<()> {
        let db = self.db.lock().unwrap();
        db.execute_batch(
            "CREATE TABLE IF NOT EXISTS causal_nodes (
                id TEXT PRIMARY KEY,
                node_type TEXT NOT NULL,
                flow_id TEXT,
                timestamp_ms INTEGER NOT NULL
            );
            CREATE TABLE IF NOT EXISTS causal_edges (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                source_id TEXT NOT NULL,
                target_id TEXT NOT NULL,
                edge_type TEXT NOT NULL,
                flow_id TEXT,
                timestamp_ms INTEGER NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_edges_source ON causal_edges(source_id);
            CREATE INDEX IF NOT EXISTS idx_edges_target ON causal_edges(target_id);
            CREATE INDEX IF NOT EXISTS idx_nodes_flow ON causal_nodes(flow_id);",
        )?;
        Ok(())
    }

    pub fn insert_node(&self, node: &CausalNode) -> anyhow::Result<()> {
        let db = self.db.lock().unwrap();
        let node_type_json = serde_json::to_string(&node.node_type)?;
        db.execute(
            "INSERT OR REPLACE INTO causal_nodes (id, node_type, flow_id, timestamp_ms)
             VALUES (?1, ?2, ?3, ?4)",
            rusqlite::params![node.id, node_type_json, node.flow_id, node.timestamp_ms],
        )?;
        Ok(())
    }

    pub fn insert_edge(&self, edge: &CausalEdge) -> anyhow::Result<i64> {
        let db = self.db.lock().unwrap();
        db.execute(
            "INSERT INTO causal_edges (source_id, target_id, edge_type, flow_id, timestamp_ms)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            rusqlite::params![
                edge.source_id,
                edge.target_id,
                edge.edge_type.as_str(),
                edge.flow_id,
                edge.timestamp_ms,
            ],
        )?;
        Ok(db.last_insert_rowid())
    }

    /// Trace all causes of a node (BFS backward through target→source).
    pub fn trace_causes(&self, node_id: &str, max_depth: u32) -> anyhow::Result<CausalSubgraph> {
        self.bfs_traverse(node_id, max_depth, Direction::Backward)
    }

    /// Trace all effects of a node (BFS forward through source→target).
    pub fn trace_effects(&self, node_id: &str, max_depth: u32) -> anyhow::Result<CausalSubgraph> {
        self.bfs_traverse(node_id, max_depth, Direction::Forward)
    }

    /// Find root causes: nodes with no incoming edges in the causal subgraph.
    pub fn root_causes(&self, node_id: &str) -> anyhow::Result<Vec<CausalNode>> {
        let subgraph = self.trace_causes(node_id, 100)?;
        let has_incoming: HashSet<&str> = subgraph
            .edges
            .iter()
            .map(|e| e.source_id.as_str())
            .collect();
        Ok(subgraph
            .nodes
            .into_iter()
            .filter(|n| !has_incoming.contains(n.id.as_str()))
            .collect())
    }

    /// Get all nodes and edges for a flow.
    pub fn flow_graph(&self, flow_id: &str) -> anyhow::Result<CausalSubgraph> {
        let db = self.db.lock().unwrap();
        let mut nodes = Vec::new();
        {
            let mut stmt = db.prepare(
                "SELECT id, node_type, flow_id, timestamp_ms FROM causal_nodes WHERE flow_id = ?1",
            )?;
            let rows = stmt.query_map([flow_id], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, Option<String>>(2)?,
                    row.get::<_, i64>(3)?,
                ))
            })?;
            for row in rows {
                let (id, node_type_json, fid, ts) = row?;
                let node_type: CausalNodeType = serde_json::from_str(&node_type_json)?;
                nodes.push(CausalNode {
                    id,
                    node_type,
                    flow_id: fid,
                    timestamp_ms: ts,
                });
            }
        }
        let mut edges = Vec::new();
        {
            let mut stmt = db.prepare(
                "SELECT source_id, target_id, edge_type, flow_id, timestamp_ms
                 FROM causal_edges WHERE flow_id = ?1",
            )?;
            let rows = stmt.query_map([flow_id], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, Option<String>>(3)?,
                    row.get::<_, i64>(4)?,
                ))
            })?;
            for row in rows {
                let (src, tgt, et, fid, ts) = row?;
                if let Some(edge_type) = CausalEdgeType::from_str(&et) {
                    edges.push(CausalEdge {
                        source_id: src,
                        target_id: tgt,
                        edge_type,
                        flow_id: fid,
                        timestamp_ms: ts,
                    });
                }
            }
        }
        Ok(CausalSubgraph { nodes, edges })
    }

    fn bfs_traverse(
        &self,
        start_id: &str,
        max_depth: u32,
        direction: Direction,
    ) -> anyhow::Result<CausalSubgraph> {
        let db = self.db.lock().unwrap();

        let mut visited: HashSet<String> = HashSet::new();
        let mut queue: VecDeque<(String, u32)> = VecDeque::new();
        let mut result_nodes = Vec::new();
        let mut result_edges = Vec::new();

        // Load start node if it exists
        if let Some(node) = Self::load_node(&db, start_id)? {
            result_nodes.push(node);
            visited.insert(start_id.to_string());
            queue.push_back((start_id.to_string(), 0));
        }

        let (edge_col, neighbor_col) = match direction {
            Direction::Backward => ("source_id", "target_id"),
            Direction::Forward => ("target_id", "source_id"),
        };

        while let Some((current_id, depth)) = queue.pop_front() {
            if depth >= max_depth {
                continue;
            }
            let query = format!(
                "SELECT source_id, target_id, edge_type, flow_id, timestamp_ms
                 FROM causal_edges WHERE {edge_col} = ?1"
            );
            let mut stmt = db.prepare(&query)?;
            let rows = stmt.query_map([&current_id], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, Option<String>>(3)?,
                    row.get::<_, i64>(4)?,
                ))
            })?;
            for row in rows {
                let (src, tgt, et, fid, ts) = row?;
                if let Some(edge_type) = CausalEdgeType::from_str(&et) {
                    result_edges.push(CausalEdge {
                        source_id: src.clone(),
                        target_id: tgt.clone(),
                        edge_type,
                        flow_id: fid,
                        timestamp_ms: ts,
                    });
                    let neighbor = match direction {
                        Direction::Backward => &tgt,
                        Direction::Forward => &src,
                    };
                    if !visited.contains(neighbor) {
                        visited.insert(neighbor.clone());
                        if let Some(node) = Self::load_node(&db, neighbor)? {
                            result_nodes.push(node);
                        }
                        queue.push_back((neighbor.clone(), depth + 1));
                    }
                }
            }
        }

        Ok(CausalSubgraph {
            nodes: result_nodes,
            edges: result_edges,
        })
    }

    fn load_node(db: &Connection, id: &str) -> anyhow::Result<Option<CausalNode>> {
        let mut stmt = db.prepare(
            "SELECT id, node_type, flow_id, timestamp_ms FROM causal_nodes WHERE id = ?1",
        )?;
        let mut rows = stmt.query_map([id], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, Option<String>>(2)?,
                row.get::<_, i64>(3)?,
            ))
        })?;
        if let Some(row) = rows.next() {
            let (id, node_type_json, flow_id, timestamp_ms) = row?;
            let node_type: CausalNodeType = serde_json::from_str(&node_type_json)?;
            Ok(Some(CausalNode {
                id,
                node_type,
                flow_id,
                timestamp_ms,
            }))
        } else {
            Ok(None)
        }
    }
}

enum Direction {
    Backward,
    Forward,
}
```

- [ ] **Step 5: Run tests**

Run: `ORT_LIB_PATH=/usr/lib64 ORT_PREFER_DYNAMIC_LINK=1 cargo test -p navra-flow causal_graph -- --nocapture 2>&1 | tail -15`

Expected: All 7 tests pass.

- [ ] **Step 6: Commit**

```bash
git add navra-flow/src/causal_graph.rs navra-flow/src/lib.rs
git commit -s -m "feat(flow): add CausalGraphStore with W3C PROV-DM types and BFS queries"
```

---

### Task 2: CausalSink trait and ProvenanceHook

**Files:**
- Create: `navra-security/src/hooks/provenance_hook.rs`
- Modify: `navra-security/src/hooks/mod.rs`

- [ ] **Step 1: Write failing test for ProvenanceHook**

Create `navra-security/src/hooks/provenance_hook.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::{AgentIdentity, CallContext};
    use navra_protocol::CallToolResult;
    use std::sync::Mutex;

    struct TestSink {
        tool_calls: Mutex<Vec<(String, String, String, String)>>,
        tool_results: Mutex<Vec<(String, String)>>,
    }

    impl TestSink {
        fn new() -> Self {
            Self {
                tool_calls: Mutex::new(Vec::new()),
                tool_results: Mutex::new(Vec::new()),
            }
        }
    }

    impl CausalSink for TestSink {
        fn record_tool_call(
            &self,
            node_id: &str,
            tool_name: &str,
            agent_id: &str,
            session_id: &str,
            _input_node_ids: &[String],
        ) {
            self.tool_calls.lock().unwrap().push((
                node_id.to_string(),
                tool_name.to_string(),
                agent_id.to_string(),
                session_id.to_string(),
            ));
        }

        fn record_tool_result(&self, result_node_id: &str, tool_call_node_id: &str) {
            self.tool_results
                .lock()
                .unwrap()
                .push((result_node_id.to_string(), tool_call_node_id.to_string()));
        }
    }

    fn test_ctx() -> CallContext {
        CallContext::new(AgentIdentity::new("agent-a", "dev"), "session-1")
    }

    #[tokio::test]
    async fn hook_records_tool_call_on_post() {
        let sink = Arc::new(TestSink::new());
        let hook = ProvenanceHook::new(Arc::clone(&sink) as Arc<dyn CausalSink>);
        let result = CallToolResult::text("file contents here");
        let ctx = test_ctx();

        hook.post_tool_use("file_read", &serde_json::json!({"path": "/etc/hosts"}), &result, &ctx)
            .await;

        let calls = sink.tool_calls.lock().unwrap();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].1, "file_read");
        assert_eq!(calls[0].2, "agent-a");
        assert_eq!(calls[0].3, "session-1");

        let results = sink.tool_results.lock().unwrap();
        assert_eq!(results.len(), 1);
    }

    #[tokio::test]
    async fn hook_always_returns_continue() {
        let sink = Arc::new(TestSink::new());
        let hook = ProvenanceHook::new(Arc::clone(&sink) as Arc<dyn CausalSink>);
        let result = CallToolResult::text("ok");
        let ctx = test_ctx();

        let decision = hook
            .post_tool_use("file_read", &serde_json::json!({}), &result, &ctx)
            .await;
        assert!(matches!(decision, HookDecision::Continue));
    }

    #[tokio::test]
    async fn hook_records_errors_too() {
        let sink = Arc::new(TestSink::new());
        let hook = ProvenanceHook::new(Arc::clone(&sink) as Arc<dyn CausalSink>);
        let result = CallToolResult::error("permission denied");
        let ctx = test_ctx();

        hook.post_tool_use("file_write", &serde_json::json!({}), &result, &ctx)
            .await;

        let calls = sink.tool_calls.lock().unwrap();
        assert_eq!(calls.len(), 1);
    }
}
```

- [ ] **Step 2: Register module in mod.rs**

Add to `navra-security/src/hooks/mod.rs` after `pub mod temporal_contract;`:

```rust
pub mod provenance_hook;
```

Add to the `pub use` block:

```rust
pub use provenance_hook::{CausalSink, ProvenanceHook};
```

- [ ] **Step 3: Run test to verify compile failure**

Run: `ORT_LIB_PATH=/usr/lib64 ORT_PREFER_DYNAMIC_LINK=1 cargo test -p navra-security provenance_hook -- --nocapture 2>&1 | tail -5`

Expected: Compile error.

- [ ] **Step 4: Implement CausalSink and ProvenanceHook**

Write the implementation at the top of `provenance_hook.rs`:

```rust
//! Causal provenance hook: records causal relationships between tool calls.
//!
//! An observation-only post-hook that creates causal graph nodes for each
//! tool call and its result. Never modifies results.

use super::{Hook, HookDecision};
use crate::auth::CallContext;
use navra_protocol::CallToolResult;
use std::sync::Arc;

/// Trait for causal graph storage, decoupling navra-security from navra-flow.
///
/// Same decoupling pattern as `ExtractionStore` in `memory_extraction.rs`.
/// The concrete implementation (`CausalGraphStore`) lives in navra-flow;
/// the server wires it at startup.
pub trait CausalSink: Send + Sync + 'static {
    fn record_tool_call(
        &self,
        node_id: &str,
        tool_name: &str,
        agent_id: &str,
        session_id: &str,
        input_node_ids: &[String],
    );

    fn record_tool_result(&self, result_node_id: &str, tool_call_node_id: &str);
}

/// Post-hook that records causal provenance for every tool call.
pub struct ProvenanceHook {
    sink: Arc<dyn CausalSink>,
}

impl ProvenanceHook {
    pub fn new(sink: Arc<dyn CausalSink>) -> Self {
        Self { sink }
    }
}

#[async_trait::async_trait]
impl Hook for ProvenanceHook {
    fn name(&self) -> &str {
        "causal-provenance"
    }

    async fn post_tool_use(
        &self,
        tool_name: &str,
        _arguments: &serde_json::Value,
        _result: &CallToolResult,
        ctx: &CallContext,
    ) -> HookDecision {
        let call_node_id = uuid::Uuid::new_v4().to_string();
        let result_node_id = uuid::Uuid::new_v4().to_string();

        self.sink.record_tool_call(
            &call_node_id,
            tool_name,
            &ctx.agent.name,
            &ctx.session_id,
            &[],
        );

        self.sink.record_tool_result(&result_node_id, &call_node_id);

        HookDecision::Continue
    }
}
```

- [ ] **Step 5: Run tests**

Run: `ORT_LIB_PATH=/usr/lib64 ORT_PREFER_DYNAMIC_LINK=1 cargo test -p navra-security provenance_hook -- --nocapture 2>&1 | tail -10`

Expected: 3 tests pass.

- [ ] **Step 6: Commit**

```bash
git add navra-security/src/hooks/provenance_hook.rs navra-security/src/hooks/mod.rs
git commit -s -m "feat(security): add CausalSink trait and ProvenanceHook"
```

---

### Task 3: CausalGraphStore implements CausalSink

**Files:**
- Modify: `navra-flow/src/causal_graph.rs`

- [ ] **Step 1: Write test for CausalSink implementation**

Add to `causal_graph.rs` tests:

```rust
    #[test]
    fn causal_sink_records_tool_call_and_result() {
        let store = CausalGraphStore::open_memory().unwrap();
        store.record_tool_call("tc-1", "file_read", "agent-a", "sess-1", &[]);
        store.record_tool_result("tr-1", "tc-1");

        let graph = store.trace_effects("tc-1", 10).unwrap();
        assert_eq!(graph.nodes.len(), 2);
        assert_eq!(graph.edges.len(), 1);
        assert_eq!(graph.edges[0].edge_type, CausalEdgeType::WasGeneratedBy);
    }
```

- [ ] **Step 2: Run test — compile failure**

Run: `ORT_LIB_PATH=/usr/lib64 ORT_PREFER_DYNAMIC_LINK=1 cargo test -p navra-flow causal_sink_records -- --nocapture 2>&1 | tail -5`

Expected: `record_tool_call` method not found.

- [ ] **Step 3: Add CausalSink import and implementation**

Add to `causal_graph.rs` after the `impl CausalGraphStore` block:

```rust
impl navra_security::hooks::CausalSink for CausalGraphStore {
    fn record_tool_call(
        &self,
        node_id: &str,
        tool_name: &str,
        agent_id: &str,
        session_id: &str,
        _input_node_ids: &[String],
    ) {
        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as i64;

        let node = CausalNode {
            id: node_id.to_string(),
            node_type: CausalNodeType::ToolCall {
                tool_name: tool_name.to_string(),
                agent_id: agent_id.to_string(),
                session_id: session_id.to_string(),
            },
            flow_id: None,
            timestamp_ms: now_ms,
        };
        if let Err(e) = self.insert_node(&node) {
            tracing::warn!(error = %e, "Failed to record causal tool-call node");
        }
    }

    fn record_tool_result(&self, result_node_id: &str, tool_call_node_id: &str) {
        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as i64;

        let node = CausalNode {
            id: result_node_id.to_string(),
            node_type: CausalNodeType::AgentAction {
                agent_id: String::new(),
                action_type: "tool_result".to_string(),
            },
            flow_id: None,
            timestamp_ms: now_ms,
        };
        if let Err(e) = self.insert_node(&node) {
            tracing::warn!(error = %e, "Failed to record causal result node");
        }

        let edge = CausalEdge {
            source_id: result_node_id.to_string(),
            target_id: tool_call_node_id.to_string(),
            edge_type: CausalEdgeType::WasGeneratedBy,
            flow_id: None,
            timestamp_ms: now_ms,
        };
        if let Err(e) = self.insert_edge(&edge) {
            tracing::warn!(error = %e, "Failed to record causal edge");
        }
    }
}
```

- [ ] **Step 4: Run tests**

Run: `ORT_LIB_PATH=/usr/lib64 ORT_PREFER_DYNAMIC_LINK=1 cargo test -p navra-flow causal_graph -- --nocapture 2>&1 | tail -15`

Expected: All 8 tests pass.

- [ ] **Step 5: Commit**

```bash
git add navra-flow/src/causal_graph.rs
git commit -s -m "feat(flow): implement CausalSink for CausalGraphStore"
```

---

### Task 4: Add causal_node_id to BlackboardEntry and MailboxMessage

**Files:**
- Modify: `navra-flow/src/blackboard.rs` (line 18-28)
- Modify: `navra-flow/src/mailbox.rs` (line 16-25)

- [ ] **Step 1: Add field to BlackboardEntry**

In `navra-flow/src/blackboard.rs`, add after the `provenance` field:

```rust
    /// Optional causal graph node ID linking this entry to the provenance graph.
    pub causal_node_id: Option<String>,
```

Fix all construction sites — search for `BlackboardEntry {` in the file and add `causal_node_id: None,` to each.

- [ ] **Step 2: Add field to MailboxMessage**

In `navra-flow/src/mailbox.rs`, add after the `provenance` field:

```rust
    /// Optional causal graph node ID linking this message to the provenance graph.
    pub causal_node_id: Option<String>,
```

Fix all construction sites — search for `MailboxMessage {` in the file and add `causal_node_id: None,` to each.

- [ ] **Step 3: Build and fix any remaining compile errors**

Run: `ORT_LIB_PATH=/usr/lib64 ORT_PREFER_DYNAMIC_LINK=1 cargo build -p navra-flow 2>&1 | tail -20`

Fix any remaining struct literal errors in tests or other files that construct these types.

- [ ] **Step 4: Run all flow tests**

Run: `ORT_LIB_PATH=/usr/lib64 ORT_PREFER_DYNAMIC_LINK=1 cargo test -p navra-flow 2>&1 | tail -10`

Expected: All existing tests pass.

- [ ] **Step 5: Commit**

```bash
git add navra-flow/src/blackboard.rs navra-flow/src/mailbox.rs
git commit -s -m "feat(flow): add causal_node_id to BlackboardEntry and MailboxMessage"
```

---

### Task 5: Wire ProvenanceHook in server + final verification

**Files:**
- Modify: `navra-server/src/main.rs`

- [ ] **Step 1: Wire the hook after existing hooks**

After the memory extraction hook wiring in main.rs, add:

```rust
    // Causal provenance hook (observation-only, records tool call causality)
    {
        let causal_db_path = data_dir.join("causal_provenance.db");
        match navra_flow::causal_graph::CausalGraphStore::open(&causal_db_path) {
            Ok(store) => {
                let store = std::sync::Arc::new(store);
                tracing::info!(
                    path = %causal_db_path.display(),
                    "Causal provenance graph enabled"
                );
                builder = builder.hook(navra_core::hooks::ProvenanceHook::new(
                    store as std::sync::Arc<dyn navra_core::hooks::CausalSink>,
                ));
            }
            Err(e) => {
                tracing::warn!(
                    error = %e,
                    "Failed to open causal provenance DB — provenance tracking disabled"
                );
            }
        }
    }
```

- [ ] **Step 2: Build full workspace**

Run: `ORT_LIB_PATH=/usr/lib64 ORT_PREFER_DYNAMIC_LINK=1 cargo build --workspace 2>&1 | tail -5`

Expected: Build succeeds.

- [ ] **Step 3: Run full test suite**

Run: `ORT_LIB_PATH=/usr/lib64 ORT_PREFER_DYNAMIC_LINK=1 cargo test --workspace 2>&1 | tail -20`

Expected: All tests pass.

- [ ] **Step 4: Run clippy**

Run: `ORT_LIB_PATH=/usr/lib64 ORT_PREFER_DYNAMIC_LINK=1 cargo clippy --workspace 2>&1 | tail -10`

Expected: 0 warnings.

- [ ] **Step 5: Commit**

```bash
git add navra-server/src/main.rs
git commit -s -m "feat(server): wire CausalGraphStore and ProvenanceHook"
```
