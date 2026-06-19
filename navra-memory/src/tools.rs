//! Knowledge pipeline MCP tools (NAVRA-145).
//!
//! Exposes navra-memory and navra-rag capabilities as MCP tools:
//! - `knowledge_search` — hybrid FTS5+vector search with RRF fusion
//! - `entity_graph_query` — 1-2 hop entity relationship traversal
//! - `decay_score` — batch effective score computation for entries
//! - `distill` — extract structured knowledge from raw text

use crate::decay::effective_score;
use crate::entity_graph::EntityGraph;
use crate::knowledge::KnowledgeStore;
use crate::retrieval::MemoryRetriever;
use navra_macros::tool;
use navra_mcp::auth::CallContext;
use navra_mcp::models::ModelBackend;
use navra_mcp::protocol::CallToolResult;
use navra_mcp::Module;
use rusqlite::params;
use std::sync::{Arc, Mutex};

pub struct KnowledgeModule {
    state: Arc<KnowledgeState>,
}

struct KnowledgeState {
    knowledge: Arc<KnowledgeStore>,
    graph: Arc<Mutex<EntityGraph>>,
    #[cfg(feature = "rag")]
    chunk_store: Option<Arc<navra_rag::ChunkStore>>,
    #[cfg(feature = "rag")]
    embedding_model: Option<Arc<dyn ModelBackend>>,
    distill_model: Option<Arc<dyn ModelBackend>>,
    classifier_model: Option<Arc<dyn ModelBackend>>,
}

impl KnowledgeModule {
    pub fn new(knowledge: Arc<KnowledgeStore>, graph: Arc<Mutex<EntityGraph>>) -> Self {
        Self {
            state: Arc::new(KnowledgeState {
                knowledge,
                graph,
                #[cfg(feature = "rag")]
                chunk_store: None,
                #[cfg(feature = "rag")]
                embedding_model: None,
                distill_model: None,
                classifier_model: None,
            }),
        }
    }

    #[cfg(feature = "rag")]
    pub fn with_vector_search(
        mut self,
        chunk_store: Arc<navra_rag::ChunkStore>,
        embedding_model: Arc<dyn ModelBackend>,
    ) -> Self {
        let state = Arc::get_mut(&mut self.state).unwrap();
        state.chunk_store = Some(chunk_store);
        state.embedding_model = Some(embedding_model);
        self
    }

    pub fn with_distill_model(mut self, model: Arc<dyn ModelBackend>) -> Self {
        Arc::get_mut(&mut self.state).unwrap().distill_model = Some(model);
        self
    }

    pub fn with_classifier(mut self, model: Arc<dyn ModelBackend>) -> Self {
        Arc::get_mut(&mut self.state).unwrap().classifier_model = Some(model);
        self
    }
}

impl Module for KnowledgeModule {
    fn name(&self) -> &str {
        "knowledge"
    }

    fn tools(
        &self,
    ) -> Vec<(
        navra_mcp::protocol::ToolDefinition,
        navra_mcp::ToolHandler,
    )> {
        let s = self.state.clone();
        vec![
            handle_search_handler(s.clone()),
            handle_graph_query_handler(s.clone()),
            handle_decay_score_handler(s.clone()),
            handle_distill_handler(s),
        ]
    }
}

#[tool(
    name = "knowledge_search",
    description = "Search the knowledge store using hybrid FTS5 full-text search with optional vector similarity and RRF fusion. Returns ranked results with scores."
)]
async fn handle_search(
    #[arg(description = "Natural language search query")] query: String,
    #[arg(description = "Max results (default 10)", default = "10")] limit: Option<u64>,
    _ctx: CallContext,
    #[state] state: Arc<KnowledgeState>,
) -> CallToolResult {
    if query.is_empty() {
        return CallToolResult::error("Missing required parameter: query");
    }

    let limit = limit.unwrap_or(10) as usize;

    // Try hybrid search with vector channel if available
    #[cfg(feature = "rag")]
    if let (Some(ref chunk_store), Some(ref embed_model)) =
        (&state.chunk_store, &state.embedding_model)
    {
        let embed_req = navra_mcp::models::EmbedRequest {
            text: query.clone(),
        };
        match embed_model.embed(&embed_req).await {
            Ok(response) => {
                let retriever = MemoryRetriever::new(&state.knowledge)
                    .with_chunk_store(chunk_store.clone());
                match retriever.retrieve_with_embedding(&query, &response.embedding, limit) {
                    Ok(results) => return format_search_results(&results),
                    Err(e) => {
                        tracing::warn!("Hybrid search failed, falling back to FTS: {e}");
                    }
                }
            }
            Err(e) => {
                tracing::warn!("Embedding failed, falling back to FTS: {e}");
            }
        }
    }

    // FTS-only fallback
    let retriever = MemoryRetriever::new(&state.knowledge);
    match retriever.retrieve(&query, limit) {
        Ok(results) => format_search_results(&results),
        Err(e) => CallToolResult::error(format!("Search failed: {e}")),
    }
}

fn format_search_results(results: &[crate::retrieval::ScoredEntry]) -> CallToolResult {
    if results.is_empty() {
        return CallToolResult::text("No results found.");
    }

    let entries: Vec<serde_json::Value> = results
        .iter()
        .map(|r| {
            serde_json::json!({
                "id": r.entry.id,
                "type": r.entry.memory_type.as_str(),
                "title": r.entry.title,
                "content": r.entry.content,
                "tags": r.entry.tags,
                "score": r.score,
            })
        })
        .collect();

    CallToolResult::text(serde_json::to_string_pretty(&entries).unwrap_or_default())
}

#[tool(
    name = "entity_graph_query",
    description = "Traverse the entity-relationship graph. Returns entities and relationships within 1-2 hops of the queried entity, with relation types and confidence scores."
)]
async fn handle_graph_query(
    #[arg(description = "Entity name to query relationships for")] entity: String,
    #[arg(
        description = "Number of hops to traverse (1 or 2, default 1)",
        default = "1"
    )]
    hops: Option<u64>,
    _ctx: CallContext,
    #[state] state: Arc<KnowledgeState>,
) -> CallToolResult {
    if entity.is_empty() {
        return CallToolResult::error("Missing required parameter: entity");
    }

    let hops = hops.unwrap_or(1).min(2);

    // 1-hop: direct relationships
    let graph = match state.graph.lock() {
        Ok(g) => g,
        Err(e) => return CallToolResult::error(format!("Graph lock failed: {e}")),
    };
    let direct = match graph.relations_of(&entity) {
        Ok(rels) => rels,
        Err(e) => return CallToolResult::error(format!("Graph query failed: {e}")),
    };

    let mut result = serde_json::json!({
        "entity": entity,
        "hops": hops,
        "direct_relationships": direct.iter().map(|r| {
            serde_json::json!({
                "id": r.id,
                "entity1": r.entity1,
                "relation": r.relation,
                "entity2": r.entity2,
                "confidence": r.confidence,
                "valid_from": r.valid_from,
                "valid_until": r.valid_until,
                "source": r.source,
            })
        }).collect::<Vec<_>>(),
    });

    // 2-hop: transitive relationships
    if hops >= 2 {
        match graph.traverse_2hop(&entity) {
            Ok(paths) => {
                let two_hop: Vec<serde_json::Value> = paths
                    .iter()
                    .map(|(r1, mid, r2, target)| {
                        serde_json::json!({
                            "hop1_relation": r1,
                            "intermediate": mid,
                            "hop2_relation": r2,
                            "target": target,
                        })
                    })
                    .collect();
                result["two_hop_paths"] = serde_json::json!(two_hop);
            }
            Err(e) => {
                result["two_hop_error"] = serde_json::json!(format!("{e}"));
            }
        }
    }

    CallToolResult::text(serde_json::to_string_pretty(&result).unwrap_or_default())
}

#[tool(
    name = "decay_score",
    description = "Compute effective memory scores for knowledge entries using exponential decay with importance modulation. Returns current scores indicating how 'alive' each memory is."
)]
async fn handle_decay_score(
    #[arg(
        description = "Comma-separated entry IDs to score, or 'all' for all entries (max 100)"
    )]
    entry_ids: String,
    _ctx: CallContext,
    #[state] state: Arc<KnowledgeState>,
) -> CallToolResult {
    if entry_ids.is_empty() {
        return CallToolResult::error("Missing required parameter: entry_ids");
    }

    let base_decay_rate = 0.001;
    let now_secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64;

    let db = state.knowledge.db();

    let results: Vec<serde_json::Value> = if entry_ids.trim() == "all" {
        let mut stmt = match db.prepare(
            "SELECT id, title, importance, created_at, access_count FROM memory_knowledge LIMIT 100",
        ) {
            Ok(s) => s,
            Err(e) => return CallToolResult::error(format!("Query failed: {e}")),
        };
        let collected: Result<Vec<_>, _> = stmt
            .query_map([], |row| {
                let id: String = row.get(0)?;
                let title: String = row.get(1)?;
                let importance: f64 = row.get(2)?;
                let created_at: i64 = row.get(3)?;
                let access_count: i64 = row.get(4)?;
                let age_hours = (now_secs - created_at).max(0) as f64 / 3600.0;
                let score =
                    effective_score(importance, age_hours, access_count as u32, base_decay_rate);
                Ok(serde_json::json!({
                    "id": id,
                    "title": title,
                    "importance": importance,
                    "age_hours": age_hours,
                    "access_count": access_count,
                    "effective_score": score,
                }))
            })
            .map(|rows| rows.filter_map(|r| r.ok()).collect());
        match collected {
            Ok(v) => v,
            Err(e) => return CallToolResult::error(format!("Query failed: {e}")),
        }
    } else {
        let ids: Vec<&str> = entry_ids.split(',').map(|s| s.trim()).collect();
        let mut scored = Vec::new();
        for id in ids {
            let row = db.query_row(
                "SELECT title, importance, created_at, access_count FROM memory_knowledge WHERE id = ?1",
                params![id],
                |row| {
                    let title: String = row.get(0)?;
                    let importance: f64 = row.get(1)?;
                    let created_at: i64 = row.get(2)?;
                    let access_count: i64 = row.get(3)?;
                    Ok((title, importance, created_at, access_count))
                },
            );
            match row {
                Ok((title, importance, created_at, access_count)) => {
                    let age_hours = (now_secs - created_at).max(0) as f64 / 3600.0;
                    let score = effective_score(
                        importance,
                        age_hours,
                        access_count as u32,
                        base_decay_rate,
                    );
                    scored.push(serde_json::json!({
                        "id": id,
                        "title": title,
                        "importance": importance,
                        "age_hours": age_hours,
                        "access_count": access_count,
                        "effective_score": score,
                    }));
                }
                Err(_) => {
                    scored.push(serde_json::json!({
                        "id": id,
                        "error": "not found",
                    }));
                }
            }
        }
        scored
    };

    CallToolResult::text(serde_json::to_string_pretty(&results).unwrap_or_default())
}

#[tool(
    name = "distill",
    description = "Extract structured knowledge entries from raw text. Classifies content as Fact, Event, Instruction, Insight, User, or Project with confidence scores and tags. Set memory_type to 'auto' to use the ONNX classifier."
)]
async fn handle_distill(
    #[arg(description = "Raw text to distill into knowledge entries")] text: String,
    #[arg(description = "Source identifier (e.g. session ID, URL, filename)")]
    source: Option<String>,
    #[arg(
        description = "Memory type: 'auto' to classify with ONNX model, or explicit type (fact, event, instruction, insight, user, project)"
    )]
    memory_type: Option<String>,
    _ctx: CallContext,
    #[state] state: Arc<KnowledgeState>,
) -> CallToolResult {
    if text.is_empty() {
        return CallToolResult::error("Missing required parameter: text");
    }

    let source = source.unwrap_or_default();

    // If memory_type=auto, use the classifier if available
    if memory_type.as_deref() == Some("auto") {
        if let Some(ref classifier) = state.classifier_model {
            let entries: Vec<serde_json::Value> = {
                let mut results = Vec::new();
                for paragraph in text.split("\n\n").filter(|p| !p.trim().is_empty()).take(20) {
                    let trimmed = paragraph.trim();
                    let request = navra_mcp::models::ClassifyRequest {
                        text: trimmed.to_string(),
                    };
                    let (kind, confidence) = match classifier.classify(&request).await {
                        Ok(response) => {
                            if let Some(top) = response.top_label() {
                                (top.label.clone(), top.score)
                            } else {
                                ("fact".to_string(), 0.5)
                            }
                        }
                        Err(_) => ("fact".to_string(), 0.5),
                    };
                    let title = if trimmed.len() > 80 {
                        format!("{}...", &trimmed[..77])
                    } else {
                        trimmed.to_string()
                    };
                    results.push(serde_json::json!({
                        "kind": kind,
                        "title": title,
                        "content": trimmed,
                        "tags": [],
                        "confidence": confidence,
                    }));
                }
                results
            };

            let result = serde_json::json!({
                "method": "classifier",
                "source": source,
                "entries": entries,
            });
            return CallToolResult::text(
                serde_json::to_string_pretty(&result).unwrap_or_default(),
            );
        }
    }

    // Try LLM-based extraction if a model is available
    if let Some(ref model) = state.distill_model {
        let prompt = crate::pipeline::SYNTHESIZE_PROMPT;
        let request = navra_mcp::models::GenerateRequest {
            prompt: text.clone(),
            max_tokens: Some(2048),
            temperature: Some(0.1),
            system: Some(prompt.to_string()),
            images: vec![],
        };

        match model.generate(&request).await {
            Ok(response) => {
                match serde_json::from_str::<Vec<serde_json::Value>>(&response.text) {
                    Ok(entries) => {
                        let result = serde_json::json!({
                            "method": "llm",
                            "source": source,
                            "entries": entries,
                        });
                        return CallToolResult::text(
                            serde_json::to_string_pretty(&result).unwrap_or_default(),
                        );
                    }
                    Err(e) => {
                        tracing::warn!("Model returned unparseable JSON, falling back to stub: {e}");
                    }
                }
            }
            Err(e) => {
                tracing::warn!("Model distillation failed, falling back to stub: {e}");
            }
        }
    }

    // Stub extraction: split text into paragraphs, each becomes a Fact
    let entries: Vec<serde_json::Value> = text
        .split("\n\n")
        .filter(|p| !p.trim().is_empty())
        .take(20)
        .map(|paragraph| {
            let trimmed = paragraph.trim();
            let title = if trimmed.len() > 80 {
                format!("{}...", &trimmed[..77])
            } else {
                trimmed.to_string()
            };
            serde_json::json!({
                "kind": "Fact",
                "title": title,
                "content": trimmed,
                "tags": [],
                "confidence": 0.5,
            })
        })
        .collect();

    let result = serde_json::json!({
        "method": "stub",
        "source": source,
        "entries": entries,
    });
    CallToolResult::text(serde_json::to_string_pretty(&result).unwrap_or_default())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{MemoryEntry, MemoryType};
    use navra_mcp::auth::AgentIdentity;

    fn test_ctx() -> CallContext {
        CallContext::new(AgentIdentity::new("test", "dev"), "test-session")
    }

    fn test_knowledge() -> Arc<KnowledgeStore> {
        let store = KnowledgeStore::open_memory().unwrap();
        let entry = MemoryEntry {
            id: "e1".to_string(),
            memory_type: MemoryType::Fact,
            title: "Rust memory safety".to_string(),
            content: "Rust provides memory safety without garbage collection".to_string(),
            tags: vec!["rust".to_string(), "safety".to_string()],
            created_at: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs() as i64,
            updated_at: None,
        };
        store.store(&entry).unwrap();
        store
            .db()
            .execute(
                "UPDATE memory_knowledge SET importance = 0.9 WHERE id = 'e1'",
                [],
            )
            .unwrap();

        let entry2 = MemoryEntry {
            id: "e2".to_string(),
            memory_type: MemoryType::Insight,
            title: "User prefers Rust".to_string(),
            content: "The user consistently chooses Rust for new projects".to_string(),
            tags: vec!["preference".to_string()],
            created_at: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs() as i64,
            updated_at: None,
        };
        store.store(&entry2).unwrap();
        Arc::new(store)
    }

    fn test_graph() -> Arc<Mutex<EntityGraph>> {
        let graph = EntityGraph::open_memory().unwrap();
        graph
            .add("Alice", "works_at", "Acme", None, None, 0.95, Some("session-1"))
            .unwrap();
        graph
            .add("Acme", "located_in", "Paris", None, None, 0.9, None)
            .unwrap();
        graph
            .add("Alice", "knows", "Bob", None, None, 0.8, None)
            .unwrap();
        Arc::new(Mutex::new(graph))
    }

    #[test]
    fn module_provides_four_tools() {
        let knowledge = Arc::new(KnowledgeStore::open_memory().unwrap());
        let graph = Arc::new(Mutex::new(EntityGraph::open_memory().unwrap()));
        let module = KnowledgeModule::new(knowledge, graph);

        assert_eq!(module.name(), "knowledge");
        let tools = module.tools();
        let names: Vec<_> = tools.iter().map(|(def, _)| def.name.as_str()).collect();
        assert!(names.contains(&"knowledge_search"));
        assert!(names.contains(&"entity_graph_query"));
        assert!(names.contains(&"decay_score"));
        assert!(names.contains(&"distill"));
        assert_eq!(tools.len(), 4);
    }

    #[tokio::test]
    async fn search_returns_results() {
        let knowledge = test_knowledge();
        let graph = Arc::new(Mutex::new(EntityGraph::open_memory().unwrap()));
        let state = Arc::new(KnowledgeState {
            knowledge,
            graph,
            #[cfg(feature = "rag")]
            chunk_store: None,
            #[cfg(feature = "rag")]
            embedding_model: None,
            distill_model: None,
            classifier_model: None,
        });

        let (_, handler) = handle_search_handler(state);
        let result = handler(
            serde_json::json!({"query": "Rust safety"}),
            test_ctx(),
        )
        .await;

        assert!(!result.is_error, "search should succeed");
        match &result.content[0] {
            navra_mcp::protocol::Content::Text(t) => {
                assert!(t.text.contains("Rust"), "should find Rust entry");
            }
            _ => panic!("expected text content"),
        }
    }

    #[tokio::test]
    async fn search_empty_query_errors() {
        let knowledge = Arc::new(KnowledgeStore::open_memory().unwrap());
        let graph = Arc::new(Mutex::new(EntityGraph::open_memory().unwrap()));
        let state = Arc::new(KnowledgeState {
            knowledge,
            graph,
            #[cfg(feature = "rag")]
            chunk_store: None,
            #[cfg(feature = "rag")]
            embedding_model: None,
            distill_model: None,
            classifier_model: None,
        });

        let (_, handler) = handle_search_handler(state);
        let result = handler(serde_json::json!({"query": ""}), test_ctx()).await;
        assert!(result.is_error);
    }

    #[tokio::test]
    async fn search_no_results() {
        let knowledge = Arc::new(KnowledgeStore::open_memory().unwrap());
        let graph = Arc::new(Mutex::new(EntityGraph::open_memory().unwrap()));
        let state = Arc::new(KnowledgeState {
            knowledge,
            graph,
            #[cfg(feature = "rag")]
            chunk_store: None,
            #[cfg(feature = "rag")]
            embedding_model: None,
            distill_model: None,
            classifier_model: None,
        });

        let (_, handler) = handle_search_handler(state);
        let result = handler(
            serde_json::json!({"query": "xyznonexistent"}),
            test_ctx(),
        )
        .await;
        assert!(!result.is_error);
        match &result.content[0] {
            navra_mcp::protocol::Content::Text(t) => {
                assert!(t.text.contains("No results"));
            }
            _ => panic!("expected text content"),
        }
    }

    #[tokio::test]
    async fn graph_query_1hop() {
        let knowledge = Arc::new(KnowledgeStore::open_memory().unwrap());
        let graph = test_graph();
        let state = Arc::new(KnowledgeState {
            knowledge,
            graph,
            #[cfg(feature = "rag")]
            chunk_store: None,
            #[cfg(feature = "rag")]
            embedding_model: None,
            distill_model: None,
            classifier_model: None,
        });

        let (_, handler) = handle_graph_query_handler(state);
        let result = handler(
            serde_json::json!({"entity": "Alice"}),
            test_ctx(),
        )
        .await;

        assert!(!result.is_error);
        match &result.content[0] {
            navra_mcp::protocol::Content::Text(t) => {
                let parsed: serde_json::Value = serde_json::from_str(&t.text).unwrap();
                let rels = parsed["direct_relationships"].as_array().unwrap();
                assert_eq!(rels.len(), 2);
                assert!(parsed.get("two_hop_paths").is_none());
            }
            _ => panic!("expected text content"),
        }
    }

    #[tokio::test]
    async fn graph_query_2hop() {
        let knowledge = Arc::new(KnowledgeStore::open_memory().unwrap());
        let graph = test_graph();
        let state = Arc::new(KnowledgeState {
            knowledge,
            graph,
            #[cfg(feature = "rag")]
            chunk_store: None,
            #[cfg(feature = "rag")]
            embedding_model: None,
            distill_model: None,
            classifier_model: None,
        });

        let (_, handler) = handle_graph_query_handler(state);
        let result = handler(
            serde_json::json!({"entity": "Alice", "hops": 2}),
            test_ctx(),
        )
        .await;

        assert!(!result.is_error);
        match &result.content[0] {
            navra_mcp::protocol::Content::Text(t) => {
                let parsed: serde_json::Value = serde_json::from_str(&t.text).unwrap();
                let paths = parsed["two_hop_paths"].as_array().unwrap();
                assert!(!paths.is_empty());
                assert!(t.text.contains("Paris"));
            }
            _ => panic!("expected text content"),
        }
    }

    #[tokio::test]
    async fn graph_query_empty_entity_errors() {
        let knowledge = Arc::new(KnowledgeStore::open_memory().unwrap());
        let graph = Arc::new(Mutex::new(EntityGraph::open_memory().unwrap()));
        let state = Arc::new(KnowledgeState {
            knowledge,
            graph,
            #[cfg(feature = "rag")]
            chunk_store: None,
            #[cfg(feature = "rag")]
            embedding_model: None,
            distill_model: None,
            classifier_model: None,
        });

        let (_, handler) = handle_graph_query_handler(state);
        let result = handler(serde_json::json!({"entity": ""}), test_ctx()).await;
        assert!(result.is_error);
    }

    #[tokio::test]
    async fn decay_score_specific_ids() {
        let knowledge = test_knowledge();
        let graph = Arc::new(Mutex::new(EntityGraph::open_memory().unwrap()));
        let state = Arc::new(KnowledgeState {
            knowledge,
            graph,
            #[cfg(feature = "rag")]
            chunk_store: None,
            #[cfg(feature = "rag")]
            embedding_model: None,
            distill_model: None,
            classifier_model: None,
        });

        let (_, handler) = handle_decay_score_handler(state);
        let result = handler(
            serde_json::json!({"entry_ids": "e1, e2"}),
            test_ctx(),
        )
        .await;

        assert!(!result.is_error);
        match &result.content[0] {
            navra_mcp::protocol::Content::Text(t) => {
                let parsed: Vec<serde_json::Value> = serde_json::from_str(&t.text).unwrap();
                assert_eq!(parsed.len(), 2);
                assert!(parsed[0]["effective_score"].as_f64().unwrap() > 0.0);
            }
            _ => panic!("expected text content"),
        }
    }

    #[tokio::test]
    async fn decay_score_all() {
        let knowledge = test_knowledge();
        let graph = Arc::new(Mutex::new(EntityGraph::open_memory().unwrap()));
        let state = Arc::new(KnowledgeState {
            knowledge,
            graph,
            #[cfg(feature = "rag")]
            chunk_store: None,
            #[cfg(feature = "rag")]
            embedding_model: None,
            distill_model: None,
            classifier_model: None,
        });

        let (_, handler) = handle_decay_score_handler(state);
        let result = handler(
            serde_json::json!({"entry_ids": "all"}),
            test_ctx(),
        )
        .await;

        assert!(!result.is_error);
        match &result.content[0] {
            navra_mcp::protocol::Content::Text(t) => {
                let parsed: Vec<serde_json::Value> = serde_json::from_str(&t.text).unwrap();
                assert_eq!(parsed.len(), 2);
            }
            _ => panic!("expected text content"),
        }
    }

    #[tokio::test]
    async fn decay_score_not_found() {
        let knowledge = Arc::new(KnowledgeStore::open_memory().unwrap());
        let graph = Arc::new(Mutex::new(EntityGraph::open_memory().unwrap()));
        let state = Arc::new(KnowledgeState {
            knowledge,
            graph,
            #[cfg(feature = "rag")]
            chunk_store: None,
            #[cfg(feature = "rag")]
            embedding_model: None,
            distill_model: None,
            classifier_model: None,
        });

        let (_, handler) = handle_decay_score_handler(state);
        let result = handler(
            serde_json::json!({"entry_ids": "nonexistent"}),
            test_ctx(),
        )
        .await;

        assert!(!result.is_error);
        match &result.content[0] {
            navra_mcp::protocol::Content::Text(t) => {
                assert!(t.text.contains("not found"));
            }
            _ => panic!("expected text content"),
        }
    }

    #[tokio::test]
    async fn distill_stub_extracts_paragraphs() {
        let knowledge = Arc::new(KnowledgeStore::open_memory().unwrap());
        let graph = Arc::new(Mutex::new(EntityGraph::open_memory().unwrap()));
        let state = Arc::new(KnowledgeState {
            knowledge,
            graph,
            #[cfg(feature = "rag")]
            chunk_store: None,
            #[cfg(feature = "rag")]
            embedding_model: None,
            distill_model: None,
            classifier_model: None,
        });

        let (_, handler) = handle_distill_handler(state);
        let result = handler(
            serde_json::json!({
                "text": "Rust is a systems programming language.\n\nIt provides memory safety without GC.",
                "source": "test-doc"
            }),
            test_ctx(),
        )
        .await;

        assert!(!result.is_error);
        match &result.content[0] {
            navra_mcp::protocol::Content::Text(t) => {
                let parsed: serde_json::Value = serde_json::from_str(&t.text).unwrap();
                assert_eq!(parsed["method"], "stub");
                assert_eq!(parsed["source"], "test-doc");
                let entries = parsed["entries"].as_array().unwrap();
                assert_eq!(entries.len(), 2);
                assert_eq!(entries[0]["kind"], "Fact");
            }
            _ => panic!("expected text content"),
        }
    }

    #[tokio::test]
    async fn distill_empty_text_errors() {
        let knowledge = Arc::new(KnowledgeStore::open_memory().unwrap());
        let graph = Arc::new(Mutex::new(EntityGraph::open_memory().unwrap()));
        let state = Arc::new(KnowledgeState {
            knowledge,
            graph,
            #[cfg(feature = "rag")]
            chunk_store: None,
            #[cfg(feature = "rag")]
            embedding_model: None,
            distill_model: None,
            classifier_model: None,
        });

        let (_, handler) = handle_distill_handler(state);
        let result = handler(serde_json::json!({"text": ""}), test_ctx()).await;
        assert!(result.is_error);
    }
}
