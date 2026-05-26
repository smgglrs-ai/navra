//! Integration tests for smgglrs-rag public API.
//!
//! Tests ChunkStore, ChunkConfig, chunk_text, and RagModule through
//! the public interface only.

use smgglrs_core::models::{EmbedRequest, EmbedResponse, ModelBackend, ModelError};
use smgglrs_core::permissions::{PathAcl, PermissionEngine};
use smgglrs_core::Module;
use smgglrs_rag::chunk::chunk_text;
use smgglrs_rag::{ChunkConfig, ChunkStore, RagModule};
use std::collections::HashSet;
use std::sync::Arc;

// =====================================================================
// Helpers
// =====================================================================

struct FakeEmbeddingModel;

impl ModelBackend for FakeEmbeddingModel {
    fn embed(
        &self,
        _req: &EmbedRequest,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<EmbedResponse, ModelError>> + Send + '_>,
    > {
        Box::pin(async {
            Ok(EmbedResponse {
                embedding: vec![0.1, 0.2, 0.3, 0.4],
                dimensions: 4,
            })
        })
    }
}

fn test_perm_engine() -> PermissionEngine {
    let mut engine = PermissionEngine::new();
    engine.add_permission_set(
        "dev".to_string(),
        PathAcl {
            ring: None,
            allow: vec!["/**".to_string()],
            deny: vec![],
            operations: ["read", "search"].into_iter().map(String::from).collect(),
            requires_approval: HashSet::new(),
        },
    );
    engine
}

fn build_rag_module() -> RagModule {
    let store = Arc::new(ChunkStore::open_memory(4).unwrap());
    let model: Arc<dyn ModelBackend> = Arc::new(FakeEmbeddingModel);
    RagModule::new(store, model, Arc::new(test_perm_engine()))
}

// =====================================================================
// 1. Module construction and naming
// =====================================================================

#[test]
fn module_name_is_rag() {
    let module = build_rag_module();
    assert_eq!(module.name(), "rag");
}

// =====================================================================
// 2. Tool definitions
// =====================================================================

#[test]
fn module_registers_four_tools() {
    let module = build_rag_module();
    let tools = module.tools();
    assert_eq!(tools.len(), 4);
}

#[test]
fn module_registers_expected_tool_names() {
    let module = build_rag_module();
    let tools = module.tools();
    let names: Vec<&str> = tools.iter().map(|(def, _)| def.name.as_str()).collect();

    let expected = ["rag_index", "rag_query", "rag_similar", "rag_status"];
    for name in &expected {
        assert!(names.contains(name), "Missing tool: {name}");
    }
}

#[test]
fn all_tool_names_prefixed_with_rag() {
    let module = build_rag_module();
    let tools = module.tools();
    for (def, _) in &tools {
        assert!(
            def.name.starts_with("rag_"),
            "Tool '{}' does not start with 'rag_'",
            def.name
        );
    }
}

#[test]
fn all_tools_have_descriptions_and_object_schema() {
    let module = build_rag_module();
    let tools = module.tools();
    for (def, _) in &tools {
        assert!(
            def.description.is_some(),
            "Tool '{}' missing description",
            def.name
        );
        assert_eq!(def.input_schema.schema_type, "object");
    }
}

// =====================================================================
// 3. ChunkStore construction
// =====================================================================

#[test]
fn chunk_store_open_memory_succeeds() {
    let store = ChunkStore::open_memory(4).unwrap();
    let stats = store.stats().unwrap();
    assert_eq!(stats.document_count, 0);
    assert_eq!(stats.chunk_count, 0);
    assert_eq!(stats.dimensions, 4);
}

#[test]
fn chunk_store_zero_dimensions_disables_vectors() {
    let store = ChunkStore::open_memory(0).unwrap();
    let results = store.search(&[0.0, 0.0], 5).unwrap();
    assert!(results.is_empty());
}

// =====================================================================
// 4. Chunking logic
// =====================================================================

#[test]
fn chunk_text_empty_returns_empty() {
    let chunks = chunk_text("", &ChunkConfig::default());
    assert!(chunks.is_empty());
}

#[test]
fn chunk_text_short_returns_single_chunk() {
    let config = ChunkConfig {
        target_size: 1024,
        overlap: 128,
        min_size: 5,
    };
    let chunks = chunk_text("Hello, world!", &config);
    assert_eq!(chunks.len(), 1);
    assert_eq!(chunks[0].content, "Hello, world!");
    assert_eq!(chunks[0].index, 0);
    assert_eq!(chunks[0].start_byte, 0);
}

#[test]
fn chunk_text_respects_min_size() {
    let config = ChunkConfig {
        target_size: 1024,
        overlap: 0,
        min_size: 100,
    };
    let chunks = chunk_text("tiny", &config);
    assert!(chunks.is_empty());
}

#[test]
fn chunk_config_default_values() {
    let config = ChunkConfig::default();
    assert_eq!(config.target_size, 1024);
    assert_eq!(config.overlap, 128);
    assert_eq!(config.min_size, 64);
}

// =====================================================================
// 5. Search with empty store
// =====================================================================

#[test]
fn search_empty_store_returns_empty() {
    let store = ChunkStore::open_memory(4).unwrap();
    let query = vec![0.1, 0.2, 0.3, 0.4];
    let results = store.search(&query, 10).unwrap();
    assert!(results.is_empty());
}

#[test]
fn is_indexed_on_empty_store() {
    let store = ChunkStore::open_memory(4).unwrap();
    assert!(!store.is_indexed("/nonexistent.md").unwrap());
}
