//! Leakage detection hooks (L2 similarity + L3 semantic analysis).
//!
//! Two layers of defense against information leakage through LLM
//! reasoning, complementing L1 label-based IFC:
//!
//! **L2 — Similarity-based detection** (`SimilarityLeakageHook`):
//! Compares outgoing tool arguments against tainted values using
//! embedding cosine similarity. Catches paraphrased exfiltration.
//! Fast (~40ms with BGE-large), runs inline on every write.
//!
//! **L3 — Semantic analysis** (`SemanticLeakageJudge`, future):
//! Asks an LLM judge "does this outgoing text reveal information
//! from this tainted content?" Catches derived information that
//! similarity cannot detect. Slow (~500ms+), runs selectively
//! on high-risk writes (confidentiality >= Secret) and out-of-band
//! as a post-hoc audit on blackbox transcripts.
//!
//! Only runs on write tools (determined by `is_write_tool`). Only
//! compares against values with confidentiality >= Sensitive.

use super::{Hook, HookDecision};
use crate::auth::CallContext;
use crate::ifc::value_store::ValueStoreMap;
use navra_protocol::label::Confidentiality;
use std::sync::Arc;

/// Embedding function: takes text, returns vector.
pub type EmbedFn = Arc<dyn Fn(&str) -> Option<Vec<f32>> + Send + Sync>;

pub struct SimilarityLeakageConfig {
    pub enabled: bool,
    pub similarity_threshold: f32,
    pub min_text_length: usize,
}

impl Default for SimilarityLeakageConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            similarity_threshold: 0.75,
            min_text_length: 10,
        }
    }
}

pub struct SimilarityLeakageHook {
    value_stores: Arc<ValueStoreMap>,
    embed_fn: EmbedFn,
    config: SimilarityLeakageConfig,
}

impl SimilarityLeakageHook {
    pub fn new(
        value_stores: Arc<ValueStoreMap>,
        embed_fn: EmbedFn,
        config: SimilarityLeakageConfig,
    ) -> Self {
        Self {
            value_stores,
            embed_fn,
            config,
        }
    }
}

fn extract_text_from_args(args: &serde_json::Value) -> String {
    let mut parts = Vec::new();
    collect_strings(args, &mut parts);
    parts.join(" ")
}

fn collect_strings(value: &serde_json::Value, out: &mut Vec<String>) {
    match value {
        serde_json::Value::String(s) => out.push(s.clone()),
        serde_json::Value::Array(arr) => {
            for item in arr {
                collect_strings(item, out);
            }
        }
        serde_json::Value::Object(map) => {
            for v in map.values() {
                collect_strings(v, out);
            }
        }
        _ => {}
    }
}

fn cosine_similarity(a: &[f32], b: &[f32]) -> f32 {
    if a.len() != b.len() || a.is_empty() {
        return 0.0;
    }
    let mut dot = 0.0f32;
    let mut norm_a = 0.0f32;
    let mut norm_b = 0.0f32;
    for (x, y) in a.iter().zip(b.iter()) {
        dot += x * y;
        norm_a += x * x;
        norm_b += y * y;
    }
    let denom = norm_a.sqrt() * norm_b.sqrt();
    if denom == 0.0 {
        0.0
    } else {
        dot / denom
    }
}

fn content_to_text(content: &[navra_protocol::Content]) -> String {
    content
        .iter()
        .filter_map(|c| match c {
            navra_protocol::Content::Text(t) => Some(t.text.as_str()),
            _ => None,
        })
        .collect::<Vec<_>>()
        .join(" ")
}

#[async_trait::async_trait]
impl Hook for SimilarityLeakageHook {
    fn name(&self) -> &str {
        "similarity-leakage"
    }

    async fn pre_tool_use(
        &self,
        tool_name: &str,
        arguments: &serde_json::Value,
        ctx: &CallContext,
    ) -> HookDecision {
        if !self.config.enabled {
            return HookDecision::Continue;
        }

        let tool_annotations = None; // TODO: pass annotations when available
        if !crate::ifc::is_write_tool(tool_name, tool_annotations) {
            return HookDecision::Continue;
        }

        let outgoing_text = extract_text_from_args(arguments);
        if outgoing_text.len() < self.config.min_text_length {
            return HookDecision::Continue;
        }

        let outgoing_embedding = match (self.embed_fn)(&outgoing_text) {
            Some(e) => e,
            None => return HookDecision::Continue,
        };

        let store = self.value_stores.get_or_create(&ctx.session_id);
        let values = store.list();

        let sensitive_ids: Vec<String> = values
            .iter()
            .filter(|v| v.label.confidentiality >= Confidentiality::Sensitive)
            .map(|v| v.id.clone())
            .collect();

        if sensitive_ids.is_empty() {
            return HookDecision::Continue;
        }

        for id in &sensitive_ids {
            let value = match store.get(id) {
                Some(v) => v,
                None => continue,
            };

            let value_text = content_to_text(&value.content);
            if value_text.len() < self.config.min_text_length {
                continue;
            }

            let value_embedding = match (self.embed_fn)(&value_text) {
                Some(e) => e,
                None => continue,
            };

            let similarity = cosine_similarity(&outgoing_embedding, &value_embedding);

            if similarity >= self.config.similarity_threshold {
                tracing::warn!(
                    tool = %tool_name,
                    session = %ctx.session_id,
                    agent = %ctx.agent.name,
                    similarity = %format!("{similarity:.3}"),
                    tainted_var = %id,
                    source_tool = %value.source_tool,
                    confidentiality = ?value.label.confidentiality,
                    "Similarity leakage detected: outgoing content similar to tainted value"
                );
                return HookDecision::Block(format!(
                    "Similarity leakage detected: outgoing content is {:.0}% similar to \
                     tainted value from '{}' (confidentiality: {:?})",
                    similarity * 100.0,
                    value.source_tool,
                    value.label.confidentiality,
                ));
            }
        }

        HookDecision::Continue
    }
}

// ═══════════════════════════════════════════════════════════════════
// L3 — Semantic analysis via LLM judge.
//
// Asks a model: "Does this outgoing text reveal information from
// the following tainted content?" Catches derived information that
// embedding similarity cannot detect (e.g., "password starts with
// h" from "hunter2").
//
// Two modes:
//   Inline (selective): runs on write tools when session
//     confidentiality >= Secret. ~500ms+ latency, only for
//     high-risk writes. Complements L2 which runs on all writes.
//   Continuous (async): runs outside the agent's latency chain
//     via tokio::spawn after every write. The write proceeds
//     immediately; L3 analyzes it in the background. If leakage
//     is detected, the session trust score is penalized and the
//     session taint is retroactively elevated so L1 blocks
//     subsequent writes. Similar to NeuroTaint's causal influence
//     analysis, but continuous rather than post-hoc.
//
// The judge model must NOT be the same model driving the agent
// (to avoid self-evaluation circularity).
// ═══════════════════════════════════════════════════════════════════

/// Function that asks an LLM judge whether outgoing text reveals
/// information from tainted content. Returns a confidence score
/// (0.0 = no leakage, 1.0 = certain leakage).
pub type JudgeFn =
    Arc<dyn Fn(&str, &str) -> std::pin::Pin<Box<dyn std::future::Future<Output = Option<f32>> + Send>> + Send + Sync>;

pub struct SemanticLeakageConfig {
    pub enabled: bool,
    pub confidence_threshold: f32,
    pub min_confidentiality: Confidentiality,
}

impl Default for SemanticLeakageConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            confidence_threshold: 0.7,
            min_confidentiality: Confidentiality::Secret,
        }
    }
}

pub struct SemanticLeakageJudge {
    value_stores: Arc<ValueStoreMap>,
    judge_fn: JudgeFn,
    config: SemanticLeakageConfig,
}

impl SemanticLeakageJudge {
    pub fn new(
        value_stores: Arc<ValueStoreMap>,
        judge_fn: JudgeFn,
        config: SemanticLeakageConfig,
    ) -> Self {
        Self {
            value_stores,
            judge_fn,
            config,
        }
    }
}

#[async_trait::async_trait]
impl Hook for SemanticLeakageJudge {
    fn name(&self) -> &str {
        "semantic-leakage-judge"
    }

    async fn pre_tool_use(
        &self,
        tool_name: &str,
        arguments: &serde_json::Value,
        ctx: &CallContext,
    ) -> HookDecision {
        if !self.config.enabled {
            return HookDecision::Continue;
        }

        let tool_annotations = None;
        if !crate::ifc::is_write_tool(tool_name, tool_annotations) {
            return HookDecision::Continue;
        }

        let outgoing_text = extract_text_from_args(arguments);
        if outgoing_text.len() < 10 {
            return HookDecision::Continue;
        }

        let store = self.value_stores.get_or_create(&ctx.session_id);
        let values = store.list();

        let sensitive_ids: Vec<String> = values
            .iter()
            .filter(|v| v.label.confidentiality >= self.config.min_confidentiality)
            .map(|v| v.id.clone())
            .collect();

        if sensitive_ids.is_empty() {
            return HookDecision::Continue;
        }

        for id in &sensitive_ids {
            let value = match store.get(id) {
                Some(v) => v,
                None => continue,
            };

            let value_text = content_to_text(&value.content);
            if value_text.len() < 10 {
                continue;
            }

            let confidence = match (self.judge_fn)(&outgoing_text, &value_text).await {
                Some(c) => c,
                None => continue,
            };

            if confidence >= self.config.confidence_threshold {
                tracing::warn!(
                    tool = %tool_name,
                    session = %ctx.session_id,
                    agent = %ctx.agent.name,
                    confidence = %format!("{confidence:.3}"),
                    tainted_var = %id,
                    source_tool = %value.source_tool,
                    "Semantic leakage: LLM judge detected information reveal"
                );
                return HookDecision::Block(format!(
                    "Semantic leakage detected: LLM judge confidence {:.0}% that \
                     outgoing text reveals information from '{}' (confidentiality: {:?})",
                    confidence * 100.0,
                    value.source_tool,
                    value.label.confidentiality,
                ));
            }
        }

        HookDecision::Continue
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::AgentIdentity;
    use crate::ifc::value_store::{StoredValue, ValueStoreMap};
    use navra_protocol::label::{Confidentiality, DataLabel, Integrity};
    use serde_json::json;

    fn mock_embed(text: &str) -> Option<Vec<f32>> {
        // Deterministic mock: character bigram frequency vector.
        // 26x26 = 676 dims — enough to discriminate different text.
        let text_lower = text.to_lowercase();
        let bytes: Vec<u8> = text_lower
            .bytes()
            .filter(|b| b.is_ascii_alphabetic())
            .map(|b| b - b'a')
            .collect();
        let mut v = vec![0.0f32; 676];
        for pair in bytes.windows(2) {
            let idx = (pair[0] as usize) * 26 + pair[1] as usize;
            v[idx] += 1.0;
        }
        let norm: f32 = v.iter().map(|x| x * x).sum::<f32>().sqrt();
        if norm > 0.0 {
            for x in &mut v {
                *x /= norm;
            }
        }
        Some(v)
    }

    fn test_ctx(session: &str) -> CallContext {
        CallContext::new(AgentIdentity::new("tester", "dev"), session)
    }

    fn make_hook(stores: Arc<ValueStoreMap>) -> SimilarityLeakageHook {
        SimilarityLeakageHook::new(
            stores,
            Arc::new(mock_embed),
            SimilarityLeakageConfig::default(),
        )
    }

    fn store_tainted_value(stores: &ValueStoreMap, session: &str, content: &str) {
        let store = stores.get_or_create(session);
        store.store(StoredValue {
            id: format!("v-test-{}", content.len()),
            content: vec![navra_protocol::Content::text(content)],
            label: DataLabel {
                integrity: Integrity::Untrusted,
                confidentiality: Confidentiality::Secret,
            },
            source_tool: "file_read".to_string(),
            created_at: std::time::Instant::now(),
            is_error: false,
        });
    }

    #[tokio::test]
    async fn blocks_similar_content() {
        let stores = Arc::new(ValueStoreMap::new());
        store_tainted_value(&stores, "sess1", "API_KEY=sk-secret-abc123");

        let hook = make_hook(stores);
        let ctx = test_ctx("sess1");

        // Same text should be blocked (similarity ~1.0)
        let decision = hook
            .pre_tool_use(
                "file_write",
                &json!({"path": "/tmp/out", "content": "API_KEY=sk-secret-abc123"}),
                &ctx,
            )
            .await;

        assert!(
            matches!(decision, HookDecision::Block(_)),
            "Identical content should be blocked: {decision:?}"
        );
    }

    #[tokio::test]
    async fn allows_unrelated_content() {
        let stores = Arc::new(ValueStoreMap::new());
        store_tainted_value(&stores, "sess1", "API_KEY=sk-secret-abc123");

        let hook = make_hook(stores);
        let ctx = test_ctx("sess1");

        // Completely unrelated text should pass
        let decision = hook
            .pre_tool_use(
                "file_write",
                &json!({"path": "/tmp/out", "content": "The weather is nice today and the sun is shining brightly"}),
                &ctx,
            )
            .await;

        assert!(
            matches!(decision, HookDecision::Continue),
            "Unrelated content should pass: {decision:?}"
        );
    }

    #[tokio::test]
    async fn skips_read_tools() {
        let stores = Arc::new(ValueStoreMap::new());
        store_tainted_value(&stores, "sess1", "API_KEY=sk-secret-abc123");

        let hook = make_hook(stores);
        let ctx = test_ctx("sess1");

        let decision = hook
            .pre_tool_use(
                "file_read",
                &json!({"path": "API_KEY=sk-secret-abc123"}),
                &ctx,
            )
            .await;

        assert!(matches!(decision, HookDecision::Continue));
    }

    #[tokio::test]
    async fn skips_short_content() {
        let stores = Arc::new(ValueStoreMap::new());
        store_tainted_value(&stores, "sess1", "API_KEY=sk-secret-abc123");

        let hook = make_hook(stores);
        let ctx = test_ctx("sess1");

        let decision = hook
            .pre_tool_use(
                "file_write",
                &json!({"path": "/tmp/out", "content": "hi"}),
                &ctx,
            )
            .await;

        assert!(matches!(decision, HookDecision::Continue));
    }

    #[tokio::test]
    async fn skips_when_no_tainted_values() {
        let stores = Arc::new(ValueStoreMap::new());
        let hook = make_hook(stores);
        let ctx = test_ctx("sess1");

        let decision = hook
            .pre_tool_use(
                "file_write",
                &json!({"path": "/tmp/out", "content": "API_KEY=sk-secret-abc123"}),
                &ctx,
            )
            .await;

        assert!(matches!(decision, HookDecision::Continue));
    }

    #[tokio::test]
    async fn disabled_hook_passes() {
        let stores = Arc::new(ValueStoreMap::new());
        store_tainted_value(&stores, "sess1", "API_KEY=sk-secret-abc123");

        let hook = SimilarityLeakageHook::new(
            stores,
            Arc::new(mock_embed),
            SimilarityLeakageConfig {
                enabled: false,
                ..Default::default()
            },
        );
        let ctx = test_ctx("sess1");

        let decision = hook
            .pre_tool_use(
                "file_write",
                &json!({"path": "/tmp/out", "content": "API_KEY=sk-secret-abc123"}),
                &ctx,
            )
            .await;

        assert!(matches!(decision, HookDecision::Continue));
    }

    #[tokio::test]
    async fn extracts_text_from_nested_args() {
        let args = json!({
            "headers": {"auth": "Bearer token123"},
            "body": {"data": "secret content here"},
            "url": "https://example.com"
        });
        let text = extract_text_from_args(&args);
        assert!(text.contains("Bearer token123"));
        assert!(text.contains("secret content here"));
        assert!(text.contains("https://example.com"));
    }

    #[test]
    fn cosine_similarity_identical() {
        let a = vec![1.0, 0.0, 0.0];
        let b = vec![1.0, 0.0, 0.0];
        assert!((cosine_similarity(&a, &b) - 1.0).abs() < 1e-6);
    }

    #[test]
    fn cosine_similarity_orthogonal() {
        let a = vec![1.0, 0.0];
        let b = vec![0.0, 1.0];
        assert!(cosine_similarity(&a, &b).abs() < 1e-6);
    }
}
