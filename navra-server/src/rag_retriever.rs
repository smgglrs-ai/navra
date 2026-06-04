use navra_model::ModelBackend;
use navra_rag::{CascadeConfig, ChunkStore};
use navra_rag::Reranker;
use std::sync::Arc;

pub struct RagRetriever {
    store: Arc<ChunkStore>,
    embedding_model: Arc<dyn ModelBackend>,
    reranker: Arc<dyn Reranker>,
    cascade: CascadeConfig,
    metrics: Option<Arc<navra_core::metrics::Metrics>>,
}

impl RagRetriever {
    pub fn new(
        store: Arc<ChunkStore>,
        embedding_model: Arc<dyn ModelBackend>,
        reranker: Arc<dyn Reranker>,
        cascade: CascadeConfig,
        metrics: Option<Arc<navra_core::metrics::Metrics>>,
    ) -> Self {
        Self {
            store,
            embedding_model,
            reranker,
            cascade,
            metrics,
        }
    }
}

impl navra_agent::ContextRetriever for RagRetriever {
    fn retrieve(
        &self,
        query: &str,
        max_tokens: usize,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = String> + Send + '_>> {
        let query = query.to_string();
        Box::pin(async move {
            tracing::info!(query = %query, max_tokens = max_tokens, "ContextRetriever: retrieving");

            if let Some(ref m) = self.metrics {
                m.rag_queries_total
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            }

            let embed_request = navra_model::EmbedRequest {
                text: query.clone(),
            };
            let embedding = match self.embedding_model.embed(&embed_request).await {
                Ok(r) => r.embedding,
                Err(_) => return String::new(),
            };

            let limit = 5;
            let fetch_limit = if self.reranker.is_active() {
                limit * 4
            } else {
                limit
            };

            let (candidates, vector_skipped, rerank_skipped) = match self
                .store
                .search_hybrid_cascading(&query, &embedding, fetch_limit, &self.cascade)
            {
                Ok(r) => r,
                Err(_) => return String::new(),
            };

            if let Some(ref m) = self.metrics {
                if vector_skipped {
                    m.rag_vector_skips
                        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                }
                if rerank_skipped {
                    m.rag_rerank_skips
                        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                }
            }

            if candidates.is_empty() {
                return String::new();
            }

            let results = if rerank_skipped || !self.reranker.is_active() {
                candidates.into_iter().take(limit).collect::<Vec<_>>()
            } else {
                self.reranker
                    .rerank(&query, candidates)
                    .into_iter()
                    .take(limit)
                    .collect()
            };

            let max_chars = max_tokens * 4;
            let mut output = String::new();
            for r in &results {
                if output.len() + r.content.len() > max_chars {
                    break;
                }
                if !output.is_empty() {
                    output.push_str("\n---\n");
                }
                output.push_str(&format!("[{}]\n{}", r.path, r.content));
            }
            output
        })
    }
}
