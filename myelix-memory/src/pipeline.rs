//! Distillation pipeline: ingest → synthesize → reconcile → forge.
//!
//! Converts working memory turns into distilled knowledge entries.
//! The `synthesize` stage optionally uses a `ModelBackend` for
//! LLM-based knowledge extraction. Without a model it falls back
//! to extracting user messages as low-confidence facts.

use std::sync::Arc;

use myelix_model::{GenerateRequest, ModelBackend};

use crate::error::MemoryError;
use crate::knowledge::KnowledgeStore;
use crate::types::{DistilledEntry, MemoryType, Turn};
use crate::working::WorkingMemory;

/// System prompt sent to the model during the synthesize stage.
const SYNTHESIZE_PROMPT: &str = "\
Extract structured knowledge from this conversation segment. \
For each piece of knowledge, classify it as Fact, Event, Instruction, or Insight. \
Return a JSON array with objects: \
{\"kind\": \"<Fact|Event|Instruction|Insight>\", \"title\": \"<short title>\", \
\"content\": \"<full detail>\", \"tags\": [\"<tag>\", ...], \"confidence\": <0.0-1.0>}. \
Return ONLY the JSON array, no other text.";

/// A single extracted knowledge item from the model response.
#[derive(Debug, serde::Deserialize)]
struct ExtractedItem {
    kind: String,
    title: String,
    content: String,
    #[serde(default)]
    tags: Vec<String>,
    #[serde(default = "default_confidence")]
    confidence: f64,
}

fn default_confidence() -> f64 {
    0.7
}

/// A segment of conversation turns to be distilled.
#[derive(Debug, Clone)]
pub struct Segment {
    pub session_id: String,
    pub turns: Vec<Turn>,
}

/// Four-stage distillation pipeline.
pub struct DistillationPipeline<'a> {
    working: &'a WorkingMemory,
    knowledge: &'a KnowledgeStore,
    model: Option<Arc<dyn ModelBackend>>,
}

impl<'a> DistillationPipeline<'a> {
    pub fn new(working: &'a WorkingMemory, knowledge: &'a KnowledgeStore) -> Self {
        Self {
            working,
            knowledge,
            model: None,
        }
    }

    /// Set a model backend for LLM-based knowledge extraction.
    pub fn with_model(mut self, model: Arc<dyn ModelBackend>) -> Self {
        self.model = Some(model);
        self
    }

    /// Stage 1: Load session turns and group into segments.
    ///
    /// Each segment contains contiguous turns from a single session.
    /// For now, each session is one segment.
    pub fn ingest(&self, session_id: &str) -> Result<Vec<Segment>, MemoryError> {
        let turns = self.working.get_session_turns(session_id)?;
        if turns.is_empty() {
            return Ok(vec![]);
        }
        Ok(vec![Segment {
            session_id: session_id.to_string(),
            turns,
        }])
    }

    /// Stage 2: Synthesize distilled entries from a segment.
    ///
    /// When a model is configured, sends the segment text to the LLM
    /// and parses structured knowledge entries from the response.
    /// Falls back to stub extraction if no model is set or if the
    /// model response cannot be parsed.
    pub async fn synthesize(&self, segment: &Segment) -> Result<Vec<DistilledEntry>, MemoryError> {
        if let Some(ref model) = self.model {
            match self.synthesize_with_model(model, segment).await {
                Ok(entries) if !entries.is_empty() => return Ok(entries),
                Ok(_) => {
                    tracing::warn!("model returned no entries, falling back to stub");
                }
                Err(e) => {
                    tracing::warn!("model synthesis failed, falling back to stub: {e}");
                }
            }
        }

        self.synthesize_stub(segment)
    }

    /// LLM-based synthesis: send segment text to the model and parse
    /// the JSON response into distilled entries.
    async fn synthesize_with_model(
        &self,
        model: &Arc<dyn ModelBackend>,
        segment: &Segment,
    ) -> Result<Vec<DistilledEntry>, MemoryError> {
        let text = self.segment_to_text(segment);

        let request = GenerateRequest {
            prompt: text,
            max_tokens: Some(2048),
            temperature: Some(0.1),
            system: Some(SYNTHESIZE_PROMPT.to_string()),
            images: vec![],
        };

        let response = model
            .generate(&request)
            .await
            .map_err(|e| MemoryError::Other(format!("model generate failed: {e}")))?;

        self.parse_model_response(&response.text, &segment.session_id)
    }

    /// Build a text representation of a segment for the model prompt.
    fn segment_to_text(&self, segment: &Segment) -> String {
        let mut lines = Vec::new();
        for turn in &segment.turns {
            for msg in &turn.messages {
                lines.push(format!("[{}]: {}", msg.role.as_str(), msg.content));
            }
        }
        lines.join("\n")
    }

    /// Parse the model's JSON response into distilled entries.
    fn parse_model_response(
        &self,
        text: &str,
        session_id: &str,
    ) -> Result<Vec<DistilledEntry>, MemoryError> {
        let items: Vec<ExtractedItem> = serde_json::from_str(text)
            .map_err(|e| MemoryError::Other(format!("failed to parse model JSON: {e}")))?;

        let mut entries = Vec::new();
        for item in items {
            let kind = match item.kind.to_lowercase().as_str() {
                "fact" => MemoryType::Fact,
                "event" => MemoryType::Event,
                "instruction" => MemoryType::Instruction,
                "insight" => MemoryType::Insight,
                other => {
                    tracing::warn!("unknown memory type from model: {other}, defaulting to Fact");
                    MemoryType::Fact
                }
            };

            let confidence = item.confidence.clamp(0.0, 1.0);

            entries.push(DistilledEntry::new(
                kind,
                item.title,
                item.content,
                item.tags,
                confidence,
                session_id.to_string(),
            ));
        }

        Ok(entries)
    }

    /// Stub synthesis: extract user messages as low-confidence facts.
    fn synthesize_stub(&self, segment: &Segment) -> Result<Vec<DistilledEntry>, MemoryError> {
        let mut entries = Vec::new();

        for turn in &segment.turns {
            for msg in &turn.messages {
                if msg.role.as_str() == "user" && !msg.content.is_empty() {
                    let title = if msg.content.len() > 80 {
                        format!("{}...", &msg.content[..77])
                    } else {
                        msg.content.clone()
                    };

                    entries.push(DistilledEntry::new(
                        MemoryType::Fact,
                        title,
                        msg.content.clone(),
                        vec![],
                        0.5, // Low confidence: stub, not LLM-synthesized
                        segment.session_id.clone(),
                    ));
                }
            }
        }

        Ok(entries)
    }

    /// Stage 3: Reconcile entries against existing knowledge.
    ///
    /// Computes content_key, checks for existing entry, upserts
    /// or flags conflict.
    pub fn reconcile(&self, entries: Vec<DistilledEntry>) -> Result<Vec<DistilledEntry>, MemoryError> {
        // Content keys are already computed in DistilledEntry::new.
        // In this skeleton, we just pass through. A full implementation
        // would check for conflicts and merge content.
        Ok(entries)
    }

    /// Stage 4: Forge — persist reconciled entries into the knowledge store.
    fn forge(&self, entries: &[DistilledEntry]) -> Result<usize, MemoryError> {
        let mut stored = 0;
        for entry in entries {
            self.knowledge.store_distilled(entry)?;
            stored += 1;
        }
        Ok(stored)
    }

    /// Run the full 4-stage pipeline for a session.
    ///
    /// Returns the number of entries stored/updated.
    pub async fn run(&self, session_id: &str) -> Result<usize, MemoryError> {
        let segments = self.ingest(session_id)?;
        let mut total = 0;
        for segment in &segments {
            let synthesized = self.synthesize(segment).await?;
            let reconciled = self.reconcile(synthesized)?;
            total += self.forge(&reconciled)?;
        }
        Ok(total)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{Message, Role};

    fn make_turn(session: &str, content: &str, ts: i64) -> Turn {
        Turn {
            turn_id: uuid::Uuid::new_v4().to_string(),
            session_id: session.to_string(),
            agent: "test".to_string(),
            messages: vec![
                Message {
                    role: Role::User,
                    content: content.to_string(),
                    timestamp: ts,
                    metadata: None,
                },
                Message {
                    role: Role::Assistant,
                    content: "Understood.".to_string(),
                    timestamp: ts + 1,
                    metadata: None,
                },
            ],
            created_at: ts,
        }
    }

    #[test]
    fn ingest_extracts_segments() {
        let wm = WorkingMemory::open_memory().unwrap();
        wm.add_turn(&make_turn("s1", "Hello", 1000)).unwrap();
        wm.add_turn(&make_turn("s1", "World", 2000)).unwrap();

        let ks = KnowledgeStore::open_memory().unwrap();
        let pipeline = DistillationPipeline::new(&wm, &ks);

        let segments = pipeline.ingest("s1").unwrap();
        assert_eq!(segments.len(), 1);
        assert_eq!(segments[0].turns.len(), 2);
    }

    #[test]
    fn ingest_empty_session() {
        let wm = WorkingMemory::open_memory().unwrap();
        let ks = KnowledgeStore::open_memory().unwrap();
        let pipeline = DistillationPipeline::new(&wm, &ks);

        let segments = pipeline.ingest("empty").unwrap();
        assert!(segments.is_empty());
    }

    #[tokio::test]
    async fn synthesize_produces_entries() {
        let wm = WorkingMemory::open_memory().unwrap();
        wm.add_turn(&make_turn("s1", "Rust is great", 1000)).unwrap();

        let ks = KnowledgeStore::open_memory().unwrap();
        let pipeline = DistillationPipeline::new(&wm, &ks);

        let segments = pipeline.ingest("s1").unwrap();
        let entries = pipeline.synthesize(&segments[0]).await.unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].kind, MemoryType::Fact);
        assert!(!entries[0].content_key.is_empty());
    }

    #[tokio::test]
    async fn full_pipeline_stores_entries() {
        let wm = WorkingMemory::open_memory().unwrap();
        wm.add_turn(&make_turn("s1", "Important fact", 1000)).unwrap();
        wm.add_turn(&make_turn("s1", "Another fact", 2000)).unwrap();

        let ks = KnowledgeStore::open_memory().unwrap();
        let pipeline = DistillationPipeline::new(&wm, &ks);

        let stored = pipeline.run("s1").await.unwrap();
        assert_eq!(stored, 2);
        assert_eq!(ks.count().unwrap(), 2);
    }

    #[tokio::test]
    async fn synthesize_without_model_uses_stub() {
        let wm = WorkingMemory::open_memory().unwrap();
        wm.add_turn(&make_turn("s1", "The sky is blue", 1000)).unwrap();
        wm.add_turn(&make_turn("s1", "Water is wet", 2000)).unwrap();

        let ks = KnowledgeStore::open_memory().unwrap();
        let pipeline = DistillationPipeline::new(&wm, &ks);

        let segments = pipeline.ingest("s1").unwrap();
        let entries = pipeline.synthesize(&segments[0]).await.unwrap();

        // Stub produces one Fact per user message
        assert_eq!(entries.len(), 2);
        for entry in &entries {
            assert_eq!(entry.kind, MemoryType::Fact);
            assert!((entry.confidence - 0.5).abs() < f64::EPSILON);
        }
        assert_eq!(entries[0].content, "The sky is blue");
        assert_eq!(entries[1].content, "Water is wet");
    }
}
