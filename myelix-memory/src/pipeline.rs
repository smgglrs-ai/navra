//! Distillation pipeline: ingest → synthesize → reconcile → forge.
//!
//! Converts working memory turns into distilled knowledge entries.
//! The `synthesize` stage requires a model backend and is stubbed
//! for now — it produces a placeholder entry from each segment.

use crate::error::MemoryError;
use crate::knowledge::KnowledgeStore;
use crate::types::{DistilledEntry, MemoryType, Turn};
use crate::working::WorkingMemory;

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
}

impl<'a> DistillationPipeline<'a> {
    pub fn new(working: &'a WorkingMemory, knowledge: &'a KnowledgeStore) -> Self {
        Self { working, knowledge }
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
    /// Stub implementation: extracts a summary entry from the first
    /// user message. Full implementation requires a ModelBackend to
    /// generate proper summaries.
    pub fn synthesize(&self, segment: &Segment) -> Result<Vec<DistilledEntry>, MemoryError> {
        let mut entries = Vec::new();

        // Collect all user messages as potential facts
        for turn in &segment.turns {
            for msg in &turn.messages {
                if msg.role.as_str() == "user" && !msg.content.is_empty() {
                    // Truncate long content for the title
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
    pub fn run(&self, session_id: &str) -> Result<usize, MemoryError> {
        let segments = self.ingest(session_id)?;
        let mut total = 0;
        for segment in &segments {
            let synthesized = self.synthesize(segment)?;
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

    #[test]
    fn synthesize_produces_entries() {
        let wm = WorkingMemory::open_memory().unwrap();
        wm.add_turn(&make_turn("s1", "Rust is great", 1000)).unwrap();

        let ks = KnowledgeStore::open_memory().unwrap();
        let pipeline = DistillationPipeline::new(&wm, &ks);

        let segments = pipeline.ingest("s1").unwrap();
        let entries = pipeline.synthesize(&segments[0]).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].kind, MemoryType::Fact);
        assert!(!entries[0].content_key.is_empty());
    }

    #[test]
    fn full_pipeline_stores_entries() {
        let wm = WorkingMemory::open_memory().unwrap();
        wm.add_turn(&make_turn("s1", "Important fact", 1000)).unwrap();
        wm.add_turn(&make_turn("s1", "Another fact", 2000)).unwrap();

        let ks = KnowledgeStore::open_memory().unwrap();
        let pipeline = DistillationPipeline::new(&wm, &ks);

        let stored = pipeline.run("s1").unwrap();
        assert_eq!(stored, 2);
        assert_eq!(ks.count().unwrap(), 2);
    }
}
