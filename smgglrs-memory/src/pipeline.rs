//! Distillation pipeline: ingest → synthesize → reconcile → forge.
//!
//! Converts working memory turns into distilled knowledge entries.
//! The `synthesize` stage optionally uses a `ModelBackend` for
//! LLM-based knowledge extraction. Without a model it falls back
//! to extracting user messages as low-confidence facts.

use std::fs;
use std::path::Path;
use std::sync::Arc;

use chrono::Utc;
use smgglrs_model::{GenerateRequest, ModelBackend};

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

/// Synchronous content sanitizer function type.
///
/// Accepts content, returns sanitized content. Injected from the
/// server layer to apply PII filtering without smgglrs-memory
/// depending on smgglrs-security.
pub type ContentSanitizer = Arc<dyn Fn(&str) -> String + Send + Sync>;

/// Four-stage distillation pipeline.
pub struct DistillationPipeline<'a> {
    working: &'a WorkingMemory,
    knowledge: &'a KnowledgeStore,
    model: Option<Arc<dyn ModelBackend>>,
    /// Optional content sanitizer applied before writing output.
    sanitizer: Option<ContentSanitizer>,
}

impl<'a> DistillationPipeline<'a> {
    pub fn new(working: &'a WorkingMemory, knowledge: &'a KnowledgeStore) -> Self {
        Self {
            working,
            knowledge,
            model: None,
            sanitizer: None,
        }
    }

    /// Set a model backend for LLM-based knowledge extraction.
    pub fn with_model(mut self, model: Arc<dyn ModelBackend>) -> Self {
        self.model = Some(model);
        self
    }

    /// Set a content sanitizer for PII filtering on output.
    ///
    /// The sanitizer is applied to distilled entry content before
    /// writing to Markdown files and before forging into the knowledge store.
    pub fn with_sanitizer(mut self, sanitizer: ContentSanitizer) -> Self {
        self.sanitizer = Some(sanitizer);
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

    /// Apply the content sanitizer to a string, if one is configured.
    fn sanitize(&self, content: &str) -> String {
        match &self.sanitizer {
            Some(f) => f(content),
            None => content.to_string(),
        }
    }

    /// Stage 4: Forge — persist reconciled entries into the knowledge store.
    ///
    /// When a sanitizer is configured, entry content is filtered for PII
    /// before being persisted.
    fn forge(&self, entries: &[DistilledEntry]) -> Result<usize, MemoryError> {
        let mut stored = 0;
        for entry in entries {
            let sanitized = if self.sanitizer.is_some() {
                let mut e = entry.clone();
                e.content = self.sanitize(&e.content);
                e.title = self.sanitize(&e.title);
                e
            } else {
                entry.clone()
            };
            self.knowledge.store_distilled(&sanitized)?;
            stored += 1;
        }
        Ok(stored)
    }

    /// Export distilled entries as Markdown files with YAML frontmatter.
    /// Creates one file per entry in the output directory.
    ///
    /// When a sanitizer is configured, entry content and title are
    /// filtered for PII before writing.
    pub fn export_markdown(
        &self,
        entries: &[DistilledEntry],
        output_dir: &Path,
    ) -> Result<usize, MemoryError> {
        fs::create_dir_all(output_dir)
            .map_err(|e| MemoryError::Other(format!("failed to create output dir: {e}")))?;

        let mut written = 0;
        for entry in entries {
            let filename = Self::sanitize_filename(entry);
            let path = output_dir.join(&filename);

            // Apply PII sanitizer to title and content
            let sanitized_title = self.sanitize(&entry.title);
            let sanitized_content = self.sanitize(&entry.content);

            let tags_yaml = if entry.tags.is_empty() {
                "[]".to_string()
            } else {
                format!(
                    "[{}]",
                    entry
                        .tags
                        .iter()
                        .map(|t| t.as_str())
                        .collect::<Vec<_>>()
                        .join(", ")
                )
            };

            let today = Utc::now().format("%Y-%m-%d");

            let content = format!(
                "---\ntype: {}\nname: \"{}\"\nsource_session: \"{}\"\nconfidence: {:.2}\ntags: {}\ncreated_at: {}\n---\n\n{}\n",
                entry.kind.as_str(),
                sanitized_title.replace('"', "\\\""),
                entry.source_session,
                entry.confidence,
                tags_yaml,
                today,
                sanitized_content,
            );

            fs::write(&path, &content)
                .map_err(|e| MemoryError::Other(format!("failed to write {}: {e}", path.display())))?;

            written += 1;
        }

        Ok(written)
    }

    /// Build a sanitized filename from a distilled entry.
    ///
    /// Format: `{type}_{sanitized_title}.md` where spaces become
    /// underscores and the total length is capped at 60 characters.
    fn sanitize_filename(entry: &DistilledEntry) -> String {
        let sanitized: String = entry
            .title
            .chars()
            .map(|c| if c.is_alphanumeric() || c == '-' { c } else { '_' })
            .collect::<String>()
            .to_lowercase();

        let prefix = format!("{}_{}", entry.kind.as_str(), sanitized);
        let truncated = if prefix.len() > 60 {
            prefix[..60].to_string()
        } else {
            prefix
        };

        format!("{}.md", truncated)
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

/// Extract a structured failure insight from a failed task.
///
/// Produces a `DistilledEntry` with `MemoryType::Insight` tagged
/// `["failure", "lesson"]`. The content follows the ReasoningBank
/// format: what was attempted, why it failed, what to avoid.
///
/// # Arguments
/// - `task_name` — task identifier or short description
/// - `mandate` — what the task was supposed to accomplish
/// - `error` — the error message or failure description
/// - `attempt_history` — list of `(error, output)` pairs from retries
pub fn extract_failure_insight(
    task_name: &str,
    mandate: &str,
    error: &str,
    attempt_history: &[(String, String)],
) -> DistilledEntry {
    let approaches: Vec<String> = attempt_history
        .iter()
        .enumerate()
        .map(|(i, (err, _output))| format!("Attempt {}: {}", i + 1, err))
        .collect();

    let history_summary = if approaches.is_empty() {
        error.to_string()
    } else {
        approaches.join(". ")
    };

    let title = format!("Failure: {task_name}");

    let content = format!(
        "When attempting [{task_name}] with mandate \"{mandate}\", \
         the approach failed because [{error}]. \
         Attempt history: {history_summary}. \
         Avoid repeating this approach without addressing the root cause."
    );

    DistilledEntry::new(
        MemoryType::Insight,
        title,
        content,
        vec!["failure".to_string(), "lesson".to_string()],
        0.7,
        String::new(),
    )
}

/// Extract a structured success insight from a completed task.
///
/// Produces a `DistilledEntry` with `MemoryType::Insight` tagged
/// `["success", "strategy"]`. The content follows the ReasoningBank
/// format: what worked and why.
///
/// # Arguments
/// - `task_name` — task identifier or short description
/// - `mandate` — what the task accomplished
/// - `result_summary` — brief description of the output
/// - `iterations` — how many attempts it took to succeed
pub fn extract_success_insight(
    task_name: &str,
    mandate: &str,
    result_summary: &str,
    iterations: u32,
) -> DistilledEntry {
    let title = format!("Success: {task_name}");

    let summary = if result_summary.len() > 200 {
        format!("{}...", &result_summary[..197])
    } else {
        result_summary.to_string()
    };

    let content = format!(
        "For [{task_name}] with mandate \"{mandate}\", \
         the approach succeeded in {iterations} iteration(s). \
         Key outcome: {summary}."
    );

    DistilledEntry::new(
        MemoryType::Insight,
        title,
        content,
        vec!["success".to_string(), "strategy".to_string()],
        0.85,
        String::new(),
    )
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
            fork_id: None,
            parent_fork: None,
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

    /// A mock model backend that returns a fixed JSON response
    /// for the `generate` method, simulating LLM-based extraction.
    struct MockModelBackend {
        response_json: String,
    }

    impl MockModelBackend {
        fn new(json: &str) -> Self {
            Self {
                response_json: json.to_string(),
            }
        }
    }

    impl smgglrs_model::ModelBackend for MockModelBackend {
        fn generate(
            &self,
            _request: &smgglrs_model::GenerateRequest,
        ) -> std::pin::Pin<
            Box<dyn std::future::Future<Output = Result<smgglrs_model::GenerateResponse, smgglrs_model::ModelError>> + Send + '_>,
        > {
            let text = self.response_json.clone();
            Box::pin(async move {
                Ok(smgglrs_model::GenerateResponse {
                    text,
                    prompt_tokens: Some(100),
                    completion_tokens: Some(50),
                })
            })
        }
    }

    /// A mock model that always returns an error.
    struct FailingModelBackend;

    impl smgglrs_model::ModelBackend for FailingModelBackend {
        fn generate(
            &self,
            _request: &smgglrs_model::GenerateRequest,
        ) -> std::pin::Pin<
            Box<dyn std::future::Future<Output = Result<smgglrs_model::GenerateResponse, smgglrs_model::ModelError>> + Send + '_>,
        > {
            Box::pin(async {
                Err(smgglrs_model::ModelError::Inference("mock failure".into()))
            })
        }
    }

    #[tokio::test]
    async fn synthesize_with_model_extracts_fact_and_insight() {
        let model_json = r#"[
            {
                "kind": "Fact",
                "title": "Rust memory safety",
                "content": "Rust provides memory safety without garbage collection",
                "tags": ["rust", "memory"],
                "confidence": 0.95
            },
            {
                "kind": "Insight",
                "title": "User prefers Rust",
                "content": "The user shows a strong preference for Rust-based tooling",
                "tags": ["preference"],
                "confidence": 0.8
            }
        ]"#;

        let wm = WorkingMemory::open_memory().unwrap();
        wm.add_turn(&make_turn("s1", "I love Rust for its memory safety", 1000))
            .unwrap();
        wm.add_turn(&make_turn("s1", "I always choose Rust for new projects", 2000))
            .unwrap();

        let ks = KnowledgeStore::open_memory().unwrap();
        let model: Arc<dyn smgglrs_model::ModelBackend> =
            Arc::new(MockModelBackend::new(model_json));
        let pipeline = DistillationPipeline::new(&wm, &ks).with_model(model);

        let segments = pipeline.ingest("s1").unwrap();
        assert_eq!(segments.len(), 1);

        let entries = pipeline.synthesize(&segments[0]).await.unwrap();
        assert_eq!(entries.len(), 2);

        assert_eq!(entries[0].kind, MemoryType::Fact);
        assert_eq!(entries[0].title, "Rust memory safety");
        assert_eq!(
            entries[0].content,
            "Rust provides memory safety without garbage collection"
        );
        assert_eq!(entries[0].tags, vec!["rust", "memory"]);
        assert!((entries[0].confidence - 0.95).abs() < f64::EPSILON);

        assert_eq!(entries[1].kind, MemoryType::Insight);
        assert_eq!(entries[1].title, "User prefers Rust");
        assert!((entries[1].confidence - 0.8).abs() < f64::EPSILON);
    }

    #[tokio::test]
    async fn full_pipeline_with_model_stores_entries() {
        let model_json = r#"[
            {
                "kind": "Fact",
                "title": "Sky color",
                "content": "The sky is blue due to Rayleigh scattering",
                "tags": ["science"],
                "confidence": 0.9
            },
            {
                "kind": "Insight",
                "title": "User curious about science",
                "content": "The user asks about natural phenomena",
                "tags": ["interest"],
                "confidence": 0.75
            }
        ]"#;

        let wm = WorkingMemory::open_memory().unwrap();
        wm.add_turn(&make_turn("s1", "Why is the sky blue?", 1000))
            .unwrap();

        let ks = KnowledgeStore::open_memory().unwrap();
        let model: Arc<dyn smgglrs_model::ModelBackend> =
            Arc::new(MockModelBackend::new(model_json));
        let pipeline = DistillationPipeline::new(&wm, &ks).with_model(model);

        let stored = pipeline.run("s1").await.unwrap();
        assert_eq!(stored, 2);
        assert_eq!(ks.count().unwrap(), 2);
    }

    #[tokio::test]
    async fn synthesize_with_failing_model_falls_back_to_stub() {
        let wm = WorkingMemory::open_memory().unwrap();
        wm.add_turn(&make_turn("s1", "Hello world", 1000)).unwrap();

        let ks = KnowledgeStore::open_memory().unwrap();
        let model: Arc<dyn smgglrs_model::ModelBackend> = Arc::new(FailingModelBackend);
        let pipeline = DistillationPipeline::new(&wm, &ks).with_model(model);

        let segments = pipeline.ingest("s1").unwrap();
        let entries = pipeline.synthesize(&segments[0]).await.unwrap();

        // Should fall back to stub: one Fact per user message
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].kind, MemoryType::Fact);
        assert!((entries[0].confidence - 0.5).abs() < f64::EPSILON);
        assert_eq!(entries[0].content, "Hello world");
    }

    #[tokio::test]
    async fn synthesize_with_invalid_json_falls_back_to_stub() {
        let wm = WorkingMemory::open_memory().unwrap();
        wm.add_turn(&make_turn("s1", "Test message", 1000)).unwrap();

        let ks = KnowledgeStore::open_memory().unwrap();
        let model: Arc<dyn smgglrs_model::ModelBackend> =
            Arc::new(MockModelBackend::new("not valid json"));
        let pipeline = DistillationPipeline::new(&wm, &ks).with_model(model);

        let segments = pipeline.ingest("s1").unwrap();
        let entries = pipeline.synthesize(&segments[0]).await.unwrap();

        // Should fall back to stub
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].kind, MemoryType::Fact);
        assert!((entries[0].confidence - 0.5).abs() < f64::EPSILON);
    }

    #[test]
    fn export_markdown_creates_files() {
        let wm = WorkingMemory::open_memory().unwrap();
        let ks = KnowledgeStore::open_memory().unwrap();
        let pipeline = DistillationPipeline::new(&wm, &ks);

        let entries = vec![
            DistilledEntry::new(
                MemoryType::Fact,
                "Project uses PostgreSQL 16".to_string(),
                "Project uses PostgreSQL 16 for the main data store.\nThe connection pool is configured with max 20 connections.".to_string(),
                vec!["database".to_string(), "infrastructure".to_string()],
                0.85,
                "sess-abc123".to_string(),
            ),
            DistilledEntry::new(
                MemoryType::Insight,
                "User prefers Rust".to_string(),
                "The user consistently chooses Rust for new projects.".to_string(),
                vec!["preference".to_string()],
                0.9,
                "sess-def456".to_string(),
            ),
        ];

        let dir = tempfile::tempdir().unwrap();
        let count = pipeline.export_markdown(&entries, dir.path()).unwrap();
        assert_eq!(count, 2);

        let files: Vec<_> = std::fs::read_dir(dir.path())
            .unwrap()
            .filter_map(|e| e.ok())
            .collect();
        assert_eq!(files.len(), 2);

        // Check that expected filenames exist
        let names: Vec<String> = files.iter().map(|f| f.file_name().to_string_lossy().to_string()).collect();
        assert!(names.iter().any(|n| n.starts_with("fact_")));
        assert!(names.iter().any(|n| n.starts_with("insight_")));
    }

    #[test]
    fn export_markdown_frontmatter_is_valid_yaml() {
        let wm = WorkingMemory::open_memory().unwrap();
        let ks = KnowledgeStore::open_memory().unwrap();
        let pipeline = DistillationPipeline::new(&wm, &ks);

        let entries = vec![DistilledEntry::new(
            MemoryType::Fact,
            "Sky is blue".to_string(),
            "The sky appears blue due to Rayleigh scattering.".to_string(),
            vec!["science".to_string(), "nature".to_string()],
            0.95,
            "sess-001".to_string(),
        )];

        let dir = tempfile::tempdir().unwrap();
        pipeline.export_markdown(&entries, dir.path()).unwrap();

        let file_path = dir.path().join("fact_sky_is_blue.md");
        let content = std::fs::read_to_string(&file_path).unwrap();

        // Extract frontmatter between --- delimiters
        let parts: Vec<&str> = content.splitn(3, "---").collect();
        assert_eq!(parts.len(), 3, "expected YAML frontmatter delimiters");

        let frontmatter = parts[1].trim();
        // Parse as YAML to verify validity
        let yaml: serde_json::Value = serde_yaml::from_str(frontmatter).unwrap();
        assert_eq!(yaml["type"], "fact");
        assert_eq!(yaml["name"], "Sky is blue");
        assert_eq!(yaml["source_session"], "sess-001");
        assert_eq!(yaml["confidence"], 0.95);
        assert_eq!(yaml["tags"][0], "science");
        assert_eq!(yaml["tags"][1], "nature");
    }

    #[test]
    fn export_markdown_content_matches_entry() {
        let wm = WorkingMemory::open_memory().unwrap();
        let ks = KnowledgeStore::open_memory().unwrap();
        let pipeline = DistillationPipeline::new(&wm, &ks);

        let body = "PostgreSQL 16 is the primary database.\nMax pool size is 20.";
        let entries = vec![DistilledEntry::new(
            MemoryType::Event,
            "DB migration done".to_string(),
            body.to_string(),
            vec![],
            0.7,
            "sess-xyz".to_string(),
        )];

        let dir = tempfile::tempdir().unwrap();
        pipeline.export_markdown(&entries, dir.path()).unwrap();

        let file_path = dir.path().join("event_db_migration_done.md");
        let content = std::fs::read_to_string(&file_path).unwrap();

        // Body appears after the closing ---
        let parts: Vec<&str> = content.splitn(3, "---").collect();
        let markdown_body = parts[2].trim();
        assert_eq!(markdown_body, body);
    }

    /// A mock sanitizer that replaces "secret" with "[REDACTED:test]".
    fn mock_sanitizer() -> ContentSanitizer {
        Arc::new(|content: &str| content.replace("secret", "[REDACTED:test]"))
    }

    #[test]
    fn export_markdown_with_sanitizer_redacts_content() {
        let wm = WorkingMemory::open_memory().unwrap();
        let ks = KnowledgeStore::open_memory().unwrap();
        let pipeline = DistillationPipeline::new(&wm, &ks)
            .with_sanitizer(mock_sanitizer());

        let entries = vec![DistilledEntry::new(
            MemoryType::Fact,
            "Has a secret".to_string(),
            "The secret is 42".to_string(),
            vec![],
            0.9,
            "sess-1".to_string(),
        )];

        let dir = tempfile::tempdir().unwrap();
        let count = pipeline.export_markdown(&entries, dir.path()).unwrap();
        assert_eq!(count, 1);

        let files: Vec<_> = std::fs::read_dir(dir.path())
            .unwrap()
            .filter_map(|e| e.ok())
            .collect();
        let content = std::fs::read_to_string(files[0].path()).unwrap();
        assert!(!content.contains("secret"), "Expected 'secret' redacted in markdown output: {content}");
        assert!(content.contains("[REDACTED:test]"));
    }

    #[tokio::test]
    async fn forge_with_sanitizer_redacts_stored_content() {
        let wm = WorkingMemory::open_memory().unwrap();
        wm.add_turn(&make_turn("s1", "The secret is 42", 1000)).unwrap();

        let ks = KnowledgeStore::open_memory().unwrap();
        let pipeline = DistillationPipeline::new(&wm, &ks)
            .with_sanitizer(mock_sanitizer());

        let stored = pipeline.run("s1").await.unwrap();
        assert_eq!(stored, 1);

        let entries = ks.list(None).unwrap();
        assert_eq!(entries.len(), 1);
        assert!(!entries[0].content.contains("secret"),
            "Expected 'secret' redacted in knowledge store: {}", entries[0].content);
        assert!(entries[0].content.contains("[REDACTED:test]"));
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

    #[test]
    fn failure_insight_produces_correct_format() {
        let insight = extract_failure_insight(
            "deploy_app",
            "Deploy the application to production",
            "Connection refused on port 443",
            &[
                ("Timeout after 30s".to_string(), "partial output".to_string()),
                ("Connection refused on port 443".to_string(), String::new()),
            ],
        );

        assert_eq!(insight.kind, MemoryType::Insight);
        assert_eq!(insight.title, "Failure: deploy_app");
        assert!(insight.content.contains("deploy_app"));
        assert!(insight.content.contains("Connection refused"));
        assert!(insight.content.contains("Attempt 1"));
        assert!(insight.content.contains("Attempt 2"));
        assert_eq!(insight.tags, vec!["failure", "lesson"]);
        assert!((insight.confidence - 0.7).abs() < f64::EPSILON);
    }

    #[test]
    fn failure_insight_with_empty_history() {
        let insight = extract_failure_insight(
            "build",
            "Build the project",
            "Compilation error",
            &[],
        );

        assert!(insight.content.contains("Compilation error"));
        assert!(insight.content.contains("build"));
        assert_eq!(insight.tags, vec!["failure", "lesson"]);
    }

    #[test]
    fn success_insight_produces_correct_format() {
        let insight = extract_success_insight(
            "analyze_code",
            "Analyze the codebase for security issues",
            "Found 3 vulnerabilities: SQL injection in login.rs, XSS in template.rs, path traversal in files.rs",
            2,
        );

        assert_eq!(insight.kind, MemoryType::Insight);
        assert_eq!(insight.title, "Success: analyze_code");
        assert!(insight.content.contains("analyze_code"));
        assert!(insight.content.contains("2 iteration(s)"));
        assert!(insight.content.contains("3 vulnerabilities"));
        assert_eq!(insight.tags, vec!["success", "strategy"]);
        assert!((insight.confidence - 0.85).abs() < f64::EPSILON);
    }

    #[test]
    fn success_insight_truncates_long_result() {
        let long_result = "x".repeat(300);
        let insight = extract_success_insight(
            "task",
            "Do something",
            &long_result,
            1,
        );

        // Content should be truncated (200 chars + "...")
        assert!(insight.content.len() < 400);
        assert!(insight.content.contains("..."));
    }

    #[test]
    fn failure_insight_is_searchable_by_tags() {
        let ks = KnowledgeStore::open_memory().unwrap();
        let insight = extract_failure_insight(
            "deploy",
            "Deploy app",
            "Port conflict",
            &[],
        );
        ks.store_distilled(&insight).unwrap();

        let results = ks.search_with_tags("deploy", &["failure"]).unwrap();
        assert_eq!(results.len(), 1);
        assert!(results[0].tags.contains(&"failure".to_string()));
        assert!(results[0].tags.contains(&"lesson".to_string()));
    }

    #[test]
    fn insights_superseded_by_same_task_pattern() {
        let ks = KnowledgeStore::open_memory().unwrap();

        let insight1 = extract_failure_insight(
            "deploy",
            "Deploy app",
            "Port conflict",
            &[],
        );
        let gen1 = ks.store_distilled_with_generation(&insight1).unwrap();
        assert_eq!(gen1, 1);

        // Same title -> same content_key -> supersession
        let insight2 = extract_failure_insight(
            "deploy",
            "Deploy app",
            "Memory limit exceeded",
            &[],
        );
        let gen2 = ks.store_distilled_with_generation(&insight2).unwrap();
        assert_eq!(gen2, 2);

        // Only one entry should exist
        assert_eq!(ks.count().unwrap(), 1);

        // Content should be updated
        let entry = ks.query_by_key(&insight2.content_key).unwrap().unwrap();
        assert!(entry.content.contains("Memory limit exceeded"));
    }

    #[test]
    fn strategy_generation_tracks_evolution() {
        let ks = KnowledgeStore::open_memory().unwrap();

        let insight = extract_success_insight(
            "build",
            "Build project",
            "All tests pass",
            1,
        );

        ks.store_distilled_with_generation(&insight).unwrap();
        assert_eq!(ks.strategy_generation_of(&insight.content_key).unwrap(), Some(1));

        // Supersede with updated insight
        let updated = DistilledEntry {
            content: "Build with --release flag for better performance".to_string(),
            ..insight.clone()
        };
        ks.store_distilled_with_generation(&updated).unwrap();
        assert_eq!(ks.strategy_generation_of(&insight.content_key).unwrap(), Some(2));

        // Third evolution
        ks.store_distilled_with_generation(&updated).unwrap();
        assert_eq!(ks.strategy_generation_of(&insight.content_key).unwrap(), Some(3));
    }

    #[test]
    fn retrieval_returns_most_relevant_insight_k1() {
        let ks = KnowledgeStore::open_memory().unwrap();

        // Store multiple insights
        let insight1 = extract_failure_insight(
            "deploy_app",
            "Deploy the web application",
            "Port 443 already in use",
            &[],
        );
        ks.store_distilled(&insight1).unwrap();

        let insight2 = extract_success_insight(
            "build_project",
            "Build the Rust project",
            "Clean build succeeded",
            1,
        );
        ks.store_distilled(&insight2).unwrap();

        let insight3 = extract_failure_insight(
            "deploy_staging",
            "Deploy to staging environment",
            "TLS certificate expired",
            &[],
        );
        ks.store_distilled(&insight3).unwrap();

        // Search for deploy-related insights, k=1
        let retriever = crate::retrieval::MemoryRetriever::new(&ks);
        let results = retriever.retrieve("deploy application", 1).unwrap();
        assert_eq!(results.len(), 1);
        // Should find a deploy-related insight
        assert!(
            results[0].entry.title.contains("deploy")
                || results[0].entry.content.contains("deploy"),
            "Expected deploy-related insight, got: {}",
            results[0].entry.title,
        );
    }
}
