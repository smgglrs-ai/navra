//! Composable skill source pipeline.
//!
//! Allows loading [`SkillCard`]s from multiple sources (directories,
//! registries, in-memory collections) and merging them with
//! deduplication and optional allow-list filtering.

use std::collections::HashSet;
use std::path::PathBuf;

use crate::types::SkillCard;

/// A source of skill cards.
pub trait SkillSource: Send + Sync {
    /// Load all skill cards from this source.
    fn load(&self) -> Vec<SkillCard>;

    /// Human-readable name for this source (used in logs).
    fn name(&self) -> &str;
}

/// Loads skill cards from a directory of YAML files.
pub struct DirectorySource {
    path: PathBuf,
    label: String,
}

impl DirectorySource {
    /// Create a new directory source.
    pub fn new(path: PathBuf) -> Self {
        let label = format!("dir:{}", path.display());
        Self { path, label }
    }
}

impl SkillSource for DirectorySource {
    fn load(&self) -> Vec<SkillCard> {
        crate::weaver::load_skill_cards(&self.path)
    }

    fn name(&self) -> &str {
        &self.label
    }
}

/// Merges skill cards from multiple sources with deduplication and filtering.
pub struct SkillPipeline {
    sources: Vec<Box<dyn SkillSource>>,
    allowed: Option<HashSet<String>>,
}

impl Default for SkillPipeline {
    fn default() -> Self {
        Self::new()
    }
}

impl SkillPipeline {
    /// Create an empty pipeline.
    pub fn new() -> Self {
        Self {
            sources: Vec::new(),
            allowed: None,
        }
    }

    /// Append a skill source.
    pub fn add_source(mut self, source: Box<dyn SkillSource>) -> Self {
        self.sources.push(source);
        self
    }

    /// Restrict output to only these skill names.
    pub fn with_allowed(mut self, names: HashSet<String>) -> Self {
        self.allowed = Some(names);
        self
    }

    /// Load from all sources, deduplicate by name (first wins), and
    /// filter by the allow set if configured.
    pub fn load_all(&self) -> Vec<SkillCard> {
        let mut seen = HashSet::new();
        let mut cards = Vec::new();

        for source in &self.sources {
            for card in source.load() {
                if seen.insert(card.name.clone()) {
                    cards.push(card);
                }
            }
        }

        if let Some(ref allowed) = self.allowed {
            cards.retain(|c| allowed.contains(&c.name));
        }

        cards
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct MockSource {
        label: String,
        cards: Vec<SkillCard>,
    }

    impl MockSource {
        fn new(label: &str, cards: Vec<SkillCard>) -> Self {
            Self {
                label: label.to_string(),
                cards,
            }
        }
    }

    impl SkillSource for MockSource {
        fn load(&self) -> Vec<SkillCard> {
            self.cards.clone()
        }

        fn name(&self) -> &str {
            &self.label
        }
    }

    fn card(name: &str, content: &str) -> SkillCard {
        SkillCard {
            name: name.to_string(),
            keywords: vec![],
            content: content.to_string(),
        }
    }

    #[test]
    fn pipeline_dedup_by_name() {
        let p = SkillPipeline::new()
            .add_source(Box::new(MockSource::new(
                "a",
                vec![card("git", "first"), card("file", "first")],
            )))
            .add_source(Box::new(MockSource::new(
                "b",
                vec![card("git", "second"), card("exec", "second")],
            )));

        let result = p.load_all();
        assert_eq!(result.len(), 3);
        assert_eq!(result[0].content, "first"); // git from source a
        assert_eq!(result[2].name, "exec");
    }

    #[test]
    fn pipeline_acl_filters() {
        let allowed: HashSet<String> = ["git".to_string()].into_iter().collect();
        let p = SkillPipeline::new()
            .add_source(Box::new(MockSource::new(
                "a",
                vec![card("git", "g"), card("file", "f")],
            )))
            .with_allowed(allowed);

        let result = p.load_all();
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].name, "git");
    }

    #[test]
    fn pipeline_empty_sources() {
        let p = SkillPipeline::new();
        assert!(p.load_all().is_empty());
    }

    #[test]
    fn directory_source_loads() {
        let dir = tempfile::tempdir().unwrap();
        let yaml = "name: test_skill\nkeywords: [test]\ncontent: do the thing\n";
        std::fs::write(dir.path().join("skill.yaml"), yaml).unwrap();

        let src = DirectorySource::new(dir.path().to_path_buf());
        let cards = src.load();
        assert_eq!(cards.len(), 1);
        assert_eq!(cards[0].name, "test_skill");
    }
}
