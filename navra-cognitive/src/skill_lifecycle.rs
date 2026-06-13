//! Skill lifecycle management: creation, testing, registry, per-skill memory, IFC labeling.

use std::collections::HashMap;
use std::fmt;

use navra_protocol::label::{Confidentiality, DataLabel, Integrity};
use serde::{Deserialize, Serialize};

use crate::types::SkillCard;
use crate::weaver::select_skill_cards;

/// A managed skill with lifecycle metadata, IFC label, and experience memory.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Skill {
    /// The underlying skill card (name, keywords, content).
    pub card: SkillCard,
    /// Monotonically increasing version number.
    pub version: u32,
    /// Model that generated this skill (if AI-authored).
    pub created_by_model: Option<String>,
    /// IFC integrity label: Trusted (human-authored) or Untrusted (generated/downloaded).
    pub integrity: Integrity,
    /// Whether the skill has passed structural validation.
    pub test_status: TestStatus,
    /// Per-skill experience log recording usage outcomes.
    pub memory: Vec<SkillMemoryEntry>,
}

impl Skill {
    /// Return the IFC data label for this skill.
    pub fn ifc_label(&self) -> DataLabel {
        DataLabel {
            integrity: self.integrity,
            confidentiality: Confidentiality::Public,
        }
    }
}

/// Validation status of a skill.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum TestStatus {
    /// Not yet validated.
    Untested,
    /// Passed structural validation.
    Passed,
    /// Failed validation with a reason.
    Failed(String),
}

/// A record of a skill being used in a task.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SkillMemoryEntry {
    /// Unix timestamp of the usage.
    pub timestamp: i64,
    /// Description of the task that used this skill.
    pub task: String,
    /// Outcome of the usage.
    pub outcome: SkillOutcome,
    /// Lessons learned or notes from this usage.
    pub notes: String,
}

/// Outcome of a skill usage.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum SkillOutcome {
    /// The skill contributed to a successful task completion.
    Success,
    /// The skill did not help or caused issues.
    Failure,
    /// The skill partially helped.
    PartialSuccess,
}

/// Registry for managing skill lifecycle.
pub struct SkillRegistry {
    skills: HashMap<String, Skill>,
    require_tests: bool,
}

impl SkillRegistry {
    /// Create a new registry.
    ///
    /// When `require_tests` is true, only skills with `TestStatus::Passed`
    /// can be registered or selected.
    pub fn new(require_tests: bool) -> Self {
        Self {
            skills: HashMap::new(),
            require_tests,
        }
    }

    /// Register a skill in the registry.
    ///
    /// If `require_tests` is enabled and the skill has not passed validation,
    /// registration is rejected. When a skill with the same name already
    /// exists, the newer version replaces the older one.
    pub fn register(&mut self, skill: Skill) -> Result<(), SkillError> {
        if self.require_tests && skill.test_status != TestStatus::Passed {
            return Err(SkillError::TestRequired(skill.card.name.clone()));
        }

        if skill.integrity == Integrity::Untrusted {
            tracing::warn!(
                skill = %skill.card.name,
                "Registering skill with Untrusted integrity label"
            );
        }

        self.skills.insert(skill.card.name.clone(), skill);
        Ok(())
    }

    /// Look up a skill by name.
    pub fn get(&self, name: &str) -> Option<&Skill> {
        self.skills.get(name)
    }

    /// Select skills matching a task description.
    ///
    /// Delegates to `select_skill_cards` for keyword matching, then
    /// filters by test status when `require_tests` is enabled.
    pub fn select(&self, task: &str, limit: usize, token_budget: usize) -> Vec<&Skill> {
        let candidates: Vec<&Skill> = if self.require_tests {
            self.skills
                .values()
                .filter(|s| s.test_status == TestStatus::Passed)
                .collect()
        } else {
            self.skills.values().collect()
        };

        let cards: Vec<SkillCard> = candidates.iter().map(|s| s.card.clone()).collect();
        let selected = select_skill_cards(&cards, task, limit, token_budget as u32);

        selected
            .into_iter()
            .filter_map(|card| self.skills.get(&card.name))
            .collect()
    }

    /// Record a usage entry in a skill's memory log.
    pub fn record_usage(&mut self, name: &str, entry: SkillMemoryEntry) {
        if let Some(skill) = self.skills.get_mut(name) {
            skill.memory.push(entry);
        }
    }

    /// Remove a skill from the registry, returning it if it existed.
    pub fn unregister(&mut self, name: &str) -> Option<Skill> {
        self.skills.remove(name)
    }

    /// List all registered skills.
    pub fn list(&self) -> Vec<&Skill> {
        self.skills.values().collect()
    }

    /// List skills filtered by IFC integrity label.
    pub fn list_by_integrity(&self, integrity: Integrity) -> Vec<&Skill> {
        self.skills
            .values()
            .filter(|s| s.integrity == integrity)
            .collect()
    }
}

/// Errors from skill registry operations.
#[derive(Debug)]
pub enum SkillError {
    /// The skill must pass validation before registration.
    TestRequired(String),
}

impl fmt::Display for SkillError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TestRequired(name) => {
                write!(f, "skill '{name}' must pass tests before registration")
            }
        }
    }
}

impl std::error::Error for SkillError {}

/// A test case for structural validation of a skill.
pub struct SkillTest {
    /// Test name.
    pub name: String,
    /// Test input/scenario description.
    pub input: String,
    /// Expected substring that should appear in the skill content.
    pub expected: String,
}

/// Minimum content length in characters (~80 tokens).
const MIN_CONTENT_CHARS: usize = 320;
/// Maximum content length in characters (~500 tokens).
const MAX_CONTENT_CHARS: usize = 2000;

/// Validate a skill's structure and test expectations.
///
/// Checks:
/// - `card.name` is non-empty and a valid identifier (alphanumeric + underscore)
/// - `card.keywords` is non-empty
/// - `card.content` length is within 320-2000 characters (~80-500 tokens)
/// - Each test's `expected` substring appears in the content
pub fn validate_skill(skill: &Skill, tests: &[SkillTest]) -> TestStatus {
    if skill.card.name.is_empty() {
        return TestStatus::Failed("skill name is empty".into());
    }

    if !skill
        .card
        .name
        .chars()
        .all(|c| c.is_alphanumeric() || c == '_')
    {
        return TestStatus::Failed(format!(
            "skill name '{}' contains invalid characters",
            skill.card.name
        ));
    }

    if skill.card.keywords.is_empty() {
        return TestStatus::Failed("keywords are empty".into());
    }

    let content_len = skill.card.content.len();
    if content_len < MIN_CONTENT_CHARS {
        return TestStatus::Failed(format!(
            "content too short ({content_len} chars, minimum {MIN_CONTENT_CHARS})"
        ));
    }
    if content_len > MAX_CONTENT_CHARS {
        return TestStatus::Failed(format!(
            "content too long ({content_len} chars, maximum {MAX_CONTENT_CHARS})"
        ));
    }

    for test in tests {
        if !skill.card.content.contains(&test.expected) {
            return TestStatus::Failed(format!(
                "test '{}': expected substring '{}' not found in content",
                test.name, test.expected
            ));
        }
    }

    TestStatus::Passed
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_skill(name: &str, keywords: Vec<&str>, content: &str) -> Skill {
        Skill {
            card: SkillCard {
                name: name.to_string(),
                keywords: keywords.into_iter().map(String::from).collect(),
                content: content.to_string(),
            },
            version: 1,
            created_by_model: None,
            integrity: Integrity::Trusted,
            test_status: TestStatus::Passed,
            memory: Vec::new(),
        }
    }

    fn valid_content() -> String {
        "Use file_read to read files. Always check if the file exists before reading. \
         Handle errors gracefully and report them to the user. When writing files use \
         file_write with the full path. Never overwrite without confirmation. Check \
         permissions before attempting write operations. For large files, consider \
         reading in chunks to avoid memory issues. Always close file handles properly."
            .to_string()
    }

    #[test]
    fn register_tested_skill() {
        let mut reg = SkillRegistry::new(true);
        let skill = make_skill("file_ops", vec!["file", "read"], &valid_content());
        assert!(reg.register(skill).is_ok());
        assert!(reg.get("file_ops").is_some());
    }

    #[test]
    fn register_untested_blocked() {
        let mut reg = SkillRegistry::new(true);
        let mut skill = make_skill("file_ops", vec!["file"], &valid_content());
        skill.test_status = TestStatus::Untested;
        let err = reg.register(skill).unwrap_err();
        assert!(matches!(err, SkillError::TestRequired(_)));
    }

    #[test]
    fn register_untested_allowed() {
        let mut reg = SkillRegistry::new(false);
        let mut skill = make_skill("file_ops", vec!["file"], &valid_content());
        skill.test_status = TestStatus::Untested;
        assert!(reg.register(skill).is_ok());
        assert!(reg.get("file_ops").is_some());
    }

    #[test]
    fn select_filters_by_task() {
        let mut reg = SkillRegistry::new(false);
        reg.register(make_skill(
            "file_ops",
            vec!["file", "read", "write"],
            &valid_content(),
        ))
        .unwrap();
        reg.register(make_skill(
            "git_workflow",
            vec!["git", "commit", "branch"],
            &"Use git_status to check repository state before making changes. \
              Always create a branch for new features. Commit frequently with \
              descriptive messages. Push to remote after committing. Review diffs \
              before staging. Never force push to main. Check for merge conflicts \
              before merging. Use rebase for linear history when appropriate."
                .to_string(),
        ))
        .unwrap();
        reg.register(make_skill(
            "security_check",
            vec!["security", "auth", "vulnerability"],
            &"Check for hardcoded secrets in source code. Validate all external \
              inputs before processing. Use parameterized queries for database \
              access. Apply principle of least privilege to all service accounts. \
              Review dependency versions for known vulnerabilities. Enable TLS \
              for all network communications. Audit authentication flows regularly."
                .to_string(),
        ))
        .unwrap();

        let selected = reg.select("read the config file", 3, 2000);
        assert_eq!(selected.len(), 1);
        assert_eq!(selected[0].card.name, "file_ops");
    }

    #[test]
    fn record_usage_appends_memory() {
        let mut reg = SkillRegistry::new(false);
        reg.register(make_skill("file_ops", vec!["file"], &valid_content()))
            .unwrap();

        reg.record_usage(
            "file_ops",
            SkillMemoryEntry {
                timestamp: 1000,
                task: "read config".into(),
                outcome: SkillOutcome::Success,
                notes: "worked well".into(),
            },
        );
        reg.record_usage(
            "file_ops",
            SkillMemoryEntry {
                timestamp: 2000,
                task: "write log".into(),
                outcome: SkillOutcome::PartialSuccess,
                notes: "needed retry".into(),
            },
        );

        let skill = reg.get("file_ops").unwrap();
        assert_eq!(skill.memory.len(), 2);
        assert_eq!(skill.memory[0].task, "read config");
        assert_eq!(skill.memory[1].outcome, SkillOutcome::PartialSuccess);
    }

    #[test]
    fn version_replaces_older() {
        let mut reg = SkillRegistry::new(false);
        let mut v1 = make_skill("file_ops", vec!["file"], &valid_content());
        v1.version = 1;
        reg.register(v1).unwrap();

        let mut v2 = make_skill("file_ops", vec!["file", "read"], &valid_content());
        v2.version = 2;
        reg.register(v2).unwrap();

        let skill = reg.get("file_ops").unwrap();
        assert_eq!(skill.version, 2);
        assert_eq!(skill.card.keywords.len(), 2);
    }

    #[test]
    fn unregister_removes() {
        let mut reg = SkillRegistry::new(false);
        reg.register(make_skill("file_ops", vec!["file"], &valid_content()))
            .unwrap();
        assert!(reg.get("file_ops").is_some());

        let removed = reg.unregister("file_ops");
        assert!(removed.is_some());
        assert!(reg.get("file_ops").is_none());
    }

    #[test]
    fn ifc_untrusted_skill_labeled() {
        let mut skill = make_skill("downloaded", vec!["test"], &valid_content());
        skill.integrity = Integrity::Untrusted;

        let label = skill.ifc_label();
        assert_eq!(label.integrity, Integrity::Untrusted);
        assert_eq!(label.confidentiality, Confidentiality::Public);
    }

    #[test]
    fn list_by_integrity_filters() {
        let mut reg = SkillRegistry::new(false);

        let trusted = make_skill("trusted_skill", vec!["safe"], &valid_content());
        reg.register(trusted).unwrap();

        let mut untrusted = make_skill("untrusted_skill", vec!["risky"], &valid_content());
        untrusted.integrity = Integrity::Untrusted;
        reg.register(untrusted).unwrap();

        let trusted_list = reg.list_by_integrity(Integrity::Trusted);
        assert_eq!(trusted_list.len(), 1);
        assert_eq!(trusted_list[0].card.name, "trusted_skill");

        let untrusted_list = reg.list_by_integrity(Integrity::Untrusted);
        assert_eq!(untrusted_list.len(), 1);
        assert_eq!(untrusted_list[0].card.name, "untrusted_skill");
    }

    #[test]
    fn validate_skill_checks_structure() {
        let skill = make_skill("file_ops", vec!["file", "read"], &valid_content());
        assert_eq!(validate_skill(&skill, &[]), TestStatus::Passed);

        let mut bad = make_skill("file_ops", vec![], &valid_content());
        bad.card.keywords.clear();
        let status = validate_skill(&bad, &[]);
        assert!(matches!(status, TestStatus::Failed(ref msg) if msg.contains("keywords")));
    }

    #[test]
    fn validate_skill_content_too_short() {
        let skill = make_skill("tiny", vec!["test"], "too short");
        let status = validate_skill(&skill, &[]);
        assert!(matches!(status, TestStatus::Failed(ref msg) if msg.contains("too short")));
    }

    #[test]
    fn validate_skill_content_too_long() {
        let long_content = "x".repeat(2001);
        let skill = make_skill("huge", vec!["test"], &long_content);
        let status = validate_skill(&skill, &[]);
        assert!(matches!(status, TestStatus::Failed(ref msg) if msg.contains("too long")));
    }

    #[test]
    fn validate_skill_test_expected_substring() {
        let skill = make_skill("file_ops", vec!["file"], &valid_content());
        let tests = vec![SkillTest {
            name: "mentions file_read".into(),
            input: "read a file".into(),
            expected: "file_read".into(),
        }];
        assert_eq!(validate_skill(&skill, &tests), TestStatus::Passed);

        let bad_tests = vec![SkillTest {
            name: "missing keyword".into(),
            input: "do something".into(),
            expected: "nonexistent_function".into(),
        }];
        let status = validate_skill(&skill, &bad_tests);
        assert!(
            matches!(status, TestStatus::Failed(ref msg) if msg.contains("nonexistent_function"))
        );
    }

    #[test]
    fn validate_skill_invalid_name() {
        let skill = make_skill("", vec!["test"], &valid_content());
        let status = validate_skill(&skill, &[]);
        assert!(matches!(status, TestStatus::Failed(ref msg) if msg.contains("name is empty")));

        let mut bad_name = make_skill("valid", vec!["test"], &valid_content());
        bad_name.card.name = "has-dashes".into();
        let status = validate_skill(&bad_name, &[]);
        assert!(
            matches!(status, TestStatus::Failed(ref msg) if msg.contains("invalid characters"))
        );
    }

    #[test]
    fn skill_serialize_roundtrip() {
        let skill = make_skill("file_ops", vec!["file", "read"], &valid_content());
        let json = serde_json::to_string(&skill).unwrap();
        let back: Skill = serde_json::from_str(&json).unwrap();
        assert_eq!(back.card.name, "file_ops");
        assert_eq!(back.version, 1);
        assert_eq!(back.integrity, Integrity::Trusted);
        assert_eq!(back.test_status, TestStatus::Passed);
    }
}
