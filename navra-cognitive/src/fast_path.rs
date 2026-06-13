//! Early commitment fast paths for task classification.
//!
//! Classifies incoming prompts against known task patterns and
//! constrains the tool set and iteration count for recognized tasks.
//! Reduces token burn on well-understood task types.

use serde::{Deserialize, Serialize};

/// A fast path definition: recognized task pattern with constraints.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FastPath {
    pub name: String,
    pub keywords: Vec<String>,
    pub constrained_tools: Vec<String>,
    pub max_iterations: usize,
    pub temperature: Option<f32>,
}

/// Result of task classification against fast paths.
#[derive(Debug, Clone)]
pub enum ClassifyResult {
    FastPath(FastPath),
    FullReasoning,
}

/// Classify a task prompt against a list of fast paths.
///
/// Uses keyword overlap: if >= `threshold` fraction of a fast path's
/// keywords appear in the prompt, that fast path matches.
/// Returns the best match or `FullReasoning` if none match.
pub fn classify_task(prompt: &str, fast_paths: &[FastPath], threshold: f64) -> ClassifyResult {
    let lower = prompt.to_lowercase();
    let prompt_words: Vec<&str> = lower
        .split(|c: char| !c.is_alphanumeric())
        .filter(|w| w.len() > 2)
        .collect();

    let mut best: Option<(&FastPath, f64)> = None;

    for fp in fast_paths {
        if fp.keywords.is_empty() {
            continue;
        }
        let matched = fp
            .keywords
            .iter()
            .filter(|kw| prompt_words.iter().any(|w| w.contains(kw.as_str())))
            .count();
        let score = matched as f64 / fp.keywords.len() as f64;

        if score >= threshold {
            if best.as_ref().is_none_or(|(_, s)| score > *s) {
                best = Some((fp, score));
            }
        }
    }

    match best {
        Some((fp, _)) => ClassifyResult::FastPath(fp.clone()),
        None => ClassifyResult::FullReasoning,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn review_path() -> FastPath {
        FastPath {
            name: "code-review".into(),
            keywords: vec!["review".into(), "code".into(), "quality".into()],
            constrained_tools: vec!["file_read".into(), "file_search".into()],
            max_iterations: 5,
            temperature: Some(0.1),
        }
    }

    fn deploy_path() -> FastPath {
        FastPath {
            name: "deploy".into(),
            keywords: vec!["deploy".into(), "production".into(), "release".into()],
            constrained_tools: vec!["git_status".into(), "git_push".into()],
            max_iterations: 3,
            temperature: Some(0.0),
        }
    }

    #[test]
    fn matches_review_task() {
        let paths = vec![review_path(), deploy_path()];
        let result = classify_task("Review the code quality of src/main.rs", &paths, 0.5);
        match result {
            ClassifyResult::FastPath(fp) => assert_eq!(fp.name, "code-review"),
            ClassifyResult::FullReasoning => panic!("expected fast path match"),
        }
    }

    #[test]
    fn matches_deploy_task() {
        let paths = vec![review_path(), deploy_path()];
        let result = classify_task("Deploy to production and create a release", &paths, 0.5);
        match result {
            ClassifyResult::FastPath(fp) => assert_eq!(fp.name, "deploy"),
            ClassifyResult::FullReasoning => panic!("expected fast path match"),
        }
    }

    #[test]
    fn no_match_returns_full_reasoning() {
        let paths = vec![review_path(), deploy_path()];
        let result = classify_task("Explain how ownership works in Rust", &paths, 0.5);
        assert!(matches!(result, ClassifyResult::FullReasoning));
    }

    #[test]
    fn empty_paths_returns_full_reasoning() {
        let result = classify_task("anything", &[], 0.5);
        assert!(matches!(result, ClassifyResult::FullReasoning));
    }

    #[test]
    fn threshold_controls_match_sensitivity() {
        let paths = vec![FastPath {
            name: "strict".into(),
            keywords: vec![
                "alpha".into(),
                "beta".into(),
                "gamma".into(),
                "delta".into(),
            ],
            constrained_tools: vec![],
            max_iterations: 3,
            temperature: None,
        }];

        // Only 1/4 keywords match — below 0.5 threshold
        let result = classify_task("alpha is important", &paths, 0.5);
        assert!(matches!(result, ClassifyResult::FullReasoning));

        // Same prompt with lower threshold
        let result = classify_task("alpha is important", &paths, 0.2);
        match result {
            ClassifyResult::FastPath(fp) => assert_eq!(fp.name, "strict"),
            ClassifyResult::FullReasoning => panic!("expected match at 0.2 threshold"),
        }
    }

    #[test]
    fn serialization_roundtrip() {
        let fp = review_path();
        let json = serde_json::to_string(&fp).unwrap();
        let back: FastPath = serde_json::from_str(&json).unwrap();
        assert_eq!(back.name, "code-review");
        assert_eq!(back.constrained_tools.len(), 2);
    }
}
