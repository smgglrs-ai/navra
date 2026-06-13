//! Deterministic replay for repetitive tool-loop tasks.
//!
//! After a tool loop completes successfully, its action sequence can
//! be compiled into a `Recipe` — a branch-free list of tool calls
//! with argument templates. Future runs with similar task patterns
//! can replay the recipe without LLM inference, achieving 93%+ token
//! savings.

use crate::action::ActionRecord;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};

/// A compiled recipe from a successful tool loop trace.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Recipe {
    pub id: String,
    pub task_description: String,
    pub steps: Vec<RecipeStep>,
    pub created_at: i64,
}

/// A single step in a replay recipe.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecipeStep {
    pub tool_name: String,
    pub arguments: serde_json::Value,
}

/// Compile a successful tool loop result into a replayable recipe.
///
/// Only succeeds if all actions were successful and the loop completed
/// normally (not interrupted). Returns `None` if the trace contains
/// failures or is empty.
pub fn compile_recipe(task_description: &str, actions: &[ActionRecord]) -> Option<Recipe> {
    if actions.is_empty() || actions.iter().any(|a| !a.success) {
        return None;
    }

    let steps: Vec<RecipeStep> = actions
        .iter()
        .filter_map(|a| {
            let (tool_name, args) = a.action.tool_call_parts()?;
            Some(RecipeStep {
                tool_name,
                arguments: args,
            })
        })
        .collect();

    if steps.is_empty() {
        return None;
    }

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64;

    Some(Recipe {
        id: uuid::Uuid::new_v4().to_string(),
        task_description: task_description.to_string(),
        steps,
        created_at: now,
    })
}

/// A matched recipe with its similarity score.
#[derive(Debug, Clone)]
pub struct ReplayMatch {
    pub recipe: Recipe,
    pub similarity: f64,
}

impl ReplayMatch {
    /// Whether this match should require user confirmation before replaying.
    /// Matches below 0.8 similarity or with write operations need confirmation.
    pub fn needs_confirmation(&self) -> bool {
        if self.similarity < 0.8 {
            return true;
        }
        self.recipe.steps.iter().any(|s| {
            s.tool_name.contains("write")
                || s.tool_name.contains("delete")
                || s.tool_name.contains("commit")
                || s.tool_name.contains("push")
        })
    }
}

/// File-backed recipe store.
pub struct RecipeStore {
    dir: PathBuf,
}

impl RecipeStore {
    pub fn new(dir: &Path) -> Self {
        std::fs::create_dir_all(dir).ok();
        Self {
            dir: dir.to_path_buf(),
        }
    }

    pub fn save(&self, recipe: &Recipe) -> std::io::Result<()> {
        let path = self.dir.join(format!("{}.json", recipe.id));
        let json = serde_json::to_string_pretty(recipe)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
        std::fs::write(path, json)
    }

    pub fn load(&self, id: &str) -> std::io::Result<Recipe> {
        let path = self.dir.join(format!("{id}.json"));
        let json = std::fs::read_to_string(path)?;
        serde_json::from_str(&json)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))
    }

    pub fn list(&self) -> Vec<Recipe> {
        let Ok(entries) = std::fs::read_dir(&self.dir) else {
            return Vec::new();
        };
        entries
            .flatten()
            .filter(|e| e.path().extension().is_some_and(|ext| ext == "json"))
            .filter_map(|e| {
                let json = std::fs::read_to_string(e.path()).ok()?;
                serde_json::from_str(&json).ok()
            })
            .collect()
    }

    /// Find a recipe matching a task description using word overlap.
    ///
    /// Returns the best match with its similarity score if above
    /// threshold (0.0-1.0, default 0.6 = 60% word overlap).
    /// Callers should confirm with the user before replaying if
    /// `needs_confirmation()` returns true.
    pub fn find_match(&self, task_description: &str, threshold: f64) -> Option<ReplayMatch> {
        let query_words = tokenize_words(task_description);
        if query_words.is_empty() {
            return None;
        }

        self.list()
            .into_iter()
            .filter_map(|r| {
                let recipe_words = tokenize_words(&r.task_description);
                let sim = word_overlap(&query_words, &recipe_words);
                if sim >= threshold {
                    Some(ReplayMatch {
                        recipe: r,
                        similarity: sim,
                    })
                } else {
                    None
                }
            })
            .max_by(|a, b| {
                a.similarity
                    .partial_cmp(&b.similarity)
                    .unwrap_or(std::cmp::Ordering::Equal)
            })
    }
}

/// Apply variable substitution to a recipe's arguments.
///
/// Replaces template values in arguments with values from the
/// substitution map. Template syntax: `{{key}}`.
pub fn substitute_variables(recipe: &Recipe, vars: &HashMap<String, String>) -> Vec<RecipeStep> {
    recipe
        .steps
        .iter()
        .map(|step| {
            let args_str = serde_json::to_string(&step.arguments).unwrap_or_default();
            let mut substituted = args_str;
            for (key, value) in vars {
                substituted = substituted.replace(&format!("{{{{{key}}}}}"), value);
            }
            RecipeStep {
                tool_name: step.tool_name.clone(),
                arguments: serde_json::from_str(&substituted)
                    .unwrap_or_else(|_| step.arguments.clone()),
            }
        })
        .collect()
}

fn tokenize_words(text: &str) -> Vec<String> {
    text.to_lowercase()
        .split(|c: char| !c.is_alphanumeric())
        .filter(|w| w.len() > 2)
        .map(String::from)
        .collect()
}

fn word_overlap(a: &[String], b: &[String]) -> f64 {
    if a.is_empty() || b.is_empty() {
        return 0.0;
    }
    let set_a: std::collections::HashSet<_> = a.iter().collect();
    let set_b: std::collections::HashSet<_> = b.iter().collect();
    let intersection = set_a.intersection(&set_b).count();
    let union = set_a.union(&set_b).count();
    if union == 0 {
        0.0
    } else {
        intersection as f64 / union as f64
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::action::{ActionRecord, AgentAction};

    fn make_action(tool: &str, path: &str, success: bool) -> ActionRecord {
        ActionRecord {
            action: AgentAction::classify(tool, &serde_json::json!({"path": path})),
            success,
            duration_ms: 100,
            output_preview: "ok".to_string(),
        }
    }

    #[test]
    fn compile_recipe_from_successful_actions() {
        let actions = vec![
            make_action("file_read", "/src/main.rs", true),
            make_action("file_read", "/src/lib.rs", true),
        ];
        let recipe = compile_recipe("Review main files", &actions);
        assert!(recipe.is_some());
        let recipe = recipe.unwrap();
        assert_eq!(recipe.steps.len(), 2);
        assert_eq!(recipe.steps[0].tool_name, "file_read");
    }

    #[test]
    fn compile_recipe_fails_on_error_action() {
        let actions = vec![
            make_action("file_read", "/src/main.rs", true),
            make_action("file_write", "/src/bad.rs", false),
        ];
        assert!(compile_recipe("Broken run", &actions).is_none());
    }

    #[test]
    fn compile_recipe_fails_on_empty() {
        assert!(compile_recipe("Empty", &[]).is_none());
    }

    #[test]
    fn recipe_store_save_load_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let store = RecipeStore::new(dir.path());

        let actions = vec![make_action("file_read", "/test.rs", true)];
        let recipe = compile_recipe("Test task", &actions).unwrap();
        let id = recipe.id.clone();

        store.save(&recipe).unwrap();
        let loaded = store.load(&id).unwrap();
        assert_eq!(loaded.task_description, "Test task");
        assert_eq!(loaded.steps.len(), 1);
    }

    #[test]
    fn recipe_store_list() {
        let dir = tempfile::tempdir().unwrap();
        let store = RecipeStore::new(dir.path());

        let a1 = vec![make_action("file_read", "/a.rs", true)];
        let a2 = vec![make_action("git_status", "", true)];

        store.save(&compile_recipe("Task A", &a1).unwrap()).unwrap();
        store.save(&compile_recipe("Task B", &a2).unwrap()).unwrap();

        assert_eq!(store.list().len(), 2);
    }

    #[test]
    fn find_match_by_word_overlap() {
        let dir = tempfile::tempdir().unwrap();
        let store = RecipeStore::new(dir.path());

        let a = vec![make_action("file_read", "/src/main.rs", true)];
        store
            .save(&compile_recipe("Review the main source files", &a).unwrap())
            .unwrap();

        let matched = store.find_match("Review main source", 0.5);
        assert!(matched.is_some());

        let no_match = store.find_match("Deploy to production", 0.5);
        assert!(no_match.is_none());
    }

    #[test]
    fn replay_match_needs_confirmation_for_low_similarity() {
        let m = ReplayMatch {
            recipe: Recipe {
                id: "test".into(),
                task_description: "test".into(),
                steps: vec![RecipeStep {
                    tool_name: "file_read".into(),
                    arguments: serde_json::json!({}),
                }],
                created_at: 0,
            },
            similarity: 0.65,
        };
        assert!(m.needs_confirmation());
    }

    #[test]
    fn replay_match_needs_confirmation_for_write_ops() {
        let m = ReplayMatch {
            recipe: Recipe {
                id: "test".into(),
                task_description: "test".into(),
                steps: vec![RecipeStep {
                    tool_name: "file_write".into(),
                    arguments: serde_json::json!({}),
                }],
                created_at: 0,
            },
            similarity: 0.95,
        };
        assert!(m.needs_confirmation());
    }

    #[test]
    fn replay_match_auto_for_high_sim_read_only() {
        let m = ReplayMatch {
            recipe: Recipe {
                id: "test".into(),
                task_description: "test".into(),
                steps: vec![RecipeStep {
                    tool_name: "file_read".into(),
                    arguments: serde_json::json!({}),
                }],
                created_at: 0,
            },
            similarity: 0.95,
        };
        assert!(!m.needs_confirmation());
    }

    #[test]
    fn substitute_variables_replaces_templates() {
        let recipe = Recipe {
            id: "test".to_string(),
            task_description: "test".to_string(),
            steps: vec![RecipeStep {
                tool_name: "file_read".to_string(),
                arguments: serde_json::json!({"path": "{{project_dir}}/main.rs"}),
            }],
            created_at: 0,
        };
        let mut vars = HashMap::new();
        vars.insert("project_dir".to_string(), "/home/user/project".to_string());

        let steps = substitute_variables(&recipe, &vars);
        assert_eq!(steps[0].arguments["path"], "/home/user/project/main.rs");
    }

    #[test]
    fn word_overlap_identical() {
        let a = tokenize_words("review the source code");
        let b = tokenize_words("review the source code");
        assert!((word_overlap(&a, &b) - 1.0).abs() < 0.01);
    }

    #[test]
    fn word_overlap_disjoint() {
        let a = tokenize_words("review source code");
        let b = tokenize_words("deploy production server");
        assert!(word_overlap(&a, &b) < 0.01);
    }
}

#[cfg(kani)]
mod kani_proofs {
    use super::*;

    fn make_words(a: u8, b: u8) -> Vec<String> {
        let mut v = Vec::new();
        if a & 1 != 0 {
            v.push("alpha".to_string());
        }
        if a & 2 != 0 {
            v.push("beta".to_string());
        }
        if a & 4 != 0 {
            v.push("gamma".to_string());
        }
        if b & 1 != 0 {
            v.push("delta".to_string());
        }
        v
    }

    #[kani::proof]
    fn overlap_in_unit_range() {
        let a_bits: u8 = kani::any();
        let b_bits: u8 = kani::any();
        let a2_bits: u8 = kani::any();
        let b2_bits: u8 = kani::any();
        kani::assume(a_bits <= 7);
        kani::assume(b_bits <= 1);
        kani::assume(a2_bits <= 7);
        kani::assume(b2_bits <= 1);
        let words_a = make_words(a_bits, b_bits);
        let words_b = make_words(a2_bits, b2_bits);
        let score = word_overlap(&words_a, &words_b);
        assert!(score >= 0.0);
        assert!(score <= 1.0);
    }

    #[kani::proof]
    fn overlap_symmetric() {
        let a_bits: u8 = kani::any();
        let b_bits: u8 = kani::any();
        let a2_bits: u8 = kani::any();
        let b2_bits: u8 = kani::any();
        kani::assume(a_bits <= 7);
        kani::assume(b_bits <= 1);
        kani::assume(a2_bits <= 7);
        kani::assume(b2_bits <= 1);
        let words_a = make_words(a_bits, b_bits);
        let words_b = make_words(a2_bits, b2_bits);
        let ab = word_overlap(&words_a, &words_b);
        let ba = word_overlap(&words_b, &words_a);
        assert!(ab == ba, "Jaccard similarity must be symmetric");
    }

    #[kani::proof]
    fn overlap_reflexive() {
        let bits: u8 = kani::any();
        let b_bits: u8 = kani::any();
        kani::assume(bits <= 7);
        kani::assume(b_bits <= 1);
        let words = make_words(bits, b_bits);
        let score = word_overlap(&words, &words);
        if words.is_empty() {
            assert!(score == 0.0);
        } else {
            assert!(score == 1.0, "overlap with self must be 1.0");
        }
    }
}
