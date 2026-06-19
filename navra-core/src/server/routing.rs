//! Multi-hypothesis tool routing for fuzzy tool name resolution.
//!
//! When an exact tool name match fails, scores registered tools using
//! edit distance and argument schema overlap to find the best match.

use std::collections::HashMap;

/// Configuration for tool routing behavior.
#[derive(Debug, Clone)]
pub struct ToolRoutingConfig {
    /// Score threshold for automatic routing (0.0–1.0). Default: disabled (0.0).
    pub auto_route_threshold: f32,
    /// Score threshold for including in suggestions (0.0–1.0). Default: 0.3.
    pub suggestion_threshold: f32,
    /// Enable/disable tool routing entirely.
    pub enabled: bool,
}

impl Default for ToolRoutingConfig {
    fn default() -> Self {
        Self {
            auto_route_threshold: 0.0,
            suggestion_threshold: 0.3,
            enabled: false,
        }
    }
}

/// A scored candidate match for a tool name.
#[derive(Debug, Clone)]
pub struct RoutingCandidate {
    pub name: String,
    pub score: f32,
    pub edit_distance: usize,
}

/// Find the best matching tools for an unknown tool name.
pub fn find_candidates(
    unknown_name: &str,
    registered_names: &[&str],
    request_args: &serde_json::Value,
    tool_schemas: &HashMap<String, Option<Vec<String>>>,
    config: &ToolRoutingConfig,
) -> Vec<RoutingCandidate> {
    if !config.enabled {
        return Vec::new();
    }

    let mut candidates: Vec<RoutingCandidate> = registered_names
        .iter()
        .filter_map(|name| {
            let dist = edit_distance(unknown_name, name);
            let max_len = unknown_name.len().max(name.len());
            if max_len == 0 {
                return None;
            }

            // Edit distance similarity: 1.0 = identical, 0.0 = completely different
            let edit_sim = 1.0 - (dist as f32 / max_len as f32);

            // Argument overlap similarity (Jaccard on parameter names)
            let arg_sim = argument_jaccard(request_args, tool_schemas.get(*name));

            // Combined score: 70% edit distance, 30% argument overlap
            let score = edit_sim * 0.7 + arg_sim * 0.3;

            if score >= config.suggestion_threshold {
                Some(RoutingCandidate {
                    name: name.to_string(),
                    score,
                    edit_distance: dist,
                })
            } else {
                None
            }
        })
        .collect();

    candidates.sort_by(|a, b| {
        b.score
            .partial_cmp(&a.score)
            .unwrap_or(std::cmp::Ordering::Equal)
    });
    candidates.truncate(5);
    candidates
}

/// Levenshtein edit distance between two strings.
fn edit_distance(a: &str, b: &str) -> usize {
    let a_len = a.len();
    let b_len = b.len();
    let mut matrix = vec![vec![0usize; b_len + 1]; a_len + 1];

    for i in 0..=a_len {
        matrix[i][0] = i;
    }
    for j in 0..=b_len {
        matrix[0][j] = j;
    }

    let a_bytes = a.as_bytes();
    let b_bytes = b.as_bytes();

    for i in 1..=a_len {
        for j in 1..=b_len {
            let cost = if a_bytes[i - 1] == b_bytes[j - 1] {
                0
            } else {
                1
            };
            matrix[i][j] = (matrix[i - 1][j] + 1)
                .min(matrix[i][j - 1] + 1)
                .min(matrix[i - 1][j - 1] + cost);
        }
    }

    matrix[a_len][b_len]
}

/// Jaccard similarity between request argument keys and tool schema properties.
fn argument_jaccard(
    request_args: &serde_json::Value,
    schema_props: Option<&Option<Vec<String>>>,
) -> f32 {
    let request_keys: std::collections::HashSet<&str> = request_args
        .as_object()
        .map(|o| o.keys().map(|k| k.as_str()).collect())
        .unwrap_or_default();

    let schema_keys: std::collections::HashSet<&str> = schema_props
        .and_then(|p| p.as_ref())
        .map(|props| props.iter().map(|s| s.as_str()).collect())
        .unwrap_or_default();

    if request_keys.is_empty() && schema_keys.is_empty() {
        return 0.0;
    }

    let intersection = request_keys.intersection(&schema_keys).count();
    let union = request_keys.union(&schema_keys).count();

    if union == 0 {
        0.0
    } else {
        intersection as f32 / union as f32
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn edit_distance_identical() {
        assert_eq!(edit_distance("file_read", "file_read"), 0);
    }

    #[test]
    fn edit_distance_one_char() {
        assert_eq!(edit_distance("file_read", "file_reed"), 1);
    }

    #[test]
    fn edit_distance_misspelling() {
        assert_eq!(edit_distance("file_raed", "file_read"), 2);
    }

    #[test]
    fn edit_distance_completely_different() {
        let d = edit_distance("file_read", "git_commit");
        assert!(d > 5);
    }

    #[test]
    fn argument_jaccard_full_overlap() {
        let args = json!({"path": "/tmp", "offset": 0});
        let schema = Some(vec!["path".to_string(), "offset".to_string()]);
        assert!((argument_jaccard(&args, Some(&schema)) - 1.0).abs() < 0.01);
    }

    #[test]
    fn argument_jaccard_partial_overlap() {
        let args = json!({"path": "/tmp", "content": "hello"});
        let schema = Some(vec!["path".to_string(), "offset".to_string()]);
        let sim = argument_jaccard(&args, Some(&schema));
        assert!(sim > 0.3 && sim < 0.5); // 1 overlap out of 3 union
    }

    #[test]
    fn argument_jaccard_no_overlap() {
        let args = json!({"query": "test"});
        let schema = Some(vec!["path".to_string(), "offset".to_string()]);
        assert!((argument_jaccard(&args, Some(&schema))).abs() < 0.01);
    }

    #[test]
    fn find_candidates_disabled() {
        let config = ToolRoutingConfig::default(); // enabled: false
        let names = vec!["file_read", "file_write"];
        let candidates = find_candidates("file_raed", &names, &json!({}), &HashMap::new(), &config);
        assert!(candidates.is_empty());
    }

    #[test]
    fn find_candidates_misspelling() {
        let config = ToolRoutingConfig {
            enabled: true,
            suggestion_threshold: 0.3,
            auto_route_threshold: 0.8,
        };
        let names = vec!["file_read", "file_write", "git_commit", "git_status"];
        let candidates =
            find_candidates("file_raed", &names, &json!({}), &HashMap::new(), &config);
        assert!(!candidates.is_empty());
        assert_eq!(candidates[0].name, "file_read");
        assert!(candidates[0].score > 0.5);
    }

    #[test]
    fn find_candidates_with_args_boost() {
        let config = ToolRoutingConfig {
            enabled: true,
            suggestion_threshold: 0.3,
            auto_route_threshold: 0.8,
        };
        let names = vec!["file_read", "file_write"];
        let mut schemas = HashMap::new();
        schemas.insert(
            "file_read".to_string(),
            Some(vec!["path".to_string(), "offset".to_string()]),
        );
        schemas.insert(
            "file_write".to_string(),
            Some(vec!["path".to_string(), "content".to_string()]),
        );

        let args = json!({"path": "/tmp/test.txt", "offset": 10});
        let candidates = find_candidates("fle_read", &names, &args, &schemas, &config);
        assert!(!candidates.is_empty());
        // file_read should score higher due to argument overlap
        assert_eq!(candidates[0].name, "file_read");
    }

    #[test]
    fn find_candidates_truncates_to_5() {
        let config = ToolRoutingConfig {
            enabled: true,
            suggestion_threshold: 0.0, // accept everything
            auto_route_threshold: 0.8,
        };
        let names: Vec<&str> = (0..20)
            .map(|i| match i {
                0 => "tool_a",
                1 => "tool_b",
                2 => "tool_c",
                3 => "tool_d",
                4 => "tool_e",
                5 => "tool_f",
                _ => "zzz",
            })
            .collect();
        let candidates =
            find_candidates("tool_x", &names, &json!({}), &HashMap::new(), &config);
        assert!(candidates.len() <= 5);
    }

    #[test]
    fn find_candidates_distant_name_low_score() {
        let config = ToolRoutingConfig {
            enabled: true,
            suggestion_threshold: 0.5,
            auto_route_threshold: 0.8,
        };
        let names = vec!["file_read"];
        let candidates = find_candidates(
            "completely_unrelated_tool_name",
            &names,
            &json!({}),
            &HashMap::new(),
            &config,
        );
        assert!(candidates.is_empty());
    }
}
