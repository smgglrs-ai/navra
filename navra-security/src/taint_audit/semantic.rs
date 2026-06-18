//! Semantic evidence tracking: detects taint propagation through
//! meaning-preserving transformations (paraphrase, summarization).
//!
//! Without an embedding model, falls back to string overlap analysis
//! using Jaccard similarity on word sets.

use super::{TaintMechanism, TaintPath};
use navra_core::blackbox::BlackboxEntry;

/// Analyze semantic similarity between untrusted outputs and trusted sink args.
pub fn analyze(
    untrusted: &[&BlackboxEntry],
    trusted_sinks: &[&BlackboxEntry],
) -> Vec<TaintPath> {
    let mut paths = Vec::new();

    for source in untrusted {
        let source_text = extract_text_content(source);
        if source_text.is_empty() {
            continue;
        }
        let source_words = word_set(&source_text);

        for sink in trusted_sinks {
            if sink.seq <= source.seq {
                continue;
            }

            let sink_text = extract_text_content(sink);
            if sink_text.is_empty() {
                continue;
            }
            let sink_words = word_set(&sink_text);

            let similarity = jaccard_similarity(&source_words, &sink_words);

            if similarity > 0.3 {
                paths.push(TaintPath {
                    source_seq: source.seq,
                    sink_seq: sink.seq,
                    source_tool: source.tool_name.clone(),
                    sink_tool: sink.tool_name.clone(),
                    mechanism: TaintMechanism::Semantic,
                    confidence: similarity,
                    evidence: format!(
                        "Word overlap {:.0}% between untrusted output and trusted write args",
                        similarity * 100.0
                    ),
                });
            }
        }
    }

    paths
}

fn extract_text_content(entry: &BlackboxEntry) -> String {
    let mut text = String::new();
    text.push_str(&entry.tool_args);
    text.push(' ');
    text.push_str(&entry.tool_result);
    text
}

fn word_set(text: &str) -> std::collections::HashSet<String> {
    text.split_whitespace()
        .map(|w| w.to_lowercase().trim_matches(|c: char| !c.is_alphanumeric()).to_string())
        .filter(|w| w.len() >= 3)
        .collect()
}

fn jaccard_similarity(
    a: &std::collections::HashSet<String>,
    b: &std::collections::HashSet<String>,
) -> f32 {
    if a.is_empty() || b.is_empty() {
        return 0.0;
    }
    let intersection = a.intersection(b).count() as f32;
    let union = a.union(b).count() as f32;
    intersection / union
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn jaccard_identical() {
        let mut a = std::collections::HashSet::new();
        a.insert("hello".into());
        a.insert("world".into());
        assert_eq!(jaccard_similarity(&a, &a), 1.0);
    }

    #[test]
    fn jaccard_disjoint() {
        let mut a = std::collections::HashSet::new();
        a.insert("hello".into());
        let mut b = std::collections::HashSet::new();
        b.insert("world".into());
        assert_eq!(jaccard_similarity(&a, &b), 0.0);
    }

    #[test]
    fn jaccard_empty() {
        let a = std::collections::HashSet::new();
        let b = std::collections::HashSet::new();
        assert_eq!(jaccard_similarity(&a, &b), 0.0);
    }

    #[test]
    fn word_set_normalizes() {
        let words = word_set("Hello, WORLD! test");
        assert!(words.contains("hello"));
        assert!(words.contains("world"));
        assert!(words.contains("test"));
    }
}
