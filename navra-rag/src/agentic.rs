//! Agentic RAG L2: multi-step retrieval with query decomposition and
//! self-correction.
//!
//! Decomposes complex queries into sub-queries, routes each to the
//! appropriate search strategy (hybrid/semantic/lexical), then merges
//! results with RRF fusion. A self-correction loop refines queries
//! when initial results fall below a relevance threshold.

use crate::store::{ChunkResult, ChunkStore};
use std::collections::HashMap;

/// A decomposed sub-query with its routing strategy.
#[derive(Debug, Clone)]
pub struct SubQuery {
    pub text: String,
    pub strategy: SearchStrategy,
}

/// Search strategy for a sub-query.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SearchStrategy {
    /// FTS5 + vector (default).
    Hybrid,
    /// Vector only (conceptual questions).
    Semantic,
    /// FTS5 only (exact terms, code symbols).
    Lexical,
}

/// Heuristic query decomposition.
///
/// Splits compound queries on conjunctions (" and ", " then ", " also "),
/// then routes each sub-query to a search strategy based on content
/// analysis. Single queries pass through as one `SubQuery`.
pub fn decompose_query(query: &str) -> Vec<SubQuery> {
    let parts = split_on_conjunctions(query);
    parts
        .into_iter()
        .map(|text| {
            let strategy = classify_strategy(&text);
            SubQuery { text, strategy }
        })
        .collect()
}

fn split_on_conjunctions(query: &str) -> Vec<String> {
    let delimiters = [" and then ", " and also ", " then ", " also ", " and "];
    let mut parts = vec![query.to_string()];

    for delim in &delimiters {
        let mut next = Vec::new();
        for part in parts {
            let lower = part.to_lowercase();
            if let Some(pos) = lower.find(delim) {
                let left = part[..pos].trim().to_string();
                let right = part[pos + delim.len()..].trim().to_string();
                if !left.is_empty() {
                    next.push(left);
                }
                if !right.is_empty() {
                    next.push(right);
                }
            } else {
                next.push(part);
            }
        }
        parts = next;
    }

    parts
}

fn classify_strategy(text: &str) -> SearchStrategy {
    if looks_like_code_symbol(text) {
        return SearchStrategy::Lexical;
    }
    if looks_like_conceptual(text) {
        return SearchStrategy::Semantic;
    }
    SearchStrategy::Hybrid
}

fn looks_like_code_symbol(text: &str) -> bool {
    if text.contains("::") || text.contains("->") {
        return true;
    }
    // Parentheses that look like function calls (not sentence parens)
    if text.contains("()") {
        return true;
    }
    // camelCase or PascalCase: lowercase followed by uppercase
    let bytes = text.as_bytes();
    for i in 1..bytes.len() {
        if bytes[i - 1].is_ascii_lowercase() && bytes[i].is_ascii_uppercase() {
            return true;
        }
    }
    // snake_case identifiers (word_word with no spaces around _)
    if text.contains('_') && !text.contains(' ') && text.len() > 2 {
        return true;
    }
    false
}

fn looks_like_conceptual(text: &str) -> bool {
    let lower = text.trim_start().to_lowercase();
    lower.starts_with("how ")
        || lower.starts_with("why ")
        || lower.starts_with("what ")
        || lower.starts_with("explain ")
        || lower.starts_with("describe ")
}

/// Result of an agentic retrieval.
#[derive(Debug, Clone)]
pub struct AgenticResult {
    pub results: Vec<ChunkResult>,
    pub hops: usize,
    pub sub_queries: Vec<SubQuery>,
    pub refined: bool,
}

/// Multi-step retriever with query decomposition and self-correction.
pub struct AgenticRetriever<'a> {
    store: &'a ChunkStore,
    max_hops: usize,
    min_relevance: f32,
}

impl<'a> AgenticRetriever<'a> {
    pub fn new(store: &'a ChunkStore) -> Self {
        Self {
            store,
            max_hops: 3,
            min_relevance: 0.01,
        }
    }

    pub fn with_max_hops(mut self, n: usize) -> Self {
        self.max_hops = n;
        self
    }

    pub fn with_min_relevance(mut self, r: f32) -> Self {
        self.min_relevance = r;
        self
    }

    pub fn retrieve(
        &self,
        query: &str,
        query_embedding: &[f32],
        limit: usize,
    ) -> Result<AgenticResult, rusqlite::Error> {
        let sub_queries = decompose_query(query);
        let fetch_limit = limit * 3;

        let mut all_results = self.execute_sub_queries(&sub_queries, query_embedding, fetch_limit)?;
        let mut hops = 1;
        let mut refined = false;

        while hops < self.max_hops {
            let top_relevance = all_results.first().map(|r| r.distance as f32).unwrap_or(0.0);
            if top_relevance >= self.min_relevance {
                break;
            }

            refined = true;
            let extra_terms = extract_followup_terms(&all_results);
            if extra_terms.is_empty() {
                break;
            }

            let refined_query = format!("{} {}", query, extra_terms.join(" "));
            let refined_sub = vec![SubQuery {
                text: refined_query,
                strategy: SearchStrategy::Hybrid,
            }];
            let new_results = self.execute_sub_queries(&refined_sub, query_embedding, fetch_limit)?;

            all_results = merge_rrf(&[&all_results, &new_results]);
            hops += 1;
        }

        all_results.truncate(limit);

        Ok(AgenticResult {
            results: all_results,
            hops,
            sub_queries,
            refined,
        })
    }

    fn execute_sub_queries(
        &self,
        sub_queries: &[SubQuery],
        query_embedding: &[f32],
        limit: usize,
    ) -> Result<Vec<ChunkResult>, rusqlite::Error> {
        let mut per_query_results: Vec<Vec<ChunkResult>> = Vec::new();

        for sq in sub_queries {
            let results = match sq.strategy {
                SearchStrategy::Hybrid => {
                    self.store.search_hybrid(&sq.text, query_embedding, limit)?
                }
                SearchStrategy::Semantic => self.store.search(query_embedding, limit)?,
                SearchStrategy::Lexical => self.store.search_fts(&sq.text, limit)?,
            };
            per_query_results.push(results);
        }

        if per_query_results.len() == 1 {
            return Ok(per_query_results.into_iter().next().unwrap());
        }

        let refs: Vec<&Vec<ChunkResult>> = per_query_results.iter().collect();
        let slices: Vec<&[ChunkResult]> = refs.iter().map(|v| v.as_slice()).collect();
        Ok(merge_rrf(&slices))
    }
}

/// Merge multiple result lists using Reciprocal Rank Fusion (k=60).
fn merge_rrf(lists: &[&[ChunkResult]]) -> Vec<ChunkResult> {
    let k = 60.0_f64;
    let mut scores: HashMap<String, f64> = HashMap::new();
    let mut entries: HashMap<String, ChunkResult> = HashMap::new();

    for list in lists {
        for (rank, result) in list.iter().enumerate() {
            let key = format!("{}:{}", result.path, result.chunk_index);
            *scores.entry(key.clone()).or_insert(0.0) += 1.0 / (k + rank as f64 + 1.0);
            entries.entry(key).or_insert_with(|| result.clone());
        }
    }

    let mut fused: Vec<ChunkResult> = scores
        .into_iter()
        .filter_map(|(key, score)| {
            entries.remove(&key).map(|mut r| {
                r.distance = score;
                r
            })
        })
        .collect();
    fused.sort_by(|a, b| {
        b.distance
            .partial_cmp(&a.distance)
            .unwrap_or(std::cmp::Ordering::Equal)
    });
    fused
}

/// Extract potential follow-up search terms from results.
///
/// Scans result content for function names, type names, and file paths
/// that could seed a follow-up search.
pub fn extract_followup_terms(results: &[ChunkResult]) -> Vec<String> {
    let mut terms = Vec::new();
    let mut seen = std::collections::HashSet::new();

    for result in results {
        // Function names: fn xxx, pub fn xxx, def xxx, async fn xxx
        for cap in regex_lite::Regex::new(r"(?:pub\s+)?(?:async\s+)?fn\s+([a-zA-Z_][a-zA-Z0-9_]*)")
            .unwrap()
            .captures_iter(&result.content)
        {
            if let Some(m) = cap.get(1) {
                let name = m.as_str().to_string();
                if seen.insert(name.clone()) {
                    terms.push(name);
                }
            }
        }

        // Type names: struct Xxx, enum Xxx, class Xxx, trait Xxx
        for cap in
            regex_lite::Regex::new(r"(?:pub\s+)?(?:struct|enum|class|trait)\s+([A-Z][a-zA-Z0-9_]*)")
                .unwrap()
                .captures_iter(&result.content)
        {
            if let Some(m) = cap.get(1) {
                let name = m.as_str().to_string();
                if seen.insert(name.clone()) {
                    terms.push(name);
                }
            }
        }

        // File paths: /path/to/file.ext or path/to/file.ext
        for cap in regex_lite::Regex::new(r"(?:^|[\s(])(/?\w[\w/.-]+\.\w+)")
            .unwrap()
            .captures_iter(&result.content)
        {
            if let Some(m) = cap.get(1) {
                let path = m.as_str().to_string();
                if seen.insert(path.clone()) {
                    terms.push(path);
                }
            }
        }
    }

    terms
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chunk::Chunk;

    fn test_store() -> ChunkStore {
        ChunkStore::open_memory(4).unwrap()
    }

    fn make_chunk(content: &str, index: usize) -> Chunk {
        Chunk {
            content: content.to_string(),
            start_byte: 0,
            end_byte: content.len(),
            index,
            breadcrumb: None,
            section_start_byte: None,
            section_end_byte: None,
        }
    }

    #[test]
    fn decompose_simple_query() {
        let subs = decompose_query("find the auth module");
        assert_eq!(subs.len(), 1);
        assert_eq!(subs[0].text, "find the auth module");
        assert_eq!(subs[0].strategy, SearchStrategy::Hybrid);
    }

    #[test]
    fn decompose_compound_query() {
        let subs = decompose_query("find the auth module and check its tests");
        assert_eq!(subs.len(), 2);
        assert_eq!(subs[0].text, "find the auth module");
        assert_eq!(subs[1].text, "check its tests");
    }

    #[test]
    fn decompose_code_symbol() {
        let subs = decompose_query("AuthError::InvalidToken");
        assert_eq!(subs.len(), 1);
        assert_eq!(subs[0].strategy, SearchStrategy::Lexical);

        let subs = decompose_query("camelCase identifier");
        assert_eq!(subs.len(), 1);
        assert_eq!(subs[0].strategy, SearchStrategy::Lexical);

        let subs = decompose_query("foo_bar");
        assert_eq!(subs.len(), 1);
        assert_eq!(subs[0].strategy, SearchStrategy::Lexical);

        let subs = decompose_query("my_func()");
        assert_eq!(subs.len(), 1);
        assert_eq!(subs[0].strategy, SearchStrategy::Lexical);
    }

    #[test]
    fn decompose_conceptual() {
        let subs = decompose_query("how does IFC work");
        assert_eq!(subs.len(), 1);
        assert_eq!(subs[0].strategy, SearchStrategy::Semantic);

        let subs = decompose_query("why is safety important");
        assert_eq!(subs.len(), 1);
        assert_eq!(subs[0].strategy, SearchStrategy::Semantic);

        let subs = decompose_query("what are the permission rules");
        assert_eq!(subs.len(), 1);
        assert_eq!(subs[0].strategy, SearchStrategy::Semantic);
    }

    #[test]
    fn retrieve_single_hop() {
        let store = test_store();
        let chunks = vec![
            make_chunk("Rust ownership and borrowing rules", 0),
            make_chunk("Python garbage collection overview", 1),
        ];
        let embeddings = vec![vec![1.0, 0.0, 0.0, 0.0], vec![0.0, 1.0, 0.0, 0.0]];
        store
            .index_document("/lang.md", &chunks, &embeddings)
            .unwrap();

        let retriever = AgenticRetriever::new(&store);
        let result = retriever
            .retrieve("Rust ownership", &[0.9, 0.1, 0.0, 0.0], 5)
            .unwrap();

        assert!(!result.results.is_empty());
        assert_eq!(result.hops, 1);
        assert!(!result.refined);
        assert_eq!(result.results[0].content, "Rust ownership and borrowing rules");
    }

    #[test]
    fn retrieve_self_correction() {
        let store = test_store();
        // Index a document with a function definition that can be used for refinement
        let chunks = vec![
            make_chunk("pub fn authenticate_user(token: &str) -> Result<User, AuthError>", 0),
            make_chunk("The auth system verifies credentials", 1),
        ];
        let embeddings = vec![vec![0.5, 0.5, 0.0, 0.0], vec![0.0, 0.0, 0.5, 0.5]];
        store
            .index_document("/auth.rs", &chunks, &embeddings)
            .unwrap();

        // Set a very high min_relevance so first hop always "fails"
        // and triggers refinement, but allow enough hops
        let retriever = AgenticRetriever::new(&store)
            .with_min_relevance(0.9)
            .with_max_hops(3);

        let result = retriever
            .retrieve("login verification", &[0.3, 0.3, 0.3, 0.1], 5)
            .unwrap();

        // Should have attempted refinement (hops > 1) because initial
        // RRF scores are well below 0.9
        assert!(result.hops > 1 || result.results.is_empty());
        assert!(result.refined || result.results.is_empty());
    }

    #[test]
    fn retrieve_max_hops_respected() {
        let store = test_store();
        let chunks = vec![make_chunk("some content here", 0)];
        let embeddings = vec![vec![1.0, 0.0, 0.0, 0.0]];
        store
            .index_document("/doc.md", &chunks, &embeddings)
            .unwrap();

        let retriever = AgenticRetriever::new(&store)
            .with_min_relevance(999.0) // impossible to meet
            .with_max_hops(2);

        let result = retriever
            .retrieve("query", &[0.5, 0.5, 0.0, 0.0], 5)
            .unwrap();

        assert!(result.hops <= 2);
    }

    #[test]
    fn extract_followup_terms_finds_functions() {
        let results = vec![ChunkResult {
            path: "/lib.rs".to_string(),
            content: "pub fn foo_bar() -> bool { true }\npub async fn baz_qux() {}".to_string(),
            chunk_index: 0,
            distance: 0.5,
        }];

        let terms = extract_followup_terms(&results);
        assert!(terms.contains(&"foo_bar".to_string()));
        assert!(terms.contains(&"baz_qux".to_string()));
    }

    #[test]
    fn extract_followup_terms_finds_types() {
        let results = vec![ChunkResult {
            path: "/types.rs".to_string(),
            content: "pub struct AuthConfig {\n}\nenum TokenKind { A, B }".to_string(),
            chunk_index: 0,
            distance: 0.5,
        }];

        let terms = extract_followup_terms(&results);
        assert!(terms.contains(&"AuthConfig".to_string()));
        assert!(terms.contains(&"TokenKind".to_string()));
    }

    #[test]
    fn agentic_result_tracks_metadata() {
        let store = test_store();
        let chunks = vec![
            make_chunk("authentication module code", 0),
            make_chunk("permission checking logic", 1),
        ];
        let embeddings = vec![vec![1.0, 0.0, 0.0, 0.0], vec![0.0, 1.0, 0.0, 0.0]];
        store
            .index_document("/sec.rs", &chunks, &embeddings)
            .unwrap();

        let retriever = AgenticRetriever::new(&store);
        let result = retriever
            .retrieve(
                "authentication and permission checking",
                &[0.7, 0.3, 0.0, 0.0],
                10,
            )
            .unwrap();

        assert!(result.hops >= 1);
        assert!(!result.sub_queries.is_empty());
        assert!(result.sub_queries.len() >= 2); // decomposed on "and"
        assert!(!result.results.is_empty());
    }
}
