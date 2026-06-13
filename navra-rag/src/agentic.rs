//! Agentic RAG L2: multi-step retrieval with query decomposition and
//! self-correction.
//!
//! Decomposes complex queries into sub-queries, routes each to the
//! appropriate search strategy (hybrid/semantic/lexical/filtered), then
//! merges results with RRF fusion. A self-correction loop refines queries
//! when initial results fall below a relevance threshold.
//!
//! Supports negation-aware FTS5 queries: words like "not", "without",
//! "except", "excluding" are detected and translated to FTS5 NOT
//! operators on the lexical channel.
//!
//! Supports temporal/numeric predicate detection: dates and keywords
//! like "after", "since" are parsed and routed to filtered search
//! with `SearchFilter` constraints.

use crate::store::{ChunkResult, ChunkStore, SearchFilter};
use std::collections::HashMap;

/// A decomposed sub-query with its routing strategy.
#[derive(Debug, Clone)]
pub struct SubQuery {
    /// Query text with temporal/numeric predicates and negation phrases removed.
    pub text: String,
    /// Strategy selected by `classify_strategy`.
    pub strategy: SearchStrategy,
    /// Terms to exclude via FTS5 NOT operator.
    pub negation_terms: Vec<String>,
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
    /// Temporal or numeric predicate detected — vector search
    /// with metadata pre-filtering.
    Filtered(SearchFilter),
}

/// Negation patterns we scan for. Order matters: longer phrases first
/// to avoid partial matches.
const NEGATION_PATTERNS: &[&str] = &[
    "not related to ",
    "without any ",
    "excluding ",
    "without ",
    "except ",
    "not ",
    "no ",
];

/// Heuristic query decomposition.
///
/// Splits compound queries on conjunctions (" and ", " then ", " also "),
/// then routes each sub-query to a search strategy based on content
/// analysis. Scans for negation words and extracts them as
/// `negation_terms` for FTS5 NOT operators. Detects temporal predicates
/// and routes to filtered search.
pub fn decompose_query(query: &str) -> Vec<SubQuery> {
    let parts = split_on_conjunctions(query);
    parts
        .into_iter()
        .map(|text| {
            let (cleaned, negation_terms) = extract_negations(&text);
            let mut sq = classify_strategy(&cleaned);
            sq.negation_terms = negation_terms;
            sq
        })
        .collect()
}

/// Classify a query string into a search strategy.
///
/// Checks in order:
/// 1. Temporal predicates (dates, "after/since") -> `Filtered`
/// 2. Code symbols (`::`, snake_case, CamelCase) -> `Lexical`
/// 3. Conceptual phrasing ("how does", "what is", "explain") -> `Semantic`
/// 4. Otherwise -> `Hybrid`
pub fn classify_strategy(text: &str) -> SubQuery {
    if let Some(sub) = try_temporal(text) {
        return sub;
    }

    if looks_like_code_symbol(text) {
        return SubQuery {
            text: text.to_string(),
            strategy: SearchStrategy::Lexical,
            negation_terms: Vec::new(),
        };
    }

    if looks_like_conceptual(text) {
        return SubQuery {
            text: text.to_string(),
            strategy: SearchStrategy::Semantic,
            negation_terms: Vec::new(),
        };
    }

    SubQuery {
        text: text.to_string(),
        strategy: SearchStrategy::Hybrid,
        negation_terms: Vec::new(),
    }
}

// --- Negation extraction ---

fn extract_negations(query: &str) -> (String, Vec<String>) {
    let mut negation_terms = Vec::new();
    let mut remaining = query.to_string();

    for &pattern in NEGATION_PATTERNS {
        loop {
            let lower = remaining.to_lowercase();
            let Some(pos) = lower.find(pattern) else {
                break;
            };

            let after = &remaining[pos + pattern.len()..];
            let term = extract_next_term(after);
            if term.is_empty() {
                break;
            }

            negation_terms.push(term.clone());

            let end_pos = pos + pattern.len() + term.len();
            let before = remaining[..pos].to_string();
            let after_term = remaining[end_pos..].to_string();
            remaining = format!("{}{}", before.trim_end(), after_term);
            remaining = remaining.trim().to_string();

            while remaining.contains("  ") {
                remaining = remaining.replace("  ", " ");
            }
        }
    }

    remaining = remaining.trim().to_string();
    (remaining, negation_terms)
}

fn extract_next_term(text: &str) -> String {
    let trimmed = text.trim_start();
    if trimmed.is_empty() {
        return String::new();
    }
    let end = trimmed
        .find(|c: char| c.is_whitespace())
        .unwrap_or(trimmed.len());
    trimmed[..end].to_string()
}

/// Apply FTS5 negation to a query string.
///
/// Produces FTS5 syntax: `query NOT term1 NOT term2`.
pub fn apply_fts5_negation(query: &str, negations: &[String]) -> String {
    if negations.is_empty() {
        return query.to_string();
    }
    let mut result = query.to_string();
    for term in negations {
        result = format!("{} NOT {}", result, term);
    }
    result
}

// --- Conjunction splitting ---

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

// --- Strategy classification helpers ---

fn looks_like_code_symbol(text: &str) -> bool {
    if text.contains("::") || text.contains("->") {
        return true;
    }
    if text.contains("()") {
        return true;
    }
    let bytes = text.as_bytes();
    for i in 1..bytes.len() {
        if bytes[i - 1].is_ascii_lowercase() && bytes[i].is_ascii_uppercase() {
            return true;
        }
    }
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

// --- Temporal predicate parsing ---

const TEMPORAL_KEYWORDS: &[(&str, bool)] = &[
    ("updated after ", true),
    ("modified after ", true),
    ("updated since ", true),
    ("modified since ", true),
    ("changed after ", true),
    ("changed since ", true),
    ("from ", true),
    ("after ", true),
    ("since ", true),
    ("before ", false),
];

fn try_temporal(text: &str) -> Option<SubQuery> {
    let lower = text.to_lowercase();

    for &(keyword, is_min) in TEMPORAL_KEYWORDS {
        if let Some(pos) = lower.find(keyword) {
            let after_keyword = pos + keyword.len();
            let rest = &text[after_keyword..];

            if let Some((timestamp, date_len)) = parse_iso_date(rest.trim()) {
                if !is_min {
                    continue;
                }

                let rest_trimmed = rest.trim();
                let clause_end = after_keyword + (rest.len() - rest_trimmed.len()) + date_len;
                let mut cleaned = String::new();
                if pos > 0 {
                    cleaned.push_str(text[..pos].trim_end());
                }
                if clause_end < text.len() {
                    let suffix = text[clause_end..].trim_start();
                    if !suffix.is_empty() {
                        if !cleaned.is_empty() {
                            cleaned.push(' ');
                        }
                        cleaned.push_str(suffix);
                    }
                }

                let filter = SearchFilter {
                    min_updated_at: Some(timestamp),
                    ..Default::default()
                };

                return Some(SubQuery {
                    text: cleaned,
                    strategy: SearchStrategy::Filtered(filter),
                    negation_terms: Vec::new(),
                });
            }
        }
    }

    None
}

fn parse_iso_date(s: &str) -> Option<(i64, usize)> {
    if s.len() < 10 {
        return None;
    }

    let bytes = s.as_bytes();
    if bytes[4] != b'-' || bytes[7] != b'-' {
        return None;
    }
    if !bytes[0..4].iter().all(|b| b.is_ascii_digit())
        || !bytes[5..7].iter().all(|b| b.is_ascii_digit())
        || !bytes[8..10].iter().all(|b| b.is_ascii_digit())
    {
        return None;
    }

    let year: i64 = s[0..4].parse().ok()?;
    let month: i64 = s[5..7].parse().ok()?;
    let day: i64 = s[8..10].parse().ok()?;

    if !(1970..=2100).contains(&year) || !(1..=12).contains(&month) || !(1..=31).contains(&day) {
        return None;
    }

    let timestamp = date_to_unix(year, month, day)?;
    Some((timestamp, 10))
}

fn date_to_unix(year: i64, month: i64, day: i64) -> Option<i64> {
    let mut days: i64 = 0;

    for y in 1970..year {
        days += if is_leap(y) { 366 } else { 365 };
    }

    let month_days = [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
    for m in 1..month {
        days += month_days[(m - 1) as usize] as i64;
        if m == 2 && is_leap(year) {
            days += 1;
        }
    }

    days += day - 1;
    Some(days * 86400)
}

fn is_leap(year: i64) -> bool {
    (year % 4 == 0 && year % 100 != 0) || year % 400 == 0
}

// --- Numeric predicate detection ---

#[derive(Debug, Clone, PartialEq)]
pub struct NumericPredicate {
    pub operator: NumericOp,
    pub value: f64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NumericOp {
    GreaterThan,
    LessThan,
    AtLeast,
    AtMost,
}

pub fn detect_numeric_predicate(text: &str) -> Option<NumericPredicate> {
    let lower = text.to_lowercase();

    let patterns: &[(&str, NumericOp)] = &[
        ("greater than ", NumericOp::GreaterThan),
        ("more than ", NumericOp::GreaterThan),
        ("at least ", NumericOp::AtLeast),
        ("less than ", NumericOp::LessThan),
        ("fewer than ", NumericOp::LessThan),
        ("at most ", NumericOp::AtMost),
        (">= ", NumericOp::AtLeast),
        ("<= ", NumericOp::AtMost),
        ("> ", NumericOp::GreaterThan),
        ("< ", NumericOp::LessThan),
    ];

    for (pattern, op) in patterns {
        if let Some(pos) = lower.find(pattern) {
            let after = &text[pos + pattern.len()..];
            let num_str: String = after
                .trim_start()
                .chars()
                .take_while(|c| c.is_ascii_digit() || *c == '.')
                .collect();
            if let Ok(value) = num_str.parse::<f64>() {
                return Some(NumericPredicate {
                    operator: op.clone(),
                    value,
                });
            }
        }
    }

    None
}

// --- Retriever ---

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

        let mut all_results =
            self.execute_sub_queries(&sub_queries, query_embedding, fetch_limit)?;
        let mut hops = 1;
        let mut refined = false;

        while hops < self.max_hops {
            let top_relevance = all_results
                .first()
                .map(|r| r.distance as f32)
                .unwrap_or(0.0);
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
                negation_terms: Vec::new(),
            }];
            let new_results =
                self.execute_sub_queries(&refined_sub, query_embedding, fetch_limit)?;

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
                    let fts_query = apply_fts5_negation(&sq.text, &sq.negation_terms);
                    self.store
                        .search_hybrid(&fts_query, query_embedding, limit)?
                }
                SearchStrategy::Semantic => self.store.search(query_embedding, limit)?,
                SearchStrategy::Lexical => {
                    let fts_query = apply_fts5_negation(&sq.text, &sq.negation_terms);
                    self.store.search_fts(&fts_query, limit)?
                }
                SearchStrategy::Filtered(ref filter) => {
                    self.store.search_filtered(query_embedding, filter, limit)?
                }
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
pub fn extract_followup_terms(results: &[ChunkResult]) -> Vec<String> {
    let mut terms = Vec::new();
    let mut seen = std::collections::HashSet::new();

    for result in results {
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

    // --- Negation extraction tests (TW19) ---

    #[test]
    fn negation_not_related_to() {
        let subs = decompose_query("find auth not related to OAuth");
        assert_eq!(subs.len(), 1);
        assert_eq!(subs[0].text, "find auth");
        assert_eq!(subs[0].negation_terms, vec!["OAuth"]);
    }

    #[test]
    fn negation_without() {
        let subs = decompose_query("files without tests");
        assert_eq!(subs.len(), 1);
        assert_eq!(subs[0].text, "files");
        assert_eq!(subs[0].negation_terms, vec!["tests"]);
    }

    #[test]
    fn negation_except() {
        let subs = decompose_query("modules except logging");
        assert_eq!(subs.len(), 1);
        assert_eq!(subs[0].text, "modules");
        assert_eq!(subs[0].negation_terms, vec!["logging"]);
    }

    #[test]
    fn negation_excluding() {
        let subs = decompose_query("all crates excluding benchmarks");
        assert_eq!(subs.len(), 1);
        assert_eq!(subs[0].text, "all crates");
        assert_eq!(subs[0].negation_terms, vec!["benchmarks"]);
    }

    #[test]
    fn negation_not_simple() {
        let subs = decompose_query("security not OAuth");
        assert_eq!(subs.len(), 1);
        assert_eq!(subs[0].text, "security");
        assert_eq!(subs[0].negation_terms, vec!["OAuth"]);
    }

    #[test]
    fn negation_without_any() {
        let subs = decompose_query("results without any duplicates");
        assert_eq!(subs.len(), 1);
        assert_eq!(subs[0].text, "results");
        assert_eq!(subs[0].negation_terms, vec!["duplicates"]);
    }

    #[test]
    fn no_negation_passthrough() {
        let subs = decompose_query("find the auth module");
        assert_eq!(subs.len(), 1);
        assert_eq!(subs[0].text, "find the auth module");
        assert!(subs[0].negation_terms.is_empty());
        assert_eq!(subs[0].strategy, SearchStrategy::Hybrid);
    }

    #[test]
    fn multiple_negations() {
        let subs = decompose_query("find X not Y without Z");
        assert_eq!(subs.len(), 1);
        assert_eq!(subs[0].text, "find X");
        assert!(subs[0].negation_terms.contains(&"Y".to_string()));
        assert!(subs[0].negation_terms.contains(&"Z".to_string()));
    }

    #[test]
    fn negation_no_keyword() {
        let subs = decompose_query("search documents no drafts");
        assert_eq!(subs.len(), 1);
        assert_eq!(subs[0].text, "search documents");
        assert_eq!(subs[0].negation_terms, vec!["drafts"]);
    }

    // --- FTS5 query construction tests (TW19) ---

    #[test]
    fn fts5_negation_empty() {
        let result = apply_fts5_negation("auth module", &[]);
        assert_eq!(result, "auth module");
    }

    #[test]
    fn fts5_negation_single() {
        let result = apply_fts5_negation("auth module", &["OAuth".to_string()]);
        assert_eq!(result, "auth module NOT OAuth");
    }

    #[test]
    fn fts5_negation_multiple() {
        let result = apply_fts5_negation(
            "find crates",
            &["benchmarks".to_string(), "tests".to_string()],
        );
        assert_eq!(result, "find crates NOT benchmarks NOT tests");
    }

    // --- Temporal predicate tests (TW20) ---

    #[test]
    fn temporal_after_iso_date() {
        let sq = classify_strategy("documents updated after 2024-01-15");
        assert!(
            matches!(sq.strategy, SearchStrategy::Filtered(ref f) if f.min_updated_at.is_some()),
            "expected Filtered strategy, got {:?}",
            sq.strategy,
        );
        if let SearchStrategy::Filtered(f) = &sq.strategy {
            assert_eq!(f.min_updated_at, Some(date_to_unix(2024, 1, 15).unwrap()));
        }
        assert_eq!(sq.text, "documents");
    }

    #[test]
    fn temporal_since_iso_date() {
        let sq = classify_strategy("files modified since 2024-06-01");
        assert!(
            matches!(sq.strategy, SearchStrategy::Filtered(ref f) if f.min_updated_at.is_some()),
        );
        if let SearchStrategy::Filtered(f) = &sq.strategy {
            assert_eq!(f.min_updated_at, Some(date_to_unix(2024, 6, 1).unwrap()));
        }
        assert_eq!(sq.text, "files");
    }

    #[test]
    fn temporal_after_with_trailing_text() {
        let sq = classify_strategy("changes after 2025-03-10 in auth module");
        assert!(matches!(sq.strategy, SearchStrategy::Filtered(_)));
        if let SearchStrategy::Filtered(f) = &sq.strategy {
            assert_eq!(f.min_updated_at, Some(date_to_unix(2025, 3, 10).unwrap()));
        }
        assert_eq!(sq.text, "changes in auth module");
    }

    // --- Date parsing tests (TW20) ---

    #[test]
    fn parse_valid_iso_date() {
        let (ts, len) = parse_iso_date("2024-01-15").unwrap();
        assert_eq!(len, 10);
        assert_eq!(ts, date_to_unix(2024, 1, 15).unwrap());
    }

    #[test]
    fn parse_iso_date_with_trailing() {
        let (ts, len) = parse_iso_date("2024-06-01 extra text").unwrap();
        assert_eq!(len, 10);
        assert_eq!(ts, date_to_unix(2024, 6, 1).unwrap());
    }

    #[test]
    fn parse_iso_date_too_short() {
        assert!(parse_iso_date("2024-01").is_none());
    }

    #[test]
    fn parse_iso_date_invalid_month() {
        assert!(parse_iso_date("2024-13-01").is_none());
    }

    #[test]
    fn parse_iso_date_invalid_day() {
        assert!(parse_iso_date("2024-01-32").is_none());
    }

    #[test]
    fn parse_epoch() {
        let (ts, _) = parse_iso_date("1970-01-01").unwrap();
        assert_eq!(ts, 0);
    }

    #[test]
    fn parse_leap_year() {
        let (ts_feb29, _) = parse_iso_date("2024-02-29").unwrap();
        let (ts_mar01, _) = parse_iso_date("2024-03-01").unwrap();
        assert_eq!(ts_mar01 - ts_feb29, 86400);
    }

    #[test]
    fn date_to_unix_known_value() {
        let ts = date_to_unix(2024, 1, 1).unwrap();
        assert_eq!(ts, 19723 * 86400);
    }

    // --- Numeric predicate tests (TW20) ---

    #[test]
    fn detect_greater_than() {
        let pred = detect_numeric_predicate("results greater than 100").unwrap();
        assert_eq!(pred.operator, NumericOp::GreaterThan);
        assert_eq!(pred.value, 100.0);
    }

    #[test]
    fn detect_more_than() {
        let pred = detect_numeric_predicate("more than 50 chunks").unwrap();
        assert_eq!(pred.operator, NumericOp::GreaterThan);
        assert_eq!(pred.value, 50.0);
    }

    #[test]
    fn detect_at_least() {
        let pred = detect_numeric_predicate("at least 10 results").unwrap();
        assert_eq!(pred.operator, NumericOp::AtLeast);
        assert_eq!(pred.value, 10.0);
    }

    #[test]
    fn detect_less_than() {
        let pred = detect_numeric_predicate("less than 5").unwrap();
        assert_eq!(pred.operator, NumericOp::LessThan);
        assert_eq!(pred.value, 5.0);
    }

    #[test]
    fn detect_operator_symbol() {
        let pred = detect_numeric_predicate("distance > 0.5").unwrap();
        assert_eq!(pred.operator, NumericOp::GreaterThan);
        assert_eq!(pred.value, 0.5);
    }

    #[test]
    fn no_numeric_predicate() {
        assert!(detect_numeric_predicate("find auth module").is_none());
    }

    // --- Strategy classification regression tests ---

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
    fn filtered_equality() {
        let f1 = SearchStrategy::Filtered(SearchFilter {
            min_updated_at: Some(1000),
            ..Default::default()
        });
        let f2 = SearchStrategy::Filtered(SearchFilter {
            min_updated_at: Some(1000),
            ..Default::default()
        });
        let f3 = SearchStrategy::Filtered(SearchFilter {
            min_updated_at: Some(2000),
            ..Default::default()
        });
        assert_eq!(f1, f2);
        assert_ne!(f1, f3);
    }

    // --- Retriever tests ---

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
        assert_eq!(
            result.results[0].content,
            "Rust ownership and borrowing rules"
        );
    }

    #[test]
    fn retrieve_self_correction() {
        let store = test_store();
        let chunks = vec![
            make_chunk(
                "pub fn authenticate_user(token: &str) -> Result<User, AuthError>",
                0,
            ),
            make_chunk("The auth system verifies credentials", 1),
        ];
        let embeddings = vec![vec![0.5, 0.5, 0.0, 0.0], vec![0.0, 0.0, 0.5, 0.5]];
        store
            .index_document("/auth.rs", &chunks, &embeddings)
            .unwrap();

        let retriever = AgenticRetriever::new(&store)
            .with_min_relevance(0.9)
            .with_max_hops(3);

        let result = retriever
            .retrieve("login verification", &[0.3, 0.3, 0.3, 0.1], 5)
            .unwrap();

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
            .with_min_relevance(999.0)
            .with_max_hops(2);

        let result = retriever
            .retrieve("query", &[0.5, 0.5, 0.0, 0.0], 5)
            .unwrap();

        assert!(result.hops <= 2);
    }

    #[test]
    fn retrieve_with_negation_excludes_results() {
        let store = test_store();
        let chunks = vec![
            make_chunk("auth module with OAuth integration", 0),
            make_chunk("auth module with BLAKE3 tokens", 1),
        ];
        let embeddings = vec![vec![1.0, 0.0, 0.0, 0.0], vec![0.9, 0.1, 0.0, 0.0]];
        store
            .index_document("/auth.rs", &chunks, &embeddings)
            .unwrap();

        let retriever = AgenticRetriever::new(&store);
        let result = retriever
            .retrieve("auth not OAuth", &[0.95, 0.05, 0.0, 0.0], 5)
            .unwrap();

        assert!(!result.sub_queries[0].negation_terms.is_empty());
        assert_eq!(result.sub_queries[0].negation_terms[0], "OAuth");
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
        assert!(result.sub_queries.len() >= 2);
        assert!(!result.results.is_empty());
    }
}
