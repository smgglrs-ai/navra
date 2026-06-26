//! Per-value variable store for FIDES-inspired IFC.
//!
//! Tool results are stored as labeled variables. Agents reference
//! variables by ID (`var://<id>`) in subsequent tool arguments.
//! The gateway resolves references and propagates labels through
//! the lattice join, enabling per-value write-blocking instead of
//! per-session taint.

use navra_protocol::label::DataLabel;
use navra_protocol::Content;
use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

/// A labeled value stored in the per-session variable store.
#[derive(Debug, Clone)]
pub struct StoredValue {
    /// Opaque variable ID (e.g., "v-a1b2c3d4").
    pub id: String,
    /// The tool result content.
    pub content: Vec<Content>,
    /// IFC data label assigned to this value.
    pub label: DataLabel,
    /// Name of the tool that produced this value.
    pub source_tool: String,
    /// When this value was created.
    pub created_at: Instant,
    /// Whether the tool result was an error.
    pub is_error: bool,
}

/// Summary of a stored value (for listing without content).
#[derive(Debug, Clone)]
pub struct StoredValueSummary {
    pub id: String,
    pub label: DataLabel,
    pub source_tool: String,
    pub created_at: Instant,
    pub is_error: bool,
}

impl From<&StoredValue> for StoredValueSummary {
    fn from(v: &StoredValue) -> Self {
        Self {
            id: v.id.clone(),
            label: v.label,
            source_tool: v.source_tool.clone(),
            created_at: v.created_at,
            is_error: v.is_error,
        }
    }
}

/// Per-session store of labeled values.
#[derive(Debug, Clone)]
pub struct ValueStore {
    values: Arc<RwLock<HashMap<String, StoredValue>>>,
    max_entries: usize,
    ttl: Duration,
}

impl Default for ValueStore {
    fn default() -> Self {
        Self::new()
    }
}

impl ValueStore {
    pub fn new() -> Self {
        Self {
            values: Arc::new(RwLock::new(HashMap::new())),
            max_entries: 1000,
            ttl: Duration::from_secs(3600),
        }
    }

    pub fn with_limits(max_entries: usize, ttl: Duration) -> Self {
        Self {
            values: Arc::new(RwLock::new(HashMap::new())),
            max_entries,
            ttl,
        }
    }

    /// Store a value, returning its ID. Evicts oldest if over limit.
    pub fn store(&self, value: StoredValue) -> String {
        let id = value.id.clone();
        let mut values = self.values.write().unwrap();

        // Evict expired entries first
        let now = Instant::now();
        values.retain(|_, v| now.duration_since(v.created_at) < self.ttl);

        // Evict oldest if still over limit
        if values.len() >= self.max_entries
            && let Some(oldest_id) = values
                .values()
                .min_by_key(|v| v.created_at)
                .map(|v| v.id.clone())
            {
                values.remove(&oldest_id);
            }

        values.insert(id.clone(), value);
        id
    }

    /// Get a value by ID. Returns None if not found or expired.
    pub fn get(&self, id: &str) -> Option<StoredValue> {
        let values = self.values.read().unwrap();
        values.get(id).and_then(|v| {
            if Instant::now().duration_since(v.created_at) < self.ttl {
                Some(v.clone())
            } else {
                None
            }
        })
    }

    /// List all non-expired values (summaries only, no content).
    pub fn list(&self) -> Vec<StoredValueSummary> {
        let values = self.values.read().unwrap();
        let now = Instant::now();
        values
            .values()
            .filter(|v| now.duration_since(v.created_at) < self.ttl)
            .map(StoredValueSummary::from)
            .collect()
    }

    /// Remove a value by ID.
    pub fn remove(&self, id: &str) -> Option<StoredValue> {
        let mut values = self.values.write().unwrap();
        values.remove(id)
    }

    /// Evict all expired values. Returns the number evicted.
    pub fn evict_expired(&self) -> usize {
        let mut values = self.values.write().unwrap();
        let before = values.len();
        let now = Instant::now();
        values.retain(|_, v| now.duration_since(v.created_at) < self.ttl);
        before - values.len()
    }

    pub fn count(&self) -> usize {
        let values = self.values.read().unwrap();
        values.len()
    }
}

/// Top-level store mapping session IDs to per-session ValueStores.
#[derive(Debug, Clone)]
pub struct ValueStoreMap {
    stores: Arc<RwLock<HashMap<String, ValueStore>>>,
    default_max_entries: usize,
    default_ttl: Duration,
}

impl Default for ValueStoreMap {
    fn default() -> Self {
        Self::new()
    }
}

impl ValueStoreMap {
    pub fn new() -> Self {
        Self {
            stores: Arc::new(RwLock::new(HashMap::new())),
            default_max_entries: 1000,
            default_ttl: Duration::from_secs(3600),
        }
    }

    pub fn with_limits(max_entries: usize, ttl: Duration) -> Self {
        Self {
            stores: Arc::new(RwLock::new(HashMap::new())),
            default_max_entries: max_entries,
            default_ttl: ttl,
        }
    }

    /// Get or create a per-session value store.
    pub fn get_or_create(&self, session_id: &str) -> ValueStore {
        let stores = self.stores.read().unwrap();
        if let Some(store) = stores.get(session_id) {
            return store.clone();
        }
        drop(stores);

        let mut stores = self.stores.write().unwrap();
        stores
            .entry(session_id.to_string())
            .or_insert_with(|| ValueStore::with_limits(self.default_max_entries, self.default_ttl))
            .clone()
    }

    /// Remove a session's value store.
    pub fn remove_session(&self, session_id: &str) {
        let mut stores = self.stores.write().unwrap();
        stores.remove(session_id);
    }
}

/// Result of scanning tool arguments for variable references.
#[derive(Debug)]
pub struct ResolvedArgs {
    /// The arguments with var:// URIs replaced by actual content.
    pub arguments: serde_json::Value,
    /// Effective label: join of all referenced variables' labels.
    pub effective_label: DataLabel,
    /// IDs of all variables that were referenced.
    pub referenced_vars: Vec<String>,
}

/// Variable reference prefix.
const VAR_PREFIX: &str = "var://";

/// Generate a short variable ID.
pub fn generate_var_id() -> String {
    let uuid = uuid::Uuid::new_v4();
    format!("v-{}", &uuid.simple().to_string()[..8])
}

/// Resolve all `var://<id>` references in tool arguments.
///
/// Walks the JSON value tree, finds strings matching `var://<id>`,
/// replaces them with the stored content (serialized as text),
/// and computes the effective label as the lattice join of all
/// referenced variables.
pub fn resolve_variable_refs(
    args: &serde_json::Value,
    store: &ValueStore,
) -> Result<ResolvedArgs, String> {
    let mut effective_label = DataLabel::TRUSTED_PUBLIC;
    let mut referenced_vars = Vec::new();
    let arguments = resolve_value(args, store, &mut effective_label, &mut referenced_vars)?;

    Ok(ResolvedArgs {
        arguments,
        effective_label,
        referenced_vars,
    })
}

/// Recursively resolve variable references in a JSON value.
fn resolve_value(
    value: &serde_json::Value,
    store: &ValueStore,
    effective_label: &mut DataLabel,
    referenced_vars: &mut Vec<String>,
) -> Result<serde_json::Value, String> {
    match value {
        serde_json::Value::String(s) => resolve_string(s, store, effective_label, referenced_vars),
        serde_json::Value::Object(map) => {
            let mut resolved = serde_json::Map::new();
            for (k, v) in map {
                resolved.insert(
                    k.clone(),
                    resolve_value(v, store, effective_label, referenced_vars)?,
                );
            }
            Ok(serde_json::Value::Object(resolved))
        }
        serde_json::Value::Array(arr) => {
            let mut resolved = Vec::new();
            for v in arr {
                resolved.push(resolve_value(v, store, effective_label, referenced_vars)?);
            }
            Ok(serde_json::Value::Array(resolved))
        }
        other => Ok(other.clone()),
    }
}

/// Resolve variable references within a string value.
///
/// If the entire string is `var://<id>`, replace with the variable's
/// text content. If `var://<id>` appears as a substring, replace
/// inline and still propagate the label.
fn resolve_string(
    s: &str,
    store: &ValueStore,
    effective_label: &mut DataLabel,
    referenced_vars: &mut Vec<String>,
) -> Result<serde_json::Value, String> {
    if !s.contains(VAR_PREFIX) {
        return Ok(serde_json::Value::String(s.to_string()));
    }

    // Exact match: entire string is a single var:// reference
    if s.starts_with(VAR_PREFIX) && !s[VAR_PREFIX.len()..].contains(' ') {
        let var_id = &s[VAR_PREFIX.len()..];
        let stored = store
            .get(var_id)
            .ok_or_else(|| format!("Variable not found: {var_id}"))?;
        *effective_label = effective_label.join(stored.label);
        referenced_vars.push(var_id.to_string());
        let text = content_to_text(&stored.content);
        return Ok(serde_json::Value::String(text));
    }

    // Inline references: replace var://<id> substrings
    let mut result = s.to_string();
    let mut search_from = 0;
    while let Some(start) = result[search_from..].find(VAR_PREFIX) {
        let abs_start = search_from + start;
        let id_start = abs_start + VAR_PREFIX.len();
        let id_end = result[id_start..]
            .find(|c: char| {
                c.is_whitespace()
                    || c == '"'
                    || c == '\''
                    || c == ')'
                    || c == ']'
                    || c == '}'
                    || c == ','
            })
            .map(|i| id_start + i)
            .unwrap_or(result.len());
        let var_id = &result[id_start..id_end];

        let stored = store
            .get(var_id)
            .ok_or_else(|| format!("Variable not found: {var_id}"))?;
        *effective_label = effective_label.join(stored.label);
        referenced_vars.push(var_id.to_string());

        let text = content_to_text(&stored.content);
        result.replace_range(abs_start..id_end, &text);
        search_from = abs_start + text.len();
    }

    Ok(serde_json::Value::String(result))
}

/// Serialize content items to a single text string.
fn content_to_text(content: &[Content]) -> String {
    content
        .iter()
        .filter_map(|c| c.raw.as_text().map(|t| t.text.as_str()))
        .collect::<Vec<_>>()
        .join("\n")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_value(id: &str, text: &str, label: DataLabel) -> StoredValue {
        StoredValue {
            id: id.to_string(),
            content: vec![Content::text(text)],
            label,
            source_tool: "test_tool".to_string(),
            created_at: Instant::now(),
            is_error: false,
        }
    }

    // --- ValueStore tests ---

    #[test]
    fn store_and_retrieve() {
        let store = ValueStore::new();
        let val = make_value("v-aaa", "hello", DataLabel::TRUSTED_PUBLIC);
        store.store(val);
        let retrieved = store.get("v-aaa").unwrap();
        assert_eq!(retrieved.id, "v-aaa");
        assert_eq!(retrieved.label, DataLabel::TRUSTED_PUBLIC);
    }

    #[test]
    fn get_missing_returns_none() {
        let store = ValueStore::new();
        assert!(store.get("v-nonexistent").is_none());
    }

    #[test]
    fn ttl_eviction() {
        let store = ValueStore::with_limits(1000, Duration::from_millis(1));
        let val = make_value("v-old", "data", DataLabel::TRUSTED_PUBLIC);
        store.store(val);
        std::thread::sleep(Duration::from_millis(5));
        assert!(store.get("v-old").is_none());
    }

    #[test]
    fn max_entries_eviction() {
        let store = ValueStore::with_limits(2, Duration::from_secs(3600));
        store.store(make_value("v-1", "first", DataLabel::TRUSTED_PUBLIC));
        std::thread::sleep(Duration::from_millis(1));
        store.store(make_value("v-2", "second", DataLabel::TRUSTED_PUBLIC));
        std::thread::sleep(Duration::from_millis(1));
        // Third store should evict the oldest (v-1)
        store.store(make_value("v-3", "third", DataLabel::TRUSTED_PUBLIC));
        assert!(store.get("v-1").is_none());
        assert!(store.get("v-2").is_some());
        assert!(store.get("v-3").is_some());
    }

    #[test]
    fn list_returns_summaries() {
        let store = ValueStore::new();
        store.store(make_value("v-a", "aaa", DataLabel::TRUSTED_PUBLIC));
        store.store(make_value("v-b", "bbb", DataLabel::UNTRUSTED_SENSITIVE));
        let summaries = store.list();
        assert_eq!(summaries.len(), 2);
    }

    #[test]
    fn remove_value() {
        let store = ValueStore::new();
        store.store(make_value("v-x", "data", DataLabel::TRUSTED_PUBLIC));
        assert!(store.remove("v-x").is_some());
        assert!(store.get("v-x").is_none());
        assert_eq!(store.count(), 0);
    }

    #[test]
    fn evict_expired_removes_old() {
        let store = ValueStore::with_limits(1000, Duration::from_millis(1));
        store.store(make_value("v-old", "data", DataLabel::TRUSTED_PUBLIC));
        std::thread::sleep(Duration::from_millis(5));
        let evicted = store.evict_expired();
        assert_eq!(evicted, 1);
        assert_eq!(store.count(), 0);
    }

    // --- ValueStoreMap tests ---

    #[test]
    fn map_get_or_create() {
        let map = ValueStoreMap::new();
        let store1 = map.get_or_create("session-1");
        store1.store(make_value("v-a", "data", DataLabel::TRUSTED_PUBLIC));
        let store1_again = map.get_or_create("session-1");
        assert_eq!(store1_again.count(), 1);
    }

    #[test]
    fn map_sessions_isolated() {
        let map = ValueStoreMap::new();
        let s1 = map.get_or_create("s1");
        let s2 = map.get_or_create("s2");
        s1.store(make_value("v-a", "data", DataLabel::TRUSTED_PUBLIC));
        assert_eq!(s1.count(), 1);
        assert_eq!(s2.count(), 0);
    }

    #[test]
    fn map_remove_session() {
        let map = ValueStoreMap::new();
        let store = map.get_or_create("s1");
        store.store(make_value("v-a", "data", DataLabel::TRUSTED_PUBLIC));
        map.remove_session("s1");
        let store = map.get_or_create("s1");
        assert_eq!(store.count(), 0);
    }

    // --- Variable reference resolution tests ---

    #[test]
    fn resolve_no_refs() {
        let store = ValueStore::new();
        let args = serde_json::json!({"key": "value", "num": 42});
        let resolved = resolve_variable_refs(&args, &store).unwrap();
        assert_eq!(resolved.arguments, args);
        assert_eq!(resolved.effective_label, DataLabel::TRUSTED_PUBLIC);
        assert!(resolved.referenced_vars.is_empty());
    }

    #[test]
    fn resolve_single_ref() {
        let store = ValueStore::new();
        store.store(make_value(
            "v-abc",
            "file contents",
            DataLabel::UNTRUSTED_SENSITIVE,
        ));
        let args = serde_json::json!({"content": "var://v-abc"});
        let resolved = resolve_variable_refs(&args, &store).unwrap();
        assert_eq!(resolved.arguments["content"], "file contents");
        assert_eq!(resolved.effective_label, DataLabel::UNTRUSTED_SENSITIVE);
        assert_eq!(resolved.referenced_vars, vec!["v-abc"]);
    }

    #[test]
    fn resolve_multiple_refs_joins_labels() {
        let store = ValueStore::new();
        store.store(make_value(
            "v-trusted",
            "safe data",
            DataLabel::TRUSTED_PUBLIC,
        ));
        store.store(make_value(
            "v-untrusted",
            "tainted data",
            DataLabel::UNTRUSTED_SENSITIVE,
        ));
        let args = serde_json::json!({
            "a": "var://v-trusted",
            "b": "var://v-untrusted"
        });
        let resolved = resolve_variable_refs(&args, &store).unwrap();
        assert_eq!(resolved.arguments["a"], "safe data");
        assert_eq!(resolved.arguments["b"], "tainted data");
        // Join: Untrusted+Sensitive wins
        assert_eq!(resolved.effective_label, DataLabel::UNTRUSTED_SENSITIVE);
        assert_eq!(resolved.referenced_vars.len(), 2);
    }

    #[test]
    fn resolve_nested_json() {
        let store = ValueStore::new();
        store.store(make_value(
            "v-deep",
            "nested value",
            DataLabel::UNTRUSTED_PUBLIC,
        ));
        let args = serde_json::json!({
            "outer": {
                "inner": ["var://v-deep", "literal"]
            }
        });
        let resolved = resolve_variable_refs(&args, &store).unwrap();
        assert_eq!(resolved.arguments["outer"]["inner"][0], "nested value");
        assert_eq!(resolved.arguments["outer"]["inner"][1], "literal");
        assert_eq!(
            resolved.effective_label.integrity,
            super::super::Integrity::Untrusted
        );
    }

    #[test]
    fn resolve_missing_var_returns_error() {
        let store = ValueStore::new();
        let args = serde_json::json!({"content": "var://v-nonexistent"});
        let result = resolve_variable_refs(&args, &store);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Variable not found"));
    }

    #[test]
    fn resolve_inline_ref() {
        let store = ValueStore::new();
        store.store(make_value("v-name", "Alice", DataLabel::TRUSTED_PUBLIC));
        let args = serde_json::json!({"greeting": "Hello var://v-name, welcome!"});
        let resolved = resolve_variable_refs(&args, &store).unwrap();
        assert_eq!(resolved.arguments["greeting"], "Hello Alice, welcome!");
        assert_eq!(resolved.referenced_vars, vec!["v-name"]);
    }

    #[test]
    fn generate_var_id_format() {
        let id = generate_var_id();
        assert!(id.starts_with("v-"));
        assert_eq!(id.len(), 10); // "v-" + 8 hex chars
    }

    #[test]
    fn generate_var_id_unique() {
        let id1 = generate_var_id();
        let id2 = generate_var_id();
        assert_ne!(id1, id2);
    }
}
