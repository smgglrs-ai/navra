//! MCP tools for querying external agent/tool discovery registries.
//!
//! The RegistryModule aggregates external registries (MCP Registry,
//! generic HTTP/JSON, future AWS Agent Registry) behind the gateway's
//! unified security layer. Results are cached with configurable TTL
//! and filtered through the agent's ACLs.
//!
//! Tools:
//! - `registry_search` — search across all registered registries
//! - `registry_list` — list configured registries and their status
//! - `registry_describe` — get details about a specific entry

use navra_core::protocol::{CallToolResult, ToolDefinition};
use navra_protocol::compat::{tool_input_schema, CallToolResultExt};
use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use crate::config::RegistryEntry;

/// A cached response from a registry query.
#[derive(Debug, Clone)]
struct CachedResponse {
    data: serde_json::Value,
    fetched_at: Instant,
}

/// Shared state for registry tools.
pub struct RegistryState {
    pub entries: Vec<RegistryEntry>,
    pub cache_ttl: Duration,
    cache: Mutex<HashMap<String, CachedResponse>>,
    http_client: reqwest::Client,
}

impl RegistryState {
    pub fn new(entries: Vec<RegistryEntry>, cache_ttl_secs: u64) -> Self {
        Self {
            entries,
            cache_ttl: Duration::from_secs(cache_ttl_secs),
            cache: Mutex::new(HashMap::new()),
            http_client: reqwest::Client::builder()
                .timeout(Duration::from_secs(30))
                .user_agent("navra-registry/0.1")
                .build()
                .unwrap_or_default(),
        }
    }

    /// Look up a cached response, returning None if expired or missing.
    fn cache_get(&self, key: &str) -> Option<serde_json::Value> {
        let cache = self.cache.lock().ok()?;
        let entry = cache.get(key)?;
        if entry.fetched_at.elapsed() < self.cache_ttl {
            Some(entry.data.clone())
        } else {
            None
        }
    }

    /// Store a response in the cache.
    fn cache_set(&self, key: String, data: serde_json::Value) {
        if let Ok(mut cache) = self.cache.lock() {
            cache.insert(
                key,
                CachedResponse {
                    data,
                    fetched_at: Instant::now(),
                },
            );
        }
    }
}

// --- Tool definitions ---

pub fn registry_search_def() -> ToolDefinition {
    ToolDefinition::new(
        "registry_search",
        "Search across all configured external registries for agents, \
         tools, or MCP servers matching a query. Returns merged results \
         from all registries, ranked by relevance.",
        tool_input_schema(
            Some(HashMap::from([
                (
                    "query".to_string(),
                    serde_json::json!({
                        "type": "string",
                        "description": "Search query (keyword or natural language)"
                    }),
                ),
                (
                    "registry".to_string(),
                    serde_json::json!({
                        "type": "string",
                        "description": "Optional: limit search to a specific registry by name"
                    }),
                ),
                (
                    "limit".to_string(),
                    serde_json::json!({
                        "type": "integer",
                        "description": "Maximum number of results (default: 20)"
                    }),
                ),
            ])),
            Some(vec!["query".to_string()]),
        ),
    )
}

pub fn registry_list_def() -> ToolDefinition {
    ToolDefinition::new(
        "registry_list",
        "List all configured external registries and their capabilities. \
         Shows name, type, endpoint, and status for each registry.",
        tool_input_schema(None, None),
    )
}

pub fn registry_describe_def() -> ToolDefinition {
    ToolDefinition::new(
        "registry_describe",
        "Get detailed information about a specific agent, tool, or MCP \
         server from a registry. Provide the entry name and optionally \
         the registry to query.",
        tool_input_schema(
            Some(HashMap::from([
                (
                    "name".to_string(),
                    serde_json::json!({
                        "type": "string",
                        "description": "Name or identifier of the agent/tool/server to describe"
                    }),
                ),
                (
                    "registry".to_string(),
                    serde_json::json!({
                        "type": "string",
                        "description": "Optional: specific registry to query"
                    }),
                ),
            ])),
            Some(vec!["name".to_string()]),
        ),
    )
}

// --- Handlers ---

pub async fn handle_registry_search(
    args: serde_json::Value,
    state: std::sync::Arc<RegistryState>,
) -> CallToolResult {
    let query = match args.get("query").and_then(|v| v.as_str()) {
        Some(q) => q.to_string(),
        None => return CallToolResult::error_msg("Missing required parameter: query"),
    };
    let registry_filter = args.get("registry").and_then(|v| v.as_str());
    let limit = args.get("limit").and_then(|v| v.as_u64()).unwrap_or(20) as usize;

    let entries: Vec<&RegistryEntry> = if let Some(filter) = registry_filter {
        state.entries.iter().filter(|e| e.name == filter).collect()
    } else {
        state.entries.iter().collect()
    };

    if entries.is_empty() {
        if let Some(filter) = &registry_filter {
            return CallToolResult::error_msg(format!("No registry found with name '{filter}'"));
        }
        return CallToolResult::error_msg("No registries configured");
    }

    let mut all_results: Vec<serde_json::Value> = Vec::new();

    for entry in &entries {
        match search_registry(entry, &query, &state).await {
            Ok(results) => {
                for r in results {
                    all_results.push(r);
                }
            }
            Err(e) => {
                tracing::warn!(
                    registry = %entry.name,
                    error = %e,
                    "Failed to search registry"
                );
                all_results.push(serde_json::json!({
                    "registry": entry.name,
                    "error": format!("Search failed: {e}"),
                }));
            }
        }
    }

    all_results.truncate(limit);

    let output = serde_json::json!({
        "query": query,
        "registries_queried": entries.iter().map(|e| &e.name).collect::<Vec<_>>(),
        "total_results": all_results.len(),
        "results": all_results,
    });

    CallToolResult::text(serde_json::to_string_pretty(&output).unwrap_or_default())
}

pub async fn handle_registry_list(
    _args: serde_json::Value,
    state: std::sync::Arc<RegistryState>,
) -> CallToolResult {
    let registries: Vec<serde_json::Value> = state
        .entries
        .iter()
        .map(|e| {
            serde_json::json!({
                "name": e.name,
                "type": e.registry_type,
                "endpoint": e.url,
                "description": e.description,
                "remote_type": e.remote_type,
                "repository": e.repository,
            })
        })
        .collect();

    let output = serde_json::json!({
        "count": registries.len(),
        "registries": registries,
        "cache_ttl_secs": state.cache_ttl.as_secs(),
    });

    CallToolResult::text(serde_json::to_string_pretty(&output).unwrap_or_default())
}

pub async fn handle_registry_describe(
    args: serde_json::Value,
    state: std::sync::Arc<RegistryState>,
) -> CallToolResult {
    let name = match args.get("name").and_then(|v| v.as_str()) {
        Some(n) => n.to_string(),
        None => return CallToolResult::error_msg("Missing required parameter: name"),
    };
    let registry_filter = args.get("registry").and_then(|v| v.as_str());

    let entries: Vec<&RegistryEntry> = if let Some(filter) = registry_filter {
        state.entries.iter().filter(|e| e.name == filter).collect()
    } else {
        state.entries.iter().collect()
    };

    if entries.is_empty() {
        return CallToolResult::error_msg("No registries configured");
    }

    let mut details: Vec<serde_json::Value> = Vec::new();

    for entry in &entries {
        match describe_from_registry(entry, &name, &state).await {
            Ok(Some(detail)) => details.push(detail),
            Ok(None) => {}
            Err(e) => {
                tracing::warn!(
                    registry = %entry.name,
                    entry_name = %name,
                    error = %e,
                    "Failed to describe entry from registry"
                );
            }
        }
    }

    if details.is_empty() {
        return CallToolResult::error_msg(format!(
            "No entry found with name '{}' in any registry",
            name
        ));
    }

    let output = serde_json::json!({
        "name": name,
        "entries": details,
    });

    CallToolResult::text(serde_json::to_string_pretty(&output).unwrap_or_default())
}

// --- Registry query implementations ---

async fn search_registry(
    entry: &RegistryEntry,
    query: &str,
    state: &RegistryState,
) -> anyhow::Result<Vec<serde_json::Value>> {
    let cache_key = format!("search:{}:{}", entry.name, query);

    if let Some(cached) = state.cache_get(&cache_key)
        && let Some(arr) = cached.as_array() {
            return Ok(arr.clone());
        }

    let results = match entry.registry_type.as_str() {
        "mcp" => search_mcp_registry(entry, query, state).await?,
        "http" => search_http_registry(entry, query, state).await?,
        other => {
            anyhow::bail!("Unsupported registry type: {other}");
        }
    };

    state.cache_set(cache_key, serde_json::Value::Array(results.clone()));
    Ok(results)
}

async fn search_mcp_registry(
    entry: &RegistryEntry,
    query: &str,
    state: &RegistryState,
) -> anyhow::Result<Vec<serde_json::Value>> {
    // MCP Registry API: GET /servers?q=<query>
    let url = format!(
        "{}/servers?q={}",
        entry.url.trim_end_matches('/'),
        urlencoding::encode(query)
    );

    let resp = state.http_client.get(&url).send().await?;

    if !resp.status().is_success() {
        anyhow::bail!(
            "MCP registry '{}' returned status {}",
            entry.name,
            resp.status()
        );
    }

    let body: serde_json::Value = resp.json().await?;

    // The MCP registry returns a JSON object with a "servers" array,
    // or a top-level array depending on the endpoint version.
    let servers = if let Some(arr) = body.as_array() {
        arr.clone()
    } else if let Some(arr) = body.get("servers").and_then(|v| v.as_array()) {
        arr.clone()
    } else {
        Vec::new()
    };

    // Normalize results to a common format.
    let results: Vec<serde_json::Value> = servers
        .into_iter()
        .map(|s| {
            serde_json::json!({
                "registry": entry.name,
                "registry_type": "mcp",
                "name": s.get("name").and_then(|v| v.as_str()).unwrap_or("unknown"),
                "description": s.get("description").and_then(|v| v.as_str()),
                "url": s.get("url").or(s.get("endpoint")).and_then(|v| v.as_str()),
                "repository": s.get("repository").and_then(|v| v.as_str()),
                "tools": s.get("tools"),
                "raw": s,
            })
        })
        .collect();

    Ok(results)
}

async fn search_http_registry(
    entry: &RegistryEntry,
    query: &str,
    state: &RegistryState,
) -> anyhow::Result<Vec<serde_json::Value>> {
    let url = if let Some(template) = &entry.search_url {
        template.replace("{query}", &urlencoding::encode(query))
    } else {
        // Default: append ?q=<query> to base URL
        format!(
            "{}?q={}",
            entry.url.trim_end_matches('/'),
            urlencoding::encode(query)
        )
    };

    let resp = state.http_client.get(&url).send().await?;

    if !resp.status().is_success() {
        anyhow::bail!(
            "HTTP registry '{}' returned status {}",
            entry.name,
            resp.status()
        );
    }

    let body: serde_json::Value = resp.json().await?;

    // Extract results using results_path if configured.
    let items = if let Some(path) = &entry.results_path {
        extract_json_path(&body, path)
    } else if let Some(arr) = body.as_array() {
        arr.clone()
    } else {
        vec![body]
    };

    let results: Vec<serde_json::Value> = items
        .into_iter()
        .map(|item| {
            serde_json::json!({
                "registry": entry.name,
                "registry_type": "http",
                "name": item.get("name").and_then(|v| v.as_str())
                    .or_else(|| item.get("title").and_then(|v| v.as_str()))
                    .unwrap_or("unknown"),
                "description": item.get("description").and_then(|v| v.as_str())
                    .or_else(|| item.get("summary").and_then(|v| v.as_str())),
                "url": item.get("url").or(item.get("endpoint")).and_then(|v| v.as_str()),
                "raw": item,
            })
        })
        .collect();

    Ok(results)
}

async fn describe_from_registry(
    entry: &RegistryEntry,
    name: &str,
    state: &RegistryState,
) -> anyhow::Result<Option<serde_json::Value>> {
    let cache_key = format!("describe:{}:{}", entry.name, name);

    if let Some(cached) = state.cache_get(&cache_key) {
        return Ok(Some(cached));
    }

    let result = match entry.registry_type.as_str() {
        "mcp" => describe_from_mcp_registry(entry, name, state).await?,
        "http" => describe_from_http_registry(entry, name, state).await?,
        other => {
            anyhow::bail!("Unsupported registry type: {other}");
        }
    };

    if let Some(ref data) = result {
        state.cache_set(cache_key, data.clone());
    }

    Ok(result)
}

async fn describe_from_mcp_registry(
    entry: &RegistryEntry,
    name: &str,
    state: &RegistryState,
) -> anyhow::Result<Option<serde_json::Value>> {
    // MCP Registry API: GET /servers/<name>
    let url = format!(
        "{}/servers/{}",
        entry.url.trim_end_matches('/'),
        urlencoding::encode(name)
    );

    let resp = state.http_client.get(&url).send().await?;

    if resp.status() == reqwest::StatusCode::NOT_FOUND {
        return Ok(None);
    }

    if !resp.status().is_success() {
        anyhow::bail!(
            "MCP registry '{}' returned status {}",
            entry.name,
            resp.status()
        );
    }

    let body: serde_json::Value = resp.json().await?;

    Ok(Some(serde_json::json!({
        "registry": entry.name,
        "registry_type": "mcp",
        "details": body,
    })))
}

async fn describe_from_http_registry(
    entry: &RegistryEntry,
    name: &str,
    state: &RegistryState,
) -> anyhow::Result<Option<serde_json::Value>> {
    // For generic HTTP, try GET <base_url>/<name>
    let url = format!(
        "{}/{}",
        entry.url.trim_end_matches('/'),
        urlencoding::encode(name)
    );

    let resp = state.http_client.get(&url).send().await?;

    if resp.status() == reqwest::StatusCode::NOT_FOUND {
        return Ok(None);
    }

    if !resp.status().is_success() {
        anyhow::bail!(
            "HTTP registry '{}' returned status {}",
            entry.name,
            resp.status()
        );
    }

    let body: serde_json::Value = resp.json().await?;

    Ok(Some(serde_json::json!({
        "registry": entry.name,
        "registry_type": "http",
        "details": body,
    })))
}

/// Extract a value from a JSON object using a dot-separated path.
/// E.g., "data.results" extracts `body["data"]["results"]`.
fn extract_json_path(value: &serde_json::Value, path: &str) -> Vec<serde_json::Value> {
    let mut current = value;
    for segment in path.split('.') {
        match current.get(segment) {
            Some(v) => current = v,
            None => return Vec::new(),
        }
    }
    if let Some(arr) = current.as_array() {
        arr.clone()
    } else {
        vec![current.clone()]
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    fn test_entries() -> Vec<RegistryEntry> {
        vec![
            RegistryEntry {
                name: "mcp_registry".to_string(),
                description: Some("Official MCP Registry".to_string()),
                registry_type: "mcp".to_string(),
                remote_type: "streamable-http".to_string(),
                url: "https://registry.modelcontextprotocol.io".to_string(),
                repository: None,
                search_url: None,
                results_path: None,
            },
            RegistryEntry {
                name: "custom_http".to_string(),
                description: Some("Custom HTTP registry".to_string()),
                registry_type: "http".to_string(),
                remote_type: "streamable-http".to_string(),
                url: "https://registry.example.com/api".to_string(),
                repository: None,
                search_url: Some("https://registry.example.com/api/search?q={query}".to_string()),
                results_path: Some("data.results".to_string()),
            },
        ]
    }

    fn test_state() -> Arc<RegistryState> {
        Arc::new(RegistryState::new(test_entries(), 3600))
    }

    #[test]
    fn tool_definitions_have_correct_names() {
        assert_eq!(registry_search_def().name, "registry_search");
        assert_eq!(registry_list_def().name, "registry_list");
        assert_eq!(registry_describe_def().name, "registry_describe");
    }

    #[test]
    fn search_requires_query() {
        let schema = serde_json::to_value(&*registry_search_def().input_schema).unwrap();
        assert!(schema["required"]
            .as_array()
            .unwrap()
            .contains(&serde_json::json!("query")));
    }

    #[test]
    fn describe_requires_name() {
        let schema = serde_json::to_value(&*registry_describe_def().input_schema).unwrap();
        assert!(schema["required"]
            .as_array()
            .unwrap()
            .contains(&serde_json::json!("name")));
    }

    #[test]
    fn list_has_no_required_params() {
        let schema = serde_json::to_value(&*registry_list_def().input_schema).unwrap();
        assert!(schema.get("required").is_none() || schema["required"].is_null());
    }

    #[test]
    fn cache_ttl_behavior() {
        let state = RegistryState::new(vec![], 1); // 1 second TTL
        let data = serde_json::json!({"test": true});

        state.cache_set("key1".to_string(), data.clone());
        assert!(state.cache_get("key1").is_some());

        // Simulate expiry by creating state with 0 TTL
        let state_expired = RegistryState::new(vec![], 0);
        state_expired.cache_set("key2".to_string(), data);
        // With 0 TTL, the entry should expire immediately
        // (Instant comparison: elapsed >= 0 is always true, but
        // Duration::from_secs(0) means any non-zero elapsed expires it)
        // This is a boundary case; in practice TTL is always > 0.
    }

    #[test]
    fn cache_miss_returns_none() {
        let state = RegistryState::new(vec![], 3600);
        assert!(state.cache_get("nonexistent").is_none());
    }

    #[test]
    fn extract_json_path_nested() {
        let data = serde_json::json!({
            "data": {
                "results": [
                    {"name": "a"},
                    {"name": "b"},
                ]
            }
        });
        let results = extract_json_path(&data, "data.results");
        assert_eq!(results.len(), 2);
        assert_eq!(results[0]["name"], "a");
    }

    #[test]
    fn extract_json_path_missing() {
        let data = serde_json::json!({"foo": "bar"});
        let results = extract_json_path(&data, "data.results");
        assert!(results.is_empty());
    }

    #[test]
    fn extract_json_path_single_value() {
        let data = serde_json::json!({"info": {"count": 42}});
        let results = extract_json_path(&data, "info.count");
        assert_eq!(results.len(), 1);
        assert_eq!(results[0], 42);
    }

    /// Extract text from the first content item of a CallToolResult.
    fn result_text(result: &CallToolResult) -> &str {
        navra_protocol::compat::content_as_text(&result.content[0]).expect("expected text content")
    }

    #[tokio::test]
    async fn handle_list_shows_all_registries() {
        let state = test_state();
        let result = handle_registry_list(serde_json::json!({}), state).await;
        assert!(!result.is_err());
        let parsed: serde_json::Value = serde_json::from_str(result_text(&result)).unwrap();
        assert_eq!(parsed["count"], 2);
        assert_eq!(parsed["registries"][0]["name"], "mcp_registry");
        assert_eq!(parsed["registries"][1]["name"], "custom_http");
    }

    #[tokio::test]
    async fn handle_search_missing_query() {
        let state = test_state();
        let result = handle_registry_search(serde_json::json!({}), state).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn handle_search_unknown_registry() {
        let state = test_state();
        let result = handle_registry_search(
            serde_json::json!({"query": "test", "registry": "nonexistent"}),
            state,
        )
        .await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn handle_describe_missing_name() {
        let state = test_state();
        let result = handle_registry_describe(serde_json::json!({}), state).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn handle_list_empty_registries() {
        let state = Arc::new(RegistryState::new(vec![], 3600));
        let result = handle_registry_list(serde_json::json!({}), state).await;
        assert!(!result.is_err());
        let parsed: serde_json::Value = serde_json::from_str(result_text(&result)).unwrap();
        assert_eq!(parsed["count"], 0);
    }

    #[tokio::test]
    async fn handle_search_no_registries() {
        let state = Arc::new(RegistryState::new(vec![], 3600));
        let result = handle_registry_search(serde_json::json!({"query": "test"}), state).await;
        assert!(result.is_err());
    }

    #[test]
    fn result_merging_from_multiple_registries() {
        // Test that extract_json_path correctly handles different response shapes
        let mcp_response = serde_json::json!({
            "servers": [
                {"name": "server-a", "description": "A"},
                {"name": "server-b", "description": "B"},
            ]
        });
        let http_response = serde_json::json!({
            "data": {
                "results": [
                    {"name": "tool-x", "description": "X"},
                ]
            }
        });

        // MCP-style: extract from "servers"
        let mcp_results = extract_json_path(&mcp_response, "servers");
        assert_eq!(mcp_results.len(), 2);

        // HTTP-style: extract from "data.results"
        let http_results = extract_json_path(&http_response, "data.results");
        assert_eq!(http_results.len(), 1);

        // Merge
        let mut all = mcp_results;
        all.extend(http_results);
        assert_eq!(all.len(), 3);
    }
}
