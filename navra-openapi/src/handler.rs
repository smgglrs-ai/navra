use crate::auth::AuthConfig;
use crate::parser::{Method, OperationMeta};
use navra_mcp::protocol::CallToolResult;
use navra_protocol::compat::CallToolResultExt;
use navra_protocol::truncate_str;
use reqwest::Client;

pub fn truncate_response(body: String, max_bytes: Option<usize>) -> String {
    let limit = match max_bytes {
        Some(l) if body.len() > l => l,
        _ => return body,
    };

    if let Ok(arr) = serde_json::from_str::<Vec<serde_json::Value>>(&body) {
        let mut kept = Vec::new();
        let mut size = 1; // opening '['
        for item in &arr {
            let serialized = serde_json::to_string(item).unwrap_or_default();
            let entry_cost = serialized.len() + if kept.is_empty() { 0 } else { 1 }; // comma
            if size + entry_cost + 1 > limit {
                break;
            }
            size += entry_cost;
            kept.push(serialized);
        }
        let dropped = arr.len() - kept.len();
        let mut result = format!("[{}]", kept.join(","));
        if dropped > 0 {
            result.push_str(&format!(
                "\n[truncated: showed {}/{} items, response was {} bytes]",
                kept.len(),
                arr.len(),
                body.len()
            ));
        }
        return result;
    }

    let safe_slice = truncate_str(&body, limit);
    let mut result = safe_slice.to_string();
    result.push_str(&format!(
        "\n[response truncated: {} bytes, showing first {}]",
        body.len(),
        safe_slice.len()
    ));
    result
}

pub async fn execute_operation(
    client: &Client,
    base_url: &str,
    meta: &OperationMeta,
    args: &serde_json::Value,
    auth: &AuthConfig,
    max_response_bytes: Option<usize>,
    expected_origin: Option<&str>,
) -> CallToolResult {
    let mut url = match build_url(base_url, meta, args) {
        Ok(u) => u,
        Err(e) => return CallToolResult::error_msg(format!("Failed to build URL: {e}")),
    };

    // Credential-origin pinning: never attach auth credentials when the
    // effective request origin differs from the configured/auth-expected
    // origin (or when no trusted origin could be established).
    if auth.has_credentials() {
        let request_origin = crate::url_origin(&url);
        match (expected_origin, request_origin.as_deref()) {
            (Some(expected), Some(actual)) if expected == actual => {
                url = append_auth_query_params(url, auth);
            }
            (expected, actual) => {
                tracing::error!(
                    expected_origin = ?expected,
                    request_origin = ?actual,
                    url = %url,
                    "OpenAPI bridge: refusing to attach credentials — \
                     request origin does not match the trusted origin"
                );
                return CallToolResult::error_msg(format!(
                    "refusing to attach credentials: request origin {} does \
                     not match the trusted origin {}",
                    actual.unwrap_or("<unparseable>"),
                    expected.unwrap_or("<none established>")
                ));
            }
        }
    }

    let method = match &meta.method {
        Method::Get => reqwest::Method::GET,
        Method::Post => reqwest::Method::POST,
        Method::Put => reqwest::Method::PUT,
        Method::Patch => reqwest::Method::PATCH,
        Method::Delete => reqwest::Method::DELETE,
        Method::Head => reqwest::Method::HEAD,
        Method::Options => reqwest::Method::OPTIONS,
    };

    let auth_headers = auth.headers_with_oauth().await;

    let resp = send_request(
        client,
        &method,
        &url,
        &auth_headers,
        meta,
        args,
        max_response_bytes,
    )
    .await;

    // On 401/403 with OAuth configured, try one token refresh then retry
    if let Some(ref mgr) = auth.oauth
        && let Ok(ref r) = resp
        && r.is_error == Some(true)
    {
        let body_text = r
            .content
            .first()
            .and_then(|c| c.as_text())
            .map(|t| t.text.as_str())
            .unwrap_or("");
        if body_text.contains("HTTP 401") || body_text.contains("HTTP 403") {
            tracing::info!("OAuth: received 401/403, attempting token refresh");
            match mgr.force_refresh().await {
                Ok(new_token) => {
                    let mut retry_headers = auth.headers();
                    if let Ok(val) =
                        reqwest::header::HeaderValue::from_str(&format!("Bearer {new_token}"))
                    {
                        retry_headers.insert(reqwest::header::AUTHORIZATION, val);
                    }
                    return send_request(
                        client,
                        &method,
                        &url,
                        &retry_headers,
                        meta,
                        args,
                        max_response_bytes,
                    )
                    .await
                    .unwrap_or_else(|e| {
                        CallToolResult::error_msg(format!("HTTP retry failed: {e}"))
                    });
                }
                Err(e) => {
                    tracing::warn!("OAuth token refresh failed: {e}");
                }
            }
        }
    }

    resp.unwrap_or_else(|e| CallToolResult::error_msg(format!("HTTP request failed: {e}")))
}

async fn send_request(
    client: &Client,
    method: &reqwest::Method,
    url: &str,
    headers: &reqwest::header::HeaderMap,
    meta: &OperationMeta,
    args: &serde_json::Value,
    max_response_bytes: Option<usize>,
) -> Result<CallToolResult, String> {
    let mut req = client.request(method.clone(), url);
    req = req.headers(headers.clone());

    if meta.has_body
        && let Some(body) = args.get("body")
    {
        req = req.header("Content-Type", "application/json");
        req = req.json(body);
    }

    let resp = req.send().await.map_err(|e| e.to_string())?;

    let status = resp.status();
    let max_body = max_response_bytes.unwrap_or(1024 * 1024);
    if let Some(len) = resp.content_length()
        && len as usize > max_body
    {
        return Ok(CallToolResult::error_msg(format!(
            "Response too large ({len} bytes, limit {max_body})"
        )));
    }
    let body = match resp.bytes().await {
        Ok(b) => {
            if b.len() > max_body {
                String::from_utf8_lossy(&b[..max_body]).into_owned()
            } else {
                String::from_utf8_lossy(&b).into_owned()
            }
        }
        Err(e) => {
            return Ok(CallToolResult::error_msg(format!(
                "Failed to read response: {e}"
            )));
        }
    };

    if status.is_success() {
        Ok(CallToolResult::text(truncate_response(
            body,
            max_response_bytes,
        )))
    } else {
        Ok(CallToolResult::error_msg(format!("HTTP {status}: {body}")))
    }
}

fn build_url(
    base_url: &str,
    meta: &OperationMeta,
    args: &serde_json::Value,
) -> Result<String, String> {
    let mut path = meta.path.clone();

    for param in &meta.path_params {
        let value = args
            .get(param)
            .map(|v| match v {
                serde_json::Value::String(s) => s.clone(),
                other => other.to_string(),
            })
            .ok_or_else(|| format!("Missing required path parameter: {param}"))?;
        path = path.replace(&format!("{{{param}}}"), &urlencoding::encode(&value));
    }

    let mut query_parts: Vec<(String, String)> = Vec::new();

    for param in &meta.query_params {
        if let Some(value) = args.get(param) {
            let v = match value {
                serde_json::Value::String(s) => s.clone(),
                other => other.to_string(),
            };
            query_parts.push((param.clone(), v));
        }
    }

    let mut url = format!("{base_url}{path}");
    if !query_parts.is_empty() {
        let qs: Vec<String> = query_parts
            .iter()
            .map(|(k, v)| format!("{}={}", urlencoding::encode(k), urlencoding::encode(v)))
            .collect();
        url.push('?');
        url.push_str(&qs.join("&"));
    }

    Ok(url)
}

/// Append query-string credentials (API keys) to a URL. Only called
/// after the URL's origin has been verified against the trusted origin.
fn append_auth_query_params(mut url: String, auth: &AuthConfig) -> String {
    let auth_query = auth.query_params();
    if auth_query.is_empty() {
        return url;
    }
    let qs: Vec<String> = auth_query
        .iter()
        .map(|(k, v)| format!("{}={}", urlencoding::encode(k), urlencoding::encode(v)))
        .collect();
    url.push(if url.contains('?') { '&' } else { '?' });
    url.push_str(&qs.join("&"));
    url
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parser::Method;

    fn test_meta() -> OperationMeta {
        OperationMeta {
            method: Method::Get,
            path: "/pets/{petId}".to_string(),
            path_params: vec!["petId".to_string()],
            query_params: vec!["fields".to_string()],
            has_body: false,
        }
    }

    #[test]
    fn build_url_with_path_params() {
        let meta = test_meta();
        let args = serde_json::json!({"petId": "123"});
        let url = build_url("https://api.example.com", &meta, &args).unwrap();
        assert_eq!(url, "https://api.example.com/pets/123");
    }

    #[test]
    fn build_url_with_query_params() {
        let meta = test_meta();
        let args = serde_json::json!({"petId": "123", "fields": "name,status"});
        let url = build_url("https://api.example.com", &meta, &args).unwrap();
        assert_eq!(url, "https://api.example.com/pets/123?fields=name%2Cstatus");
    }

    #[test]
    fn build_url_missing_path_param_errors() {
        let meta = test_meta();
        let args = serde_json::json!({});
        let err = build_url("https://api.example.com", &meta, &args).unwrap_err();
        assert!(err.contains("petId"));
    }

    #[test]
    fn build_url_numeric_path_param() {
        let meta = test_meta();
        let args = serde_json::json!({"petId": 42});
        let url = build_url("https://api.example.com", &meta, &args).unwrap();
        assert_eq!(url, "https://api.example.com/pets/42");
    }

    #[test]
    fn build_url_with_api_key_query() {
        let meta = OperationMeta {
            method: Method::Get,
            path: "/data".to_string(),
            path_params: vec![],
            query_params: vec![],
            has_body: false,
        };
        let args = serde_json::json!({});
        let auth = AuthConfig {
            api_key: Some(crate::auth::ApiKeyAuth {
                name: "api_key".to_string(),
                value: "secret123".to_string(),
                location: crate::auth::ApiKeyLocation::Query,
            }),
            ..Default::default()
        };
        let url = build_url("https://api.example.com", &meta, &args).unwrap();
        let url = append_auth_query_params(url, &auth);
        assert_eq!(url, "https://api.example.com/data?api_key=secret123");
    }

    #[test]
    fn build_url_encodes_special_chars_in_query() {
        let meta = OperationMeta {
            method: Method::Get,
            path: "/search".to_string(),
            path_params: vec![],
            query_params: vec!["q".to_string()],
            has_body: false,
        };
        let args = serde_json::json!({"q": "foo&bar=baz"});
        let url = build_url("https://api.example.com", &meta, &args).unwrap();
        assert_eq!(url, "https://api.example.com/search?q=foo%26bar%3Dbaz");
    }

    #[test]
    fn build_url_encodes_special_chars_in_path() {
        let meta = OperationMeta {
            method: Method::Get,
            path: "/users/{name}".to_string(),
            path_params: vec!["name".to_string()],
            query_params: vec![],
            has_body: false,
        };
        let args = serde_json::json!({"name": "john doe/admin"});
        let url = build_url("https://api.example.com", &meta, &args).unwrap();
        assert_eq!(url, "https://api.example.com/users/john%20doe%2Fadmin");
    }

    #[test]
    fn truncate_large_json_array() {
        let items: Vec<serde_json::Value> = (0..100)
            .map(|i| serde_json::json!({"id": i, "name": format!("item_{i}")}))
            .collect();
        let body = serde_json::to_string(&items).unwrap();
        let result = truncate_response(body.clone(), Some(500));
        assert!(result.len() < body.len());
        assert!(result.contains("[truncated:"));
        assert!(result.contains("100 items"));
        assert!(result.starts_with('['));
    }

    #[test]
    fn truncate_large_text() {
        let body = "x".repeat(10_000);
        let result = truncate_response(body, Some(1000));
        assert!(result.contains("[response truncated: 10000 bytes, showing first 1000]"));
        assert!(result.starts_with(&"x".repeat(1000)));
    }

    #[test]
    fn no_truncation_under_limit() {
        let body = "small response".to_string();
        let result = truncate_response(body.clone(), Some(1000));
        assert_eq!(result, body);
    }

    #[test]
    fn no_truncation_when_none() {
        let body = "x".repeat(100_000);
        let result = truncate_response(body.clone(), None);
        assert_eq!(result, body);
    }

    // ------------------------------------------------------------------
    // Credential-origin pinning (SSRF / credential-exfil prevention)
    // ------------------------------------------------------------------

    fn bearer_auth() -> AuthConfig {
        AuthConfig {
            bearer: Some("secret-token".to_string()),
            ..Default::default()
        }
    }

    fn simple_get_meta() -> OperationMeta {
        OperationMeta {
            method: Method::Get,
            path: "/data".to_string(),
            path_params: vec![],
            query_params: vec![],
            has_body: false,
        }
    }

    fn result_text(result: &CallToolResult) -> String {
        result
            .content
            .first()
            .and_then(|c| c.as_text())
            .map(|t| t.text.clone())
            .unwrap_or_default()
    }

    #[tokio::test]
    async fn credentials_refused_on_origin_mismatch() {
        // base URL points at evil.example.com but the trusted origin is
        // api.example.com — must refuse before any request is sent
        // (no network I/O happens for this test).
        let client = reqwest::Client::new();
        let auth = bearer_auth();
        let result = execute_operation(
            &client,
            "https://evil.example.com",
            &simple_get_meta(),
            &serde_json::json!({}),
            &auth,
            None,
            Some("https://api.example.com"),
        )
        .await;

        assert_eq!(result.is_error, Some(true));
        let text = result_text(&result);
        assert!(
            text.contains("refusing to attach credentials"),
            "unexpected error text: {text}"
        );
        assert!(
            text.contains("evil.example.com"),
            "error should name the origin: {text}"
        );
    }

    #[tokio::test]
    async fn credentials_refused_when_no_trusted_origin() {
        // No trusted origin established (e.g. unparseable base URL) —
        // fail closed rather than attaching credentials blindly.
        let client = reqwest::Client::new();
        let auth = bearer_auth();
        let result = execute_operation(
            &client,
            "https://api.example.com",
            &simple_get_meta(),
            &serde_json::json!({}),
            &auth,
            None,
            None,
        )
        .await;

        assert_eq!(result.is_error, Some(true));
        assert!(result_text(&result).contains("refusing to attach credentials"));
    }

    #[tokio::test]
    async fn no_credentials_no_origin_check_needed() {
        // Without credentials the origin check is skipped — the request
        // proceeds (here it simply fails to connect to a reserved port,
        // proving it was not short-circuited by the pinning check).
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_millis(500))
            .build()
            .unwrap();
        let result = execute_operation(
            &client,
            "http://127.0.0.1:1",
            &simple_get_meta(),
            &serde_json::json!({}),
            &AuthConfig::default(),
            None,
            Some("https://other.example.com"),
        )
        .await;

        let text = result_text(&result);
        assert!(
            !text.contains("refusing to attach credentials"),
            "origin pinning must not fire without credentials: {text}"
        );
    }

    #[test]
    fn append_auth_query_params_appends_after_existing_query() {
        let auth = AuthConfig {
            api_key: Some(crate::auth::ApiKeyAuth {
                name: "k".to_string(),
                value: "v".to_string(),
                location: crate::auth::ApiKeyLocation::Query,
            }),
            ..Default::default()
        };
        assert_eq!(
            append_auth_query_params("https://h.example/x?a=1".to_string(), &auth),
            "https://h.example/x?a=1&k=v"
        );
        assert_eq!(
            append_auth_query_params("https://h.example/x".to_string(), &auth),
            "https://h.example/x?k=v"
        );
        // No query credentials — URL unchanged
        assert_eq!(
            append_auth_query_params("https://h.example/x".to_string(), &AuthConfig::default()),
            "https://h.example/x"
        );
    }
}
