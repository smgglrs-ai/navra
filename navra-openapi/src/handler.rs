use crate::auth::AuthConfig;
use crate::parser::{Method, OperationMeta};
use navra_core::protocol::CallToolResult;
use reqwest::Client;

pub async fn execute_operation(
    client: &Client,
    base_url: &str,
    meta: &OperationMeta,
    args: &serde_json::Value,
    auth: &AuthConfig,
) -> CallToolResult {
    let url = match build_url(base_url, meta, args, auth) {
        Ok(u) => u,
        Err(e) => return CallToolResult::error(format!("Failed to build URL: {e}")),
    };

    let method = match &meta.method {
        Method::Get => reqwest::Method::GET,
        Method::Post => reqwest::Method::POST,
        Method::Put => reqwest::Method::PUT,
        Method::Patch => reqwest::Method::PATCH,
        Method::Delete => reqwest::Method::DELETE,
        Method::Head => reqwest::Method::HEAD,
        Method::Options => reqwest::Method::OPTIONS,
    };

    let mut req = client.request(method, &url);

    req = req.headers(auth.headers());

    if meta.has_body {
        if let Some(body) = args.get("body") {
            req = req.header("Content-Type", "application/json");
            req = req.json(body);
        }
    }

    let resp = match req.send().await {
        Ok(r) => r,
        Err(e) => return CallToolResult::error(format!("HTTP request failed: {e}")),
    };

    let status = resp.status();
    let body = match resp.text().await {
        Ok(b) => b,
        Err(e) => return CallToolResult::error(format!("Failed to read response: {e}")),
    };

    if status.is_success() {
        CallToolResult::text(body)
    } else {
        CallToolResult::error(format!("HTTP {status}: {body}"))
    }
}

fn build_url(
    base_url: &str,
    meta: &OperationMeta,
    args: &serde_json::Value,
    auth: &AuthConfig,
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

    for (k, v) in auth.query_params() {
        query_parts.push((k, v));
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
        let auth = AuthConfig::default();
        let url = build_url("https://api.example.com", &meta, &args, &auth).unwrap();
        assert_eq!(url, "https://api.example.com/pets/123");
    }

    #[test]
    fn build_url_with_query_params() {
        let meta = test_meta();
        let args = serde_json::json!({"petId": "123", "fields": "name,status"});
        let auth = AuthConfig::default();
        let url = build_url("https://api.example.com", &meta, &args, &auth).unwrap();
        assert_eq!(url, "https://api.example.com/pets/123?fields=name%2Cstatus");
    }

    #[test]
    fn build_url_missing_path_param_errors() {
        let meta = test_meta();
        let args = serde_json::json!({});
        let auth = AuthConfig::default();
        let err = build_url("https://api.example.com", &meta, &args, &auth).unwrap_err();
        assert!(err.contains("petId"));
    }

    #[test]
    fn build_url_numeric_path_param() {
        let meta = test_meta();
        let args = serde_json::json!({"petId": 42});
        let auth = AuthConfig::default();
        let url = build_url("https://api.example.com", &meta, &args, &auth).unwrap();
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
        let url = build_url("https://api.example.com", &meta, &args, &auth).unwrap();
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
        let auth = AuthConfig::default();
        let url = build_url("https://api.example.com", &meta, &args, &auth).unwrap();
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
        let auth = AuthConfig::default();
        let url = build_url("https://api.example.com", &meta, &args, &auth).unwrap();
        assert_eq!(url, "https://api.example.com/users/john%20doe%2Fadmin");
    }
}
