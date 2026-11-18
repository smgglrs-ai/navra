pub mod auth;
pub mod handler;
pub mod oauth;
pub mod parser;

use auth::AuthConfig;
use navra_mcp::protocol::ToolDefinition;
use navra_mcp::{Module, ToolHandler, ToolOperation};
use parser::{Method, ParsedOperation};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

/// Security policy for where an OpenAPI spec may be fetched from and
/// which base URL the bridge may talk to.
///
/// Defaults are the secure choices: plaintext `http://` spec sources
/// are refused, and the spec's own `servers[0].url` is used as the
/// bridge base URL.
#[derive(Debug, Clone, Default)]
pub struct SpecSourcePolicy {
    /// Allow fetching specs from `http://` (plaintext) sources.
    ///
    /// A plaintext spec fetch leaks any credentials attached to the
    /// bridged API in transit and lets a network attacker substitute
    /// the spec (pointing the bridge — and its credentials — at a
    /// host of the attacker's choosing). Only enable for trusted
    /// local networks after review.
    pub allow_insecure_spec: bool,
    /// Explicit base URL override, primarily for local-file specs.
    ///
    /// Takes precedence over the spec's `servers[0].url`. The origin
    /// (scheme+host+port) of this URL becomes the only origin that
    /// auth credentials will ever be attached to.
    pub base_url_override: Option<String>,
}

pub struct OpenApiModule {
    name: String,
    tools: Vec<ParsedOperation>,
    client: reqwest::Client,
    base_url: String,
    auth: AuthConfig,
    max_response_bytes: Option<usize>,
    /// Origin (scheme+host+port) that credentials may be attached to.
    /// `None` means no origin could be established — credentials are
    /// then never attached (fail-closed).
    auth_origin: Option<String>,
}

impl OpenApiModule {
    pub async fn from_spec(
        name: &str,
        spec_source: &str,
        auth: AuthConfig,
        filter: &[String],
    ) -> anyhow::Result<Self> {
        Self::from_spec_with_timeout(name, spec_source, auth, filter, None, None).await
    }

    pub async fn from_spec_with_timeout(
        name: &str,
        spec_source: &str,
        auth: AuthConfig,
        filter: &[String],
        request_timeout: Option<Duration>,
        max_response_bytes: Option<usize>,
    ) -> anyhow::Result<Self> {
        // Secure defaults: no plaintext spec sources, no base URL override.
        Self::from_spec_with_policy(
            name,
            spec_source,
            auth,
            filter,
            request_timeout,
            max_response_bytes,
            SpecSourcePolicy::default(),
        )
        .await
    }

    /// Build a bridge with an explicit [`SpecSourcePolicy`].
    ///
    /// Security invariants enforced here:
    /// - `http://` spec sources are refused unless
    ///   `policy.allow_insecure_spec` is set.
    /// - When the spec is fetched from a URL, the spec's
    ///   `servers[0].url` origin must match the spec source's origin —
    ///   a mismatch means the spec is trying to redirect the bridge
    ///   (and its credentials) elsewhere and the bridge is refused.
    /// - `policy.base_url_override` (intended for local-file specs)
    ///   takes precedence over `servers[0].url`; its origin becomes
    ///   the only origin credentials will be attached to.
    pub async fn from_spec_with_policy(
        name: &str,
        spec_source: &str,
        auth: AuthConfig,
        filter: &[String],
        request_timeout: Option<Duration>,
        max_response_bytes: Option<usize>,
        policy: SpecSourcePolicy,
    ) -> anyhow::Result<Self> {
        let is_url = spec_source.starts_with("http://") || spec_source.starts_with("https://");
        let spec_text = fetch_spec(spec_source, policy.allow_insecure_spec).await?;
        let spec = if spec_source.ends_with(".yaml")
            || spec_source.ends_with(".yml")
            || spec_text.starts_with("openapi:")
            || spec_text.starts_with("swagger:")
        {
            parser::parse_spec_yaml(&spec_text)?
        } else {
            parser::parse_spec(&spec_text)?
        };

        let spec_base_url = parser::extract_base_url(&spec);
        let base_url = match &policy.base_url_override {
            Some(override_url) => override_url.trim_end_matches('/').to_string(),
            None => spec_base_url.clone(),
        };
        if base_url.is_empty() {
            anyhow::bail!(
                "OpenAPI spec '{spec_source}' declares no servers[0].url and no \
                 base_url_override was provided — refusing bridge with no target"
            );
        }

        // Origin pinning. For URL-sourced specs the spec source's origin
        // is the only origin the bridge (and its credentials) may talk
        // to; a servers[0].url pointing elsewhere is refused. For
        // local-file specs the effective base URL's origin is trusted.
        let auth_origin: Option<String> = if is_url {
            let source_origin = url_origin(spec_source)
                .ok_or_else(|| anyhow::anyhow!("invalid spec source URL: {spec_source}"))?;
            let spec_origin = url_origin(&spec_base_url).ok_or_else(|| {
                anyhow::anyhow!(
                    "spec servers[0].url '{spec_base_url}' is not an absolute \
                     http(s) URL"
                )
            })?;
            if source_origin != spec_origin {
                tracing::error!(
                    upstream = %name,
                    spec_source = %spec_source,
                    source_origin = %source_origin,
                    spec_servers_origin = %spec_origin,
                    "OpenAPI bridge refused: servers[0].url origin does not \
                     match the spec source origin (possible spec substitution)"
                );
                anyhow::bail!(
                    "refusing OpenAPI bridge '{name}': spec at {spec_source} \
                     declares servers[0].url '{spec_base_url}' (origin \
                     {spec_origin}) which does not match the spec source \
                     origin {source_origin}. If this is intentional, pass a \
                     SpecSourcePolicy base_url_override pinned to the \
                     intended origin"
                );
            }
            Some(source_origin)
        } else {
            url_origin(&base_url)
        };

        let tools = parser::generate_tools(&spec, name, filter);

        let mut client_builder = reqwest::Client::builder();
        if let Some(timeout) = request_timeout {
            client_builder = client_builder.timeout(timeout);
        }
        let client = client_builder.build().unwrap_or_default();

        tracing::info!(
            upstream = %name,
            tools = tools.len(),
            base_url = %base_url,
            timeout_secs = ?request_timeout.map(|d| d.as_secs()),
            "OpenAPI bridge: parsed spec"
        );

        Ok(Self {
            name: name.to_string(),
            tools,
            client,
            base_url,
            auth,
            max_response_bytes,
            auth_origin,
        })
    }

    /// The base URL all bridged requests are sent to.
    pub fn base_url(&self) -> &str {
        &self.base_url
    }

    pub fn tool_count(&self) -> usize {
        self.tools.len()
    }

    /// Run the tool scanner on generated tools, removing malicious ones.
    pub fn scan_tools(&mut self, scanner: &mut navra_auth::tool_scanner::ToolScanner) {
        use navra_auth::tool_scanner::ScanVerdict;
        let defs: Vec<_> = self.tools.iter().map(|p| p.definition.clone()).collect();
        let results = scanner.scan_tools(&self.name, &defs);
        let mut keep = vec![true; self.tools.len()];
        for (i, result) in results.iter().enumerate() {
            match &result.verdict {
                ScanVerdict::Malicious { reasons } => {
                    tracing::error!(
                        upstream = %self.name,
                        tool = %result.tool_name,
                        reasons = ?reasons,
                        "BLOCKED malicious OpenAPI tool"
                    );
                    keep[i] = false;
                }
                ScanVerdict::Suspicious { reasons } => {
                    tracing::warn!(
                        upstream = %self.name,
                        tool = %result.tool_name,
                        reasons = ?reasons,
                        "Suspicious OpenAPI tool (allowed)"
                    );
                }
                ScanVerdict::Safe => {}
            }
        }
        let mut idx = 0;
        self.tools.retain(|_| {
            let k = keep[idx];
            idx += 1;
            k
        });
    }

    /// Remove tools marked "deny" in tool_overrides so they never
    /// appear in tools/list or tool_operations().
    pub fn apply_overrides(&mut self, overrides: &HashMap<String, String>) {
        self.tools.retain(
            |parsed| match overrides.get(parsed.definition.name.as_ref()) {
                Some(v) if v == "deny" => {
                    tracing::info!(
                        tool = %parsed.definition.name,
                        "OpenAPI tool denied by tool_overrides, removing"
                    );
                    false
                }
                _ => true,
            },
        );
    }

    pub fn tool_operations(&self) -> HashMap<String, ToolOperation> {
        self.tools
            .iter()
            .map(|parsed| {
                let op = match parsed.meta.method {
                    Method::Get | Method::Head | Method::Options => ToolOperation::Read,
                    Method::Post | Method::Put | Method::Patch | Method::Delete => {
                        ToolOperation::Write
                    }
                };
                (parsed.definition.name.to_string(), op)
            })
            .collect()
    }
}

const MAX_SPEC_SIZE: usize = 10 * 1024 * 1024; // 10 MiB

/// Extract the origin (scheme + normalized host + port) of an absolute
/// http(s) URL. Default ports are normalized (`https://h` ==
/// `https://h:443`). Returns `None` for non-http(s) or unparseable
/// inputs.
pub(crate) fn url_origin(url: &str) -> Option<String> {
    let (scheme, rest) = url.split_once("://")?;
    if !matches!(scheme, "http" | "https") {
        return None;
    }
    // Strip path, query, fragment
    let authority = rest.split(['/', '?', '#']).next()?;
    // Strip userinfo (user:pass@host)
    let authority = match authority.rsplit_once('@') {
        Some((_, host_port)) => host_port,
        None => authority,
    };
    let default_port = if scheme == "https" { "443" } else { "80" };
    let (host, port) = if let Some(rest) = authority.strip_prefix('[') {
        // IPv6 literal: [::1] or [::1]:8080
        let (h, rest) = rest.split_once(']')?;
        let p = rest
            .strip_prefix(':')
            .filter(|p| !p.is_empty() && p.chars().all(|c| c.is_ascii_digit()))
            .unwrap_or(default_port);
        (h.to_string(), p.to_string())
    } else {
        match authority.rsplit_once(':') {
            Some((h, p)) if !p.is_empty() && p.chars().all(|c| c.is_ascii_digit()) => {
                (h.to_string(), p.to_string())
            }
            _ => (authority.to_string(), default_port.to_string()),
        }
    };
    if host.is_empty() {
        return None;
    }
    Some(format!("{scheme}://{host}:{port}"))
}

async fn fetch_spec(source: &str, allow_insecure: bool) -> anyhow::Result<String> {
    if source.starts_with("http://") {
        if !allow_insecure {
            anyhow::bail!(
                "refusing to fetch OpenAPI spec from plaintext http:// source \
                 {source}: a plaintext spec fetch exposes bridged credentials \
                 in transit and allows spec substitution by a network \
                 attacker. Use https://, a local spec file, or explicitly \
                 opt in with SpecSourcePolicy {{ allow_insecure_spec: true }}"
            );
        }
        tracing::warn!(
            source = %source,
            "Fetching OpenAPI spec over plaintext http:// (allow_insecure_spec set)"
        );
    }
    if source.starts_with("http://") || source.starts_with("https://") {
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(30))
            .build()
            .map_err(|e| anyhow::anyhow!("HTTP client error: {e}"))?;
        let resp = client
            .get(source)
            .send()
            .await
            .map_err(|e| anyhow::anyhow!("Failed to fetch OpenAPI spec from {source}: {e}"))?;
        let status = resp.status();
        if !status.is_success() {
            anyhow::bail!("Failed to fetch OpenAPI spec from {source}: HTTP {status}");
        }
        if let Some(len) = resp.content_length()
            && len as usize > MAX_SPEC_SIZE
        {
            anyhow::bail!("OpenAPI spec too large ({len} bytes, max {MAX_SPEC_SIZE})");
        }
        let bytes = resp
            .bytes()
            .await
            .map_err(|e| anyhow::anyhow!("Failed to read spec response: {e}"))?;
        if bytes.len() > MAX_SPEC_SIZE {
            anyhow::bail!(
                "OpenAPI spec too large ({} bytes, max {MAX_SPEC_SIZE})",
                bytes.len()
            );
        }
        String::from_utf8(bytes.to_vec())
            .map_err(|e| anyhow::anyhow!("Spec is not valid UTF-8: {e}"))
    } else {
        let meta = tokio::fs::metadata(source).await.ok();
        if let Some(m) = meta
            && m.len() as usize > MAX_SPEC_SIZE
        {
            anyhow::bail!(
                "OpenAPI spec file too large ({} bytes, max {MAX_SPEC_SIZE})",
                m.len()
            );
        }
        tokio::fs::read_to_string(source)
            .await
            .map_err(|e| anyhow::anyhow!("Failed to read OpenAPI spec from {source}: {e}"))
    }
}

impl Module for OpenApiModule {
    fn name(&self) -> &str {
        &self.name
    }

    fn tools(&self) -> Vec<(ToolDefinition, ToolHandler)> {
        self.tools
            .iter()
            .map(|parsed| {
                let client = self.client.clone();
                let base_url = self.base_url.clone();
                let meta = parsed.meta.clone();
                let auth = self.auth.clone();
                let max_response_bytes = self.max_response_bytes;
                let auth_origin = self.auth_origin.clone();

                let handler: ToolHandler = Arc::new(move |args, _ctx| {
                    let client = client.clone();
                    let base_url = base_url.clone();
                    let meta = meta.clone();
                    let auth = auth.clone();
                    let auth_origin = auth_origin.clone();
                    Box::pin(async move {
                        // OpenAPI bridge tools always produce a final
                        // result; widen into the response union.
                        navra_protocol::CallToolResponse::Complete(
                            handler::execute_operation(
                                &client,
                                &base_url,
                                &meta,
                                &args,
                                &auth,
                                max_response_bytes,
                                auth_origin.as_deref(),
                            )
                            .await,
                        )
                    })
                });

                (parsed.definition.clone(), handler)
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn petstore_spec() -> &'static str {
        r#"{
            "openapi": "3.0.0",
            "info": { "title": "Petstore", "version": "1.0.0" },
            "servers": [{ "url": "https://petstore.example.com/v1" }],
            "paths": {
                "/pets": {
                    "get": {
                        "operationId": "listPets",
                        "summary": "List all pets",
                        "parameters": [
                            {
                                "name": "limit",
                                "in": "query",
                                "schema": { "type": "integer" }
                            }
                        ],
                        "responses": { "200": { "description": "OK" } }
                    },
                    "post": {
                        "operationId": "createPet",
                        "summary": "Create a pet",
                        "requestBody": {
                            "content": {
                                "application/json": {
                                    "schema": { "type": "object" }
                                }
                            }
                        },
                        "responses": { "201": { "description": "Created" } }
                    }
                }
            }
        }"#
    }

    #[tokio::test]
    async fn module_from_inline_spec() {
        let tmpfile = std::env::temp_dir().join("navra_openapi_test.json");
        tokio::fs::write(&tmpfile, petstore_spec()).await.unwrap();

        let module = OpenApiModule::from_spec(
            "petstore",
            tmpfile.to_str().unwrap(),
            AuthConfig::default(),
            &[],
        )
        .await
        .unwrap();

        assert_eq!(module.name(), "petstore");
        assert_eq!(module.tool_count(), 2);

        let tools = module.tools();
        assert_eq!(tools.len(), 2);
        let names: Vec<&str> = tools.iter().map(|t| &*t.0.name).collect();
        assert!(names.contains(&"petstore_listpets"));
        assert!(names.contains(&"petstore_createpet"));

        tokio::fs::remove_file(&tmpfile).await.ok();
    }

    #[tokio::test]
    async fn tool_operations_classifies_methods() {
        let tmpfile = std::env::temp_dir().join("navra_openapi_test_ops.json");
        tokio::fs::write(&tmpfile, petstore_spec()).await.unwrap();

        let module = OpenApiModule::from_spec(
            "petstore",
            tmpfile.to_str().unwrap(),
            AuthConfig::default(),
            &[],
        )
        .await
        .unwrap();

        let ops = module.tool_operations();
        assert_eq!(
            ops.get("petstore_listpets"),
            Some(&navra_mcp::ToolOperation::Read)
        );
        assert_eq!(
            ops.get("petstore_createpet"),
            Some(&navra_mcp::ToolOperation::Write)
        );

        tokio::fs::remove_file(&tmpfile).await.ok();
    }

    #[tokio::test]
    async fn apply_overrides_removes_denied_tools() {
        let tmpfile = std::env::temp_dir().join("navra_openapi_test_deny.json");
        tokio::fs::write(&tmpfile, petstore_spec()).await.unwrap();

        let mut module = OpenApiModule::from_spec(
            "petstore",
            tmpfile.to_str().unwrap(),
            AuthConfig::default(),
            &[],
        )
        .await
        .unwrap();

        assert_eq!(module.tool_count(), 2);

        let mut overrides = HashMap::new();
        overrides.insert("petstore_createpet".to_string(), "deny".to_string());
        module.apply_overrides(&overrides);

        assert_eq!(module.tool_count(), 1);
        let tools = module.tools();
        assert_eq!(tools[0].0.name, "petstore_listpets");

        // Denied tool should also be absent from tool_operations
        let ops = module.tool_operations();
        assert!(!ops.contains_key("petstore_createpet"));

        tokio::fs::remove_file(&tmpfile).await.ok();
    }

    #[tokio::test]
    async fn module_with_filter() {
        let tmpfile = std::env::temp_dir().join("navra_openapi_test_filter.json");
        tokio::fs::write(&tmpfile, petstore_spec()).await.unwrap();

        let module = OpenApiModule::from_spec(
            "petstore",
            tmpfile.to_str().unwrap(),
            AuthConfig::default(),
            &["listPets".to_string()],
        )
        .await
        .unwrap();

        assert_eq!(module.tool_count(), 1);
        let tools = module.tools();
        assert_eq!(tools[0].0.name, "petstore_listpets");

        tokio::fs::remove_file(&tmpfile).await.ok();
    }

    // ------------------------------------------------------------------
    // Spec-source security (SSRF / credential-exfil prevention)
    // ------------------------------------------------------------------

    #[test]
    fn url_origin_normalization() {
        assert_eq!(
            url_origin("https://api.example.com/v1").as_deref(),
            Some("https://api.example.com:443")
        );
        assert_eq!(
            url_origin("https://api.example.com:443/v1").as_deref(),
            Some("https://api.example.com:443")
        );
        assert_eq!(
            url_origin("http://api.example.com").as_deref(),
            Some("http://api.example.com:80")
        );
        assert_eq!(
            url_origin("http://api.example.com:8080/x?q=1#frag").as_deref(),
            Some("http://api.example.com:8080")
        );
        assert_eq!(
            url_origin("https://user:pass@api.example.com/v1").as_deref(),
            Some("https://api.example.com:443")
        );
        assert_eq!(
            url_origin("http://[::1]:9000/api").as_deref(),
            Some("http://[::1]:9000")
        );
        assert_eq!(url_origin("ftp://api.example.com"), None);
        assert_eq!(url_origin("not-a-url"), None);
        assert_eq!(url_origin("http://"), None);
    }

    #[tokio::test]
    async fn insecure_http_spec_source_refused_by_default() {
        let err = OpenApiModule::from_spec(
            "api",
            "http://127.0.0.1:9/spec.json",
            AuthConfig::default(),
            &[],
        )
        .await
        .err()
        .expect("from_spec must fail");
        let msg = err.to_string();
        assert!(
            msg.contains("allow_insecure_spec"),
            "error must name the escape hatch: {msg}"
        );
        assert!(msg.contains("http://"), "error must name the source: {msg}");
    }

    /// Minimal axum server that serves `body` at GET /spec.json.
    async fn spec_server(body: String) -> (u16, tokio::task::JoinHandle<()>) {
        let app = axum::Router::new().route(
            "/spec.json",
            axum::routing::get(move || {
                let body = body.clone();
                async move { axum::Json(serde_json::from_str::<serde_json::Value>(&body).unwrap()) }
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let handle = tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        (port, handle)
    }

    fn spec_with_servers(servers_url: String) -> String {
        serde_json::json!({
            "openapi": "3.0.0",
            "info": { "title": "T", "version": "1.0.0" },
            "servers": [{ "url": servers_url }],
            "paths": {}
        })
        .to_string()
    }

    #[tokio::test]
    async fn origin_mismatched_servers_url_refused() {
        // Spec served over http://127.0.0.1:PORT but declaring a
        // servers[0].url on a different origin — classic spec-
        // substitution / credential-exfil attempt. Even with
        // allow_insecure_spec set, the mismatch must be refused.
        let (port, _handle) =
            spec_server(spec_with_servers("https://evil.example.com/v1".to_string())).await;

        let policy = SpecSourcePolicy {
            allow_insecure_spec: true,
            base_url_override: None,
        };
        let err = OpenApiModule::from_spec_with_policy(
            "api",
            &format!("http://127.0.0.1:{port}/spec.json"),
            AuthConfig::default(),
            &[],
            None,
            None,
            policy,
        )
        .await
        .err()
        .expect("from_spec must fail");

        let msg = err.to_string();
        assert!(
            msg.contains("does not match the spec source origin"),
            "error must explain the origin mismatch: {msg}"
        );
        assert!(
            msg.contains("evil.example.com"),
            "error should name the offending servers url: {msg}"
        );
    }

    #[tokio::test]
    async fn http_source_with_matching_origin_loads_when_explicitly_allowed() {
        let (port, _handle) =
            spec_server(spec_with_servers(format!("http://127.0.0.1:{port}/v1"))).await;

        let policy = SpecSourcePolicy {
            allow_insecure_spec: true,
            base_url_override: None,
        };
        let module = OpenApiModule::from_spec_with_policy(
            "api",
            &format!("http://127.0.0.1:{port}/spec.json"),
            AuthConfig::default(),
            &[],
            None,
            None,
            policy,
        )
        .await
        .unwrap();

        assert_eq!(module.base_url(), format!("http://127.0.0.1:{port}/v1"));
    }

    #[tokio::test]
    async fn http_source_servers_url_trailing_slash_stripped_in_base() {
        let (port, _handle) =
            spec_server(spec_with_servers(format!("http://127.0.0.1:{port}/v1/"))).await;

        let policy = SpecSourcePolicy {
            allow_insecure_spec: true,
            base_url_override: None,
        };
        let module = OpenApiModule::from_spec_with_policy(
            "api",
            &format!("http://127.0.0.1:{port}/spec.json"),
            AuthConfig::default(),
            &[],
            None,
            None,
            policy,
        )
        .await
        .unwrap();
        assert_eq!(module.base_url(), format!("http://127.0.0.1:{port}/v1"));
    }

    #[tokio::test]
    async fn local_spec_base_url_override_takes_precedence() {
        let tmpfile = std::env::temp_dir().join("navra_openapi_test_override.json");
        tokio::fs::write(&tmpfile, petstore_spec()).await.unwrap();

        let policy = SpecSourcePolicy {
            allow_insecure_spec: false,
            base_url_override: Some("https://override.example.com/api".to_string()),
        };
        let module = OpenApiModule::from_spec_with_policy(
            "petstore",
            tmpfile.to_str().unwrap(),
            AuthConfig::default(),
            &[],
            None,
            None,
            policy,
        )
        .await
        .unwrap();

        // Override wins over the spec's servers[0].url
        // (https://petstore.example.com/v1)...
        assert_eq!(module.base_url(), "https://override.example.com/api");
        // ...and becomes the origin credentials may attach to.
        assert_eq!(
            module.auth_origin.as_deref(),
            Some("https://override.example.com:443")
        );

        tokio::fs::remove_file(&tmpfile).await.ok();
    }

    #[tokio::test]
    async fn local_spec_without_servers_or_override_refused() {
        let tmpfile = std::env::temp_dir().join("navra_openapi_test_noservers.json");
        tokio::fs::write(
            &tmpfile,
            r#"{
                "openapi": "3.0.0",
                "info": { "title": "T", "version": "1.0.0" },
                "paths": {}
            }"#,
        )
        .await
        .unwrap();

        let err =
            OpenApiModule::from_spec("api", tmpfile.to_str().unwrap(), AuthConfig::default(), &[])
                .await
                .err()
                .expect("from_spec must fail");
        assert!(
            err.to_string().contains("base_url_override"),
            "error should point at the override escape hatch: {err}"
        );

        tokio::fs::remove_file(&tmpfile).await.ok();
    }
}
