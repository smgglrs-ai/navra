pub mod auth;
pub mod handler;
pub mod parser;

use auth::AuthConfig;
use navra_mcp::protocol::ToolDefinition;
use navra_mcp::{Module, ToolHandler, ToolOperation};
use parser::{Method, ParsedOperation};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

pub struct OpenApiModule {
    name: String,
    tools: Vec<ParsedOperation>,
    client: reqwest::Client,
    base_url: String,
    auth: AuthConfig,
    max_response_bytes: Option<usize>,
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
        let spec_text = fetch_spec(spec_source).await?;
        let spec = if spec_source.ends_with(".yaml")
            || spec_source.ends_with(".yml")
            || spec_text.starts_with("openapi:")
            || spec_text.starts_with("swagger:")
        {
            parser::parse_spec_yaml(&spec_text)?
        } else {
            parser::parse_spec(&spec_text)?
        };

        let base_url = parser::extract_base_url(&spec);
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
        })
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
        self.tools
            .retain(|parsed| match overrides.get(&parsed.definition.name) {
                Some(v) if v == "deny" => {
                    tracing::info!(
                        tool = %parsed.definition.name,
                        "OpenAPI tool denied by tool_overrides, removing"
                    );
                    false
                }
                _ => true,
            });
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
                (parsed.definition.name.clone(), op)
            })
            .collect()
    }
}

const MAX_SPEC_SIZE: usize = 10 * 1024 * 1024; // 10 MiB

async fn fetch_spec(source: &str) -> anyhow::Result<String> {
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
        if let Some(len) = resp.content_length() {
            if len as usize > MAX_SPEC_SIZE {
                anyhow::bail!(
                    "OpenAPI spec too large ({len} bytes, max {MAX_SPEC_SIZE})"
                );
            }
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
        if let Some(m) = meta {
            if m.len() as usize > MAX_SPEC_SIZE {
                anyhow::bail!(
                    "OpenAPI spec file too large ({} bytes, max {MAX_SPEC_SIZE})",
                    m.len()
                );
            }
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

                let handler: ToolHandler = Arc::new(move |args, _ctx| {
                    let client = client.clone();
                    let base_url = base_url.clone();
                    let meta = meta.clone();
                    let auth = auth.clone();
                    Box::pin(async move {
                        handler::execute_operation(
                            &client,
                            &base_url,
                            &meta,
                            &args,
                            &auth,
                            max_response_bytes,
                        )
                        .await
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
        let names: Vec<&str> = tools.iter().map(|t| t.0.name.as_str()).collect();
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
}
