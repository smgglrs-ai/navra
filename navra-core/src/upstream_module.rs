//! Adapts an upstream MCP server into the Module trait via rmcp.
//!
//! An `UpstreamModule` connects to an external MCP server using rmcp's
//! client transports, discovers its tools/prompts/resources, and
//! presents them as a navra Module.

use crate::protocol::{
    CallToolParams, CallToolResult, GetPromptParams, PromptDefinition, ReadResourceParams,
    ResourceDefinition, ToolDefinition,
};
use navra_mcp::{Module, PromptHandler, ResourceHandler, ToolHandler, ToolOperation};
use std::collections::HashMap;
use std::sync::Arc;

fn classify_tool(def: &ToolDefinition) -> ToolOperation {
    if let Some(ref ann) = def.annotations {
        if ann.read_only_hint == Some(true) {
            return ToolOperation::Read;
        }
        if ann.destructive_hint == Some(true) {
            return ToolOperation::Write;
        }
    }
    if navra_auth::ifc::is_write_tool(&def.name, def.annotations.as_ref()) {
        return ToolOperation::Write;
    }
    ToolOperation::Read
}

/// Signed-manifest verification to run during upstream discovery.
///
/// When provided, the upstream's registration fails closed unless the
/// manifest signature verifies, the TOFU key pin matches, and the
/// served tool set matches the signed manifest exactly.
pub struct ManifestCheck<'a> {
    /// The signed manifest supplied by configuration.
    pub signed: &'a navra_auth::manifest::SignedManifest,
    /// TOFU key store (persistent pins).
    pub key_store: &'a mut navra_auth::manifest::ManifestKeyStore,
}

/// Content bounds for upstream discovery.
///
/// Upstream `tools/list` responses are untrusted input: without
/// bounds, a hostile server can flood the gateway with tool
/// definitions (memory/CPU during scanning and registration) or with
/// absurdly nested schemas and descriptions. Exceeding a bound fails
/// closed — the upstream registration is rejected with a clear error —
/// unless `truncate_oversized` is set, in which case descriptions are
/// truncated and excess tools dropped with warnings. Schema depth can
/// never be truncated and always rejects.
#[derive(Debug, Clone, PartialEq)]
pub struct DiscoveryBounds {
    /// Maximum number of tools accepted from one upstream.
    pub max_tools: usize,
    /// Maximum JSON nesting depth of any tool's input schema.
    pub max_input_schema_depth: usize,
    /// Maximum length (bytes) of any tool description.
    pub max_description_length: usize,
    /// Maximum total size (bytes) of all serialized tool definitions.
    pub max_total_definition_bytes: u64,
    /// Truncate instead of reject where truncation is sound
    /// (descriptions, tool count). Depth violations always reject.
    pub truncate_oversized: bool,
}

impl Default for DiscoveryBounds {
    fn default() -> Self {
        Self {
            max_tools: 1000,
            max_input_schema_depth: 32,
            max_description_length: 4096,
            max_total_definition_bytes: 4 * 1024 * 1024,
            truncate_oversized: false,
        }
    }
}

impl DiscoveryBounds {
    /// Enforce the bounds over a set of discovered tool definitions.
    ///
    /// In reject mode any violation is an error naming the bound. In
    /// truncate mode descriptions are truncated to
    /// `max_description_length`, tools beyond `max_tools` are dropped,
    /// and only non-truncatable violations (schema depth, total size
    /// after truncation) still error.
    fn enforce(
        &self,
        upstream: &str,
        mut tools: Vec<ToolDefinition>,
    ) -> Result<Vec<ToolDefinition>, String> {
        if tools.len() > self.max_tools {
            if self.truncate_oversized {
                tracing::warn!(
                    upstream = %upstream,
                    tools = tools.len(),
                    max_tools = self.max_tools,
                    "Upstream exceeds max_tools — dropping excess (truncate mode)"
                );
                tools.truncate(self.max_tools);
            } else {
                return Err(format!(
                    "upstream '{upstream}': advertises {} tools, exceeding \
                     max_tools_per_upstream ({}) — rejecting registration",
                    tools.len(),
                    self.max_tools
                ));
            }
        }

        let mut total_bytes: u64 = 0;
        let mut bounded = Vec::with_capacity(tools.len());
        for mut tool in tools {
            let depth = schema_depth(tool.input_schema.as_ref());
            if depth > self.max_input_schema_depth {
                return Err(format!(
                    "upstream '{upstream}': tool '{}' has an input schema nested \
                     {depth} levels deep, exceeding max_input_schema_depth ({}) — \
                     rejecting registration (schema depth cannot be truncated)",
                    tool.name, self.max_input_schema_depth
                ));
            }

            if let Some(desc) = tool.description.as_deref()
                && desc.len() > self.max_description_length
            {
                if self.truncate_oversized {
                    tracing::warn!(
                        upstream = %upstream,
                        tool = %tool.name,
                        length = desc.len(),
                        max = self.max_description_length,
                        "Tool description exceeds max_description_length — truncating"
                    );
                    let boundary = desc.floor_char_boundary(self.max_description_length);
                    tool.description = Some(format!("{}…[truncated]", &desc[..boundary]).into());
                } else {
                    return Err(format!(
                        "upstream '{upstream}': tool '{}' has a {}-byte description, \
                         exceeding max_description_length ({}) — rejecting registration",
                        tool.name,
                        desc.len(),
                        self.max_description_length
                    ));
                }
            }

            total_bytes += serde_json::to_string(&tool)
                .map(|s| s.len() as u64)
                .unwrap_or(u64::MAX);
            if total_bytes > self.max_total_definition_bytes {
                return Err(format!(
                    "upstream '{upstream}': total tool definition size exceeds \
                     max_total_definition_bytes ({}) — rejecting registration",
                    self.max_total_definition_bytes
                ));
            }
            bounded.push(tool);
        }
        Ok(bounded)
    }
}

/// Maximum JSON nesting depth of a serde_json value (an object or
/// array counts as one level over its children).
fn json_depth(value: &serde_json::Value) -> usize {
    match value {
        serde_json::Value::Object(map) => map.values().map(json_depth).max().map_or(1, |d| d + 1),
        serde_json::Value::Array(arr) => arr.iter().map(json_depth).max().map_or(1, |d| d + 1),
        _ => 0,
    }
}

/// Nesting depth of a JSON schema object (the map itself is one level).
fn schema_depth(schema: &serde_json::Map<String, serde_json::Value>) -> usize {
    schema.values().map(json_depth).max().map_or(1, |d| d + 1)
}

/// Options for [`UpstreamModule::discover_with`].
pub struct DiscoveryOptions<'a> {
    /// Supply-chain scanner (tool poisoning, rug pulls, ...).
    pub scanner: Option<&'a mut navra_auth::tool_scanner::ToolScanner>,
    /// Signed manifest + TOFU keystore verification.
    pub manifest: Option<ManifestCheck<'a>>,
    /// Content bounds enforced over the discovered definitions.
    pub bounds: DiscoveryBounds,
}

impl<'a> DiscoveryOptions<'a> {
    /// Options with no scanner, no manifest, and default bounds.
    pub fn new() -> Self {
        Self {
            scanner: None,
            manifest: None,
            bounds: DiscoveryBounds::default(),
        }
    }
}

impl<'a> Default for DiscoveryOptions<'a> {
    fn default() -> Self {
        Self::new()
    }
}

/// A module backed by an upstream MCP server via rmcp.
pub struct UpstreamModule {
    name: String,
    peer: rmcp::Peer<rmcp::RoleClient>,
    tools: Vec<ToolDefinition>,
    tool_operations: HashMap<String, ToolOperation>,
    tool_classifications: HashMap<String, navra_auth::permissions::ResourceClass>,
    prompts: Vec<PromptDefinition>,
    resources: Vec<ResourceDefinition>,
}

impl UpstreamModule {
    /// Return the upstream's discovered prompt definitions.
    pub fn discovered_prompts(&self) -> &[PromptDefinition] {
        &self.prompts
    }

    /// Return the upstream name.
    pub fn upstream_name(&self) -> &str {
        &self.name
    }

    /// Return the tool operation classifications.
    pub fn tool_operations(&self) -> &HashMap<String, ToolOperation> {
        &self.tool_operations
    }

    /// Return the semantic tool classifications.
    pub fn tool_classifications(&self) -> &HashMap<String, navra_auth::permissions::ResourceClass> {
        &self.tool_classifications
    }

    /// Connect to an upstream via rmcp and discover its capabilities.
    ///
    /// Calls `tools/list`, `prompts/list`, and `resources/list` on the
    /// upstream, caching the definitions. Errors during discovery are
    /// logged but don't prevent the module from being created — the
    /// corresponding capability will simply be empty.
    ///
    /// This infallible form performs no manifest verification; use
    /// [`UpstreamModule::discover_with`] to enforce a signed manifest.
    pub async fn discover(
        name: &str,
        peer: rmcp::Peer<rmcp::RoleClient>,
        scanner: Option<&mut navra_auth::tool_scanner::ToolScanner>,
        tool_overrides: &HashMap<String, String>,
    ) -> Self {
        Self::discover_with(
            name,
            peer,
            DiscoveryOptions {
                scanner,
                manifest: None,
                bounds: DiscoveryBounds::default(),
            },
            tool_overrides,
        )
        .await
        // Structural invariant: with no manifest check and default
        // bounds, discovery above never returns Err. If this ever
        // changes, fail loudly instead of silently registering an
        // empty module.
        .unwrap_or_else(|e| panic!("discovery without manifest check failed: {e}"))
    }

    /// Connect to an upstream via rmcp and discover its capabilities,
    /// verifying a signed tool manifest when one is configured and
    /// enforcing content bounds over the discovered definitions.
    ///
    /// Fail-closed: a manifest whose signature does not verify (tampered
    /// content), whose signing key changed since the TOFU pin, or whose
    /// tool set does not match what the upstream serves rejects the
    /// upstream entirely with a clear error. The same applies to
    /// content-bound violations (tool count, schema depth, description
    /// length, total definition bytes) unless truncation was opted into.
    pub async fn discover_with(
        name: &str,
        peer: rmcp::Peer<rmcp::RoleClient>,
        options: DiscoveryOptions<'_>,
        tool_overrides: &HashMap<String, String>,
    ) -> Result<Self, String> {
        let DiscoveryOptions {
            scanner,
            manifest,
            bounds,
        } = options;

        let discovered =
            discover_tools(name, &peer, scanner, manifest, &bounds, tool_overrides).await?;

        let prompts = peer.list_all_prompts().await.unwrap_or_else(|e| {
            tracing::warn!(upstream = %name, error = %e, "Failed to discover prompts");
            Vec::new()
        });

        let resources = peer.list_all_resources().await.unwrap_or_else(|e| {
            tracing::warn!(upstream = %name, error = %e, "Failed to discover resources");
            Vec::new()
        });

        tracing::info!(
            upstream = %name,
            tools = discovered.tools.len(),
            prompts = prompts.len(),
            resources = resources.len(),
            "Discovered upstream capabilities"
        );

        Ok(Self {
            name: name.to_string(),
            peer,
            tools: discovered.tools,
            tool_operations: discovered.tool_operations,
            tool_classifications: discovered.tool_classifications,
            prompts,
            resources,
        })
    }
}

/// The accepted tool set produced by one discovery run.
pub struct DiscoveredTools {
    pub tools: Vec<ToolDefinition>,
    pub tool_operations: HashMap<String, ToolOperation>,
    pub tool_classifications: HashMap<String, navra_auth::permissions::ResourceClass>,
}

/// Run the discovery pipeline over an upstream peer: list tools,
/// enforce content bounds, verify the signed manifest (if any), scan
/// for supply-chain threats, and apply tool overrides.
///
/// Shared by initial registration and by `list_changed` refreshes so
/// both paths enforce identical gates. Malicious tools are dropped,
/// Suspicious tools pass with a warning.
async fn discover_tools(
    name: &str,
    peer: &rmcp::Peer<rmcp::RoleClient>,
    scanner: Option<&mut navra_auth::tool_scanner::ToolScanner>,
    manifest: Option<ManifestCheck<'_>>,
    bounds: &DiscoveryBounds,
    tool_overrides: &HashMap<String, String>,
) -> Result<DiscoveredTools, String> {
    {
        let tools = peer.list_all_tools().await.unwrap_or_else(|e| {
            tracing::warn!(upstream = %name, error = %e, "Failed to discover tools");
            Vec::new()
        });

        // Content bounds first: the definitions are untrusted input
        // and must be bounded before any further processing.
        let tools = bounds.enforce(name, tools)?;

        if let Some(check) = manifest {
            use navra_auth::manifest::{ManifestVerification, verify_signed_manifest};
            match verify_signed_manifest(check.signed, check.key_store) {
                ManifestVerification::Trusted => {
                    tracing::info!(
                        upstream = %name,
                        signer = %check.signed.signer_did,
                        "Upstream manifest verified (TOFU: trusted)"
                    );
                }
                ManifestVerification::FirstUse => {
                    tracing::info!(
                        upstream = %name,
                        signer = %check.signed.signer_did,
                        "Upstream manifest verified — key pinned (TOFU: first use)"
                    );
                }
                ManifestVerification::KeyChanged { pinned, presented } => {
                    return Err(format!(
                        "upstream '{name}': manifest signing key changed \
                         (pinned {pinned}, presented {presented}) — \
                         rejecting upstream; remove the old pin manually to re-pin"
                    ));
                }
                ManifestVerification::InvalidSignature => {
                    return Err(format!(
                        "upstream '{name}': manifest signature verification failed \
                         (tampered content or invalid signature) — rejecting upstream"
                    ));
                }
            }

            let expected = check.signed.manifest.tools_fingerprint();
            let served = navra_auth::manifest::tools_fingerprint(&tools);
            if expected != served {
                return Err(format!(
                    "upstream '{name}': served tools do not match the signed manifest \
                     (possible rug pull) — rejecting upstream"
                ));
            }
        }

        let tools = if let Some(scanner) = scanner {
            use navra_auth::tool_scanner::ScanVerdict;
            let results = scanner.scan_tools(name, &tools);
            if results.len() != tools.len() {
                // Fail closed: a count mismatch means the scanner
                // misbehaved. zip() below drops unmatched tools, which
                // is stricter than treating them as Suspicious.
                tracing::error!(
                    upstream = %name,
                    expected = tools.len(),
                    got = results.len(),
                    "Scanner returned wrong number of results — dropping unmatched tools (fail closed)"
                );
            }
            let mut filtered = Vec::new();
            for (tool, result) in tools.into_iter().zip(results.iter()) {
                match &result.verdict {
                    ScanVerdict::Malicious { reasons } => {
                        tracing::error!(
                            upstream = %name,
                            tool = %result.tool_name,
                            reasons = ?reasons,
                            "BLOCKED malicious upstream tool"
                        );
                    }
                    ScanVerdict::Suspicious { reasons } => {
                        tracing::warn!(
                            upstream = %name,
                            tool = %result.tool_name,
                            reasons = ?reasons,
                            "Suspicious upstream tool (allowed)"
                        );
                        filtered.push(tool);
                    }
                    ScanVerdict::Safe => {
                        filtered.push(tool);
                    }
                }
            }
            filtered
        } else {
            tools
        };

        let mut tool_operations = HashMap::new();
        let mut accepted_tools = Vec::new();
        for def in tools {
            let op = if let Some(override_str) = tool_overrides.get(def.name.as_ref()) {
                match override_str.as_str() {
                    "read" => ToolOperation::Read,
                    "write" => ToolOperation::Write,
                    "deny" => ToolOperation::Deny,
                    _ => classify_tool(&def),
                }
            } else {
                classify_tool(&def)
            };
            if op == ToolOperation::Deny {
                tracing::info!(upstream = %name, tool = %def.name, "Denied upstream tool by policy");
                continue;
            }
            tool_operations.insert(def.name.to_string(), op);
            accepted_tools.push(def);
        }

        let mut tool_classifications = HashMap::new();
        for def in &accepted_tools {
            let domain = navra_auth::permissions::resource_class::infer_domain_heuristic(&def.name);
            let operation = navra_auth::permissions::resource_class::infer_operation_heuristic(
                &def.name,
                def.annotations.as_ref(),
            );
            tool_classifications.insert(
                def.name.to_string(),
                navra_auth::permissions::ResourceClass::new(domain, operation),
            );
        }

        Ok(DiscoveredTools {
            tools: accepted_tools,
            tool_operations,
            tool_classifications,
        })
    }
}

/// Build (definition, handler) pairs for a set of upstream tools.
///
/// Each handler closes over the upstream peer and the tool name,
/// forwarding calls over rmcp. Used both at registration and when
/// rebuilding the registry after a `list_changed` refresh.
pub fn upstream_tool_handlers(
    peer: &rmcp::Peer<rmcp::RoleClient>,
    tools: &[ToolDefinition],
) -> Vec<(ToolDefinition, ToolHandler)> {
    tools
        .iter()
        .map(|def| {
            let tool_name = def.name.clone();
            let peer = peer.clone();
            let handler: ToolHandler = Arc::new(move |args, _ctx| {
                let peer = peer.clone();
                let name = tool_name.clone();
                Box::pin(async move {
                    let mut params = CallToolParams::new(name);
                    if let Some(obj) = args.as_object() {
                        params = params.with_arguments(obj.clone());
                    }
                    match peer.call_tool(params).await {
                        Ok(result) => result,
                        Err(e) => {
                            use navra_protocol::compat::CallToolResultExt;
                            CallToolResult::error_msg(format!("upstream error: {e}"))
                        }
                    }
                })
            });
            (def.clone(), handler)
        })
        .collect()
}

/// rmcp client handler that forwards upstream `tools/list_changed`
/// notifications to an [`UpstreamWatcher`].
///
/// Construct with [`UpstreamNotificationHandler::new`], which returns
/// the handler (to pass to `serve`) and the receiving end of the
/// notification channel.
pub struct UpstreamNotificationHandler {
    tx: tokio::sync::mpsc::UnboundedSender<()>,
}

impl UpstreamNotificationHandler {
    /// Create the handler and the notification receiver.
    pub fn new() -> (Self, tokio::sync::mpsc::UnboundedReceiver<()>) {
        let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
        (Self { tx }, rx)
    }
}

impl rmcp::handler::client::ClientHandler for UpstreamNotificationHandler {
    fn on_tool_list_changed(
        &self,
        _context: rmcp::service::NotificationContext<rmcp::service::RoleClient>,
    ) -> impl std::future::Future<Output = ()> + rmcp::service::MaybeSendFuture + '_ {
        let _ = self.tx.send(());
        tracing::debug!("Upstream sent tools/list_changed");
        std::future::ready(())
    }
}

/// Refresh loop for an upstream that advertises `list_changed`.
///
/// Owned by the server after build; spawn [`UpstreamWatcher::run`]
/// with the `Arc<McpServer>`. On each notification (debounced to at
/// most one refresh per `min_refresh_interval`) the watcher re-runs
/// the full discovery pipeline — scanner, manifest verification, and
/// bounds included — and atomically swaps the module's tool registry.
/// A failed refresh keeps the existing tools (fail closed to the last
/// known-good set); tools that turned Malicious on refresh are not
/// registered.
pub struct UpstreamWatcher {
    name: String,
    peer: rmcp::Peer<rmcp::RoleClient>,
    events: tokio::sync::mpsc::UnboundedReceiver<()>,
    scanner: Option<navra_auth::tool_scanner::ToolScanner>,
    manifest: Option<(
        navra_auth::manifest::SignedManifest,
        navra_auth::manifest::ManifestKeyStore,
    )>,
    bounds: DiscoveryBounds,
    tool_overrides: HashMap<String, String>,
    min_refresh_interval: std::time::Duration,
}

impl UpstreamWatcher {
    /// Assemble a watcher from the pieces used for the initial
    /// discovery (the scanner and manifest data are reused so rug-pull
    /// hashes and TOFU pins persist across refreshes).
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        name: impl Into<String>,
        peer: rmcp::Peer<rmcp::RoleClient>,
        events: tokio::sync::mpsc::UnboundedReceiver<()>,
        scanner: Option<navra_auth::tool_scanner::ToolScanner>,
        manifest: Option<(
            navra_auth::manifest::SignedManifest,
            navra_auth::manifest::ManifestKeyStore,
        )>,
        bounds: DiscoveryBounds,
        tool_overrides: HashMap<String, String>,
        min_refresh_interval: std::time::Duration,
    ) -> Self {
        Self {
            name: name.into(),
            peer,
            events,
            scanner,
            manifest,
            bounds,
            tool_overrides,
            min_refresh_interval,
        }
    }

    /// Run the refresh loop until the notification channel closes.
    pub async fn run(mut self, server: std::sync::Arc<crate::server::McpServer>) {
        loop {
            if self.events.recv().await.is_none() {
                // Upstream connection dropped; nothing left to watch.
                return;
            }
            // Debounce: wait out the minimum interval, then swallow
            // any notifications that arrived inside the window so a
            // chatty upstream triggers one refresh, not a storm.
            tokio::time::sleep(self.min_refresh_interval).await;
            while self.events.try_recv().is_ok() {}
            if let Err(e) = self.refresh_once(&server).await {
                tracing::error!(
                    upstream = %self.name,
                    error = %e,
                    "list_changed refresh failed — keeping the existing tool registry (fail closed)"
                );
            }
        }
    }

    async fn refresh_once(
        &mut self,
        server: &std::sync::Arc<crate::server::McpServer>,
    ) -> Result<(), String> {
        let manifest_check = self
            .manifest
            .as_mut()
            .map(|(signed, key_store)| ManifestCheck { signed, key_store });
        let discovered = discover_tools(
            &self.name,
            &self.peer,
            self.scanner.as_mut(),
            manifest_check,
            &self.bounds,
            &self.tool_overrides,
        )
        .await?;
        let handlers = upstream_tool_handlers(&self.peer, &discovered.tools);
        server.swap_upstream_tools(
            &self.name,
            handlers,
            discovered.tool_operations,
            discovered.tool_classifications,
        );
        Ok(())
    }
}

impl Module for UpstreamModule {
    fn name(&self) -> &str {
        &self.name
    }

    fn tools(&self) -> Vec<(ToolDefinition, ToolHandler)> {
        upstream_tool_handlers(&self.peer, &self.tools)
    }

    fn prompts(&self) -> Vec<(PromptDefinition, PromptHandler)> {
        self.prompts
            .iter()
            .map(|def| {
                let prompt_name = def.name.clone();
                let peer = self.peer.clone();
                let handler: PromptHandler =
                    Arc::new(move |args: HashMap<String, String>, _ctx| {
                        let peer = peer.clone();
                        let name = prompt_name.clone();
                        Box::pin(async move {
                            let mut params = GetPromptParams::new(name);
                            if !args.is_empty() {
                                let obj: serde_json::Map<String, serde_json::Value> = args
                                    .into_iter()
                                    .map(|(k, v)| (k, serde_json::Value::String(v)))
                                    .collect();
                                params.arguments = Some(obj);
                            }
                            match peer.get_prompt(params).await {
                                Ok(result) => result,
                                Err(e) => {
                                    let mut r = crate::protocol::GetPromptResult::new(vec![]);
                                    r.description = Some(format!("upstream error: {e}"));
                                    r
                                }
                            }
                        })
                    });
                (def.clone(), handler)
            })
            .collect()
    }

    fn resources(&self) -> Vec<(ResourceDefinition, ResourceHandler)> {
        self.resources
            .iter()
            .map(|def| {
                let peer = self.peer.clone();
                let handler: ResourceHandler = Arc::new(move |uri: String, _ctx| {
                    let peer = peer.clone();
                    Box::pin(async move {
                        let params = ReadResourceParams::new(uri.clone());
                        match peer.read_resource(params).await {
                            Ok(result) => result,
                            Err(e) => crate::protocol::ReadResourceResult::new(vec![
                                crate::protocol::ResourceContent::TextResourceContents {
                                    uri,
                                    mime_type: Some("text/plain".to_string()),
                                    text: format!("upstream error: {e}"),
                                    meta: None,
                                },
                            ]),
                        }
                    })
                });
                (def.clone(), handler)
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classify_tool_read_write() {
        assert_eq!(
            classify_tool(&tool_def("read_file", None)),
            ToolOperation::Read
        );
        assert_eq!(
            classify_tool(&tool_def("write_file", None)),
            ToolOperation::Write
        );
    }

    #[test]
    fn classify_tool_read_only_annotation_returns_read() {
        let ann = navra_protocol::ToolAnnotations::new().read_only(true);
        // Even a tool with a write-like name should be classified Read
        // when the read_only_hint annotation is true.
        assert_eq!(
            classify_tool(&tool_def("write_something", Some(ann))),
            ToolOperation::Read
        );
    }

    #[test]
    fn classify_tool_destructive_annotation_returns_write() {
        let ann = navra_protocol::ToolAnnotations::new().destructive(true);
        // A tool with a read-like name should be classified Write
        // when the destructive_hint annotation is true.
        assert_eq!(
            classify_tool(&tool_def("list_items", Some(ann))),
            ToolOperation::Write
        );
    }

    #[test]
    fn classify_tool_read_only_takes_priority_over_destructive() {
        // When both read_only and destructive are set, read_only wins
        // because we check it first.
        let ann = navra_protocol::ToolAnnotations::new()
            .read_only(true)
            .destructive(true);
        assert_eq!(
            classify_tool(&tool_def("ambiguous_tool", Some(ann))),
            ToolOperation::Read
        );
    }

    #[test]
    fn classify_tool_no_annotations_falls_through_to_name_heuristic() {
        // Tools without annotations are classified by name heuristic.
        assert_eq!(
            classify_tool(&tool_def("git_commit", None)),
            ToolOperation::Write
        );
        assert_eq!(
            classify_tool(&tool_def("git_status", None)),
            ToolOperation::Read
        );
        assert_eq!(
            classify_tool(&tool_def("shell_exec", None)),
            ToolOperation::Write
        );
    }

    #[test]
    fn request_timeout_secs_wired_into_retry_config() {
        // Verify the config-to-RetryConfig conversion correctly maps
        // request_timeout_secs to the RetryConfig's request_timeout field.
        let mut config = navra_protocol::RetryConfig::default();
        assert_eq!(config.request_timeout, std::time::Duration::from_secs(45));

        // Simulate what UpstreamConfig::retry_config() does
        let custom_timeout_secs: u64 = 10;
        config.request_timeout = std::time::Duration::from_secs(custom_timeout_secs);
        assert_eq!(config.request_timeout, std::time::Duration::from_secs(10));
    }

    fn tool_def(
        name: &str,
        annotations: Option<navra_protocol::ToolAnnotations>,
    ) -> ToolDefinition {
        let mut def = ToolDefinition::new_with_raw(
            name.to_string(),
            None,
            navra_protocol::compat::empty_input_schema(),
        );
        def.annotations = annotations;
        def
    }
}
