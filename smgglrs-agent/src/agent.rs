//! High-level agent entry point with builder pattern.

use crate::client::McpClient;
use crate::error::AgentError;
use crate::tool_loop::{run_tool_loop, ToolLoopConfig, ToolLoopResult};
use smgglrs_model::ModelBackend;
use smgglrs_protocol::label::DataLabel;
use smgglrs_protocol::Upstream;
use smgglrs_security::identity::CapSigner;
use smgglrs_security::safety::FilterPipeline;
use std::sync::Arc;

/// An AI agent connected to an MCP server with a model backend.
///
/// Use [`Agent::builder()`] to construct.
pub struct Agent {
    client: McpClient,
    model: Box<dyn ModelBackend>,
    config: ToolLoopConfig,
    signer: Option<Arc<dyn CapSigner>>,
}

impl Agent {
    /// Create a new [`AgentBuilder`].
    pub fn builder() -> AgentBuilder {
        AgentBuilder::new()
    }

    /// Run a task: send the user prompt through the tool-use loop.
    ///
    /// Each call generates a unique `run_id` (UUID v4) that is included
    /// in the returned [`ToolLoopResult`] and passed to the audit callback.
    pub async fn run(&mut self, prompt: &str) -> Result<ToolLoopResult, AgentError> {
        let run_id = uuid::Uuid::new_v4().to_string();
        run_tool_loop(self.model.as_ref(), &mut self.client, prompt, &self.config, run_id).await
    }

    /// Direct access to the MCP client.
    pub fn client(&mut self) -> &mut McpClient {
        &mut self.client
    }

    /// Direct access to the model backend.
    pub fn model(&self) -> &dyn ModelBackend {
        self.model.as_ref()
    }

    /// The agent's DID:key identifier (if identity was configured).
    pub fn did(&self) -> Option<&str> {
        self.signer.as_ref().map(|s| s.did())
    }

    /// Current taint level.
    pub fn taint(&self) -> DataLabel {
        self.client.taint()
    }
}

/// Builder for constructing an [`Agent`].
pub struct AgentBuilder {
    upstream: Option<Upstream>,
    endpoint_url: Option<String>,
    auth_token: Option<String>,
    model: Option<Box<dyn ModelBackend>>,
    signer: Option<Arc<dyn CapSigner>>,
    config: ToolLoopConfig,
}

impl AgentBuilder {
    fn new() -> Self {
        Self {
            upstream: None,
            endpoint_url: None,
            auth_token: None,
            model: None,
            signer: None,
            config: ToolLoopConfig::default(),
        }
    }

    /// Set the MCP server endpoint URL (HTTP streamable-http transport).
    /// Connection is deferred to `build()` so auth tokens are included.
    pub async fn endpoint(mut self, url: &str) -> Result<Self, AgentError> {
        self.endpoint_url = Some(url.to_string());
        Ok(self)
    }

    /// Connect to an MCP server via SSE.
    pub async fn endpoint_sse(mut self, url: &str) -> Result<Self, AgentError> {
        self.upstream = Some(Upstream::sse("agent", url).await?);
        Ok(self)
    }

    /// Connect to an MCP server by spawning a subprocess (stdio transport).
    pub async fn spawn(
        mut self,
        command: &[String],
        cwd: Option<&str>,
    ) -> Result<Self, AgentError> {
        self.upstream = Some(Upstream::spawn("agent", command, cwd).await?);
        Ok(self)
    }

    /// Use a pre-connected [`Upstream`].
    pub fn upstream(mut self, upstream: Upstream) -> Self {
        self.upstream = Some(upstream);
        self
    }

    /// Set authentication token (Bearer or capability token).
    pub fn auth_token(mut self, token: impl Into<String>) -> Self {
        self.auth_token = Some(token.into());
        self
    }

    /// Set the model backend for chat completion.
    pub fn model(mut self, backend: impl ModelBackend + 'static) -> Self {
        self.model = Some(Box::new(backend));
        self
    }

    /// Set cryptographic identity for capability token operations.
    pub fn identity(mut self, signer: Arc<dyn CapSigner>) -> Self {
        self.signer = Some(signer);
        self
    }

    /// Set the system prompt.
    pub fn system_prompt(mut self, prompt: impl Into<String>) -> Self {
        self.config.system_prompt = Some(prompt.into());
        self
    }

    /// Set max iterations for the tool-use loop (default: 10).
    pub fn max_iterations(mut self, n: usize) -> Self {
        self.config.max_iterations = n;
        self
    }

    /// Set temperature for model calls.
    pub fn temperature(mut self, t: f32) -> Self {
        self.config.temperature = Some(t);
        self
    }

    /// Set max tokens per model response.
    pub fn max_tokens(mut self, n: u32) -> Self {
        self.config.max_tokens = Some(n);
        self
    }

    /// Restrict which tools the agent can see and call.
    /// Tools not in this list are filtered out after MCP discovery.
    pub fn allowed_tools(mut self, tools: Vec<String>) -> Self {
        self.config.allowed_tools = Some(tools);
        self
    }

    /// Set a JSON schema for structured model output.
    /// The model will be constrained to produce output matching this schema.
    /// Typically set from the persona's `output_json_schema` field.
    pub fn output_json_schema(mut self, schema: serde_json::Value) -> Self {
        self.config.output_json_schema = Some(schema);
        self
    }

    /// Mark tools as non-progress (status-polling).
    /// Rounds where ALL tool calls are non-progress tools don't count
    /// toward the iteration limit. Use for tools like `team_status`
    /// and `team_result` that observe state without making progress.
    pub fn non_progress_tools(mut self, tools: Vec<String>) -> Self {
        self.config.non_progress_tools = Some(tools);
        self
    }

    /// Force tool calls for the first N progress iterations.
    /// Prevents the model from producing text responses prematurely.
    pub fn force_tool_iterations(mut self, n: usize) -> Self {
        self.config.force_tool_iterations = Some(n);
        self
    }

    /// Set a PII filter for model-generated reasoning text.
    /// When set, the model's text output is filtered through this
    /// pipeline before being stored in conversation history or
    /// returned in the final response.
    pub fn pii_filter(mut self, pipeline: Arc<FilterPipeline>) -> Self {
        self.config.pii_filter = Some(pipeline);
        self
    }

    /// Set the per-turn reasoning token cap (default: 2048).
    /// Prevents small models from wasting context on verbose
    /// explanations between tool calls.
    pub fn max_reasoning_tokens(mut self, n: usize) -> Self {
        self.config.max_reasoning_tokens = Some(n);
        self
    }

    /// Enable or disable malformed output repair (default: true).
    /// When enabled, the tool loop attempts to fix common JSON
    /// errors in small model tool call arguments.
    pub fn repair_malformed_output(mut self, enabled: bool) -> Self {
        self.config.repair_malformed_output = enabled;
        self
    }

    /// Set the context window size for tool output compression.
    pub fn context_window_tokens(mut self, n: u32) -> Self {
        self.config.context_window_tokens = n;
        self
    }

    /// Set the max tool output token limit.
    pub fn max_tool_output_tokens(mut self, n: u32) -> Self {
        self.config.max_tool_output_tokens = n;
        self
    }

    /// Set an embedding model for query-aware extractive compression.
    pub fn embedding_model(mut self, model: Arc<dyn smgglrs_model::ModelBackend>) -> Self {
        self.config.embedding_model = Some(model);
        self
    }

    /// Set an audit sink for recording tool and model calls.
    pub fn audit_sink(mut self, sink: crate::audit::SharedAuditSink) -> Self {
        self.config.audit_sink = Some(sink);
        self
    }

    /// Load a persona from the cognitive core and set system prompt +
    /// output schema automatically.
    ///
    /// This is a convenience method that replaces manual calls to
    /// `ForgeService::load()`, `weaver::assemble()`, `.system_prompt()`,
    /// and `.output_json_schema()`.
    ///
    /// # Arguments
    /// - `forge` — loaded cognitive artifacts
    /// - `name` — persona name (e.g. "software_developer")
    pub fn persona(
        self,
        forge: &smgglrs_cognitive::ForgeService,
        name: &str,
    ) -> Result<Self, AgentError> {
        self.persona_with_context(forge, name, None, None, None)
    }

    /// Load a persona with optional specialization, context, and phase.
    pub fn persona_with_context(
        mut self,
        forge: &smgglrs_cognitive::ForgeService,
        name: &str,
        specialization: Option<&str>,
        context: Option<&str>,
        phase: Option<&str>,
    ) -> Result<Self, AgentError> {
        let output = smgglrs_cognitive::assemble_with_phase(
            forge, name, "", specialization, context, phase,
        )
        .map_err(|e| AgentError::Config(format!("persona '{name}': {e}")))?;

        self.config.system_prompt = Some(output.system_prompt());

        if let Some(schema) = output.output_json_schema {
            self.config.output_json_schema = Some(schema);
        }

        // Restrict to persona's declared tools if any
        let persona = forge
            .get_persona(name)
            .ok_or_else(|| AgentError::Config(format!("persona '{name}' not found")))?;
        if !persona.tools.is_empty() {
            self.config.allowed_tools = Some(persona.tools.clone());
        }

        if let Some(limit) = output.context_limit {
            self.config.context_window_tokens = limit;
        }
        if let Some(max_output) = persona.max_tool_output_tokens {
            self.config.max_tool_output_tokens = max_output;
        }

        tracing::info!(
            persona = name,
            tokens = output.estimated_tokens,
            context_limit = ?output.context_limit,
            "Loaded persona"
        );

        Ok(self)
    }

    /// Load a persona with pre-resolved upstream prompts injected at
    /// their specified positions.
    ///
    /// Use [`crate::resolve::resolve_mcp_prompts`] to fetch the prompts
    /// before calling this method.
    pub fn persona_with_prompts(
        mut self,
        forge: &smgglrs_cognitive::ForgeService,
        name: &str,
        resolved_prompts: &[smgglrs_cognitive::ResolvedPrompt],
    ) -> Result<Self, AgentError> {
        let output = smgglrs_cognitive::assemble_full(
            forge, name, "", None, None, None, resolved_prompts,
        )
        .map_err(|e| AgentError::Config(format!("persona '{name}': {e}")))?;

        self.config.system_prompt = Some(output.system_prompt());

        if let Some(schema) = output.output_json_schema {
            self.config.output_json_schema = Some(schema);
        }

        let persona = forge
            .get_persona(name)
            .ok_or_else(|| AgentError::Config(format!("persona '{name}' not found")))?;
        if !persona.tools.is_empty() {
            self.config.allowed_tools = Some(persona.tools.clone());
        }

        if let Some(limit) = output.context_limit {
            self.config.context_window_tokens = limit;
        }
        if let Some(max_output) = persona.max_tool_output_tokens {
            self.config.max_tool_output_tokens = max_output;
        }

        tracing::info!(
            persona = name,
            tokens = output.estimated_tokens,
            context_limit = ?output.context_limit,
            upstream_prompts = resolved_prompts.len(),
            "Loaded persona with upstream prompts"
        );

        Ok(self)
    }

    /// Load an MCP-sourced persona: resolve the persona's source via
    /// `prompts/get`, then assemble the system prompt via the Weaver.
    ///
    /// This handles personas where the core mandate comes from an
    /// upstream MCP server. The YAML is a thin pointer — the "soul"
    /// is fetched at runtime.
    ///
    /// # Arguments
    /// - `forge` — loaded cognitive artifacts
    /// - `name` — persona name
    /// - `client` — MCP client connected to the upstream(s)
    /// - `user_prompt` — the user's prompt (for template resolution)
    pub async fn persona_from_mcp(
        mut self,
        forge: &smgglrs_cognitive::ForgeService,
        name: &str,
        client: &mut McpClient,
        user_prompt: &str,
    ) -> Result<Self, AgentError> {
        let persona = forge
            .get_persona(name)
            .ok_or_else(|| AgentError::Config(format!("persona '{name}' not found")))?;

        let (resolved_persona, resolved_prompts) =
            crate::resolve::resolve_persona(client, persona, user_prompt).await?;

        // Assemble with the resolved persona injected into a temporary forge
        // is not needed — we use assemble_full with the resolved mandate.
        // But assemble_full takes a persona name and looks it up in the forge,
        // so we assemble manually using the resolved persona directly.

        // Build the system prompt from the resolved persona
        let output = smgglrs_cognitive::assemble_full(
            forge, name, "", None, None, None, &resolved_prompts,
        )
        .map_err(|e| AgentError::Config(format!("persona '{name}': {e}")))?;

        if persona.source.is_some() && resolved_persona.core_mandate != persona.core_mandate {
            let system = output.system_prompt();
            let patched = system.replacen(&persona.core_mandate, &resolved_persona.core_mandate, 1);
            self.config.system_prompt = Some(patched);
        } else {
            self.config.system_prompt = Some(output.system_prompt());
        }

        if let Some(schema) = output.output_json_schema {
            self.config.output_json_schema = Some(schema);
        }

        if !persona.tools.is_empty() {
            self.config.allowed_tools = Some(persona.tools.clone());
        }

        if let Some(limit) = output.context_limit {
            self.config.context_window_tokens = limit;
        }
        if let Some(max_output) = persona.max_tool_output_tokens {
            self.config.max_tool_output_tokens = max_output;
        }

        tracing::info!(
            persona = name,
            source = persona.source.is_some(),
            tokens = output.estimated_tokens,
            upstream_prompts = resolved_prompts.len(),
            "Loaded MCP-sourced persona"
        );

        Ok(self)
    }

    /// Build the agent. Requires endpoint and model to be set.
    pub async fn build(self) -> Result<Agent, AgentError> {
        let upstream = if let Some(upstream) = self.upstream {
            upstream
        } else if let Some(ref url) = self.endpoint_url {
            if let Some(ref token) = self.auth_token {
                Upstream::http_with_auth("agent", url, token).await?
            } else {
                Upstream::http("agent", url).await?
            }
        } else {
            return Err(AgentError::Config("endpoint not set".into()));
        };

        let model = self
            .model
            .ok_or_else(|| AgentError::Config("model not set".into()))?;

        let client = McpClient::new(upstream);

        Ok(Agent {
            client,
            model,
            config: self.config,
            signer: self.signer,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn build_fails_without_endpoint() {
        let result = Agent::builder().build().await;
        assert!(result.is_err());
        let err = result.err().unwrap();
        assert!(matches!(err, AgentError::Config(_)));
        assert!(err.to_string().contains("endpoint"));
    }

    #[tokio::test]
    async fn build_fails_without_model() {
        let result = Agent::builder().build().await;
        assert!(result.err().unwrap().to_string().contains("endpoint"));
    }
}
