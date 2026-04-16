//! High-level agent entry point with builder pattern.

use crate::client::McpClient;
use crate::error::AgentError;
use crate::tool_loop::{run_tool_loop, ToolLoopConfig, ToolLoopResult};
use myelix_model::ModelBackend;
use myelix_protocol::label::DataLabel;
use myelix_protocol::Upstream;
use myelix_security::identity::CapSigner;
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
    pub async fn run(&mut self, prompt: &str) -> Result<ToolLoopResult, AgentError> {
        run_tool_loop(self.model.as_ref(), &mut self.client, prompt, &self.config).await
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
    auth_token: Option<String>,
    model: Option<Box<dyn ModelBackend>>,
    signer: Option<Arc<dyn CapSigner>>,
    config: ToolLoopConfig,
}

impl AgentBuilder {
    fn new() -> Self {
        Self {
            upstream: None,
            auth_token: None,
            model: None,
            signer: None,
            config: ToolLoopConfig::default(),
        }
    }

    /// Connect to an MCP server via HTTP (streamable-http transport).
    pub async fn endpoint(mut self, url: &str) -> Result<Self, AgentError> {
        self.upstream = Some(Upstream::http("agent", url).await?);
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

    /// Build the agent. Requires endpoint and model to be set.
    pub fn build(self) -> Result<Agent, AgentError> {
        let upstream = self
            .upstream
            .ok_or_else(|| AgentError::Config("endpoint not set".into()))?;
        let model = self
            .model
            .ok_or_else(|| AgentError::Config("model not set".into()))?;

        let mut client = McpClient::new(upstream);
        if let Some(token) = self.auth_token {
            client = client.with_auth(token);
        }

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

    #[test]
    fn build_fails_without_endpoint() {
        let result = Agent::builder().build();
        assert!(result.is_err());
        let err = result.err().unwrap();
        assert!(matches!(err, AgentError::Config(_)));
        assert!(err.to_string().contains("endpoint"));
    }

    #[test]
    fn build_fails_without_model() {
        // endpoint is checked first, so this also returns the endpoint error
        let result = Agent::builder().build();
        assert!(result.err().unwrap().to_string().contains("endpoint"));
    }
}
