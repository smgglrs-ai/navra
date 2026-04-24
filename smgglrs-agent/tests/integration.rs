//! Integration tests for smgglrs-agent public API.
//!
//! Tests the builder pattern, McpClient IFC taint tracking, tool loop,
//! and type conversions using mock transports.

use smgglrs_agent::{
    Agent, AgentError, McpClient, ToolLoopConfig,
    extract_text, run_tool_loop,
    CallToolResult, Content, DataLabel,
    CreateResponseRequest, OutputItem, MessageItem, FunctionCallItem,
    ModelBackend, ModelResponse, ResponseStatus, ItemStatus,
};
use smgglrs_model::ModelError;
use smgglrs_protocol::upstream::{Transport, UpstreamError};
use smgglrs_protocol::Upstream;
use smgglrs_responses::response::Usage;
use async_trait::async_trait;
use std::future::Future;
use std::pin::Pin;
use std::sync::Mutex;

// =====================================================================
// Mock infrastructure
// =====================================================================

struct MockTransport {
    responses: Mutex<Vec<serde_json::Value>>,
}

impl MockTransport {
    fn new(responses: Vec<serde_json::Value>) -> Self {
        Self { responses: Mutex::new(responses) }
    }
}

#[async_trait]
impl Transport for MockTransport {
    async fn request(
        &mut self,
        _body: serde_json::Value,
    ) -> Result<serde_json::Value, UpstreamError> {
        let mut responses = self.responses.lock().unwrap();
        if responses.is_empty() {
            Ok(serde_json::json!({"jsonrpc": "2.0", "result": {}, "id": 1}))
        } else {
            Ok(responses.remove(0))
        }
    }

    fn shutdown(&mut self) {}
}

/// Build a mock client. If `include_list_tools` is true, a list_tools
/// response is prepended (needed for run_tool_loop).
async fn mock_client_inner(
    include_list_tools: bool,
    tool_responses: Vec<serde_json::Value>,
) -> McpClient {
    let mut all = vec![
        serde_json::json!({
            "jsonrpc": "2.0",
            "result": {
                "protocolVersion": "2025-03-26",
                "capabilities": {},
                "serverInfo": {"name": "test", "version": "0.1.0"}
            },
            "id": 1
        }),
        serde_json::json!({"jsonrpc": "2.0", "result": {}, "id": 2}),
    ];
    if include_list_tools {
        all.push(serde_json::json!({
            "jsonrpc": "2.0",
            "result": {"tools": []},
            "id": 3
        }));
    }
    all.extend(tool_responses);
    let transport = MockTransport::new(all);
    let upstream = Upstream::connect("test", transport).await.unwrap();
    McpClient::new(upstream)
}

async fn mock_client(tool_responses: Vec<serde_json::Value>) -> McpClient {
    mock_client_inner(true, tool_responses).await
}

async fn mock_client_no_list(tool_responses: Vec<serde_json::Value>) -> McpClient {
    mock_client_inner(false, tool_responses).await
}

struct MockModel {
    responses: Mutex<Vec<ModelResponse>>,
}

impl MockModel {
    fn new(responses: Vec<ModelResponse>) -> Self {
        Self { responses: Mutex::new(responses) }
    }
}

impl ModelBackend for MockModel {
    fn respond(
        &self,
        _req: &CreateResponseRequest,
    ) -> Pin<Box<dyn Future<Output = Result<ModelResponse, ModelError>> + Send + '_>> {
        let response = {
            let mut responses = self.responses.lock().unwrap();
            if responses.is_empty() {
                return Box::pin(async {
                    Err(ModelError::Inference("no more responses".into()))
                });
            }
            responses.remove(0)
        };
        Box::pin(async move { Ok(response) })
    }
}

fn text_response(text: &str) -> ModelResponse {
    ModelResponse {
        id: "resp_test".into(),
        object: "response".into(),
        created_at: None,
        completed_at: None,
        status: ResponseStatus::Completed,
        model: Some("test".into()),
        output: vec![OutputItem::Message(MessageItem::assistant(text))],
        usage: Some(Usage {
            input_tokens: 10,
            output_tokens: 5,
            total_tokens: 15,
            input_tokens_details: None,
            output_tokens_details: None,
        }),
        error: None,
        previous_response_id: None,
        instructions: None,
        tools: vec![],
        tool_choice: None,
        text: None,
        reasoning: None,
        truncation: None,
        temperature: None,
        max_output_tokens: None,
        metadata: Default::default(),
        incomplete_details: None,
        extra: Default::default(),
    }
}

fn tool_call_response(name: &str, args: &str) -> ModelResponse {
    ModelResponse {
        id: "resp_test".into(),
        object: "response".into(),
        created_at: None,
        completed_at: None,
        status: ResponseStatus::Completed,
        model: Some("test".into()),
        output: vec![OutputItem::FunctionCall(FunctionCallItem {
            id: Some("fc_1".into()),
            call_id: "call_1".into(),
            name: name.to_string(),
            arguments: args.to_string(),
            status: Some(ItemStatus::Completed),
        })],
        usage: Some(Usage {
            input_tokens: 10,
            output_tokens: 5,
            total_tokens: 15,
            input_tokens_details: None,
            output_tokens_details: None,
        }),
        error: None,
        previous_response_id: None,
        instructions: None,
        tools: vec![],
        tool_choice: None,
        text: None,
        reasoning: None,
        truncation: None,
        temperature: None,
        max_output_tokens: None,
        metadata: Default::default(),
        incomplete_details: None,
        extra: Default::default(),
    }
}

// =====================================================================
// 1. AgentBuilder validation
// =====================================================================

#[tokio::test]
async fn builder_fails_without_endpoint() {
    let result = Agent::builder().build().await;
    assert!(result.is_err());
    let err = result.err().unwrap();
    assert!(matches!(err, AgentError::Config(_)));
    assert!(err.to_string().contains("endpoint"));
}

#[tokio::test]
async fn builder_config_methods_chainable() {
    // Verify builder methods return Self for chaining
    let builder = Agent::builder()
        .system_prompt("You are helpful")
        .max_iterations(5)
        .temperature(0.7)
        .max_tokens(1000)
        .allowed_tools(vec!["docs_read".into()])
        .non_progress_tools(vec!["team_status".into()])
        .force_tool_iterations(2);
    // Can't build without endpoint, but config was set
    let result = builder.build().await;
    assert!(result.is_err());
}

// =====================================================================
// 2. McpClient taint tracking
// =====================================================================

#[tokio::test]
async fn client_taint_starts_trusted() {
    let client = mock_client_no_list(vec![]).await;
    assert_eq!(client.taint(), DataLabel::TRUSTED_PUBLIC);
}

#[tokio::test]
async fn client_call_external_read_taints() {
    let mut client = mock_client_no_list(vec![serde_json::json!({
        "jsonrpc": "2.0",
        "result": {
            "content": [{"type": "text", "text": "file data"}],
            "isError": false
        },
        "id": 3
    })])
    .await;

    let _result = client.call_tool("docs_read", serde_json::json!({})).await.unwrap();
    assert_eq!(
        client.taint().integrity,
        smgglrs_protocol::label::Integrity::Untrusted,
    );
}

#[tokio::test]
async fn client_call_non_read_stays_trusted() {
    let mut client = mock_client_no_list(vec![serde_json::json!({
        "jsonrpc": "2.0",
        "result": {
            "content": [{"type": "text", "text": "ok"}],
            "isError": false
        },
        "id": 3
    })])
    .await;

    let _result = client.call_tool("git_status", serde_json::json!({})).await.unwrap();
    assert_eq!(client.taint(), DataLabel::TRUSTED_PUBLIC);
}

// =====================================================================
// 3. Tool loop with mock model
// =====================================================================

#[tokio::test]
async fn tool_loop_immediate_text_response() {
    let model = MockModel::new(vec![text_response("Hello!")]);
    let mut client = mock_client(vec![]).await;
    let config = ToolLoopConfig::default();

    let result = run_tool_loop(&model, &mut client, "Hi", &config, "run-1".into())
        .await
        .unwrap();
    assert_eq!(result.response, "Hello!");
    assert_eq!(result.iterations, 0);
    assert_eq!(result.run_id, "run-1");
}

#[tokio::test]
async fn tool_loop_one_tool_call() {
    let model = MockModel::new(vec![
        tool_call_response("git_status", "{}"),
        text_response("Repo is clean."),
    ]);
    let mut client = mock_client(vec![serde_json::json!({
        "jsonrpc": "2.0",
        "result": {
            "content": [{"type": "text", "text": "nothing to commit"}],
            "isError": false
        },
        "id": 4
    })])
    .await;
    let config = ToolLoopConfig::default();

    let result = run_tool_loop(&model, &mut client, "status?", &config, "run-2".into())
        .await
        .unwrap();
    assert_eq!(result.response, "Repo is clean.");
    assert_eq!(result.iterations, 1);
    assert_eq!(result.input_tokens, 20);
    assert_eq!(result.output_tokens, 10);
}

// =====================================================================
// 4. extract_text helper
// =====================================================================

#[test]
fn extract_text_success() {
    let result = CallToolResult::success(vec![
        Content::text("line 1"),
        Content::text("line 2"),
    ]);
    assert_eq!(extract_text(&result), "line 1line 2");
}

#[test]
fn extract_text_error() {
    let result = CallToolResult::error("something failed");
    assert_eq!(extract_text(&result), "Error: something failed");
}

// =====================================================================
// 5. AgentError variants
// =====================================================================

#[test]
fn agent_error_display() {
    let e = AgentError::Config("no model".into());
    assert_eq!(format!("{e}"), "configuration error: no model");

    let e = AgentError::MaxIterations(10);
    assert_eq!(format!("{e}"), "max iterations (10) exceeded");

    let e = AgentError::IfcViolation("tainted write".into());
    assert_eq!(format!("{e}"), "IFC violation: tainted write");
}

// =====================================================================
// 6. ToolLoopConfig defaults
// =====================================================================

#[test]
fn tool_loop_config_defaults() {
    let config = ToolLoopConfig::default();
    assert_eq!(config.max_iterations, 10);
    assert!(config.system_prompt.is_none());
    assert!(config.temperature.is_none());
    assert!(config.max_tokens.is_none());
    assert!(config.allowed_tools.is_none());
    assert!(config.output_json_schema.is_none());
    assert!(config.non_progress_tools.is_none());
    assert!(config.force_tool_iterations.is_none());
}
