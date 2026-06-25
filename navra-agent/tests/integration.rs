//! Integration tests for navra-agent public API.
//!
//! Tests the builder pattern, McpClient IFC taint tracking, tool loop,
//! and type conversions using mock transports.

use navra_agent::{
    extract_text, run_tool_loop, Agent, AgentError, CallToolResult, Content, CreateResponseRequest,
    DataLabel, FunctionCallItem, ItemStatus, McpClient, MessageItem, ModelBackend, ModelResponse,
    OutputItem, ResponseStatus, ToolLoopConfig,
};
use navra_model::ModelError;
use navra_protocol::compat::CallToolResultExt;
use navra_responses::response::Usage;
use rmcp::model::*;
use rmcp::service::ServiceExt;
use std::future::Future;
use std::pin::Pin;
use std::sync::Mutex;

// =====================================================================
// Mock infrastructure
// =====================================================================

struct MockServer {
    tools: Vec<Tool>,
    call_responses: Mutex<Vec<rmcp::model::CallToolResult>>,
}

impl MockServer {
    fn new(tools: Vec<Tool>, call_responses: Vec<rmcp::model::CallToolResult>) -> Self {
        Self {
            tools,
            call_responses: Mutex::new(call_responses),
        }
    }

    fn empty() -> Self {
        Self::new(vec![], vec![])
    }
}

impl rmcp::ServerHandler for MockServer {
    fn get_info(&self) -> ServerInfo {
        InitializeResult::new(ServerCapabilities::builder().enable_tools().build())
            .with_server_info(Implementation::new("test", "0.1.0"))
    }

    fn list_tools(
        &self,
        _request: Option<PaginatedRequestParams>,
        _context: rmcp::service::RequestContext<rmcp::RoleServer>,
    ) -> impl Future<Output = Result<ListToolsResult, rmcp::Error>> + Send + '_ {
        async {
            Ok(ListToolsResult {
                meta: None,
                tools: self.tools.clone(),
                next_cursor: None,
            })
        }
    }

    fn call_tool(
        &self,
        _request: CallToolRequestParams,
        _context: rmcp::service::RequestContext<rmcp::RoleServer>,
    ) -> impl Future<Output = Result<rmcp::model::CallToolResult, rmcp::Error>> + Send + '_ {
        let resp = {
            let mut responses = self.call_responses.lock().unwrap();
            if responses.is_empty() {
                rmcp::model::CallToolResult::text("ok")
            } else {
                responses.remove(0)
            }
        };
        async move { Ok(resp) }
    }
}

async fn connect_mock(server: MockServer) -> McpClient {
    let (server_io, client_io) = tokio::io::duplex(65536);
    tokio::spawn(async move {
        if let Ok(svc) = server.serve(server_io).await {
            let _ = svc.waiting().await;
        }
    });
    let client = <() as ServiceExt<rmcp::RoleClient>>::serve((), client_io)
        .await
        .expect("client connect");
    let peer = client.peer().clone();
    tokio::spawn(async move {
        let _ = client.waiting().await;
    });
    McpClient::new(peer)
}

async fn mock_client(tool_responses: Vec<rmcp::model::CallToolResult>) -> McpClient {
    connect_mock(MockServer::new(vec![], tool_responses)).await
}

async fn mock_client_no_list(tool_responses: Vec<rmcp::model::CallToolResult>) -> McpClient {
    connect_mock(MockServer::new(vec![], tool_responses)).await
}

struct MockModel {
    responses: Mutex<Vec<ModelResponse>>,
}

impl MockModel {
    fn new(responses: Vec<ModelResponse>) -> Self {
        Self {
            responses: Mutex::new(responses),
        }
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
                return Box::pin(async { Err(ModelError::Inference("no more responses".into())) });
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
    let builder = Agent::builder()
        .system_prompt("You are helpful")
        .max_iterations(5)
        .temperature(0.7)
        .max_tokens(1000)
        .allowed_tools(vec!["file_read".into()])
        .non_progress_tools(vec!["team_status".into()])
        .force_tool_iterations(2);
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
    let mut client =
        mock_client_no_list(vec![rmcp::model::CallToolResult::text("file data")]).await;

    let _result = client
        .call_tool("file_read", serde_json::json!({}))
        .await
        .unwrap();
    assert_eq!(
        client.taint().integrity,
        navra_protocol::label::Integrity::Untrusted,
    );
}

#[tokio::test]
async fn client_call_git_status_taints_session() {
    let mut client = mock_client_no_list(vec![rmcp::model::CallToolResult::text("ok")]).await;

    let _result = client
        .call_tool("git_status", serde_json::json!({}))
        .await
        .unwrap();
    assert_eq!(client.taint(), DataLabel::UNTRUSTED_PUBLIC);
}

// =====================================================================
// 3. Tool loop with mock model
// =====================================================================

#[tokio::test]
async fn tool_loop_immediate_text_response() {
    let model = MockModel::new(vec![text_response("Hello!")]);
    let mut client = mock_client(vec![]).await;
    let mut config = ToolLoopConfig::default();

    let result = run_tool_loop(&model, &mut client, "Hi", &mut config, "run-1".into())
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
    let mut client =
        mock_client(vec![rmcp::model::CallToolResult::text("nothing to commit")]).await;
    let mut config = ToolLoopConfig::default();

    let result = run_tool_loop(&model, &mut client, "status?", &mut config, "run-2".into())
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
    let result = CallToolResult::success(vec![Content::text("line 1"), Content::text("line 2")]);
    assert_eq!(extract_text(&result), "line 1line 2");
}

#[test]
fn extract_text_error() {
    let result = CallToolResult::error_msg("something failed");
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
