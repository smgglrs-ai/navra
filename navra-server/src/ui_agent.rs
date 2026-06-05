//! Agentic chat handler for the web UI.
//!
//! Wires the `/api/chat/agent` endpoint to navra-agent's ReAct
//! tool-use loop, streaming NDJSON events back to the client.
//! Session management endpoints persist conversation turns via
//! navra-memory's WorkingMemory.

use std::sync::Arc;

use axum::extract::State;
use axum::response::IntoResponse;

use navra_agent::{McpClient, ToolLoopConfig};
use navra_cognitive::ForgeService;
use navra_core::McpServer;
use navra_memory::{Message, Role, Turn, WorkingMemory};
use navra_model::ModelBackend;

use navra_core::Upstream;

/// Thread-safe wrapper around WorkingMemory.
///
/// rusqlite::Connection is !Send, so we wrap the entire WorkingMemory
/// in a std::sync::Mutex and access it via spawn_blocking.
pub(crate) struct SharedMemory {
    inner: std::sync::Mutex<WorkingMemory>,
}

impl SharedMemory {
    pub fn new(memory: WorkingMemory) -> Self {
        Self {
            inner: std::sync::Mutex::new(memory),
        }
    }

    pub fn with<F, R>(&self, f: F) -> R
    where
        F: FnOnce(&WorkingMemory) -> R,
    {
        let mem = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        f(&mem)
    }
}

/// Shared state for the agentic chat routes.
pub(crate) struct AgentChatState {
    pub server: Arc<McpServer>,
    pub model: Arc<dyn ModelBackend>,
    pub forge: Arc<ForgeService>,
    pub memory: Arc<SharedMemory>,
    #[allow(dead_code)]
    pub listen_addr: String,
    pub context_retriever: Option<Arc<dyn navra_agent::ContextRetriever>>,
}

/// POST /api/chat/agent request body.
#[derive(serde::Deserialize)]
pub(crate) struct AgentChatRequest {
    /// User prompt text.
    pub prompt: String,
    /// Session ID for multi-turn conversations.
    /// If omitted, a new session is created.
    pub session_id: Option<String>,
    /// Persona name (optional).
    pub persona: Option<String>,
    /// Max iterations for the tool loop (default: 10).
    pub max_iterations: Option<usize>,
}

/// GET /api/sessions response item.
#[derive(serde::Serialize)]
struct SessionInfo {
    id: String,
    turn_count: usize,
    created_at: i64,
    last_turn_at: Option<i64>,
}

/// GET /api/sessions/{id} response item.
#[derive(serde::Serialize)]
struct TurnInfo {
    turn_id: String,
    created_at: i64,
    messages: Vec<MessageInfo>,
}

#[derive(serde::Serialize)]
struct MessageInfo {
    role: String,
    content: String,
    timestamp: i64,
    metadata: Option<String>,
}

// ---------------------------------------------------------------------------
// In-process MCP transport
// ---------------------------------------------------------------------------

use crate::direct_transport::DirectTransport;

// ---------------------------------------------------------------------------
// Streaming audit sink
// ---------------------------------------------------------------------------

/// Audit sink that sends events to a tokio channel for NDJSON streaming.
struct StreamingAuditSink {
    tx: tokio::sync::mpsc::UnboundedSender<serde_json::Value>,
}

impl navra_agent::AuditSink for StreamingAuditSink {
    fn log_tool_call(
        &self,
        _run_id: &str,
        _agent_id: &str,
        iteration: u32,
        tool_name: &str,
        tool_args: &str,
        tool_result: &str,
        duration_ms: u64,
    ) {
        // Truncate large results for streaming
        let result_preview = if tool_result.len() > 4096 {
            format!("{}...", &tool_result[..4096])
        } else {
            tool_result.to_string()
        };

        let _ = self.tx.send(serde_json::json!({
            "type": "tool_call",
            "tool": tool_name,
            "args": serde_json::from_str::<serde_json::Value>(tool_args).unwrap_or(serde_json::json!(tool_args)),
            "iteration": iteration,
        }));

        let _ = self.tx.send(serde_json::json!({
            "type": "tool_result",
            "tool": tool_name,
            "result": result_preview,
            "duration_ms": duration_ms,
        }));
    }

    fn log_model_call(
        &self,
        _run_id: &str,
        _agent_id: &str,
        iteration: u32,
        _model_name: &str,
        input_tokens: u32,
        output_tokens: u32,
        response_type: &str,
    ) {
        let _ = self.tx.send(serde_json::json!({
            "type": "thinking",
            "iteration": iteration,
            "input_tokens": input_tokens,
            "output_tokens": output_tokens,
            "response_type": response_type,
        }));
    }
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

/// POST /api/chat/agent — agentic multi-turn chat with ReAct tool-use loop.
///
/// Returns NDJSON stream with event types:
/// - `{"type": "tool_call", "tool": "...", "args": {...}}`
/// - `{"type": "tool_result", "tool": "...", "result": "...", "duration_ms": N}`
/// - `{"type": "thinking", "iteration": N, ...}`
/// - `{"type": "text", "content": "..."}`
/// - `{"type": "done", "session_id": "...", "iterations": N, "usage": {...}}`
/// - `{"type": "error", "message": "..."}`
pub(crate) async fn handle_agentic_chat(
    State(state): State<Arc<AgentChatState>>,
    axum::Json(req): axum::Json<AgentChatRequest>,
) -> impl IntoResponse {
    if req.prompt.is_empty() {
        return (
            axum::http::StatusCode::BAD_REQUEST,
            [("content-type", "application/x-ndjson")],
            format!(
                "{}\n",
                serde_json::json!({"type": "error", "message": "prompt is required"})
            ),
        )
            .into_response();
    }

    // Get or create session
    let session_id = req
        .session_id
        .unwrap_or_else(|| uuid::Uuid::new_v4().to_string());

    // Build the NDJSON event channel
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<serde_json::Value>();
    let audit_sink: navra_agent::SharedAuditSink =
        Arc::new(StreamingAuditSink { tx: tx.clone() });

    // Build system prompt from persona if specified
    let system_prompt = if let Some(ref persona_name) = req.persona {
        if !persona_name.is_empty() {
            navra_cognitive::assemble(&state.forge, persona_name, &req.prompt, None, None)
                .map(|w| w.system_prompt())
                .ok()
        } else {
            None
        }
    } else {
        None
    };

    let prompt = req.prompt.clone();
    let max_iterations = req.max_iterations.unwrap_or(10);
    let server = state.server.clone();
    let model = state.model.clone();
    let shared_memory = state.memory.clone();
    let context_retriever = state.context_retriever.clone();
    let sid = session_id.clone();

    // Store the user turn
    let now_ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64;

    let user_turn = Turn {
        turn_id: uuid::Uuid::new_v4().to_string(),
        session_id: sid.clone(),
        agent: "ui-agent".to_string(),
        messages: vec![Message {
            role: Role::User,
            content: prompt.clone(),
            timestamp: now_ts,
            metadata: None,
        }],
        created_at: now_ts,
        fork_id: None,
        parent_fork: None,
    };
    state.memory.with(|mem| {
        if let Err(e) = mem.add_turn(&user_turn) {
            tracing::warn!(error = %e, "Failed to store user turn");
        }
    });

    // Spawn the agent loop in a background task
    let tx_done = tx.clone();
    let sid_bg = sid.clone();
    let memory_bg = shared_memory.clone();

    tokio::spawn(async move {
        // Create in-process transport and connect
        let transport = DirectTransport::new(
            server,
            navra_core::auth::AgentIdentity::new("ui-agent", "dev"),
        );
        let upstream = match Upstream::connect("ui-agent", transport).await {
            Ok(u) => u,
            Err(e) => {
                let _ = tx_done.send(serde_json::json!({
                    "type": "error",
                    "message": format!("failed to connect: {e}"),
                }));
                return;
            }
        };
        let mut client = McpClient::new(upstream);

        // Configure tool loop
        let mut config = ToolLoopConfig {
            max_iterations,
            system_prompt,
            temperature: Some(0.7),
            audit_sink: Some(audit_sink),
            context_retriever,
            ..Default::default()
        };

        let run_id = uuid::Uuid::new_v4().to_string();
        let result =
            navra_agent::run_tool_loop(model.as_ref(), &mut client, &prompt, &mut config, run_id)
                .await;

        match result {
            Ok(tool_result) => {
                // Send final text
                let _ = tx_done.send(serde_json::json!({
                    "type": "text",
                    "content": tool_result.response,
                }));

                // Store assistant turn
                let resp_ts = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs() as i64;

                let assistant_turn = Turn {
                    turn_id: uuid::Uuid::new_v4().to_string(),
                    session_id: sid_bg.clone(),
                    agent: "ui-agent".to_string(),
                    messages: vec![Message {
                        role: Role::Assistant,
                        content: tool_result.response.clone(),
                        timestamp: resp_ts,
                        metadata: Some(
                            serde_json::json!({
                                "iterations": tool_result.iterations,
                                "input_tokens": tool_result.input_tokens,
                                "output_tokens": tool_result.output_tokens,
                            })
                            .to_string(),
                        ),
                    }],
                    created_at: resp_ts,
                    fork_id: None,
                    parent_fork: None,
                };
                memory_bg.with(|mem| {
                    if let Err(e) = mem.add_turn(&assistant_turn) {
                        tracing::warn!(error = %e, "Failed to store assistant turn");
                    }
                });

                let _ = tx_done.send(serde_json::json!({
                    "type": "done",
                    "session_id": sid_bg,
                    "iterations": tool_result.iterations,
                    "usage": {
                        "input_tokens": tool_result.input_tokens,
                        "output_tokens": tool_result.output_tokens,
                    },
                }));
            }
            Err(e) => {
                let _ = tx_done.send(serde_json::json!({
                    "type": "error",
                    "message": format!("{e}"),
                }));
            }
        }
    });

    // Stream events as NDJSON
    let body = axum::body::Body::from_stream(async_stream::stream! {
        while let Some(event) = rx.recv().await {
            let mut line = serde_json::to_string(&event).unwrap_or_default();
            line.push('\n');
            yield Ok::<_, std::convert::Infallible>(line);
        }
    });

    (
        axum::http::StatusCode::OK,
        [("content-type", "application/x-ndjson")],
        body,
    )
        .into_response()
}

// ---------------------------------------------------------------------------
// Session management handlers
// ---------------------------------------------------------------------------

/// GET /api/sessions — list chat sessions.
pub(crate) async fn handle_list_sessions(
    State(state): State<Arc<AgentChatState>>,
) -> impl IntoResponse {
    let sessions = state.memory.with(|mem| list_sessions_from_memory(mem));
    axum::Json(serde_json::json!({ "sessions": sessions }))
}

/// POST /api/sessions — create a new chat session.
pub(crate) async fn handle_create_session(
    State(_state): State<Arc<AgentChatState>>,
) -> impl IntoResponse {
    let session_id = uuid::Uuid::new_v4().to_string();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64;

    axum::Json(serde_json::json!({
        "session_id": session_id,
        "created_at": now,
    }))
}

/// GET /api/sessions/{id} — get session history.
pub(crate) async fn handle_get_session(
    State(state): State<Arc<AgentChatState>>,
    axum::extract::Path(session_id): axum::extract::Path<String>,
) -> impl IntoResponse {
    let turns = state
        .memory
        .with(|mem| mem.get_session_turns(&session_id).unwrap_or_default());

    let turn_infos: Vec<TurnInfo> = turns
        .iter()
        .map(|t| TurnInfo {
            turn_id: t.turn_id.clone(),
            created_at: t.created_at,
            messages: t
                .messages
                .iter()
                .map(|m| MessageInfo {
                    role: m.role.as_str().to_string(),
                    content: m.content.clone(),
                    timestamp: m.timestamp,
                    metadata: m.metadata.clone(),
                })
                .collect(),
        })
        .collect();

    axum::Json(serde_json::json!({
        "session_id": session_id,
        "turns": turn_infos,
    }))
}

/// DELETE /api/sessions/{id} — delete a session.
pub(crate) async fn handle_delete_session(
    State(state): State<Arc<AgentChatState>>,
    axum::extract::Path(session_id): axum::extract::Path<String>,
) -> impl IntoResponse {
    match state.memory.with(|mem| mem.clear_session(&session_id)) {
        Ok(()) => axum::Json(serde_json::json!({"deleted": true})),
        Err(e) => axum::Json(serde_json::json!({"deleted": false, "error": format!("{e}")})),
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// List distinct session IDs from working memory.
fn list_sessions_from_memory(memory: &WorkingMemory) -> Vec<SessionInfo> {
    match memory.list_sessions() {
        Ok(sessions) => sessions
            .into_iter()
            .map(|(id, turn_count, created_at, last_turn_at)| SessionInfo {
                id,
                turn_count,
                created_at,
                last_turn_at: Some(last_turn_at),
            })
            .collect(),
        Err(e) => {
            tracing::warn!(error = %e, "Failed to list sessions");
            Vec::new()
        }
    }
}

// ---------------------------------------------------------------------------
// Route builder
// ---------------------------------------------------------------------------

/// Build the agentic chat routes and return them as a Router.
///
/// Routes:
/// - POST /chat/agent — agentic multi-turn chat
/// - GET /sessions — list sessions
/// - POST /sessions — create session
/// - GET /sessions/{id} — get session history
/// - DELETE /sessions/{id} — delete session
pub(crate) fn build_agent_routes(state: Arc<AgentChatState>) -> axum::Router {
    axum::Router::new()
        .route("/chat/agent", axum::routing::post(handle_agentic_chat))
        .route(
            "/sessions",
            axum::routing::get(handle_list_sessions).post(handle_create_session),
        )
        .route(
            "/sessions/{id}",
            axum::routing::get(handle_get_session).delete(handle_delete_session),
        )
        .with_state(state)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use http_body_util::BodyExt;
    use tower::util::ServiceExt;

    struct StubBackend;

    impl navra_model::ModelBackend for StubBackend {
        fn respond(
            &self,
            _request: &navra_model::CreateResponseRequest,
        ) -> std::pin::Pin<
            Box<
                dyn std::future::Future<
                        Output = Result<navra_model::ModelResponse, navra_model::ModelError>,
                    > + Send
                    + '_,
            >,
        > {
            Box::pin(async {
                Ok(navra_model::ModelResponse {
                    id: "resp_stub".into(),
                    object: "response".into(),
                    created_at: None,
                    completed_at: None,
                    status: navra_model::ResponseStatus::Completed,
                    model: Some("stub".into()),
                    output: vec![navra_model::OutputItem::Message(
                        navra_model::MessageItem::assistant(
                            "I checked the tools and here is your answer.",
                        ),
                    )],
                    usage: None,
                    error: None,
                    previous_response_id: None,
                    instructions: None,
                    tools: Vec::new(),
                    tool_choice: None,
                    text: None,
                    reasoning: None,
                    truncation: None,
                    temperature: None,
                    max_output_tokens: None,
                    metadata: Default::default(),
                    incomplete_details: None,
                    extra: Default::default(),
                })
            })
        }
    }

    fn build_test_state() -> Arc<AgentChatState> {
        let server = Arc::new(navra_core::McpServer::builder().allow_anonymous().build());
        let model = Arc::new(StubBackend) as Arc<dyn ModelBackend>;
        let forge = Arc::new(ForgeService::empty());
        let memory = Arc::new(SharedMemory::new(WorkingMemory::open_memory().unwrap()));

        Arc::new(AgentChatState {
            server,
            model,
            forge,
            memory,
            listen_addr: "127.0.0.1:0".to_string(),
            context_retriever: None,
        })
    }

    fn build_test_router() -> axum::Router {
        build_agent_routes(build_test_state())
    }

    async fn post_json(
        router: &axum::Router,
        path: &str,
        body: serde_json::Value,
    ) -> (StatusCode, String) {
        let req = Request::builder()
            .method("POST")
            .uri(path)
            .header("content-type", "application/json")
            .body(Body::from(serde_json::to_string(&body).unwrap()))
            .unwrap();

        let resp = router.clone().oneshot(req).await.unwrap();
        let status = resp.status();
        let bytes = resp.into_body().collect().await.unwrap().to_bytes();
        (status, String::from_utf8_lossy(&bytes).to_string())
    }

    async fn get_json(router: &axum::Router, path: &str) -> (StatusCode, serde_json::Value) {
        let req = Request::builder()
            .method("GET")
            .uri(path)
            .body(Body::empty())
            .unwrap();

        let resp = router.clone().oneshot(req).await.unwrap();
        let status = resp.status();
        let bytes = resp.into_body().collect().await.unwrap().to_bytes();
        let json: serde_json::Value = serde_json::from_slice(&bytes)
            .unwrap_or(serde_json::json!({"raw": String::from_utf8_lossy(&bytes).to_string()}));
        (status, json)
    }

    async fn delete_json(router: &axum::Router, path: &str) -> (StatusCode, serde_json::Value) {
        let req = Request::builder()
            .method("DELETE")
            .uri(path)
            .body(Body::empty())
            .unwrap();

        let resp = router.clone().oneshot(req).await.unwrap();
        let status = resp.status();
        let bytes = resp.into_body().collect().await.unwrap().to_bytes();
        let json: serde_json::Value =
            serde_json::from_slice(&bytes).unwrap_or(serde_json::json!({}));
        (status, json)
    }

    #[tokio::test]
    async fn agent_chat_returns_ndjson_events() {
        let router = build_test_router();

        let (status, body) = post_json(
            &router,
            "/chat/agent",
            serde_json::json!({"prompt": "hello"}),
        )
        .await;

        assert_eq!(status, StatusCode::OK);

        // Parse NDJSON lines
        let events: Vec<serde_json::Value> = body
            .lines()
            .filter(|l| !l.is_empty())
            .filter_map(|l| serde_json::from_str(l).ok())
            .collect();

        assert!(!events.is_empty(), "expected NDJSON events, got: {body}");

        // Should have at least a text event and a done event
        let has_text = events.iter().any(|e| e["type"] == "text");
        let has_done = events.iter().any(|e| e["type"] == "done");
        assert!(has_text, "expected text event in: {body}");
        assert!(has_done, "expected done event in: {body}");

        // Done event should have session_id
        let done = events.iter().find(|e| e["type"] == "done").unwrap();
        assert!(done["session_id"].is_string());
    }

    #[tokio::test]
    async fn agent_chat_empty_prompt_returns_error() {
        let router = build_test_router();

        let (status, body) =
            post_json(&router, "/chat/agent", serde_json::json!({"prompt": ""})).await;

        assert_eq!(status, StatusCode::BAD_REQUEST);
        let event: serde_json::Value = body
            .lines()
            .next()
            .and_then(|l| serde_json::from_str(l).ok())
            .unwrap_or_default();
        assert_eq!(event["type"], "error");
    }

    #[tokio::test]
    async fn session_create_returns_id() {
        let router = build_test_router();

        let (status, body) = post_json(&router, "/sessions", serde_json::json!({})).await;

        assert_eq!(status, StatusCode::OK);
        let json: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert!(json["session_id"].is_string());
        assert!(json["created_at"].is_number());
    }

    #[tokio::test]
    async fn session_history_after_chat() {
        let state = build_test_state();
        let router = build_agent_routes(state.clone());

        // Chat with a specific session
        let session_id = uuid::Uuid::new_v4().to_string();
        let (status, _body) = post_json(
            &router,
            "/chat/agent",
            serde_json::json!({
                "prompt": "test prompt",
                "session_id": session_id,
            }),
        )
        .await;
        assert_eq!(status, StatusCode::OK);

        // Wait a moment for the background task to complete
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;

        // Get session history
        let (status, json) = get_json(&router, &format!("/sessions/{session_id}")).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(json["session_id"], session_id);

        let turns = json["turns"].as_array().unwrap();
        // Should have at least the user turn (assistant turn may not have been saved yet
        // depending on timing, but user turn is saved synchronously before spawning)
        assert!(
            !turns.is_empty(),
            "expected at least user turn, got: {json}"
        );

        // First turn should be the user message
        assert_eq!(turns[0]["messages"][0]["role"], "user");
        assert_eq!(turns[0]["messages"][0]["content"], "test prompt");
    }

    #[tokio::test]
    async fn session_delete() {
        let state = build_test_state();
        let router = build_agent_routes(state.clone());
        let session_id = "test-delete-session";

        // Add a turn manually
        let turn = Turn {
            turn_id: uuid::Uuid::new_v4().to_string(),
            session_id: session_id.to_string(),
            agent: "ui-agent".to_string(),
            messages: vec![Message {
                role: Role::User,
                content: "hello".to_string(),
                timestamp: 1000,
                metadata: None,
            }],
            created_at: 1000,
            fork_id: None,
            parent_fork: None,
        };
        state.memory.with(|mem| mem.add_turn(&turn).unwrap());
        assert_eq!(
            state.memory.with(|mem| mem.turn_count(session_id).unwrap()),
            1
        );

        // Delete
        let (status, json) = delete_json(&router, &format!("/sessions/{session_id}")).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(json["deleted"], true);

        // Verify deleted
        assert_eq!(
            state.memory.with(|mem| mem.turn_count(session_id).unwrap()),
            0
        );
    }

    #[tokio::test]
    async fn session_list_returns_array() {
        let router = build_test_router();
        let (status, json) = get_json(&router, "/sessions").await;
        assert_eq!(status, StatusCode::OK);
        assert!(json["sessions"].is_array());
    }

    #[tokio::test]
    async fn agent_chat_with_session_continuity() {
        let state = build_test_state();
        let router = build_agent_routes(state.clone());
        let session_id = uuid::Uuid::new_v4().to_string();

        // First message
        let (status, _) = post_json(
            &router,
            "/chat/agent",
            serde_json::json!({
                "prompt": "first question",
                "session_id": session_id,
            }),
        )
        .await;
        assert_eq!(status, StatusCode::OK);

        // Second message with same session
        let (status, _) = post_json(
            &router,
            "/chat/agent",
            serde_json::json!({
                "prompt": "follow-up question",
                "session_id": session_id,
            }),
        )
        .await;
        assert_eq!(status, StatusCode::OK);

        // Wait for background tasks
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;

        // Both user turns should be stored
        let turn_count = state
            .memory
            .with(|mem| mem.turn_count(&session_id).unwrap());
        assert!(
            turn_count >= 2,
            "expected at least 2 turns (2 user messages), got {turn_count}"
        );
    }
}
