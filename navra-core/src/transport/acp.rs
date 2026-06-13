//! ACP v0.2.0 (Agent Communication Protocol) RESTful transport.
//!
//! Implements the ACP OpenAPI spec as Axum routes under `/acp/`.
//! Supports agent discovery, run lifecycle (sync/async/stream),
//! session retrieval, and typed SSE events.
//!
//! Reference: <https://agentcommunicationprotocol.dev>

use crate::acp::agents;
use crate::acp::dispatch::{self, RunDispatcher, ToolDispatcher};
use crate::acp::store::RunStore;
use crate::acp::types::*;
use crate::server::McpServer;
use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::sse::{Event as SseEvent, KeepAlive, Sse};
use axum::response::IntoResponse;
use axum::routing::{get, post};
use axum::{Json, Router};
use std::convert::Infallible;
use std::sync::Arc;
use tokio_stream::wrappers::ReceiverStream;
use tokio_stream::StreamExt;

#[derive(Clone)]
struct AcpState {
    server: Arc<McpServer>,
    runs: RunStore,
    dispatcher: Arc<dyn RunDispatcher>,
    flows: Vec<FlowSummary>,
    approval_gate: Option<Arc<crate::hooks::ApprovalGateHook>>,
}

const RUN_MAX_AGE_SECS: u64 = 3600;

fn build_routes(state: AcpState) -> Router {
    let sweep_store = state.runs.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(300));
        loop {
            interval.tick().await;
            let expired = sweep_store.expire(std::time::Duration::from_secs(RUN_MAX_AGE_SECS));
            if expired > 0 {
                tracing::debug!(expired, "ACP run store sweep");
            }
        }
    });

    Router::new()
        .route("/acp/ping", get(handle_ping))
        .route("/acp/agents", get(handle_list_agents))
        .route("/acp/agents/{name}", get(handle_get_agent))
        .route("/acp/runs", post(handle_create_run))
        .route(
            "/acp/runs/{run_id}",
            get(handle_get_run).post(handle_resume_run),
        )
        .route("/acp/runs/{run_id}/cancel", post(handle_cancel_run))
        .route("/acp/runs/{run_id}/events", get(handle_list_events))
        .route("/acp/session/{session_id}", get(handle_get_session))
        .with_state(state)
}

/// Build the ACP v0.2.0 router with the default tool-only dispatcher.
pub fn build_acp_router(server: Arc<McpServer>) -> Router {
    let state = AcpState {
        server,
        runs: RunStore::new(),
        dispatcher: Arc::new(ToolDispatcher),
        flows: vec![],
        approval_gate: None,
    };
    build_routes(state)
}

/// Build the ACP v0.2.0 router with a custom dispatcher, flows, and
/// optional approval gate for await/resume.
pub fn build_acp_router_with_dispatcher(
    server: Arc<McpServer>,
    dispatcher: Arc<dyn RunDispatcher>,
    flows: Vec<FlowSummary>,
    approval_gate: Option<Arc<crate::hooks::ApprovalGateHook>>,
) -> Router {
    let state = AcpState {
        server,
        runs: RunStore::new(),
        dispatcher,
        flows,
        approval_gate,
    };
    build_routes(state)
}

fn authenticate(
    server: &McpServer,
    headers: &HeaderMap,
) -> Result<crate::auth::AgentIdentity, (StatusCode, Json<AcpError>)> {
    server.authenticator().authenticate(headers).map_err(|_| {
        (
            StatusCode::UNAUTHORIZED,
            Json(AcpError::server_error("Authentication failed")),
        )
    })
}

// --- Handlers ---

async fn handle_ping() -> Json<serde_json::Value> {
    Json(serde_json::json!({}))
}

async fn handle_list_agents(
    State(state): State<AcpState>,
    headers: HeaderMap,
    Query(params): Query<PaginationParams>,
) -> Result<Json<AgentsListResponse>, (StatusCode, Json<AcpError>)> {
    authenticate(&state.server, &headers)?;
    let all: Vec<AgentManifest> = agents::build_manifests(&state.server, &state.flows)
        .into_iter()
        .map(|m| agents::with_metrics(m, &state.runs))
        .collect();

    let start = params.offset.min(all.len());
    let end = (start + params.limit).min(all.len());
    let agents_page = all[start..end].to_vec();

    Ok(Json(AgentsListResponse {
        agents: agents_page,
    }))
}

async fn handle_get_agent(
    State(state): State<AcpState>,
    headers: HeaderMap,
    Path(name): Path<String>,
) -> Result<Json<AgentManifest>, (StatusCode, Json<AcpError>)> {
    authenticate(&state.server, &headers)?;
    let manifests = agents::build_manifests(&state.server, &state.flows);
    match manifests.into_iter().find(|m| m.name == name) {
        Some(manifest) => Ok(Json(agents::with_metrics(manifest, &state.runs))),
        None => Err((
            StatusCode::NOT_FOUND,
            Json(AcpError::not_found(format!("Agent '{}' not found", name))),
        )),
    }
}

async fn handle_create_run(
    State(state): State<AcpState>,
    headers: HeaderMap,
    Json(request): Json<RunCreateRequest>,
) -> Result<impl IntoResponse, (StatusCode, Json<AcpError>)> {
    let agent = authenticate(&state.server, &headers)?;

    let manifests = agents::build_manifests(&state.server, &state.flows);
    if !manifests.iter().any(|m| m.name == request.agent_name) {
        return Err((
            StatusCode::NOT_FOUND,
            Json(AcpError::not_found(format!(
                "Agent '{}' not found",
                request.agent_name
            ))),
        ));
    }

    if request.input.is_empty() {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(AcpError::invalid_input(
                "input must contain at least one message",
            )),
        ));
    }

    let mode = request.mode.unwrap_or(RunMode::Sync);
    let run = dispatch::create_run(
        &state.runs,
        &state.server,
        &request.agent_name,
        request.session_id,
        &agent,
    );
    let run_id = run.run_id.clone();

    match mode {
        RunMode::Sync => {
            let completed = state
                .dispatcher
                .execute(
                    state.server.clone(),
                    state.runs.clone(),
                    run_id,
                    request.input,
                    agent,
                )
                .await;
            Ok((StatusCode::OK, Json(completed)).into_response())
        }
        RunMode::Async => {
            let dispatcher = state.dispatcher.clone();
            let server = state.server.clone();
            let runs = state.runs.clone();
            let input = request.input;
            tokio::spawn(async move {
                dispatcher.execute(server, runs, run_id, input, agent).await;
            });
            Ok((StatusCode::ACCEPTED, Json(run)).into_response())
        }
        RunMode::Stream => {
            let rx = state.dispatcher.execute_stream(
                state.server.clone(),
                state.runs.clone(),
                run_id.clone(),
                request.input,
                agent,
            );

            let created_event = Event::RunCreated { run };
            let created_data = serde_json::to_string(&created_event).unwrap_or_default();

            let initial = futures_util::stream::once(async move {
                Ok::<_, Infallible>(SseEvent::default().event("run.created").data(created_data))
            });

            let rest = ReceiverStream::new(rx).map(|event| {
                let event_type = match &event {
                    Event::MessageCreated { .. } => "message.created",
                    Event::MessagePart { .. } => "message.part",
                    Event::MessageCompleted { .. } => "message.completed",
                    Event::RunCreated { .. } => "run.created",
                    Event::RunInProgress { .. } => "run.in-progress",
                    Event::RunAwaiting { .. } => "run.awaiting",
                    Event::RunCompleted { .. } => "run.completed",
                    Event::RunCancelled { .. } => "run.cancelled",
                    Event::RunFailed { .. } => "run.failed",
                    Event::Error { .. } => "error",
                    Event::Generic { .. } => "generic",
                };
                let data = serde_json::to_string(&event).unwrap_or_default();
                Ok::<_, Infallible>(SseEvent::default().event(event_type).data(data))
            });

            let stream = initial.chain(rest);
            Ok(Sse::new(stream)
                .keep_alive(KeepAlive::default())
                .into_response())
        }
    }
}

async fn handle_get_run(
    State(state): State<AcpState>,
    headers: HeaderMap,
    Path(run_id): Path<String>,
) -> Result<Json<Run>, (StatusCode, Json<AcpError>)> {
    authenticate(&state.server, &headers)?;
    state.runs.get(&run_id).map(Json).ok_or_else(|| {
        (
            StatusCode::NOT_FOUND,
            Json(AcpError::not_found(format!("Run '{}' not found", run_id))),
        )
    })
}

async fn handle_resume_run(
    State(state): State<AcpState>,
    headers: HeaderMap,
    Path(run_id): Path<String>,
    Json(request): Json<RunResumeRequest>,
) -> Result<Json<Run>, (StatusCode, Json<AcpError>)> {
    let agent = authenticate(&state.server, &headers)?;
    let run = state.runs.get(&run_id).ok_or_else(|| {
        (
            StatusCode::NOT_FOUND,
            Json(AcpError::not_found(format!("Run '{}' not found", run_id))),
        )
    })?;

    if run.status != RunStatus::Awaiting {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(AcpError::invalid_input(format!(
                "Run '{}' is not in awaiting state (current: {:?})",
                run_id, run.status
            ))),
        ));
    }

    let approved = request
        .await_resume
        .get("approved")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    let reason = request
        .await_resume
        .get("reason")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();

    let request_id = run
        .await_request
        .as_ref()
        .and_then(|r| r.get("request_id"))
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();

    if let Some(gate) = state.approval_gate.as_ref() {
        if approved {
            gate.approve(&request_id);
        } else {
            gate.deny(&request_id, reason);
        }
    }

    state.runs.clear_await(&run_id);

    if approved {
        let pending_tool = run
            .await_request
            .as_ref()
            .and_then(|r| r.get("tool_name"))
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        let pending_args = run
            .await_request
            .as_ref()
            .and_then(|r| r.get("arguments"))
            .cloned()
            .unwrap_or(serde_json::json!({}));

        state.runs.update_status(&run_id, RunStatus::InProgress);

        if !pending_tool.is_empty() {
            let ctx = crate::auth::CallContext::new(agent, run_id.clone());
            let call_params = crate::protocol::CallToolParams {
                name: pending_tool,
                arguments: pending_args,
                meta: None,
            };
            let result = state.server.handle_call_tool(call_params, ctx).await;
            let result_text: String = result
                .content
                .iter()
                .filter_map(|c| match c {
                    crate::protocol::Content::Text(t) => Some(t.text.clone()),
                    _ => None,
                })
                .collect::<Vec<_>>()
                .join("\n");

            let msg = Message {
                role: "agent".to_string(),
                parts: vec![MessagePart::text(result_text)],
                created_at: Some(dispatch::now_iso()),
                completed_at: Some(dispatch::now_iso()),
            };
            state.runs.add_output_message(&run_id, msg);
        }

        let finished = state
            .runs
            .set_finished(&run_id, RunStatus::Completed, dispatch::now_iso())
            .unwrap();
        state.runs.add_event(
            &run_id,
            Event::RunCompleted {
                run: finished.clone(),
            },
        );
        Ok(Json(finished))
    } else {
        let finished = state
            .runs
            .set_finished(&run_id, RunStatus::Failed, dispatch::now_iso())
            .unwrap();
        state.runs.add_event(
            &run_id,
            Event::RunFailed {
                run: finished.clone(),
            },
        );
        Ok(Json(finished))
    }
}

async fn handle_cancel_run(
    State(state): State<AcpState>,
    headers: HeaderMap,
    Path(run_id): Path<String>,
) -> Result<(StatusCode, Json<Run>), (StatusCode, Json<AcpError>)> {
    authenticate(&state.server, &headers)?;
    let run = state.runs.get(&run_id).ok_or_else(|| {
        (
            StatusCode::NOT_FOUND,
            Json(AcpError::not_found(format!("Run '{}' not found", run_id))),
        )
    })?;

    match run.status {
        RunStatus::Completed | RunStatus::Failed | RunStatus::Cancelled => {
            return Err((
                StatusCode::BAD_REQUEST,
                Json(AcpError::invalid_input(format!(
                    "Run '{}' already finished ({:?})",
                    run_id, run.status
                ))),
            ));
        }
        _ => {}
    }

    let finished_at = dispatch::now_iso();
    let cancelled = state
        .runs
        .set_finished(&run_id, RunStatus::Cancelled, finished_at)
        .unwrap();
    state.runs.add_event(
        &run_id,
        Event::RunCancelled {
            run: cancelled.clone(),
        },
    );

    Ok((StatusCode::ACCEPTED, Json(cancelled)))
}

async fn handle_list_events(
    State(state): State<AcpState>,
    headers: HeaderMap,
    Path(run_id): Path<String>,
) -> Result<Json<RunEventsListResponse>, (StatusCode, Json<AcpError>)> {
    authenticate(&state.server, &headers)?;
    if state.runs.get(&run_id).is_none() {
        return Err((
            StatusCode::NOT_FOUND,
            Json(AcpError::not_found(format!("Run '{}' not found", run_id))),
        ));
    }
    let events = state.runs.list_events(&run_id);
    Ok(Json(RunEventsListResponse { events }))
}

async fn handle_get_session(
    State(state): State<AcpState>,
    headers: HeaderMap,
    Path(session_id): Path<String>,
) -> Result<Json<SessionSpec>, (StatusCode, Json<AcpError>)> {
    authenticate(&state.server, &headers)?;

    match state.server.sessions().get(&session_id) {
        Some(_) => {
            let run_ids = state.runs.runs_for_session(&session_id);
            let history = run_ids
                .iter()
                .map(|rid| format!("/acp/runs/{}", rid))
                .collect();
            Ok(Json(SessionSpec {
                id: session_id,
                history,
                state: None,
            }))
        }
        None => Err((
            StatusCode::NOT_FOUND,
            Json(AcpError::not_found(format!(
                "Session '{}' not found",
                session_id
            ))),
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::{AgentIdentity, NoAuthenticator};
    use crate::protocol::{CallToolResult, ToolDefinition, ToolInputSchema};
    use axum::body::Body;
    use axum::http::Request;
    use http_body_util::BodyExt;
    use tower::util::ServiceExt;

    fn test_server() -> Arc<McpServer> {
        Arc::new(
            McpServer::builder()
                .name("test-agent")
                .version("0.1.0")
                .authenticator(NoAuthenticator {
                    default_identity: AgentIdentity::new("tester", "dev"),
                })
                .tool(
                    ToolDefinition {
                        name: "ping".to_string(),
                        description: Some("Returns pong".to_string()),
                        input_schema: ToolInputSchema {
                            schema_type: "object".to_string(),
                            properties: None,
                            required: None,
                        },
                        annotations: None,
                        ttl_ms: None,
                        cache_scope: None,
                    },
                    |_args, _ctx| Box::pin(async { CallToolResult::text("pong") }),
                )
                .build(),
        )
    }

    async fn get_json(router: &Router, path: &str) -> (StatusCode, serde_json::Value) {
        let req = Request::builder()
            .method("GET")
            .uri(path)
            .body(Body::empty())
            .unwrap();
        let resp = router.clone().oneshot(req).await.unwrap();
        let status = resp.status();
        let bytes = resp.into_body().collect().await.unwrap().to_bytes();
        let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        (status, json)
    }

    async fn post_json(
        router: &Router,
        path: &str,
        body: serde_json::Value,
    ) -> (StatusCode, serde_json::Value) {
        let req = Request::builder()
            .method("POST")
            .uri(path)
            .header("content-type", "application/json")
            .body(Body::from(serde_json::to_string(&body).unwrap()))
            .unwrap();
        let resp = router.clone().oneshot(req).await.unwrap();
        let status = resp.status();
        let bytes = resp.into_body().collect().await.unwrap().to_bytes();
        let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        (status, json)
    }

    async fn post_raw(
        router: &Router,
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

    #[tokio::test]
    async fn ping_returns_ok() {
        let router = build_acp_router(test_server());
        let (status, json) = get_json(&router, "/acp/ping").await;
        assert_eq!(status, StatusCode::OK);
        assert!(json.is_object());
    }

    #[tokio::test]
    async fn list_agents_returns_manifests() {
        let router = build_acp_router(test_server());
        let (status, json) = get_json(&router, "/acp/agents").await;
        assert_eq!(status, StatusCode::OK);
        let agents = json["agents"].as_array().unwrap();
        assert_eq!(agents.len(), 1);
        assert_eq!(agents[0]["name"], "test-agent");
        assert!(agents[0]["description"].as_str().unwrap().contains("navra"));
    }

    #[tokio::test]
    async fn get_agent_returns_manifest() {
        let router = build_acp_router(test_server());
        let (status, json) = get_json(&router, "/acp/agents/test-agent").await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(json["name"], "test-agent");
        let caps = json["metadata"]["capabilities"].as_array().unwrap();
        assert!(
            caps.iter().any(|c| c["name"] == "ping"),
            "Expected 'ping' in capabilities: {:?}",
            caps
        );
    }

    #[tokio::test]
    async fn get_agent_not_found() {
        let router = build_acp_router(test_server());
        let (status, json) = get_json(&router, "/acp/agents/nonexistent").await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        assert_eq!(json["code"], "not_found");
    }

    #[tokio::test]
    async fn create_run_sync_mode() {
        let router = build_acp_router(test_server());
        let (status, json) = post_json(
            &router,
            "/acp/runs",
            serde_json::json!({
                "agent_name": "test-agent",
                "input": [{
                    "role": "user",
                    "parts": [{"content_type": "text/plain", "content": "/tool ping {}"}]
                }],
                "mode": "sync"
            }),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(json["status"], "completed");
        assert_eq!(json["agent_name"], "test-agent");
        let output = json["output"].as_array().unwrap();
        assert!(!output.is_empty());
        let text = serde_json::to_string(&output[0]["parts"]).unwrap();
        assert!(text.contains("pong"), "Expected 'pong' in output: {}", text);
    }

    #[tokio::test]
    async fn create_run_async_mode() {
        let router = build_acp_router(test_server());
        let (status, json) = post_json(
            &router,
            "/acp/runs",
            serde_json::json!({
                "agent_name": "test-agent",
                "input": [{
                    "role": "user",
                    "parts": [{"content_type": "text/plain", "content": "/tool ping {}"}]
                }],
                "mode": "async"
            }),
        )
        .await;
        assert_eq!(status, StatusCode::ACCEPTED);
        assert_eq!(json["status"], "created");
        assert!(json["run_id"].as_str().is_some());
    }

    #[tokio::test]
    async fn create_run_stream_mode() {
        let router = build_acp_router(test_server());
        let (status, body) = post_raw(
            &router,
            "/acp/runs",
            serde_json::json!({
                "agent_name": "test-agent",
                "input": [{
                    "role": "user",
                    "parts": [{"content_type": "text/plain", "content": "/tool ping {}"}]
                }],
                "mode": "stream"
            }),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert!(
            body.contains("run.created"),
            "Expected run.created event: {}",
            body
        );
        assert!(body.contains("pong"), "Expected pong in stream: {}", body);
    }

    #[tokio::test]
    async fn create_run_default_mode_is_sync() {
        let router = build_acp_router(test_server());
        let (status, json) = post_json(
            &router,
            "/acp/runs",
            serde_json::json!({
                "agent_name": "test-agent",
                "input": [{
                    "role": "user",
                    "parts": [{"content_type": "text/plain", "content": "hello"}]
                }]
            }),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(json["status"], "completed");
    }

    #[tokio::test]
    async fn create_run_unknown_agent() {
        let router = build_acp_router(test_server());
        let (status, json) = post_json(
            &router,
            "/acp/runs",
            serde_json::json!({
                "agent_name": "unknown",
                "input": [{
                    "role": "user",
                    "parts": [{"content_type": "text/plain", "content": "hello"}]
                }]
            }),
        )
        .await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        assert_eq!(json["code"], "not_found");
    }

    #[tokio::test]
    async fn create_run_empty_input() {
        let router = build_acp_router(test_server());
        let (status, json) = post_json(
            &router,
            "/acp/runs",
            serde_json::json!({
                "agent_name": "test-agent",
                "input": []
            }),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(json["code"], "invalid_input");
    }

    #[tokio::test]
    async fn get_run_existing() {
        let server = test_server();
        let state = AcpState {
            server: server.clone(),
            runs: RunStore::new(),
            dispatcher: Arc::new(ToolDispatcher),
            flows: vec![],
            approval_gate: None,
        };
        let agent = AgentIdentity::new("tester", "dev");
        let run = dispatch::create_run(&state.runs, &state.server, "test-agent", None, &agent);
        let router = build_acp_router(server);

        // We need to use the same state — build a custom router for this test
        let test_router = Router::new()
            .route("/acp/runs/{run_id}", get(handle_get_run))
            .with_state(state);

        let (status, json) = get_json(&test_router, &format!("/acp/runs/{}", run.run_id)).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(json["run_id"], run.run_id);
    }

    #[tokio::test]
    async fn get_run_not_found() {
        let router = build_acp_router(test_server());
        let (status, json) = get_json(&router, "/acp/runs/nonexistent").await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        assert_eq!(json["code"], "not_found");
    }

    #[tokio::test]
    async fn cancel_run() {
        let server = test_server();
        let state = AcpState {
            server: server.clone(),
            runs: RunStore::new(),
            dispatcher: Arc::new(ToolDispatcher),
            flows: vec![],
            approval_gate: None,
        };
        let agent = AgentIdentity::new("tester", "dev");
        let run = dispatch::create_run(&state.runs, &state.server, "test-agent", None, &agent);
        state.runs.update_status(&run.run_id, RunStatus::InProgress);

        let test_router = Router::new()
            .route("/acp/runs/{run_id}/cancel", post(handle_cancel_run))
            .with_state(state);

        let req = Request::builder()
            .method("POST")
            .uri(format!("/acp/runs/{}/cancel", run.run_id))
            .header("content-type", "application/json")
            .body(Body::empty())
            .unwrap();
        let resp = test_router.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::ACCEPTED);
        let bytes = resp.into_body().collect().await.unwrap().to_bytes();
        let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(json["status"], "cancelled");
    }

    #[tokio::test]
    async fn cancel_completed_run_fails() {
        let server = test_server();
        let state = AcpState {
            server: server.clone(),
            runs: RunStore::new(),
            dispatcher: Arc::new(ToolDispatcher),
            flows: vec![],
            approval_gate: None,
        };
        let agent = AgentIdentity::new("tester", "dev");
        let run = dispatch::create_run(&state.runs, &state.server, "test-agent", None, &agent);
        state
            .runs
            .set_finished(&run.run_id, RunStatus::Completed, dispatch::now_iso());

        let test_router = Router::new()
            .route("/acp/runs/{run_id}/cancel", post(handle_cancel_run))
            .with_state(state);

        let req = Request::builder()
            .method("POST")
            .uri(format!("/acp/runs/{}/cancel", run.run_id))
            .header("content-type", "application/json")
            .body(Body::empty())
            .unwrap();
        let resp = test_router.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn list_events_for_run() {
        let server = test_server();
        let state = AcpState {
            server: server.clone(),
            runs: RunStore::new(),
            dispatcher: Arc::new(ToolDispatcher),
            flows: vec![],
            approval_gate: None,
        };
        let agent = AgentIdentity::new("tester", "dev");
        let run = dispatch::create_run(&state.runs, &state.server, "test-agent", None, &agent);

        let test_router = Router::new()
            .route("/acp/runs/{run_id}/events", get(handle_list_events))
            .with_state(state);

        let (status, json) =
            get_json(&test_router, &format!("/acp/runs/{}/events", run.run_id)).await;
        assert_eq!(status, StatusCode::OK);
        let events = json["events"].as_array().unwrap();
        assert!(!events.is_empty());
        assert_eq!(events[0]["type"], "run.created");
    }

    #[tokio::test]
    async fn list_events_not_found() {
        let router = build_acp_router(test_server());
        let (status, json) = get_json(&router, "/acp/runs/nonexistent/events").await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        assert_eq!(json["code"], "not_found");
    }

    #[tokio::test]
    async fn create_run_json_tool_format() {
        let router = build_acp_router(test_server());
        let (status, json) = post_json(
            &router,
            "/acp/runs",
            serde_json::json!({
                "agent_name": "test-agent",
                "input": [{
                    "role": "user",
                    "parts": [{
                        "content_type": "application/json",
                        "content": "{\"tool\": \"ping\", \"arguments\": {}}"
                    }]
                }],
                "mode": "sync"
            }),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(json["status"], "completed");
        let output_str = serde_json::to_string(&json["output"]).unwrap();
        assert!(output_str.contains("pong"), "Expected pong: {}", output_str);
    }

    #[tokio::test]
    async fn run_type_serialization() {
        let run = Run {
            agent_name: "test".to_string(),
            run_id: "abc-123".to_string(),
            status: RunStatus::InProgress,
            output: vec![],
            created_at: "2026-06-05T00:00:00Z".to_string(),
            session_id: None,
            await_request: None,
            error: None,
            finished_at: None,
        };
        let json = serde_json::to_value(&run).unwrap();
        assert_eq!(json["status"], "in-progress");
        assert_eq!(json["agent_name"], "test");
    }

    #[tokio::test]
    async fn event_type_serialization() {
        let event = Event::RunCompleted {
            run: Run {
                agent_name: "test".to_string(),
                run_id: "abc".to_string(),
                status: RunStatus::Completed,
                output: vec![],
                created_at: "2026-06-05T00:00:00Z".to_string(),
                session_id: None,
                await_request: None,
                error: None,
                finished_at: Some("2026-06-05T00:00:01Z".to_string()),
            },
        };
        let json = serde_json::to_value(&event).unwrap();
        assert_eq!(json["type"], "run.completed");
        assert_eq!(json["run"]["status"], "completed");
    }

    #[tokio::test]
    async fn error_serialization() {
        let err = AcpError::not_found("test");
        let json = serde_json::to_value(&err).unwrap();
        assert_eq!(json["code"], "not_found");
        assert_eq!(json["message"], "test");
    }

    #[tokio::test]
    async fn agents_pagination() {
        let router = build_acp_router(test_server());
        let (status, json) = get_json(&router, "/acp/agents?limit=0&offset=0").await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(json["agents"].as_array().unwrap().len(), 0);
    }

    #[tokio::test]
    async fn create_run_creates_session() {
        let server = test_server();
        let router = build_acp_router(server.clone());
        let (status, json) = post_json(
            &router,
            "/acp/runs",
            serde_json::json!({
                "agent_name": "test-agent",
                "session_id": "my-session-1",
                "input": [{
                    "role": "user",
                    "parts": [{"content_type": "text/plain", "content": "hello"}]
                }]
            }),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(json["session_id"], "my-session-1");
        assert!(
            server.sessions().get("my-session-1").is_some(),
            "Session should have been created"
        );
    }

    #[tokio::test]
    async fn create_run_auto_generates_session() {
        let router = build_acp_router(test_server());
        let (status, json) = post_json(
            &router,
            "/acp/runs",
            serde_json::json!({
                "agent_name": "test-agent",
                "input": [{
                    "role": "user",
                    "parts": [{"content_type": "text/plain", "content": "hello"}]
                }]
            }),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert!(json["session_id"].as_str().is_some());
    }

    #[tokio::test]
    async fn resume_run_not_awaiting() {
        let server = test_server();
        let state = AcpState {
            server: server.clone(),
            runs: RunStore::new(),
            dispatcher: Arc::new(ToolDispatcher),
            flows: vec![],
            approval_gate: None,
        };
        let agent = AgentIdentity::new("tester", "dev");
        let run = dispatch::create_run(&state.runs, &state.server, "test-agent", None, &agent);
        state.runs.update_status(&run.run_id, RunStatus::InProgress);

        let test_router = Router::new()
            .route(
                "/acp/runs/{run_id}",
                get(handle_get_run).post(handle_resume_run),
            )
            .with_state(state);

        let (status, json) = post_json(
            &test_router,
            &format!("/acp/runs/{}", run.run_id),
            serde_json::json!({
                "run_id": run.run_id,
                "await_resume": {"approved": true},
                "mode": "sync"
            }),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(json["code"], "invalid_input");
    }

    #[tokio::test]
    async fn resume_run_approved() {
        let server = test_server();
        let state = AcpState {
            server: server.clone(),
            runs: RunStore::new(),
            dispatcher: Arc::new(ToolDispatcher),
            flows: vec![],
            approval_gate: None,
        };
        let agent = AgentIdentity::new("tester", "dev");
        let run = dispatch::create_run(&state.runs, &state.server, "test-agent", None, &agent);
        state.runs.set_awaiting(
            &run.run_id,
            serde_json::json!({
                "request_id": "a-1",
                "tool_name": "ping",
                "arguments": {}
            }),
        );

        let test_router = Router::new()
            .route(
                "/acp/runs/{run_id}",
                get(handle_get_run).post(handle_resume_run),
            )
            .with_state(state);

        let (status, json) = post_json(
            &test_router,
            &format!("/acp/runs/{}", run.run_id),
            serde_json::json!({
                "run_id": run.run_id,
                "await_resume": {"approved": true},
                "mode": "sync"
            }),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(json["status"], "completed");
        let output_str = serde_json::to_string(&json["output"]).unwrap();
        assert!(output_str.contains("pong"), "Expected pong: {}", output_str);
    }

    #[tokio::test]
    async fn resume_run_denied() {
        let server = test_server();
        let state = AcpState {
            server: server.clone(),
            runs: RunStore::new(),
            dispatcher: Arc::new(ToolDispatcher),
            flows: vec![],
            approval_gate: None,
        };
        let agent = AgentIdentity::new("tester", "dev");
        let run = dispatch::create_run(&state.runs, &state.server, "test-agent", None, &agent);
        state.runs.set_awaiting(
            &run.run_id,
            serde_json::json!({"request_id": "a-1", "tool_name": "ping"}),
        );

        let test_router = Router::new()
            .route(
                "/acp/runs/{run_id}",
                get(handle_get_run).post(handle_resume_run),
            )
            .with_state(state);

        let (status, json) = post_json(
            &test_router,
            &format!("/acp/runs/{}", run.run_id),
            serde_json::json!({
                "run_id": run.run_id,
                "await_resume": {"approved": false, "reason": "too risky"},
                "mode": "sync"
            }),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(json["status"], "failed");
    }

    #[tokio::test]
    async fn multiple_messages_in_run() {
        let router = build_acp_router(test_server());
        let (status, json) = post_json(
            &router,
            "/acp/runs",
            serde_json::json!({
                "agent_name": "test-agent",
                "input": [
                    {
                        "role": "user",
                        "parts": [{"content_type": "text/plain", "content": "/tool ping {}"}]
                    },
                    {
                        "role": "user",
                        "parts": [{"content_type": "text/plain", "content": "just text"}]
                    }
                ],
                "mode": "sync"
            }),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(json["status"], "completed");
        let output_str = serde_json::to_string(&json["output"]).unwrap();
        assert!(output_str.contains("pong"));
        assert!(output_str.contains("Received"));
    }

    #[tokio::test]
    async fn agents_with_flows() {
        let server = test_server();
        let state = AcpState {
            server: server.clone(),
            runs: RunStore::new(),
            dispatcher: Arc::new(ToolDispatcher),
            flows: vec![FlowSummary {
                name: "audit".to_string(),
                description: "Security audit".to_string(),
                nodes: vec![
                    FlowNodeSummary {
                        id: "scan".to_string(),
                        description: "Scan for issues".to_string(),
                    },
                    FlowNodeSummary {
                        id: "fix".to_string(),
                        description: "Fix issues".to_string(),
                    },
                ],
            }],
            approval_gate: None,
        };

        let test_router = Router::new()
            .route("/acp/agents", get(handle_list_agents))
            .route("/acp/agents/{name}", get(handle_get_agent))
            .with_state(state);

        let (status, json) = get_json(&test_router, "/acp/agents").await;
        assert_eq!(status, StatusCode::OK);
        let agents = json["agents"].as_array().unwrap();
        assert_eq!(agents.len(), 3);
        let names: Vec<&str> = agents.iter().filter_map(|a| a["name"].as_str()).collect();
        assert!(names.contains(&"test-agent"));
        assert!(names.contains(&"audit-scan"));
        assert!(names.contains(&"audit-fix"));

        let (status, json) = get_json(&test_router, "/acp/agents/audit-scan").await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(json["description"], "Scan for issues");

        let (status, _) = get_json(&test_router, "/acp/agents/audit-unknown").await;
        assert_eq!(status, StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn agents_include_metrics_after_runs() {
        let server = test_server();
        let state = AcpState {
            server: server.clone(),
            runs: RunStore::new(),
            dispatcher: Arc::new(ToolDispatcher),
            flows: vec![],
            approval_gate: None,
        };

        let agent = AgentIdentity::new("tester", "dev");
        let run = dispatch::create_run(&state.runs, &state.server, "test-agent", None, &agent);
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        state
            .runs
            .set_finished(&run.run_id, RunStatus::Completed, dispatch::now_iso());

        let test_router = Router::new()
            .route("/acp/agents/{name}", get(handle_get_agent))
            .with_state(state);

        let (status, json) = get_json(&test_router, "/acp/agents/test-agent").await;
        assert_eq!(status, StatusCode::OK);
        let status_obj = &json["status"];
        assert!(status_obj.is_object(), "Expected status metrics");
        assert_eq!(status_obj["success_rate"], 100.0);
        assert!(status_obj["avg_run_time_seconds"].as_f64().unwrap() > 0.0);
    }

    #[tokio::test]
    async fn session_shows_run_history() {
        let server = test_server();
        let router = build_acp_router(server.clone());

        let (_, json) = post_json(
            &router,
            "/acp/runs",
            serde_json::json!({
                "agent_name": "test-agent",
                "session_id": "hist-session",
                "input": [{
                    "role": "user",
                    "parts": [{"content_type": "text/plain", "content": "hello"}]
                }]
            }),
        )
        .await;
        let run_id = json["run_id"].as_str().unwrap().to_string();

        let (status, json) = get_json(&router, "/acp/session/hist-session").await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(json["id"], "hist-session");
        let history = json["history"].as_array().unwrap();
        assert_eq!(history.len(), 1);
        assert!(history[0].as_str().unwrap().contains(&run_id));
    }

    #[tokio::test]
    async fn session_not_found() {
        let router = build_acp_router(test_server());
        let (status, json) = get_json(&router, "/acp/session/nonexistent").await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        assert_eq!(json["code"], "not_found");
    }
}
