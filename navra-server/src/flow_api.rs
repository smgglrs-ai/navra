//! HTTP endpoints for flow graph visualization.
//!
//! Provides REST and SSE endpoints consumed by the React Flow UI:
//! - `GET /flows/{id}/graph` — JSON graph for React Flow
//! - `GET /flows/{id}/graph/dot` — Graphviz DOT representation
//! - `GET /flows/{id}/events` — SSE stream of FlowEvent

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::sse::{Event, KeepAlive, Sse};
use axum::response::IntoResponse;
use std::convert::Infallible;
use std::sync::Arc;

use crate::flow_tools::FlowRegistry;

/// Shared state for flow API handlers.
#[derive(Clone)]
pub(crate) struct FlowApiState {
    pub registry: Arc<FlowRegistry>,
    pub event_log: Option<Arc<navra_flow::event_log::EventLog>>,
}

/// `GET /flows/{id}/graph` — returns the flow graph as JSON.
async fn handle_flow_graph(
    State(state): State<FlowApiState>,
    Path(flow_id): Path<String>,
) -> impl IntoResponse {
    match state.registry.flow_graph_json(&flow_id) {
        Some(graph) => axum::Json(graph).into_response(),
        None => (StatusCode::NOT_FOUND, format!("Unknown flow: {flow_id}")).into_response(),
    }
}

/// `GET /flows/{id}/graph/dot` — returns the flow graph as Graphviz DOT.
async fn handle_flow_graph_dot(
    State(state): State<FlowApiState>,
    Path(flow_id): Path<String>,
) -> impl IntoResponse {
    match state.registry.flow_graph_json(&flow_id) {
        Some(graph) => {
            // Build a DOT string from the graph JSON
            let mut dot = String::from("digraph flow {\n  rankdir=LR;\n");
            if let Some(nodes) = graph["nodes"].as_array() {
                for node in nodes {
                    let id = node["id"].as_str().unwrap_or("?");
                    let label = node["label"].as_str().unwrap_or(id);
                    let status = node["status"].as_str().unwrap_or("pending");
                    let color = match status {
                        "running" => "blue",
                        "done" => "green",
                        "failed" => "red",
                        "skipped" => "gray",
                        _ => "black",
                    };
                    dot.push_str(&format!(
                        "  \"{id}\" [label=\"{label}\\n[{status}]\", color={color}];\n"
                    ));
                }
            }
            if let Some(edges) = graph["edges"].as_array() {
                for edge in edges {
                    let src = edge["source"].as_str().unwrap_or("?");
                    let tgt = edge["target"].as_str().unwrap_or("?");
                    let label = edge["label"].as_str().unwrap_or("");
                    dot.push_str(&format!("  \"{src}\" -> \"{tgt}\" [label=\"{label}\"];\n"));
                }
            }
            dot.push_str("}\n");
            (
                [(axum::http::header::CONTENT_TYPE, "text/plain; charset=utf-8")],
                dot,
            )
                .into_response()
        }
        None => (StatusCode::NOT_FOUND, format!("Unknown flow: {flow_id}")).into_response(),
    }
}

/// `GET /flows/{id}/events` — SSE stream of FlowEvent.
///
/// Supports `Last-Event-ID` header for reconnection: sends all events
/// since the given sequence number, then keeps the connection open for
/// new events (polled every 2 seconds).
async fn handle_flow_events(
    State(state): State<FlowApiState>,
    Path(flow_id): Path<String>,
    headers: axum::http::HeaderMap,
) -> impl IntoResponse {
    let Some(event_log) = state.event_log else {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            "Event log not configured",
        )
            .into_response();
    };

    // Check flow exists
    if state.registry.get_status(&flow_id).is_none() {
        return (StatusCode::NOT_FOUND, format!("Unknown flow: {flow_id}")).into_response();
    }

    let last_event_id: i64 = headers
        .get("last-event-id")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);

    let flow_id_owned = flow_id.clone();
    let stream = async_stream::stream! {
        let mut cursor = last_event_id;

        loop {
            match event_log.events_since(&flow_id_owned, cursor) {
                Ok(events) => {
                    for stored in &events {
                        cursor = stored.seq;
                        let json = serde_json::to_string(&stored.event)
                            .unwrap_or_else(|_| "{}".to_string());
                        yield Ok::<_, Infallible>(
                            Event::default()
                                .id(cursor.to_string())
                                .event("flow_event")
                                .data(json)
                        );
                    }
                }
                Err(e) => {
                    yield Ok(Event::default().event("error").data(format!("{e}")));
                    break;
                }
            }

            // Check if flow is done — if so, send a final event and close
            let is_done = state
                .registry
                .get_status(&flow_id_owned)
                .and_then(|s| s["status"].as_str().map(String::from))
                .map(|s| s == "completed" || s == "failed")
                .unwrap_or(true);

            if is_done {
                yield Ok(Event::default().event("done").data("flow finished"));
                break;
            }

            tokio::time::sleep(std::time::Duration::from_secs(2)).await;
        }
    };

    Sse::new(stream)
        .keep_alive(KeepAlive::default())
        .into_response()
}

/// Build an axum Router for the flow graph API.
pub(crate) fn flow_api_router(
    registry: Arc<FlowRegistry>,
    event_log: Option<Arc<navra_flow::event_log::EventLog>>,
) -> axum::Router {
    let state = FlowApiState {
        registry,
        event_log,
    };

    axum::Router::new()
        .route("/flows/{id}/graph", axum::routing::get(handle_flow_graph))
        .route(
            "/flows/{id}/graph/dot",
            axum::routing::get(handle_flow_graph_dot),
        )
        .route(
            "/flows/{id}/events",
            axum::routing::get(handle_flow_events),
        )
        .with_state(state)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::flow_tools::{FlowRegistry, NodeStatus};

    #[test]
    fn flow_graph_json_returns_correct_structure() {
        let reg = FlowRegistry::new();
        let id = reg.register("test-flow");

        reg.update_nodes(
            &id,
            vec![
                NodeStatus {
                    id: "scout".to_string(),
                    specialist: "scout".to_string(),
                    status: "done".to_string(),
                    output: Some("found stuff".to_string()),
                    started_at: None,
                    completed_at: None,
                },
                NodeStatus {
                    id: "analyst".to_string(),
                    specialist: "analyst".to_string(),
                    status: "running".to_string(),
                    output: None,
                    started_at: None,
                    completed_at: None,
                },
            ],
        );

        let graph = reg.flow_graph_json(&id).unwrap();
        assert_eq!(graph["name"], "test-flow");
        assert_eq!(graph["status"], "running");

        let nodes = graph["nodes"].as_array().unwrap();
        assert_eq!(nodes.len(), 2);
        assert_eq!(nodes[0]["id"], "scout");
        assert_eq!(nodes[0]["status"], "done");
        assert_eq!(nodes[1]["id"], "analyst");
        assert_eq!(nodes[1]["status"], "running");
    }

    #[test]
    fn flow_graph_json_unknown_flow() {
        let reg = FlowRegistry::new();
        assert!(reg.flow_graph_json("nonexistent").is_none());
    }

    #[test]
    fn flow_graph_dot_output() {
        let reg = FlowRegistry::new();
        let id = reg.register("dot-test");

        reg.update_nodes(
            &id,
            vec![NodeStatus {
                id: "task1".to_string(),
                specialist: "dev".to_string(),
                status: "done".to_string(),
                output: None,
                started_at: None,
                completed_at: None,
            }],
        );

        let graph = reg.flow_graph_json(&id).unwrap();
        // Build DOT from graph JSON — same logic as handler
        let mut dot = String::from("digraph flow {\n  rankdir=LR;\n");
        if let Some(nodes) = graph["nodes"].as_array() {
            for node in nodes {
                let nid = node["id"].as_str().unwrap_or("?");
                let label = node["label"].as_str().unwrap_or(nid);
                let status = node["status"].as_str().unwrap_or("pending");
                dot.push_str(&format!(
                    "  \"{nid}\" [label=\"{label}\\n[{status}]\", color=green];\n"
                ));
            }
        }
        dot.push_str("}\n");

        assert!(dot.contains("digraph flow"));
        assert!(dot.contains("task1"));
        assert!(dot.contains("dev"));
    }

    #[tokio::test]
    async fn flow_api_graph_endpoint() {
        use axum::body::Body;
        use axum::http::Request;
        use tower::ServiceExt;

        let reg = Arc::new(FlowRegistry::new());
        let id = reg.register("api-test");
        reg.update_nodes(
            &id,
            vec![NodeStatus {
                id: "t1".to_string(),
                specialist: "dev".to_string(),
                status: "pending".to_string(),
                output: None,
                started_at: None,
                completed_at: None,
            }],
        );

        let app = flow_api_router(reg, None);

        let resp = app
            .oneshot(
                Request::builder()
                    .uri(format!("/flows/{id}/graph"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::OK);

        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["name"], "api-test");
        assert!(json["nodes"].as_array().unwrap().len() > 0);
    }

    #[tokio::test]
    async fn flow_api_graph_not_found() {
        use axum::body::Body;
        use axum::http::Request;
        use tower::ServiceExt;

        let reg = Arc::new(FlowRegistry::new());
        let app = flow_api_router(reg, None);

        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/flows/nonexistent/graph")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn flow_api_dot_endpoint() {
        use axum::body::Body;
        use axum::http::Request;
        use tower::ServiceExt;

        let reg = Arc::new(FlowRegistry::new());
        let id = reg.register("dot-api");
        reg.update_nodes(
            &id,
            vec![NodeStatus {
                id: "t1".to_string(),
                specialist: "dev".to_string(),
                status: "done".to_string(),
                output: None,
                started_at: None,
                completed_at: None,
            }],
        );

        let app = flow_api_router(reg, None);

        let resp = app
            .oneshot(
                Request::builder()
                    .uri(format!("/flows/{id}/graph/dot"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::OK);
        let ct = resp.headers().get("content-type").unwrap().to_str().unwrap();
        assert!(ct.contains("text/plain"));

        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let dot = String::from_utf8(body.to_vec()).unwrap();
        assert!(dot.starts_with("digraph flow"));
        assert!(dot.contains("t1"));
    }

    #[tokio::test]
    async fn flow_api_events_no_log() {
        use axum::body::Body;
        use axum::http::Request;
        use tower::ServiceExt;

        let reg = Arc::new(FlowRegistry::new());
        let _id = reg.register("evt-test");

        let app = flow_api_router(reg, None);

        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/flows/evt-test/events")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        // Without event_log configured, should return 503
        assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
    }
}
