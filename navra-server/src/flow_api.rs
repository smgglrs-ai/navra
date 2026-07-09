//! HTTP endpoints for flow graph visualization.
//!
//! Provides REST and SSE endpoints consumed by the React Flow UI:
//! - `GET /flows/{id}/graph` — JSON graph for React Flow
//! - `GET /flows/{id}/graph/dot` — Graphviz DOT representation
//! - `GET /flows/{id}/events` — SSE stream of FlowEvent

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::response::sse::{Event, KeepAlive, Sse};
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
                [(
                    axum::http::header::CONTENT_TYPE,
                    "text/plain; charset=utf-8",
                )],
                dot,
            )
                .into_response()
        }
        None => (StatusCode::NOT_FOUND, format!("Unknown flow: {flow_id}")).into_response(),
    }
}

/// `GET /flows/{id}/graph/bpmn` — returns BPMN 2.0 XML for the flow.
///
/// Generates BPMN XML from the flow's DAG structure with status
/// extensions on each node. Consumable by bpmn.io or any BPMN viewer.
async fn handle_flow_graph_bpmn(
    State(state): State<FlowApiState>,
    Path(flow_id): Path<String>,
) -> impl IntoResponse {
    let flows = state
        .registry
        .flows
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    let Some(run) = flows.get(&flow_id) else {
        return (StatusCode::NOT_FOUND, format!("Unknown flow: {flow_id}")).into_response();
    };

    let dag = navra_flow::DagConfig {
        name: run.name.clone(),
        description: None,
        parameters: std::collections::HashMap::new(),
        tasks: run
            .node_statuses
            .iter()
            .map(|n| navra_flow::TaskDefinition {
                id: n.id.clone(),
                specialist: n.specialist.clone(),
                model: None,
                mandate: n.id.clone(),
                depends_on: run
                    .edges
                    .iter()
                    .filter(|e| e.target == n.id)
                    .map(|e| e.source.clone())
                    .collect(),
                expected_output: None,
                success_criteria: vec![],
                back_edges: vec![],
                generates_tasks: false,
                verification: None,
                tools: None,
                operations: None,
                temperature: None,
                approval_required: false,
            })
            .collect(),
        blackboard_capacity: None,
    };

    let statuses: std::collections::HashMap<String, String> = run
        .node_statuses
        .iter()
        .map(|n| (n.id.clone(), n.status.clone()))
        .collect();

    let xml = navra_flow::bpmn::generate_bpmn(&dag, &statuses);

    (
        [(
            axum::http::header::CONTENT_TYPE,
            "application/xml; charset=utf-8",
        )],
        xml,
    )
        .into_response()
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
        return (StatusCode::SERVICE_UNAVAILABLE, "Event log not configured").into_response();
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
        .route("/flows/{id}/events", axum::routing::get(handle_flow_events))
        .route(
            "/flows/{id}/graph/bpmn",
            axum::routing::get(handle_flow_graph_bpmn),
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
        let ct = resp
            .headers()
            .get("content-type")
            .unwrap()
            .to_str()
            .unwrap();
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
