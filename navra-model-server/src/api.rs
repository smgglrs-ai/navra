use axum::{
    Json, Router,
    extract::{Request, State},
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
    routing::{get, post},
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::sync::RwLock;

use crate::registry::ModelRegistry;
use crate::router::SessionRouter;

#[derive(Clone)]
pub struct ServerState {
    pub registry: Arc<RwLock<ModelRegistry>>,
    /// Within-session cost router (see `crate::router`).
    pub router: Arc<SessionRouter>,
}

/// Routes that require a token when auth is enabled.
fn core_routes(state: ServerState) -> Router {
    Router::new()
        .route("/hardware", get(hardware))
        .route("/v1/models", get(list_models))
        .route("/v1/chat/completions", post(chat_completions))
        .route("/v1/embeddings", post(embeddings))
        .route("/v1/classify", post(classify))
        .with_state(state)
}

pub fn router(state: ServerState) -> Router {
    Router::new()
        // Unauthenticated health probe (container orchestrators).
        .route("/health", get(health))
        .merge(core_routes(state))
}

/// Router with bearer-token auth on all inference routes.
///
/// `/health` stays open for readiness/liveness probes; everything
/// else requires `Authorization: Bearer <token>`.
pub fn router_with_auth(state: ServerState, token: &str) -> Router {
    Router::new()
        .route("/health", get(health))
        .merge(
            core_routes(state).route_layer(axum::middleware::from_fn_with_state(
                Arc::new(token.to_string()),
                token_auth_middleware,
            )),
        )
}

/// Constant-time byte comparison (CWE-208): no early exit on the
/// first differing byte.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

async fn token_auth_middleware(
    State(expected): State<Arc<String>>,
    headers: HeaderMap,
    request: Request,
    next: axum::middleware::Next,
) -> axum::response::Response {
    let provided = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "));
    let authorized = provided.is_some_and(|p| constant_time_eq(p.as_bytes(), expected.as_bytes()));
    if !authorized {
        return (
            StatusCode::UNAUTHORIZED,
            Json(ApiError {
                error: "unauthorized".to_string(),
            }),
        )
            .into_response();
    }
    next.run(request).await
}

async fn health() -> impl IntoResponse {
    Json(serde_json::json!({"status": "ok"}))
}

async fn hardware() -> impl IntoResponse {
    let summary = crate::hardware::detect(2 * 1024 * 1024 * 1024);
    Json(summary)
}

// --- /v1/models ---

#[derive(Serialize)]
struct ModelListResponse {
    object: &'static str,
    data: Vec<ModelInfo>,
}

#[derive(Serialize)]
struct ModelInfo {
    id: String,
    object: &'static str,
}

async fn list_models(State(state): State<ServerState>) -> impl IntoResponse {
    let registry = state.registry.read().await;
    let data = registry
        .list()
        .into_iter()
        .map(|id| ModelInfo {
            id,
            object: "model",
        })
        .collect();
    Json(ModelListResponse {
        object: "list",
        data,
    })
}

// --- /v1/chat/completions ---

#[derive(Deserialize)]
struct ChatRequest {
    model: String,
    #[serde(flatten)]
    rest: serde_json::Value,
}

async fn chat_completions(
    State(state): State<ServerState>,
    Json(req): Json<ChatRequest>,
) -> Result<impl IntoResponse, (StatusCode, Json<ApiError>)> {
    let registry = state.registry.read().await;

    // Within-session cost routing: decide which model actually serves
    // this request. The client keeps requesting the frontier name; the
    // response `model` field is rewritten back so the client context
    // stays consistent, and the actual backend is exposed via the
    // `x-navra-routed-model` header for auditability.
    let messages: Vec<serde_json::Value> = req
        .rest
        .get("input")
        .or_else(|| req.rest.get("messages"))
        .and_then(|m| m.as_array())
        .cloned()
        .unwrap_or_default();
    let tools_present = req
        .rest
        .get("tools")
        .and_then(|t| t.as_array())
        .is_some_and(|a| !a.is_empty());
    let available = registry.list();
    let decision = state
        .router
        .decide(&req.model, &messages, tools_present, &available);

    if decision.routed {
        tracing::info!(
            from = %req.model,
            to = %decision.model,
            reason = decision.reason,
            "Within-session model routing"
        );
    }

    let backend = registry
        .get(&decision.model)
        .ok_or_else(|| model_not_found(&req.model))?;

    // The flattened `rest` no longer carries `model` (captured above),
    // so re-inject the routed model name before deserializing.
    let mut request_value = req.rest;
    request_value["model"] = serde_json::json!(decision.model);
    let request: navra_model::CreateResponseRequest = serde_json::from_value(request_value)
        .map_err(|e| bad_request(&format!("invalid request: {e}")))?;

    let mut response = backend
        .respond(&request)
        .await
        .map_err(|e| internal_inference("chat completion", &e))?;

    // Transparency: the client sees the model it requested; the
    // header carries what actually served the request.
    response.model = Some(req.model.clone());
    let headers = [(
        axum::http::HeaderName::from_static("x-navra-routed-model"),
        decision.model,
    )];
    Ok((headers, Json(response)))
}

// --- /v1/embeddings ---

#[derive(Deserialize)]
struct EmbedApiRequest {
    model: String,
    input: String,
}

#[derive(Serialize)]
struct EmbedApiResponse {
    object: &'static str,
    data: Vec<EmbedApiData>,
}

#[derive(Serialize)]
struct EmbedApiData {
    object: &'static str,
    embedding: Vec<f32>,
    index: usize,
}

async fn embeddings(
    State(state): State<ServerState>,
    Json(req): Json<EmbedApiRequest>,
) -> Result<impl IntoResponse, (StatusCode, Json<ApiError>)> {
    let registry = state.registry.read().await;
    let backend = registry
        .get(&req.model)
        .ok_or_else(|| model_not_found(&req.model))?;

    let embed_req = navra_model::EmbedRequest { text: req.input };
    let response = backend
        .embed(&embed_req)
        .await
        .map_err(|e| internal_inference("embedding", &e))?;

    Ok(Json(EmbedApiResponse {
        object: "list",
        data: vec![EmbedApiData {
            object: "embedding",
            embedding: response.embedding,
            index: 0,
        }],
    }))
}

// --- /v1/classify ---

#[derive(Deserialize)]
struct ClassifyApiRequest {
    model: String,
    text: String,
}

#[derive(Serialize)]
struct ClassifyApiResponse {
    labels: Vec<ClassifyApiLabel>,
}

#[derive(Serialize)]
struct ClassifyApiLabel {
    label: String,
    score: f32,
}

async fn classify(
    State(state): State<ServerState>,
    Json(req): Json<ClassifyApiRequest>,
) -> Result<impl IntoResponse, (StatusCode, Json<ApiError>)> {
    let registry = state.registry.read().await;
    let backend = registry
        .get(&req.model)
        .ok_or_else(|| model_not_found(&req.model))?;

    let classify_req = navra_model::ClassifyRequest { text: req.text };
    let response = backend
        .classify(&classify_req)
        .await
        .map_err(|e| internal_inference("classification", &e))?;

    Ok(Json(ClassifyApiResponse {
        labels: response
            .labels
            .into_iter()
            .map(|l| ClassifyApiLabel {
                label: l.label,
                score: l.score,
            })
            .collect(),
    }))
}

// --- Error helpers ---

#[derive(Serialize)]
pub struct ApiError {
    error: String,
}

fn model_not_found(model: &str) -> (StatusCode, Json<ApiError>) {
    (
        StatusCode::NOT_FOUND,
        Json(ApiError {
            error: format!("model '{model}' not loaded"),
        }),
    )
}

fn bad_request(msg: &str) -> (StatusCode, Json<ApiError>) {
    (
        StatusCode::BAD_REQUEST,
        Json(ApiError {
            error: msg.to_string(),
        }),
    )
}

fn internal(msg: &str) -> (StatusCode, Json<ApiError>) {
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        Json(ApiError {
            error: msg.to_string(),
        }),
    )
}

/// Internal error from a model backend: log the full error
/// server-side, return only a generic message to the client.
///
/// Backend errors can embed upstream URLs, API keys in malformed
/// request errors, or local file paths — none of which belong in a
/// client-visible response body.
fn internal_inference(stage: &str, e: &navra_model::ModelError) -> (StatusCode, Json<ApiError>) {
    tracing::error!(stage, error = %e, "Model backend inference failure");
    internal("internal model error")
}

#[cfg(test)]
mod tests {
    use super::*;
    use navra_model::{CreateResponseRequest, ModelBackend, ModelError, ModelResponse};
    use std::future::Future;
    use std::pin::Pin;

    async fn test_state() -> ServerState {
        ServerState {
            registry: Arc::new(RwLock::new(
                ModelRegistry::from_config(&std::collections::HashMap::new())
                    .await
                    .unwrap(),
            )),
            router: Arc::new(SessionRouter::new(crate::router::RoutingConfig::default())),
        }
    }

    /// A backend that reports the model name it was registered under.
    struct EchoBackend(String);

    impl ModelBackend for EchoBackend {
        fn respond(
            &self,
            _request: &CreateResponseRequest,
        ) -> Pin<Box<dyn Future<Output = Result<ModelResponse, ModelError>> + Send + '_>> {
            Box::pin(async {
                Ok(ModelResponse {
                    id: "resp_test".into(),
                    object: "response".into(),
                    created_at: None,
                    completed_at: None,
                    status: navra_model::ResponseStatus::Completed,
                    model: Some(self.0.clone()),
                    output: vec![],
                    usage: None,
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
                    metadata: std::collections::HashMap::new(),
                    incomplete_details: None,
                    extra: std::collections::HashMap::new(),
                })
            })
        }
    }

    async fn routed_state(config: crate::router::RoutingConfig) -> ServerState {
        let mut registry = ModelRegistry::from_config(&std::collections::HashMap::new())
            .await
            .unwrap();
        registry.insert("frontier", Arc::new(EchoBackend("frontier".into())));
        registry.insert("cheap", Arc::new(EchoBackend("cheap".into())));
        ServerState {
            registry: Arc::new(RwLock::new(registry)),
            router: Arc::new(SessionRouter::new(config)),
        }
    }

    fn routing_config() -> crate::router::RoutingConfig {
        crate::router::RoutingConfig {
            enabled: true,
            rules: vec![crate::router::RoutingRule {
                from: "frontier".to_string(),
                to: "cheap".to_string(),
                switch_only_at_compaction: false,
            }],
            min_messages: 2,
        }
    }

    async fn post_chat(app: axum::Router, body: serde_json::Value) -> axum::response::Response {
        let req = axum::http::Request::builder()
            .method("POST")
            .uri("/v1/chat/completions")
            .header("content-type", "application/json")
            .body(axum::body::Body::from(serde_json::to_vec(&body).unwrap()))
            .unwrap();
        tower::ServiceExt::oneshot(app, req).await.unwrap()
    }

    #[tokio::test]
    async fn health_endpoint() {
        let app = router(test_state().await);
        let req = axum::http::Request::builder()
            .uri("/health")
            .body(axum::body::Body::empty())
            .unwrap();
        let resp = tower::ServiceExt::oneshot(app, req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn list_models_empty() {
        let app = router(test_state().await);
        let req = axum::http::Request::builder()
            .uri("/v1/models")
            .body(axum::body::Body::empty())
            .unwrap();
        let resp = tower::ServiceExt::oneshot(app, req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn chat_completions_model_not_found() {
        let app = router(test_state().await);
        let body = serde_json::json!({
            "model": "nonexistent",
            "messages": [{"type": "message", "role": "user", "content": "hello"}]
        });
        let req = axum::http::Request::builder()
            .method("POST")
            .uri("/v1/chat/completions")
            .header("content-type", "application/json")
            .body(axum::body::Body::from(serde_json::to_vec(&body).unwrap()))
            .unwrap();
        let resp = tower::ServiceExt::oneshot(app, req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn chat_completions_routes_simple_session_to_cheap_model() {
        let app = router(routed_state(routing_config()).await);
        let resp = post_chat(
            app,
            serde_json::json!({
                "model": "frontier",
                "input": [
                    {"type": "message", "role": "user", "content": "hello"},
                    {"type": "message", "role": "user", "content": "thanks"}
                ]
            }),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(
            resp.headers()
                .get("x-navra-routed-model")
                .and_then(|v| v.to_str().ok()),
            Some("cheap")
        );
        let bytes = http_body_util::BodyExt::collect(resp.into_body())
            .await
            .unwrap()
            .to_bytes();
        let body: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        // Transparency: the client sees the model it requested.
        assert_eq!(body["model"], "frontier");
    }

    #[tokio::test]
    async fn chat_completions_keeps_frontier_for_complex_turns() {
        let app = router(routed_state(routing_config()).await);
        let resp = post_chat(
            app,
            serde_json::json!({
                "model": "frontier",
                "input": [
                    {"type": "message", "role": "user", "content": "hello"},
                    {"type": "message", "role": "user", "content": "review this architecture"}
                ]
            }),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(
            resp.headers()
                .get("x-navra-routed-model")
                .and_then(|v| v.to_str().ok()),
            Some("frontier")
        );
    }

    #[tokio::test]
    async fn chat_completions_passthrough_without_rules() {
        let app = router(routed_state(crate::router::RoutingConfig::default()).await);
        let resp = post_chat(
            app,
            serde_json::json!({
                "model": "frontier",
                "input": [
                    {"type": "message", "role": "user", "content": "hello"},
                    {"type": "message", "role": "user", "content": "thanks"}
                ]
            }),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(
            resp.headers()
                .get("x-navra-routed-model")
                .and_then(|v| v.to_str().ok()),
            Some("frontier")
        );
    }

    #[tokio::test]
    async fn chat_completions_tools_keep_frontier_model() {
        let app = router(routed_state(routing_config()).await);
        let resp = post_chat(
            app,
            serde_json::json!({
                "model": "frontier",
                "tools": [{"type": "function", "name": "f", "parameters": {"type": "object"}}],
                "input": [
                    {"type": "message", "role": "user", "content": "hello"},
                    {"type": "message", "role": "user", "content": "run the tool"}
                ]
            }),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(
            resp.headers()
                .get("x-navra-routed-model")
                .and_then(|v| v.to_str().ok()),
            Some("frontier")
        );
    }

    #[tokio::test]
    async fn embeddings_model_not_found() {
        let app = router(test_state().await);
        let body = serde_json::json!({"model": "nonexistent", "input": "test"});
        let req = axum::http::Request::builder()
            .method("POST")
            .uri("/v1/embeddings")
            .header("content-type", "application/json")
            .body(axum::body::Body::from(serde_json::to_vec(&body).unwrap()))
            .unwrap();
        let resp = tower::ServiceExt::oneshot(app, req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn classify_model_not_found() {
        let app = router(test_state().await);
        let body = serde_json::json!({"model": "nonexistent", "text": "test"});
        let req = axum::http::Request::builder()
            .method("POST")
            .uri("/v1/classify")
            .header("content-type", "application/json")
            .body(axum::body::Body::from(serde_json::to_vec(&body).unwrap()))
            .unwrap();
        let resp = tower::ServiceExt::oneshot(app, req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    /// A backend that always fails with a detail-rich error, to
    /// verify the client only sees a generic message.
    struct FailingBackend;

    impl ModelBackend for FailingBackend {
        fn respond(
            &self,
            _request: &CreateResponseRequest,
        ) -> Pin<Box<dyn Future<Output = Result<ModelResponse, ModelError>> + Send + '_>> {
            Box::pin(async {
                Err(ModelError::Inference(
                    "upstream http://10.0.0.5:8080/v1 with key sk-super-secret failed".into(),
                ))
            })
        }
    }

    async fn failing_state() -> ServerState {
        let mut registry = ModelRegistry::from_config(&std::collections::HashMap::new())
            .await
            .unwrap();
        registry.insert("broken", Arc::new(FailingBackend));
        ServerState {
            registry: Arc::new(RwLock::new(registry)),
            router: Arc::new(SessionRouter::new(crate::router::RoutingConfig::default())),
        }
    }

    #[tokio::test]
    async fn inference_error_response_is_generic() {
        let app = router(failing_state().await);
        let resp = post_chat(
            app,
            serde_json::json!({
                "model": "broken",
                "input": [{"type": "message", "role": "user", "content": "hello"}]
            }),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);
        let bytes = http_body_util::BodyExt::collect(resp.into_body())
            .await
            .unwrap()
            .to_bytes();
        let body: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        let msg = body["error"].as_str().unwrap();
        assert_eq!(msg, "internal model error");
        assert!(
            !msg.contains("sk-super-secret") && !msg.contains("10.0.0.5"),
            "internal details must not leak: {msg}"
        );
    }

    // --- Token auth ---

    async fn get_status(app: axum::Router, uri: &str, token: Option<&str>) -> StatusCode {
        let mut builder = axum::http::Request::builder().uri(uri);
        if let Some(t) = token {
            builder = builder.header("authorization", format!("Bearer {t}"));
        }
        let resp =
            tower::ServiceExt::oneshot(app, builder.body(axum::body::Body::empty()).unwrap())
                .await
                .unwrap();
        resp.status()
    }

    #[tokio::test]
    async fn auth_rejects_missing_token() {
        let app = router_with_auth(test_state().await, "sekrit");
        assert_eq!(
            get_status(app, "/v1/models", None).await,
            StatusCode::UNAUTHORIZED
        );
    }

    #[tokio::test]
    async fn auth_rejects_wrong_token() {
        let app = router_with_auth(test_state().await, "sekrit");
        assert_eq!(
            get_status(app, "/v1/models", Some("wrong")).await,
            StatusCode::UNAUTHORIZED
        );
    }

    #[tokio::test]
    async fn auth_accepts_valid_token() {
        let app = router_with_auth(test_state().await, "sekrit");
        assert_eq!(
            get_status(app, "/v1/models", Some("sekrit")).await,
            StatusCode::OK
        );
    }

    #[tokio::test]
    async fn auth_keeps_health_open() {
        let app = router_with_auth(test_state().await, "sekrit");
        assert_eq!(get_status(app, "/health", None).await, StatusCode::OK);
    }

    #[test]
    fn constant_time_compare() {
        assert!(constant_time_eq(b"abc", b"abc"));
        assert!(!constant_time_eq(b"abc", b"abd"));
        assert!(!constant_time_eq(b"abc", b"abcd"));
        assert!(constant_time_eq(b"", b""));
    }
}
