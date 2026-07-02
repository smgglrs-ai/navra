use axum::{
    Json, Router,
    extract::State,
    http::StatusCode,
    response::IntoResponse,
    routing::{get, post},
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::sync::RwLock;

use crate::registry::ModelRegistry;

#[derive(Clone)]
pub struct ServerState {
    pub registry: Arc<RwLock<ModelRegistry>>,
}

pub fn router(state: ServerState) -> Router {
    Router::new()
        .route("/health", get(health))
        .route("/hardware", get(hardware))
        .route("/v1/models", get(list_models))
        .route("/v1/chat/completions", post(chat_completions))
        .route("/v1/embeddings", post(embeddings))
        .route("/v1/classify", post(classify))
        .with_state(state)
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
    let backend = registry
        .get(&req.model)
        .ok_or_else(|| model_not_found(&req.model))?;

    let request: navra_model::CreateResponseRequest = serde_json::from_value(req.rest)
        .map_err(|e| bad_request(&format!("invalid request: {e}")))?;

    let response = backend
        .respond(&request)
        .await
        .map_err(|e| internal(&format!("inference error: {e}")))?;

    // ModelResponse (navra_responses::Response) derives Serialize
    Ok(Json(response))
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
        .map_err(|e| internal(&format!("embedding error: {e}")))?;

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
        .map_err(|e| internal(&format!("classification error: {e}")))?;

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

#[cfg(test)]
mod tests {
    use super::*;

    async fn test_state() -> ServerState {
        ServerState {
            registry: Arc::new(RwLock::new(
                ModelRegistry::from_config(&std::collections::HashMap::new())
                    .await
                    .unwrap(),
            )),
        }
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
            "messages": [{"role": "user", "content": "hello"}]
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
}
