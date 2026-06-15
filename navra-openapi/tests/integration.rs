use axum::{routing, Json, Router};
use navra_core::Module;
use navra_openapi::auth::AuthConfig;
use navra_openapi::OpenApiModule;
use serde_json::json;
use std::sync::Arc;
use tokio::sync::Mutex;

fn spec_for_port(port: u16) -> String {
    serde_json::to_string(&json!({
        "openapi": "3.0.0",
        "info": { "title": "Test API", "version": "1.0.0" },
        "servers": [{ "url": format!("http://127.0.0.1:{port}") }],
        "paths": {
            "/items": {
                "get": {
                    "operationId": "listItems",
                    "summary": "List items",
                    "parameters": [
                        {
                            "name": "limit",
                            "in": "query",
                            "schema": { "type": "integer" }
                        }
                    ],
                    "responses": { "200": { "description": "OK" } }
                },
                "post": {
                    "operationId": "createItem",
                    "summary": "Create an item",
                    "requestBody": {
                        "content": {
                            "application/json": {
                                "schema": { "type": "object" }
                            }
                        }
                    },
                    "responses": { "201": { "description": "Created" } }
                }
            },
            "/items/{itemId}": {
                "get": {
                    "operationId": "getItem",
                    "summary": "Get an item",
                    "parameters": [
                        {
                            "name": "itemId",
                            "in": "path",
                            "required": true,
                            "schema": { "type": "string" }
                        }
                    ],
                    "responses": { "200": { "description": "OK" } }
                },
                "delete": {
                    "operationId": "deleteItem",
                    "summary": "Delete an item",
                    "parameters": [
                        {
                            "name": "itemId",
                            "in": "path",
                            "required": true,
                            "schema": { "type": "string" }
                        }
                    ],
                    "responses": { "204": { "description": "Deleted" } }
                }
            }
        }
    }))
    .unwrap()
}

async fn start_mock_server() -> (u16, tokio::task::JoinHandle<()>) {
    let requests: Arc<Mutex<Vec<(String, String, String)>>> = Arc::new(Mutex::new(Vec::new()));
    let req_clone = requests.clone();

    let app = Router::new()
        .route(
            "/items",
            routing::get(|| async { Json(json!({"items": [{"id": "1", "name": "cat"}]})) }).post({
                let reqs = req_clone.clone();
                move |body: Json<serde_json::Value>| {
                    let reqs = reqs.clone();
                    async move {
                        reqs.lock().await.push((
                            "POST".into(),
                            "/items".into(),
                            body.0.to_string(),
                        ));
                        (
                            axum::http::StatusCode::CREATED,
                            Json(json!({"id": "2", "name": "dog"})),
                        )
                    }
                }
            }),
        )
        .route(
            "/items/{itemId}",
            routing::get(
                |axum::extract::Path(id): axum::extract::Path<String>| async move {
                    Json(json!({"id": id, "name": "cat"}))
                },
            )
            .delete(
                |axum::extract::Path(id): axum::extract::Path<String>| async move {
                    axum::http::StatusCode::NO_CONTENT
                },
            ),
        );

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();

    let handle = tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });

    // Give server a moment to start
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    (port, handle)
}

#[tokio::test]
async fn openapi_module_lists_tools() {
    let (port, _handle) = start_mock_server().await;
    let spec = spec_for_port(port);
    let tmpfile = std::env::temp_dir().join("navra_openapi_integ.json");
    tokio::fs::write(&tmpfile, &spec).await.unwrap();

    let module = OpenApiModule::from_spec(
        "test_api",
        tmpfile.to_str().unwrap(),
        AuthConfig::default(),
        &[],
    )
    .await
    .unwrap();

    let tools = module.tools();
    assert_eq!(tools.len(), 4);

    let names: Vec<&str> = tools.iter().map(|t| t.0.name.as_str()).collect();
    assert!(names.contains(&"test_api_listitems"));
    assert!(names.contains(&"test_api_createitem"));
    assert!(names.contains(&"test_api_getitem"));
    assert!(names.contains(&"test_api_deleteitem"));

    tokio::fs::remove_file(&tmpfile).await.ok();
}

#[tokio::test]
async fn call_get_tool() {
    let (port, _handle) = start_mock_server().await;
    let spec = spec_for_port(port);
    let tmpfile = std::env::temp_dir().join("navra_openapi_integ_get.json");
    tokio::fs::write(&tmpfile, &spec).await.unwrap();

    let module =
        OpenApiModule::from_spec("api", tmpfile.to_str().unwrap(), AuthConfig::default(), &[])
            .await
            .unwrap();

    let tools = module.tools();
    let (_, handler) = tools
        .iter()
        .find(|(d, _)| d.name == "api_listitems")
        .unwrap();

    let result = handler(json!({}), dummy_ctx()).await;
    assert!(!result.is_error);

    tokio::fs::remove_file(&tmpfile).await.ok();
}

#[tokio::test]
async fn call_get_with_path_param() {
    let (port, _handle) = start_mock_server().await;
    let spec = spec_for_port(port);
    let tmpfile = std::env::temp_dir().join("navra_openapi_integ_path.json");
    tokio::fs::write(&tmpfile, &spec).await.unwrap();

    let module =
        OpenApiModule::from_spec("api", tmpfile.to_str().unwrap(), AuthConfig::default(), &[])
            .await
            .unwrap();

    let tools = module.tools();
    let (_, handler) = tools.iter().find(|(d, _)| d.name == "api_getitem").unwrap();

    let result = handler(json!({"itemId": "42"}), dummy_ctx()).await;
    assert!(!result.is_error);

    tokio::fs::remove_file(&tmpfile).await.ok();
}

#[tokio::test]
async fn call_post_with_body() {
    let (port, _handle) = start_mock_server().await;
    let spec = spec_for_port(port);
    let tmpfile = std::env::temp_dir().join("navra_openapi_integ_post.json");
    tokio::fs::write(&tmpfile, &spec).await.unwrap();

    let module =
        OpenApiModule::from_spec("api", tmpfile.to_str().unwrap(), AuthConfig::default(), &[])
            .await
            .unwrap();

    let tools = module.tools();
    let (_, handler) = tools
        .iter()
        .find(|(d, _)| d.name == "api_createitem")
        .unwrap();

    let result = handler(json!({"body": {"name": "fish"}}), dummy_ctx()).await;
    assert!(!result.is_error);

    tokio::fs::remove_file(&tmpfile).await.ok();
}

#[tokio::test]
async fn missing_path_param_returns_error() {
    let (port, _handle) = start_mock_server().await;
    let spec = spec_for_port(port);
    let tmpfile = std::env::temp_dir().join("navra_openapi_integ_missing.json");
    tokio::fs::write(&tmpfile, &spec).await.unwrap();

    let module =
        OpenApiModule::from_spec("api", tmpfile.to_str().unwrap(), AuthConfig::default(), &[])
            .await
            .unwrap();

    let tools = module.tools();
    let (_, handler) = tools.iter().find(|(d, _)| d.name == "api_getitem").unwrap();

    let result = handler(json!({}), dummy_ctx()).await;
    assert!(result.is_error);

    tokio::fs::remove_file(&tmpfile).await.ok();
}

#[tokio::test]
async fn tool_filter_limits_exposed_tools() {
    let (port, _handle) = start_mock_server().await;
    let spec = spec_for_port(port);
    let tmpfile = std::env::temp_dir().join("navra_openapi_integ_filter.json");
    tokio::fs::write(&tmpfile, &spec).await.unwrap();

    let module = OpenApiModule::from_spec(
        "api",
        tmpfile.to_str().unwrap(),
        AuthConfig::default(),
        &["listItems".to_string(), "getItem".to_string()],
    )
    .await
    .unwrap();

    assert_eq!(module.tool_count(), 2);
    let tools = module.tools();
    let names: Vec<&str> = tools.iter().map(|t| t.0.name.as_str()).collect();
    assert!(names.contains(&"api_listitems"));
    assert!(names.contains(&"api_getitem"));
    assert!(!names.contains(&"api_createitem"));
    assert!(!names.contains(&"api_deleteitem"));

    tokio::fs::remove_file(&tmpfile).await.ok();
}

fn dummy_ctx() -> navra_core::auth::CallContext {
    navra_core::auth::CallContext::new(
        navra_core::auth::AgentIdentity {
            name: "test".to_string(),
            permissions: "default".to_string(),
            signing_key: None,
            did: None,
            capabilities: None,
        },
        "test-session",
    )
}
