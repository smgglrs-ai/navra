use std::sync::Arc;

use crate::config;
use crate::expand_tilde;

/// Build the web UI routes and attach them to the given router.
///
/// This adds static asset routes (`/`, `/ui/style.css`, `/ui/app.js`)
/// and authenticated API routes (`/api/status`, `/api/models`, `/api/agents`,
/// `/api/flows`, `/api/chat`).
pub(crate) fn attach_ui_routes(
    router: axum::Router,
    cfg: &config::Config,
    server: &Arc<myelix_core::McpServer>,
    models: &std::collections::HashMap<String, Arc<dyn myelix_model::ModelBackend>>,
) -> axum::Router {
    // Load cognitive core if configured
    let forge = if let Some(ref path) = cfg.cognitive_core {
        let expanded = expand_tilde(path);
        match myelix_cognitive::ForgeService::load(std::path::Path::new(&expanded)) {
            Ok(f) => {
                tracing::info!(
                    personas = f.persona_count(),
                    heuristics = f.heuristic_count(),
                    "Cognitive core loaded for UI"
                );
                Arc::new(f)
            }
            Err(e) => {
                tracing::warn!("Cognitive core load failed: {e}");
                Arc::new(myelix_cognitive::ForgeService::empty())
            }
        }
    } else {
        Arc::new(myelix_cognitive::ForgeService::empty())
    };

    // Scan flow directories
    let mut flow_files: Vec<(String, std::path::PathBuf)> = Vec::new();
    for dir in &cfg.flow_dirs {
        let expanded = expand_tilde(dir);
        let path = std::path::Path::new(&expanded);
        if let Ok(entries) = std::fs::read_dir(path) {
            for entry in entries.flatten() {
                let p = entry.path();
                if p.extension().map(|e| e == "toml").unwrap_or(false) {
                    let name = p.file_stem()
                        .map(|s| s.to_string_lossy().to_string())
                        .unwrap_or_default();
                    flow_files.push((name, p));
                }
            }
        }
    }

    // Build model info from config
    let model_info: Vec<serde_json::Value> = cfg.models.iter().map(|(name, mcfg)| {
        let backend = if mcfg.source.is_some() {
            "managed"
        } else if mcfg.task == "embedding" || mcfg.task == "classification" {
            "onnx"
        } else {
            "external"
        };
        serde_json::json!({
            "name": name,
            "task": mcfg.task,
            "backend": backend,
            "source": mcfg.source,
            "runtime": mcfg.runtime,
            "context_size": mcfg.context_size,
        })
    }).collect();

    // Build agent info from config
    let agent_info: Vec<serde_json::Value> = cfg.agents.iter().map(|a| {
        let pset = cfg.permissions.get(&a.permissions);
        serde_json::json!({
            "name": a.name,
            "permissions": a.permissions,
            "ring": pset.and_then(|p| p.ring),
            "capability_token": a.capability_token,
            "did": a.did,
            "safety": pset.map(|p| &p.safety),
            "operations": pset.map(|p| &p.operations),
            "taint": "Trusted",
        })
    }).collect();

    // Persona list for the chat selector
    let persona_names: Vec<String> = forge.persona_names().iter().map(|s| s.to_string()).collect();

    // Chat model: pick first chat/generate model, or empty
    let chat_model_name = cfg.models.iter()
        .find(|(_, m)| m.task == "chat" || m.task == "generate")
        .map(|(name, _)| name.clone());
    let chat_backend: Option<Arc<dyn myelix_model::ModelBackend>> = chat_model_name
        .as_ref()
        .and_then(|name| models.get(name))
        .cloned();

    // Shared state for all UI handlers
    let ui_models = Arc::new(model_info);
    let ui_agents = Arc::new(agent_info);
    let ui_personas = Arc::new(persona_names);
    let ui_forge = forge.clone();
    let ui_chat_backend = chat_backend;
    let ui_flows = Arc::new(flow_files);

    router
        // --- Static assets ---
        .route("/", axum::routing::get(|| async {
            ([("content-type", "text/html")], include_str!("../ui/index.html"))
        }))
        .route("/ui/style.css", axum::routing::get(|| async {
            ([("content-type", "text/css")], include_str!("../ui/style.css"))
        }))
        .route("/ui/app.js", axum::routing::get(|| async {
            ([("content-type", "application/javascript")], include_str!("../ui/app.js"))
        }))

        // --- API: Server status (authenticated) ---
        .route("/api/status", {
            let models = ui_models.clone();
            let personas = ui_personas.clone();
            let api_server = Arc::clone(server);
            axum::routing::get(move |headers: axum::http::HeaderMap| {
                let models = models.clone();
                let personas = personas.clone();
                let api_server = Arc::clone(&api_server);
                async move {
                    if api_server.authenticator().authenticate(&headers).is_err() {
                        return axum::Json(serde_json::json!({"error": "unauthorized"}));
                    }
                    let model_names: Vec<&str> = models.iter()
                        .filter_map(|m| m["name"].as_str())
                        .collect();
                    axum::Json(serde_json::json!({
                        "name": "mcpd",
                        "version": env!("CARGO_PKG_VERSION"),
                        "status": "running",
                        "models": model_names,
                        "personas": *personas,
                        "crates": 17,
                    }))
                }
            })
        })

        // --- API: Models (authenticated) ---
        .route("/api/models", {
            let models = ui_models.clone();
            let api_server = Arc::clone(server);
            axum::routing::get(move |headers: axum::http::HeaderMap| {
                let models = models.clone();
                let api_server = Arc::clone(&api_server);
                async move {
                    if api_server.authenticator().authenticate(&headers).is_err() {
                        return axum::Json(serde_json::json!({"error": "unauthorized"}));
                    }
                    axum::Json(serde_json::json!(*models))
                }
            })
        })

        // --- API: Agents (authenticated) ---
        .route("/api/agents", {
            let agents = ui_agents.clone();
            let api_server = Arc::clone(server);
            axum::routing::get(move |headers: axum::http::HeaderMap| {
                let agents = agents.clone();
                let api_server = Arc::clone(&api_server);
                async move {
                    if api_server.authenticator().authenticate(&headers).is_err() {
                        return axum::Json(serde_json::json!({"error": "unauthorized"}));
                    }
                    axum::Json(serde_json::json!(*agents))
                }
            })
        })

        // --- API: Flows (authenticated) ---
        .route("/api/flows", {
            let flows = ui_flows.clone();
            let api_server = Arc::clone(server);
            axum::routing::get(move |headers: axum::http::HeaderMap| {
                let flows = flows.clone();
                let api_server = Arc::clone(&api_server);
                async move {
                    if api_server.authenticator().authenticate(&headers).is_err() {
                        return axum::Json(serde_json::json!({"error": "unauthorized"}));
                    }
                    let list: Vec<serde_json::Value> = flows.iter().map(|(name, path)| {
                        // Try to read the flow TOML for task count
                        let tasks = std::fs::read_to_string(path)
                            .ok()
                            .and_then(|content| {
                                let val: toml::Value = toml::from_str(&content).ok()?;
                                val.get("tasks")?.as_array().map(|a| a.len())
                            })
                            .unwrap_or(0);
                        serde_json::json!({
                            "name": name,
                            "path": path.display().to_string(),
                            "tasks": tasks,
                        })
                    }).collect();
                    axum::Json(serde_json::json!(list))
                }
            })
        })

        // --- API: Chat (authenticated, streaming) ---
        .route("/api/chat", {
            let backend = ui_chat_backend.clone();
            let forge = ui_forge.clone();
            let api_server = Arc::clone(server);
            axum::routing::post(move |headers: axum::http::HeaderMap, body: axum::Json<serde_json::Value>| {
                let backend = backend.clone();
                let forge = forge.clone();
                let api_server = Arc::clone(&api_server);
                async move {
                    if api_server.authenticator().authenticate(&headers).is_err() {
                        return axum::Json(serde_json::json!({"error": "unauthorized"})).into_response();
                    }
                    use axum::response::IntoResponse;

                    let prompt = body["prompt"].as_str().unwrap_or("").to_string();
                    let persona = body["persona"].as_str().unwrap_or("").to_string();

                    if prompt.is_empty() {
                        return (
                            axum::http::StatusCode::BAD_REQUEST,
                            "prompt is required",
                        ).into_response();
                    }

                    let Some(backend) = backend else {
                        return (
                            axum::http::StatusCode::SERVICE_UNAVAILABLE,
                            "no chat model loaded",
                        ).into_response();
                    };

                    // Assemble prompt with Weaver if persona is set
                    let system_prompt = if !persona.is_empty() {
                        myelix_cognitive::assemble(&forge, &persona, &prompt, None, None)
                            .map(|w| w.system_prompt())
                            .unwrap_or_default()
                    } else {
                        String::new()
                    };

                    let mut input = Vec::new();
                    if !system_prompt.is_empty() {
                        input.push(myelix_model::InputItem::system(&system_prompt));
                    }
                    input.push(myelix_model::InputItem::user(&prompt));

                    let request = myelix_model::CreateResponseRequest::new(
                        String::new(),
                        input,
                    );

                    // Call model
                    match backend.respond(&request).await {
                        Ok(response) => {
                            let text = response.text().unwrap_or_default();
                            let usage = response.usage.as_ref();
                            let ndjson = format!(
                                "{}\n{}\n",
                                serde_json::json!({"type": "text", "content": text}),
                                serde_json::json!({
                                    "type": "done",
                                    "usage": {
                                        "input_tokens": usage.map(|u| u.input_tokens).unwrap_or(0),
                                        "output_tokens": usage.map(|u| u.output_tokens).unwrap_or(0),
                                    }
                                }),
                            );
                            (
                                [("content-type", "application/x-ndjson")],
                                ndjson,
                            ).into_response()
                        }
                        Err(e) => {
                            (
                                axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                                format!("model error: {e}"),
                            ).into_response()
                        }
                    }
                }
            })
        })
}
