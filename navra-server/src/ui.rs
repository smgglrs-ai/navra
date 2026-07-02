use std::sync::Arc;

use axum::response::IntoResponse;

use crate::config;
use crate::expand_tilde;
use crate::ui_events::UiBroadcaster;

#[path = "ui_assets_gen.rs"]
mod ui_assets_gen;
use ui_assets_gen::UI_DIST_AVAILABLE;

/// Cached Google OAuth token from Application Default Credentials.
/// Refreshes automatically when the token is within 60s of expiry.
struct GcpTokenCache {
    client_id: String,
    client_secret: String,
    refresh_token: String,
    state: tokio::sync::Mutex<(String, std::time::Instant)>,
}

impl GcpTokenCache {
    fn from_adc() -> Option<Arc<Self>> {
        let path = dirs::config_dir()?.join("gcloud/application_default_credentials.json");
        let data = std::fs::read_to_string(path).ok()?;
        let json: serde_json::Value = serde_json::from_str(&data).ok()?;
        Some(Arc::new(Self {
            client_id: json["client_id"].as_str()?.to_string(),
            client_secret: json["client_secret"].as_str()?.to_string(),
            refresh_token: json["refresh_token"].as_str()?.to_string(),
            state: tokio::sync::Mutex::new((String::new(), std::time::Instant::now())),
        }))
    }

    async fn token(&self) -> Result<String, String> {
        let mut state = self.state.lock().await;
        if !state.0.is_empty() && state.1 > std::time::Instant::now() {
            return Ok(state.0.clone());
        }
        let client = reqwest::Client::new();
        let form_body = format!(
            "client_id={}&client_secret={}&refresh_token={}&grant_type=refresh_token",
            urlencoding::encode(&self.client_id),
            urlencoding::encode(&self.client_secret),
            urlencoding::encode(&self.refresh_token),
        );
        let resp = client
            .post("https://oauth2.googleapis.com/token")
            .header("content-type", "application/x-www-form-urlencoded")
            .body(form_body)
            .send()
            .await
            .map_err(|e| format!("OAuth token refresh failed: {e}"))?;
        let json: serde_json::Value = resp
            .json()
            .await
            .map_err(|e| format!("OAuth token parse failed: {e}"))?;
        let token = json["access_token"]
            .as_str()
            .ok_or_else(|| {
                let err = json["error_description"]
                    .as_str()
                    .unwrap_or("unknown error");
                format!("OAuth token refresh error: {err}")
            })?
            .to_string();
        let expires_in = json["expires_in"].as_u64().unwrap_or(3600);
        let expiry = std::time::Instant::now()
            + std::time::Duration::from_secs(expires_in.saturating_sub(60));
        *state = (token.clone(), expiry);
        Ok(token)
    }
}

/// Axum middleware that authenticates requests against the MCP server's
/// authenticator. Applied as a route layer on all `/api/*` routes.
async fn auth_middleware(
    axum::extract::State(server): axum::extract::State<Arc<navra_core::McpServer>>,
    headers: axum::http::HeaderMap,
    request: axum::extract::Request,
    next: axum::middleware::Next,
) -> axum::response::Response {
    if server.authenticator().authenticate(&headers).is_err() {
        return (
            axum::http::StatusCode::UNAUTHORIZED,
            axum::Json(serde_json::json!({"error": "unauthorized"})),
        )
            .into_response();
    }
    next.run(request).await
}

/// Build the web UI routes and attach them to the given router.
///
/// This adds static asset routes (`/`, `/ui/style.css`, `/ui/app.js`)
/// and authenticated API routes (`/api/status`, `/api/models`, `/api/agents`,
/// `/api/flows`, `/api/chat`).
pub(crate) fn attach_ui_routes(
    router: axum::Router,
    cfg: &config::Config,
    server: &Arc<navra_core::McpServer>,
    models: &std::collections::HashMap<String, Arc<dyn navra_model::ModelBackend>>,
    ollama_fallback_model: Option<&str>,
    ui_broadcaster: Option<Arc<UiBroadcaster>>,
    context_retriever: Option<Arc<dyn navra_agent::ContextRetriever>>,
) -> axum::Router {
    // Load cognitive core if configured
    let forge = if let Some(ref path) = cfg.cognitive_core {
        let expanded = expand_tilde(path);
        match navra_cognitive::ForgeService::load(std::path::Path::new(&expanded)) {
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
                Arc::new(navra_cognitive::ForgeService::empty())
            }
        }
    } else {
        Arc::new(navra_cognitive::ForgeService::empty())
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
                    let name = p
                        .file_stem()
                        .map(|s| s.to_string_lossy().to_string())
                        .unwrap_or_default();
                    flow_files.push((name, p));
                }
            }
        }
    }

    // Build model info from config
    let model_info: Vec<serde_json::Value> = cfg
        .models
        .iter()
        .map(|(name, mcfg)| {
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
        })
        .collect();

    // Build agent info from config
    let agent_info: Vec<serde_json::Value> = cfg
        .agents
        .iter()
        .map(|a| {
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
        })
        .collect();

    // Persona list for the chat selector
    let persona_names: Vec<String> = forge
        .persona_names()
        .iter()
        .map(|s| s.to_string())
        .collect();

    // Chat model: pick first chat/generate model, or empty
    let chat_backend: Option<Arc<dyn navra_model::ModelBackend>> = {
        // Try config-defined chat model first
        let from_config = cfg
            .models
            .iter()
            .find(|(_, m)| m.task == "chat" || m.task == "generate")
            .map(|(name, _)| name.clone())
            .and_then(|name| models.get(&name))
            .cloned();

        // Fall back to Ollama if no config-defined model
        from_config.or_else(|| {
            let model_name = ollama_fallback_model?;
            Some(Arc::new(navra_model::OpenAiBackend::new(
                "http://localhost:11434/v1",
                model_name,
                None,
                navra_model::Locality::Local,
            )) as Arc<dyn navra_model::ModelBackend>)
        })
    };

    // Shared state for all UI handlers
    let ui_models = Arc::new(model_info);
    let ui_agents = Arc::new(agent_info);
    let ui_personas = Arc::new(persona_names);
    let ui_forge = forge.clone();
    let ui_chat_backend = chat_backend;
    let ui_flows = Arc::new(flow_files);

    // Build the API router with auth middleware applied to all routes
    let api_router = axum::Router::new()
        // --- API: Server status ---
        .route("/status", {
            let models = ui_models.clone();
            let personas = ui_personas.clone();
            axum::routing::get(move || {
                let models = models.clone();
                let personas = personas.clone();
                async move {
                    let model_names: Vec<&str> = models.iter()
                        .filter_map(|m| m["name"].as_str())
                        .collect();
                    axum::Json(serde_json::json!({
                        "name": "navra",
                        "version": env!("CARGO_PKG_VERSION"),
                        "status": "running",
                        "models": model_names,
                        "personas": *personas,
                        "crates": 17,
                    }))
                }
            })
        })

        // --- API: Models ---
        .route("/models", {
            let models = ui_models.clone();
            axum::routing::get(move || {
                let models = models.clone();
                async move {
                    axum::Json(serde_json::json!(*models))
                }
            })
        })

        // --- API: Agents ---
        .route("/agents", {
            let agents = ui_agents.clone();
            axum::routing::get(move || {
                let agents = agents.clone();
                async move {
                    axum::Json(serde_json::json!(*agents))
                }
            })
        })

        // --- API: Flows ---
        .route("/flows", {
            let flows = ui_flows.clone();
            axum::routing::get(move || {
                let flows = flows.clone();
                async move {
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

        // --- API: Chat (streaming) ---
        .route("/chat", {
            let backend = ui_chat_backend.clone();
            let forge = ui_forge.clone();
            axum::routing::post(move |body: axum::Json<serde_json::Value>| {
                let backend = backend.clone();
                let forge = forge.clone();
                async move {
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
                        navra_cognitive::assemble(&forge, &persona, &prompt, None, None)
                            .map(|w| w.system_prompt())
                            .unwrap_or_default()
                    } else {
                        String::new()
                    };

                    let mut input = Vec::new();
                    if !system_prompt.is_empty() {
                        input.push(navra_model::InputItem::system(&system_prompt));
                    }
                    input.push(navra_model::InputItem::user(&prompt));

                    let request = navra_model::CreateResponseRequest::new(
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

        // --- API: Process table (active sessions) ---
        .route("/process", {
            let server = Arc::clone(server);
            axum::routing::get(move || {
                let server = server.clone();
                async move {
                    let snapshots = server.process_table().snapshot();
                    axum::Json(serde_json::json!(snapshots))
                }
            })
        })

        // --- API: Audit log (blackbox entries with pagination) ---
        .route("/audit", {
            let server = Arc::clone(server);
            axum::routing::get(move |query: axum::extract::Query<std::collections::HashMap<String, String>>| {
                let server = server.clone();
                async move {
                    let limit: usize = query.get("limit").and_then(|s| s.parse().ok()).unwrap_or(50);
                    let offset: usize = query.get("offset").and_then(|s| s.parse().ok()).unwrap_or(0);
                    let agent = query.get("agent").map(|s| s.as_str());
                    let tool = query.get("tool").map(|s| s.as_str());

                    if let Some(bb) = server.blackbox() {
                        let (entries, total) = bb.query(limit, offset, agent, tool);
                        axum::Json(serde_json::json!({
                            "entries": entries,
                            "total": total,
                        }))
                    } else {
                        axum::Json(serde_json::json!({
                            "entries": [],
                            "total": 0,
                        }))
                    }
                }
            })
        })

        // --- API: Permissions ---
        .route("/permissions", {
            let permissions = cfg.permissions.clone();
            axum::routing::get(move || {
                let permissions = permissions.clone();
                async move {
                    let sets: serde_json::Map<String, serde_json::Value> = permissions.iter().map(|(name, pset)| {
                        (name.clone(), serde_json::json!({
                            "ring": pset.ring,
                            "allow": pset.allow,
                            "deny": pset.deny,
                            "operations": pset.operations,
                            "safety": pset.safety,
                            "tool_rules": pset.tool_rules.iter().map(|r| {
                                serde_json::json!({
                                    "tool": r.tool,
                                    "policy": r.policy,
                                })
                            }).collect::<Vec<_>>(),
                        }))
                    }).collect();
                    axum::Json(serde_json::json!({ "permission_sets": sets }))
                }
            })
        })

        .route_layer(axum::middleware::from_fn_with_state(
            Arc::clone(server),
            auth_middleware,
        ));

    // --- Agentic chat routes (ReAct tool-use loop) ---
    let agent_api_router = if let Some(ref backend) = ui_chat_backend {
        let memory_db = navra_memory::WorkingMemory::open(
            &dirs::data_dir()
                .unwrap_or_else(|| std::path::PathBuf::from("/tmp"))
                .join("navra/ui_chat.db"),
        )
        .unwrap_or_else(|e| {
            tracing::warn!("Failed to open UI chat memory: {e}, using in-memory");
            navra_memory::WorkingMemory::open_memory().expect("in-memory WorkingMemory")
        });
        let memory = Arc::new(crate::ui_agent::SharedMemory::new(memory_db));

        let agent_state = Arc::new(crate::ui_agent::AgentChatState {
            server: Arc::clone(server),
            model: Arc::clone(backend),
            forge: forge.clone(),
            memory,
            _listen_addr: cfg.server.listen_addr(),
            context_retriever: context_retriever.clone(),
        });
        Some(
            crate::ui_agent::build_agent_routes(agent_state).route_layer(
                axum::middleware::from_fn_with_state(Arc::clone(server), auth_middleware),
            ),
        )
    } else {
        None
    };

    // --- OpenAI-compatible model proxy ---
    // Agents and external clients (Goose, etc.) use http://localhost:9315/v1
    // as their model endpoint. All requests go through safety filters, blackbox
    // audit, and persona injection.
    let proxy_backend = ui_chat_backend.clone();
    let proxy_server = Arc::clone(server);
    let proxy_forge = ui_forge.clone();
    let proxy_model_entries = cfg.models.clone();
    let proxy_models: std::collections::HashMap<String, Arc<dyn navra_model::ModelBackend>> =
        models.clone();
    let proxy_gcp_tokens: Option<Arc<GcpTokenCache>> = GcpTokenCache::from_adc();
    let v1_router = axum::Router::new()
        .route(
            "/chat/completions",
            axum::routing::post(
                move |headers: axum::http::HeaderMap, body: axum::Json<serde_json::Value>| {
                    let model_entries = proxy_model_entries.clone();
                    let _all_models = proxy_models.clone();
                    let backend = proxy_backend.clone();
                    let forge = proxy_forge.clone();
                    let srv = proxy_server.clone();
                    let gcp = proxy_gcp_tokens.clone();
                    async move {
                        let start = std::time::Instant::now();
                        let Some(_backend) = backend else {
                            return axum::Json(serde_json::json!({
                                "error": {"message": "no model configured", "type": "server_error"}
                            }))
                            .into_response();
                        };

                        // Identify the caller for safety/audit
                        let agent = srv.authenticator().authenticate(&headers).ok();
                        let agent_name = agent.as_ref().map(|a| a.name.as_str()).unwrap_or("anonymous");
                        let permissions = agent.as_ref().map(|a| a.permissions.as_str()).unwrap_or("dev");

                        // Concurrency limit for model requests (same semaphore as tool calls)
                        let _concurrency_permit = if let Some(ref a) = agent
                            && let Some(max) = a.max_concurrent {
                                match srv.acquire_concurrency_permit(&a.name, max) {
                                    Ok(permit) => Some(permit),
                                    Err(()) => {
                                        return axum::Json(serde_json::json!({
                                            "error": {"message": format!("Concurrency limit ({max}) reached for agent '{}'", a.name), "type": "rate_limit_error"}
                                        })).into_response();
                                    }
                                }
                            } else {
                                None
                            };

                        // Extract OpenAI-format messages
                        let mut messages = body["messages"].as_array().cloned().unwrap_or_default();
                        let model_name = body["model"].as_str().unwrap_or("default");

                        // Safety filter: scan inbound user/system messages
                        if let Some(pipeline) = srv.safety_pipeline(permissions) {
                            let filter_ctx = navra_core::safety::FilterContext {
                                agent_name,
                                operation: "model_proxy",
                                path: None,
                            };
                            for msg in &mut messages {
                                let role = msg["role"].as_str().unwrap_or("");
                                if (role == "user" || role == "system")
                                    && let Some(text) = msg["content"].as_str() {
                                        match pipeline.process_inbound(text, &filter_ctx).await {
                                            Ok(filtered) => {
                                                msg["content"] = serde_json::Value::String(filtered);
                                            }
                                            Err(reason) => {
                                                return axum::Json(serde_json::json!({
                                                    "error": {"message": format!("Content blocked: {reason}"), "type": "safety_error"}
                                                })).into_response();
                                            }
                                        }
                                    }
                            }
                        }

                        // Inject persona system prompt if requested
                        let persona_name = headers
                            .get("x-persona")
                            .and_then(|v| v.to_str().ok())
                            .map(String::from)
                            .or_else(|| {
                                messages
                                    .first()
                                    .filter(|m| m["role"].as_str() == Some("system"))
                                    .and_then(|m| m["content"].as_str())
                                    .and_then(|c| c.strip_prefix("persona:"))
                                    .map(|p| p.trim().to_string())
                            });
                        if let Some(ref pname) = persona_name
                            && let Ok(output) =
                                navra_cognitive::assemble(&forge, pname, "", None, None)
                            {
                                messages.insert(0, serde_json::json!({
                                    "role": "system",
                                    "content": output.system_prompt(),
                                }));
                            }

                        let mut proxy_body = body.0.clone();
                        proxy_body["messages"] = serde_json::Value::Array(messages);
                        let is_streaming = proxy_body["stream"].as_bool().unwrap_or(false);

                        // Resolve model entry from agent config
                        let model_entry = agent
                            .as_ref()
                            .and_then(|a| a.model.as_ref())
                            .and_then(|name| model_entries.get(name));

                        let is_vertex = model_entry
                            .and_then(|e| e.base_url.as_deref())
                            .map(|u| u.contains("googleapis.com"))
                            .unwrap_or(false);

                        // Build upstream URL and request body
                        let (upstream_url, send_body) = if is_vertex {
                            // Vertex AI: translate OpenAI format → Anthropic Messages format
                            let entry = model_entry.unwrap();
                            let base = entry.base_url.as_deref().unwrap().trim_end_matches('/');

                            // Use model_name from config, or from request body
                            let vertex_model = entry.model_name.as_deref().unwrap_or(model_name);
                            // Convert dash-date to @date for Vertex
                            let vertex_model = if !vertex_model.contains('@') {
                                if let Some(pos) = vertex_model.rfind('-') {
                                    let suffix = &vertex_model[pos + 1..];
                                    if suffix.len() == 8 && suffix.bytes().all(|b| b.is_ascii_digit()) {
                                        std::borrow::Cow::Owned(format!("{}@{}", &vertex_model[..pos], suffix))
                                    } else {
                                        std::borrow::Cow::Borrowed(vertex_model)
                                    }
                                } else {
                                    std::borrow::Cow::Borrowed(vertex_model)
                                }
                            } else {
                                std::borrow::Cow::Borrowed(vertex_model)
                            };
                            let specifier = if is_streaming { "streamRawPredict" } else { "rawPredict" };
                            let url = format!("{base}/{vertex_model}:{specifier}");

                            // Convert OpenAI messages → Anthropic messages
                            let oai_messages = proxy_body["messages"].as_array().cloned().unwrap_or_default();
                            let mut system_text: Option<String> = None;
                            let anthropic_messages: Vec<serde_json::Value> = oai_messages
                                .into_iter()
                                .filter_map(|msg| {
                                    let role = msg["role"].as_str().unwrap_or("").to_string();
                                    if role == "system" {
                                        system_text = msg["content"].as_str().map(String::from);
                                        return None;
                                    }
                                    // Map tool calls in assistant messages
                                    if role == "assistant" {
                                        if let Some(tool_calls) = msg["tool_calls"].as_array() {
                                            let mut content = Vec::new();
                                            if let Some(text) = msg["content"].as_str() {
                                                if !text.is_empty() {
                                                    content.push(serde_json::json!({"type": "text", "text": text}));
                                                }
                                            }
                                            for tc in tool_calls {
                                                let args: serde_json::Value = tc["function"]["arguments"]
                                                    .as_str()
                                                    .and_then(|s| serde_json::from_str(s).ok())
                                                    .unwrap_or(serde_json::json!({}));
                                                content.push(serde_json::json!({
                                                    "type": "tool_use",
                                                    "id": tc["id"],
                                                    "name": tc["function"]["name"],
                                                    "input": args,
                                                }));
                                            }
                                            return Some(serde_json::json!({"role": "assistant", "content": content}));
                                        }
                                    }
                                    // Map tool result messages
                                    if role == "tool" {
                                        return Some(serde_json::json!({
                                            "role": "user",
                                            "content": [{
                                                "type": "tool_result",
                                                "tool_use_id": msg["tool_call_id"],
                                                "content": msg["content"],
                                            }],
                                        }));
                                    }
                                    Some(serde_json::json!({"role": role, "content": msg["content"]}))
                                })
                                .collect();

                            let max_tokens = proxy_body["max_tokens"].as_u64()
                                .or(proxy_body["max_completion_tokens"].as_u64())
                                .unwrap_or(4096);
                            let mut body = serde_json::json!({
                                "anthropic_version": "vertex-2023-10-16",
                                "max_tokens": max_tokens,
                                "messages": anthropic_messages,
                            });
                            if let Some(ref sys) = system_text {
                                body["system"] = serde_json::json!(sys);
                            }
                            if let Some(temp) = proxy_body.get("temperature") {
                                body["temperature"] = temp.clone();
                            }
                            // Convert OpenAI tools format → Anthropic tools format
                            if let Some(tools) = proxy_body["tools"].as_array() {
                                let anthropic_tools: Vec<serde_json::Value> = tools
                                    .iter()
                                    .filter_map(|t| {
                                        let func = &t["function"];
                                        Some(serde_json::json!({
                                            "name": func["name"],
                                            "description": func.get("description").cloned().unwrap_or(serde_json::json!("")),
                                            "input_schema": func.get("parameters").cloned().unwrap_or(serde_json::json!({"type": "object"})),
                                        }))
                                    })
                                    .collect();
                                body["tools"] = serde_json::json!(anthropic_tools);
                                if let Some(tc) = proxy_body.get("tool_choice") {
                                    body["tool_choice"] = match tc.as_str() {
                                        Some("auto") => serde_json::json!({"type": "auto"}),
                                        Some("none") => serde_json::json!({"type": "none"}),
                                        Some("required") => serde_json::json!({"type": "any"}),
                                        _ => serde_json::json!({"type": "auto"}),
                                    };
                                }
                            }
                            if is_streaming {
                                body["stream"] = serde_json::json!(true);
                            }
                            (url, body)
                        } else {
                            // Standard OpenAI-compatible upstream
                            let url = model_entry
                                .and_then(|e| {
                                    if let Some(url) = e.base_url.as_deref() {
                                        return Some(format!("{url}/v1/chat/completions"));
                                    }
                                    if let Some(port) = e.port {
                                        return Some(format!("http://127.0.0.1:{port}/v1/chat/completions"));
                                    }
                                    None
                                })
                                .unwrap_or_else(|| "http://localhost:11434/v1/chat/completions".to_string());
                            (url, proxy_body)
                        };

                        let client = reqwest::Client::builder()
                            .timeout(std::time::Duration::from_secs(600))
                            .build()
                            .unwrap_or_else(|_| reqwest::Client::new());
                        let mut req = client.post(&upstream_url).json(&send_body);

                        // Upstream auth
                        if is_vertex {
                            if let Some(entry) = model_entry
                                && let Some(ref key) = entry.api_key
                            {
                                req = req.header("Authorization", format!("Bearer {key}"));
                            } else if let Some(ref cache) = gcp {
                                match cache.token().await {
                                    Ok(t) => req = req.header("Authorization", format!("Bearer {t}")),
                                    Err(e) => {
                                        return axum::Json(serde_json::json!({
                                            "error": {"message": e, "type": "authentication_error"}
                                        })).into_response();
                                    }
                                }
                            } else {
                                return axum::Json(serde_json::json!({
                                    "error": {"message": "No Vertex AI credentials", "type": "authentication_error"}
                                })).into_response();
                            }
                        }

                        let resp = match req.send().await {
                            Ok(r) => r,
                            Err(e) => {
                                return axum::Json(serde_json::json!({
                                    "error": {"message": format!("Upstream error: {e}"), "type": "upstream_error"}
                                })).into_response();
                            }
                        };

                        let status = resp.status();

                        if is_streaming {
                            let stream = resp.bytes_stream();
                            srv.metrics().model_proxy_requests.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                            return axum::body::Body::from_stream(stream).into_response();
                        }

                        let resp_bytes = resp.bytes().await.unwrap_or_default();
                        if !status.is_success() {
                            return (
                                axum::http::StatusCode::from_u16(status.as_u16())
                                    .unwrap_or(axum::http::StatusCode::BAD_GATEWAY),
                                axum::body::Body::from(resp_bytes),
                            ).into_response();
                        }

                        let mut resp_json: serde_json::Value = match serde_json::from_slice(&resp_bytes) {
                            Ok(v) => v,
                            Err(_) => {
                                return (axum::http::StatusCode::OK, axum::body::Body::from(resp_bytes)).into_response();
                            }
                        };

                        // For Vertex responses, convert Anthropic format → OpenAI format
                        if is_vertex {
                            let mut text_parts = Vec::new();
                            let mut tool_calls = Vec::new();
                            if let Some(blocks) = resp_json["content"].as_array() {
                                for block in blocks {
                                    match block["type"].as_str() {
                                        Some("text") => {
                                            if let Some(t) = block["text"].as_str() {
                                                text_parts.push(t.to_string());
                                            }
                                        }
                                        Some("tool_use") => {
                                            tool_calls.push(serde_json::json!({
                                                "id": block["id"],
                                                "type": "function",
                                                "function": {
                                                    "name": block["name"],
                                                    "arguments": serde_json::to_string(&block["input"]).unwrap_or_else(|_| "{}".to_string()),
                                                },
                                            }));
                                        }
                                        _ => {}
                                    }
                                }
                            }
                            let finish_reason = match resp_json["stop_reason"].as_str() {
                                Some("end_turn") | Some("stop_sequence") => "stop",
                                Some("max_tokens") => "length",
                                Some("tool_use") => "tool_calls",
                                _ => "stop",
                            };
                            let content = if text_parts.is_empty() {
                                serde_json::Value::Null
                            } else {
                                serde_json::Value::String(text_parts.join(""))
                            };
                            let mut message = serde_json::json!({
                                "role": "assistant",
                                "content": content,
                            });
                            if !tool_calls.is_empty() {
                                message["tool_calls"] = serde_json::json!(tool_calls);
                            }
                            let input_tokens = resp_json["usage"]["input_tokens"].as_u64().unwrap_or(0);
                            let output_tokens = resp_json["usage"]["output_tokens"].as_u64().unwrap_or(0);
                            resp_json = serde_json::json!({
                                "id": resp_json["id"],
                                "object": "chat.completion",
                                "model": resp_json["model"],
                                "choices": [{
                                    "index": 0,
                                    "message": message,
                                    "finish_reason": finish_reason,
                                }],
                                "usage": {
                                    "prompt_tokens": input_tokens,
                                    "completion_tokens": output_tokens,
                                    "total_tokens": input_tokens + output_tokens,
                                },
                            });
                        }

                        // Safety filter: scan outbound assistant content
                        if let Some(pipeline) = srv.safety_pipeline(permissions) {
                            let filter_ctx = navra_core::safety::FilterContext {
                                agent_name,
                                operation: "model_proxy",
                                path: None,
                            };
                            if let Some(choices) = resp_json["choices"].as_array_mut() {
                                for choice in choices {
                                    if let Some(content) = choice["message"]["content"].as_str() {
                                        match pipeline.process_outbound(content, &filter_ctx).await {
                                            Ok(filtered) => {
                                                choice["message"]["content"] = serde_json::Value::String(filtered);
                                            }
                                            Err(reason) => {
                                                choice["message"]["content"] = serde_json::Value::String(
                                                    format!("[FILTERED: {reason}]"),
                                                );
                                            }
                                        }
                                    }
                                }
                            }
                        }

                        // Blackbox audit
                        let duration_us = start.elapsed().as_micros() as u64;
                        if let Some(bb) = srv.blackbox() {
                            let output_summary = resp_json["choices"]
                                .as_array()
                                .and_then(|c| c.first())
                                .and_then(|c| c["message"]["content"].as_str())
                                .unwrap_or("")
                                .chars().take(500).collect::<String>();
                            bb.record(
                                agent_name, permissions, "",
                                "model_proxy",
                                &format!("model={model_name}"),
                                &output_summary,
                                "ok", duration_us, "Trusted",
                            );
                        }
                        srv.metrics().model_proxy_requests.fetch_add(1, std::sync::atomic::Ordering::Relaxed);

                        if let Some(usage) = resp_json.get("usage") {
                            let prompt = usage["prompt_tokens"].as_u64().unwrap_or(0);
                            let completion = usage["completion_tokens"].as_u64().unwrap_or(0);
                            let cached = usage["prompt_tokens_details"]["cached_tokens"]
                                .as_u64()
                                .unwrap_or(0);
                            let uncached = prompt.saturating_sub(cached);
                            srv.metrics().record_tokens(uncached, completion, cached);
                        }

                        axum::Json(resp_json).into_response()
                    }
                },
            ),
        )
        .route(
            "/messages",
            {
                let anthropic_server = Arc::clone(server);
                let anthropic_model_entries = cfg.models.clone();
                let anthropic_forge = ui_forge.clone();
                let gcp_tokens: Option<Arc<GcpTokenCache>> = GcpTokenCache::from_adc();
                axum::routing::post(
                    move |headers: axum::http::HeaderMap, body: axum::Json<serde_json::Value>| {
                        let model_entries = anthropic_model_entries.clone();
                        let forge = anthropic_forge.clone();
                        let srv = anthropic_server.clone();
                        let gcp = gcp_tokens.clone();
                        async move {
                            let start = std::time::Instant::now();

                            // Authenticate caller
                            let agent = srv.authenticator().authenticate(&headers).ok();
                            let agent_name = agent.as_ref().map(|a| a.name.as_str()).unwrap_or("anonymous");
                            let permissions = agent.as_ref().map(|a| a.permissions.as_str()).unwrap_or("dev");

                            // Concurrency limit
                            let _concurrency_permit = if let Some(ref a) = agent
                                && let Some(max) = a.max_concurrent {
                                    match srv.acquire_concurrency_permit(&a.name, max) {
                                        Ok(permit) => Some(permit),
                                        Err(()) => {
                                            return axum::Json(serde_json::json!({
                                                "type": "error",
                                                "error": {"type": "rate_limit_error", "message": format!("Concurrency limit ({max}) reached for agent '{}'", a.name)}
                                            })).into_response();
                                        }
                                    }
                                } else {
                                    None
                                };

                            let mut proxy_body = body.0.clone();
                            let model_name = proxy_body["model"].as_str().unwrap_or("default").to_string();

                            // Safety filter: scan inbound user messages
                            // Anthropic content is either a string or an array of content blocks
                            if let Some(pipeline) = srv.safety_pipeline(permissions) {
                                let filter_ctx = navra_core::safety::FilterContext {
                                    agent_name,
                                    operation: "model_proxy",
                                    path: None,
                                };
                                if let Some(messages) = proxy_body["messages"].as_array_mut() {
                                    for msg in messages.iter_mut() {
                                        let role = msg["role"].as_str().unwrap_or("");
                                        if role != "user" { continue; }
                                        // String content
                                        if let Some(text) = msg["content"].as_str().map(String::from) {
                                            match pipeline.process_inbound(&text, &filter_ctx).await {
                                                Ok(filtered) => {
                                                    msg["content"] = serde_json::Value::String(filtered);
                                                }
                                                Err(reason) => {
                                                    return axum::Json(serde_json::json!({
                                                        "type": "error",
                                                        "error": {"type": "invalid_request_error", "message": format!("Content blocked: {reason}")}
                                                    })).into_response();
                                                }
                                            }
                                        }
                                        // Array of content blocks — filter text blocks only
                                        if let Some(blocks) = msg["content"].as_array_mut() {
                                            for block in blocks.iter_mut() {
                                                if block["type"].as_str() == Some("text") {
                                                    if let Some(text) = block["text"].as_str().map(String::from) {
                                                        match pipeline.process_inbound(&text, &filter_ctx).await {
                                                            Ok(filtered) => {
                                                                block["text"] = serde_json::Value::String(filtered);
                                                            }
                                                            Err(reason) => {
                                                                return axum::Json(serde_json::json!({
                                                                    "type": "error",
                                                                    "error": {"type": "invalid_request_error", "message": format!("Content blocked: {reason}")}
                                                                })).into_response();
                                                            }
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                                // Filter system prompt (string or array of text blocks).
                                // Use .get() to avoid inserting null for missing keys —
                                // Vertex rejects "system": null.
                                if let Some(text) = proxy_body.get("system").and_then(|v| v.as_str()).map(String::from) {
                                    match pipeline.process_inbound(&text, &filter_ctx).await {
                                        Ok(filtered) => {
                                            proxy_body["system"] = serde_json::Value::String(filtered);
                                        }
                                        Err(reason) => {
                                            return axum::Json(serde_json::json!({
                                                "type": "error",
                                                "error": {"type": "invalid_request_error", "message": format!("Content blocked: {reason}")}
                                            })).into_response();
                                        }
                                    }
                                } else if proxy_body.get("system").and_then(|v| v.as_array()).is_some() {
                                    let blocks = proxy_body["system"].as_array_mut().unwrap();
                                    for block in blocks.iter_mut() {
                                        if block["type"].as_str() == Some("text") {
                                            if let Some(text) = block["text"].as_str().map(String::from) {
                                                match pipeline.process_inbound(&text, &filter_ctx).await {
                                                    Ok(filtered) => {
                                                        block["text"] = serde_json::Value::String(filtered);
                                                    }
                                                    Err(reason) => {
                                                        return axum::Json(serde_json::json!({
                                                            "type": "error",
                                                            "error": {"type": "invalid_request_error", "message": format!("Content blocked: {reason}")}
                                                        })).into_response();
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            }

                            // Persona injection into the system prompt
                            let persona_name = headers
                                .get("x-persona")
                                .and_then(|v| v.to_str().ok())
                                .map(String::from)
                                .or_else(|| {
                                    proxy_body.get("system")
                                        .and_then(|v| v.as_str())
                                        .and_then(|s| s.strip_prefix("persona:"))
                                        .map(|p| p.trim().to_string())
                                });
                            if let Some(ref pname) = persona_name
                                && let Ok(output) =
                                    navra_cognitive::assemble(&forge, pname, "", None, None)
                            {
                                let persona_text = output.system_prompt().to_string();
                                match proxy_body.get("system") {
                                    Some(serde_json::Value::String(existing)) => {
                                        proxy_body["system"] = serde_json::Value::String(
                                            format!("{persona_text}\n\n{existing}"),
                                        );
                                    }
                                    Some(serde_json::Value::Array(_)) => {
                                        if let Some(blocks) = proxy_body["system"].as_array_mut() {
                                            blocks.insert(0, serde_json::json!({
                                                "type": "text",
                                                "text": persona_text,
                                            }));
                                        }
                                    }
                                    _ => {
                                        proxy_body["system"] = serde_json::Value::String(persona_text);
                                    }
                                }
                            }

                            // Resolve upstream URL and auth.
                            // For Vertex AI, base_url is the project endpoint prefix and
                            // we construct the full rawPredict/streamRawPredict URL from
                            // the model name in the request body — matching the Anthropic
                            // Vertex SDK's URL construction.
                            let model_entry = agent
                                .as_ref()
                                .and_then(|a| a.model.as_ref())
                                .and_then(|name| model_entries.get(name));

                            let is_vertex;
                            let is_streaming = proxy_body["stream"].as_bool().unwrap_or(false);
                            let upstream_url = if let Some(entry) = model_entry
                                && let Some(ref base) = entry.base_url
                            {
                                is_vertex = base.contains("googleapis.com");
                                if is_vertex {
                                    let base = base.trim_end_matches('/');
                                    let specifier = if is_streaming { "streamRawPredict" } else { "rawPredict" };
                                    // Vertex uses @ before the version date (claude-sonnet-4-5@20250929)
                                    // but Anthropic SDK sends a dash (claude-sonnet-4-5-20250929).
                                    // Convert the last -YYYYMMDD to @YYYYMMDD if no @ is present.
                                    let vertex_model = if !model_name.contains('@') {
                                        if let Some(pos) = model_name.rfind('-') {
                                            let suffix = &model_name[pos + 1..];
                                            if suffix.len() == 8 && suffix.bytes().all(|b| b.is_ascii_digit()) {
                                                format!("{}@{}", &model_name[..pos], suffix)
                                            } else {
                                                model_name.to_string()
                                            }
                                        } else {
                                            model_name.to_string()
                                        }
                                    } else {
                                        model_name.to_string()
                                    };
                                    format!("{base}/{vertex_model}:{specifier}")
                                } else {
                                    format!("{base}/v1/messages")
                                }
                            } else {
                                is_vertex = false;
                                "https://api.anthropic.com/v1/messages".to_string()
                            };

                            // Vertex AI body adjustments: model goes in URL, version in body
                            if is_vertex {
                                proxy_body.as_object_mut().map(|o| o.remove("model"));
                                if let Some(obj) = proxy_body.as_object_mut() {
                                    obj.entry("anthropic_version")
                                        .or_insert(serde_json::json!("vertex-2023-10-16"));
                                }
                            }

                            // Build upstream request with auth headers
                            let client = reqwest::Client::builder()
                                .timeout(std::time::Duration::from_secs(600))
                                .build()
                                .unwrap_or_else(|_| reqwest::Client::new());
                            let mut req = client.post(&upstream_url).json(&proxy_body);

                            // Upstream auth. The client's x-api-key contains the navra
                            // token — never forward it upstream. Model config api_key
                            // is used when set; for Vertex without a configured key,
                            // shell out to gcloud for a fresh OAuth token.
                            if let Some(entry) = model_entry
                                && let Some(ref key) = entry.api_key
                            {
                                if is_vertex {
                                    req = req.header("Authorization", format!("Bearer {key}"));
                                } else {
                                    req = req.header("x-api-key", key);
                                }
                            } else if is_vertex {
                                let Some(ref cache) = gcp else {
                                    return axum::Json(serde_json::json!({
                                        "type": "error",
                                        "error": {"type": "authentication_error", "message": "No Vertex AI credentials: set api_key in model config or run gcloud auth application-default login"}
                                    })).into_response();
                                };
                                match cache.token().await {
                                    Ok(t) => {
                                        req = req.header("Authorization", format!("Bearer {t}"));
                                    }
                                    Err(e) => {
                                        return axum::Json(serde_json::json!({
                                            "type": "error",
                                            "error": {"type": "authentication_error", "message": e}
                                        })).into_response();
                                    }
                                }
                            } else {
                                // Direct Anthropic: use api_key from model config if set,
                                // otherwise the endpoint is unauthenticated (will fail upstream)
                            }

                            // Forward anthropic-version from client (or use default)
                            if let Some(ver) = headers.get("anthropic-version") {
                                req = req.header("anthropic-version", ver);
                            } else {
                                req = req.header("anthropic-version", "2023-06-01");
                            }

                            let resp = match req.send().await {
                                Ok(r) => r,
                                Err(e) => {
                                    return axum::Json(serde_json::json!({
                                        "type": "error",
                                        "error": {"type": "api_error", "message": format!("Upstream error: {e}")}
                                    })).into_response();
                                }
                            };

                            let status = resp.status();

                            // Streaming: SSE pass-through
                            if is_streaming {
                                let stream = resp.bytes_stream();
                                srv.metrics().model_proxy_requests.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                                return axum::body::Body::from_stream(stream).into_response();
                            }

                            let resp_bytes = resp.bytes().await.unwrap_or_default();
                            if !status.is_success() {
                                return (
                                    axum::http::StatusCode::from_u16(status.as_u16())
                                        .unwrap_or(axum::http::StatusCode::BAD_GATEWAY),
                                    axum::body::Body::from(resp_bytes),
                                ).into_response();
                            }

                            let mut resp_json: serde_json::Value = match serde_json::from_slice(&resp_bytes) {
                                Ok(v) => v,
                                Err(_) => {
                                    return (axum::http::StatusCode::OK, axum::body::Body::from(resp_bytes)).into_response();
                                }
                            };

                            // Safety filter: scan outbound content blocks
                            if let Some(pipeline) = srv.safety_pipeline(permissions) {
                                let filter_ctx = navra_core::safety::FilterContext {
                                    agent_name,
                                    operation: "model_proxy",
                                    path: None,
                                };
                                if let Some(blocks) = resp_json["content"].as_array_mut() {
                                    for block in blocks.iter_mut() {
                                        if block["type"].as_str() == Some("text") {
                                            if let Some(text) = block["text"].as_str().map(String::from) {
                                                match pipeline.process_outbound(&text, &filter_ctx).await {
                                                    Ok(filtered) => {
                                                        block["text"] = serde_json::Value::String(filtered);
                                                    }
                                                    Err(reason) => {
                                                        block["text"] = serde_json::Value::String(
                                                            format!("[FILTERED: {reason}]"),
                                                        );
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            }

                            // Blackbox audit
                            let duration_us = start.elapsed().as_micros() as u64;
                            if let Some(bb) = srv.blackbox() {
                                let output_summary = resp_json["content"]
                                    .as_array()
                                    .and_then(|blocks| {
                                        blocks.iter().find_map(|b| {
                                            if b["type"].as_str() == Some("text") {
                                                b["text"].as_str()
                                            } else {
                                                None
                                            }
                                        })
                                    })
                                    .unwrap_or("")
                                    .chars().take(500).collect::<String>();
                                bb.record(
                                    agent_name, permissions, "",
                                    "model_proxy",
                                    &format!("model={model_name}"),
                                    &output_summary,
                                    "ok", duration_us, "Trusted",
                                );
                            }
                            srv.metrics().model_proxy_requests.fetch_add(1, std::sync::atomic::Ordering::Relaxed);

                            // Token metrics (Anthropic usage format)
                            if let Some(usage) = resp_json.get("usage") {
                                let input = usage["input_tokens"].as_u64().unwrap_or(0);
                                let output = usage["output_tokens"].as_u64().unwrap_or(0);
                                let cached = usage["cache_read_input_tokens"].as_u64().unwrap_or(0);
                                let uncached = input.saturating_sub(cached);
                                srv.metrics().record_tokens(uncached, output, cached);
                            }

                            axum::Json(resp_json).into_response()
                        }
                    },
                )
            },
        )
        .route_layer(axum::middleware::from_fn_with_state(
            Arc::clone(server),
            auth_middleware,
        ));

    let mut r = router.nest("/v1", v1_router).nest("/api", api_router);

    if let Some(agent_router) = agent_api_router {
        r = r.nest("/api", agent_router);
    }

    r = r.route("/ws/ui", {
        let broadcaster = ui_broadcaster;
        axum::routing::get(move |
                ws: axum::extract::WebSocketUpgrade,
                query: axum::extract::Query<std::collections::HashMap<String, String>>,
            | {
                let broadcaster = broadcaster.clone();
                async move {
                    let _token = query.get("token").cloned().unwrap_or_default();
                    ws.on_upgrade(move |socket| handle_ui_ws(socket, broadcaster))
                }
            })
    });

    if UI_DIST_AVAILABLE {
        r = r
            .route(
                "/",
                axum::routing::get(|| async {
                    let body = ui_assets_gen::index_html();
                    ([("content-type", "text/html; charset=utf-8")], body)
                }),
            )
            .route(
                "/assets/{*path}",
                axum::routing::get(
                    |axum::extract::Path(path): axum::extract::Path<String>| async move {
                        serve_ui_asset(&format!("assets/{path}"))
                    },
                ),
            );
    } else {
        r = r
            .route(
                "/",
                axum::routing::get(|| async {
                    (
                        [("content-type", "text/html")],
                        include_str!("../ui/index.html"),
                    )
                }),
            )
            .route(
                "/ui/style.css",
                axum::routing::get(|| async {
                    (
                        [("content-type", "text/css")],
                        include_str!("../ui/style.css"),
                    )
                }),
            )
            .route(
                "/ui/app.js",
                axum::routing::get(|| async {
                    (
                        [("content-type", "application/javascript")],
                        include_str!("../ui/app.js"),
                    )
                }),
            );
    }

    r
}

fn serve_ui_asset(path: &str) -> axum::response::Response {
    match ui_assets_gen::get_asset(&format!("/{path}")) {
        Some((bytes, mime)) => ([(axum::http::header::CONTENT_TYPE, mime)], bytes).into_response(),
        None => (axum::http::StatusCode::NOT_FOUND, "not found").into_response(),
    }
}

async fn handle_ui_ws(
    socket: axum::extract::ws::WebSocket,
    broadcaster: Option<Arc<UiBroadcaster>>,
) {
    use axum::extract::ws::Message;
    use futures_util::{SinkExt, StreamExt};

    let Some(broadcaster) = broadcaster else {
        return;
    };

    let (mut sender, _receiver) = socket.split();
    let mut rx = broadcaster.subscribe();

    while let Ok(msg) = rx.recv().await {
        if sender.send(Message::Text(msg.into())).await.is_err() {
            break;
        }
    }
}

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
                        navra_model::MessageItem::assistant("hello"),
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

    fn test_config() -> config::Config {
        let mut cfg = config::Config::default();
        cfg.cognitive_core = None;
        cfg.models.insert(
            "stub".into(),
            config::ModelConfig {
                model_path: None,
                source: None,
                tokenizer_path: None,
                task: "chat".into(),
                device: None,
                dimensions: None,
                labels: Vec::new(),
                threshold: None,
                format: None,
                runtime: None,
                context_size: None,
                parallel: None,
                model_name: None,
                cache_type: None,
                speculative: None,
                base_url: None,
                api_key: None,
                locality: None,
                agentic: None,
                execution_mode: None,
                port: None,
            },
        );
        cfg
    }

    fn test_server() -> Arc<navra_core::McpServer> {
        Arc::new(navra_core::McpServer::builder().allow_anonymous().build())
    }

    fn test_models() -> std::collections::HashMap<String, Arc<dyn navra_model::ModelBackend>> {
        let mut m = std::collections::HashMap::new();
        m.insert(
            "stub".into(),
            Arc::new(StubBackend) as Arc<dyn navra_model::ModelBackend>,
        );
        m
    }

    fn build_test_router() -> axum::Router {
        let server = test_server();
        let models = test_models();
        let cfg = test_config();
        let base = axum::Router::new();
        attach_ui_routes(base, &cfg, &server, &models, Some("stub"), None, None)
    }

    async fn post_json(
        router: &axum::Router,
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
        let json: serde_json::Value = serde_json::from_slice(&bytes)
            .unwrap_or(serde_json::json!({"raw": String::from_utf8_lossy(&bytes).to_string()}));
        (status, json)
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

    #[tokio::test]
    async fn v1_chat_completions_returns_openai_format() {
        let router = build_test_router();
        let (status, json) = post_json(
            &router,
            "/v1/chat/completions",
            serde_json::json!({
                "model": "qwen3:8b",
                "messages": [{"role": "user", "content": "say hello in one word"}],
                "max_tokens": 5
            }),
        )
        .await;

        // Should return 200 with OpenAI format (even if model returns empty)
        assert_eq!(status, StatusCode::OK);
        assert_eq!(json["object"], "chat.completion");
        assert!(json["choices"].is_array());
        assert_eq!(json["choices"][0]["message"]["role"], "assistant");
        assert!(json["usage"].is_object());
    }

    #[tokio::test]
    async fn api_status_returns_server_info() {
        let router = build_test_router();
        let (status, json) = get_json(&router, "/api/status").await;

        assert_eq!(status, StatusCode::OK);
        assert_eq!(json["name"], "navra");
        assert_eq!(json["status"], "running");
    }

    #[tokio::test]
    async fn static_assets_no_auth() {
        let router = build_test_router();

        let req = Request::builder().uri("/").body(Body::empty()).unwrap();
        let resp = router.clone().oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }
}
