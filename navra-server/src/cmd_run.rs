//! `navra run` subcommand — single-shot agent execution.

#[cfg(feature = "embedded")]
use navra_model_runtime::ModelRuntime;

/// Create a configured MCP transport with optional auth header.
macro_rules! authed_transport {
    ($endpoint:expr, $token:expr) => {{
        let mut config =
            rmcp::transport::streamable_http_client::StreamableHttpClientTransportConfig::with_uri(
                $endpoint,
            );
        if let Some(t) = $token {
            config = config.auth_header(t);
        }
        rmcp::transport::StreamableHttpClientTransport::from_config(config)
    }};
}

pub(crate) struct RunAgentParams<'a> {
    pub prompt: &'a str,
    pub model_name: Option<&'a str>,
    pub persona_name: &'a str,
    pub endpoint: &'a str,
    pub token: Option<&'a str>,
    pub max_iterations: usize,
    pub upstream_prompts: &'a [String],
    #[allow(dead_code)]
    pub no_embedded: bool,
}

pub(crate) async fn run_agent(params: RunAgentParams<'_>) -> anyhow::Result<()> {
    let RunAgentParams {
        prompt,
        model_name,
        persona_name,
        endpoint,
        token,
        max_iterations,
        upstream_prompts,
        #[cfg_attr(not(feature = "embedded"), allow(unused))]
        no_embedded,
    } = params;
    // Auto-detect model from Ollama if not specified
    let model_name = if let Some(m) = model_name {
        m.to_string()
    } else {
        // Pick first available Ollama model
        let resp = reqwest::Client::new()
            .get("http://localhost:11434/api/tags")
            .send()
            .await
            .ok()
            .and_then(|r| futures_util::FutureExt::now_or_never(r.json::<serde_json::Value>()));
        match resp {
            Some(Ok(tags)) => tags["models"]
                .as_array()
                .and_then(|m| m.first())
                .and_then(|m| m["name"].as_str())
                .unwrap_or("gemma4:26b")
                .to_string(),
            _ => "gemma4:26b".to_string(),
        }
    };

    eprintln!("Model:    {model_name}");
    eprintln!("Persona:  {persona_name}");
    eprintln!("Endpoint: {endpoint}");
    eprintln!();

    // Detect model provider from name
    enum ModelProvider {
        Ollama,
        VertexAI {
            url: String,
            token: Option<String>,
            region: String,
        },
        AnthropicDirect {
            key: String,
        },
    }

    let provider = if model_name.starts_with("claude") {
        let project = std::env::var("ANTHROPIC_VERTEX_PROJECT_ID")
            .or_else(|_| std::env::var("GOOGLE_CLOUD_PROJECT"))
            .unwrap_or_default();
        let region = std::env::var("CLOUD_ML_REGION")
            .or_else(|_| std::env::var("GOOGLE_CLOUD_REGION"))
            .unwrap_or_else(|_| "us-east5".to_string());

        if !project.is_empty() {
            let host = if region == "global" {
                "aiplatform.googleapis.com".to_string()
            } else {
                format!("{region}-aiplatform.googleapis.com")
            };
            let url = format!(
                "https://{host}/v1/projects/{project}/locations/{region}/publishers/anthropic/models/{model_name}:rawPredict"
            );
            let token = std::process::Command::new("gcloud")
                .args(["auth", "print-access-token"])
                .output()
                .ok()
                .and_then(|o| String::from_utf8(o.stdout).ok())
                .map(|s| s.trim().to_string());
            ModelProvider::VertexAI { url, token, region }
        } else if let Ok(key) = std::env::var("ANTHROPIC_API_KEY") {
            ModelProvider::AnthropicDirect { key }
        } else {
            anyhow::bail!(
                "Claude model requested but no ANTHROPIC_VERTEX_PROJECT_ID or ANTHROPIC_API_KEY set"
            );
        }
    } else {
        ModelProvider::Ollama
    };

    // Load persona if cognitive_core exists
    let mut forge = navra_cognitive::ForgeService::load(std::path::Path::new("cognitive_core"))
        .ok()
        .or_else(|| {
            // Try common locations
            for p in ["../cognitive_core", "/etc/navra/cognitive_core"] {
                if let Ok(f) = navra_cognitive::ForgeService::load(std::path::Path::new(p)) {
                    return Some(f);
                }
            }
            None
        });

    // Discover upstream personas from the running navra server
    if let Some(ref mut f) = forge {
        let discover_peer = {
            let transport = authed_transport!(endpoint, token);
            rmcp::service::ServiceExt::<rmcp::RoleClient>::serve((), transport)
                .await
                .ok()
                .map(|c| {
                    let peer = c.peer().clone();
                    tokio::spawn(async move {
                        let _ = c.waiting().await;
                    });
                    peer
                })
        };
        if let Some(peer) = discover_peer {
            let client = navra_agent::McpClient::new(peer);
            if let Ok(prompts) = client.list_prompts().await {
                for p in &prompts {
                    if let Some(persona_name) = p.name.strip_prefix("persona:") {
                        let desc = p.description.as_deref().unwrap_or("");
                        if f.register_upstream_persona(persona_name, "upstream", &p.name, desc) {
                            eprintln!("Discovered upstream persona: {persona_name}");
                        }
                    }
                }
            }
        }
    }

    // Build agent with provider-specific backend
    let base_builder = navra_agent::Agent::builder().endpoint(endpoint).await?;

    let non_progress = vec![
        "team_status".to_string(),
        "team_result".to_string(),
        "team_bb_read".to_string(),
        "team_bb_notifications".to_string(),
        "models_list".to_string(),
        "personas_list".to_string(),
        "flow_status".to_string(),
        "flow_result".to_string(),
    ];

    macro_rules! configure_builder {
        ($b:expr) => {
            $b.max_iterations(max_iterations)
                .temperature(0.0)
                .max_tokens(32768)
                .force_tool_iterations(5)
                .non_progress_tools(non_progress.clone())
        };
    }

    // Embedded runtime state — kept alive for the duration of the agent run
    #[allow(unused_mut)]
    let mut embedded_endpoint: Option<(
        Box<dyn navra_model_runtime::ModelRuntime>,
        navra_model_runtime::Endpoint,
    )> = None;

    let mut builder = match provider {
        ModelProvider::VertexAI {
            url,
            token,
            ref region,
        } => {
            eprintln!("Provider: Vertex AI ({region})");
            let backend = navra_model::AnthropicBackend::new(
                url,
                &model_name,
                token,
                navra_model::Locality::Remote,
            );
            configure_builder!(base_builder.model(backend))
        }
        ModelProvider::AnthropicDirect { key } => {
            eprintln!("Provider: Anthropic API");
            let backend = navra_model::AnthropicBackend::new(
                "https://api.anthropic.com",
                &model_name,
                Some(key),
                navra_model::Locality::Remote,
            );
            configure_builder!(base_builder.model(backend))
        }
        ModelProvider::Ollama => {
            #[cfg(feature = "embedded")]
            if !no_embedded {
                let (m, t) = if let Some(pos) = model_name.find(':') {
                    (&model_name[..pos], &model_name[pos + 1..])
                } else {
                    (model_name.as_str(), "latest")
                };
                if let Some(gguf_path) = navra_model_hub::try_local_ollama(m, t) {
                    let runtime = navra_model_runtime::embedded::EmbeddedRuntime::new();
                    let gpus = navra_model_runtime::gpu::detect_gpus();
                    let target = navra_model_runtime::HardwareTarget::from_gpus(&gpus);
                    let cfg = navra_model_runtime::ServeConfig {
                        model_path: gguf_path,
                        context_size: 8192,
                        gpus,
                        target,
                        ..Default::default()
                    };
                    match runtime.serve(&cfg).await {
                        Ok(ep) => {
                            eprintln!("Provider: embedded (llama.cpp in-process)");
                            embedded_endpoint = Some((Box::new(runtime), ep));
                        }
                        Err(e) => {
                            eprintln!("Embedded runtime failed ({e}), falling back to Ollama API");
                        }
                    }
                }
            }

            if let Some((_, ref ep)) = embedded_endpoint {
                let backend = navra_model::OpenAiBackend::new(
                    format!("{}/v1", ep.url),
                    &model_name,
                    None,
                    navra_model::Locality::Local,
                );
                configure_builder!(base_builder.model(backend))
            } else {
                let ollama_url = std::env::var("OLLAMA_HOST")
                    .unwrap_or_else(|_| "http://localhost:11434".to_string());
                eprintln!("Provider: Ollama ({ollama_url})");
                let backend = navra_model::OpenAiBackend::new(
                    format!("{ollama_url}/v1"),
                    &model_name,
                    None,
                    navra_model::Locality::Local,
                );
                configure_builder!(base_builder.model(backend))
            }
        }
    };

    // Apply auth token
    let auth_token = token
        .map(String::from)
        .or_else(|| std::env::var("MCPD_TOKEN").ok());
    if let Some(ref t) = auth_token {
        builder = builder.auth_token(t.clone());
    }

    // Parse --upstream-prompt flags into McpPromptRef entries
    let cli_prompt_refs: Vec<navra_cognitive::McpPromptRef> = upstream_prompts
        .iter()
        .filter_map(|s| {
            let (upstream, prompt_name) = s.split_once(':')?;
            Some(navra_cognitive::McpPromptRef {
                upstream: upstream.to_string(),
                prompt: prompt_name.to_string(),
                inject_position: navra_cognitive::InjectPosition::AfterExamples,
                arguments: None,
            })
        })
        .collect();

    if !cli_prompt_refs.is_empty() {
        eprintln!("Upstream prompts: {}", cli_prompt_refs.len());
    }

    // Apply persona
    if let Some(ref forge) = forge {
        if let Some(persona) = forge.get_persona(persona_name) {
            // Check if this is an MCP-sourced persona
            let has_source = persona.source.is_some();

            // Collect persona-defined mcp_prompts and CLI-provided ones
            let all_refs: Vec<navra_cognitive::McpPromptRef> = persona
                .mcp_prompts
                .iter()
                .cloned()
                .chain(cli_prompt_refs.iter().cloned())
                .collect();

            if has_source || !all_refs.is_empty() {
                // Need an MCP connection to resolve source and/or prompts
                let resolver_peer = {
                    let transport = authed_transport!(endpoint, token);
                    let c =
                        rmcp::service::ServiceExt::<rmcp::RoleClient>::serve((), transport).await?;
                    let peer = c.peer().clone();
                    tokio::spawn(async move {
                        let _ = c.waiting().await;
                    });
                    peer
                };
                let mut resolver_client = navra_agent::McpClient::new(resolver_peer);

                if has_source {
                    // MCP-sourced persona: resolve source + mcp_prompts together
                    builder = builder
                        .persona_from_mcp(forge, persona_name, &mut resolver_client, prompt)
                        .await?;

                    // Also resolve any CLI-provided upstream prompts
                    if !cli_prompt_refs.is_empty() {
                        let extra_resolved = navra_agent::resolve::resolve_mcp_prompts(
                            &mut resolver_client,
                            &cli_prompt_refs,
                            prompt,
                        )
                        .await?;

                        if !extra_resolved.is_empty() {
                            eprintln!("Resolved {} CLI upstream prompt(s)", extra_resolved.len());
                        }
                    }

                    eprintln!("Loaded MCP-sourced persona: {persona_name}");
                } else {
                    // Local persona with upstream prompts to resolve
                    let resolved = navra_agent::resolve::resolve_mcp_prompts(
                        &mut resolver_client,
                        &all_refs,
                        prompt,
                    )
                    .await?;

                    if !resolved.is_empty() {
                        eprintln!("Resolved {} upstream prompt(s)", resolved.len());
                    }

                    builder = builder.persona_with_prompts(forge, persona_name, &resolved)?;
                }
            } else {
                builder = builder.persona(forge, persona_name)?;
            }

            eprintln!("Loaded persona: {persona_name}");
        }
    } else if !cli_prompt_refs.is_empty() {
        // No persona loaded but CLI prompts were specified — resolve and append
        let resolver_peer = {
            let transport = authed_transport!(endpoint, token);
            let c = rmcp::service::ServiceExt::<rmcp::RoleClient>::serve((), transport).await?;
            let peer = c.peer().clone();
            tokio::spawn(async move {
                let _ = c.waiting().await;
            });
            peer
        };
        let mut resolver_client = navra_agent::McpClient::new(resolver_peer);

        let resolved = navra_agent::resolve::resolve_mcp_prompts(
            &mut resolver_client,
            &cli_prompt_refs,
            prompt,
        )
        .await?;

        if !resolved.is_empty() {
            let extra = resolved
                .iter()
                .map(|rp| format!("## Upstream Prompt: {}\n\n{}", rp.label, rp.content))
                .collect::<Vec<_>>()
                .join("\n\n");

            builder = builder.system_prompt(extra);
            eprintln!(
                "Resolved {} upstream prompt(s) (no persona)",
                resolved.len()
            );
        }
    }

    let mut agent = builder.build().await?;

    // List tools
    let tools = agent.client().list_tools().await?;
    eprintln!("{} tools available", tools.len());
    eprintln!();

    // Run
    let start = std::time::Instant::now();
    match agent.run(prompt).await {
        Ok(result) => {
            // Print report to stdout (pipeable)
            println!("{}", result.response);

            // Print stats to stderr
            eprintln!();
            eprintln!("---");
            eprintln!("Iterations: {}", result.iterations);
            eprintln!(
                "Tokens:     {} in + {} out",
                result.input_tokens, result.output_tokens
            );
            eprintln!("Time:       {:.1}s", start.elapsed().as_secs_f64());
            eprintln!("Taint:      {:?}", result.taint);
            eprintln!("Blackbox:   navra audit");
        }
        Err(e) => {
            eprintln!("Error: {e}");
            std::process::exit(1);
        }
    }

    if let Some((runtime, ep)) = embedded_endpoint {
        let _ = runtime.stop(&ep).await;
    }

    Ok(())
}

/// Run a flow YAML file directly via MCP `flow_start`, poll to
/// completion, and print the result. No agent loop involved.
pub(crate) async fn run_flow_file(
    path: &str,
    prompt: &str,
    endpoint: &str,
    token: Option<&str>,
) -> anyhow::Result<()> {
    let yaml = std::fs::read_to_string(path)
        .map_err(|e| anyhow::anyhow!("Cannot read flow file {path}: {e}"))?;
    eprintln!("Flow file: {path}");
    eprintln!("Endpoint:  {endpoint}");

    let transport = authed_transport!(endpoint, token);
    let client = rmcp::service::ServiceExt::<rmcp::RoleClient>::serve((), transport).await?;
    let peer = client.peer().clone();
    let mut mcp = navra_agent::McpClient::new(peer);

    // Parse parameters from the prompt (key=value pairs)
    let mut params = serde_json::Map::new();
    for part in prompt.split_whitespace() {
        if let Some((k, v)) = part.split_once('=') {
            params.insert(k.to_string(), serde_json::Value::String(v.to_string()));
        }
    }

    let args = serde_json::json!({
        "flow_definition": yaml,
        "prompt": prompt,
        "parameters": params,
    });

    eprintln!("Starting flow...\n");
    let start_result = mcp.call_tool("flow_start", args).await?;
    let start_text = start_result
        .content
        .first()
        .and_then(|c| c.raw.as_text())
        .map(|t| t.text.clone())
        .unwrap_or_default();

    // Extract flow_id from response
    let flow_id = serde_json::from_str::<serde_json::Value>(&start_text)
        .ok()
        .and_then(|v| v.get("flow_id").and_then(|f| f.as_str()).map(String::from))
        .unwrap_or_else(|| {
            eprintln!("flow_start response: {start_text}");
            String::new()
        });

    if flow_id.is_empty() {
        anyhow::bail!("flow_start did not return a flow_id");
    }
    eprintln!("Flow ID: {flow_id}");

    // Poll until complete
    loop {
        tokio::time::sleep(std::time::Duration::from_secs(5)).await;
        let status_result = mcp
            .call_tool(
                "flow_status",
                serde_json::json!({"flow_id": flow_id}),
            )
            .await?;
        let status_text = status_result
            .content
            .first()
            .and_then(|c| c.raw.as_text())
            .map(|t| t.text.clone())
            .unwrap_or_default();

        if let Ok(v) = serde_json::from_str::<serde_json::Value>(&status_text) {
            let status = v.get("status").and_then(|s| s.as_str()).unwrap_or("");
            let completed = v.get("completed").and_then(|c| c.as_u64()).unwrap_or(0);
            let failed = v.get("failed").and_then(|f| f.as_u64()).unwrap_or(0);
            let total = v.get("total").and_then(|t| t.as_u64()).unwrap_or(0);
            eprint!("\r{status}: {completed}/{total} done, {failed} failed  ");
            if status == "completed" || status == "failed" {
                eprintln!();
                break;
            }
        }
    }

    // Fetch result
    let result = mcp
        .call_tool("flow_result", serde_json::json!({"flow_id": flow_id}))
        .await?;
    for content in &result.content {
        if let Some(text) = content.raw.as_text() {
            println!("{}", text.text);
        }
    }

    let _ = client.cancel().await;
    Ok(())
}
