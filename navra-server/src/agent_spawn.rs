use crate::team_tools::{AuditLogSink, TeamRegistry, DEFAULT_OPERATIONS};
use navra_core::identity::CapSigner;

/// Context needed to spawn a teammate as a background agent task.
pub struct TeammateSpawnContext {
    pub team_registry: std::sync::Arc<TeamRegistry>,
    pub navra_addr: String,
    pub signer: std::sync::Arc<navra_core::identity::Ed25519Signer>,
    pub forge: Option<std::sync::Arc<navra_cognitive::ForgeService>>,
    /// Root capability payload used as the parent for delegated teammate tokens.
    /// When `Some`, teammate tokens are minted via `build_delegated_payload`
    /// with proper delegation chain (parent nonce, attenuation validation).
    /// When `None`, falls back to flat `build_payload` (backward compatible).
    pub root_payload: Option<navra_core::auth::capability::CapabilityPayload>,
    /// Optional PII filter applied to model-generated reasoning text.
    /// When set, teammate agents filter their text output to prevent
    /// PII leaking through model reasoning even after tool results
    /// were redacted.
    pub pii_filter: Option<std::sync::Arc<navra_core::safety::FilterPipeline>>,
    /// Audit log for recording teammate runs.
    pub audit_log: Option<std::sync::Arc<navra_memory::AuditLog>>,
    /// Path to cognitive core directory on the host (for container mounts).
    pub cognitive_core_path: Option<String>,
    /// Shared model server endpoint (e.g. `http://127.0.0.1:PORT/v1`).
    /// When set, containerized agents use this instead of Ollama.
    pub model_server_url: Option<String>,
    /// Semaphore limiting concurrent GPU-bound agent executions.
    pub gpu_semaphore: std::sync::Arc<tokio::sync::Semaphore>,
    /// Whether to use containerized agent execution via Podman.
    pub containerized: bool,
    /// Container image for agent sandboxes.
    pub agent_image: String,
    /// Memory limit per container (e.g., "2g").
    pub container_memory: String,
    /// CPU limit per container (e.g., "2").
    pub container_cpus: String,
    /// PID limit per container.
    pub container_pids: u32,
    /// Optional embedding model for query-aware tool output compression.
    pub embedding_model: Option<std::sync::Arc<dyn navra_model::ModelBackend>>,
    /// OpenShell compute driver gRPC endpoint (e.g., `http://\[::1\]:50051`).
    /// When set, agents are spawned via OpenShell instead of Podman.
    pub openshell_gateway: Option<String>,
    /// Shared exec state for routing exec_run calls to the correct sandbox.
    pub exec_state: Option<std::sync::Arc<crate::exec_tools::ExecState>>,
    /// Workspace provider for populating agent sandbox workspaces.
    pub workspace_provider: Option<std::sync::Arc<dyn crate::workspace::WorkspaceProvider>>,
    /// Maximum total tokens per agent run (circuit breaker). None = unlimited.
    pub max_tokens_per_run: Option<u64>,
    /// Context fill ratio to enable tool output compression. None = disabled.
    pub compression_start_ratio: Option<f32>,
    /// Recent items kept verbatim during conversation compaction. None = derive.
    pub compaction_keep_recent: Option<usize>,
    /// Context fill ratio to trigger conversation compaction. None = derive.
    pub compaction_trigger_ratio: Option<f32>,
}

/// Check if Podman is available on this system.
pub fn is_podman_available() -> bool {
    std::process::Command::new("podman")
        .arg("--version")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

/// Spawn a teammate agent in a Podman container.
///
/// The agent binary (`navra-agent`) reads its configuration from
/// environment variables and communicates with the gateway over HTTP.
/// The container uses `slirp4netns` networking so it can reach the
/// host gateway and model server via `10.0.2.2`.
///
/// **Security note on NAVRA_TOKEN**: The token passed to the container
/// is NOT the server's root token. It is a short-lived delegated token
/// minted via `build_delegated_payload` with:
/// - Scoped operations: only the teammate's allowed operations
/// - Scoped tools: only the teammate's allowed tools
/// - TTL: matches the team's `timeout_secs` (container deadline)
/// - Delegation chain: traceable back to the root payload via parent nonce
///
/// A compromised container can only call the specific tools granted to
/// that teammate, and the token expires when the team times out.
fn spawn_containerized_agent(
    ctx: &TeammateSpawnContext,
    team_id: &str,
    teammate_id: &str,
    message: &str,
    max_iterations: usize,
    timeout_secs: u64,
    _generates_tasks: bool,
) -> tokio::task::JoinHandle<()> {
    let reg = std::sync::Arc::clone(&ctx.team_registry);
    let signer = std::sync::Arc::clone(&ctx.signer);
    let root_payload = ctx.root_payload.clone();
    let navra_addr = ctx.navra_addr.clone();
    let model_server_url = ctx.model_server_url.clone();
    let agent_image = ctx.agent_image.clone();
    let container_memory = ctx.container_memory.clone();
    let container_cpus = ctx.container_cpus.clone();
    let container_pids = ctx.container_pids;
    let gpu_semaphore = std::sync::Arc::clone(&ctx.gpu_semaphore);
    let cognitive_core_path = ctx.cognitive_core_path.clone();
    let audit_log = ctx.audit_log.clone();
    let team_id = team_id.to_string();
    let teammate_id = teammate_id.to_string();
    let message = message.to_string();

    tokio::spawn(async move {
        let deadline = std::time::Duration::from_secs(timeout_secs);
        let timeout_reg = reg.clone();
        let timeout_team = team_id.clone();
        let timeout_task = teammate_id.clone();

        let result = tokio::time::timeout(deadline, async {
            // Acquire GPU semaphore before running
            let _permit = gpu_semaphore.acquire().await.unwrap();

            // Build scoped capability token
            let (tm_ops, tm_tools, tm_persona, teammate_model) = {
                let teams = reg.teams.lock().unwrap_or_else(|e| e.into_inner());
                teams
                    .get(&team_id)
                    .and_then(|t| t.teammates.get(&teammate_id))
                    .map(|tm| {
                        (
                            tm.operations.clone(),
                            tm.tools.clone(),
                            tm.persona.clone(),
                            tm.model.clone(),
                        )
                    })
                    .unwrap_or_else(|| {
                        let fallback_ops: Vec<String> = DEFAULT_OPERATIONS.iter().map(|s| s.to_string()).collect();
                        let fallback_tools = reg.default_tools_for_operations(&fallback_ops);
                        (fallback_ops, fallback_tools, None, "auto".to_string())
                    })
            };

            let did = format!("did:teammate:{}:{}", team_id, teammate_id);
            let token = if let Some(ref root) = root_payload {
                match navra_core::auth::capability::build_delegated_payload(
                    root,
                    &did,
                    tm_ops,
                    tm_tools,
                    2,
                    timeout_secs,
                ) {
                    Ok(payload) => {
                        match navra_core::auth::capability::encode_token(&payload, signer.as_ref())
                        {
                            Ok(t) => t,
                            Err(e) => {
                                reg.set_failed(&team_id, &teammate_id, format!("Token error: {e}"));
                                return;
                            }
                        }
                    }
                    Err(e) => {
                        reg.set_failed(
                            &team_id,
                            &teammate_id,
                            format!("Token delegation error: {e}"),
                        );
                        return;
                    }
                }
            } else {
                let cap = navra_core::auth::capability::CapabilitySet {
                    paths: vec!["**".to_string()],
                    operations: tm_ops,
                    tools: tm_tools,
                    credentials: vec![],
                };
                let payload = navra_core::auth::capability::build_payload(
                    signer.did(),
                    &did,
                    cap,
                    2,
                    timeout_secs,
                );
                match navra_core::auth::capability::encode_token(&payload, signer.as_ref()) {
                    Ok(t) => t,
                    Err(e) => {
                        reg.set_failed(&team_id, &teammate_id, format!("Token error: {e}"));
                        return;
                    }
                }
            };

            // Resolve model
            let mut model = teammate_model;
            if model == "auto" {
                if let Some(selected) =
                    crate::model_selection::select_model_for_task(&reg.model_cards, tm_persona.as_deref(), &message)
                {
                    model = selected;
                } else {
                    model = "granite3.3:8b".to_string();
                }
            }
            if let Some(bare) = model.strip_prefix("ollama://") {
                model = bare.to_string();
            }
            // Strip hub prefixes — the model name passed to Ollama/vLLM
            // must be a bare model name, not a URI.
            if let Some(bare) = model.strip_prefix("ollama://") {
                model = bare.to_string();
            }

            // Parse the gateway port from navra_addr (e.g. "127.0.0.1:9315")
            let gateway_port = navra_addr.rsplit(':').next().unwrap_or("9315");
            let gateway_url = format!("http://10.0.2.2:{gateway_port}/mcp");

            // Route model calls through navra gateway for safety filters, IFC, audit
            let container_model_ep = model_server_url
                .as_ref()
                .map(|u| {
                    u.replace("127.0.0.1", "10.0.2.2")
                        .replace("localhost", "10.0.2.2")
                })
                .unwrap_or_else(|| format!("http://10.0.2.2:{gateway_port}/v1"));

            let container_name = format!("navra-agent-{}-{}", team_id, teammate_id);

            reg.set_resolved_model(&team_id, &teammate_id, &model);
            eprintln!(
                "  [container] {} → model: {}, image: {}",
                teammate_id, model, agent_image
            );

            // Build persona env vars
            let persona_env: Vec<String> = if let Some(ref name) = tm_persona {
                vec!["-e".to_string(), format!("NAVRA_PERSONA={name}")]
            } else {
                vec![]
            };

            // Mount cognitive core directory if persona is set and path is known
            let cognitive_mount: Vec<String> = match (&tm_persona, &cognitive_core_path) {
                (Some(_), Some(core_path)) => vec![
                    "-v".to_string(),
                    format!("{core_path}:/cognitive_core:ro,Z"),
                    "-e".to_string(),
                    "NAVRA_COGNITIVE_CORE=/cognitive_core".to_string(),
                ],
                _ => vec![],
            };

            let mut cmd = tokio::process::Command::new("podman");
            cmd.arg("run")
                .arg("--rm")
                .arg("--name")
                .arg(&container_name)
                .arg("--network=slirp4netns:allow_host_loopback=true")
                .arg(format!("--memory={container_memory}"))
                .arg(format!("--cpus={container_cpus}"))
                .arg(format!("--pids-limit={container_pids}"))
                .arg("--read-only")
                .arg("--security-opt=no-new-privileges")
                .arg("-e")
                .arg(format!("NAVRA_ENDPOINT={gateway_url}"))
                .arg("-e")
                .arg(format!("NAVRA_TOKEN={token}"))
                .arg("-e")
                .arg(format!("NAVRA_MODEL_ENDPOINT={container_model_ep}"))
                .arg("-e")
                .arg(format!("NAVRA_MODEL_NAME={model}"))
                .arg("-e")
                .arg(format!("NAVRA_TASK={message}"))
                .arg("-e")
                .arg(format!("NAVRA_MAX_ITERATIONS={max_iterations}"));

            for arg in &persona_env {
                cmd.arg(arg);
            }
            for arg in &cognitive_mount {
                cmd.arg(arg);
            }

            cmd.arg(&agent_image);

            // Record container name
            reg.set_container_id(&team_id, &teammate_id, container_name.clone());

            let output = cmd
                .stdout(std::process::Stdio::piped())
                .stderr(std::process::Stdio::piped())
                .output()
                .await;

            match output {
                Ok(output) => {
                    let stdout = String::from_utf8_lossy(&output.stdout);
                    let stderr = String::from_utf8_lossy(&output.stderr);

                    if !output.status.success() {
                        tracing::error!(
                            team = %team_id, teammate = %teammate_id,
                            stderr = %stderr,
                            "Container agent failed"
                        );
                        reg.set_failed(
                            &team_id,
                            &teammate_id,
                            format!("Container exited with error: {stderr}"),
                        );
                        return;
                    }

                    // Parse JSON output from the agent binary.
                    // The stdout may contain log lines before the JSON
                    // (tracing warnings from the tool loop). Find the
                    // first '{' to locate the JSON object.
                    let json_str = stdout.find('{').map(|i| &stdout[i..]).unwrap_or(&stdout);
                    match serde_json::from_str::<serde_json::Value>(json_str) {
                        Ok(result) => {
                            let response = result
                                .get("output")
                                .and_then(|v| v.as_str())
                                .unwrap_or("")
                                .to_string();
                            let iterations = result
                                .get("iterations")
                                .and_then(|v| v.as_u64())
                                .unwrap_or(0);
                            let tokens_in = result
                                .get("tokens_in")
                                .and_then(|v| v.as_u64())
                                .unwrap_or(0) as u32;
                            let tokens_out = result
                                .get("tokens_out")
                                .and_then(|v| v.as_u64())
                                .unwrap_or(0) as u32;

                            let total_tokens = tokens_in + tokens_out;
                            reg.add_tokens(&team_id, total_tokens);
                            reg.set_agent_metrics(
                                &team_id,
                                &teammate_id,
                                iterations as u32,
                                total_tokens,
                            );

                            tracing::info!(
                                team = %team_id, teammate = %teammate_id,
                                iterations = iterations,
                                tokens = total_tokens,
                                "Container teammate completed"
                            );

                            // Audit log
                            if let Some(ref audit) = audit_log {
                                let now_ms = std::time::SystemTime::now()
                                    .duration_since(std::time::UNIX_EPOCH)
                                    .unwrap_or_default()
                                    .as_millis()
                                    as i64;
                                let run_id = format!("tm-{team_id}-{teammate_id}");
                                let run = navra_memory::AuditRun {
                                    run_id,
                                    agent_id: teammate_id.clone(),
                                    prompt: message.clone(),
                                    persona: tm_persona.clone(),
                                    model: model.clone(),
                                    started_at: now_ms - (deadline.as_millis() as i64),
                                    ended_at: Some(now_ms),
                                    teammates: vec![],
                                    final_report: Some(response.clone()),
                                    exit_reason: Some("completed".to_string()),
                                };
                                let _ = audit.begin_run(&run);
                            }

                            // Prefer blackboard findings over stdout
                            let bb_key = format!("findings/{}", teammate_id);
                            let bb_output = reg.bb_read(&team_id, &bb_key).map(|e| e.value);
                            let final_output = if let Some(bb) = bb_output {
                                tracing::info!(
                                    team = %team_id, teammate = %teammate_id,
                                    "Using blackboard output (key: {bb_key})"
                                );
                                bb
                            } else {
                                response
                            };
                            reg.set_output(&team_id, &teammate_id, final_output);
                        }
                        Err(e) => {
                            // Check blackboard before falling back to raw stdout
                            let bb_key = format!("findings/{}", teammate_id);
                            if let Some(bb) = reg.bb_read(&team_id, &bb_key).map(|e| e.value) {
                                tracing::info!(
                                    team = %team_id, teammate = %teammate_id,
                                    "Stdout not parseable but blackboard has findings"
                                );
                                reg.set_output(&team_id, &teammate_id, bb);
                            } else {
                                let raw = stdout.trim().to_string();
                                if !raw.is_empty() {
                                    tracing::warn!(
                                        team = %team_id, teammate = %teammate_id,
                                        error = %e,
                                        "Could not parse container JSON output, using raw text"
                                    );
                                    reg.set_output(&team_id, &teammate_id, raw);
                                } else {
                                    reg.set_failed(
                                        &team_id,
                                        &teammate_id,
                                        format!("Container produced no output. stderr: {stderr}"),
                                    );
                                }
                            }
                        }
                    }
                }
                Err(e) => {
                    tracing::error!(
                        team = %team_id, teammate = %teammate_id,
                        error = %e,
                        "Failed to run container"
                    );
                    reg.set_failed(&team_id, &teammate_id, format!("Podman exec error: {e}"));
                }
            }
        })
        .await;

        if result.is_err() {
            tracing::warn!(
                team = %timeout_team, teammate = %timeout_task,
                "Container teammate timed out after {timeout_secs}s"
            );
            // Try to stop the container on timeout
            let container_name = format!("navra-agent-{}-{}", timeout_team, timeout_task);
            let _ = tokio::process::Command::new("podman")
                .args(["stop", "-t", "5", &container_name])
                .output()
                .await;
            timeout_reg.set_failed(
                &timeout_team,
                &timeout_task,
                format!("Timed out after {timeout_secs}s"),
            );
        }
    })
}

/// Spawn a teammate agent inside an OpenShell sandbox.
///
/// Uses the OpenShell compute driver to create a sandbox running
/// `navra-agent`. Workspace is mounted at `/workspace` read-write.
/// The sandbox_id is registered in ExecState so the agent can call
/// `exec_run` to execute commands inside the sandbox.
fn spawn_openshell_agent(
    ctx: &TeammateSpawnContext,
    team_id: &str,
    teammate_id: &str,
    message: &str,
    max_iterations: usize,
    timeout_secs: u64,
    _generates_tasks: bool,
) -> tokio::task::JoinHandle<()> {
    let reg = std::sync::Arc::clone(&ctx.team_registry);
    let signer = std::sync::Arc::clone(&ctx.signer);
    let root_payload = ctx.root_payload.clone();
    let navra_addr = ctx.navra_addr.clone();
    let gateway_url = ctx.openshell_gateway.clone().unwrap();
    let agent_image = ctx.agent_image.clone();
    let exec_state = ctx.exec_state.as_ref().map(std::sync::Arc::clone);
    let workspace_provider = ctx.workspace_provider.as_ref().map(std::sync::Arc::clone);
    let gpu_semaphore = std::sync::Arc::clone(&ctx.gpu_semaphore);
    let cognitive_core_path = ctx.cognitive_core_path.clone();
    let model_server_url = ctx.model_server_url.clone();
    let team_id = team_id.to_string();
    let teammate_id = teammate_id.to_string();
    let message = message.to_string();

    tokio::spawn(async move {
        let deadline = std::time::Duration::from_secs(timeout_secs);
        let timeout_reg = reg.clone();
        let timeout_team = team_id.clone();
        let timeout_task = teammate_id.clone();

        let result = tokio::time::timeout(deadline, async {
            let _permit = gpu_semaphore.acquire().await.unwrap();

            // Build scoped capability token (same as Podman path)
            let (tm_ops, tm_tools, tm_persona, teammate_model) = {
                let teams = reg.teams.lock().unwrap_or_else(|e| e.into_inner());
                teams
                    .get(&team_id)
                    .and_then(|t| t.teammates.get(&teammate_id))
                    .map(|tm| {
                        (
                            tm.operations.clone(),
                            tm.tools.clone(),
                            tm.persona.clone(),
                            tm.model.clone(),
                        )
                    })
                    .unwrap_or_else(|| {
                        let fallback_ops: Vec<String> = DEFAULT_OPERATIONS.iter().map(|s| s.to_string()).collect();
                        let fallback_tools = reg.default_tools_for_operations(&fallback_ops);
                        (fallback_ops, fallback_tools, None, "auto".to_string())
                    })
            };

            let did = format!("did:teammate:{}:{}", team_id, teammate_id);
            let token = if let Some(ref root) = root_payload {
                match navra_core::auth::capability::build_delegated_payload(
                    root,
                    &did,
                    tm_ops,
                    tm_tools,
                    2,
                    timeout_secs,
                ) {
                    Ok(payload) => {
                        match navra_core::auth::capability::encode_token(&payload, signer.as_ref())
                        {
                            Ok(t) => t,
                            Err(e) => {
                                reg.set_failed(&team_id, &teammate_id, format!("Token error: {e}"));
                                return;
                            }
                        }
                    }
                    Err(e) => {
                        reg.set_failed(
                            &team_id,
                            &teammate_id,
                            format!("Token delegation error: {e}"),
                        );
                        return;
                    }
                }
            } else {
                let cap = navra_core::auth::capability::CapabilitySet {
                    paths: vec!["**".to_string()],
                    operations: tm_ops,
                    tools: tm_tools,
                    credentials: vec![],
                };
                let payload = navra_core::auth::capability::build_payload(
                    signer.did(),
                    &did,
                    cap,
                    2,
                    timeout_secs,
                );
                match navra_core::auth::capability::encode_token(&payload, signer.as_ref()) {
                    Ok(t) => t,
                    Err(e) => {
                        reg.set_failed(&team_id, &teammate_id, format!("Token error: {e}"));
                        return;
                    }
                }
            };

            // Resolve model
            let mut model = teammate_model;
            if model == "auto" {
                if let Some(selected) =
                    crate::model_selection::select_model_for_task(&reg.model_cards, tm_persona.as_deref(), &message)
                {
                    model = selected;
                } else {
                    model = "granite3.3:8b".to_string();
                }
            }
            if let Some(bare) = model.strip_prefix("ollama://") {
                model = bare.to_string();
            }

            let gateway_port = navra_addr.rsplit(':').next().unwrap_or("9315");
            let mcp_url = format!("http://10.0.2.2:{gateway_port}/mcp");

            // Route model calls through navra gateway for safety filters, IFC, audit
            let model_endpoint = model_server_url
                .clone()
                .unwrap_or_else(|| format!("http://10.0.2.2:{gateway_port}/v1"));

            reg.set_resolved_model(&team_id, &teammate_id, &model);
            eprintln!(
                "  [openshell] {} → model: {}, image: {}",
                teammate_id, model, agent_image
            );

            // Prepare workspace
            let workspace_dir = tempfile::tempdir().ok();
            if let (Some(provider), Some(ws_dir)) = (&workspace_provider, &workspace_dir)
                && let Err(e) = provider.populate(ws_dir.path())
            {
                reg.set_failed(
                    &team_id,
                    &teammate_id,
                    format!("Workspace populate error: {e}"),
                );
                return;
            }

            // Build mounts
            let mut mounts = Vec::new();
            if let Some(ref ws_dir) = workspace_dir {
                mounts.push(navra_model_runtime::openshell::Mount {
                    source: ws_dir.path().to_string_lossy().to_string(),
                    target: "/workspace".to_string(),
                    read_only: false,
                });
            }
            if let (Some(core_path), Some(_)) = (&cognitive_core_path, &tm_persona) {
                mounts.push(navra_model_runtime::openshell::Mount {
                    source: core_path.clone(),
                    target: "/cognitive_core".to_string(),
                    read_only: true,
                });
            }

            // Build env vars
            let mut env = std::collections::HashMap::new();
            env.insert("NAVRA_ENDPOINT".to_string(), mcp_url);
            env.insert("NAVRA_TOKEN".to_string(), token);
            env.insert("NAVRA_MODEL_ENDPOINT".to_string(), model_endpoint);
            env.insert("NAVRA_MODEL_NAME".to_string(), model);
            env.insert("NAVRA_TASK".to_string(), message.clone());
            env.insert(
                "NAVRA_MAX_ITERATIONS".to_string(),
                max_iterations.to_string(),
            );
            if let Some(ref name) = tm_persona {
                env.insert("NAVRA_PERSONA".to_string(), name.clone());
                env.insert(
                    "NAVRA_COGNITIVE_CORE".to_string(),
                    "/cognitive_core".to_string(),
                );
            }

            // Build sandbox labels
            let mut labels = std::collections::HashMap::new();
            labels.insert("runtime".to_string(), "agent".to_string());
            labels.insert("purpose".to_string(), "teammate".to_string());
            labels.insert("team".to_string(), team_id.clone());
            labels.insert("agent".to_string(), teammate_id.clone());

            let request = navra_model_runtime::openshell::CreateSandboxRequest {
                labels,
                supervisor: Some(navra_model_runtime::openshell::SupervisorConfig {
                    entrypoint: "navra-agent".to_string(),
                    args: vec![],
                    env,
                    mounts,
                }),
            };

            // Connect to OpenShell compute driver
            let channel = match tonic::transport::Channel::from_shared(gateway_url.clone()) {
                Ok(c) => match c.connect().await {
                    Ok(ch) => ch,
                    Err(e) => {
                        reg.set_failed(
                            &team_id,
                            &teammate_id,
                            format!("OpenShell connect error: {e}"),
                        );
                        return;
                    }
                },
                Err(e) => {
                    reg.set_failed(
                        &team_id,
                        &teammate_id,
                        format!("OpenShell channel error: {e}"),
                    );
                    return;
                }
            };

            let mut client = navra_model_runtime::openshell::ComputeDriverClient::new(channel);

            // Create sandbox
            let resp = match client.create_sandbox(request).await {
                Ok(r) => r.into_inner(),
                Err(e) => {
                    reg.set_failed(&team_id, &teammate_id, format!("CreateSandbox error: {e}"));
                    return;
                }
            };

            let sandbox_id = resp.sandbox_id.clone();

            // Record sandbox info
            {
                let mut teams = reg.teams.lock().unwrap_or_else(|e| e.into_inner());
                if let Some(team) = teams.get_mut(&team_id)
                    && let Some(tm) = team.teammates.get_mut(&teammate_id)
                {
                    tm.sandbox_id = Some(sandbox_id.clone());
                    if let Some(ref ws_dir) = workspace_dir {
                        tm.workspace_path = Some(ws_dir.path().to_path_buf());
                    }
                }
            }

            // Register sandbox for exec_run routing
            if let Some(ref exec) = exec_state {
                exec.register_sandbox(did.clone(), sandbox_id.clone());
            }

            // Wait for sandbox to be running
            let mut attempts = 0;
            loop {
                attempts += 1;
                if attempts > 120 {
                    reg.set_failed(
                        &team_id,
                        &teammate_id,
                        "Sandbox failed to start (timeout)".to_string(),
                    );
                    let _ = client
                        .destroy_sandbox(navra_model_runtime::openshell::DestroySandboxRequest {
                            sandbox_id: sandbox_id.clone(),
                        })
                        .await;
                    return;
                }

                match client
                    .sandbox_status(navra_model_runtime::openshell::SandboxStatusRequest {
                        sandbox_id: sandbox_id.clone(),
                    })
                    .await
                {
                    Ok(status) => {
                        let state = status.into_inner().state;
                        if state == navra_model_runtime::openshell::SandboxState::Running as i32 {
                            break;
                        }
                        if state == navra_model_runtime::openshell::SandboxState::Failed as i32 {
                            reg.set_failed(
                                &team_id,
                                &teammate_id,
                                "Sandbox entered failed state".to_string(),
                            );
                            let _ = client
                                .destroy_sandbox(
                                    navra_model_runtime::openshell::DestroySandboxRequest {
                                        sandbox_id: sandbox_id.clone(),
                                    },
                                )
                                .await;
                            return;
                        }
                    }
                    Err(e) => {
                        reg.set_failed(&team_id, &teammate_id, format!("SandboxStatus error: {e}"));
                        return;
                    }
                }
                tokio::time::sleep(std::time::Duration::from_millis(500)).await;
            }

            {
                let mut teams = reg.teams.lock().unwrap_or_else(|e| e.into_inner());
                if let Some(team) = teams.get_mut(&team_id)
                    && let Some(tm) = team.teammates.get_mut(&teammate_id)
                {
                    tm.status = "working".to_string();
                }
            }

            // Wait for sandbox to complete (agent finishes its ReAct loop)
            loop {
                tokio::time::sleep(std::time::Duration::from_secs(2)).await;
                match client
                    .sandbox_status(navra_model_runtime::openshell::SandboxStatusRequest {
                        sandbox_id: sandbox_id.clone(),
                    })
                    .await
                {
                    Ok(status) => {
                        let state = status.into_inner().state;
                        if state == navra_model_runtime::openshell::SandboxState::Stopped as i32
                            || state == navra_model_runtime::openshell::SandboxState::Failed as i32
                        {
                            break;
                        }
                    }
                    Err(_) => break,
                }
            }

            // Collect workspace results
            if let (Some(provider), Some(ws_dir)) = (&workspace_provider, &workspace_dir) {
                match provider.collect(ws_dir.path()) {
                    Ok(result) => {
                        let summary = format!("Workspace: {} files", result.files.len(),);
                        reg.set_output(&team_id, &teammate_id, summary);
                    }
                    Err(e) => {
                        reg.set_output(
                            &team_id,
                            &teammate_id,
                            format!("Done (workspace collect error: {e})"),
                        );
                    }
                }
            } else {
                reg.set_output(&team_id, &teammate_id, "Done".to_string());
            }

            // Cleanup: destroy sandbox and deregister exec state
            let _ = client
                .destroy_sandbox(navra_model_runtime::openshell::DestroySandboxRequest {
                    sandbox_id: sandbox_id.clone(),
                })
                .await;
            if let Some(ref exec) = exec_state {
                exec.remove_sandbox(&did);
            }
        })
        .await;

        if result.is_err() {
            tracing::warn!(
                team = %timeout_team, teammate = %timeout_task,
                "OpenShell teammate timed out after {timeout_secs}s"
            );
            timeout_reg.set_failed(
                &timeout_team,
                &timeout_task,
                format!("Timed out after {timeout_secs}s"),
            );
        }
    })
}

/// Spawn a teammate agent in a background task.
///
/// This is the shared logic used by team_message, flow_start, and
/// flow_escalate. Returns a JoinHandle for the background task.
pub fn spawn_teammate_agent(
    ctx: &TeammateSpawnContext,
    team_id: &str,
    teammate_id: &str,
    message: &str,
    max_iterations: usize,
    timeout_secs: u64,
    generates_tasks: bool,
) -> tokio::task::JoinHandle<()> {
    // OpenShell path: preferred when gateway is configured
    if ctx.openshell_gateway.is_some() {
        return spawn_openshell_agent(
            ctx,
            team_id,
            teammate_id,
            message,
            max_iterations,
            timeout_secs,
            generates_tasks,
        );
    }

    // Containerized path: spawn agent in a Podman container
    if ctx.containerized && is_podman_available() {
        return spawn_containerized_agent(
            ctx,
            team_id,
            teammate_id,
            message,
            max_iterations,
            timeout_secs,
            generates_tasks,
        );
    }

    // In-process path (fallback)
    let reg = std::sync::Arc::clone(&ctx.team_registry);
    let signer = std::sync::Arc::clone(&ctx.signer);
    let forge = ctx.forge.clone();
    let root_payload = ctx.root_payload.clone();
    let pii_filter = ctx.pii_filter.clone();
    let audit_log = ctx.audit_log.clone();
    let embedding_model = ctx.embedding_model.clone();
    let max_tokens_per_run = ctx.max_tokens_per_run;
    let compression_start_ratio = ctx.compression_start_ratio;
    let compaction_keep_recent = ctx.compaction_keep_recent;
    let compaction_trigger_ratio = ctx.compaction_trigger_ratio;
    let navra_addr = ctx.navra_addr.clone();
    let team_id = team_id.to_string();
    let teammate_id = teammate_id.to_string();
    let message = message.to_string();

    tokio::spawn(async move {
        let deadline = std::time::Duration::from_secs(timeout_secs);
        let timeout_reg = reg.clone();
        let timeout_team = team_id.clone();
        let timeout_task = teammate_id.clone();
        let result = tokio::time::timeout(deadline, async move {
            let mcp_url = format!("http://{navra_addr}/mcp");

            let (tm_ops, tm_tools, tm_temperature, tm_max_tokens, tm_force_tool_iters) = {
                let teams = reg.teams.lock().unwrap_or_else(|e| e.into_inner());
                teams.get(&team_id)
                    .and_then(|t| t.teammates.get(&teammate_id))
                    .map(|tm| (tm.operations.clone(), tm.tools.clone(), tm.temperature, tm.max_tokens, tm.force_tool_iterations))
                    .unwrap_or_else(|| {
                        let fallback_ops: Vec<String> = DEFAULT_OPERATIONS.iter().map(|s| s.to_string()).collect();
                        let fallback_tools = reg.default_tools_for_operations(&fallback_ops);
                        (fallback_ops, fallback_tools, None, None, None)
                    })
            };
            let tm_tools_desc = tm_tools.join(", ");
            let did = format!("did:teammate:{}:{}", team_id, teammate_id);
            let token = if let Some(ref root) = root_payload {
                // Delegated token: scoped to teammate's operations/tools,
                // chained from the server's root capability payload.
                match navra_core::auth::capability::build_delegated_payload(
                    root, &did, tm_ops, tm_tools, 2, timeout_secs,
                ) {
                    Ok(payload) => match navra_core::auth::capability::encode_token(&payload, signer.as_ref()) {
                        Ok(t) => t,
                        Err(e) => {
                            tracing::error!(team = %team_id, to = %teammate_id, error = %e, "Failed to encode teammate token");
                            reg.set_failed(&team_id, &teammate_id, format!("Token error: {e}"));
                            return;
                        }
                    },
                    Err(e) => {
                        tracing::error!(team = %team_id, to = %teammate_id, error = %e, "Failed to build delegated token");
                        reg.set_failed(&team_id, &teammate_id, format!("Token delegation error: {e}"));
                        return;
                    }
                }
            } else {
                // Flat token (backward compatible): no parent delegation chain.
                let cap = navra_core::auth::capability::CapabilitySet {
                    paths: vec!["**".to_string()],
                    operations: tm_ops,
                    tools: tm_tools,
                    credentials: vec![],
                };
                let payload = navra_core::auth::capability::build_payload(
                    signer.did(), &did, cap, 2, timeout_secs,
                );
                match navra_core::auth::capability::encode_token(&payload, signer.as_ref()) {
                    Ok(t) => t,
                    Err(e) => {
                        tracing::error!(team = %team_id, to = %teammate_id, error = %e, "Failed to mint teammate token");
                        reg.set_failed(&team_id, &teammate_id, format!("Token error: {e}"));
                        return;
                    }
                }
            };

            let tm_persona = {
                let teams = reg.teams.lock().unwrap_or_else(|e| e.into_inner());
                teams.get(&team_id)
                    .and_then(|t| t.teammates.get(&teammate_id))
                    .and_then(|tm| tm.persona.clone())
            };

            let escalate_hint = if !generates_tasks {
                "\nIf your task requires reviewing more than 5 files or covers multiple distinct concern areas, call flow_escalate to spawn a sub-team. Provide the mandate and any context you have gathered so far."
            } else {
                ""
            };

            let system_prompt = if let Some(ref persona_name) = tm_persona {
                let persona_prompt = forge.as_ref().and_then(|f| {
                    let output = navra_cognitive::assemble(f, persona_name, "", None, None).ok()?;
                    Some(output.system_prompt())
                });
                match persona_prompt {
                    Some(prompt) => format!(
                        "{prompt}\n\n\
                         You are working as part of a team.\n\
                         You have access to MCP tools: {tools}.{escalate_hint}\n\
                         Your team_id is: {team_id}",
                        tools = tm_tools_desc
                    ),
                    None => format!(
                        "You are a specialist agent named '{}' (persona: {}).\n\n\
                         You have access to MCP tools: {}.{escalate_hint}\n\
                         Your team_id is: {}",
                        teammate_id, persona_name, tm_tools_desc, team_id
                    ),
                }
            } else {
                format!(
                    "You are a specialist agent named '{}'.\n\n\
                     You have access to MCP tools: {}.{escalate_hint}\n\
                     Your team_id is: {}",
                    teammate_id, tm_tools_desc, team_id
                )
            };

            let mut teammate_model = {
                let teams = reg.teams.lock().unwrap_or_else(|e| e.into_inner());
                teams.get(&team_id)
                    .and_then(|t| t.teammates.get(&teammate_id))
                    .map(|tm| tm.model.clone())
                    .unwrap_or_else(|| "auto".to_string())
            };

            // Validate model name
            if teammate_model != "auto"
                && !reg.model_cards.iter().any(|c| c.model_uri == teammate_model || c.inference_name() == teammate_model)
            {
                tracing::warn!(
                    task = %teammate_id, model = %teammate_model,
                    "Unknown model, falling back to auto-select"
                );
                teammate_model = "auto".to_string();
            }
            if teammate_model == "auto" {
                if let Some(selected) = crate::model_selection::select_model_for_task(
                    &reg.model_cards,
                    tm_persona.as_deref(),
                    &message,
                ) {
                    teammate_model = selected;
                } else if std::env::var("ANTHROPIC_API_KEY").is_ok()
                    || std::env::var("ANTHROPIC_VERTEX_PROJECT_ID").is_ok()
                {
                    teammate_model = "claude-sonnet-4-6@default".to_string();
                } else {
                    teammate_model = "granite3.3:8b".to_string();
                }
            }

            if let Some(bare) = teammate_model.strip_prefix("ollama://") {
                teammate_model = bare.to_string();
            }
            reg.set_resolved_model(&team_id, &teammate_id, &teammate_model);
            eprintln!("  [teammate] {} → model: {}", teammate_id, teammate_model);

            let is_claude = teammate_model.starts_with("claude");

            let card_context_window = reg.model_cards.iter()
                .find(|c| c.inference_name() == teammate_model || c.model_uri == teammate_model)
                .and_then(|c| c.vendor.context_window);

            macro_rules! run_teammate {
                ($backend:expr) => {{
                    let r = async {
                        let mut builder = navra_agent::Agent::builder()
                            .endpoint(&mcp_url).await?
                            .auth_token(&token)
                            .model($backend)
                            .system_prompt(&system_prompt)
                            .max_iterations(max_iterations)
                            .force_tool_iterations(tm_force_tool_iters.unwrap_or(1));
                        if let Some(t) = tm_temperature {
                            builder = builder.temperature(t);
                        }
                        if let Some(m) = tm_max_tokens {
                            builder = builder.max_tokens(m);
                        }
                        if let Some(cw) = card_context_window {
                            builder = builder.context_window_tokens(cw);
                            tracing::info!(
                                teammate = %teammate_id,
                                context_window = cw,
                                "Context window set from model card"
                            );
                        }
                        if let Some(budget) = max_tokens_per_run {
                            builder = builder.max_tokens_per_run(budget);
                        }
                        if let Some(r) = compression_start_ratio {
                            builder = builder.compression_start_ratio(r);
                        }
                        if let Some(n) = compaction_keep_recent {
                            builder = builder.compaction_keep_recent(n);
                        }
                        if let Some(r) = compaction_trigger_ratio {
                            builder = builder.compaction_trigger_ratio(r);
                        }
                        // Enable cooperative signal delivery
                        let (builder_with_signal, signal_handle) = builder.with_signal();
                        builder = builder_with_signal;
                        reg.store_signal_handle(&team_id, &teammate_id, signal_handle);
                        // Note: generates_tasks schema enforcement is NOT
                        // applied here. Ollama can't handle format + tools
                        // simultaneously, and ignores format on large prompts.
                        // The resilient parser in parse_planner_tasks()
                        // recovers valid JSON from malformed model output.
                        if let Some(ref filter) = pii_filter {
                            builder = builder.pii_filter(std::sync::Arc::clone(filter));
                        }
                        if let Some(ref embed) = embedding_model {
                            builder = builder.embedding_model(std::sync::Arc::clone(embed));
                        }
                        if let Some(ref audit) = audit_log {
                            let sink: navra_agent::SharedAuditSink =
                                std::sync::Arc::new(AuditLogSink(std::sync::Arc::clone(audit)));
                            builder = builder.audit_sink(sink);
                        }
                        let mut agent = builder.build().await?;
                        let result = agent.run(&message).await;
                        agent.close();
                        result
                    };
                    r.await
                }};
            }

            let agent_result = if is_claude {
                let use_vertex = std::env::var("CLAUDE_CODE_USE_VERTEX").is_ok()
                    || std::env::var("ANTHROPIC_VERTEX_PROJECT_ID").is_ok();
                if use_vertex {
                    let project = std::env::var("ANTHROPIC_VERTEX_PROJECT_ID")
                        .unwrap_or_else(|_| "my-project".to_string());
                    let region = std::env::var("CLOUD_ML_REGION")
                        .unwrap_or_else(|_| "us-east5".to_string());
                    let host = if region == "global" {
                        "aiplatform.googleapis.com".to_string()
                    } else {
                        format!("{region}-aiplatform.googleapis.com")
                    };
                    let url = format!(
                        "https://{host}/v1/projects/{project}/locations/{region}/publishers/anthropic/models/{teammate_model}:rawPredict"
                    );
                    let token_output = std::process::Command::new("gcloud")
                        .args(["auth", "print-access-token"])
                        .output();
                    let gcloud_token = match token_output {
                        Ok(output) if output.status.success() => {
                            let t = String::from_utf8_lossy(&output.stdout).trim().to_string();
                            if t.is_empty() {
                                tracing::error!(teammate = %teammate_id, "gcloud returned empty token");
                                reg.set_failed(&team_id, &teammate_id, "Empty gcloud token".to_string());
                                return;
                            }
                            t
                        }
                        Ok(output) => {
                            let err = String::from_utf8_lossy(&output.stderr);
                            tracing::error!(teammate = %teammate_id, error = %err, "gcloud token failed");
                            reg.set_failed(&team_id, &teammate_id, format!("gcloud error: {err}"));
                            return;
                        }
                        Err(e) => {
                            tracing::error!(teammate = %teammate_id, error = %e, "gcloud not available");
                            reg.set_failed(&team_id, &teammate_id, format!("gcloud error: {e}"));
                            return;
                        }
                    };
                    run_teammate!(navra_model::AnthropicBackend::new(
                        &url, &teammate_model, Some(gcloud_token), navra_model::Locality::Remote,
                    ))
                } else {
                    let key = std::env::var("ANTHROPIC_API_KEY").ok();
                    run_teammate!(navra_model::AnthropicBackend::new(
                        "https://api.anthropic.com", &teammate_model, key, navra_model::Locality::Remote,
                    ))
                }
            } else {
                let gateway_ep = format!("http://localhost:{}/v1", navra_addr.rsplit(':').next().unwrap_or("9315"));
                run_teammate!(navra_model::OpenAiBackend::new(
                    &gateway_ep, &teammate_model, None, navra_model::Locality::Local,
                ))
            };

            match agent_result {
                Ok(result) => {
                    let tokens = result.input_tokens + result.output_tokens;
                    reg.add_tokens(&team_id, tokens);
                    reg.set_agent_metrics(&team_id, &teammate_id, result.iterations as u32, tokens);
                    tracing::info!(
                        team = %team_id, to = %teammate_id,
                        iterations = result.iterations,
                        tokens = tokens,
                        "Teammate completed"
                    );
                    // Record teammate run in audit log
                    if let Some(ref audit) = audit_log {
                        let now_ms = std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)
                            .unwrap_or_default()
                            .as_millis() as i64;
                        let run_id = format!("tm-{team_id}-{teammate_id}");
                        let run = navra_memory::AuditRun {
                            run_id: run_id.clone(),
                            agent_id: teammate_id.clone(),
                            prompt: message.clone(),
                            persona: tm_persona.clone(),
                            model: teammate_model.clone(),
                            started_at: now_ms - (deadline.as_millis() as i64),
                            ended_at: Some(now_ms),
                            teammates: vec![],
                            final_report: Some(result.response.clone()),
                            exit_reason: Some("completed".to_string()),
                        };
                        if let Err(e) = audit.begin_run(&run) {
                            tracing::warn!(run_id = %run_id, error = %e, "Failed to record teammate run in audit");
                        }
                    }
                    reg.set_output(&team_id, &teammate_id, result.response);
                }
                Err(e) => {
                    tracing::error!(team = %team_id, to = %teammate_id, error = %e, "Teammate failed");
                    // Record failed teammate run in audit log
                    if let Some(ref audit) = audit_log {
                        let now_ms = std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)
                            .unwrap_or_default()
                            .as_millis() as i64;
                        let run_id = format!("tm-{team_id}-{teammate_id}");
                        let run = navra_memory::AuditRun {
                            run_id,
                            agent_id: teammate_id.clone(),
                            prompt: message.clone(),
                            persona: tm_persona.clone(),
                            model: teammate_model.clone(),
                            started_at: now_ms - (deadline.as_millis() as i64),
                            ended_at: Some(now_ms),
                            teammates: vec![],
                            final_report: None,
                            exit_reason: Some(format!("failed: {e}")),
                        };
                        let _ = audit.begin_run(&run);
                    }
                    reg.set_failed(&team_id, &teammate_id, format!("Agent error: {e}"));
                }
            }
        }).await;

        if result.is_err() {
            tracing::warn!(team = %timeout_team, to = %timeout_task, "Teammate timed out after {timeout_secs}s");
            timeout_reg.set_failed(
                &timeout_team,
                &timeout_task,
                format!("Timed out after {timeout_secs}s"),
            );
        }
    })
}
