//! navra — secure MCP gateway daemon.
//!
//! CLI entry point, configuration loading, module wiring, systemd
//! integration, and system tray. Composes all navra-* crates into
//! a running gateway.

use anyhow::Context as _;

mod acp_agent;
mod agent_bundle;
mod build_tools;
mod cli;
mod cmd_agent;
mod cmd_eval;
mod cmd_misc;
mod cmd_model;
mod cmd_pii;
mod cmd_run;
mod cmd_wrap;
mod eval;
mod config;
mod config_watcher;
mod demo;
mod direct_transport;
mod discover;
mod exec_tools;
mod flow_api;
mod flow_escalation;
mod flow_execution;
mod flow_tools;
mod grpc_manager;
mod init;
mod mdns;
mod memory_tools;
mod network_discovery;
mod plan_execute;
mod policy_sync;
mod rag_retriever;
mod registry_tools;
mod session_distillation;
mod agent_spawn;
mod model_selection;
mod team_tools;
mod tray;
mod triggers;
mod ui;
mod ui_agent;
mod ui_events;
pub(crate) mod util;
pub(crate) mod setup;
pub(crate) mod workspace;

use clap::Parser;
use navra_core::auth::TokenAuthenticator;
use navra_core::identity::{self, CapSigner, Ed25519Signer};
use navra_core::permissions::{PathAcl, PermissionEngine};
use std::sync::Arc;

use cli::{AgentAction, Cli, Commands, ConfigAction, ModelAction, PiiAction, TokenAction};


fn init_tracing() -> anyhow::Result<()> {
    use tracing_subscriber::layer::SubscriberExt;
    use tracing_subscriber::util::SubscriberInitExt;

    let env_filter =
        tracing_subscriber::EnvFilter::from_default_env().add_directive("navra=info".parse()?);
    let fmt_layer = tracing_subscriber::fmt::layer();

    let registry = tracing_subscriber::registry()
        .with(env_filter)
        .with(fmt_layer);

    #[cfg(feature = "otel")]
    {
        if std::env::var("OTEL_EXPORTER_OTLP_ENDPOINT").is_ok() {
            let exporter = opentelemetry_otlp::SpanExporter::builder()
                .with_tonic()
                .build()?;
            let provider = opentelemetry_sdk::trace::SdkTracerProvider::builder()
                .with_batch_exporter(exporter)
                .with_resource(
                    opentelemetry_sdk::Resource::builder()
                        .with_service_name("navra")
                        .build(),
                )
                .build();
            let otel_layer = tracing_opentelemetry::layer().with_tracer(provider.tracer("navra"));
            registry.with(otel_layer).init();
            return Ok(());
        }
    }

    registry.init();
    Ok(())
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    init_tracing()?;

    match cli.command {
        Commands::Init {
            quiet,
            agent_name,
            safety,
            project,
            model,
            model_url,
            api_key,
            allow,
            install_service,
            dry_run,
            output,
            profile,
        } => {
            init::run_init(
                quiet,
                agent_name,
                safety,
                project,
                model,
                model_url,
                api_key,
                allow,
                install_service,
                dry_run,
                output,
                profile,
            )
            .await?;
        }
        Commands::Serve {
            config: config_path,
            no_tray,
            dev_mode,
        } => {
            let cfg = config::Config::load(config_path.as_deref())?;
            if dev_mode {
                tracing::warn!(
                    "--dev-mode enabled: anonymous access allowed without authentication"
                );
            }
            serve(cfg, no_tray, dev_mode).await?;
        }
        Commands::Stdio {
            config: config_path,
        } => {
            let cfg = config::Config::load(config_path.as_deref())?;
            stdio(cfg).await?;
        }
        Commands::Token { action } => match action {
            TokenAction::Generate { name, permissions } => {
                let token = config::generate_token();
                let hash = TokenAuthenticator::hash_token(&token);
                println!("Agent: {name}");
                println!("Permissions: {permissions}");
                println!("Token: {token}");
                println!("Hash:  {hash}");
                println!("\nAdd to config.toml:");
                println!("[[agents]]");
                println!("name = \"{name}\"");
                println!("token_hash = \"{hash}\"");
                println!("permissions = \"{permissions}\"");
            }
            TokenAction::List => {
                let cfg = config::Config::load(None)?;
                if cfg.agents.is_empty() {
                    println!("No agents configured.");
                } else {
                    println!("{:<20} {:<20}", "NAME", "PERMISSIONS");
                    println!("{:<20} {:<20}", "----", "-----------");
                    for agent in &cfg.agents {
                        println!("{:<20} {:<20}", agent.name, agent.permissions);
                    }
                }
            }
        },
        Commands::Approve { id } => {
            let cfg = config::Config::load(None)?;
            let addr = cfg.server.listen_addr();
            cmd_misc::approve_or_deny(&addr, &id, true).await?;
        }
        Commands::Deny { id } => {
            let cfg = config::Config::load(None)?;
            let addr = cfg.server.listen_addr();
            cmd_misc::approve_or_deny(&addr, &id, false).await?;
        }
        Commands::Status => {
            let cfg = config::Config::load(None)?;
            let addr = cfg.server.listen_addr();
            cmd_misc::query_status(&addr).await?;
        }
        Commands::Schema => {
            let schema = schemars::schema_for!(config::Config);
            println!(
                "{}",
                serde_json::to_string_pretty(&schema)
                    .context("failed to serialize config schema")?
            );
        }
        Commands::Install => {
            cmd_misc::install_systemd_units()?;
        }
        Commands::Uninstall => {
            cmd_misc::uninstall_systemd_units()?;
        }
        Commands::Agent { action } => match action {
            AgentAction::Install {
                oci_ref,
                allow_unsigned,
                max_permissions,
            } => {
                let cfg = config::Config::load(None)?;
                cmd_agent::agent_install(&oci_ref, allow_unsigned, max_permissions.as_deref(), &cfg)
                    .await?;
            }
            AgentAction::Inspect { oci_ref } => {
                cmd_agent::agent_inspect(&oci_ref).await?;
            }
            AgentAction::Init { bundle, name } => {
                cmd_agent::agent_init(&bundle, name.as_deref())?;
            }
            AgentAction::Upgrade {
                bundle,
                allow_unsigned: _,
            } => {
                cmd_agent::agent_upgrade(&bundle)?;
            }
            AgentAction::List => {
                cmd_agent::agent_list()?;
            }
            AgentAction::Remove { name } => {
                cmd_agent::agent_remove(&name)?;
            }
        },
        Commands::Model { action } => match action {
            ModelAction::Serve {
                config: config_path,
                bind,
                auto,
                budget,
            } => {
                model_serve(config_path, bind, auto, budget).await?;
            }
            ModelAction::Pull { name } => {
                cmd_model::model_pull(&name).await?;
            }
            ModelAction::List => {
                cmd_model::model_list()?;
            }
            ModelAction::Available => {
                cmd_model::model_available();
            }
        },
        Commands::Pii { action } => match action {
            PiiAction::Download { multilingual } => {
                cmd_pii::pii_download(multilingual).await?;
            }
            PiiAction::Status => {
                cmd_pii::pii_status();
            }
        },
        Commands::Eval { action } => {
            cmd_eval::run(action)?;
        }
        Commands::Config { action } => match action {
            ConfigAction::ImportMcp {
                path,
                discover,
                no_redact,
            } => {
                let redact = !no_redact;
                if discover || path.is_none() {
                    let files = if discover {
                        config::import::discover_config_files()
                    } else {
                        Vec::new()
                    };
                    if let Some(p) = &path {
                        cmd_misc::import_mcp_file(p, redact)?;
                    }
                    if files.is_empty() && path.is_none() {
                        eprintln!("Usage: navra config import-mcp <path>");
                        eprintln!("       navra config import-mcp --discover");
                        std::process::exit(1);
                    }
                    for file in &files {
                        cmd_misc::import_mcp_file(&file.to_string_lossy(), redact)?;
                    }
                } else if let Some(p) = &path {
                    cmd_misc::import_mcp_file(p, redact)?;
                }
            }
            ConfigAction::ListLibraries { config: cfg_path } => {
                let cfg = config::Config::load(cfg_path.as_deref())
                    .unwrap_or_else(|_| config::Config::default());
                let dirs = config::libraries::resolve_dirs(&cfg.libraries.library_dirs);
                let libs = config::libraries::scan_libraries(&dirs)?;
                if libs.is_empty() {
                    println!("No operator libraries found.");
                    println!("Library directories:");
                    for d in &dirs {
                        println!("  {}", d.display());
                    }
                } else {
                    let summaries = config::libraries::summarize_libraries(&libs);
                    for s in &summaries {
                        println!("{}:", s.path.display());
                        for key in &s.keys {
                            println!("  {key}");
                        }
                    }
                }
            }
        },
        Commands::Improve {
            target,
            cycles,
            branch,
            config: _,
        } => {
            println!("navra self-improvement: {} cycles on {}", cycles, target);
            println!("Branch: {branch}");

            let target_path = std::path::Path::new(&target)
                .canonicalize()
                .unwrap_or_else(|e| {
                    eprintln!("Cannot resolve target: {e}");
                    std::process::exit(1);
                });

            // Create git worktree
            let worktree_path = target_path.join(".navra-improve").join(&branch);
            let worktree_result = std::process::Command::new("git")
                .args([
                    "worktree",
                    "add",
                    worktree_path
                        .to_str()
                        .ok_or_else(|| anyhow::anyhow!("worktree path is not valid UTF-8"))?,
                    "-b",
                    &branch,
                ])
                .current_dir(&target_path)
                .output();

            match worktree_result {
                Ok(output) if output.status.success() => {
                    println!("Created worktree at {}", worktree_path.display());
                }
                Ok(output) => {
                    let stderr = String::from_utf8_lossy(&output.stderr);
                    if stderr.contains("already exists") {
                        println!("Worktree already exists at {}", worktree_path.display());
                    } else {
                        eprintln!("Failed to create worktree: {}", stderr);
                        std::process::exit(1);
                    }
                }
                Err(e) => {
                    eprintln!("git worktree failed: {e}");
                    std::process::exit(1);
                }
            }

            // Start the server, run cycles, then stop
            println!("Starting navra for self-improvement...");
            println!("Target: {}", worktree_path.display());
            println!("Cycles: {cycles}");
            println!();
            println!("Use 'navra serve' in another terminal, then call:");
            println!("  flow_start(flow_name=\"self-improve\", prompt=\"Improve the project\",");
            println!(
                "    parameters={{\"target_dir\": \"{}\", \"cycle\": \"1\"}})",
                worktree_path.display()
            );
            println!();
            println!("After each cycle, review the worktree and merge if satisfied:");
            println!("  cd {} && git log --oneline", target_path.display());
            println!("  git merge {branch}");
            println!("  git worktree remove {}", worktree_path.display());
        }
        Commands::ValidateCognitive { cognitive_core } => {
            let path = std::path::Path::new(&cognitive_core);
            if !path.exists() {
                eprintln!("Cognitive core directory not found: {}", path.display());
                std::process::exit(1);
            }
            let forge = navra_cognitive::ForgeService::load(path)?;
            let findings = forge.validate();
            let mut has_errors = false;
            for finding in &findings {
                if finding.severity == navra_cognitive::Severity::Error {
                    has_errors = true;
                }
                println!("[{}] {}", finding.severity, finding.message);
            }
            if findings.is_empty() {
                println!("No issues found.");
            }
            if has_errors {
                std::process::exit(1);
            }
        }
        Commands::Run {
            prompt,
            model,
            persona,
            endpoint,
            token,
            max_iterations,
            upstream_prompts,
            workflow,
            flow,
            config: _run_config,
            no_embedded,
            dry_run,
        } => {
            if let Some(ref flow_file) = flow {
                cmd_run::run_flow_file(flow_file, &prompt, &endpoint, token.as_deref(), model.as_deref()).await?;
                return Ok(());
            }
            // If prompt looks like instance/workflow, treat as workflow run
            let (prompt, _workflow_name) = if let Some(wf) = workflow {
                (format!("Run workflow: {wf}"), Some(wf))
            } else if prompt.contains('/') && !prompt.contains(' ') {
                let wf = prompt.clone();
                (format!("Run workflow: {wf}"), Some(wf))
            } else {
                (prompt, None)
            };
            if dry_run {
                println!("--- Dry Run ---");
                println!("Endpoint: {endpoint}");
                println!("Model: {}", model.as_deref().unwrap_or("auto-detect"));
                println!("Persona: {persona}");
                println!("Max iterations: {max_iterations}");
                if !upstream_prompts.is_empty() {
                    println!("Upstream prompts: {}", upstream_prompts.join(", "));
                }
                let forge = navra_cognitive::ForgeService::empty();
                match navra_cognitive::assemble(&forge, &persona, &prompt, None, None) {
                    Ok(output) => {
                        println!("\n--- System Prompt ---");
                        println!("{}", output.system_prompt());
                        println!("\n--- User Prompt ---");
                        println!("{prompt}");
                    }
                    Err(e) => {
                        println!("\nPersona '{persona}' not found: {e}");
                        println!("\n--- User Prompt ---");
                        println!("{prompt}");
                    }
                }
            } else {
                cmd_run::run_agent(cmd_run::RunAgentParams {
                    prompt: &prompt,
                    model_name: model.as_deref(),
                    persona_name: &persona,
                    endpoint: &endpoint,
                    token: token.as_deref(),
                    max_iterations,
                    upstream_prompts: &upstream_prompts,
                    no_embedded,
                })
                .await?;
            }
        }
        Commands::Audit {
            limit,
            detail,
            agent,
            tool,
            verify,
        } => {
            cmd_misc::audit_command(limit, detail, agent, tool, verify)?;
        }
        Commands::Policy { action } => match action {
            cli::PolicyAction::Suggest {
                hours,
                format,
                db,
                agent,
                min_count,
            } => {
                cmd_misc::policy_suggest(hours, &format, db.as_deref(), agent.as_deref(), min_count)?;
            }
        },
        Commands::Wrap {
            bind,
            safety,
            name,
            no_tray,
            discover,
            allow_all,
            sandbox,
            allow_domains,
            command,
        } => {
            cmd_wrap::wrap_command(
                command,
                bind,
                safety,
                name,
                no_tray,
                discover,
                allow_all,
                sandbox,
                allow_domains,
            )
            .await?;
        }
        Commands::Demo {
            project,
            live,
            model,
            max_rounds,
            files_per_round,
            min_delta,
            prompt,
            writable,
            allow_read,
            allow_write,
        } => {
            if live {
                demo::run_demo_live(
                    &project,
                    &model,
                    max_rounds,
                    files_per_round,
                    min_delta,
                    prompt.as_deref(),
                    writable,
                    &allow_read,
                    &allow_write,
                )
                .await?;
            } else {
                demo::run_demo(&project).await?;
            }
        }
    }

    Ok(())
}

/// Bootstrap the root identity from config.
///
/// If `[server.identity]` specifies a `key_path`, loads or creates
/// a file-based identity. Otherwise, uses the OS keyring.
async fn bootstrap_identity(cfg: &config::Config) -> anyhow::Result<Ed25519Signer> {
    if let Some(ref identity_cfg) = cfg.server.identity
        && let Some(ref key_path) = identity_cfg.key_path
    {
        let path = std::path::Path::new(key_path);
        return Ok(identity::load_or_create_file_identity(path)?);
    }
    // keyring 4 uses zbus which calls block_on internally —
    // must run on a blocking thread to avoid runtime nesting
    match tokio::task::spawn_blocking(identity::load_or_create_keyring_identity)
        .await
        .map_err(|e| anyhow::anyhow!("keyring task panicked: {e}"))?
    {
        Ok(signer) => Ok(signer),
        Err(e) => {
            tracing::warn!(
                error = %e,
                "Keyring unavailable, falling back to file identity"
            );
            let default_path = dirs::config_dir()
                .ok_or_else(|| {
                    anyhow::anyhow!("Cannot determine config directory for identity key")
                })?
                .join("navra/identity.key");
            Ok(identity::load_or_create_file_identity(&default_path)?)
        }
    }
}

/// Build the permission engine from config.
fn build_perm_engine(cfg: &config::Config) -> PermissionEngine {
    let mut engine = PermissionEngine::new();
    for (name, pset) in &cfg.permissions {
        let acl = PathAcl {
            ring: pset.ring,
            allow: pset.allow.clone(),
            deny: pset.deny.clone(),
            operations: pset.operations.iter().cloned().collect(),
            requires_approval: pset.approve.iter().cloned().collect(),
        };
        engine.add_permission_set(name.clone(), acl);

        if let Some(ring) = pset.ring {
            tracing::info!(
                permission_set = %name,
                ring = ring,
                "Permission ring"
            );
        }
    }

    // When no agents are configured, anonymous access uses the "readonly"
    // permission set. If it's missing, tools will fail with DeniedUnknown.
    // Warn loudly at startup so the operator knows why.
    if cfg.agents.is_empty() && !cfg.permissions.contains_key("readonly") {
        tracing::warn!(
            "No [permissions.readonly] in config. Anonymous agents use the \
             'readonly' permission set — without it, all path-based tools \
             (file_read, file_tree, etc.) will be denied. Add a \
             [permissions.readonly] section to grant access."
        );
    }

    engine.apply_ring_inheritance();
    engine
}

/// Start a shared model server container for containerized agent execution.
///
/// Launches a llama-server container via Podman, mounts the first available
/// GGUF model, and polls `/health` until ready. Returns the endpoint URL
/// (rewritten for container access via `10.0.2.2`) and the container name.
async fn start_model_server_container(
    cfg: &config::Config,
) -> anyhow::Result<(String, u16, String)> {
    // Find the first chat/generate model with a resolved GGUF path
    let hub = navra_model_hub::ModelHub::new().ok();
    let mut model_path: Option<std::path::PathBuf> = None;

    for model_cfg in cfg.models.values() {
        if !matches!(model_cfg.task.as_str(), "chat" | "generate") {
            continue;
        }
        if let Some(ref source) = model_cfg.source {
            if let Some(ref h) = hub
                && let Ok(uri) = navra_model_hub::ModelUri::parse(source)
                && let Ok(p) = h.pull(&uri).await
            {
                model_path = Some(p);
                break;
            }
        } else if let Some(ref path_str) = model_cfg.model_path {
            let expanded = util::expand_tilde(path_str);
            let p = std::path::PathBuf::from(&expanded);
            if p.exists() {
                model_path = Some(p);
                break;
            }
        }
    }

    let gguf_path = model_path.ok_or_else(|| {
        anyhow::anyhow!("No chat/generate GGUF model found for model server container")
    })?;
    let gguf_str = gguf_path
        .to_str()
        .ok_or_else(|| anyhow::anyhow!("Invalid model path"))?;

    // Pick a free port
    let listener = std::net::TcpListener::bind("127.0.0.1:0")?;
    let port = listener.local_addr()?.port();
    drop(listener);

    let container_name = "navra-model-server".to_string();
    let image = &cfg.server.model_server_image;
    let parallel = cfg.budget.max_parallel.max(2);

    tracing::info!(
        image = %image,
        model = %gguf_str,
        port = port,
        "Starting shared model server container"
    );

    // Stop any leftover container with the same name
    let _ = tokio::process::Command::new("podman")
        .args(["rm", "-f", &container_name])
        .output()
        .await;

    let output = tokio::process::Command::new("podman")
        .arg("run")
        .arg("-d")
        .arg("--rm")
        .arg("--name")
        .arg(&container_name)
        .arg("--device")
        .arg("nvidia.com/gpu=all")
        .arg("-v")
        .arg(format!("{gguf_str}:/model/model.gguf:ro,Z"))
        .arg("-p")
        .arg(format!("127.0.0.1:{port}:8080"))
        .arg(image)
        .arg("-m")
        .arg("/model/model.gguf")
        .arg("-ngl")
        .arg("99")
        .arg("--parallel")
        .arg(parallel.to_string())
        .arg("--ctx-size")
        .arg("8192")
        .arg("--cont-batching")
        .output()
        .await
        .map_err(|e| anyhow::anyhow!("podman run failed: {e}"))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(anyhow::anyhow!("Model server container failed: {stderr}"));
    }

    // Poll /health until ready (up to 120s)
    let client = reqwest::Client::new();
    let health_url = format!("http://127.0.0.1:{port}/health");
    for attempt in 0..240 {
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
        if let Ok(resp) = client.get(&health_url).send().await
            && resp.status().is_success()
        {
            tracing::info!(port = port, "Model server container is ready");
            let endpoint = format!("http://127.0.0.1:{port}/v1");
            return Ok((endpoint, port, container_name));
        }
        if attempt % 20 == 19 {
            tracing::info!(
                attempt = attempt + 1,
                "Still waiting for model server health..."
            );
        }
    }

    // Cleanup on timeout
    let _ = tokio::process::Command::new("podman")
        .args(["stop", &container_name])
        .output()
        .await;
    Err(anyhow::anyhow!(
        "Model server did not become healthy within 120s"
    ))
}

enum TransportMode {
    Http { no_tray: bool },
    Stdio,
}

async fn stdio(cfg: config::Config) -> anyhow::Result<()> {
    serve_inner(cfg, TransportMode::Stdio, false).await
}

async fn model_serve(
    config_path: Option<String>,
    bind: String,
    auto: bool,
    budget: Option<String>,
) -> anyhow::Result<()> {
    let cfg = config::Config::load(config_path.as_deref())?;

    if auto {
        let desktop_res = 2 * 1024 * 1024 * 1024; // 2 GB
        let summary = navra_model_server::hardware::detect(desktop_res);
        navra_model_server::hardware::print_summary(&summary);
        println!();
    }

    let vram_budget = budget
        .map(|b| util::parse_size_bytes(&b))
        .transpose()?
        .unwrap_or(0);

    let server_config = navra_model_server::ModelServerConfig {
        models: util::convert_model_configs(&cfg.models),
        bind: bind.clone(),
        vram_budget,
        desktop_reservation: 2 * 1024 * 1024 * 1024,
    };

    let server = navra_model_server::ModelServer::new(server_config).await?;
    server.serve(&bind).await
}

pub(crate) async fn serve(cfg: config::Config, no_tray: bool, dev_mode: bool) -> anyhow::Result<()> {
    serve_inner(cfg, TransportMode::Http { no_tray }, dev_mode).await
}

async fn serve_inner(
    cfg: config::Config,
    mode: TransportMode,
    dev_mode: bool,
) -> anyhow::Result<()> {
    // Branded startup banner (before tracing, so it's always visible)
    {
        let version = env!("CARGO_PKG_VERSION");
        let profile = if cfg!(debug_assertions) {
            "debug"
        } else {
            "release"
        };
        eprintln!("navra v{version} ({profile})");
    }

    tracing::info!("Starting navra");

    // Bootstrap root identity (DID:key from Ed25519)
    let root_signer = Arc::new(bootstrap_identity(&cfg).await?);
    tracing::info!(
        root_did = %root_signer.did(),
        algorithm = %root_signer.algorithm(),
        "Root identity"
    );

    // Build credential store from config mappings
    let credential_store = Arc::new(navra_core::credentials::MappedCredentialStore::new(
        cfg.credentials.clone(),
    ));
    if !cfg.credentials.is_empty() {
        tracing::info!(count = cfg.credentials.len(), "Credential mappings loaded");
    }

    let perm_engine = Arc::new(build_perm_engine(&cfg));

    // Build quota engine from rate limits in permission sets
    let mut quota_engine = navra_core::quota::QuotaEngine::new();
    for (name, pset) in &cfg.permissions {
        if let Some(ref rate_limit_str) = pset.rate_limit
            && let Some((max_str, window_str)) = rate_limit_str.split_once('/')
            && let (Ok(max_calls), Ok(window_secs)) =
                (max_str.parse::<u64>(), window_str.parse::<u64>())
        {
            quota_engine.add_limit(
                name.clone(),
                navra_core::quota::RateLimit {
                    max_calls,
                    window_secs,
                },
            );
            tracing::info!(
                permission_set = %name,
                max_calls = max_calls,
                window_secs = window_secs,
                "Rate limit"
            );
        }
    }

    // --- Build server builder with core infrastructure ---
    let process_table = navra_core::process::ProcessTable::new();
    let session_store: navra_core::session::SessionStore;

    if cfg.server.mcp_version == "2025-03-26" {
        tracing::warn!(
            "MCP version 2025-03-26 is deprecated — stateless dispatch (2026-07-28) is now the default. \
             Remove mcp_version from config.toml to use the new default."
        );
    }

    let metrics = std::sync::Arc::new(navra_core::metrics::Metrics::new());

    let mut builder = navra_core::McpServer::builder()
        .name("navra")
        .version(env!("CARGO_PKG_VERSION"))
        .mcp_version(&cfg.server.mcp_version)
        .hook_timeout(std::time::Duration::from_secs(cfg.server.hook_timeout_secs))
        .process_table(process_table.clone())
        .metrics(metrics.clone())
        .max_sessions(cfg.server.max_sessions)
        .session_ttl_secs(cfg.server.session_ttl_secs);

    // Persistent session store (SQLite)
    {
        let session_db_path = dirs::data_dir()
            .unwrap_or_else(|| std::path::PathBuf::from("."))
            .join("navra/sessions.db");
        if let Some(parent) = session_db_path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        match navra_memory::SqliteSessionBackend::open(&session_db_path) {
            Ok(backend) => {
                let existing = {
                    use navra_core::session::SessionBackend;
                    backend.count()
                };
                let store =
                    navra_core::session::SessionStore::with_backend(std::sync::Arc::new(backend));
                session_store = store.clone();
                builder = builder.session_store(store);
                tracing::info!(
                    path = %session_db_path.display(),
                    sessions = existing,
                    "Persistent session store enabled"
                );
            }
            Err(e) => {
                tracing::warn!(
                    error = %e,
                    "Failed to open session DB, falling back to in-memory sessions"
                );
                session_store = navra_core::session::SessionStore::new();
                builder = builder.session_store(session_store.clone());
            }
        }
    }

    // Gateway blackbox — always on, append-only, hash-chained
    {
        let bb_path = dirs::data_dir()
            .unwrap_or_else(|| std::path::PathBuf::from("."))
            .join("navra/blackbox.db");
        if let Some(parent) = bb_path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        match navra_core::blackbox::Blackbox::open(&bb_path) {
            Ok(bb) => {
                let bb = match memory_tools::build_pii_sanitizer(cfg.memory_pii_filter()) {
                    Some(filter) => {
                        tracing::info!("Blackbox PII filter enabled");
                        bb.with_pii_filter(filter)
                    }
                    None => bb,
                };
                if let Some(days) = cfg.memory_audit_retention_days() {
                    let deleted = bb.expire_older_than(days);
                    if deleted > 0 {
                        tracing::info!(deleted, days, "Retention: expired old blackbox entries");
                    }
                }
                let count = bb.count();
                builder = builder.blackbox(bb);
                tracing::info!(
                    path = %bb_path.display(),
                    entries = count,
                    "Blackbox enabled (append-only, hash-chained)"
                );
            }
            Err(e) => {
                tracing::error!(error = %e, "Failed to open blackbox — tool calls will NOT be recorded");
            }
        }
    }

    // Wire IFC policies and trusted paths from permission sets
    for (name, pset) in &cfg.permissions {
        let policy = navra_core::ifc::TaintedWritePolicy::from_str(&pset.tainted_write_policy)
            .unwrap_or_else(|e| {
                tracing::error!(permission_set = %name, error = %e, "Invalid IFC config, defaulting to Deny");
                navra_core::ifc::TaintedWritePolicy::Deny
            });
        builder = builder.ifc_policy(name.clone(), policy.clone());
        if policy != navra_core::ifc::TaintedWritePolicy::Allow {
            tracing::info!(
                permission_set = %name,
                policy = %pset.tainted_write_policy,
                "IFC tainted write policy"
            );
        }
        if !pset.trusted_paths.is_empty() {
            tracing::info!(
                permission_set = %name,
                count = pset.trusted_paths.len(),
                "IFC trusted paths configured"
            );
            builder = builder.trusted_paths(name.clone(), pset.trusted_paths.clone());
        }
    }

    // Wire path ACLs for gateway-level enforcement on upstream tools
    for (name, pset) in &cfg.permissions {
        let acl = PathAcl {
            ring: pset.ring,
            allow: pset.allow.clone(),
            deny: pset.deny.clone(),
            operations: pset.operations.iter().cloned().collect(),
            requires_approval: pset.approve.iter().cloned().collect(),
        };
        builder = builder.path_acl(name.clone(), acl);
    }

    // IFC + stateless mode warning
    if cfg.server.mcp_version != "2025-03-26" {
        let has_ifc_enforcement = cfg.permissions.values().any(|pset| {
            let p = navra_core::ifc::TaintedWritePolicy::from_str(&pset.tainted_write_policy)
                .unwrap_or(navra_core::ifc::TaintedWritePolicy::Deny);
            p != navra_core::ifc::TaintedWritePolicy::Allow
        });
        if has_ifc_enforcement {
            tracing::warn!(
                "IFC tainted_write_policy is active in stateless mode. \
                 Taint persists via server-side sessions keyed by agent name. \
                 All clients sharing the same identity share taint state — \
                 if one reads sensitive data, all are blocked from writing. \
                 This is safe (fail-closed) but may over-block in multi-client setups. \
                 Use session-based dispatch (mcp_version = \"2025-03-26\") or \
                 capability tokens for per-client taint isolation."
            );
        }
    }

    if quota_engine.has_limits() {
        builder = builder.quota_engine(quota_engine);
    }

    // --- Authentication ---
    builder = setup::auth::wire_auth(builder, &cfg, &root_signer, dev_mode)?;

    // --- Models and safety filters ---
    let mf = setup::models::load_models_and_filters(&cfg).await?;
    let models = mf.models;
    let safety_state = mf.safety_state;
    let mut running_endpoints = mf.running_endpoints;

    // --- Safety profiles ---
    builder = setup::safety::wire_safety_profiles(builder, &cfg, &safety_state);

    // --- Approval infrastructure ---
    let approvals = Arc::new(navra_core::permissions::ApprovalStore::with_grant_ttl(
        cfg.approval.timeout_secs,
        cfg.approval.grant_ttl_secs,
    ));
    let _notifier: Arc<dyn navra_core::notify::Notifier> = match cfg.approval.notify.as_str() {
        "dbus" => match navra_core::notify::DbusNotifier::new().await {
            Ok(n) => {
                tracing::info!("D-Bus notifier connected");
                Arc::new(n)
            }
            Err(e) => {
                tracing::warn!("D-Bus unavailable ({e}), falling back to CLI-only approvals");
                Arc::new(navra_core::notify::NoopNotifier)
            }
        },
        _ => Arc::new(navra_core::notify::NoopNotifier),
    };

    // --- Policy sync registry ---
    let endpoint_registry = std::sync::Arc::new(policy_sync::ToolEndpointRegistry::new());

    // --- Feature modules (exec, RAG, voice, vision, upstream, gRPC) ---
    let (mut builder, module_outputs) = setup::modules::wire_modules(
        builder,
        &cfg,
        &models,
        &perm_engine,
        &metrics,
        &credential_store,
        &endpoint_registry,
    )
    .await;
    let setup::modules::ModuleOutputs {
        exec_module,
        shared_chunk_store,
        rag_context_retriever,
        forge: _forge,
        embedding_model,
        _grpc_manager,
        _mdns_daemon,
    } = module_outputs;

    let mdns_enabled = cfg
        .server
        .discovery
        .as_ref()
        .map(|d| d.mdns)
        .unwrap_or(false);

    // --- Gateway tools ---
    builder = setup::tools::wire_cap_delegate(builder, &cfg, &root_signer);
    let mut builder = setup::tools::wire_sys_status(builder);

    // --- Audit log ---
    let audit_db_path = dirs::data_dir()
        .unwrap_or_else(|| std::path::PathBuf::from("."))
        .join("navra/audit.db");
    if let Some(parent) = audit_db_path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    let audit_sanitizer: Option<navra_memory::ContentSanitizer> = {
        let sanitizer_pipeline = memory_tools::build_pii_sanitizer(cfg.memory_pii_filter());
        sanitizer_pipeline.map(|pipeline| -> navra_memory::ContentSanitizer {
            Arc::new(move |content: &str| {
                memory_tools::sanitize_for_storage_sync(content, &Some(Arc::clone(&pipeline)))
            })
        })
    };
    let audit_log: Arc<navra_memory::AuditLog> =
        match navra_memory::audit::AuditLog::open(&audit_db_path) {
            Ok(log) => {
                let log = match audit_sanitizer {
                    Some(sanitizer) => log.with_sanitizer(sanitizer),
                    None => log,
                };
                tracing::info!(path = %audit_db_path.display(), "Audit log enabled");
                Arc::new(log)
            }
            Err(e) => {
                tracing::warn!(error = %e, "Failed to open audit DB, using in-memory");
                match navra_memory::audit::AuditLog::open_memory() {
                    Ok(log) => Arc::new(log),
                    Err(e2) => {
                        anyhow::bail!(
                            "Failed to open audit DB ({e}) and in-memory fallback ({e2})"
                        );
                    }
                }
            }
        };
    if let Some(days) = cfg.memory_audit_retention_days() {
        match audit_log.expire_older_than(days) {
            Ok(n) if n > 0 => tracing::info!(deleted = n, days, "Retention: expired old audit entries"),
            _ => {}
        }
    }

    // --- Flow orchestration tools ---
    let flow_registry = Arc::new(flow_tools::FlowRegistry::new());
    let resolved_flow_dirs = setup::tools::resolve_flow_dirs(&cfg);
    builder = setup::tools::wire_flow_tools(builder, &cfg, &flow_registry, &audit_log);

    // --- Team orchestration tools ---
    let reasoning_pii_filter = setup::models::build_reasoning_pii_filter(&cfg, &safety_state);
    let (mut builder, team_registry_ref, _trigger_registry, mut trigger_webhook_router) =
        setup::tools::wire_team_tools(
            builder,
            &cfg,
            &root_signer,
            &models,
            &exec_module,
            &embedding_model,
            &flow_registry,
            &audit_log,
            &resolved_flow_dirs,
            &reasoning_pii_filter,
            &mut running_endpoints,
        )
        .await;

    // --- Knowledge memory tools ---
    let pii_metrics: Option<Arc<navra_core::safety::PiiMetrics>> =
        Some(Arc::new(navra_core::safety::PiiMetrics::new()));
    let pii_sanitizer = memory_tools::build_pii_sanitizer(cfg.memory_pii_filter());
    if pii_sanitizer.is_some() {
        tracing::info!(
            profile = cfg.memory_pii_filter(),
            "PII filter enabled for memory ingestion and audit logs"
        );
    }

    let knowledge_store: Option<Arc<std::sync::Mutex<navra_memory::KnowledgeStore>>> = {
        let kb_path = dirs::data_dir()
            .unwrap_or_else(|| std::path::PathBuf::from("."))
            .join("navra/knowledge.db");
        if let Some(parent) = kb_path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        match navra_memory::KnowledgeStore::open(&kb_path) {
            Ok(store) => {
                tracing::info!(path = %kb_path.display(), "Knowledge store opened");
                Some(Arc::new(std::sync::Mutex::new(store)))
            }
            Err(e) => {
                tracing::warn!(error = %e, "Failed to open knowledge store, memory tools disabled");
                None
            }
        }
    };

    builder = setup::tools::wire_memory_tools(
        builder,
        &cfg,
        &knowledge_store,
        &shared_chunk_store,
        &pii_sanitizer,
        &pii_metrics,
    );

    // --- Registry proxy tools ---
    builder = setup::tools::wire_registry_tools(builder, &cfg);

    // --- Audit query tool ---
    builder = setup::tools::wire_audit_query(builder, &audit_log);

    // --- plan_execute + build_test ---
    let server_cell: Arc<std::sync::OnceLock<Arc<navra_core::McpServer>>> =
        Arc::new(std::sync::OnceLock::new());
    builder = setup::tools::wire_late_tools(builder, &cfg, &perm_engine, &server_cell);

    // --- Resources (flow://, navra://) ---
    let boot_instant = std::time::Instant::now();
    builder = setup::resources::wire_flow_resources(builder, &audit_log);
    builder = setup::resources::wire_kernel_resources(
        builder,
        &process_table,
        &session_store,
        &server_cell,
        boot_instant,
    );

    // --- SSE broadcaster + hooks ---
    let broadcaster = navra_core::transport::SseBroadcaster::new();
    let mut builder = builder.broadcaster(broadcaster.clone());
    builder = setup::hooks::wire_hooks(builder, &cfg, &safety_state, &knowledge_store);

    // --- Policy sync filter ---
    let (policy_sync_filter, policy_sync_handle) = policy_sync::PolicySyncFilter::new();
    builder = builder.tool_filter(policy_sync_filter);

    // --- Build server ---
    let server = Arc::new(builder.build());
    let _ = server_cell.set(Arc::clone(&server));
    team_registry_ref.set_tool_operations(server.tool_operations().clone());

    // --- Config watcher for hot reload ---
    let _config_watcher = if cfg.server.config_watch {
        let config_path = config::Config::default_config_path();
        let (tx, mut rx) = tokio::sync::watch::channel(std::sync::Arc::new(cfg.clone()));
        match config_watcher::ConfigWatcher::new(
            config_path,
            cfg.server.config_watch_debounce_ms,
            tx,
        ) {
            Ok(w) => {
                let registry = Arc::clone(&endpoint_registry);
                tokio::spawn(async move {
                    while rx.changed().await.is_ok() {
                        let new_cfg = rx.borrow().clone();
                        let blocked = registry.evaluate_config(&new_cfg.upstream);
                        let changed = policy_sync_handle.update_blocked(blocked);
                        if changed > 0 {
                            tracing::info!(
                                changed,
                                "Policy sync: tool availability updated after config reload"
                            );
                        }
                    }
                });
                Some(w)
            }
            Err(e) => {
                tracing::warn!(error = %e, "Failed to start config watcher");
                None
            }
        }
    } else {
        None
    };

    tracing::info!(
        tools = server.tool_count(),
        prompts = server.prompt_count(),
        resources = server.resource_count(),
        "Server ready"
    );

    // --- Run transport ---
    match mode {
        TransportMode::Stdio => {
            navra_core::transport::run_stdio_server(server)
                .await
                .map_err(|e| anyhow::anyhow!("{e}"))?;
        }
        TransportMode::Http { no_tray } => {
            setup::transport::run_http_transport(
                setup::transport::TransportState {
                    server,
                    broadcaster,
                    cfg: cfg.clone(),
                    root_signer: Arc::clone(&root_signer),
                    approvals,
                    flow_registry,
                    resolved_flow_dirs,
                    models,
                    trigger_webhook_router: trigger_webhook_router.take(),
                    rag_context_retriever,
                    mdns_enabled,
                },
                no_tray,
            )
            .await?;
        }
    }

    // --- Stop runtime-served models ---
    for (runtime, endpoint) in &running_endpoints {
        tracing::info!(url = %endpoint.url, backend = ?endpoint.backend, "Stopping model runtime");
        if let Err(e) = runtime.stop(endpoint).await {
            tracing::error!(error = %e, "Failed to stop model runtime");
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use navra_core::protocol::{ReadResourceResult, ResourceContent};
    use navra_protocol::compat::{CallToolResultExt, tool_input_schema};

    fn extract_resource_text(rc: &ResourceContent) -> String {
        match rc {
            ResourceContent::TextResourceContents { text, .. } => text.clone(),
            ResourceContent::BlobResourceContents { blob, .. } => blob.clone(),
        }
    }

    /// Helper: build a resource handler closure for navra://proc.
    fn proc_handler(pt: &navra_core::process::ProcessTable) -> navra_core::ResourceHandler {
        let pt = pt.clone();
        Arc::new(move |uri: String, _ctx| {
            let pt = pt.clone();
            Box::pin(async move {
                let agents = pt.snapshot();
                let json = serde_json::json!({ "agents": agents });
                ReadResourceResult::new(vec![ResourceContent::TextResourceContents {
                    uri,
                    mime_type: Some("application/json".to_string()),
                    text: serde_json::to_string_pretty(&json).unwrap_or_default(),
                    meta: None,
                }])
            })
        })
    }

    /// Helper: build a resource handler closure for navra://sessions.
    fn sessions_handler(ss: &navra_core::session::SessionStore) -> navra_core::ResourceHandler {
        let ss = ss.clone();
        Arc::new(move |uri: String, _ctx| {
            let ss = ss.clone();
            Box::pin(async move {
                let sessions = ss.list_all();
                let count = sessions.len();
                let session_list: Vec<serde_json::Value> = sessions
                    .iter()
                    .map(|s| {
                        serde_json::json!({
                            "id": s.id,
                            "agent": s.agent.name,
                            "created_at": s.created_at,
                        })
                    })
                    .collect();
                let json = serde_json::json!({
                    "count": count,
                    "sessions": session_list,
                });
                ReadResourceResult::new(vec![ResourceContent::TextResourceContents {
                    uri,
                    mime_type: Some("application/json".to_string()),
                    text: serde_json::to_string_pretty(&json).unwrap_or_default(),
                    meta: None,
                }])
            })
        })
    }

    /// Helper: build a resource handler closure for navra://version.
    fn version_handler() -> navra_core::ResourceHandler {
        let boot = std::time::Instant::now();
        Arc::new(move |uri: String, _ctx| {
            Box::pin(async move {
                let json = serde_json::json!({
                    "name": "navra",
                    "version": env!("CARGO_PKG_VERSION"),
                    "protocol_version": navra_core::protocol::PROTOCOL_VERSION,
                    "crates": 20,
                    "uptime_secs": boot.elapsed().as_secs(),
                });
                ReadResourceResult::new(vec![ResourceContent::TextResourceContents {
                    uri,
                    mime_type: Some("application/json".to_string()),
                    text: serde_json::to_string_pretty(&json).unwrap_or_default(),
                    meta: None,
                }])
            })
        })
    }

    #[tokio::test]
    async fn kernel_proc_returns_valid_json() {
        let pt = navra_core::process::ProcessTable::new();
        pt.record_call("claude", "dev", None, None, "file_read");
        pt.complete_call("claude", "file_read");
        pt.record_denied("claude", "dev", None, None);

        let handler = proc_handler(&pt);
        let ctx = navra_core::auth::CallContext::new(
            navra_core::auth::AgentIdentity::new("tester", "dev"),
            "test-session",
        );
        let result = handler("navra://proc".to_string(), ctx).await;

        assert_eq!(result.contents.len(), 1);
        let text = extract_resource_text(&result.contents[0]);
        let parsed: serde_json::Value = serde_json::from_str(&text).unwrap();
        let agents = parsed["agents"].as_array().unwrap();
        assert_eq!(agents.len(), 1);
        assert_eq!(agents[0]["name"], "claude");
        assert_eq!(agents[0]["call_count"], 1);
        assert_eq!(agents[0]["denied_count"], 1);
    }

    #[tokio::test]
    async fn kernel_sessions_returns_valid_json() {
        let ss = navra_core::session::SessionStore::new();
        ss.create(navra_core::session::Session {
            id: "abc-123".to_string(),
            agent: navra_core::auth::AgentIdentity::new("claude", "dev"),
            client_info: navra_core::protocol::ClientInfo::new("test", ""),
            initialized: true,
            context_label: navra_core::ifc::DataLabel::TRUSTED_PUBLIC,
            created_at: 1715000000,
            last_accessed: 1715000000,
        });

        let handler = sessions_handler(&ss);
        let ctx = navra_core::auth::CallContext::new(
            navra_core::auth::AgentIdentity::new("tester", "dev"),
            "test-session",
        );
        let result = handler("navra://sessions".to_string(), ctx).await;

        assert_eq!(result.contents.len(), 1);
        let text = extract_resource_text(&result.contents[0]);
        let parsed: serde_json::Value = serde_json::from_str(&text).unwrap();
        assert_eq!(parsed["count"], 1);
        let sessions = parsed["sessions"].as_array().unwrap();
        assert_eq!(sessions[0]["id"], "abc-123");
        assert_eq!(sessions[0]["agent"], "claude");
        assert_eq!(sessions[0]["created_at"], 1715000000);
    }

    #[tokio::test]
    async fn kernel_version_has_expected_fields() {
        let handler = version_handler();
        let ctx = navra_core::auth::CallContext::new(
            navra_core::auth::AgentIdentity::new("tester", "dev"),
            "test-session",
        );
        let result = handler("navra://version".to_string(), ctx).await;

        assert_eq!(result.contents.len(), 1);
        let text = extract_resource_text(&result.contents[0]);
        let parsed: serde_json::Value = serde_json::from_str(&text).unwrap();
        assert_eq!(parsed["name"], "navra");
        assert!(parsed["version"].is_string());
        assert_eq!(
            parsed["protocol_version"],
            navra_core::protocol::PROTOCOL_VERSION
        );
        assert!(parsed["crates"].is_number());
        assert!(parsed["uptime_secs"].is_number());
    }

    #[tokio::test]
    async fn kernel_tools_via_server() {
        // Build a minimal server with a couple of tools, then verify
        // the tool_names() method that navra://tools relies on.
        use navra_core::protocol::ToolDefinition;

        let server = navra_core::McpServer::builder()
            .name("test")
            .version("0.1.0")
            .allow_anonymous()
            .tool(
                ToolDefinition::new("file_read", "Read a file", tool_input_schema(None, None)),
                |_args, _ctx| Box::pin(async { navra_core::protocol::CallToolResult::text("ok") }),
            )
            .tool(
                ToolDefinition::new("git_status", "Git status", tool_input_schema(None, None)),
                |_args, _ctx| Box::pin(async { navra_core::protocol::CallToolResult::text("ok") }),
            )
            .build();

        let names = server.tool_names();
        assert!(names.contains(&"file_read".to_string()));
        assert!(names.contains(&"git_status".to_string()));
        // Also includes gateway IFC tools registered in build()
        assert!(names.contains(&"navra_var_list".to_string()));
    }
}
