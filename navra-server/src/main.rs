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
mod flow_tools;
mod grpc_manager;
mod init;
mod mdns;
mod memory_tools;
mod network_discovery;
mod plan_execute;
mod rag_retriever;
mod registry_tools;
mod session_distillation;
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
use navra_core::Module;
use navra_core::auth::TokenAuthenticator;
use navra_core::identity::{self, CapSigner, Ed25519Signer};
use navra_core::permissions::{PathAcl, PermissionEngine};
use navra_protocol::compat::CallToolResultExt;
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
                cmd_run::run_flow_file(flow_file, &prompt, &endpoint, token.as_deref()).await?;
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

    // Build server, registering enabled modules
    // Shared process table — created early so kernel resource handlers can capture it.
    let process_table = navra_core::process::ProcessTable::new();

    // Shared session store — created early so kernel resource handlers can capture it.
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

    // Persistent session store (SQLite) — sessions survive restarts
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
                // Attach PII filter to blackbox for sanitizing tool args/results
                let bb = match memory_tools::build_pii_sanitizer(cfg.memory_pii_filter()) {
                    Some(filter) => {
                        tracing::info!("Blackbox PII filter enabled");
                        bb.with_pii_filter(filter)
                    }
                    None => bb,
                };
                // Blackbox retention sweep at startup
                if let Some(days) = cfg.memory_audit_retention_days() {
                    let deleted = bb.expire_older_than(days);
                    if deleted > 0 {
                        tracing::info!(
                            deleted = deleted,
                            days = days,
                            "Retention: expired old blackbox entries"
                        );
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

    // Wire path ACLs for gateway-level enforcement on upstream tools.
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

    // IFC + stateless mode: taint persists via server-side sessions
    // keyed by agent name ("stateless:{agent_name}"). This means all
    // clients sharing the same agent identity share taint state — if
    // one reads a secret, all are blocked from writing. This is safe
    // (fails closed) but can over-block in multi-client deployments.
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

    // Register authenticator chain
    builder = setup::auth::wire_auth(builder, &cfg, &root_signer, dev_mode)?;

    // --- Load models into registry ---
    // The model registry is owned by navra-model-server and manages
    // model lifecycle (loading, unloading, runtime process tracking).
    // The gateway extracts the model backends for direct use.
    let model_entries = util::convert_model_configs(&cfg.models);
    let model_registry = navra_model_server::ModelRegistry::from_config(&model_entries)
        .await
        .context("failed to build model registry")?;
    let models = model_registry.models().clone();

    // Keep the registry alive for runtime process management.
    // When the registry is dropped, it logs but doesn't stop runtimes
    // (shutdown is handled below via running_endpoints for backward compat).
    let _model_registry = model_registry;

    // Legacy endpoint tracking for shutdown — still needed for team
    // models added later in containerized mode.
    let mut running_endpoints: Vec<(
        Box<dyn navra_model_runtime::ModelRuntime>,
        navra_model_runtime::Endpoint,
    )> = Vec::new();

    #[cfg(feature = "onnx")]
    let pii_ner_filter: Option<Arc<navra_core::safety::NerFilter>> = {
        let pii_ml_dir = cfg.pii_multilingual_model_dir();
        let pii_en_dir = cfg.pii_model_dir();
        match navra_core::safety::load_ner_filter(&pii_ml_dir) {
            Some(filter) => {
                tracing::info!(
                    dir = %pii_ml_dir.display(),
                    "Multilingual PII NER model loaded (EN, FR, DE, ES, IT, PT, NL)"
                );
                Some(Arc::new(filter))
            }
            None => match navra_core::safety::load_ner_filter(&pii_en_dir) {
                Some(filter) => {
                    tracing::info!(
                        dir = %pii_en_dir.display(),
                        "English PII NER model loaded for semantic entity detection"
                    );
                    Some(Arc::new(filter))
                }
                None => {
                    tracing::info!(
                        "PII NER model not installed. Run 'navra pii download' for semantic PII detection."
                    );
                    None
                }
            },
        }
    };

    #[cfg(feature = "onnx")]
    let privacy_filter: Option<Arc<navra_core::safety::PrivacyFilterModel>> = {
        let privacy_filter_dir = navra_core::safety::default_privacy_filter_model_dir();
        match navra_core::safety::load_privacy_filter(&privacy_filter_dir) {
            Some(filter) => {
                tracing::info!(
                    dir = %privacy_filter_dir.display(),
                    "OpenAI privacy-filter loaded (address, date, secret detection)"
                );
                Some(Arc::new(filter))
            }
            None => {
                tracing::info!(
                    "OpenAI privacy-filter not installed. Download from HuggingFace for address/date/secret PII detection."
                );
                None
            }
        }
    };

    // Build custom PII filter from global pii_patterns config (shared across all pipelines)
    let custom_pii_filter: Option<Arc<navra_core::safety::CustomPiiFilter>> =
        if !cfg.pii_patterns.is_empty() {
            let patterns: Vec<(String, String, String)> = cfg
                .pii_patterns
                .iter()
                .map(|p| (p.name.clone(), p.regex.clone(), p.category.clone()))
                .collect();
            match navra_core::safety::CustomPiiFilter::new(patterns) {
                Ok(filter) => {
                    if filter.has_patterns() {
                        // Register custom categories as PII for IFC labeling
                        navra_core::safety::register_pii_categories(&filter.categories());
                        tracing::info!(
                            patterns = cfg.pii_patterns.len(),
                            categories = ?filter.categories(),
                            "Custom PII patterns loaded"
                        );
                        Some(Arc::new(filter))
                    } else {
                        None
                    }
                }
                Err(e) => {
                    tracing::error!(error = %e, "Failed to compile custom PII patterns");
                    None
                }
            }
        } else {
            None
        };

    // Build shared safety filter state for reuse by both builder-level
    // profiles and the SafetyHook in the hook pipeline.
    let safety_state = setup::safety::SafetyFilterState {
        custom_pii_filter: custom_pii_filter.clone(),
        #[cfg(feature = "onnx")]
        pii_ner_filter: pii_ner_filter.clone(),
        #[cfg(feature = "onnx")]
        privacy_filter: privacy_filter.clone(),
        models: models.clone(),
    };

    // Register safety profiles and per-tool permissions per permission set
    builder = setup::safety::wire_safety_profiles(builder, &cfg, &safety_state);

    // Build shared approval infrastructure
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

    // --- Resolve named models for modules ---
    // Find the first embedding model in the registry.
    let embedding_model_name = cfg
        .models
        .iter()
        .find(|(_, m)| m.task == "embedding")
        .map(|(name, _)| name.clone());
    let embedding_model = embedding_model_name
        .as_ref()
        .and_then(|name| models.get(name))
        .cloned();

    // --- Git module (upstream MCP server) ---
    // Git tools are provided by docker.io/mcp/git as an upstream MCP server.
    // Gateway-level path ACLs enforce repo_path permissions.
    if cfg.git_enabled() {
        let has_git_upstream = cfg
            .upstream
            .iter()
            .any(|u| u.name == "git" || u.name == "mcp-git");
        if !has_git_upstream {
            tracing::warn!(
                "[modules.git] is enabled but no [[upstream]] named 'git' found. \
                 Add to config.toml:\n\
                 [[upstream]]\n\
                 name = \"git\"\n\
                 transport = \"stdio\"\n\
                 command = [\"podman\", \"run\", \"--rm\", \"-i\", \"docker.io/mcp/git\"]"
            );
        }
    }

    // --- Exec module (OpenShell agent sandboxing) ---
    let exec_module: Option<Arc<exec_tools::ExecState>> =
        if let Some(ref gateway) = cfg.server.openshell_gateway {
            let channel = tonic::transport::Channel::from_shared(gateway.clone())
                .expect("valid OpenShell gateway URL")
                .connect_lazy();
            let client = navra_model_runtime::openshell::ComputeDriverClient::new(channel);
            let state = Arc::new(exec_tools::ExecState::new(client));
            tracing::info!(gateway = %gateway, "Tool 'exec_run' enabled (OpenShell)");
            let (def, handler) = exec_tools::exec_run_tool(Arc::clone(&state));
            builder = builder.tool(def, move |args, ctx| {
                let h = Arc::clone(&handler);
                Box::pin(async move { h(args, ctx).await })
            });
            Some(state)
        } else {
            None
        };

    // --- RAG module ---
    // Keep a shared reference to the chunk store so memory tools can
    // cascade-delete embedding vectors when knowledge entries are erased.
    let mut shared_chunk_store: Option<std::sync::Arc<navra_rag::ChunkStore>> = None;
    let mut rag_context_retriever: Option<Arc<dyn navra_agent::ContextRetriever>> = None;

    if cfg.rag_enabled() {
        if let Some(ref model) = embedding_model {
            let rag_db_path = cfg.rag_db_path();
            let dims = embedding_model_name
                .as_ref()
                .and_then(|name| cfg.models.get(name))
                .and_then(|m| m.dimensions)
                .unwrap_or(768);
            match navra_rag::ChunkStore::open(&rag_db_path, dims) {
                Ok(store) => {
                    // Enable semantic query cache if TTL > 0
                    let cache_ttl = cfg.rag_query_cache_ttl_secs();
                    let store = if cache_ttl > 0 {
                        let cache_config = navra_rag::QueryCacheConfig {
                            capacity: cfg.rag_query_cache_max_entries(),
                            ttl: std::time::Duration::from_secs(cache_ttl),
                            ..navra_rag::QueryCacheConfig::default()
                        };
                        tracing::info!(
                            ttl_secs = cache_ttl,
                            max_entries = cfg.rag_query_cache_max_entries(),
                            "RAG query cache enabled"
                        );
                        store.with_query_cache(cache_config)
                    } else {
                        store
                    };

                    let store_arc = std::sync::Arc::new(store);
                    shared_chunk_store = Some(Arc::clone(&store_arc));

                    // Load cross-encoder reranker if configured
                    let reranker: Arc<dyn navra_rag::Reranker> = {
                        let model_path = cfg.rag_reranker_model_path();
                        let tokenizer_path = cfg.rag_reranker_tokenizer_path();
                        let r = navra_rag::load_reranker(
                            model_path
                                .as_ref()
                                .map(|p| std::path::Path::new(p.as_str())),
                            tokenizer_path
                                .as_ref()
                                .map(|p| std::path::Path::new(p.as_str())),
                        );
                        Arc::from(r)
                    };

                    let chunk_config = navra_rag::ChunkConfig {
                        graphability_threshold: Some(0.3),
                        ..navra_rag::ChunkConfig::default()
                    };
                    let cascade = navra_rag::CascadeConfig {
                        bm25_skip_vector_threshold: Some(0.0000001),
                        vector_skip_rerank_threshold: Some(2.0),
                    };
                    let reranker_for_retriever = reranker.clone();
                    let cascade_for_retriever = cascade.clone();
                    let rag = navra_rag::RagModule::with_reranker(
                        store_arc,
                        model.clone(),
                        chunk_config,
                        perm_engine.clone(),
                        reranker,
                    )
                    .with_cascade(cascade)
                    .with_metrics(metrics.clone());
                    rag_context_retriever =
                        Some(Arc::new(crate::rag_retriever::RagRetriever::new(
                            Arc::clone(
                                shared_chunk_store
                                    .as_ref()
                                    .expect("chunk store must be initialized before RAG retriever"),
                            ),
                            model.clone(),
                            reranker_for_retriever,
                            cascade_for_retriever,
                            Some(metrics.clone()),
                        )));
                    tracing::info!(
                        "Module 'rag' enabled (db: {rag_db_path}, dims: {dims}, cascade: on, graphability: 0.3)"
                    );
                    builder = builder.module(rag);
                }
                Err(e) => {
                    tracing::error!("Failed to open RAG store: {e}");
                }
            }
        } else {
            tracing::warn!("RAG module requires an embedding model, skipping");
        }
    }

    // --- Voice module ---
    if let Some(voice_cfg) = cfg.modules.voice.as_ref().filter(|_| cfg.voice_enabled()) {
        let asr = models.get(&voice_cfg.asr_model).cloned();
        let tts = models.get(&voice_cfg.tts_model).cloned();

        match (asr, tts) {
            (Some(asr_model), Some(tts_model)) => {
                let voice = navra_modal_voice::VoiceModule::with_config(
                    asr_model,
                    tts_model,
                    voice_cfg.vad_threshold,
                    voice_cfg.max_record_secs,
                    voice_cfg.silence_timeout_ms,
                    voice_cfg.voice.clone(),
                    perm_engine.clone(),
                );
                tracing::info!(
                    asr = %voice_cfg.asr_model,
                    tts = %voice_cfg.tts_model,
                    "Module 'voice' enabled"
                );
                builder = builder.module(voice);
            }
            (None, _) => {
                tracing::warn!(
                    model = %voice_cfg.asr_model,
                    "Voice module: ASR model '{}' not found, skipping",
                    voice_cfg.asr_model
                );
            }
            (_, None) => {
                tracing::warn!(
                    model = %voice_cfg.tts_model,
                    "Voice module: TTS model '{}' not found, skipping",
                    voice_cfg.tts_model
                );
            }
        }
    }

    // --- Vision module ---
    if let Some(vision_cfg) = cfg.modules.vision.as_ref().filter(|_| cfg.vision_enabled()) {
        if let Some(vision_model) = models.get(&vision_cfg.model).cloned() {
            let vision = navra_modal_vision::VisionModule::new(vision_model, perm_engine.clone());
            tracing::info!(model = %vision_cfg.model, "Module 'vision' enabled");
            builder = builder.module(vision);
        } else {
            tracing::warn!(
                model = %vision_cfg.model,
                "Vision module: model '{}' not found, skipping",
                vision_cfg.model
            );
        }
    }

    // --- Load ForgeService for persona auto-discovery ---
    // Loaded once here so upstream persona: prompts can be registered
    // before the forge is shared with other subsystems.
    let mut forge = if let Some(ref cc_path) = cfg.cognitive_core {
        let expanded = util::expand_tilde(cc_path);
        match navra_cognitive::ForgeService::load(std::path::Path::new(&expanded)) {
            Ok(f) => f,
            Err(e) => {
                tracing::warn!(error = %e, "Failed to load cognitive core, using empty forge");
                navra_cognitive::ForgeService::empty()
            }
        }
    } else {
        navra_cognitive::ForgeService::empty()
    };

    // --- AID upstream discovery ---
    if !cfg.discover.is_empty() {
        tracing::info!(
            domains = cfg.discover.len(),
            "Discovering upstream MCP servers via AID"
        );
        let discovery_timeout = cfg
            .server
            .discovery
            .as_ref()
            .map(|d| std::time::Duration::from_secs(d.timeout_secs))
            .unwrap_or_else(|| std::time::Duration::from_secs(10));
        let discovered =
            discover::discover_all_with_timeout(&cfg.discover, discovery_timeout).await;
        for endpoint in &discovered {
            tracing::info!(
                domain = %endpoint.domain,
                url = %endpoint.url,
                description = ?endpoint.description,
                auth = ?endpoint.auth,
                "Discovered MCP endpoint"
            );
            let transport =
                rmcp::transport::StreamableHttpClientTransport::from_uri(endpoint.url.clone());
            match rmcp::service::ServiceExt::<rmcp::RoleClient>::serve((), transport).await {
                Ok(client) => {
                    let peer = client.peer().clone();
                    tokio::spawn(async move {
                        let _ = client.waiting().await;
                    });
                    let module = navra_core::UpstreamModule::discover(
                        &endpoint.domain,
                        peer,
                        None,
                        &Default::default(),
                    )
                    .await;
                    tracing::info!(
                        domain = %endpoint.domain,
                        "Connected discovered upstream (rmcp)"
                    );
                    for prompt_def in module.discovered_prompts() {
                        if let Some(persona_name) = prompt_def.name.strip_prefix("persona:") {
                            let description = prompt_def.description.as_deref().unwrap_or("");
                            forge.register_upstream_persona(
                                persona_name,
                                module.upstream_name(),
                                &prompt_def.name,
                                description,
                            );
                        }
                    }
                    builder = builder.module(module);
                }
                Err(e) => {
                    tracing::warn!(
                        domain = %endpoint.domain,
                        error = %e,
                        "Failed to connect to discovered endpoint"
                    );
                }
            }
        }
        if discovered.is_empty() && !cfg.discover.is_empty() {
            tracing::info!("No MCP endpoints discovered via AID");
        }
    }

    // --- mDNS/DNS-SD LAN discovery ---
    let mdns_enabled = cfg
        .server
        .discovery
        .as_ref()
        .map(|d| d.mdns)
        .unwrap_or(false);
    // Keep the daemon alive for advertising — drop stops it.
    let mut _mdns_daemon: Option<mdns_sd::ServiceDaemon> = None;

    if mdns_enabled {
        let mdns_browse_secs = cfg
            .server
            .discovery
            .as_ref()
            .map(|d| d.mdns_browse_secs)
            .unwrap_or(3);
        tracing::info!("Browsing LAN for MCP servers via mDNS...");
        let lan_servers = mdns::browse(std::time::Duration::from_secs(mdns_browse_secs)).await;

        for server in &lan_servers {
            let url = server.url();
            let transport = rmcp::transport::StreamableHttpClientTransport::from_uri(url.clone());
            match rmcp::service::ServiceExt::<rmcp::RoleClient>::serve((), transport).await {
                Ok(client) => {
                    let peer = client.peer().clone();
                    tokio::spawn(async move {
                        let _ = client.waiting().await;
                    });
                    let module = navra_core::UpstreamModule::discover(
                        &server.name,
                        peer,
                        None,
                        &Default::default(),
                    )
                    .await;
                    tracing::info!(
                        name = %server.name,
                        url = %url,
                        "Connected LAN upstream (rmcp)"
                    );
                    for prompt_def in module.discovered_prompts() {
                        if let Some(persona_name) = prompt_def.name.strip_prefix("persona:") {
                            let description = prompt_def.description.as_deref().unwrap_or("");
                            forge.register_upstream_persona(
                                persona_name,
                                module.upstream_name(),
                                &prompt_def.name,
                                description,
                            );
                        }
                    }
                    builder = builder.module(module);
                }
                Err(e) => {
                    tracing::debug!(
                        name = %server.name,
                        error = %e,
                        "Failed to connect to LAN upstream"
                    );
                }
            }
        }
    }

    // --- Upstream MCP servers ---
    builder =
        setup::upstream::wire_upstream(builder, &cfg, &credential_store, &mut forge).await;

    // --- gRPC out-of-process modules ---
    let mut _grpc_manager = if !cfg.grpc_modules.is_empty() {
        let mut manager = grpc_manager::GrpcModuleManager::new(cfg.grpc_modules.clone());
        let modules = manager.start_all().await;
        for module in modules {
            tracing::info!(module = module.name(), "Connected gRPC module");
            builder = builder.module(module);
        }
        Some(manager)
    } else {
        None
    };

    // Register cap_delegate tool if any agent can delegate
    if cfg.permissions.values().any(|ps| ps.can_delegate) {
        let delegate_signer = Arc::clone(&root_signer);
        let delegate_permissions = cfg.permissions.clone();
        let max_depth = cfg
            .server
            .identity
            .as_ref()
            .map(|i| i.max_delegation_depth)
            .unwrap_or(3);
        let default_ttl = cfg
            .server
            .identity
            .as_ref()
            .map(|i| i.token_ttl)
            .unwrap_or(3600);

        builder = builder.tool(
            navra_core::protocol::ToolDefinition::new(
                "cap_delegate",
                "Issue an attenuated capability token for a sub-agent. \
                     The new token grants a subset of the caller's capabilities.",
                navra_protocol::compat::tool_input_schema(
                    {
                        let mut props = std::collections::HashMap::new();
                        props.insert(
                            "subject_did".to_string(),
                            serde_json::json!({
                                "type": "string",
                                "description": "DID of the sub-agent receiving the token"
                            }),
                        );
                        props.insert(
                            "ring".to_string(),
                            serde_json::json!({
                                "type": "integer",
                                "description": "Ring level (must be >= caller's ring)"
                            }),
                        );
                        props.insert(
                            "operations".to_string(),
                            serde_json::json!({
                                "type": "array", "items": { "type": "string" },
                                "description": "Operations to grant (subset of caller's)"
                            }),
                        );
                        props.insert(
                            "tools".to_string(),
                            serde_json::json!({
                                "type": "array", "items": { "type": "string" },
                                "description": "Tool globs to grant (subset of caller's)"
                            }),
                        );
                        props.insert(
                            "paths".to_string(),
                            serde_json::json!({
                                "type": "array", "items": { "type": "string" },
                                "description": "Path globs to grant (subset of caller's)"
                            }),
                        );
                        props.insert(
                            "credentials".to_string(),
                            serde_json::json!({
                                "type": "array", "items": { "type": "string" },
                                "description": "Credential labels to grant (subset of caller's)"
                            }),
                        );
                        props.insert(
                            "ttl".to_string(),
                            serde_json::json!({
                                "type": "integer",
                                "description": "Token TTL in seconds"
                            }),
                        );
                        Some(props)
                    },
                    Some(vec!["subject_did".to_string()]),
                ),
            ),
            move |args, ctx| {
                let signer = Arc::clone(&delegate_signer);
                let permissions = delegate_permissions.clone();
                let max_depth = max_depth;
                let default_ttl = default_ttl;
                Box::pin(async move {
                    use navra_core::auth::capability::{
                        CapabilitySet, build_payload, encode_token, validate_delegation,
                    };
                    use navra_core::protocol::CallToolResult;

                    // Check caller has capabilities (must be cap-token authenticated)
                    // Reject callers with wildcard tool access — cap_delegate must
                    // be explicitly listed in the token's tools (CWE-269).
                    let parent_caps = match &ctx.agent.capabilities {
                        Some(caps) => {
                            if !caps.tools.iter().any(|t| t == "cap_delegate") {
                                return CallToolResult::error_msg(
                                    "Permission denied: cap_delegate must be explicitly \
                                     listed in capability token tools (wildcard not accepted)",
                                );
                            }
                            caps
                        }
                        None => {
                            // Legacy agent — check can_delegate via permission set
                            let perm_name = &ctx.agent.permissions;
                            let can_delegate = permissions
                                .get(perm_name)
                                .map(|ps| ps.can_delegate)
                                .unwrap_or(false);
                            if !can_delegate {
                                return CallToolResult::error_msg(
                                    "Permission denied: delegation not allowed for this agent",
                                );
                            }
                            // Build a pseudo-parent from permission set for validation
                            return CallToolResult::error_msg(
                                "Delegation requires a capability token. \
                                 Use a capability-token-authenticated session.",
                            );
                        }
                    };

                    let subject_did = args
                        .get("subject_did")
                        .and_then(|v| v.as_str())
                        .unwrap_or("")
                        .to_string();
                    if subject_did.is_empty() {
                        return CallToolResult::error_msg("subject_did is required");
                    }

                    let ring = args
                        .get("ring")
                        .and_then(|v| v.as_u64())
                        .unwrap_or(parent_caps.ring as u64) as u8;

                    let operations: Vec<String> = args
                        .get("operations")
                        .and_then(|v| v.as_array())
                        .map(|arr| {
                            arr.iter()
                                .filter_map(|v| v.as_str().map(String::from))
                                .collect()
                        })
                        .unwrap_or_else(|| parent_caps.operations.iter().cloned().collect());

                    let tools: Vec<String> = args
                        .get("tools")
                        .and_then(|v| v.as_array())
                        .map(|arr| {
                            arr.iter()
                                .filter_map(|v| v.as_str().map(String::from))
                                .collect()
                        })
                        .unwrap_or_else(|| parent_caps.tools.clone());

                    let paths: Vec<String> = args
                        .get("paths")
                        .and_then(|v| v.as_array())
                        .map(|arr| {
                            arr.iter()
                                .filter_map(|v| v.as_str().map(String::from))
                                .collect()
                        })
                        .unwrap_or_else(|| parent_caps.paths.clone());

                    let credentials: Vec<String> = args
                        .get("credentials")
                        .and_then(|v| v.as_array())
                        .map(|arr| {
                            arr.iter()
                                .filter_map(|v| v.as_str().map(String::from))
                                .collect()
                        })
                        .unwrap_or_else(|| parent_caps.credentials.clone());

                    let ttl = args
                        .get("ttl")
                        .and_then(|v| v.as_u64())
                        .unwrap_or(default_ttl);

                    let cap_set = CapabilitySet {
                        paths,
                        operations,
                        tools,
                        credentials,
                    };

                    let issuer_did = ctx
                        .agent
                        .did
                        .clone()
                        .unwrap_or_else(|| format!("agent:{}", ctx.agent.name));

                    let mut child_payload =
                        build_payload(&issuer_did, &subject_did, cap_set, ring, ttl);

                    // Build parent payload for validation
                    let parent_payload = navra_core::auth::capability::CapabilityPayload {
                        v: 1,
                        iss: signer.did().to_string(),
                        sub: issuer_did.clone(),
                        cap: CapabilitySet {
                            paths: parent_caps.paths.clone(),
                            operations: parent_caps.operations.iter().cloned().collect(),
                            tools: parent_caps.tools.clone(),
                            credentials: parent_caps.credentials.clone(),
                        },
                        ring: parent_caps.ring,
                        iat: 0,
                        exp: parent_caps.expires_at,
                        nonce: navra_core::auth::capability::generate_nonce(),
                        parent: None,
                        obo: None,
                        sandbox: None,
                        aud: None,
                    };

                    // Set parent nonce reference
                    child_payload.parent = Some(parent_payload.nonce);

                    // Validate attenuation
                    if let Err(e) = validate_delegation(&parent_payload, &child_payload, max_depth)
                    {
                        return CallToolResult::error_msg(format!("Delegation denied: {e}"));
                    }

                    // Sign with root key (navra signs all tokens)
                    match encode_token(&child_payload, signer.as_ref()) {
                        Ok(token) => {
                            tracing::info!(
                                issuer = %issuer_did,
                                subject = %subject_did,
                                ring = ring,
                                "Delegated capability token"
                            );
                            CallToolResult::text(token)
                        }
                        Err(e) => CallToolResult::error_msg(format!("Failed to sign token: {e}")),
                    }
                })
            },
        );
        tracing::info!("Registered cap_delegate tool");
    }

    // Register sys_status tool (process table viewer)
    {
        builder = builder.tool(
            navra_core::protocol::ToolDefinition::new(
                "sys_status",
                "Show AI OS process table: active agents, their rings, \
                     call counts, and active tool calls.",
                navra_protocol::compat::tool_input_schema(None, None),
            ),
            |_args, _ctx| {
                // The actual data comes from the server's process table,
                // but the handler doesn't have access to &self.
                // We return a placeholder — the real implementation
                // will be added when we refactor tool handlers to
                // receive a server reference.
                Box::pin(async {
                    navra_core::protocol::CallToolResult::text(
                        "sys_status: use GET /sys/status for process table",
                    )
                })
            },
        );
    }

    // Resolve flow directories (auto-discover if not configured)
    let resolved_flow_dirs = {
        let mut dirs = cfg.flow_dirs.clone();
        if dirs.is_empty() {
            for candidate in &["examples/flows", "flows"] {
                if std::path::Path::new(candidate).is_dir() {
                    dirs.push(candidate.to_string());
                }
            }
        }
        dirs
    };

    // Open audit log early so it can be shared with flow tools and audit_query.
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
            Ok(n) if n > 0 => tracing::info!(
                deleted = n,
                days = days,
                "Retention: expired old audit entries"
            ),
            _ => {}
        }
    }

    // Register flow orchestration tools
    let flow_registry = Arc::new(flow_tools::FlowRegistry::new());
    let team_registry_ref: Arc<team_tools::TeamRegistry>;
    {
        // flow_start — registered later, after team_registry is created

        // flow_status — check progress of a flow
        let registry = Arc::clone(&flow_registry);
        builder = builder.tool(flow_tools::flow_status_tool_def(), move |args, _ctx| {
            let registry = Arc::clone(&registry);
            Box::pin(flow_tools::handle_flow_status(args, registry))
        });

        // flow_result — get output from a completed flow or node
        let registry = Arc::clone(&flow_registry);
        let fr_audit = Arc::clone(&audit_log);
        builder = builder.tool(flow_tools::flow_result_tool_def(), move |args, _ctx| {
            let registry = Arc::clone(&registry);
            let audit = Arc::clone(&fr_audit);
            Box::pin(flow_tools::handle_flow_result(args, registry, Some(audit)))
        });

        // flow_list — list available YAML flows from configured directories
        let flow_dirs = resolved_flow_dirs.clone();
        builder = builder.tool(flow_tools::flow_list_tool_def(), move |_args, _ctx| {
            let flow_dirs = flow_dirs.clone();
            Box::pin(flow_tools::handle_flow_list(flow_dirs))
        });

        tracing::info!(
            "Registered flow orchestration tools (flow_start, flow_status, flow_result, flow_list, flow_escalate)"
        );
    }

    // Trigger infrastructure: initialized after flow_ctx is built.
    let mut _trigger_registry: Option<triggers::TriggerRegistry> = None;
    let mut trigger_webhook_router: Option<axum::Router> = None;

    // Register team orchestration tools
    {
        // Pre-fetch Ollama model metadata for all locally running models.
        // This populates vendor fields (family, parameters, context_window)
        // so the lead agent can make informed model selection decisions.
        let mut ollama_meta: std::collections::HashMap<String, serde_json::Value> =
            std::collections::HashMap::new();
        if let Ok(resp) = reqwest::Client::new()
            .get("http://localhost:11434/api/tags")
            .send()
            .await
            && let Ok(tags) = resp.json::<serde_json::Value>().await
            && let Some(models) = tags["models"].as_array()
        {
            for m in models {
                if let Some(name) = m["name"].as_str() {
                    // Query /api/show for detailed model info
                    if let Ok(show_resp) = reqwest::Client::new()
                        .post("http://localhost:11434/api/show")
                        .json(&serde_json::json!({"name": name}))
                        .send()
                        .await
                        && let Ok(info) = show_resp.json::<serde_json::Value>().await
                    {
                        ollama_meta.insert(name.to_string(), info);
                    }
                }
            }
        }
        if !ollama_meta.is_empty() {
            tracing::info!(
                models = ollama_meta.len(),
                "Fetched Ollama model metadata for model cards"
            );
        }

        // Build composite model cards from config + discovered Ollama models.
        // Config entries take precedence; Ollama models not in config are added automatically.
        let mut model_keys: Vec<(String, Option<&config::ModelConfig>)> = cfg
            .models
            .iter()
            .map(|(k, v)| (k.clone(), Some(v)))
            .collect();
        let configured_sources: std::collections::HashSet<String> = cfg
            .models
            .values()
            .filter_map(|m| m.source.as_ref())
            .filter_map(|s| s.strip_prefix("ollama://"))
            .map(|s| s.to_string())
            .collect();
        for name in ollama_meta.keys() {
            if !configured_sources.contains(name) {
                model_keys.push((name.clone(), None));
            }
        }

        let model_cards: Vec<team_tools::ModelCard> = model_keys
            .iter()
            .map(|(name, mcfg_opt)| {
                let mcfg_ref = mcfg_opt.as_ref();
                let display_name = mcfg_ref
                    .and_then(|m| m.model_name.as_deref())
                    .unwrap_or(name);
                let uri_str = mcfg_ref
                    .and_then(|m| m.source.as_deref())
                    .unwrap_or(display_name);
                let mut card = navra_model_hub::ModelCard::new(uri_str);

                // Populate vendor metadata from config (if available)
                if let Some(mcfg) = mcfg_ref {
                    card.vendor.source = Some(
                        if mcfg.source.is_some() {
                            match mcfg.source.as_deref() {
                                Some(s) if s.starts_with("ollama://") => "ollama",
                                Some(s) if s.starts_with("hf://") => "huggingface",
                                Some(s) if s.starts_with("oci://") => "oci",
                                _ => "local",
                            }
                        } else {
                            "local"
                        }
                        .into(),
                    );
                    card.vendor.context_window = mcfg.context_size;
                    card.vendor.tasks = match mcfg.task.as_str() {
                        "chat" | "generate" => vec!["text-generation".into()],
                        "embedding" => vec!["feature-extraction".into()],
                        "classification" => vec!["text-classification".into()],
                        _ => vec![],
                    };
                    if let Some(runtime) = &mcfg.runtime {
                        card.vendor.runtime = Some(runtime.clone());
                    }
                }

                // Enrich with Ollama /api/show metadata if available
                if let Some(info) = ollama_meta.get(display_name) {
                    card.vendor.source = Some("ollama".into());
                    // model_info contains parameter count, architecture, etc.
                    if let Some(model_info) = info.get("model_info") {
                        // Extract context window from model metadata
                        for (key, val) in model_info.as_object().into_iter().flatten() {
                            if key.ends_with(".context_length")
                                && let Some(ctx) = val.as_u64()
                            {
                                card.vendor.context_window = Some(ctx as u32);
                            }
                            if key.ends_with(".embedding_length")
                                && let Some(dim) = val.as_u64()
                            {
                                card.vendor
                                    .custom
                                    .insert("embedding_dim".into(), serde_json::json!(dim));
                            }
                        }
                        // Parameter count from general.parameter_count
                        if let Some(params) = model_info.get("general.parameter_count")
                            && let Some(p) = params.as_u64()
                        {
                            let label = if p >= 1_000_000_000 {
                                format!("{}B", p / 1_000_000_000)
                            } else if p >= 1_000_000 {
                                format!("{}M", p / 1_000_000)
                            } else {
                                format!("{p}")
                            };
                            card.vendor.parameters = Some(label);
                        }
                        // Architecture / family
                        if let Some(arch) = model_info.get("general.architecture")
                            && let Some(a) = arch.as_str()
                        {
                            card.vendor.family = Some(a.to_string());
                        }
                    }
                    // Quantization from details
                    if let Some(details) = info.get("details") {
                        if let Some(quant) = details.get("quantization_level")
                            && let Some(q) = quant.as_str()
                        {
                            card.vendor.quantization = Some(q.to_string());
                        }
                        if let Some(family) = details.get("family")
                            && card.vendor.family.is_none()
                        {
                            card.vendor.family = family.as_str().map(|s| s.to_string());
                        }
                    }
                    // License from license field
                    if let Some(license) = info.get("license")
                        && let Some(l) = license.as_str()
                    {
                        // Take first line as the license identifier
                        card.vendor.license = l.lines().next().map(|s| s.to_string());
                    }
                    card.vendor.format = Some("gguf".into());
                }

                // Detect Claude/Anthropic models
                if display_name.starts_with("claude") {
                    card.vendor.source = Some("anthropic".into());
                    card.vendor.family = Some("claude".into());
                    // Extract parameter hint from model name (e.g. "sonnet", "opus")
                    if display_name.contains("sonnet") {
                        card.vendor.parameters = Some("medium".into());
                    } else if display_name.contains("opus") {
                        card.vendor.parameters = Some("large".into());
                    } else if display_name.contains("haiku") {
                        card.vendor.parameters = Some("small".into());
                    }
                }

                // Merge operator-defined agentic metadata from config
                if let Some(mcfg) = mcfg_ref
                    && let Some(agentic_cfg) = &mcfg.agentic
                {
                    card.merge_agentic(&agentic_cfg.to_agentic_meta());
                }

                card
            })
            .collect();

        let team_registry = Arc::new(team_tools::TeamRegistry::new().with_models(model_cards));

        // Containerized agent execution: detect mode and start shared model server
        let containerized = match cfg.server.containerized {
            Some(true) => {
                if team_tools::is_podman_available() {
                    true
                } else {
                    tracing::warn!(
                        "Containerized mode requested but Podman not available, falling back to in-process"
                    );
                    false
                }
            }
            Some(false) => false,
            None => team_tools::is_podman_available(),
        };

        let model_server_url: Option<String> = if containerized {
            match start_model_server_container(&cfg).await {
                Ok((url, port, name)) => {
                    tracing::info!(url = %url, container = %name, "Shared model server started");
                    // Track container for shutdown
                    running_endpoints.push((
                        Box::new(navra_model_runtime::podman::PodmanRuntime::new(
                            navra_model_runtime::Engine::LlamaCpp,
                        )),
                        navra_model_runtime::Endpoint {
                            url: format!("http://127.0.0.1:{port}"),
                            id: name,
                            backend: navra_model_runtime::RuntimeBackend::new(
                                navra_model_runtime::Engine::LlamaCpp,
                                navra_model_runtime::Isolation::Podman,
                            ),
                        },
                    ));
                    Some(url)
                }
                Err(e) => {
                    tracing::warn!(error = %e, "Failed to start model server container, agents will use Ollama");
                    None
                }
            }
        } else {
            None
        };

        let gpu_semaphore = Arc::new(tokio::sync::Semaphore::new(
            if cfg.budget.max_parallel == 0 {
                64
            } else {
                cfg.budget.max_parallel
            },
        ));

        if containerized {
            tracing::info!(
                agent_image = %cfg.server.agent_image,
                model_server = ?model_server_url,
                "Containerized agent execution enabled"
            );
        }

        // team_create
        let reg = Arc::clone(&team_registry);
        let tc_budget_cfg = cfg.budget.clone();
        builder = builder.tool(team_tools::team_create_def(), move |args, ctx| {
            let reg = Arc::clone(&reg);
            let budget_cfg = tc_budget_cfg.clone();
            let agent_name = ctx.agent.name.clone();
            Box::pin(async move {
                team_tools::handle_team_create(args, reg, &budget_cfg, &agent_name).await
            })
        });

        // team_add
        let reg = Arc::clone(&team_registry);
        builder = builder.tool(team_tools::team_add_def(), move |args, _ctx| {
            let reg = Arc::clone(&reg);
            Box::pin(team_tools::handle_team_add(args, reg))
        });

        // Root capability payload for teammate token delegation.
        // Grants all operations and tools that teammates could possibly use.
        // Individual teammate tokens are scoped down from this via
        // build_delegated_payload (attenuation-only delegation chain).
        let root_cap = navra_core::auth::capability::CapabilitySet {
            paths: vec!["**".to_string()],
            operations: vec![
                "read".to_string(),
                "write".to_string(),
                "search".to_string(),
                "list".to_string(),
                "git.status".to_string(),
                "git.diff".to_string(),
                "git.log".to_string(),
                "git.commit".to_string(),
                "git.branch".to_string(),
            ],
            tools: vec!["*".to_string()],
            credentials: vec![],
        };
        let root_payload = navra_core::auth::capability::build_payload(
            root_signer.did(),
            root_signer.did(),
            root_cap,
            1,
            86400,
        );

        // Build a PII filter for model reasoning text. Uses "standard"
        // safety profile (regex PII + NER) to redact PII that the model
        // echoes in its reasoning even after tool results were redacted.
        let reasoning_pii_filter: Option<Arc<navra_core::safety::FilterPipeline>> = {
            let has_pii_profile = cfg.permissions.values().any(|p| {
                matches!(
                    p.safety.as_str(),
                    "standard" | "guardian" | "guardian-deep" | "block"
                )
            });
            if has_pii_profile {
                #[cfg(feature = "onnx")]
                let mut pipeline = navra_core::safety::build_pipeline("standard");
                #[cfg(not(feature = "onnx"))]
                let pipeline = navra_core::safety::build_pipeline("standard");
                #[cfg(feature = "onnx")]
                if let Some(ref ner) = pii_ner_filter {
                    pipeline.add_ner_filter_shared(Arc::clone(ner));
                }
                #[cfg(feature = "onnx")]
                if let Some(ref pf) = privacy_filter {
                    pipeline.add_privacy_filter_shared(Arc::clone(pf));
                }
                tracing::info!("PII filter enabled for model reasoning text");
                Some(Arc::new(pipeline))
            } else {
                None
            }
        };

        // team_message — async: spawns full agent teammate in background
        let msg_spawn_ctx = Arc::new(team_tools::TeammateSpawnContext {
            team_registry: Arc::clone(&team_registry),
            navra_addr: cfg.server.listen_addr(),
            signer: Arc::clone(&root_signer),
            forge: cfg.cognitive_core.as_ref().and_then(|p| {
                let expanded = util::expand_tilde(p);
                navra_cognitive::ForgeService::load(std::path::Path::new(&expanded))
                    .map(Arc::new)
                    .ok()
            }),
            root_payload: Some(root_payload.clone()),
            pii_filter: reasoning_pii_filter.clone(),
            audit_log: Some(Arc::clone(&audit_log)),
            cognitive_core_path: cfg.cognitive_core.as_ref().map(|p| util::expand_tilde(p)),
            model_server_url: model_server_url.clone(),
            gpu_semaphore: Arc::clone(&gpu_semaphore),
            containerized,
            agent_image: cfg.server.agent_image.clone(),
            container_memory: cfg.server.container_memory.clone(),
            container_cpus: cfg.server.container_cpus.clone(),
            container_pids: cfg.server.container_pids,
            embedding_model: embedding_model.clone(),
            openshell_gateway: cfg.server.openshell_gateway.clone(),
            exec_state: exec_module.clone(),
            workspace_provider: None,
            max_tokens_per_run: cfg.budget.max_tokens_per_run,
            compression_start_ratio: cfg.budget.compression_start_ratio,
            compaction_keep_recent: cfg.budget.compaction_keep_recent,
            compaction_trigger_ratio: cfg.budget.compaction_trigger_ratio,
        });
        builder = builder.tool(team_tools::team_message_def(), move |args, _ctx| {
            let spawn_ctx = Arc::clone(&msg_spawn_ctx);
            Box::pin(async move { team_tools::handle_team_message(args, &spawn_ctx).await })
        });

        // team_status
        let reg = Arc::clone(&team_registry);
        builder = builder.tool(team_tools::team_status_def(), move |args, _ctx| {
            let reg = Arc::clone(&reg);
            Box::pin(team_tools::handle_team_status(args, reg))
        });

        // team_result
        let reg = Arc::clone(&team_registry);
        builder = builder.tool(team_tools::team_result_def(), move |args, _ctx| {
            let reg = Arc::clone(&reg);
            Box::pin(team_tools::handle_team_result(args, reg))
        });

        // team_shutdown
        let reg = Arc::clone(&team_registry);
        builder = builder.tool(team_tools::team_shutdown_def(), move |args, _ctx| {
            let reg = Arc::clone(&reg);
            Box::pin(team_tools::handle_team_shutdown(args, reg))
        });

        // agent_signal
        let reg = Arc::clone(&team_registry);
        builder = builder.tool(team_tools::agent_signal_def(), move |args, _ctx| {
            let reg = Arc::clone(&reg);
            Box::pin(team_tools::handle_agent_signal(args, reg))
        });

        // models_list
        let cards = team_registry.model_cards.clone();
        builder = builder.tool(team_tools::models_list_def(), move |_args, _ctx| {
            let cards = cards.clone();
            Box::pin(team_tools::handle_models_list(cards))
        });

        // personas_list
        let persona_data: Vec<serde_json::Value> = if let Some(ref cc_path) = cfg.cognitive_core {
            let expanded = util::expand_tilde(cc_path);
            match navra_cognitive::ForgeService::load(std::path::Path::new(&expanded)) {
                Ok(forge) => forge
                    .persona_names()
                    .iter()
                    .filter_map(|name| {
                        forge.get_persona(name).map(|p| {
                            serde_json::json!({
                                "name": p.persona_name,
                                "display_name": p.display_name,
                                "mandate": p.core_mandate.lines().next().unwrap_or(""),
                                "heuristics": p.heuristics.len(),
                                "tools": p.tools,
                            })
                        })
                    })
                    .collect(),
                Err(_) => vec![],
            }
        } else {
            vec![]
        };
        builder = builder.tool(team_tools::personas_list_def(), move |_args, _ctx| {
            let data = persona_data.clone();
            Box::pin(team_tools::handle_personas_list(data))
        });

        // team_bb_publish
        let reg = Arc::clone(&team_registry);
        builder = builder.tool(team_tools::team_bb_publish_def(), move |args, ctx| {
            let reg = Arc::clone(&reg);
            let agent_name = ctx.agent.name.clone();
            let label = ctx.taint.level();
            Box::pin(async move {
                team_tools::handle_team_bb_publish(args, reg, &agent_name, label).await
            })
        });

        // team_bb_read
        let reg = Arc::clone(&team_registry);
        builder = builder.tool(team_tools::team_bb_read_def(), move |args, _ctx| {
            let reg = Arc::clone(&reg);
            Box::pin(team_tools::handle_team_bb_read(args, reg))
        });

        // team_bb_notifications
        let reg = Arc::clone(&team_registry);
        builder = builder.tool(team_tools::team_bb_notifications_def(), move |args, ctx| {
            let reg = Arc::clone(&reg);
            let agent_name = ctx.agent.name.clone();
            Box::pin(async move {
                team_tools::handle_team_bb_notifications(args, reg, &agent_name).await
            })
        });

        tracing::info!(
            "Registered team tools (team_create, team_add, team_message, team_status, team_result, team_shutdown, team_bb_publish, team_bb_read, team_bb_notifications, models_list)"
        );

        // Initialize checkpoint store if enabled
        let checkpoint = if cfg.budget.checkpoint {
            let db_path = util::expand_tilde(&cfg.budget.checkpoint_db);
            match navra_flow::DagCheckpoint::open(std::path::Path::new(&db_path)) {
                Ok(cp) => {
                    tracing::info!(path = %db_path, "Flow checkpoint store opened");
                    if let Ok(incomplete) = cp.list_incomplete()
                        && !incomplete.is_empty()
                    {
                        tracing::info!(
                            count = incomplete.len(),
                            flows = ?incomplete,
                            "Found incomplete flows from previous run (use flow_resume to continue)"
                        );
                    }
                    Some(Arc::new(cp))
                }
                Err(e) => {
                    tracing::warn!(path = %db_path, error = %e, "Failed to open checkpoint store — checkpointing disabled");
                    None
                }
            }
        } else {
            None
        };

        // flow_start and flow_escalate — shared context
        let flow_ctx = Arc::new(flow_tools::FlowContext {
            flow_registry: Arc::clone(&flow_registry),
            team_registry: Arc::clone(&team_registry),
            navra_addr: cfg.server.listen_addr(),
            signer: Arc::clone(&root_signer),
            forge: cfg.cognitive_core.as_ref().and_then(|p| {
                let expanded = util::expand_tilde(p);
                navra_cognitive::ForgeService::load(std::path::Path::new(&expanded))
                    .ok()
                    .map(Arc::new)
            }),
            budget_cfg: cfg.budget.clone(),
            flow_dirs: resolved_flow_dirs.clone(),
            docs_root: cfg
                .modules
                .file
                .as_ref()
                .and_then(|d| d.default_root.clone())
                .or_else(|| cfg.cognitive_core.clone()),
            root_payload: Some(root_payload.clone()),
            pii_filter: reasoning_pii_filter.clone(),
            audit_log: Some(Arc::clone(&audit_log)),
            cognitive_core_path: cfg.cognitive_core.as_ref().map(|p| util::expand_tilde(p)),
            model_server_url: model_server_url.clone(),
            gpu_semaphore: Arc::clone(&gpu_semaphore),
            containerized,
            agent_image: cfg.server.agent_image.clone(),
            container_memory: cfg.server.container_memory.clone(),
            container_cpus: cfg.server.container_cpus.clone(),
            container_pids: cfg.server.container_pids,
            embedding_model: embedding_model.clone(),
            openshell_gateway: cfg.server.openshell_gateway.clone(),
            exec_state: exec_module.clone(),
            workspace_provider: None,
            checkpoint,
        });

        // flow_start
        let fs_ctx = Arc::clone(&flow_ctx);
        builder = builder.tool(flow_tools::flow_start_tool_def(), move |args, ctx| {
            let flow_ctx = Arc::clone(&fs_ctx);
            let agent_name = ctx.agent.name.clone();
            Box::pin(
                async move { flow_tools::handle_flow_start(args, flow_ctx, &agent_name).await },
            )
        });

        // flow_escalate
        let fe_ctx = Arc::clone(&flow_ctx);
        builder = builder.tool(flow_tools::flow_escalate_tool_def(), move |args, ctx| {
            let flow_ctx = Arc::clone(&fe_ctx);
            let agent_name = ctx.agent.name.clone();
            Box::pin(
                async move { flow_tools::handle_flow_escalate(args, flow_ctx, &agent_name).await },
            )
        });

        let fr_ctx = Arc::clone(&flow_ctx);
        builder = builder.tool(flow_tools::flow_resume_tool_def(), move |args, ctx| {
            let flow_ctx = Arc::clone(&fr_ctx);
            let agent = ctx.agent.name.clone();
            Box::pin(async move { flow_tools::handle_flow_resume(args, flow_ctx, &agent).await })
        });

        tracing::info!("Registered flow tools (flow_escalate, flow_resume)");

        // --- Event-driven triggers ---
        if !cfg.triggers.is_empty() {
            let (registry, webhook_router) =
                triggers::TriggerRegistry::start(&cfg.triggers, Arc::clone(&flow_ctx));
            tracing::info!(count = cfg.triggers.len(), "Trigger infrastructure started");
            _trigger_registry = Some(registry);
            trigger_webhook_router = Some(webhook_router);
        }
        team_registry_ref = team_registry;
    }

    // --- Knowledge memory tools ---
    let pii_metrics: Option<Arc<navra_core::safety::PiiMetrics>> = {
        let m = Arc::new(navra_core::safety::PiiMetrics::new());
        Some(m)
    };
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

    if let Some(ks) = knowledge_store.clone() {
        let ks_store = Arc::clone(&ks);
        let sanitizer_for_store = pii_sanitizer.clone();
        builder = builder.tool(memory_tools::memory_store_def(), move |args, _ctx| {
            let ks = Arc::clone(&ks_store);
            let sanitizer = sanitizer_for_store.clone();
            Box::pin(memory_tools::handle_memory_store(args, ks, sanitizer))
        });

        let ks_query = Arc::clone(&ks);
        builder = builder.tool(memory_tools::memory_query_def(), move |args, _ctx| {
            let ks = Arc::clone(&ks_query);
            Box::pin(memory_tools::handle_memory_query(args, ks))
        });

        let ks_forget = Arc::clone(&ks);
        let cs_forget = shared_chunk_store.clone();
        builder = builder.tool(memory_tools::memory_forget_def(), move |args, _ctx| {
            let ks = Arc::clone(&ks_forget);
            let cs = cs_forget.clone();
            Box::pin(memory_tools::handle_memory_forget(args, ks, cs))
        });

        let ks_purge = Arc::clone(&ks);
        let sanitizer_for_purge = pii_sanitizer.clone();
        let cs_purge = shared_chunk_store.clone();
        builder = builder.tool(memory_tools::memory_purge_pii_def(), move |args, _ctx| {
            let ks = Arc::clone(&ks_purge);
            let sanitizer = sanitizer_for_purge.clone();
            let cs = cs_purge.clone();
            Box::pin(memory_tools::handle_memory_purge_pii(
                args, ks, sanitizer, cs,
            ))
        });

        let ks_forget_content = Arc::clone(&ks);
        let cs_forget_content = shared_chunk_store.clone();
        builder = builder.tool(
            memory_tools::memory_forget_by_content_def(),
            move |args, _ctx| {
                let ks = Arc::clone(&ks_forget_content);
                let cs = cs_forget_content.clone();
                Box::pin(memory_tools::handle_memory_forget_by_content(args, ks, cs))
            },
        );

        // pii_report
        let ks_report = Arc::clone(&ks);
        let metrics_for_report = pii_metrics.clone();
        let retention_days = cfg.memory_retention_days();
        let pii_retention_days = cfg.memory_pii_retention_days();
        let audit_retention_days = cfg.memory_audit_retention_days();
        builder = builder.tool(memory_tools::pii_report_def(), move |args, _ctx| {
            let ks = Arc::clone(&ks_report);
            let metrics = metrics_for_report.clone();
            Box::pin(memory_tools::handle_pii_report(
                args,
                ks,
                metrics,
                retention_days,
                pii_retention_days,
                audit_retention_days,
            ))
        });

        // memory_consent
        let ks_consent = Arc::clone(&ks);
        builder = builder.tool(memory_tools::memory_consent_def(), move |args, _ctx| {
            let ks = Arc::clone(&ks_consent);
            Box::pin(memory_tools::handle_memory_consent(args, ks))
        });

        // --- Data retention sweep at startup ---
        {
            let store = ks.lock().unwrap_or_else(|e| e.into_inner());
            if let Some(days) = cfg.memory_retention_days() {
                match store.expire_older_than(days) {
                    Ok(n) if n > 0 => tracing::info!(
                        deleted = n,
                        days = days,
                        "Retention: expired old knowledge entries"
                    ),
                    _ => {}
                }
            }
            if let Some(days) = cfg.memory_pii_retention_days() {
                match store.expire_pii_older_than(days) {
                    Ok(n) if n > 0 => tracing::info!(
                        deleted = n,
                        days = days,
                        "Retention: expired PII-flagged knowledge entries"
                    ),
                    _ => {}
                }
            }
        }

        tracing::info!(
            "Registered memory tools (memory_store, memory_query, memory_forget, memory_purge_pii, memory_forget_by_content, pii_report, memory_consent)"
        );
    }

    // --- Registry proxy module ---
    if cfg.registry_enabled() && !cfg.registry.is_empty() {
        let registry_state = Arc::new(registry_tools::RegistryState::new(
            cfg.registry.clone(),
            cfg.registry_cache_ttl_secs(),
        ));

        let rs = Arc::clone(&registry_state);
        builder = builder.tool(registry_tools::registry_search_def(), move |args, _ctx| {
            let rs = Arc::clone(&rs);
            Box::pin(registry_tools::handle_registry_search(args, rs))
        });

        let rs = Arc::clone(&registry_state);
        builder = builder.tool(registry_tools::registry_list_def(), move |args, _ctx| {
            let rs = Arc::clone(&rs);
            Box::pin(registry_tools::handle_registry_list(args, rs))
        });

        let rs = Arc::clone(&registry_state);
        builder = builder.tool(
            registry_tools::registry_describe_def(),
            move |args, _ctx| {
                let rs = Arc::clone(&rs);
                Box::pin(registry_tools::handle_registry_describe(args, rs))
            },
        );

        tracing::info!(
            registries = cfg.registry.len(),
            "Registered registry proxy tools (registry_search, registry_list, registry_describe)"
        );
    }

    // Register audit_query tool (audit_log was created earlier, reuse it)
    {
        let audit = Arc::clone(&audit_log);
        builder = builder.tool(
            navra_core::protocol::ToolDefinition::new(
                "audit_query",
                "Query the structured audit log. Returns tool calls, model calls, \
                     and run summaries from past agent executions. Use to inspect \
                     what tools were called, with what arguments, and what results \
                     were returned.",
                navra_protocol::compat::tool_input_schema(
                    {
                        let mut props = std::collections::HashMap::new();
                        props.insert(
                            "run_id".to_string(),
                            serde_json::json!({
                                "type": "string",
                                "description": "Filter by run ID (returns tool calls for that run)"
                            }),
                        );
                        props.insert("summary".to_string(), serde_json::json!({
                            "type": "boolean",
                            "description": "If true, return a summary instead of individual entries"
                        }));
                        Some(props)
                    },
                    None,
                ),
            ),
            move |args, _ctx| {
                let audit = Arc::clone(&audit);
                Box::pin(async move {
                    use navra_core::protocol::CallToolResult;

                    let run_id = args.get("run_id").and_then(|v| v.as_str());

                    if let Some(rid) = run_id {
                        let summary = args
                            .get("summary")
                            .and_then(|v| v.as_bool())
                            .unwrap_or(false);
                        if summary {
                            match audit.get_summary(rid) {
                                Ok(s) => CallToolResult::text(
                                    serde_json::to_string_pretty(&s).unwrap_or_default(),
                                ),
                                Err(e) => {
                                    CallToolResult::error_msg(format!("Audit query failed: {e}"))
                                }
                            }
                        } else {
                            match audit.get_tool_calls(rid) {
                                Ok(calls) => CallToolResult::text(
                                    serde_json::to_string_pretty(&calls).unwrap_or_default(),
                                ),
                                Err(e) => {
                                    CallToolResult::error_msg(format!("Audit query failed: {e}"))
                                }
                            }
                        }
                    } else {
                        // No run_id — list recent runs
                        match audit.get_run("latest") {
                            Ok(run) => CallToolResult::text(
                                serde_json::to_string_pretty(&run).unwrap_or_default(),
                            ),
                            Err(_) => CallToolResult::text(
                                "No audit runs found. Run a demo first.".to_string(),
                            ),
                        }
                    }
                })
            },
        );
        tracing::info!("Registered audit_query tool");
    }

    // Register plan_execute tool (needs late-bound server reference)
    let server_cell: Arc<std::sync::OnceLock<Arc<navra_core::McpServer>>> =
        Arc::new(std::sync::OnceLock::new());
    {
        let cell = Arc::clone(&server_cell);
        let allow_direct = cfg.server.allow_direct_execution;
        builder = builder.tool(plan_execute::plan_execute_tool_def(), move |args, ctx| {
            let cell = Arc::clone(&cell);
            Box::pin(async move {
                match cell.get() {
                    Some(server) => {
                        plan_execute::handle_plan_execute(args, server, ctx, allow_direct).await
                    }
                    None => navra_core::protocol::CallToolResult::error_msg(
                        "Server not yet initialized",
                    ),
                }
            })
        });
        tracing::info!("Registered plan_execute tool");
    }

    // Register build_test tool for self-improvement flows
    {
        let perm = Arc::clone(&perm_engine);
        builder = builder.tool(build_tools::build_test_tool_def(), move |args, ctx| {
            let perm = Arc::clone(&perm);
            Box::pin(async move { build_tools::handle_build_test(args, ctx, perm).await })
        });
        tracing::info!("Registered build_test tool");
    }

    // Register flow:// resources backed by audit.db.
    // Agents can read specialist outputs via resources/read with
    // URIs like "flow://flow-1/task/sec-auth-audit".
    {
        let flow_audit = Arc::clone(&audit_log);
        builder = builder.resource(
            navra_core::protocol::ResourceDefinition::new(
                navra_protocol::RawResource::new("flow://", "Flow task results")
                    .with_description("Read flow task outputs. Use flow://list for all flows, \
                     flow://<flow_id>/tasks for task list, \
                     flow://<flow_id>/task/<task_id> for a specific output.")
                    .with_mime_type("text/plain"),
                None,
            ),
            std::sync::Arc::new(move |uri: String, _ctx| {
                let audit = Arc::clone(&flow_audit);
                Box::pin(async move {
                    let text = if uri == "flow://" || uri == "flow://list" {
                        match audit.list_flows() {
                            Ok(flows) if !flows.is_empty() => {
                                flows.iter().map(|f| {
                                    format!("{}: {} tasks, {}", f.flow_id, f.task_count, f.status)
                                }).collect::<Vec<_>>().join("\n")
                            }
                            _ => "No flows found.".to_string(),
                        }
                    } else if let Some(rest) = uri.strip_prefix("flow://") {
                        let parts: Vec<&str> = rest.splitn(3, '/').collect();
                        match parts.as_slice() {
                            [flow_id, "tasks"] | [flow_id] => {
                                match audit.get_flow_results(flow_id) {
                                    Ok(results) if !results.is_empty() => {
                                        results.iter().map(|r| {
                                            format!("{} ({}): {} [{} chars]",
                                                r.task_id,
                                                r.specialist.as_deref().unwrap_or("?"),
                                                r.status,
                                                r.output.as_deref().map(|o| o.len()).unwrap_or(0))
                                        }).collect::<Vec<_>>().join("\n")
                                    }
                                    _ => format!("No results for flow {flow_id}"),
                                }
                            }
                            [flow_id, "task", task_id] => {
                                match audit.get_flow_results(flow_id) {
                                    Ok(results) => {
                                        match results.iter().find(|r| r.task_id == *task_id) {
                                            Some(r) => r.output.clone().unwrap_or_else(|| "(no output)".to_string()),
                                            None => format!("Task {task_id} not found in flow {flow_id}"),
                                        }
                                    }
                                    Err(e) => format!("Error reading flow {flow_id}: {e}"),
                                }
                            }
                            _ => format!("Invalid flow URI: {uri}. Use flow://list, flow://<id>/tasks, or flow://<id>/task/<task_id>"),
                        }
                    } else {
                        format!("Invalid URI: {uri}")
                    };
                    navra_core::protocol::ReadResourceResult::new(
                        vec![navra_core::protocol::ResourceContent::TextResourceContents {
                            uri,
                            mime_type: Some("text/plain".to_string()),
                            text,
                            meta: None,
                        }],
                    )
                })
            }),
        );
        tracing::info!("Registered flow:// resources (backed by audit.db)");
    }

    // --- Kernel introspection resources (navra://) ---
    // These expose gateway internal state to agents via MCP resources/read.
    let boot_instant = std::time::Instant::now();

    // navra://proc — Process table (active agents, call counts)
    {
        let pt = process_table.clone();
        builder = builder.resource(
            navra_core::protocol::ResourceDefinition::new(
                navra_protocol::RawResource::new("navra://proc", "Process Table")
                    .with_description("Active agent sessions and call counts")
                    .with_mime_type("application/json"),
                None,
            ),
            Arc::new(move |uri: String, _ctx| {
                let pt = pt.clone();
                Box::pin(async move {
                    let agents = pt.snapshot();
                    let json = serde_json::json!({ "agents": agents });
                    navra_core::protocol::ReadResourceResult::new(vec![
                        navra_core::protocol::ResourceContent::TextResourceContents {
                            uri,
                            mime_type: Some("application/json".to_string()),
                            text: serde_json::to_string_pretty(&json).unwrap_or_default(),
                            meta: None,
                        },
                    ])
                })
            }),
        );
    }

    // navra://sessions — Active sessions
    {
        let ss = session_store.clone();
        builder = builder.resource(
            navra_core::protocol::ResourceDefinition::new(
                navra_protocol::RawResource::new("navra://sessions", "Active Sessions")
                    .with_description("List of active MCP sessions")
                    .with_mime_type("application/json"),
                None,
            ),
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
                    navra_core::protocol::ReadResourceResult::new(vec![
                        navra_core::protocol::ResourceContent::TextResourceContents {
                            uri,
                            mime_type: Some("application/json".to_string()),
                            text: serde_json::to_string_pretty(&json).unwrap_or_default(),
                            meta: None,
                        },
                    ])
                })
            }),
        );
    }

    // navra://metrics — Gateway metrics summary
    {
        let pt = process_table.clone();
        let ss = session_store.clone();
        let boot = boot_instant;
        builder = builder.resource(
            navra_core::protocol::ResourceDefinition::new(
                navra_protocol::RawResource::new("navra://metrics", "Gateway Metrics")
                    .with_description("Gateway metrics: call counts, sessions, uptime")
                    .with_mime_type("text/plain"),
                None,
            ),
            Arc::new(move |uri: String, _ctx| {
                let pt = pt.clone();
                let ss = ss.clone();
                Box::pin(async move {
                    let snapshot = pt.snapshot();
                    let total_calls: u64 = snapshot.iter().map(|a| a.call_count).sum();
                    let total_denied: u64 = snapshot.iter().map(|a| a.denied_count).sum();
                    let session_count = ss.count();
                    let uptime = boot.elapsed().as_secs();
                    let text = format!(
                        "# navra gateway metrics\n\
                         navra_uptime_seconds {uptime}\n\
                         navra_sessions_active {session_count}\n\
                         navra_agents_active {}\n\
                         navra_tool_calls_total {total_calls}\n\
                         navra_tool_calls_denied_total {total_denied}\n",
                        snapshot.len(),
                    );
                    navra_core::protocol::ReadResourceResult::new(vec![
                        navra_core::protocol::ResourceContent::TextResourceContents {
                            uri,
                            mime_type: Some("text/plain".to_string()),
                            text,
                            meta: None,
                        },
                    ])
                })
            }),
        );
    }

    // navra://tools — Registered tool list (uses OnceLock, populated after build)
    {
        let cell = Arc::clone(&server_cell);
        builder = builder.resource(
            navra_core::protocol::ResourceDefinition::new(
                navra_protocol::RawResource::new("navra://tools", "Registered Tools")
                    .with_description("List of all registered MCP tools")
                    .with_mime_type("application/json"),
                None,
            ),
            Arc::new(move |uri: String, _ctx| {
                let cell = Arc::clone(&cell);
                Box::pin(async move {
                    let (count, tools) = match cell.get() {
                        Some(server) => {
                            let names = server.tool_names();
                            (names.len(), names)
                        }
                        None => (0, vec!["(server not yet initialized)".to_string()]),
                    };
                    let json = serde_json::json!({
                        "count": count,
                        "tools": tools,
                    });
                    navra_core::protocol::ReadResourceResult::new(vec![
                        navra_core::protocol::ResourceContent::TextResourceContents {
                            uri,
                            mime_type: Some("application/json".to_string()),
                            text: serde_json::to_string_pretty(&json).unwrap_or_default(),
                            meta: None,
                        },
                    ])
                })
            }),
        );
    }

    // navra://version — Server version info
    {
        let boot = boot_instant;
        builder = builder.resource(
            navra_core::protocol::ResourceDefinition::new(
                navra_protocol::RawResource::new("navra://version", "Server Version")
                    .with_description("Server name, version, protocol version, uptime")
                    .with_mime_type("application/json"),
                None,
            ),
            Arc::new(move |uri: String, _ctx| {
                Box::pin(async move {
                    let json = serde_json::json!({
                        "name": "navra",
                        "version": env!("CARGO_PKG_VERSION"),
                        "protocol_version": navra_core::protocol::PROTOCOL_VERSION,
                        "crates": 20,
                        "uptime_secs": boot.elapsed().as_secs(),
                    });
                    navra_core::protocol::ReadResourceResult::new(vec![
                        navra_core::protocol::ResourceContent::TextResourceContents {
                            uri,
                            mime_type: Some("application/json".to_string()),
                            text: serde_json::to_string_pretty(&json).unwrap_or_default(),
                            meta: None,
                        },
                    ])
                })
            }),
        );
    }
    tracing::info!("Registered navra:// kernel introspection resources");

    let broadcaster = navra_core::transport::SseBroadcaster::new();
    let mut builder = builder.broadcaster(broadcaster.clone());

    // Wire hooks: budget, safety, statistical guardrail, temporal contracts,
    // memory extraction, causal provenance, monitoring, tool pruning, DMN.
    builder = setup::hooks::wire_hooks(builder, &cfg, &safety_state, &knowledge_store);

    let server = Arc::new(builder.build());
    let _ = server_cell.set(Arc::clone(&server));

    team_registry_ref.set_tool_operations(server.tool_operations().clone());

    // Config watcher for hot reload (K8s ConfigMap pattern)
    let _config_watcher = if cfg.server.config_watch {
        let config_path = config::Config::default_config_path();
        let (tx, _rx) = tokio::sync::watch::channel(std::sync::Arc::new(cfg.clone()));
        match config_watcher::ConfigWatcher::new(
            config_path,
            cfg.server.config_watch_debounce_ms,
            tx,
        ) {
            Ok(w) => Some(w),
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
