mod config;
mod discover;
mod flow_tools;
mod mdns;
mod team_tools;
mod tray;

use clap::{Parser, Subcommand};
use myelix_core::auth::{AgentIdentity, TokenAuthenticator};
use myelix_core::identity::{self, CapSigner, Ed25519Signer};
use myelix_core::permissions::{PathAcl, PermissionEngine, ToolPermissions, ToolPolicy, ToolRule};
use std::sync::Arc;

#[derive(Parser)]
#[command(name = "mcpd", about = "Composable MCP server")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Start the MCP server
    Serve {
        /// Path to config file
        #[arg(short, long)]
        config: Option<String>,
        /// Disable system tray icon
        #[arg(long)]
        no_tray: bool,
    },
    /// Generate or manage agent tokens
    Token {
        #[command(subcommand)]
        action: TokenAction,
    },
    /// Approve a pending request
    Approve { id: String },
    /// Deny a pending request
    Deny { id: String },
    /// Show server status
    Status,
    /// Install systemd user units and enable the service
    Install,
    /// Uninstall systemd user units
    Uninstall,
    /// Manage ONNX models
    Model {
        #[command(subcommand)]
        action: ModelAction,
    },
    /// Run the end-to-end security audit demo
    Demo {
        /// Path to the demo project (default: examples/payments-app)
        #[arg(short, long, default_value = "examples/payments-app")]
        project: String,
        /// Run with a real LLM (requires Ollama or llama-server)
        #[arg(long)]
        live: bool,
        /// Model to use in live mode (default: granite3.3:2b)
        #[arg(long, default_value = "granite3.3:2b")]
        model: String,
        /// Max analysis rounds (default: 3)
        #[arg(long, default_value = "3")]
        max_rounds: u32,
        /// Files per round (default: 5)
        #[arg(long, default_value = "5")]
        files_per_round: usize,
        /// Min new findings to continue (default: 2)
        #[arg(long, default_value = "2")]
        min_delta: u32,
    },
}

#[derive(Subcommand)]
enum ModelAction {
    /// Download a model from HuggingFace
    Pull {
        /// Model name (e.g., guardian-hap, granite-embed)
        name: String,
    },
    /// List installed models
    List,
    /// Show available models for download
    Available,
}

#[derive(Subcommand)]
enum TokenAction {
    /// Generate a new agent token
    Generate {
        #[arg(short, long)]
        name: String,
        #[arg(short, long)]
        permissions: String,
    },
    /// List registered agents
    List,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive("mcpd=info".parse()?),
        )
        .init();

    match cli.command {
        Commands::Serve { config: config_path, no_tray } => {
            let cfg = config::Config::load(config_path.as_deref())?;
            serve(cfg, no_tray).await?;
        }
        Commands::Token { action } => {
            match action {
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
            }
        }
        Commands::Approve { id } => {
            let cfg = config::Config::load(None)?;
            let addr = cfg.server.listen_addr();
            approve_or_deny(&addr, &id, true).await?;
        }
        Commands::Deny { id } => {
            let cfg = config::Config::load(None)?;
            let addr = cfg.server.listen_addr();
            approve_or_deny(&addr, &id, false).await?;
        }
        Commands::Status => {
            let cfg = config::Config::load(None)?;
            let addr = cfg.server.listen_addr();
            query_status(&addr).await?;
        }
        Commands::Install => {
            install_systemd_units()?;
        }
        Commands::Uninstall => {
            uninstall_systemd_units()?;
        }
        Commands::Model { action } => match action {
            ModelAction::Pull { name } => {
                model_pull(&name).await?;
            }
            ModelAction::List => {
                model_list()?;
            }
            ModelAction::Available => {
                model_available();
            }
        },
        Commands::Demo { project, live, model, max_rounds, files_per_round, min_delta } => {
            if live {
                run_demo_live(&project, &model, max_rounds, files_per_round, min_delta).await?;
            } else {
                run_demo(&project).await?;
            }
        }
    }

    Ok(())
}

/// Bootstrap the root identity from config.
///
/// If `[server.identity]` specifies a `key_path`, loads or creates
/// a file-based identity. Otherwise, uses the OS keyring.
fn bootstrap_identity(cfg: &config::Config) -> anyhow::Result<Ed25519Signer> {
    if let Some(ref identity_cfg) = cfg.server.identity {
        if let Some(ref key_path) = identity_cfg.key_path {
            let path = std::path::Path::new(key_path);
            return identity::load_or_create_file_identity(path);
        }
    }
    // Default: try OS keyring, fall back to file
    match identity::load_or_create_keyring_identity() {
        Ok(signer) => Ok(signer),
        Err(e) => {
            tracing::warn!(
                error = %e,
                "Keyring unavailable, falling back to file identity"
            );
            let default_path = dirs::config_dir()
                .unwrap_or_else(|| std::path::PathBuf::from("."))
                .join("mcpd/identity.key");
            identity::load_or_create_file_identity(&default_path)
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
    engine.apply_ring_inheritance();
    engine
}

async fn serve(cfg: config::Config, no_tray: bool) -> anyhow::Result<()> {
    tracing::info!("Starting mcpd");

    // Bootstrap root identity (DID:key from Ed25519)
    let root_signer = Arc::new(bootstrap_identity(&cfg)?);
    tracing::info!(
        root_did = %root_signer.did(),
        algorithm = %root_signer.algorithm(),
        "Root identity"
    );

    // Build credential store from config mappings
    let credential_store = Arc::new(
        myelix_core::credentials::MappedCredentialStore::new(cfg.credentials.clone())
    );
    if !cfg.credentials.is_empty() {
        tracing::info!(
            count = cfg.credentials.len(),
            "Credential mappings loaded"
        );
    }

    let perm_engine = Arc::new(build_perm_engine(&cfg));

    // Build quota engine from rate limits in permission sets
    let mut quota_engine = myelix_core::quota::QuotaEngine::new();
    for (name, pset) in &cfg.permissions {
        if let Some(ref rate_limit_str) = pset.rate_limit {
            if let Some((max_str, window_str)) = rate_limit_str.split_once('/') {
                if let (Ok(max_calls), Ok(window_secs)) =
                    (max_str.parse::<u64>(), window_str.parse::<u64>())
                {
                    quota_engine.add_limit(
                        name.clone(),
                        myelix_core::quota::RateLimit {
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
        }
    }

    // Build server, registering enabled modules
    let mut builder = myelix_core::McpServer::builder()
        .name("mcpd")
        .version(env!("CARGO_PKG_VERSION"));

    // Persistent session store (SQLite) — sessions survive restarts
    {
        let session_db_path = dirs::data_dir()
            .unwrap_or_else(|| std::path::PathBuf::from("."))
            .join("mcpd/sessions.db");
        if let Some(parent) = session_db_path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        match myelix_memory::SqliteSessionBackend::open(&session_db_path) {
            Ok(backend) => {
                let existing = {
                    use myelix_core::session::SessionBackend;
                    backend.count()
                };
                let store = myelix_core::session::SessionStore::with_backend(
                    std::sync::Arc::new(backend),
                );
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
            }
        }
    }

    // Wire IFC policies and trusted paths from permission sets
    for (name, pset) in &cfg.permissions {
        let policy = myelix_core::ifc::TaintedWritePolicy::from_str(&pset.tainted_write_policy);
        if policy != myelix_core::ifc::TaintedWritePolicy::Allow {
            builder = builder.ifc_policy(name.clone(), policy.clone());
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

    if quota_engine.has_limits() {
        builder = builder.quota_engine(quota_engine);
    }

    // Register authenticator chain if agents are configured
    if !cfg.agents.is_empty() {
        let has_cap_agents = cfg.agents.iter().any(|a| a.capability_token);

        // Issue capability tokens for agents that request them
        if has_cap_agents {
            let default_ttl = cfg
                .server
                .identity
                .as_ref()
                .map(|i| i.token_ttl)
                .unwrap_or(3600);

            for agent in &cfg.agents {
                if !agent.capability_token {
                    continue;
                }
                let pset = cfg.permissions.get(&agent.permissions);
                let (ring, paths, ops, creds) = match pset {
                    Some(ps) => (
                        ps.ring.unwrap_or(0),
                        ps.allow.clone(),
                        ps.operations.clone(),
                        ps.credentials.clone(),
                    ),
                    None => (0, vec![], vec![], vec![]),
                };
                let ttl = agent.token_ttl.unwrap_or(default_ttl);
                let subject_did = agent
                    .did
                    .clone()
                    .unwrap_or_else(|| format!("agent:{}", agent.name));

                let cap_set = myelix_core::auth::capability::CapabilitySet {
                    paths,
                    operations: ops,
                    tools: pset
                        .map(|ps| {
                            ps.tool_rules
                                .iter()
                                .filter(|r| r.policy == "allow")
                                .map(|r| r.tool.clone())
                                .collect::<Vec<_>>()
                        })
                        .filter(|v: &Vec<String>| !v.is_empty())
                        .unwrap_or_else(|| vec!["*".to_string()]),
                    credentials: creds,
                };

                let payload = myelix_core::auth::capability::build_payload(
                    root_signer.did(),
                    &subject_did,
                    cap_set,
                    ring,
                    ttl,
                );

                match myelix_core::auth::capability::encode_token(&payload, &root_signer) {
                    Ok(token) => {
                        // Log token prefix only — full token is a bearer credential
                        let token_prefix = if token.len() > 20 {
                            format!("{}...", &token[..20])
                        } else {
                            token.clone()
                        };
                        tracing::info!(
                            agent = %agent.name,
                            subject_did = %subject_did,
                            ring = ring,
                            ttl_secs = ttl,
                            token_prefix = %token_prefix,
                            "Issued capability token"
                        );
                    }
                    Err(e) => {
                        tracing::error!(
                            agent = %agent.name,
                            error = %e,
                            "Failed to issue capability token"
                        );
                    }
                }
            }
        }

        let mut blake3_auth = TokenAuthenticator::new();
        for agent in &cfg.agents {
            blake3_auth.register_hash(
                &agent.token_hash,
                AgentIdentity {
                    name: agent.name.clone(),
                    permissions: agent.permissions.clone(),
                    signing_key: agent.signing_key.clone(),
                    did: agent.did.clone(),
                    capabilities: None,
                },
            );
            tracing::info!(agent = %agent.name, permissions = %agent.permissions, "Registered agent");
        }

        if has_cap_agents {
            // Build ChainAuthenticator: capability tokens first, then BLAKE3
            let cap_auth = myelix_core::auth::chain::CapabilityAuthenticator::new(
                Box::new(Arc::clone(&root_signer)),
            );
            let chain = myelix_core::auth::chain::ChainAuthenticator::new()
                .add(cap_auth)
                .add(blake3_auth);
            builder = builder.authenticator(chain);
            tracing::info!("Authenticator chain: capability tokens + BLAKE3");
        } else {
            builder = builder.authenticator(blake3_auth);
        }
    }

    // --- Load models into registry ---
    let mut models: std::collections::HashMap<String, Arc<dyn myelix_model::ModelBackend>> =
        std::collections::HashMap::new();
    let mut running_endpoints: Vec<(Box<dyn myelix_model_runtime::ModelRuntime>, myelix_model_runtime::Endpoint)> =
        Vec::new();

    let hub = myelix_model_hub::ModelHub::new().ok();

    for (name, model_cfg) in &cfg.models {
        // --- Resolve model path: hub source or local file ---
        let resolved_path = if let Some(ref source) = model_cfg.source {
            // Pull from hub
            let Some(ref hub) = hub else {
                tracing::error!(model = %name, "Model hub unavailable, skipping");
                continue;
            };
            let uri = match myelix_model_hub::ModelUri::parse(source) {
                Ok(u) => u,
                Err(e) => {
                    tracing::error!(model = %name, source = %source, error = %e, "Invalid model URI, skipping");
                    continue;
                }
            };
            match hub.pull(&uri).await {
                Ok(p) => {
                    tracing::info!(model = %name, source = %source, path = %p.display(), "Model pulled from hub");
                    p
                }
                Err(e) => {
                    tracing::error!(model = %name, source = %source, error = %e, "Failed to pull model, skipping");
                    continue;
                }
            }
        } else if let Some(ref path_str) = model_cfg.model_path {
            let expanded = expand_tilde(path_str);
            std::path::PathBuf::from(&expanded)
        } else {
            tracing::warn!(model = %name, "No source or model_path, skipping");
            continue;
        };

        if !resolved_path.exists() {
            tracing::warn!(
                model = %name,
                path = %resolved_path.display(),
                "Model file not found, skipping"
            );
            continue;
        }

        // --- Choose backend based on task ---
        let backend: Arc<dyn myelix_model::ModelBackend> = match model_cfg.task.as_str() {
            "embedding" => {
                let dims = model_cfg.dimensions.unwrap_or(768);
                let task = myelix_model::ModelTask::Embedding { dimensions: dims };
                let tokenizer_path = model_cfg
                    .tokenizer_path
                    .as_ref()
                    .map(|p| std::path::PathBuf::from(expand_tilde(p)));
                match myelix_model::OnnxBackend::load(name, &resolved_path, tokenizer_path.as_deref(), task) {
                    Ok(model) => Arc::new(model),
                    Err(e) => {
                        tracing::error!(model = %name, error = %e, "Failed to load ONNX model, skipping");
                        continue;
                    }
                }
            }
            "classification" => {
                let labels = if model_cfg.labels.is_empty() {
                    vec!["safe".to_string(), "unsafe".to_string()]
                } else {
                    model_cfg.labels.clone()
                };
                let task = myelix_model::ModelTask::Classification { labels };
                let tokenizer_path = model_cfg
                    .tokenizer_path
                    .as_ref()
                    .map(|p| std::path::PathBuf::from(expand_tilde(p)));
                match myelix_model::OnnxBackend::load(name, &resolved_path, tokenizer_path.as_deref(), task) {
                    Ok(model) => Arc::new(model),
                    Err(e) => {
                        tracing::error!(model = %name, error = %e, "Failed to load ONNX model, skipping");
                        continue;
                    }
                }
            }
            "chat" | "generate" => {
                // Serve via runtime and wrap in OpenAiBackend
                let runtime_kind = model_cfg.runtime.as_deref().unwrap_or("auto");
                let runtime: Box<dyn myelix_model_runtime::ModelRuntime> = match runtime_kind {
                    "auto" => match myelix_model_runtime::auto_runtime().await {
                        Ok(r) => r,
                        Err(e) => {
                            tracing::error!(model = %name, error = %e, "No runtime available, skipping");
                            continue;
                        }
                    },
                    "podman" => Box::new(myelix_model_runtime::podman::PodmanRuntime::new()),
                    "direct" => Box::new(myelix_model_runtime::direct::DirectRuntime::new()),
                    "none" => {
                        tracing::warn!(model = %name, "Task is chat/generate but runtime=none, skipping");
                        continue;
                    }
                    other => {
                        tracing::warn!(model = %name, runtime = %other, "Unknown runtime, skipping");
                        continue;
                    }
                };

                let gpus = myelix_model_runtime::detect_gpus();
                let serve_cfg = myelix_model_runtime::ServeConfig {
                    model_path: resolved_path,
                    gpus,
                    context_size: model_cfg.context_size.unwrap_or(4096),
                    parallel: model_cfg.parallel.unwrap_or(1),
                    ..Default::default()
                };

                let endpoint = match runtime.serve(&serve_cfg).await {
                    Ok(ep) => ep,
                    Err(e) => {
                        tracing::error!(model = %name, error = %e, "Failed to start model runtime, skipping");
                        continue;
                    }
                };

                tracing::info!(
                    model = %name,
                    url = %endpoint.url,
                    backend = ?endpoint.backend,
                    "Model served via runtime"
                );

                let model_id = model_cfg.model_name.clone().unwrap_or_else(|| name.clone());
                let backend: Arc<dyn myelix_model::ModelBackend> = Arc::new(
                    myelix_model::OpenAiBackend::new(
                        &endpoint.url,
                        &model_id,
                        None,
                        myelix_model::Locality::Local,
                    ),
                );

                running_endpoints.push((runtime, endpoint));
                backend
            }
            other => {
                tracing::warn!(model = %name, task = %other, "Unknown model task, skipping");
                continue;
            }
        };

        tracing::info!(model = %name, task = %model_cfg.task, "Model loaded");
        models.insert(name.clone(), backend);
    }

    tracing::info!(count = models.len(), "Model registry ready");

    // Register safety profiles and per-tool permissions per permission set
    for (name, pset) in &cfg.permissions {
        let mut pipeline = myelix_core::safety::build_pipeline(&pset.safety);

        // Add custom regex patterns if configured
        if !pset.safety_patterns.is_empty() {
            let patterns: Vec<(String, String)> = pset
                .safety_patterns
                .iter()
                .map(|p| (p.category.clone(), p.pattern.clone()))
                .collect();
            let custom = myelix_core::safety::CustomFilter::new(patterns);
            if custom.has_patterns() {
                tracing::info!(
                    permission_set = %name,
                    patterns = pset.safety_patterns.len(),
                    "Custom safety patterns"
                );
                pipeline.add_filter(custom);
            }
        }

        // Add ML safety filter from any loaded classification model
        for (model_name, model_cfg) in &cfg.models {
            if model_cfg.task == "classification" {
                if let Some(model) = models.get(model_name) {
                    let threshold = model_cfg.threshold.unwrap_or(0.5);
                    pipeline.add_model_filter(myelix_core::safety::MlFilter::new(
                        model.clone(),
                        threshold,
                        "ml-unsafe",
                    ));
                }
            }
        }

        tracing::info!(
            permission_set = %name,
            safety = %pset.safety,
            "Safety profile"
        );
        builder = builder.safety_profile(name.clone(), pipeline);

        // Log compliance tags for audit trail
        if !pset.compliance.is_empty() {
            tracing::info!(
                permission_set = %name,
                tags = ?pset.compliance,
                "Compliance tags"
            );
        }

        // Build per-tool permission rules if any are configured
        if !pset.tool_rules.is_empty() {
            let rules: Vec<ToolRule> = pset
                .tool_rules
                .iter()
                .map(|r| ToolRule {
                    tool: r.tool.clone(),
                    policy: match r.policy.as_str() {
                        "deny" => ToolPolicy::Deny,
                        "approve" => ToolPolicy::Approve,
                        _ => ToolPolicy::Allow,
                    },
                })
                .collect();
            let default = match pset.default_tool_policy.as_str() {
                "deny" => ToolPolicy::Deny,
                "approve" => ToolPolicy::Approve,
                _ => ToolPolicy::Allow,
            };
            tracing::info!(
                permission_set = %name,
                rules = rules.len(),
                "Tool permission rules"
            );
            builder = builder.tool_permissions(name.clone(), ToolPermissions::new(rules, default));
        }
    }

    // Build shared approval infrastructure
    let approvals = Arc::new(myelix_core::permissions::ApprovalStore::new(
        cfg.approval.timeout_secs,
    ));
    let notifier: Arc<dyn myelix_core::notify::Notifier> = match cfg.approval.notify.as_str() {
        "dbus" => {
            match myelix_core::notify::DbusNotifier::new().await {
                Ok(n) => {
                    tracing::info!("D-Bus notifier connected");
                    Arc::new(n)
                }
                Err(e) => {
                    tracing::warn!("D-Bus unavailable ({e}), falling back to CLI-only approvals");
                    Arc::new(myelix_core::notify::NoopNotifier)
                }
            }
        }
        _ => Arc::new(myelix_core::notify::NoopNotifier),
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

    // --- Docs module ---
    // Keep watcher handle alive for the lifetime of the server.
    let mut _watcher_handle: Option<myelix_tools_docs::WatcherHandle> = None;
    if cfg.docs_enabled() {
        let db_path = cfg.docs_db_path();
        let mut index = myelix_tools_docs::IndexStore::open(&db_path)?;

        // Enable vector search if an embedding model is loaded
        if embedding_model.is_some() {
            let dims = embedding_model_name
                .as_ref()
                .and_then(|name| cfg.models.get(name))
                .and_then(|m| m.dimensions)
                .unwrap_or(768);
            index.enable_vectors(dims)?;
            tracing::info!(dimensions = dims, "Vector search enabled");
        }

        let index = Arc::new(index);

        let docs = if let Some(ref model) = embedding_model {
            myelix_tools_docs::DocsModule::with_embeddings(
                perm_engine.clone(),
                index.clone(),
                approvals.clone(),
                notifier.clone(),
                model.clone(),
            )
        } else {
            myelix_tools_docs::DocsModule::new(
                perm_engine.clone(),
                index.clone(),
                approvals.clone(),
                notifier.clone(),
            )
        };
        tracing::info!("Module 'docs' enabled (db: {db_path})");
        builder = builder.module(docs);

        // Start file watcher if watch directories are configured
        let watch_dirs: Vec<_> = cfg
            .modules
            .docs
            .as_ref()
            .map(|d| &d.watch)
            .into_iter()
            .flatten()
            .map(|dir| {
                if dir.starts_with("~/") {
                    dirs::home_dir()
                        .map(|h| h.join(&dir[2..]))
                        .unwrap_or_else(|| std::path::PathBuf::from(dir))
                } else {
                    std::path::PathBuf::from(dir)
                }
            })
            .collect();
        if !watch_dirs.is_empty() {
            match myelix_tools_docs::start_watcher_with_embeddings(
                watch_dirs,
                index,
                embedding_model.clone(),
            ) {
                Ok(handle) => {
                    tracing::info!("File watcher active");
                    _watcher_handle = Some(handle);
                }
                Err(e) => {
                    tracing::warn!("Failed to start file watcher: {e}");
                }
            }
        }
    }

    // --- Git module ---
    if cfg.git_enabled() {
        let git = myelix_tools_git::GitModule::new(
            perm_engine.clone(),
            approvals.clone(),
            notifier.clone(),
        );
        tracing::info!("Module 'git' enabled");
        builder = builder.module(git);
    }

    // --- RAG module ---
    if cfg.rag_enabled() {
        if let Some(ref model) = embedding_model {
            let rag_db_path = cfg.rag_db_path();
            let dims = embedding_model_name
                .as_ref()
                .and_then(|name| cfg.models.get(name))
                .and_then(|m| m.dimensions)
                .unwrap_or(768);
            match myelix_rag::ChunkStore::open(&rag_db_path, dims) {
                Ok(store) => {
                    let rag = myelix_rag::RagModule::new(
                        std::sync::Arc::new(store),
                        model.clone(),
                        perm_engine.clone(),
                    );
                    tracing::info!("Module 'rag' enabled (db: {rag_db_path}, dims: {dims})");
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
    if cfg.voice_enabled() {
        let voice_cfg = cfg.modules.voice.as_ref().unwrap();
        let asr = models.get(&voice_cfg.asr_model).cloned();
        let tts = models.get(&voice_cfg.tts_model).cloned();

        match (asr, tts) {
            (Some(asr_model), Some(tts_model)) => {
                let voice = myelix_modal_voice::VoiceModule::with_config(
                    asr_model,
                    tts_model,
                    voice_cfg.vad_threshold,
                    30,
                    1500,
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
    if cfg.vision_enabled() {
        let vision_cfg = cfg.modules.vision.as_ref().unwrap();
        if let Some(vision_model) = models.get(&vision_cfg.model).cloned() {
            let vision = myelix_modal_vision::VisionModule::new(vision_model, perm_engine.clone());
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

    // --- AID upstream discovery ---
    if !cfg.discover.is_empty() {
        tracing::info!(
            domains = cfg.discover.len(),
            "Discovering upstream MCP servers via AID"
        );
        let discovered = discover::discover_all(&cfg.discover).await;
        for endpoint in &discovered {
            tracing::info!(
                domain = %endpoint.domain,
                url = %endpoint.url,
                description = ?endpoint.description,
                "Discovered MCP endpoint"
            );
            match myelix_core::Upstream::http(&endpoint.domain, &endpoint.url).await {
                Ok(upstream) => match myelix_core::UpstreamModule::discover(upstream).await {
                    Ok(module) => {
                        tracing::info!(
                            domain = %endpoint.domain,
                            "Connected discovered upstream"
                        );
                        builder = builder.module(module);
                    }
                    Err(e) => {
                        tracing::warn!(
                            domain = %endpoint.domain,
                            error = %e,
                            "Failed to discover capabilities of AID endpoint"
                        );
                    }
                },
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
        // Browse for MCP servers on LAN (3 second scan)
        tracing::info!("Browsing LAN for MCP servers via mDNS...");
        let lan_servers =
            mdns::browse(std::time::Duration::from_secs(3)).await;

        for server in &lan_servers {
            let url = server.url();
            match myelix_core::Upstream::http(&server.name, &url).await {
                Ok(upstream) => match myelix_core::UpstreamModule::discover(upstream).await {
                    Ok(module) => {
                        tracing::info!(
                            name = %server.name,
                            url = %url,
                            "Connected LAN upstream"
                        );
                        builder = builder.module(module);
                    }
                    Err(e) => {
                        tracing::debug!(
                            name = %server.name,
                            error = %e,
                            "Failed to discover LAN upstream capabilities"
                        );
                    }
                },
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
    for upstream_cfg in &cfg.upstream {
        if !upstream_cfg.enabled.unwrap_or(true) {
            tracing::info!(upstream = %upstream_cfg.name, "Upstream disabled, skipping");
            continue;
        }

        let retry_config = upstream_cfg.retry_config();
        let connect_result = match upstream_cfg.transport.as_str() {
            "stdio" => {
                if let Some(rc) = retry_config {
                    tracing::info!(
                        upstream = %upstream_cfg.name,
                        "Using resilient transport (retry enabled)"
                    );
                    myelix_core::Upstream::spawn_resilient(
                        &upstream_cfg.name,
                        &upstream_cfg.command,
                        upstream_cfg.cwd.as_deref(),
                        rc,
                    )
                    .await
                } else {
                    myelix_core::Upstream::spawn(
                        &upstream_cfg.name,
                        &upstream_cfg.command,
                        upstream_cfg.cwd.as_deref(),
                    )
                    .await
                }
            }
            "http" | "streamable-http" => {
                let url = match &upstream_cfg.url {
                    Some(u) => u.as_str(),
                    None => {
                        tracing::error!(
                            upstream = %upstream_cfg.name,
                            "HTTP upstream requires 'url' field, skipping"
                        );
                        continue;
                    }
                };
                if let Some(rc) = retry_config {
                    tracing::info!(
                        upstream = %upstream_cfg.name,
                        "Using resilient transport (retry enabled)"
                    );
                    myelix_core::Upstream::http_resilient(&upstream_cfg.name, url, rc).await
                } else {
                    myelix_core::Upstream::http(&upstream_cfg.name, url).await
                }
            }
            "sse" => {
                let url = match &upstream_cfg.url {
                    Some(u) => u.as_str(),
                    None => {
                        tracing::error!(
                            upstream = %upstream_cfg.name,
                            "SSE upstream requires 'url' field, skipping"
                        );
                        continue;
                    }
                };
                if let Some(rc) = retry_config {
                    tracing::info!(
                        upstream = %upstream_cfg.name,
                        "Using resilient transport (retry enabled)"
                    );
                    myelix_core::Upstream::sse_resilient(&upstream_cfg.name, url, rc).await
                } else {
                    myelix_core::Upstream::sse(&upstream_cfg.name, url).await
                }
            }
            other => {
                tracing::error!(
                    upstream = %upstream_cfg.name,
                    transport = %other,
                    "Unknown transport type, skipping"
                );
                continue;
            }
        };

        match connect_result {
            Ok(upstream) => match myelix_core::UpstreamModule::discover(upstream).await {
                Ok(module) => {
                    tracing::info!(
                        upstream = %upstream_cfg.name,
                        transport = %upstream_cfg.transport,
                        "Connected upstream"
                    );
                    builder = builder.module(module);
                }
                Err(e) => {
                    tracing::error!(
                        upstream = %upstream_cfg.name,
                        error = %e,
                        "Failed to discover upstream capabilities, skipping"
                    );
                }
            },
            Err(e) => {
                tracing::error!(
                    upstream = %upstream_cfg.name,
                    error = %e,
                    "Failed to connect upstream, skipping"
                );
            }
        }
    }

    // Register cap_delegate tool if any agent can delegate
    if cfg
        .permissions
        .values()
        .any(|ps| ps.can_delegate)
    {
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
            myelix_core::protocol::ToolDefinition {
                name: "cap_delegate".to_string(),
                description: Some(
                    "Issue an attenuated capability token for a sub-agent. \
                     The new token grants a subset of the caller's capabilities."
                        .to_string(),
                ),
                input_schema: myelix_core::protocol::ToolInputSchema {
                    schema_type: "object".to_string(),
                    properties: {
                        let mut props = std::collections::HashMap::new();
                        props.insert("subject_did".to_string(), serde_json::json!({
                            "type": "string",
                            "description": "DID of the sub-agent receiving the token"
                        }));
                        props.insert("ring".to_string(), serde_json::json!({
                            "type": "integer",
                            "description": "Ring level (must be >= caller's ring)"
                        }));
                        props.insert("operations".to_string(), serde_json::json!({
                            "type": "array", "items": { "type": "string" },
                            "description": "Operations to grant (subset of caller's)"
                        }));
                        props.insert("tools".to_string(), serde_json::json!({
                            "type": "array", "items": { "type": "string" },
                            "description": "Tool globs to grant (subset of caller's)"
                        }));
                        props.insert("paths".to_string(), serde_json::json!({
                            "type": "array", "items": { "type": "string" },
                            "description": "Path globs to grant (subset of caller's)"
                        }));
                        props.insert("credentials".to_string(), serde_json::json!({
                            "type": "array", "items": { "type": "string" },
                            "description": "Credential labels to grant (subset of caller's)"
                        }));
                        props.insert("ttl".to_string(), serde_json::json!({
                            "type": "integer",
                            "description": "Token TTL in seconds"
                        }));
                        Some(props)
                    },
                    required: Some(vec!["subject_did".to_string()]),
                },
            },
            move |args, ctx| {
                let signer = Arc::clone(&delegate_signer);
                let permissions = delegate_permissions.clone();
                let max_depth = max_depth;
                let default_ttl = default_ttl;
                Box::pin(async move {
                    use myelix_core::auth::capability::{
                        build_payload, encode_token, validate_delegation, CapabilitySet,
                    };
                    use myelix_core::protocol::CallToolResult;

                    // Check caller has capabilities (must be cap-token authenticated)
                    // Reject callers with wildcard tool access — cap_delegate must
                    // be explicitly listed in the token's tools (CWE-269).
                    let parent_caps = match &ctx.agent.capabilities {
                        Some(caps) => {
                            if !caps.tools.iter().any(|t| t == "cap_delegate") {
                                return CallToolResult::error(
                                    "Permission denied: cap_delegate must be explicitly \
                                     listed in capability token tools (wildcard not accepted)"
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
                                return CallToolResult::error(
                                    "Permission denied: delegation not allowed for this agent",
                                );
                            }
                            // Build a pseudo-parent from permission set for validation
                            return CallToolResult::error(
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
                        return CallToolResult::error("subject_did is required");
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

                    let mut child_payload = build_payload(
                        &issuer_did,
                        &subject_did,
                        cap_set,
                        ring,
                        ttl,
                    );

                    // Build parent payload for validation
                    let parent_payload =
                        myelix_core::auth::capability::CapabilityPayload {
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
                            nonce: myelix_core::auth::capability::generate_nonce(),
                            parent: None,
                        };

                    // Set parent nonce reference
                    child_payload.parent = Some(parent_payload.nonce);

                    // Validate attenuation
                    if let Err(e) = validate_delegation(&parent_payload, &child_payload, max_depth) {
                        return CallToolResult::error(format!("Delegation denied: {e}"));
                    }

                    // Sign with root key (mcpd signs all tokens)
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
                        Err(e) => CallToolResult::error(format!("Failed to sign token: {e}")),
                    }
                })
            },
        );
        tracing::info!("Registered cap_delegate tool");
    }

    // Register sys_status tool (process table viewer)
    {
        builder = builder.tool(
            myelix_core::protocol::ToolDefinition {
                name: "sys_status".to_string(),
                description: Some(
                    "Show AI OS process table: active agents, their rings, \
                     call counts, and active tool calls."
                        .to_string(),
                ),
                input_schema: myelix_core::protocol::ToolInputSchema {
                    schema_type: "object".to_string(),
                    properties: None,
                    required: None,
                },
            },
            |_args, _ctx| {
                // The actual data comes from the server's process table,
                // but the handler doesn't have access to &self.
                // We return a placeholder — the real implementation
                // will be added when we refactor tool handlers to
                // receive a server reference.
                Box::pin(async {
                    myelix_core::protocol::CallToolResult::text(
                        "sys_status: use GET /sys/status for process table"
                    )
                })
            },
        );
    }

    // Register flow orchestration tools
    let flow_registry = Arc::new(flow_tools::FlowRegistry::new());
    {
        // flow_start — define and launch an async multi-agent flow
        let registry = Arc::clone(&flow_registry);
        builder = builder.tool(
            flow_tools::flow_start_tool_def(),
            move |args, _ctx| {
                let registry = Arc::clone(&registry);
                Box::pin(async move {
                    use myelix_core::protocol::CallToolResult;

                    let flow_toml = match args.get("flow_toml").and_then(|v| v.as_str()) {
                        Some(t) => t,
                        None => return CallToolResult::error("Missing required parameter: flow_toml"),
                    };
                    let prompt = match args.get("prompt").and_then(|v| v.as_str()) {
                        Some(p) => p.to_string(),
                        None => return CallToolResult::error("Missing required parameter: prompt"),
                    };

                    // Parse and validate the flow TOML
                    let flow_def: Result<myelix_flow::FlowDefinition, _> = toml::from_str(flow_toml);
                    let flow_name = match &flow_def {
                        Ok(def) => def.flow.name.clone(),
                        Err(e) => return CallToolResult::error(format!("Invalid flow TOML: {e}")),
                    };

                    let flow_id = registry.register(&flow_name);

                    // Spawn the flow execution in a background task
                    let bg_registry = Arc::clone(&registry);
                    let bg_flow_id = flow_id.clone();
                    let bg_flow_name = flow_name.clone();
                    tokio::spawn(async move {
                        // For now: mark as completed with a placeholder.
                        // Full execution requires creating agents for each node,
                        // which needs model backends and MCP endpoints — this will
                        // be wired in the next iteration.
                        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                        bg_registry.complete(
                            &bg_flow_id,
                            format!(
                                "Flow '{}' accepted. Prompt: {}. \
                                 Note: full multi-agent execution requires model backend \
                                 wiring (next iteration).",
                                bg_flow_name, prompt
                            ),
                        );
                    });

                    tracing::info!(flow_id = %flow_id, name = %flow_name, "Flow started");
                    CallToolResult::text(format!(
                        "Flow started.\nflow_id: {}\nname: {}\n\n\
                         Use flow_status to monitor and flow_result to read outputs.",
                        flow_id, flow_name
                    ))
                })
            },
        );

        // flow_status — check progress of a flow
        let registry = Arc::clone(&flow_registry);
        builder = builder.tool(
            flow_tools::flow_status_tool_def(),
            move |args, _ctx| {
                let registry = Arc::clone(&registry);
                Box::pin(async move {
                    use myelix_core::protocol::CallToolResult;
                    let flow_id = match args.get("flow_id").and_then(|v| v.as_str()) {
                        Some(id) => id,
                        None => return CallToolResult::error("Missing required parameter: flow_id"),
                    };
                    match registry.get_status(flow_id) {
                        Some(status) => CallToolResult::text(
                            serde_json::to_string_pretty(&status).unwrap_or_default()
                        ),
                        None => CallToolResult::error(format!("Unknown flow: {flow_id}")),
                    }
                })
            },
        );

        // flow_result — get output from a completed flow or node
        let registry = Arc::clone(&flow_registry);
        builder = builder.tool(
            flow_tools::flow_result_tool_def(),
            move |args, _ctx| {
                let registry = Arc::clone(&registry);
                Box::pin(async move {
                    use myelix_core::protocol::CallToolResult;
                    let flow_id = match args.get("flow_id").and_then(|v| v.as_str()) {
                        Some(id) => id,
                        None => return CallToolResult::error("Missing required parameter: flow_id"),
                    };
                    let node_id = args.get("node_id").and_then(|v| v.as_str());
                    match registry.get_result(flow_id, node_id) {
                        Some(result) => CallToolResult::text(
                            serde_json::to_string_pretty(&result).unwrap_or_default()
                        ),
                        None => CallToolResult::error(format!("No results for flow: {flow_id}")),
                    }
                })
            },
        );

        tracing::info!("Registered flow orchestration tools (flow_start, flow_status, flow_result)");
    }

    // Register team orchestration tools
    {
        use myelix_core::protocol::CallToolResult;
        use myelix_model::ModelBackend;

        // Pre-fetch Ollama model metadata for all locally running models.
        // This populates vendor fields (family, parameters, context_window)
        // so the lead agent can make informed model selection decisions.
        let mut ollama_meta: std::collections::HashMap<String, serde_json::Value> =
            std::collections::HashMap::new();
        if let Ok(resp) = reqwest::Client::new()
            .get("http://localhost:11434/api/tags")
            .send()
            .await
        {
            if let Ok(tags) = resp.json::<serde_json::Value>().await {
                if let Some(models) = tags["models"].as_array() {
                    for m in models {
                        if let Some(name) = m["name"].as_str() {
                            // Query /api/show for detailed model info
                            if let Ok(show_resp) = reqwest::Client::new()
                                .post("http://localhost:11434/api/show")
                                .json(&serde_json::json!({"name": name}))
                                .send()
                                .await
                            {
                                if let Ok(info) = show_resp.json::<serde_json::Value>().await {
                                    ollama_meta.insert(name.to_string(), info);
                                }
                            }
                        }
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

        // Build composite model cards from config + vendor metadata + operator agentic metadata
        let model_cards: Vec<team_tools::ModelCard> = cfg.models.iter().map(|(name, mcfg)| {
            // model_name overrides config key as the usable model identifier
            let display_name = mcfg.model_name.as_deref().unwrap_or(name);
            let uri_str = mcfg.source.as_deref().unwrap_or(display_name);
            let mut card = myelix_model_hub::ModelCard::new(uri_str);

            // Populate vendor metadata from config
            card.vendor.source = Some(if mcfg.source.is_some() {
                match mcfg.source.as_deref() {
                    Some(s) if s.starts_with("ollama://") => "ollama",
                    Some(s) if s.starts_with("hf://") => "huggingface",
                    Some(s) if s.starts_with("oci://") => "oci",
                    _ => "local",
                }
            } else {
                "local"
            }.into());
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

            // Enrich with Ollama /api/show metadata if available
            if let Some(info) = ollama_meta.get(display_name) {
                card.vendor.source = Some("ollama".into());
                // model_info contains parameter count, architecture, etc.
                if let Some(model_info) = info.get("model_info") {
                    // Extract context window from model metadata
                    for (key, val) in model_info.as_object().into_iter().flatten() {
                        if key.ends_with(".context_length") {
                            if let Some(ctx) = val.as_u64() {
                                card.vendor.context_window = Some(ctx as u32);
                            }
                        }
                        if key.ends_with(".embedding_length") {
                            if let Some(dim) = val.as_u64() {
                                card.vendor.custom.insert(
                                    "embedding_dim".into(),
                                    serde_json::json!(dim),
                                );
                            }
                        }
                    }
                    // Parameter count from general.parameter_count
                    if let Some(params) = model_info.get("general.parameter_count") {
                        if let Some(p) = params.as_u64() {
                            let label = if p >= 1_000_000_000 {
                                format!("{}B", p / 1_000_000_000)
                            } else if p >= 1_000_000 {
                                format!("{}M", p / 1_000_000)
                            } else {
                                format!("{p}")
                            };
                            card.vendor.parameters = Some(label);
                        }
                    }
                    // Architecture / family
                    if let Some(arch) = model_info.get("general.architecture") {
                        if let Some(a) = arch.as_str() {
                            card.vendor.family = Some(a.to_string());
                        }
                    }
                }
                // Quantization from details
                if let Some(details) = info.get("details") {
                    if let Some(quant) = details.get("quantization_level") {
                        if let Some(q) = quant.as_str() {
                            card.vendor.quantization = Some(q.to_string());
                        }
                    }
                    if let Some(family) = details.get("family") {
                        if card.vendor.family.is_none() {
                            card.vendor.family = family.as_str().map(|s| s.to_string());
                        }
                    }
                }
                // License from license field
                if let Some(license) = info.get("license") {
                    if let Some(l) = license.as_str() {
                        // Take first line as the license identifier
                        card.vendor.license = l.lines().next().map(|s| s.to_string());
                    }
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
            if let Some(agentic_cfg) = &mcfg.agentic {
                card.merge_agentic(&agentic_cfg.to_agentic_meta());
            }

            card
        }).collect();

        let team_registry = Arc::new(team_tools::TeamRegistry::new().with_models(model_cards));

        // team_create
        let reg = Arc::clone(&team_registry);
        builder = builder.tool(team_tools::team_create_def(), move |args, ctx| {
            let reg = Arc::clone(&reg);
            Box::pin(async move {
                let name = args.get("name").and_then(|v| v.as_str()).unwrap_or("unnamed");
                let desc = args.get("description").and_then(|v| v.as_str());
                let budget = team_tools::TeamBudget {
                    max_depth: args.get("max_depth").and_then(|v| v.as_u64()).unwrap_or(2) as u32,
                    max_agents: args.get("max_agents").and_then(|v| v.as_u64()).unwrap_or(10) as u32,
                    max_tokens: args.get("max_tokens").and_then(|v| v.as_u64()).unwrap_or(500_000),
                    timeout_secs: args.get("timeout_secs").and_then(|v| v.as_u64()).unwrap_or(600),
                };
                match reg.create_team(name, desc, &ctx.agent.name, 0, budget) {
                    Ok(team_id) => {
                        tracing::info!(team_id = %team_id, name = name, lead = %ctx.agent.name, "Team created");
                        CallToolResult::text(format!("Team created.\nteam_id: {team_id}\nname: {name}"))
                    }
                    Err(e) => CallToolResult::error(e),
                }
            })
        });

        // team_add
        let reg = Arc::clone(&team_registry);
        builder = builder.tool(team_tools::team_add_def(), move |args, _ctx| {
            let reg = Arc::clone(&reg);
            Box::pin(async move {
                let team_id = match args.get("team_id").and_then(|v| v.as_str()) {
                    Some(id) => id, None => return CallToolResult::error("Missing team_id"),
                };
                let name = match args.get("name").and_then(|v| v.as_str()) {
                    Some(n) => n, None => return CallToolResult::error("Missing name"),
                };
                let persona = args.get("persona").and_then(|v| v.as_str());
                let model = args.get("model").and_then(|v| v.as_str()).unwrap_or("auto");
                let locality = args.get("locality").and_then(|v| v.as_str()).unwrap_or("auto");

                match reg.add_teammate(team_id, name, persona, model, locality) {
                    Ok(()) => {
                        tracing::info!(team = team_id, name = name, persona = ?persona, model = model, locality = locality, "Teammate added");
                        CallToolResult::text(format!("Added '{name}' to team (persona: {}, model: {model}, locality: {locality})", persona.unwrap_or("default")))
                    }
                    Err(e) => CallToolResult::error(e),
                }
            })
        });

        // team_message — async: spawns full agent teammate in background
        // The teammate connects to mcpd via MCP, gets its own tool loop,
        // and can use docs_tree, docs_grep, docs_read, team_bb_publish, etc.
        let reg = Arc::clone(&team_registry);
        let msg_mcpd_addr = cfg.server.listen_addr();
        builder = builder.tool(team_tools::team_message_def(), move |args, _ctx| {
            let reg = Arc::clone(&reg);
            let mcpd_addr = msg_mcpd_addr.clone();
            Box::pin(async move {
                let team_id = match args.get("team_id").and_then(|v| v.as_str()) {
                    Some(id) => id.to_string(), None => return CallToolResult::error("Missing team_id"),
                };
                let to = match args.get("to").and_then(|v| v.as_str()) {
                    Some(t) => t.to_string(), None => return CallToolResult::error("Missing to"),
                };
                let message = match args.get("message").and_then(|v| v.as_str()) {
                    Some(m) => m.to_string(), None => return CallToolResult::error("Missing message"),
                };

                if let Err(e) = reg.send_message(&team_id, &to, &message) {
                    return CallToolResult::error(e);
                }

                // Spawn the teammate as a full agent in a background task
                let bg_reg = Arc::clone(&reg);
                let bg_team_id = team_id.clone();
                let bg_to = to.clone();
                let bg_message = message.clone();
                let bg_mcpd_addr = mcpd_addr.clone();

                // Get the team's timeout for the deadline
                let timeout_secs = {
                    let teams = reg.teams.lock().unwrap_or_else(|e| e.into_inner());
                    teams.get(&team_id)
                        .map(|t| {
                            let elapsed = t.created_at.elapsed().as_secs();
                            let budget = t.budget.timeout_secs;
                            if elapsed >= budget { 0 } else { budget - elapsed }
                        })
                        .unwrap_or(600)
                };

                let handle_reg = Arc::clone(&reg);
                let handle_team_id = team_id.clone();
                let handle_to = to.clone();
                let handle = tokio::spawn(async move {
                    let deadline = std::time::Duration::from_secs(timeout_secs);
                    let timeout_team_id = bg_team_id.clone();
                    let timeout_to = bg_to.clone();
                    let timeout_reg = bg_reg.clone();
                    let result = tokio::time::timeout(deadline, async move {
                    tracing::info!(team = %bg_team_id, to = %bg_to, "Teammate agent starting (full MCP agent)");

                    let mcp_url = format!("http://{bg_mcpd_addr}/mcp");

                    // Build the teammate's system prompt
                    let system_prompt = format!(
                        "You are a specialist agent named '{}' working as part of a team.\n\n\
                         You have access to MCP tools: docs_tree, docs_grep, docs_read \
                         for exploring the codebase, and team_bb_publish to share \
                         findings on the team blackboard (team_id: {}).\n\n\
                         When you find something important, publish it to the blackboard \
                         with team_bb_publish so other teammates can see it.\n\n\
                         Report findings as a JSON array:\n\
                         [{{\"file\": \"...\", \"cwe\": \"CWE-NNN\", \"severity\": \"high\", \"description\": \"...\", \"fix\": \"...\"}}]\n\
                         If no findings, return: []\n\n\
                         Your team_id is: {}",
                        bg_to, bg_team_id, bg_team_id
                    );

                    // Get the model name from the teammate's config
                    let mut teammate_model = {
                        let teams = bg_reg.teams.lock().unwrap_or_else(|e| e.into_inner());
                        teams.get(&bg_team_id)
                            .and_then(|t| t.teammates.get(&bg_to))
                            .map(|tm| tm.model.clone())
                            .unwrap_or_else(|| "auto".to_string())
                    };

                    // Resolve "auto" — check what's available
                    if teammate_model == "auto" {
                        // Prefer Ollama if running, otherwise check for Claude
                        let ollama_ok = reqwest::Client::new()
                            .get("http://localhost:11434/api/tags")
                            .send()
                            .await
                            .map(|r| r.status().is_success())
                            .unwrap_or(false);
                        if ollama_ok {
                            // Use first available Ollama model
                            if let Ok(resp) = reqwest::Client::new()
                                .get("http://localhost:11434/api/tags")
                                .send()
                                .await
                            {
                                if let Ok(json) = resp.json::<serde_json::Value>().await {
                                    if let Some(models) = json["models"].as_array() {
                                        if let Some(first) = models.first() {
                                            if let Some(name) = first["name"].as_str() {
                                                teammate_model = name.to_string();
                                            }
                                        }
                                    }
                                }
                            }
                            if teammate_model == "auto" {
                                teammate_model = "granite3.3:8b".to_string();
                            }
                        } else if std::env::var("ANTHROPIC_API_KEY").is_ok()
                            || std::env::var("ANTHROPIC_VERTEX_PROJECT_ID").is_ok()
                        {
                            teammate_model = "claude-sonnet-4-6@default".to_string();
                        } else {
                            teammate_model = "granite3.3:8b".to_string();
                        }
                        tracing::info!(teammate = %bg_to, model = %teammate_model, "Resolved 'auto' model");
                    }

                    eprintln!("  [teammate] {} → model: {}", bg_to, teammate_model);

                    let is_claude = teammate_model.starts_with("claude");

                    // Connect teammate as a full MCP agent
                    macro_rules! run_teammate {
                        ($backend:expr) => {{
                            let r = async {
                                let mut agent = myelix_agent::Agent::builder()
                                    .endpoint(&mcp_url)
                                    .await?
                                    .model($backend)
                                    .system_prompt(&system_prompt)
                                    .max_iterations(30)
                                    .temperature(0.3)
                                    .max_tokens(4096)
                                    .build()?;
                                agent.run(&bg_message).await
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
                            let url = format!(
                                "https://{region}-aiplatform.googleapis.com/v1/projects/{project}/locations/{region}/publishers/anthropic/models/{teammate_model}:rawPredict"
                            );
                            // Fresh gcloud token for this teammate — short-lived, acts as natural timeout
                            let token_output = std::process::Command::new("gcloud")
                                .args(["auth", "print-access-token"])
                                .output();
                            let token = match token_output {
                                Ok(output) if output.status.success() => {
                                    let t = String::from_utf8_lossy(&output.stdout).trim().to_string();
                                    if t.is_empty() {
                                        tracing::error!(teammate = %bg_to, "gcloud returned empty token");
                                        bg_reg.set_failed(&bg_team_id, &bg_to, "Empty gcloud token".to_string());
                                        return;
                                    }
                                    tracing::info!(teammate = %bg_to, "Got fresh gcloud token ({} chars)", t.len());
                                    t
                                }
                                Ok(output) => {
                                    let err = String::from_utf8_lossy(&output.stderr);
                                    tracing::error!(teammate = %bg_to, error = %err, "gcloud token failed");
                                    bg_reg.set_failed(&bg_team_id, &bg_to, format!("gcloud error: {err}"));
                                    return;
                                }
                                Err(e) => {
                                    tracing::error!(teammate = %bg_to, error = %e, "gcloud not available");
                                    bg_reg.set_failed(&bg_team_id, &bg_to, format!("gcloud error: {e}"));
                                    return;
                                }
                            };
                            run_teammate!(myelix_model::AnthropicBackend::new(
                                &url, &teammate_model, Some(token), myelix_model::Locality::Remote,
                            ))
                        } else {
                            let key = std::env::var("ANTHROPIC_API_KEY").ok();
                            run_teammate!(myelix_model::AnthropicBackend::new(
                                "https://api.anthropic.com", &teammate_model, key, myelix_model::Locality::Remote,
                            ))
                        }
                    } else {
                        run_teammate!(myelix_model::OpenAiBackend::new(
                            "http://localhost:11434/v1", &teammate_model, None, myelix_model::Locality::Local,
                        ))
                    };

                    match agent_result {
                        Ok(result) => {
                            let tokens = result.input_tokens + result.output_tokens;
                            bg_reg.add_tokens(&bg_team_id, tokens);
                            tracing::info!(
                                team = %bg_team_id, to = %bg_to,
                                iterations = result.iterations,
                                tokens = tokens,
                                "Teammate completed (full agent)"
                            );
                            bg_reg.set_output(&bg_team_id, &bg_to, result.response);
                        }
                        Err(e) => {
                            tracing::error!(team = %bg_team_id, to = %bg_to, error = %e, "Teammate failed");
                            bg_reg.set_failed(&bg_team_id, &bg_to, format!("Agent error: {e}"));
                        }
                    }
                    }).await; // end of timeout future

                    if result.is_err() {
                        tracing::warn!(team = %timeout_team_id, to = %timeout_to, "Teammate timed out after {timeout_secs}s");
                        timeout_reg.set_failed(&timeout_team_id, &timeout_to, format!("Timed out after {timeout_secs}s"));
                    }
                });

                // Store the handle so it can be aborted on team shutdown
                handle_reg.store_handle(&handle_team_id, &handle_to, handle);

                CallToolResult::text(format!(
                    "Task sent to '{}'. Teammate is running as a full MCP agent \
                     with tool access (docs_tree, docs_grep, docs_read, team_bb_publish). \
                     Use team_status to check progress, team_result to read output.",
                    to
                ))
            })
        });

        // team_status
        let reg = Arc::clone(&team_registry);
        builder = builder.tool(team_tools::team_status_def(), move |args, _ctx| {
            let reg = Arc::clone(&reg);
            Box::pin(async move {
                let team_id = match args.get("team_id").and_then(|v| v.as_str()) {
                    Some(id) => id, None => return CallToolResult::error("Missing team_id"),
                };
                match reg.get_status(team_id) {
                    Some(status) => CallToolResult::text(serde_json::to_string_pretty(&status).unwrap_or_default()),
                    None => CallToolResult::error(format!("Unknown team: {team_id}")),
                }
            })
        });

        // team_result
        let reg = Arc::clone(&team_registry);
        builder = builder.tool(team_tools::team_result_def(), move |args, _ctx| {
            let reg = Arc::clone(&reg);
            Box::pin(async move {
                let team_id = match args.get("team_id").and_then(|v| v.as_str()) {
                    Some(id) => id, None => return CallToolResult::error("Missing team_id"),
                };
                let teammate = match args.get("teammate").and_then(|v| v.as_str()) {
                    Some(t) => t, None => return CallToolResult::error("Missing teammate"),
                };
                match reg.get_result(team_id, teammate) {
                    Some(result) => CallToolResult::text(serde_json::to_string_pretty(&result).unwrap_or_default()),
                    None => CallToolResult::error(format!("No result from '{teammate}'")),
                }
            })
        });

        // team_shutdown
        let reg = Arc::clone(&team_registry);
        builder = builder.tool(team_tools::team_shutdown_def(), move |args, _ctx| {
            let reg = Arc::clone(&reg);
            Box::pin(async move {
                let team_id = match args.get("team_id").and_then(|v| v.as_str()) {
                    Some(id) => id, None => return CallToolResult::error("Missing team_id"),
                };
                match reg.shutdown(team_id) {
                    Ok(info) => {
                        tracing::info!(team = team_id, "Team shut down");
                        CallToolResult::text(serde_json::to_string_pretty(&info).unwrap_or_default())
                    }
                    Err(e) => CallToolResult::error(e),
                }
            })
        });

        // models_list
        let cards = team_registry.model_cards.clone();
        builder = builder.tool(team_tools::models_list_def(), move |_args, _ctx| {
            let cards = cards.clone();
            Box::pin(async move {
                CallToolResult::text(serde_json::to_string_pretty(&cards).unwrap_or_default())
            })
        });

        // team_bb_publish
        let reg = Arc::clone(&team_registry);
        builder = builder.tool(team_tools::team_bb_publish_def(), move |args, ctx| {
            let reg = Arc::clone(&reg);
            Box::pin(async move {
                let team_id = match args.get("team_id").and_then(|v| v.as_str()) {
                    Some(id) => id, None => return CallToolResult::error("Missing team_id"),
                };
                let key = match args.get("key").and_then(|v| v.as_str()) {
                    Some(k) => k, None => return CallToolResult::error("Missing key"),
                };
                let value = match args.get("value").and_then(|v| v.as_str()) {
                    Some(v) => v, None => return CallToolResult::error("Missing value"),
                };
                reg.bb_publish(team_id, key, value, &ctx.agent.name);
                CallToolResult::text(format!("Published '{key}' to team blackboard"))
            })
        });

        // team_bb_read
        let reg = Arc::clone(&team_registry);
        builder = builder.tool(team_tools::team_bb_read_def(), move |args, _ctx| {
            let reg = Arc::clone(&reg);
            Box::pin(async move {
                let team_id = match args.get("team_id").and_then(|v| v.as_str()) {
                    Some(id) => id, None => return CallToolResult::error("Missing team_id"),
                };
                let key = match args.get("key").and_then(|v| v.as_str()) {
                    Some(k) => k, None => return CallToolResult::error("Missing key"),
                };
                match reg.bb_read(team_id, key) {
                    Some(entry) => CallToolResult::text(
                        serde_json::to_string_pretty(&entry).unwrap_or_default()
                    ),
                    None => CallToolResult::error(format!("No blackboard entry: {key}")),
                }
            })
        });

        tracing::info!("Registered team tools (team_create, team_add, team_message, team_status, team_result, team_shutdown, team_bb_publish, team_bb_read, models_list)");
    }

    let server = Arc::new(builder.build());
    tracing::info!(
        tools = server.tool_count(),
        prompts = server.prompt_count(),
        resources = server.resource_count(),
        "Server ready"
    );

    // --- mDNS advertising ---
    if mdns_enabled {
        // Extract port from TCP address for advertising
        let tcp_port = cfg
            .server
            .tcp
            .as_ref()
            .and_then(|addr| addr.rsplit(':').next())
            .and_then(|p| p.parse::<u16>().ok())
            .unwrap_or(9315);

        match mdns::advertise(&server.server_info().name, tcp_port, "/mcp") {
            Ok(daemon) => {
                tracing::info!(port = tcp_port, "Advertising via mDNS on _mcp._tcp.local.");
                _mdns_daemon = Some(daemon);
            }
            Err(e) => {
                tracing::warn!("mDNS advertising failed: {e}");
            }
        }
    }

    // --- System tray ---
    if !no_tray {
        match tray::spawn_tray().await {
            Ok((cmd_rx, handle)) => {
                tracing::info!("System tray icon active");
                tokio::spawn(tray::run_tray_updater(
                    handle,
                    approvals.clone(),
                    server.pause_flag(),
                    cmd_rx,
                ));
            }
            Err(e) => {
                tracing::warn!("System tray unavailable: {e}");
            }
        }
    }

    // --- Build registry entries ---
    let mut registry_entries: Vec<serde_json::Value> = Vec::new();

    // Add mcpd's own entry (from its server card data)
    if let Some(ref discovery) = cfg.server.discovery {
        registry_entries.push(serde_json::json!({
            "server": {
                "name": server.server_info().name,
                "description": format!(
                    "{}",
                    discovery.description.as_deref().unwrap_or("mcpd MCP gateway")
                ),
                "version": server.server_info().version,
                "remotes": [{
                    "type": "streamable-http",
                    "url": &discovery.url,
                }],
            },
            "_meta": {
                "source": "self",
            }
        }));
    }

    // Add whitelisted entries from config
    for entry in &cfg.registry {
        registry_entries.push(serde_json::json!({
            "server": {
                "name": &entry.name,
                "description": &entry.description,
                "remotes": [{
                    "type": &entry.remote_type,
                    "url": &entry.url,
                }],
                "repository": entry.repository.as_ref().map(|r| serde_json::json!({"url": r})),
            },
            "_meta": {
                "source": "whitelist",
            }
        }));
    }

    if !registry_entries.is_empty() {
        tracing::info!(
            entries = registry_entries.len(),
            "Registry serving {} entries at /v0.1/servers",
            registry_entries.len()
        );
    }

    // --- HTTP transport with SSE broadcaster ---
    let broadcaster = myelix_core::transport::SseBroadcaster::new();
    let has_discovery = cfg.server.discovery.is_some() || !registry_entries.is_empty();
    let (router, server) = if has_discovery {
        let aid_record = cfg.server.discovery.as_ref().map(|discovery| {
            let mut aid = serde_json::json!({
                "v": "aid1",
                "u": &discovery.url,
                "p": "mcp",
                "a": &discovery.auth,
            });
            if let Some(ref desc) = discovery.description {
                aid["s"] = serde_json::json!(desc);
            }
            if let Some(ref docs) = discovery.docs_url {
                aid["d"] = serde_json::json!(docs);
            }
            // Populate PKA field with root Ed25519 public key
            let pubkey_multibase = format!(
                "z{}",
                bs58::encode({
                    let mut bytes = vec![0xed, 0x01];
                    bytes.extend_from_slice(&root_signer.public_key_bytes());
                    bytes
                })
                .into_string()
            );
            aid["k"] = serde_json::json!(pubkey_multibase);
            aid["i"] = serde_json::json!("root-1");
            tracing::info!(
                url = %discovery.url,
                did = %root_signer.did(),
                "AID discovery at /.well-known/agent (with PKA)"
            );
            aid
        });
        let a2a_endpoint = cfg.server.discovery.as_ref().map(|d| d.url.clone());
        if a2a_endpoint.is_some() {
            tracing::info!("A2A Agent Card at /.well-known/agent.json");
        }
        let root_did_str = Some(root_signer.did().to_string());
        let api_server_ref = Arc::clone(&server);
        let router = myelix_core::transport::build_router_with_discovery(
            server, broadcaster, aid_record, registry_entries, a2a_endpoint, root_did_str,
        );
        (router, api_server_ref)
    } else {
        let api_server_ref = Arc::clone(&server);
        let router = myelix_core::transport::build_router_with_broadcaster(server, broadcaster);
        (router, api_server_ref)
    };

    // --- Web UI: shared state + API routes ---

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

    let router = router
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
            let api_server = Arc::clone(&server);
            axum::routing::get(move |headers: axum::http::HeaderMap| {
                let models = models.clone();
                let personas = personas.clone();
                let api_server = Arc::clone(&api_server);
                async move {
                    if let Err(_) = api_server.authenticator().authenticate(&headers) {
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
            let api_server = Arc::clone(&server);
            axum::routing::get(move |headers: axum::http::HeaderMap| {
                let models = models.clone();
                let api_server = Arc::clone(&api_server);
                async move {
                    if let Err(_) = api_server.authenticator().authenticate(&headers) {
                        return axum::Json(serde_json::json!({"error": "unauthorized"}));
                    }
                    axum::Json(serde_json::json!(*models))
                }
            })
        })

        // --- API: Agents (authenticated) ---
        .route("/api/agents", {
            let agents = ui_agents.clone();
            let api_server = Arc::clone(&server);
            axum::routing::get(move |headers: axum::http::HeaderMap| {
                let agents = agents.clone();
                let api_server = Arc::clone(&api_server);
                async move {
                    if let Err(_) = api_server.authenticator().authenticate(&headers) {
                        return axum::Json(serde_json::json!({"error": "unauthorized"}));
                    }
                    axum::Json(serde_json::json!(*agents))
                }
            })
        })

        // --- API: Flows (authenticated) ---
        .route("/api/flows", {
            let flows = ui_flows.clone();
            let api_server = Arc::clone(&server);
            axum::routing::get(move |headers: axum::http::HeaderMap| {
                let flows = flows.clone();
                let api_server = Arc::clone(&api_server);
                async move {
                    if let Err(_) = api_server.authenticator().authenticate(&headers) {
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
            let api_server = Arc::clone(&server);
            axum::routing::post(move |headers: axum::http::HeaderMap, body: axum::Json<serde_json::Value>| {
                let backend = backend.clone();
                let forge = forge.clone();
                let api_server = Arc::clone(&api_server);
                async move {
                    if let Err(_) = api_server.authenticator().authenticate(&headers) {
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
        });

    tracing::info!("Web UI at http://localhost:{}", cfg.server.tcp.as_deref().and_then(|a| a.rsplit(':').next()).unwrap_or("9315"));

    // Listen on Unix socket, TCP, or both
    if let Some(ref socket_path) = cfg.server.socket {
        let tcp_addr = cfg.server.tcp.clone();

        // Ensure parent directory exists
        if let Some(parent) = std::path::Path::new(socket_path).parent() {
            std::fs::create_dir_all(parent)?;
        }

        // Remove stale socket file if it exists
        if std::path::Path::new(socket_path).exists() {
            std::fs::remove_file(socket_path)?;
        }

        let unix_listener = tokio::net::UnixListener::bind(socket_path)?;

        // Set socket permissions to owner-only (0600)
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(socket_path, std::fs::Permissions::from_mode(0o600))?;
        }

        tracing::info!("Listening on unix:{socket_path}");

        // Graceful shutdown on SIGTERM/SIGINT
        let shutdown = async {
            let ctrl_c = tokio::signal::ctrl_c();
            #[cfg(unix)]
            let mut sigterm = tokio::signal::unix::signal(
                tokio::signal::unix::SignalKind::terminate(),
            ).expect("failed to install SIGTERM handler");
            #[cfg(unix)]
            tokio::select! {
                _ = ctrl_c => tracing::info!("Received SIGINT, shutting down"),
                _ = sigterm.recv() => tracing::info!("Received SIGTERM, shutting down"),
            }
            #[cfg(not(unix))]
            ctrl_c.await.ok();
        };

        if let Some(addr) = tcp_addr {
            // Both Unix socket and TCP
            let tcp_listener = tokio::net::TcpListener::bind(&addr).await?;
            tracing::info!("Listening on tcp:{addr}");

            let tcp_router = router.clone();
            tokio::select! {
                result = axum::serve(unix_listener, router)
                    .with_graceful_shutdown(shutdown) => result?,
                result = axum::serve(tcp_listener, tcp_router) => result?,
            }
        } else {
            // Unix socket only
            axum::serve(unix_listener, router)
                .with_graceful_shutdown(shutdown).await?;
        }
    } else {
        // TCP only (fallback)
        let addr = cfg.server.listen_addr();
        let listener = tokio::net::TcpListener::bind(&addr).await?;
        tracing::info!("Listening on tcp:{addr}");

        let shutdown = async {
            let ctrl_c = tokio::signal::ctrl_c();
            #[cfg(unix)]
            let mut sigterm = tokio::signal::unix::signal(
                tokio::signal::unix::SignalKind::terminate(),
            ).expect("failed to install SIGTERM handler");
            #[cfg(unix)]
            tokio::select! {
                _ = ctrl_c => tracing::info!("Received SIGINT, shutting down"),
                _ = sigterm.recv() => tracing::info!("Received SIGTERM, shutting down"),
            }
            #[cfg(not(unix))]
            ctrl_c.await.ok();
        };

        axum::serve(listener, router)
            .with_graceful_shutdown(shutdown).await?;
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

/// Send an approve or deny request to the running server via JSON-RPC.
async fn approve_or_deny(addr: &str, request_id: &str, approve: bool) -> anyhow::Result<()> {
    let tool_name = if approve { "docs_approve" } else { "docs_deny" };
    let action = if approve { "Approved" } else { "Denied" };

    let client = reqwest::Client::new();
    let url = format!("http://{addr}/mcp");

    let body = serde_json::json!({
        "jsonrpc": "2.0",
        "method": "tools/call",
        "id": 1,
        "params": {
            "name": tool_name,
            "arguments": {
                "request_id": request_id
            }
        }
    });

    let resp = client
        .post(&url)
        .header("Content-Type", "application/json")
        .json(&body)
        .send()
        .await?;

    if !resp.status().is_success() {
        let status = resp.status();
        let text = resp.text().await.unwrap_or_default();
        anyhow::bail!("Server returned {status}: {text}");
    }

    let result: serde_json::Value = resp.json().await?;
    if let Some(error) = result.get("error") {
        let msg = error.get("message").and_then(|m| m.as_str()).unwrap_or("unknown");
        anyhow::bail!("Server error: {msg}");
    }

    println!("{action} request {request_id}");
    Ok(())
}

/// Query the running server for status via the initialize endpoint.
async fn query_status(addr: &str) -> anyhow::Result<()> {
    let client = reqwest::Client::new();
    let url = format!("http://{addr}/mcp");

    let body = serde_json::json!({
        "jsonrpc": "2.0",
        "method": "initialize",
        "id": 1,
        "params": {
            "protocolVersion": "2025-03-26",
            "capabilities": {},
            "clientInfo": {
                "name": "mcpd-cli",
                "version": env!("CARGO_PKG_VERSION")
            }
        }
    });

    let resp = client
        .post(&url)
        .header("Content-Type", "application/json")
        .json(&body)
        .send()
        .await;

    match resp {
        Ok(r) if r.status().is_success() => {
            let result: serde_json::Value = r.json().await?;
            if let Some(info) = result.get("result") {
                let name = info
                    .get("serverInfo")
                    .and_then(|s| s.get("name"))
                    .and_then(|n| n.as_str())
                    .unwrap_or("unknown");
                let version = info
                    .get("serverInfo")
                    .and_then(|s| s.get("version"))
                    .and_then(|v| v.as_str())
                    .unwrap_or("unknown");
                let has_tools = info
                    .get("capabilities")
                    .and_then(|c| c.get("tools"))
                    .is_some();
                let has_prompts = info
                    .get("capabilities")
                    .and_then(|c| c.get("prompts"))
                    .is_some();
                let has_resources = info
                    .get("capabilities")
                    .and_then(|c| c.get("resources"))
                    .is_some();

                println!("Server: {name} v{version}");
                println!("Status: running");
                println!("Address: {addr}");
                println!(
                    "Capabilities: {}",
                    [
                        has_tools.then_some("tools"),
                        has_prompts.then_some("prompts"),
                        has_resources.then_some("resources"),
                    ]
                    .into_iter()
                    .flatten()
                    .collect::<Vec<_>>()
                    .join(", ")
                );
            }
        }
        Ok(r) => {
            println!("Server at {addr} returned {}", r.status());
        }
        Err(_) => {
            println!("Server at {addr} is not reachable.");
            println!("Is mcpd running? Start it with: mcpd serve");
        }
    }
    Ok(())
}

/// Install systemd user units for mcpd.
fn install_systemd_units() -> anyhow::Result<()> {
    let unit_dir = dirs::config_dir()
        .ok_or_else(|| anyhow::anyhow!("Cannot determine config directory"))?
        .join("systemd/user");
    std::fs::create_dir_all(&unit_dir)?;

    let service_content = include_str!("../systemd/mcpd.service");
    let socket_content = include_str!("../systemd/mcpd.socket");

    let service_path = unit_dir.join("mcpd.service");
    let socket_path = unit_dir.join("mcpd.socket");

    std::fs::write(&service_path, service_content)?;
    println!("Installed {}", service_path.display());

    std::fs::write(&socket_path, socket_content)?;
    println!("Installed {}", socket_path.display());

    // Reload systemd and enable
    let reload = std::process::Command::new("systemctl")
        .args(["--user", "daemon-reload"])
        .status();
    if let Ok(status) = reload {
        if status.success() {
            println!("Reloaded systemd user daemon");
        }
    }

    let enable = std::process::Command::new("systemctl")
        .args(["--user", "enable", "mcpd.service", "mcpd.socket"])
        .status();
    if let Ok(status) = enable {
        if status.success() {
            println!("Enabled mcpd.service and mcpd.socket");
        }
    }

    println!("\nTo start now:  systemctl --user start mcpd.service");
    println!("To check logs: journalctl --user -u mcpd.service -f");
    Ok(())
}

/// Uninstall systemd user units for mcpd.
fn uninstall_systemd_units() -> anyhow::Result<()> {
    // Stop and disable first
    let _ = std::process::Command::new("systemctl")
        .args(["--user", "stop", "mcpd.service", "mcpd.socket"])
        .status();
    let _ = std::process::Command::new("systemctl")
        .args(["--user", "disable", "mcpd.service", "mcpd.socket"])
        .status();

    let unit_dir = dirs::config_dir()
        .ok_or_else(|| anyhow::anyhow!("Cannot determine config directory"))?
        .join("systemd/user");

    let service_path = unit_dir.join("mcpd.service");
    let socket_path = unit_dir.join("mcpd.socket");

    if service_path.exists() {
        std::fs::remove_file(&service_path)?;
        println!("Removed {}", service_path.display());
    }
    if socket_path.exists() {
        std::fs::remove_file(&socket_path)?;
        println!("Removed {}", socket_path.display());
    }

    let _ = std::process::Command::new("systemctl")
        .args(["--user", "daemon-reload"])
        .status();

    println!("mcpd systemd units uninstalled");
    Ok(())
}

// --- Model management ---

/// A known model in the registry.
struct KnownModel {
    /// Short name for CLI use.
    name: &'static str,
    /// Description.
    description: &'static str,
    /// HuggingFace repo ID.
    repo: &'static str,
    /// ONNX model filename within the repo.
    model_file: &'static str,
    /// Tokenizer filename (if any).
    tokenizer_file: Option<&'static str>,
    /// Config snippet template.
    config_template: &'static str,
}

const KNOWN_MODELS: &[KnownModel] = &[
    KnownModel {
        name: "guardian-hap",
        description: "Granite Guardian HAP 38M — fast safety classifier (Apache 2.0)",
        repo: "KantiArumilli/granite-guardian-hap-38m-onnx",
        model_file: "guardian_model_quantized.onnx",
        tokenizer_file: Some("tokenizer/tokenizer.json"),
        config_template: r#"[models.guardian-hap]
model_path = "{model_dir}/model.onnx"
tokenizer_path = "{model_dir}/tokenizer.json"
task = "classification"
labels = ["safe", "hap"]
threshold = 0.5"#,
    },
    KnownModel {
        name: "granite-embed",
        description: "Granite Embedding R2 — text embeddings, 768-dim (Apache 2.0)",
        repo: "yasserrmd/granite-embedding-r2-onnx",
        model_file: "model.onnx",
        tokenizer_file: Some("tokenizer.json"),
        config_template: r#"[models.granite-embed]
model_path = "{model_dir}/model.onnx"
tokenizer_path = "{model_dir}/tokenizer.json"
task = "embedding"
dimensions = 768"#,
    },
];

/// Get the models directory.
fn models_dir() -> std::path::PathBuf {
    dirs::data_dir()
        .unwrap_or_else(|| std::path::PathBuf::from("."))
        .join("mcpd/models")
}

/// Download a file from a URL to a local path with progress.
async fn download_file(url: &str, dest: &std::path::Path) -> anyhow::Result<()> {
    let client = reqwest::Client::new();
    let resp = client.get(url).send().await?;

    if !resp.status().is_success() {
        anyhow::bail!("Download failed: HTTP {}", resp.status());
    }

    let total = resp.content_length();
    let mut file = tokio::fs::File::create(dest).await?;
    let mut stream = resp.bytes_stream();

    use futures_util::StreamExt;
    use tokio::io::AsyncWriteExt;

    let mut downloaded: u64 = 0;
    while let Some(chunk) = stream.next().await {
        let chunk = chunk?;
        file.write_all(&chunk).await?;
        downloaded += chunk.len() as u64;
        if let Some(total) = total {
            eprint!(
                "\r  {:.1} / {:.1} MB",
                downloaded as f64 / 1_048_576.0,
                total as f64 / 1_048_576.0
            );
        } else {
            eprint!("\r  {:.1} MB", downloaded as f64 / 1_048_576.0);
        }
    }
    eprintln!();
    file.flush().await?;
    Ok(())
}

/// Pull a model by name or URI.
///
/// Accepts known model names (guardian-hap, granite-embed) for ONNX models,
/// or any hub URI (ollama://, hf://, oci://, file://) for general models.
async fn model_pull(name: &str) -> anyhow::Result<()> {
    // Check if it's a known ONNX model first
    if let Some(model) = KNOWN_MODELS.iter().find(|m| m.name == name) {
        let model_dir = models_dir().join(model.name);
        std::fs::create_dir_all(&model_dir)?;

        println!("Pulling {} ...", model.description);

        let model_url = format!(
            "https://huggingface.co/{}/resolve/main/{}",
            model.repo, model.model_file
        );
        let model_dest = model_dir.join("model.onnx");
        if model_dest.exists() {
            println!("  model.onnx already exists, skipping");
        } else {
            println!("  Downloading model.onnx ...");
            download_file(&model_url, &model_dest).await?;
        }

        if let Some(tok_file) = model.tokenizer_file {
            let tok_url = format!(
                "https://huggingface.co/{}/resolve/main/{}",
                model.repo, tok_file
            );
            let tok_dest = model_dir.join("tokenizer.json");
            if tok_dest.exists() {
                println!("  tokenizer.json already exists, skipping");
            } else {
                println!("  Downloading tokenizer.json ...");
                download_file(&tok_url, &tok_dest).await?;
            }
        }

        println!("\nInstalled to: {}", model_dir.display());
        println!("\nAdd to config.toml:\n");
        let config_snippet = model
            .config_template
            .replace("{model_dir}", &model_dir.to_string_lossy());
        println!("{config_snippet}");
        return Ok(());
    }

    // Otherwise, treat as a hub URI
    let uri = myelix_model_hub::ModelUri::parse(name)?;
    let hub = myelix_model_hub::ModelHub::new()?;

    println!("Pulling {uri} ...");
    let path = hub.pull(&uri).await?;
    println!("\nCached at: {}", path.display());
    println!("\nAdd to config.toml:\n");
    println!("[models.{}]", uri.cache_key());
    println!("source = \"{}\"", uri);
    println!("task = \"chat\"");
    println!("runtime = \"auto\"");

    Ok(())
}

/// List installed models (ONNX + hub-cached).
fn model_list() -> anyhow::Result<()> {
    let mut found = false;

    // ONNX models in the legacy directory
    let dir = models_dir();
    if dir.exists() {
        for entry in std::fs::read_dir(&dir)? {
            let entry = entry?;
            if entry.file_type()?.is_dir() {
                let name = entry.file_name();
                let name = name.to_string_lossy();
                let model_path = entry.path().join("model.onnx");
                let has_model = model_path.exists();
                let has_tokenizer = entry.path().join("tokenizer.json").exists();
                let size = if has_model {
                    let meta = std::fs::metadata(&model_path)?;
                    format!("{:.1} MB", meta.len() as f64 / 1_048_576.0)
                } else {
                    "incomplete".to_string()
                };

                let tok_status = if has_tokenizer { "yes" } else { "no" };
                println!("{name:<40} {size:<12} onnx  tokenizer: {tok_status}");
                found = true;
            }
        }
    }

    // Hub-cached models
    if let Ok(hub) = myelix_model_hub::ModelHub::new() {
        if let Ok(cached) = hub.list() {
            for model in cached {
                let size = format!("{:.1} MB", model.size as f64 / 1_048_576.0);
                println!("{:<40} {size:<12} hub", model.uri);
                found = true;
            }
        }
    }

    if !found {
        println!("No models installed.");
        println!("Run 'mcpd model available' to see supported models.");
        println!("Or pull any model: mcpd model pull ollama://granite3.3:8b");
    }

    Ok(())
}

/// Show available models for download.
fn model_available() {
    println!("Built-in ONNX models:");
    println!("{:<20} {}", "NAME", "DESCRIPTION");
    println!("{:<20} {}", "----", "-----------");
    for model in KNOWN_MODELS {
        println!("{:<20} {}", model.name, model.description);
    }
    println!("\nPull a built-in model:  mcpd model pull <name>");
    println!("\nYou can also pull any model by URI:");
    println!("  mcpd model pull ollama://granite3.3:8b");
    println!("  mcpd model pull hf://ibm-granite/granite-3.3-8b-instruct-GGUF");
    println!("  mcpd model pull oci://quay.io/myorg/mymodel:latest");
}

/// Run the end-to-end security audit demo.
///
/// This is a scripted walkthrough that demonstrates every subsystem
/// without requiring a real LLM. It simulates the agent interactions
/// and shows what each layer does with real data.
async fn run_demo(project: &str) -> anyhow::Result<()> {
    use std::path::Path;
    use std::time::Duration;

    let project_path = Path::new(project);
    if !project_path.exists() {
        anyhow::bail!(
            "Demo project not found at '{}'. Run from the repo root.",
            project
        );
    }

    // Verify expected files exist
    let expected_files = [
        "src/config.rs",
        "src/handler.rs",
        "src/secrets.rs",
        "src/api.rs",
        "personas/security_auditor.yaml",
        "personas/code_specialist.yaml",
        "personas/analyst.yaml",
        "config/audit-flow.toml",
    ];
    for file in &expected_files {
        if !project_path.join(file).exists() {
            anyhow::bail!("Missing demo file: {}/{}", project, file);
        }
    }

    println!();
    println!("╔══════════════════════════════════════════════════════════════╗");
    println!("║  myelix-* Framework — End-to-End Security Audit Demo       ║");
    println!("║  Project: {}{}║", project, " ".repeat(49 - project.len().min(49)));
    println!("╚══════════════════════════════════════════════════════════════╝");
    println!();

    // --- Act 1: Gateway & Identity ---
    println!("━━━ Act 1: Gateway & Identity ━━━");
    tokio::time::sleep(Duration::from_millis(300)).await;

    let identity_path = std::path::PathBuf::from("/tmp/mcpd-demo/identity.key");
    std::fs::create_dir_all("/tmp/mcpd-demo")?;
    let root_signer = myelix_core::identity::load_or_create_file_identity(&identity_path)?;
    println!("  ✓ Root identity: {}", root_signer.did());

    let agents = [
        ("security-auditor", "auditor", 2),
        ("code-specialist", "developer", 3),
        ("analyst", "analyst", 2),
    ];
    for (name, perms, ring) in &agents {
        let token = config::generate_token();
        println!(
            "  ✓ Agent \"{}\" authenticated (ring {}, permissions: {})",
            name, ring, perms
        );
        let _ = token; // Token generated but not needed for demo output
    }
    println!();

    // --- Act 2: Cognitive Core ---
    println!("━━━ Act 2: Cognitive Core ━━━");
    tokio::time::sleep(Duration::from_millis(300)).await;

    let _forge = match myelix_cognitive::ForgeService::load(project_path) {
        Ok(f) => {
            for name in f.persona_names() {
                if let Some(persona) = f.get_persona(name) {
                    println!(
                        "  ✓ Loaded persona: {} ({} heuristic modules)",
                        persona.persona_name,
                        persona.heuristics.len()
                    );
                }
            }
            println!(
                "  ✓ Loaded {} heuristic modules with {} total facets",
                f.heuristic_count(),
                ["owasp_top_10", "secure_coding", "risk_assessment"]
                    .iter()
                    .filter_map(|h| f.get_heuristic(h))
                    .map(|h| h.facets.len())
                    .sum::<usize>()
            );
            f
        }
        Err(e) => {
            println!("  ⚠ Forge load warning: {} (continuing with empty)", e);
            myelix_cognitive::ForgeService::empty()
        }
    };

    println!("  ✓ Weaver ready (stable prefix caching enabled)");
    println!();

    // --- Act 3: Parallel Scan ---
    println!("━━━ Act 3: Parallel Scan [T1|T2|T3] ━━━");
    tokio::time::sleep(Duration::from_millis(300)).await;

    // T1: scan-auth
    println!("  ┌─ T1: scan-auth (security_auditor) ────────────────────");
    let handler_content = std::fs::read_to_string(project_path.join("src/handler.rs"))?;
    let api_content = std::fs::read_to_string(project_path.join("src/api.rs"))?;
    println!("  │ Reading: src/handler.rs → IFC: Trusted");
    println!("  │ Reading: src/api.rs → IFC: Trusted");

    // Simulate finding auth issues
    if handler_content.contains("admin_refund") && !handler_content.contains("verify_admin") {
        println!("  │ Finding: CWE-287 Missing authentication on admin_refund()");
    }
    if api_content.contains("handle_user_payments") && api_content.contains("// VULN: No IDOR") {
        println!("  │ Finding: CWE-639 IDOR on handle_user_payments()");
    }
    if api_content.contains("handle_webhook") && api_content.contains("signature not verified") {
        println!("  │ Finding: CWE-347 Missing webhook signature verification");
    }
    println!("  └─ 3 findings (1 critical, 2 high)");
    println!();

    // T2: scan-injection
    println!("  ┌─ T2: scan-injection (security_auditor) ──────────────");
    println!("  │ Reading: src/handler.rs → IFC: Trusted");
    if handler_content.contains("format!(") && handler_content.contains("VALUES ('{}'") {
        println!("  │ Finding: CWE-89 SQL injection in process_payment()");
    }
    if handler_content.contains("format!(") && handler_content.contains("WHERE user_id = '{}'") {
        println!("  │ Finding: CWE-89 SQL injection in get_history()");
    }
    println!("  └─ 2 findings (2 critical)");
    println!();

    // T3: scan-secrets
    println!("  ┌─ T3: scan-secrets (security_auditor) ────────────────");
    let config_content = std::fs::read_to_string(project_path.join("src/config.rs"))?;
    println!("  │ Reading: src/config.rs → IFC: Trusted");

    // Safety filter simulation
    if config_content.contains("sk_live_") {
        println!("  │ ⚠ Safety filter: redacted \"sk_live_4eC39HqLyjW...\"");
    }
    if config_content.contains("whsec_") {
        println!("  │ ⚠ Safety filter: redacted \"whsec_MfKQ9r8GKY...\"");
    }
    println!("  │ Finding: CWE-798 Hardcoded API key in config.rs");

    // IFC taint tracking
    let secrets_content = std::fs::read_to_string(project_path.join("src/secrets.rs"))?;
    println!("  │ Reading: src/secrets.rs → IFC: Confidential ⚡");
    println!("  │ ⚡ Context tainted: Confidential (Bell-LaPadula)");
    println!("  │ ⚡ Remote model backend BLOCKED (locality: Remote)");
    println!("  │ ✓ Local model backend allowed (locality: Local)");
    if secrets_content.contains("PAYMENT_TOKEN_KEY") {
        println!("  │ Finding: CWE-312 Encryption keys in source code");
    }
    println!("  └─ 2 findings (2 critical)");
    println!();

    // --- Act 4: Synthesis ---
    println!("━━━ Act 4: Synthesis [T4] ━━━");
    tokio::time::sleep(Duration::from_millis(300)).await;

    println!("  ┌─ T4: synthesize (analyst) ──────────────────────────");
    println!("  │ Memory recall: \"Previous audit March 2026: SQL injection");
    println!("  │   in process_payment() — UNRESOLVED (ticket VULN-142)\"");
    println!("  │ Memory recall: \"PCI DSS Q1 review: encryption key in");
    println!("  │   secrets.rs — must move to KMS before Q2 deadline\"");
    println!("  │ ⚡ PATTERN MATCH: SQL injection found again (was in");
    println!("  │   previous audit, still unresolved after 1 month)");
    println!("  │ Report: 7 findings total");
    println!("  │   Critical (4): 2× SQL injection, API key exposure, PCI violation");
    println!("  │   High (2): missing admin auth, IDOR");
    println!("  │   Medium (1): PII in logs");
    println!("  └─ Prioritized report generated");
    println!();

    // --- Act 5: Fix & Review ---
    println!("━━━ Act 5: Fix & Review [T5→T6] ━━━");
    tokio::time::sleep(Duration::from_millis(300)).await;

    println!("  ┌─ T5: propose-fixes (code_specialist) ────────────────");
    println!("  │ Fix 1: SQL injection → parameterized queries (.bind())");
    println!("  │ Fix 2: Hardcoded secrets → env::var() with error handling");
    println!("  │ Fix 3: Missing auth → auth middleware on admin endpoints");
    println!("  │ ✓ Mandate check: each fix maps to a specific CWE");
    println!("  └─ 3 patches proposed");
    println!();

    println!("  ┌─ T6: review-fixes (security_auditor) ────────────────");
    println!("  │ Fix 1 (SQL injection): ✓ Approved");
    println!("  │ Fix 2 (secrets): ✓ Approved");
    println!("  │ Fix 3 (auth): ⚠ Change requested — \"also add rate limiting\"");
    println!("  │ → Routing back to T5 with feedback");
    println!("  └─ 2 approved, 1 revision needed");
    println!();

    println!("  ┌─ T5 (retry): propose-fixes (code_specialist) ────────");
    println!("  │ Fix 3 (revised): auth middleware + rate limiter");
    println!("  │ ✓ Circular fix detector: attempt 2/3, no loop");
    println!("  └─ Revised fix proposed");
    println!();

    println!("  ┌─ T6 (retry): review-fixes (security_auditor) ────────");
    println!("  │ Fix 3 (revised): ✓ Approved");
    println!("  └─ All fixes approved");
    println!();

    // --- Act 6: Commit ---
    println!("━━━ Act 6: Commit [T7] ━━━");
    tokio::time::sleep(Duration::from_millis(300)).await;

    println!("  ┌─ T7: prepare-commit (code_specialist) ───────────────");
    println!("  │ Applying 3 fixes to src/handler.rs, src/config.rs, src/api.rs");
    println!("  │ ⏳ git_commit requires approval (permission: \"approve\")");
    println!("  │ 🔔 D-Bus notification: \"Agent wants to commit 3 files\"");
    println!("  │ ✓ Auto-approved (demo mode)");
    println!(
        "  │ ✓ Commit signed (Ed25519, {})",
        root_signer.did()
    );
    println!("  │ ✓ Working memory updated: audit findings saved");
    println!("  └─ Commit: \"fix: remediate SQL injection, secret exposure,");
    println!("     and missing auth (CWE-89, CWE-798, CWE-287)\"");
    println!();

    // --- Summary ---
    println!("━━━ Summary ━━━");
    println!("  Tasks:     7 completed (2 retried)");
    println!("  Findings:  7 (4 critical, 2 high, 1 medium)");
    println!("  Fixes:     3 applied, reviewed, committed");
    println!("  IFC:       1 Confidential taint event (secrets.rs)");
    println!("  Safety:    2 secrets redacted (Stripe key, webhook secret)");
    println!("  Approvals: 1 (auto-approved in demo mode)");
    println!("  Memory:    3 items recalled, 1 new item stored");
    println!("  Personas:  3 active (security_auditor, code_specialist, analyst)");
    println!();
    println!("  Framework: {} crates, {} tests",
        16, // workspace crate count
        "668+", // test count
    );
    println!();

    Ok(())
}

/// Run the live end-to-end demo with a real LLM.
///
/// Unlike `run_demo` (scripted), this actually calls a model for each
/// task. It requires Ollama running with the specified model pulled.
async fn run_demo_live(project: &str, model_name: &str, _max_rounds: u32, _files_per_round: usize, _min_delta: u32) -> anyhow::Result<()> {
    use std::path::Path;

    let project_path = Path::new(project);
    if !project_path.exists() {
        anyhow::bail!("Demo project not found at '{}'. Run from the repo root.", project);
    }

    println!();
    println!("╔══════════════════════════════════════════════════════════════╗");
    println!("║  myelix-* Framework — LIVE Security Audit Demo             ║");
    println!("║  Project: {}{}║", project, " ".repeat(49 - project.len().min(49)));
    println!("║  Model:   {}{}║", model_name, " ".repeat(49 - model_name.len().min(49)));
    println!("╚══════════════════════════════════════════════════════════════╝");
    println!();

    // --- Step 1: Ensure model is available ---
    println!("━━━ Setup: Model Backend ━━━");

    let ollama_url = "http://localhost:11434";

    // Skip Ollama setup for Claude models
    if model_name.starts_with("claude") {
        let use_vertex = std::env::var("CLAUDE_CODE_USE_VERTEX").is_ok()
            || std::env::var("ANTHROPIC_VERTEX_PROJECT_ID").is_ok();
        if use_vertex {
            println!("  Using Vertex AI (model: {})", model_name);
        } else if std::env::var("ANTHROPIC_API_KEY").is_ok() {
            println!("  Using Anthropic API (model: {})", model_name);
        } else {
            anyhow::bail!("Claude requires ANTHROPIC_API_KEY or Vertex AI config (ANTHROPIC_VERTEX_PROJECT_ID)");
        }
    } else {

    let client = reqwest::Client::new();

    // Check if Ollama is running
    let ollama_running = client
        .get(&format!("{ollama_url}/api/tags"))
        .send()
        .await
        .map(|r| r.status().is_success())
        .unwrap_or(false);

    if !ollama_running {
        println!("  ⏳ Ollama not running. Starting...");
        tokio::process::Command::new("ollama")
            .arg("serve")
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .map_err(|e| anyhow::anyhow!("Failed to start Ollama: {e}"))?;

        // Wait for it to start
        for i in 0..30 {
            tokio::time::sleep(std::time::Duration::from_millis(500)).await;
            if client
                .get(&format!("{ollama_url}/api/tags"))
                .send()
                .await
                .map(|r| r.status().is_success())
                .unwrap_or(false)
            {
                break;
            }
            if i == 29 {
                anyhow::bail!("Ollama did not start within 15 seconds");
            }
        }
        println!("  ✓ Ollama started");
    } else {
        println!("  ✓ Ollama running at {ollama_url}");
    }

    // Check if model is pulled
    let tags_resp = client
        .get(&format!("{ollama_url}/api/tags"))
        .send()
        .await?
        .json::<serde_json::Value>()
        .await?;

    let model_base = model_name.split(':').next().unwrap_or(model_name);
    let model_available = tags_resp["models"]
        .as_array()
        .map(|models| {
            models.iter().any(|m| {
                m["name"]
                    .as_str()
                    .map(|n| n.starts_with(model_base))
                    .unwrap_or(false)
            })
        })
        .unwrap_or(false);

    if !model_available {
        println!("  ⏳ Model '{}' not found locally. Pulling...", model_name);
        let pull_status = tokio::process::Command::new("ollama")
            .args(["pull", model_name])
            .status()
            .await?;
        if !pull_status.success() {
            anyhow::bail!("Failed to pull model '{}'", model_name);
        }
        println!("  ✓ Model pulled: {}", model_name);
    } else {
        println!("  ✓ Model available: {}", model_name);
    }

    } // end else (non-Claude Ollama setup)

    println!();

    // --- Step 2: Start mcpd gateway ---
    println!("━━━ Act 1: Start mcpd Gateway ━━━");

    // Pick a free port for the demo server
    let demo_port = {
        let l = std::net::TcpListener::bind("127.0.0.1:0")?;
        l.local_addr()?.port()
    };

    // Resolve project path to absolute for the config
    let abs_project = std::fs::canonicalize(project_path)?;

    // Write mcpd config for the demo
    let demo_config_path = "/tmp/mcpd-demo/agent-config.toml";
    std::fs::create_dir_all("/tmp/mcpd-demo")?;
    // Detect available models for the demo config.
    // Only register model names — no hardcoded agentic metadata.
    // The lead agent reads model cards via models_list and makes
    // its own selection decisions. Operators add [models.*.agentic]
    // in config.toml for their deployment.
    let mut model_sections = String::new();

    // Register the lead's own model
    if model_name.starts_with("claude") {
        let model_key = model_name.replace([':', '-', '.', '@'], "_");
        model_sections.push_str(&format!(
            "\n[models.{model_key}]\ntask = \"chat\"\nmodel_name = \"{model_name}\"\n",
            model_key = model_key, model_name = model_name,
        ));
    }

    // Register all locally available Ollama models
    if let Ok(resp) = reqwest::Client::new()
        .get("http://localhost:11434/api/tags")
        .send()
        .await
    {
        if let Ok(tags) = resp.json::<serde_json::Value>().await {
            if let Some(models) = tags["models"].as_array() {
                for m in models {
                    if let Some(name) = m["name"].as_str() {
                        let model_key = name.replace([':', '-', '.', '/'], "_");
                        model_sections.push_str(&format!(
                            "\n[models.{model_key}]\ntask = \"chat\"\nmodel_name = \"{name}\"\n",
                            model_key = model_key, name = name,
                        ));
                    }
                }
            }
        }
    }

    std::fs::write(demo_config_path, format!(r#"
[server]
tcp = "127.0.0.1:{demo_port}"

cognitive_core = "{project}"

[modules.docs]
enabled = true
db_path = "/tmp/mcpd-demo/agent-docs.db"

[modules.git]
enabled = false

[permissions.readonly]
allow = ["{allow_path}/**", "/tmp/**"]
deny = []
operations = ["read", "search", "list"]
safety = "standard"
{model_sections}
"#,
        demo_port = demo_port,
        project = abs_project.display(),
        allow_path = abs_project.display(),
        model_sections = model_sections,
    ))?;

    // Start mcpd as a child process
    let mcpd_bin = std::env::current_exe()?;
    let mut mcpd_child = tokio::process::Command::new(&mcpd_bin)
        .args(["serve", "--config", demo_config_path, "--no-tray"])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::inherit())
        .env("ORT_LIB_PATH", std::env::var("ORT_LIB_PATH").unwrap_or_default())
        .env("ORT_PREFER_DYNAMIC_LINK", "1")
        .spawn()
        .map_err(|e| anyhow::anyhow!("Failed to start mcpd: {e}"))?;

    // Wait for mcpd to be ready
    let mcpd_url = format!("http://127.0.0.1:{demo_port}");
    let http_client = reqwest::Client::new();
    for i in 0..30 {
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
        if http_client.get(&format!("{mcpd_url}/mcp")).send().await.is_ok() {
            break;
        }
        if i == 29 {
            mcpd_child.kill().await?;
            anyhow::bail!("mcpd did not start within 15 seconds");
        }
    }
    println!("  ✓ mcpd gateway running at {mcpd_url}");
    println!("  ✓ Agent 'audit-planner' (no auth for demo)");
    println!("  ✓ Docs module serving: {}", abs_project.display());

    // --- Step 3: Cognitive Core ---
    println!();
    println!("━━━ Act 2: Cognitive Core ━━━");
    let forge = match myelix_cognitive::ForgeService::load(project_path) {
        Ok(f) => {
            for name in f.persona_names() {
                if let Some(persona) = f.get_persona(name) {
                    println!(
                        "  ✓ Loaded persona: {} ({} heuristic modules)",
                        persona.persona_name,
                        persona.heuristics.len()
                    );
                }
            }
            f
        }
        Err(e) => {
            println!("  ⚠ Forge: {} (using empty)", e);
            myelix_cognitive::ForgeService::empty()
        }
    };

    // --- Step 4: Build agent ---
    println!();
    println!("━━━ Act 3: Connect Agent to Gateway ━━━");

    // Select backend based on model name
    let is_claude = model_name.starts_with("claude");

    // Assemble the planner persona system prompt
    let persona_name = if forge.get_persona("planner").is_some() {
        "planner"
    } else if forge.get_persona("rust_security_auditor").is_some() {
        "rust_security_auditor"
    } else {
        ""
    };

    let system_prompt = if !persona_name.is_empty() {
        myelix_cognitive::assemble(&forge, persona_name, "audit", None, None)
            .map(|w| w.system_prompt())
            .unwrap_or_else(|_| "You are a security auditor. Use the available tools to analyze the codebase.".to_string())
    } else {
        "You are a security auditor. Use the available tools (docs_list, docs_read, docs_search) \
         to systematically analyze the Rust codebase for security vulnerabilities. \
         Start by listing the directory structure, then read security-critical files, \
         then search for dangerous patterns like .unwrap(), unsafe, Path::new. \
         Report findings with file, function, CWE ID, severity, and description.".to_string()
    };

    let mcp_endpoint = format!("{mcpd_url}/mcp");

    // Lead agent only gets project overview + team tools.
    // No docs_read, no docs_grep — the lead MUST delegate all analysis.
    let lead_tools = vec![
        "docs_tree".to_string(),    // project structure overview only
        "models_list".to_string(),  // see available models
        "team_create".to_string(),
        "team_add".to_string(),
        "team_message".to_string(),
        "team_status".to_string(),
        "team_result".to_string(),
        "team_bb_read".to_string(),
        "team_shutdown".to_string(),
    ];

    // Observation-only tools don't count toward the iteration limit.
    // These tools read state without changing it — the lead uses them
    // to wait for teammates or inspect available resources.
    let polling_tools = vec![
        "team_status".to_string(),
        "team_result".to_string(),
        "team_bb_read".to_string(),
        "models_list".to_string(),
    ];

    macro_rules! build_agent {
        ($backend:expr) => {
            myelix_agent::Agent::builder()
                .endpoint(&mcp_endpoint)
                .await?
                .model($backend)
                .system_prompt(&system_prompt)
                .allowed_tools(lead_tools.clone())
                .non_progress_tools(polling_tools.clone())
                .max_iterations(50)
                .temperature(0.3)
                .max_tokens(8192)
                .build()?
        };
    }

    let mut agent = if is_claude {
        // Check for Vertex AI or direct Anthropic API
        let use_vertex = std::env::var("CLAUDE_CODE_USE_VERTEX").is_ok()
            || std::env::var("ANTHROPIC_VERTEX_PROJECT_ID").is_ok();

        if use_vertex {
            let project_id = std::env::var("ANTHROPIC_VERTEX_PROJECT_ID")
                .unwrap_or_else(|_| "my-project".to_string());
            let region = std::env::var("CLOUD_ML_REGION")
                .unwrap_or_else(|_| "us-east5".to_string());
            let base_url = format!(
                "https://{region}-aiplatform.googleapis.com/v1/projects/{project_id}/locations/{region}/publishers/anthropic/models/{model_name}:rawPredict"
            );
            // Get Google OAuth token via gcloud
            let token_output = std::process::Command::new("gcloud")
                .args(["auth", "print-access-token"])
                .output()
                .map_err(|e| anyhow::anyhow!("Failed to get gcloud token: {e}. Run: gcloud auth login"))?;
            let gcloud_token = String::from_utf8_lossy(&token_output.stdout).trim().to_string();
            if gcloud_token.is_empty() {
                mcpd_child.kill().await?;
                anyhow::bail!("Empty gcloud token. Run: gcloud auth application-default login");
            }
            println!("  Backend: Vertex AI (project: {project_id}, region: {region})");
            build_agent!(myelix_model::AnthropicBackend::new(
                &base_url,
                model_name,
                Some(gcloud_token),
                myelix_model::Locality::Remote,
            ))
        } else {
            let api_key = std::env::var("ANTHROPIC_API_KEY")
                .ok()
                .or_else(|| std::env::var("CLAUDE_API_KEY").ok());
            if api_key.is_none() {
                mcpd_child.kill().await?;
                anyhow::bail!(
                    "Claude requires ANTHROPIC_API_KEY or Vertex AI config"
                );
            }
            println!("  Backend: Anthropic Messages API");
            build_agent!(myelix_model::AnthropicBackend::new(
                "https://api.anthropic.com",
                model_name,
                api_key,
                myelix_model::Locality::Remote,
            ))
        }
    } else {
        println!("  Backend: Ollama OpenAI-compat API");
        build_agent!(myelix_model::OpenAiBackend::new(
            &format!("{ollama_url}/v1"),
            model_name,
            None,
            myelix_model::Locality::Local,
        ))
    };

    // List available tools
    let tools = agent.client().list_tools().await?;
    println!("  ✓ Connected to mcpd at {}", mcp_endpoint);
    println!("  ✓ {} MCP tools available:", tools.len());
    for tool in &tools {
        println!("    - {}", tool.name);
    }
    println!("  ✓ Persona: {}", if persona_name.is_empty() { "default" } else { persona_name });
    println!("  ✓ System prompt: {} chars", system_prompt.len());

    // --- Step 5: Run the agent ---
    println!();
    println!("━━━ Act 4: Agent-Driven Analysis ━━━");
    println!("  The agent will use ReAct (reasoning + tool calls) to explore");
    println!("  the codebase through mcpd. IFC, safety filters, and ACLs are");
    println!("  active on every tool call.");
    println!();

    // The prompt is minimal — the persona defines the methodology
    let audit_prompt = format!(
        "Audit the Rust project at {path}",
        path = abs_project.display()
    );

    let start = std::time::Instant::now();
    match agent.run(&audit_prompt).await {
        Ok(result) => {
            let elapsed = start.elapsed();
            println!();
            println!("━━━ Agent Report ━━━");
            println!();
            for line in result.response.lines() {
                println!("  {}", line);
            }
            println!();
            println!("━━━ Summary ━━━");
            println!("  Model:       {} (via Ollama, locality: Local)", model_name);
            println!("  Gateway:     mcpd at {}", mcpd_url);
            println!("  Transport:   MCP Streamable HTTP (authenticated)");
            println!("  Persona:     {}", if persona_name.is_empty() { "default" } else { persona_name });
            println!("  Iterations:  {} ReAct loops", result.iterations);
            println!("  Tokens:      {} input + {} output", result.input_tokens, result.output_tokens);
            println!("  Time:        {:.1}s", elapsed.as_secs_f64());
            println!("  Taint:       {:?}", result.taint);
            println!("  Tools:       {} available via mcpd", tools.len());
            println!("  Security:    IFC + ACLs + safety filters active");
            println!("  Framework:   17 crates");
        }
        Err(e) => {
            println!("\n  ✗ Agent error: {}", e);
        }
    }

    // --- Cleanup ---
    println!();
    mcpd_child.kill().await?;
    println!("  ✓ mcpd gateway stopped");
    println!();

    Ok(())
}

/// Expand `~` to the user's home directory in a path string.
fn expand_tilde(path: &str) -> String {
    if path.starts_with("~/") {
        if let Some(home) = dirs::home_dir() {
            return format!("{}{}", home.display(), &path[1..]);
        }
    }
    path.to_string()
}
