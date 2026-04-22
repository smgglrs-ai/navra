mod cli;
mod config;
mod demo;
mod discover;
mod flow_tools;
mod mdns;
mod memory_tools;
mod team_tools;
mod tray;
mod ui;

use clap::Parser;
use myelix_core::auth::{AgentIdentity, TokenAuthenticator};
use myelix_core::identity::{self, CapSigner, Ed25519Signer};
use myelix_core::permissions::{PathAcl, PermissionEngine, ToolPermissions, ToolPolicy, ToolRule};
use std::sync::Arc;

use cli::{Cli, Commands, ModelAction, TokenAction};

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
                cli::model_pull(&name).await?;
            }
            ModelAction::List => {
                cli::model_list()?;
            }
            ModelAction::Available => {
                cli::model_available();
            }
        },
        Commands::Run { prompt, model, persona, endpoint, token, max_iterations } => {
            run_agent(&prompt, model.as_deref(), &persona, &endpoint, token.as_deref(), max_iterations).await?;
        }
        Commands::Audit { limit, detail, agent, tool, verify } => {
            audit_command(limit, detail, agent, tool, verify)?;
        }
        Commands::Demo { project, live, model, max_rounds, files_per_round, min_delta, prompt, writable, allow_read, allow_write } => {
            if live {
                demo::run_demo_live(&project, &model, max_rounds, files_per_round, min_delta, prompt.as_deref(), writable, &allow_read, &allow_write).await?;
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
                .ok_or_else(|| anyhow::anyhow!("Cannot determine config directory for identity key"))?
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

    // When no agents are configured, anonymous access uses the "readonly"
    // permission set. If it's missing, tools will fail with DeniedUnknown.
    // Warn loudly at startup so the operator knows why.
    if cfg.agents.is_empty() && !cfg.permissions.contains_key("readonly") {
        tracing::warn!(
            "No [permissions.readonly] in config. Anonymous agents use the \
             'readonly' permission set — without it, all path-based tools \
             (docs_read, docs_tree, etc.) will be denied. Add a \
             [permissions.readonly] section to grant access."
        );
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

    // Gateway blackbox — always on, append-only, hash-chained
    {
        let bb_path = dirs::data_dir()
            .unwrap_or_else(|| std::path::PathBuf::from("."))
            .join("mcpd/blackbox.db");
        if let Some(parent) = bb_path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        match myelix_core::blackbox::Blackbox::open(&bb_path) {
            Ok(bb) => {
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
    } else {
        tracing::warn!(
            "No agents configured — server accepts unauthenticated requests. \
             Add [[agents]] sections to config.toml to enable authentication."
        );
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
        // Set default root for docs_tree.
        // Priority: [modules.docs] default_root > top-level cognitive_core
        let mut docs = docs;
        let docs_root = cfg.modules.docs.as_ref()
            .and_then(|d| d.default_root.as_deref())
            .or(cfg.cognitive_core.as_deref());
        if let Some(root_path) = docs_root {
            let expanded = expand_tilde(root_path);
            if let Ok(canonical) = std::fs::canonicalize(&expanded) {
                let root = canonical.display().to_string();
                tracing::info!(default_root = %root, "Setting docs_tree default root");
                docs.set_default_root(root);
            }
        }
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
            .filter_map(|p| match p.canonicalize() {
                Ok(canonical) => Some(canonical),
                Err(e) => {
                    tracing::warn!(path = %p.display(), error = %e, "Skipping watch directory: canonicalization failed");
                    None
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
    if let Some(voice_cfg) = cfg.modules.voice.as_ref().filter(|_| cfg.voice_enabled()) {
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
    if let Some(vision_cfg) = cfg.modules.vision.as_ref().filter(|_| cfg.vision_enabled()) {
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

                    let flow_def_str = match args.get("flow_definition").and_then(|v| v.as_str()) {
                        Some(t) => t,
                        None => return CallToolResult::error(
                            "Missing required parameter: flow_definition"
                        ),
                    };
                    let prompt = match args.get("prompt").and_then(|v| v.as_str()) {
                        Some(p) => p.to_string(),
                        None => return CallToolResult::error("Missing required parameter: prompt"),
                    };
                    let format = args
                        .get("format")
                        .and_then(|v| v.as_str())
                        .unwrap_or("toml");

                    let flow_name = match format {
                        "yaml" => {
                            // Collect parameters from the JSON object
                            let params: std::collections::HashMap<String, String> = args
                                .get("parameters")
                                .and_then(|v| v.as_object())
                                .map(|obj| {
                                    obj.iter()
                                        .filter_map(|(k, v)| {
                                            v.as_str().map(|s| (k.clone(), s.to_string()))
                                        })
                                        .collect()
                                })
                                .unwrap_or_default();

                            match myelix_flow::yaml_loader::load_flow_yaml(
                                flow_def_str, &params,
                            ) {
                                Ok(dag) => dag.name,
                                Err(e) => return CallToolResult::error(
                                    format!("Invalid YAML flow: {e}")
                                ),
                            }
                        }
                        "toml" | _ => {
                            let flow_def: Result<myelix_flow::FlowDefinition, _> =
                                toml::from_str(flow_def_str);
                            match flow_def {
                                Ok(def) => def.flow.name.clone(),
                                Err(e) => return CallToolResult::error(
                                    format!("Invalid flow TOML: {e}")
                                ),
                            }
                        }
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

        // flow_list — list available YAML flows from configured directories
        let flow_dirs = cfg.flow_dirs.clone();
        builder = builder.tool(
            flow_tools::flow_list_tool_def(),
            move |_args, _ctx| {
                let flow_dirs = flow_dirs.clone();
                Box::pin(async move {
                    use myelix_core::protocol::CallToolResult;

                    if flow_dirs.is_empty() {
                        return CallToolResult::text(
                            "No flow directories configured. \
                             Set flow_dirs in config.toml to list available flows."
                        );
                    }

                    let mut flows = Vec::new();
                    for dir in &flow_dirs {
                        let expanded = if dir.starts_with('~') {
                            if let Some(home) = dirs::home_dir() {
                                dir.replacen('~', &home.display().to_string(), 1)
                            } else {
                                dir.clone()
                            }
                        } else {
                            dir.clone()
                        };
                        let path = std::path::Path::new(&expanded);
                        let entries = match std::fs::read_dir(path) {
                            Ok(e) => e,
                            Err(e) => {
                                tracing::warn!(dir = %expanded, error = %e, "Cannot read flow dir");
                                continue;
                            }
                        };
                        for entry in entries.flatten() {
                            let p = entry.path();
                            let ext = p.extension().and_then(|e| e.to_str());
                            if !matches!(ext, Some("yml" | "yaml")) {
                                continue;
                            }
                            let content = match std::fs::read_to_string(&p) {
                                Ok(c) => c,
                                Err(_) => continue,
                            };
                            if let Ok(envelope) = serde_yaml::from_str::<
                                myelix_flow::yaml_loader::FlowFile,
                            >(&content) {
                                let params: Vec<serde_json::Value> = envelope
                                    .parameters
                                    .iter()
                                    .map(|(k, v)| {
                                        serde_json::json!({
                                            "name": k,
                                            "type": v.param_type,
                                            "description": v.description,
                                            "default": v.default,
                                        })
                                    })
                                    .collect();
                                flows.push(serde_json::json!({
                                    "name": envelope.name,
                                    "kind": envelope.kind,
                                    "description": envelope.description,
                                    "file": p.display().to_string(),
                                    "parameters": params,
                                }));
                            }
                        }
                    }

                    CallToolResult::text(
                        serde_json::to_string_pretty(&flows).unwrap_or_default()
                    )
                })
            },
        );

        tracing::info!("Registered flow orchestration tools (flow_start, flow_status, flow_result, flow_list)");
    }

    // Register team orchestration tools
    {
        use myelix_core::protocol::CallToolResult;
        

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
                    max_iterations: args.get("max_iterations").and_then(|v| v.as_u64()).unwrap_or(50) as usize,
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

                let operations: Vec<String> = args.get("operations")
                    .and_then(|v| v.as_array())
                    .map(|arr| arr.iter().filter_map(|v| v.as_str().map(String::from)).collect())
                    .unwrap_or_else(|| team_tools::DEFAULT_OPERATIONS.iter().map(|s| s.to_string()).collect());

                let tools: Vec<String> = args.get("tools")
                    .and_then(|v| v.as_array())
                    .map(|arr| arr.iter().filter_map(|v| v.as_str().map(String::from)).collect())
                    .unwrap_or_else(|| team_tools::DEFAULT_TOOLS.iter().map(|s| s.to_string()).collect());

                match reg.add_teammate(team_id, name, persona, model, locality, operations.clone(), tools.clone()) {
                    Ok(()) => {
                        tracing::info!(team = team_id, name = name, persona = ?persona, model = model, locality = locality, operations = ?operations, tools = ?tools, "Teammate added");
                        CallToolResult::text(format!(
                            "Added '{name}' to team (persona: {}, model: {model}, locality: {locality}, operations: {operations:?}, tools: {tools:?})",
                            persona.unwrap_or("default"),
                        ))
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
        let msg_signer = Arc::clone(&root_signer);
        // Load ForgeService once and share across all teammate spawns
        let msg_forge: Option<Arc<myelix_cognitive::ForgeService>> = cfg.cognitive_core.as_ref().and_then(|p| {
            let expanded = expand_tilde(p);
            myelix_cognitive::ForgeService::load(std::path::Path::new(&expanded))
                .map(Arc::new)
                .ok()
        });
        builder = builder.tool(team_tools::team_message_def(), move |args, _ctx| {
            let reg = Arc::clone(&reg);
            let mcpd_addr = msg_mcpd_addr.clone();
            let signer = Arc::clone(&msg_signer);
            let forge = msg_forge.clone();
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
                let bg_signer = Arc::clone(&signer);

                // Get the team's timeout and iteration budget
                let (timeout_secs, teammate_max_iterations) = {
                    let teams = reg.teams.lock().unwrap_or_else(|e| e.into_inner());
                    teams.get(&team_id)
                        .map(|t| {
                            let elapsed = t.created_at.elapsed().as_secs();
                            let remaining = t.budget.timeout_secs.saturating_sub(elapsed);
                            (remaining, t.budget.max_iterations)
                        })
                        .unwrap_or((600, 50))
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

                    // Build a scoped capability token from the teammate's
                    // configured operations and tools.
                    let (tm_operations, tm_tools) = {
                        let teams = bg_reg.teams.lock().unwrap_or_else(|e| e.into_inner());
                        teams.get(&bg_team_id)
                            .and_then(|t| t.teammates.get(&bg_to))
                            .map(|tm| (tm.operations.clone(), tm.tools.clone()))
                            .unwrap_or_else(|| (
                                team_tools::DEFAULT_OPERATIONS.iter().map(|s| s.to_string()).collect(),
                                team_tools::DEFAULT_TOOLS.iter().map(|s| s.to_string()).collect(),
                            ))
                    };
                    let tm_tools_desc = tm_tools.join(", ");
                    let teammate_cap = myelix_core::auth::capability::CapabilitySet {
                        paths: vec!["**".to_string()],
                        operations: tm_operations,
                        tools: tm_tools,
                        credentials: vec![],
                    };
                    let teammate_did = format!("did:teammate:{}:{}", bg_team_id, bg_to);
                    let teammate_payload = myelix_core::auth::capability::build_payload(
                        bg_signer.did(),
                        &teammate_did,
                        teammate_cap,
                        2, // ring 2: less privileged than root
                        3600,
                    );
                    let teammate_token = match myelix_core::auth::capability::encode_token(
                        &teammate_payload,
                        bg_signer.as_ref(),
                    ) {
                        Ok(t) => t,
                        Err(e) => {
                            tracing::error!(team = %bg_team_id, to = %bg_to, error = %e, "Failed to mint teammate token");
                            bg_reg.set_failed(&bg_team_id, &bg_to, format!("Token error: {e}"));
                            return;
                        }
                    };

                    // Build the teammate's system prompt from persona if available
                    let tm_persona = {
                        let teams = bg_reg.teams.lock().unwrap_or_else(|e| e.into_inner());
                        teams.get(&bg_team_id)
                            .and_then(|t| t.teammates.get(&bg_to))
                            .and_then(|tm| tm.persona.clone())
                    };

                    let system_prompt = if let Some(ref persona_name) = tm_persona {
                        // Use cached ForgeService
                        let persona_prompt = forge.as_ref().and_then(|f| {
                            let output = myelix_cognitive::assemble(f, persona_name, "", None, None).ok()?;
                            Some(output.system_prompt())
                        });

                        match persona_prompt {
                            Some(prompt) => format!(
                                "{prompt}\n\n\
                                 You are working as part of a team.\n\
                                 You have access to MCP tools: {tools}.\n\
                                 If team_bb_publish is available, publish findings to the \
                                 blackboard (team_id: {team_id}).\n\
                                 Your team_id is: {team_id}",
                                tools = tm_tools_desc, team_id = bg_team_id
                            ),
                            None => format!(
                                "You are a specialist agent named '{}' (persona: {}).\n\n\
                                 You have access to MCP tools: {}.\n\
                                 Your team_id is: {}",
                                bg_to, persona_name, tm_tools_desc, bg_team_id
                            ),
                        }
                    } else {
                        format!(
                            "You are a specialist agent named '{}'.\n\n\
                             You have access to MCP tools: {}.\n\
                             Your team_id is: {}",
                            bg_to, tm_tools_desc, bg_team_id
                        )
                    };

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

                    // Connect teammate as a scoped MCP agent
                    macro_rules! run_teammate {
                        ($backend:expr) => {{
                            let r = async {
                                let mut agent = myelix_agent::Agent::builder()
                                    .endpoint(&mcp_url)
                                    .await?
                                    .auth_token(&teammate_token)
                                    .model($backend)
                                    .system_prompt(&system_prompt)
                                    .max_iterations(teammate_max_iterations)
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

                // Stagger teammate spawns to avoid concurrent rate limit hits
                tokio::time::sleep(std::time::Duration::from_millis(500)).await;

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

        // personas_list
        let persona_data: Vec<serde_json::Value> = if let Some(ref cc_path) = cfg.cognitive_core {
            let expanded = expand_tilde(cc_path);
            match myelix_cognitive::ForgeService::load(std::path::Path::new(&expanded)) {
                Ok(forge) => {
                    forge.persona_names().iter().filter_map(|name| {
                        forge.get_persona(name).map(|p| serde_json::json!({
                            "name": p.persona_name,
                            "display_name": p.display_name,
                            "mandate": p.core_mandate.lines().next().unwrap_or(""),
                            "heuristics": p.heuristics.len(),
                            "tools": p.tools,
                        }))
                    }).collect()
                }
                Err(_) => vec![],
            }
        } else {
            vec![]
        };
        builder = builder.tool(team_tools::personas_list_def(), move |_args, _ctx| {
            let data = persona_data.clone();
            Box::pin(async move {
                CallToolResult::text(serde_json::to_string_pretty(&data).unwrap_or_default())
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

    // --- Knowledge memory tools ---
    let knowledge_store: Option<Arc<std::sync::Mutex<myelix_memory::KnowledgeStore>>> = {
        let kb_path = dirs::data_dir()
            .unwrap_or_else(|| std::path::PathBuf::from("."))
            .join("mcpd/knowledge.db");
        if let Some(parent) = kb_path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        match myelix_memory::KnowledgeStore::open(&kb_path) {
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

    if knowledge_store.is_some() {
        let ks = knowledge_store.clone().unwrap();

        let ks_store = Arc::clone(&ks);
        builder = builder.tool(memory_tools::memory_store_def(), move |args, _ctx| {
            let ks = Arc::clone(&ks_store);
            Box::pin(async move {
                use myelix_core::protocol::CallToolResult;

                let kind_str = match args.get("kind").and_then(|v| v.as_str()) {
                    Some(k) => k,
                    None => return CallToolResult::error("Missing required parameter: kind"),
                };
                let title = match args.get("title").and_then(|v| v.as_str()) {
                    Some(t) => t,
                    None => return CallToolResult::error("Missing required parameter: title"),
                };
                let content = match args.get("content").and_then(|v| v.as_str()) {
                    Some(c) => c,
                    None => return CallToolResult::error("Missing required parameter: content"),
                };

                let memory_type = match myelix_memory::MemoryType::from_str(kind_str) {
                    Ok(mt) => mt,
                    Err(_) => return CallToolResult::error(
                        format!("Invalid kind: {kind_str}. Use: fact, event, instruction, insight")
                    ),
                };

                let tags: Vec<String> = args
                    .get("tags")
                    .and_then(|v| v.as_array())
                    .map(|arr| arr.iter().filter_map(|v| v.as_str().map(String::from)).collect())
                    .unwrap_or_default();

                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs() as i64;

                let id = uuid::Uuid::new_v4().to_string();
                let entry = myelix_memory::MemoryEntry {
                    id: id.clone(),
                    memory_type,
                    title: title.to_string(),
                    content: content.to_string(),
                    tags,
                    created_at: now,
                    updated_at: None,
                };

                let store = ks.lock().unwrap_or_else(|e| e.into_inner());
                match store.store(&entry) {
                    Ok(()) => CallToolResult::text(
                        serde_json::json!({"id": id, "status": "stored"}).to_string()
                    ),
                    Err(e) => CallToolResult::error(format!("Failed to store entry: {e}")),
                }
            })
        });

        let ks_query = Arc::clone(&ks);
        builder = builder.tool(memory_tools::memory_query_def(), move |args, _ctx| {
            let ks = Arc::clone(&ks_query);
            Box::pin(async move {
                use myelix_core::protocol::CallToolResult;

                let query = match args.get("query").and_then(|v| v.as_str()) {
                    Some(q) => q,
                    None => return CallToolResult::error("Missing required parameter: query"),
                };

                let limit = args.get("limit")
                    .and_then(|v| v.as_u64())
                    .unwrap_or(10) as usize;

                let kind_filter = args.get("kind")
                    .and_then(|v| v.as_str())
                    .and_then(|k| myelix_memory::MemoryType::from_str(k).ok());

                let store = ks.lock().unwrap_or_else(|e| e.into_inner());
                match store.search(query) {
                    Ok(entries) => {
                        let mut results: Vec<&myelix_memory::MemoryEntry> = entries.iter()
                            .filter(|e| {
                                kind_filter.as_ref().map_or(true, |k| e.memory_type == *k)
                            })
                            .collect();
                        results.truncate(limit);

                        let output: Vec<serde_json::Value> = results.iter().map(|e| {
                            serde_json::json!({
                                "id": e.id,
                                "kind": e.memory_type.as_str(),
                                "title": e.title,
                                "content": e.content,
                                "tags": e.tags,
                                "created_at": e.created_at,
                            })
                        }).collect();

                        CallToolResult::text(
                            serde_json::to_string_pretty(&output).unwrap_or_default()
                        )
                    }
                    Err(e) => CallToolResult::error(format!("Search failed: {e}")),
                }
            })
        });

        let ks_forget = Arc::clone(&ks);
        builder = builder.tool(memory_tools::memory_forget_def(), move |args, _ctx| {
            let ks = Arc::clone(&ks_forget);
            Box::pin(async move {
                use myelix_core::protocol::CallToolResult;

                let id = match args.get("id").and_then(|v| v.as_str()) {
                    Some(id) => id,
                    None => return CallToolResult::error("Missing required parameter: id"),
                };

                let store = ks.lock().unwrap_or_else(|e| e.into_inner());
                match store.delete(id) {
                    Ok(true) => CallToolResult::text(
                        serde_json::json!({"id": id, "status": "deleted"}).to_string()
                    ),
                    Ok(false) => CallToolResult::error(format!("No entry found with id: {id}")),
                    Err(e) => CallToolResult::error(format!("Failed to delete entry: {e}")),
                }
            })
        });

        tracing::info!("Registered memory tools (memory_store, memory_query, memory_forget)");
    }

    // Register audit_query tool
    {
        let audit_db_path = dirs::data_dir()
            .unwrap_or_else(|| std::path::PathBuf::from("."))
            .join("mcpd/audit.db");
        if let Some(parent) = audit_db_path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        let audit_log = match myelix_memory::audit::AuditLog::open(&audit_db_path) {
            Ok(log) => {
                tracing::info!(path = %audit_db_path.display(), "Audit log enabled");
                Arc::new(log)
            }
            Err(e) => {
                tracing::warn!(error = %e, "Failed to open audit DB, using in-memory");
                Arc::new(myelix_memory::audit::AuditLog::open_memory().unwrap())
            }
        };

        let audit = Arc::clone(&audit_log);
        builder = builder.tool(
            myelix_core::protocol::ToolDefinition {
                name: "audit_query".to_string(),
                description: Some(
                    "Query the structured audit log. Returns tool calls, model calls, \
                     and run summaries from past agent executions. Use to inspect \
                     what tools were called, with what arguments, and what results \
                     were returned."
                        .to_string(),
                ),
                input_schema: myelix_core::protocol::ToolInputSchema {
                    schema_type: "object".to_string(),
                    properties: {
                        let mut props = std::collections::HashMap::new();
                        props.insert("run_id".to_string(), serde_json::json!({
                            "type": "string",
                            "description": "Filter by run ID (returns tool calls for that run)"
                        }));
                        props.insert("summary".to_string(), serde_json::json!({
                            "type": "boolean",
                            "description": "If true, return a summary instead of individual entries"
                        }));
                        Some(props)
                    },
                    required: None,
                },
            },
            move |args, _ctx| {
                let audit = Arc::clone(&audit);
                Box::pin(async move {
                    use myelix_core::protocol::CallToolResult;

                    let run_id = args.get("run_id").and_then(|v| v.as_str());

                    if let Some(rid) = run_id {
                        let summary = args.get("summary").and_then(|v| v.as_bool()).unwrap_or(false);
                        if summary {
                            match audit.get_summary(rid) {
                                Ok(s) => CallToolResult::text(
                                    serde_json::to_string_pretty(&s).unwrap_or_default()
                                ),
                                Err(e) => CallToolResult::error(format!("Audit query failed: {e}")),
                            }
                        } else {
                            match audit.get_tool_calls(rid) {
                                Ok(calls) => CallToolResult::text(
                                    serde_json::to_string_pretty(&calls).unwrap_or_default()
                                ),
                                Err(e) => CallToolResult::error(format!("Audit query failed: {e}")),
                            }
                        }
                    } else {
                        // No run_id — list recent runs
                        match audit.get_run("latest") {
                            Ok(run) => CallToolResult::text(
                                serde_json::to_string_pretty(&run).unwrap_or_default()
                            ),
                            Err(_) => CallToolResult::text("No audit runs found. Run a demo first.".to_string()),
                        }
                    }
                })
            },
        );
        tracing::info!("Registered audit_query tool");
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
    let router = ui::attach_ui_routes(router, &cfg, &server, &models);

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

/// Expand `~` to the user's home directory in a path string.
async fn run_agent(
    prompt: &str,
    model_name: Option<&str>,
    persona_name: &str,
    endpoint: &str,
    token: Option<&str>,
    max_iterations: usize,
) -> anyhow::Result<()> {
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
            Some(Ok(tags)) => {
                tags["models"].as_array()
                    .and_then(|m| m.first())
                    .and_then(|m| m["name"].as_str())
                    .unwrap_or("gemma4:26b")
                    .to_string()
            }
            _ => "gemma4:26b".to_string(),
        }
    };

    eprintln!("Model:    {model_name}");
    eprintln!("Persona:  {persona_name}");
    eprintln!("Endpoint: {endpoint}");
    eprintln!();

    // Build model backend
    let backend = myelix_model::OpenAiBackend::new(
        "http://localhost:11434/v1",
        &model_name,
        None,
        myelix_model::Locality::Local,
    );

    // Load persona if cognitive_core exists
    let forge = myelix_cognitive::ForgeService::load(std::path::Path::new("cognitive_core"))
        .ok()
        .or_else(|| {
            // Try common locations
            for p in ["../cognitive_core", "/etc/mcpd/cognitive_core"] {
                if let Ok(f) = myelix_cognitive::ForgeService::load(std::path::Path::new(p)) {
                    return Some(f);
                }
            }
            None
        });

    // Build agent
    let mut builder = myelix_agent::Agent::builder()
        .endpoint(endpoint)
        .await?
        .model(backend)
        .max_iterations(max_iterations)
        .temperature(0.0)
        .max_tokens(8192)
        .force_tool_iterations(5)
        .non_progress_tools(vec![
            "team_status".to_string(),
            "team_result".to_string(),
            "team_bb_read".to_string(),
            "models_list".to_string(),
            "personas_list".to_string(),
        ]);

    // Apply auth token
    let auth_token = token
        .map(String::from)
        .or_else(|| std::env::var("MCPD_TOKEN").ok());
    if let Some(t) = auth_token {
        builder = builder.auth_token(t);
    }

    // Apply persona
    if let Some(ref forge) = forge {
        if forge.get_persona(persona_name).is_some() {
            builder = builder.persona(forge, persona_name)?;
            eprintln!("Loaded persona: {persona_name}");
        }
    }

    let mut agent = builder.build()?;

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
            eprintln!("Tokens:     {} in + {} out", result.input_tokens, result.output_tokens);
            eprintln!("Time:       {:.1}s", start.elapsed().as_secs_f64());
            eprintln!("Taint:      {:?}", result.taint);
            eprintln!("Blackbox:   mcpd audit");
        }
        Err(e) => {
            eprintln!("Error: {e}");
            std::process::exit(1);
        }
    }

    Ok(())
}

pub(crate) fn expand_tilde(path: &str) -> String {
    if path.starts_with("~/") {
        if let Some(home) = dirs::home_dir() {
            return format!("{}{}", home.display(), &path[1..]);
        }
    }
    path.to_string()
}

fn audit_command(limit: usize, detail: bool, agent: Option<String>, tool: Option<String>, verify: bool) -> anyhow::Result<()> {
    let bb_path = dirs::data_dir()
        .unwrap_or_else(|| std::path::PathBuf::from("."))
        .join("mcpd/blackbox.db");
    if !bb_path.exists() {
        anyhow::bail!("No blackbox found at {}. Start the server first.", bb_path.display());
    }
    let bb = myelix_core::blackbox::Blackbox::open(&bb_path)
        .map_err(|e| anyhow::anyhow!("{e}"))?;

    if verify {
        let (valid, broken) = bb.verify_chain();
        match broken {
            None => println!("Blackbox integrity: OK ({valid} entries, chain valid)"),
            Some(seq) => println!("Blackbox integrity: BROKEN at seq {seq} ({valid} valid entries before break)"),
        }
        return Ok(());
    }

    println!("Blackbox: {} ({} entries)\n", bb_path.display(), bb.count());

    let entries = bb.recent(limit);
    let filtered: Vec<_> = entries.iter().rev()
        .filter(|e| agent.as_ref().map_or(true, |a| e.agent_name == *a))
        .filter(|e| tool.as_ref().map_or(true, |t| e.tool_name == *t))
        .collect();

    if detail {
        for e in &filtered {
            println!("seq={} agent={} tool={} outcome={} duration={}us",
                e.seq, e.agent_name, e.tool_name, e.outcome, e.duration_us);
            let args_short = if e.tool_args.len() > 120 { &e.tool_args[..120] } else { &e.tool_args };
            let result_short = if e.tool_result.len() > 120 { &e.tool_result[..120] } else { &e.tool_result };
            println!("  args:   {}", args_short);
            println!("  result: {}", result_short);
            println!("  ifc:    {}", e.ifc_label);
            println!();
        }
    } else {
        println!("{:<6} {:<12} {:<12} {:<20} {:<8} {}", "SEQ", "AGENT", "OUTCOME", "TOOL", "US", "IFC");
        println!("{}", "-".repeat(80));
        for e in &filtered {
            let ifc_short = e.ifc_label
                .replace("DataLabel { integrity: ", "")
                .replace(", confidentiality: ", "/")
                .replace(" }", "");
            println!("{:<6} {:<12} {:<12} {:<20} {:<8} {}",
                e.seq, e.agent_name, e.outcome, e.tool_name, e.duration_us, ifc_short);
        }
    }

    println!("\n{} entries shown", filtered.len());
    Ok(())
}
