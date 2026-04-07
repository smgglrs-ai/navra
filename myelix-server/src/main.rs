mod config;
mod discover;
mod mdns;
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

    // Wire IFC policies from permission sets
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
                        tracing::info!(
                            agent = %agent.name,
                            subject_did = %subject_did,
                            ring = ring,
                            ttl_secs = ttl,
                            token = %token,
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

    for (name, model_cfg) in &cfg.models {
        let model_path = expand_tilde(&model_cfg.model_path);
        let path = std::path::Path::new(&model_path);

        if !path.exists() {
            tracing::warn!(
                model = %name,
                path = %model_path,
                "Model file not found, skipping"
            );
            continue;
        }

        let task = match model_cfg.task.as_str() {
            "embedding" => {
                let dims = model_cfg.dimensions.unwrap_or(768);
                myelix_model::ModelTask::Embedding { dimensions: dims }
            }
            "classification" => {
                let labels = if model_cfg.labels.is_empty() {
                    vec!["safe".to_string(), "unsafe".to_string()]
                } else {
                    model_cfg.labels.clone()
                };
                myelix_model::ModelTask::Classification { labels }
            }
            other => {
                tracing::warn!(model = %name, task = %other, "Unknown model task, skipping");
                continue;
            }
        };

        let tokenizer_path = model_cfg
            .tokenizer_path
            .as_ref()
            .map(|p| std::path::PathBuf::from(expand_tilde(p)));

        match myelix_model::OnnxBackend::load(name, path, tokenizer_path.as_deref(), task) {
            Ok(model) => {
                tracing::info!(model = %name, task = %model_cfg.task, "Model loaded");
                models.insert(name.clone(), Arc::new(model));
            }
            Err(e) => {
                tracing::error!(model = %name, error = %e, "Failed to load model, skipping");
            }
        }
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
            let vision = myelix_modal_vision::VisionModule::new(vision_model);
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
                    let parent_caps = match &ctx.agent.capabilities {
                        Some(caps) => caps,
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
                            nonce: [0u8; 16], // placeholder
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
    let router = if has_discovery {
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
        myelix_core::transport::build_router_with_discovery(
            server, broadcaster, aid_record, registry_entries, a2a_endpoint, root_did_str,
        )
    } else {
        myelix_core::transport::build_router_with_broadcaster(server, broadcaster)
    };

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

        if let Some(addr) = tcp_addr {
            // Both Unix socket and TCP
            let tcp_listener = tokio::net::TcpListener::bind(&addr).await?;
            tracing::info!("Listening on tcp:{addr}");

            let tcp_router = router.clone();
            tokio::select! {
                result = axum::serve(unix_listener, router) => result?,
                result = axum::serve(tcp_listener, tcp_router) => result?,
            }
        } else {
            // Unix socket only
            axum::serve(unix_listener, router).await?;
        }
    } else {
        // TCP only (fallback)
        let addr = cfg.server.listen_addr();
        let listener = tokio::net::TcpListener::bind(&addr).await?;
        tracing::info!("Listening on tcp:{addr}");
        axum::serve(listener, router).await?;
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

/// Pull a model from HuggingFace.
async fn model_pull(name: &str) -> anyhow::Result<()> {
    let model = KNOWN_MODELS
        .iter()
        .find(|m| m.name == name)
        .ok_or_else(|| {
            anyhow::anyhow!(
                "Unknown model: '{}'\nRun 'mcpd model available' to see supported models",
                name
            )
        })?;

    let model_dir = models_dir().join(model.name);
    std::fs::create_dir_all(&model_dir)?;

    println!("Pulling {} ...", model.description);

    // Download ONNX model
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

    // Download tokenizer if needed
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

    Ok(())
}

/// List installed models.
fn model_list() -> anyhow::Result<()> {
    let dir = models_dir();
    if !dir.exists() {
        println!("No models installed.");
        println!("Run 'mcpd model available' to see supported models.");
        return Ok(());
    }

    let mut found = false;
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
            println!("{name:<20} {size:<12} tokenizer: {tok_status}");
            found = true;
        }
    }

    if !found {
        println!("No models installed.");
        println!("Run 'mcpd model available' to see supported models.");
    }

    Ok(())
}

/// Show available models for download.
fn model_available() {
    println!("{:<20} {}", "NAME", "DESCRIPTION");
    println!("{:<20} {}", "----", "-----------");
    for model in KNOWN_MODELS {
        println!("{:<20} {}", model.name, model.description);
    }
    println!("\nPull a model: mcpd model pull <name>");
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
