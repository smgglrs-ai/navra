mod config;
mod tray;

use clap::{Parser, Subcommand};
use mcpd_core::permissions::{PathAcl, PermissionEngine};
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
        Commands::Token { action } => match action {
            TokenAction::Generate { name, permissions } => {
                let token = config::generate_token();
                println!("Agent: {name}");
                println!("Permissions: {permissions}");
                println!("Token: {token}");
                println!("\nAdd to config.toml:");
                println!("[[agents]]");
                println!("name = \"{name}\"");
                println!("token_hash = \"TODO: hash the token\"");
                println!("permissions = \"{permissions}\"");
            }
            TokenAction::List => {
                println!("TODO: list agents from config");
            }
        },
        Commands::Approve { id } => {
            println!("TODO: approve request {id}");
        }
        Commands::Deny { id } => {
            println!("TODO: deny request {id}");
        }
        Commands::Status => {
            println!("TODO: query server status");
        }
    }

    Ok(())
}

/// Build the permission engine from config.
fn build_perm_engine(cfg: &config::Config) -> PermissionEngine {
    let mut engine = PermissionEngine::new();
    for (name, pset) in &cfg.permissions {
        let acl = PathAcl {
            allow: pset.allow.clone(),
            deny: pset.deny.clone(),
            operations: pset.operations.iter().cloned().collect(),
            requires_approval: pset.approve.iter().cloned().collect(),
        };
        engine.add_permission_set(name.clone(), acl);
    }
    engine
}

async fn serve(cfg: config::Config, no_tray: bool) -> anyhow::Result<()> {
    tracing::info!("Starting mcpd");

    let perm_engine = Arc::new(build_perm_engine(&cfg));

    // Build server, registering enabled modules
    let mut builder = mcpd_core::McpServer::builder()
        .name("mcpd")
        .version(env!("CARGO_PKG_VERSION"));

    // Register safety profiles per permission set
    for (name, pset) in &cfg.permissions {
        let pipeline = mcpd_core::safety::build_pipeline(&pset.safety);
        tracing::info!(
            permission_set = %name,
            safety = %pset.safety,
            "Safety profile"
        );
        builder = builder.safety_profile(name.clone(), pipeline);
    }

    // Build shared approval infrastructure
    let approvals = Arc::new(mcpd_core::permissions::ApprovalStore::new(
        cfg.approval.timeout_secs,
    ));
    let notifier: Arc<dyn mcpd_core::notify::Notifier> = match cfg.approval.notify.as_str() {
        "dbus" => {
            match mcpd_core::notify::DbusNotifier::new().await {
                Ok(n) => {
                    tracing::info!("D-Bus notifier connected");
                    Arc::new(n)
                }
                Err(e) => {
                    tracing::warn!("D-Bus unavailable ({e}), falling back to CLI-only approvals");
                    Arc::new(mcpd_core::notify::NoopNotifier)
                }
            }
        }
        _ => Arc::new(mcpd_core::notify::NoopNotifier),
    };

    // --- Docs module ---
    if cfg.docs_enabled() {
        let db_path = cfg.docs_db_path();
        let index = Arc::new(mcpd_mod_docs::IndexStore::open(&db_path)?);
        let docs = mcpd_mod_docs::DocsModule::new(
            perm_engine.clone(),
            index,
            approvals.clone(),
            notifier.clone(),
        );
        tracing::info!("Module 'docs' enabled (db: {db_path})");
        builder = builder.module(docs);
    }

    // --- Upstream MCP servers ---
    for upstream_cfg in &cfg.upstream {
        if !upstream_cfg.enabled.unwrap_or(true) {
            tracing::info!(upstream = %upstream_cfg.name, "Upstream disabled, skipping");
            continue;
        }

        let connect_result = match upstream_cfg.transport.as_str() {
            "stdio" => {
                mcpd_core::Upstream::spawn(
                    &upstream_cfg.name,
                    &upstream_cfg.command,
                    upstream_cfg.cwd.as_deref(),
                )
                .await
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
                mcpd_core::Upstream::http(&upstream_cfg.name, url).await
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
                mcpd_core::Upstream::sse(&upstream_cfg.name, url).await
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
            Ok(upstream) => match mcpd_core::UpstreamModule::discover(upstream).await {
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

    let server = Arc::new(builder.build());
    tracing::info!(
        tools = server.tool_count(),
        prompts = server.prompt_count(),
        resources = server.resource_count(),
        "Server ready"
    );

    // --- System tray ---
    if !no_tray {
        match tray::spawn_tray().await {
            Ok((cmd_rx, handle)) => {
                tracing::info!("System tray icon active");
                tokio::spawn(tray::run_tray_updater(
                    handle,
                    approvals.clone(),
                    cmd_rx,
                ));
            }
            Err(e) => {
                tracing::warn!("System tray unavailable: {e}");
            }
        }
    }

    // --- HTTP transport ---
    let router = mcpd_core::transport::build_router(server);

    let addr = cfg.server.listen_addr();
    let listener = tokio::net::TcpListener::bind(&addr).await?;
    tracing::info!("Listening on {addr}");

    axum::serve(listener, router).await?;
    Ok(())
}
