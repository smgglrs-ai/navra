mod config;
mod tray;

use clap::{Parser, Subcommand};
use mcpd_core::auth::{AgentIdentity, TokenAuthenticator};
use mcpd_core::permissions::{PathAcl, PermissionEngine, ToolPermissions, ToolPolicy, ToolRule};
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

    // Register token-based authenticator if agents are configured
    if !cfg.agents.is_empty() {
        let mut auth = TokenAuthenticator::new();
        for agent in &cfg.agents {
            auth.register_hash(
                &agent.token_hash,
                AgentIdentity {
                    name: agent.name.clone(),
                    permissions: agent.permissions.clone(),
                },
            );
            tracing::info!(agent = %agent.name, permissions = %agent.permissions, "Registered agent");
        }
        builder = builder.authenticator(auth);
    }

    // Register safety profiles and per-tool permissions per permission set
    for (name, pset) in &cfg.permissions {
        let pipeline = mcpd_core::safety::build_pipeline(&pset.safety);
        tracing::info!(
            permission_set = %name,
            safety = %pset.safety,
            "Safety profile"
        );
        builder = builder.safety_profile(name.clone(), pipeline);

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

        let retry_config = upstream_cfg.retry_config();
        let connect_result = match upstream_cfg.transport.as_str() {
            "stdio" => {
                if let Some(rc) = retry_config {
                    tracing::info!(
                        upstream = %upstream_cfg.name,
                        "Using resilient transport (retry enabled)"
                    );
                    mcpd_core::Upstream::spawn_resilient(
                        &upstream_cfg.name,
                        &upstream_cfg.command,
                        upstream_cfg.cwd.as_deref(),
                        rc,
                    )
                    .await
                } else {
                    mcpd_core::Upstream::spawn(
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
                    mcpd_core::Upstream::http_resilient(&upstream_cfg.name, url, rc).await
                } else {
                    mcpd_core::Upstream::http(&upstream_cfg.name, url).await
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
                    mcpd_core::Upstream::sse_resilient(&upstream_cfg.name, url, rc).await
                } else {
                    mcpd_core::Upstream::sse(&upstream_cfg.name, url).await
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
