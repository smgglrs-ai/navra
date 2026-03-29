mod config;

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
        Commands::Serve { config: config_path } => {
            let cfg = config::Config::load(config_path.as_deref())?;
            serve(cfg).await?;
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

async fn serve(cfg: config::Config) -> anyhow::Result<()> {
    tracing::info!("Starting mcpd");

    let perm_engine = Arc::new(build_perm_engine(&cfg));

    // Build server, registering enabled modules
    let mut builder = mcpd_core::McpServer::builder()
        .name("mcpd")
        .version(env!("CARGO_PKG_VERSION"));

    // --- Docs module ---
    if cfg.docs_enabled() {
        let db_path = cfg.docs_db_path();
        let index = Arc::new(mcpd_mod_docs::IndexStore::open(&db_path)?);
        let docs = mcpd_mod_docs::DocsModule::new(perm_engine.clone(), index);
        tracing::info!("Module 'docs' enabled (db: {db_path})");
        builder = builder.module(docs);
    }

    // --- Future modules would be registered here ---
    // if cfg.git_enabled() { builder = builder.module(git_module); }

    let server = Arc::new(builder.build());
    tracing::info!("Registered {} tools", server.tool_count());

    let router = mcpd_core::transport::build_router(server);

    let addr = cfg.server.listen_addr();
    let listener = tokio::net::TcpListener::bind(&addr).await?;
    tracing::info!("Listening on {addr}");

    axum::serve(listener, router).await?;
    Ok(())
}
