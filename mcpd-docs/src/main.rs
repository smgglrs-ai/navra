mod config;
mod index;
mod permissions;
mod tools;

use clap::{Parser, Subcommand};
use std::sync::Arc;

#[derive(Parser)]
#[command(name = "mcpd-docs", about = "Secure MCP document server")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Start the MCP document server
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
    Approve {
        /// Request ID to approve
        id: String,
    },
    /// Deny a pending request
    Deny {
        /// Request ID to deny
        id: String,
    },
    /// Show server status
    Status,
}

#[derive(Subcommand)]
enum TokenAction {
    /// Generate a new agent token
    Generate {
        /// Agent name
        #[arg(short, long)]
        name: String,
        /// Permission set name
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

async fn serve(cfg: config::Config) -> anyhow::Result<()> {
    tracing::info!("Starting mcpd-docs");

    // Build permission engine
    let perm_engine = Arc::new(permissions::PermissionEngine::from_config(&cfg));

    // Build MCP server with tools
    let server = tools::build_server(cfg.clone(), perm_engine)?;
    let server = Arc::new(server);

    // Build transport
    let router = mcpd_core::transport::build_router(server);

    // Bind to Unix socket or TCP
    let listener = tokio::net::TcpListener::bind(&cfg.server.listen_addr()).await?;
    tracing::info!("Listening on {}", cfg.server.listen_addr());

    axum::serve(listener, router).await?;
    Ok(())
}
