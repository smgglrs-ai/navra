//! Standalone agent binary using the navra-agent SDK.
//!
//! Demonstrates how to build a CLI agent that connects to a navra
//! gateway (or any MCP server), selects a model backend, and runs
//! a single task through the agentic tool-use loop.
//!
//! Run with:
//! ```sh
//! cargo run -- --prompt "List files in the current directory"
//! ```

use anyhow::Result;
use clap::Parser;
use navra_agent::{Agent, Locality, OpenAiBackend};

// ---------------------------------------------------------------------------
// CLI argument parsing
// ---------------------------------------------------------------------------

/// A standalone AI agent powered by navra-agent.
#[derive(Parser)]
#[command(name = "navra-standalone-agent")]
#[command(about = "Run a single task through a navra MCP gateway")]
struct Cli {
    /// MCP server endpoint URL (navra gateway or any MCP server).
    #[arg(long, default_value = "http://localhost:3000/mcp")]
    endpoint: String,

    /// Bearer token for authenticating with the MCP server.
    /// Not required for local development with default navra config.
    #[arg(long, env = "NAVRA_TOKEN")]
    token: Option<String>,

    /// Model name to use for inference (passed to the backend).
    /// For Ollama: any pulled model name (e.g. "granite3.3:8b").
    /// For OpenAI-compatible APIs: the model identifier.
    #[arg(long, default_value = "granite3.3:8b")]
    model: String,

    /// Base URL of the model backend API.
    /// Defaults to local Ollama. For remote APIs, include /v1 suffix.
    #[arg(long, default_value = "http://localhost:11434/v1")]
    model_url: String,

    /// API key for the model backend (required for remote APIs).
    #[arg(long, env = "MODEL_API_KEY")]
    api_key: Option<String>,

    /// The task to execute.
    #[arg(long)]
    prompt: String,

    /// Maximum number of tool-call iterations before stopping.
    #[arg(long, default_value_t = 20)]
    max_iterations: usize,

    /// Maximum tokens the model may use per run (soft circuit breaker).
    #[arg(long, default_value_t = 50000)]
    max_tokens_per_run: u32,

    /// Restrict the agent to these tools (comma-separated).
    /// When empty, all tools advertised by the server are available.
    #[arg(long, value_delimiter = ',')]
    allowed_tools: Vec<String>,
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize tracing (respects RUST_LOG env var).
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let cli = Cli::parse();

    // -- Step 1: Create a model backend --
    //
    // OpenAiBackend works with any OpenAI-compatible API: Ollama, vLLM,
    // Mistral, Together, etc. The Locality flag tells the gateway whether
    // content needs PII filtering before it leaves the machine.
    let locality = if cli.model_url.contains("localhost") || cli.model_url.contains("127.0.0.1") {
        Locality::Local
    } else {
        Locality::Remote
    };

    let model = OpenAiBackend::new(&cli.model_url, &cli.model, cli.api_key, locality);

    // -- Step 2: Build the agent --
    //
    // Agent::builder() provides a fluent API for configuring the agent.
    // The endpoint() call connects to the MCP server and discovers
    // available tools. The model() call sets the inference backend.
    let mut builder = Agent::builder()
        .endpoint(&cli.endpoint)
        .await?
        .model(model)
        .system_prompt(
            "You are a helpful assistant. Use the available tools to \
             accomplish the user's task. Be concise in your responses.",
        )
        .max_iterations(cli.max_iterations);

    // Set authentication token if provided.
    if let Some(ref token) = cli.token {
        builder = builder.auth_token(token);
    }

    // Restrict to specific tools if the user requested it.
    if !cli.allowed_tools.is_empty() {
        builder = builder.allowed_tools(cli.allowed_tools);
    }

    let mut agent = builder.build().await?;

    // -- Step 3: Run the task --
    //
    // agent.run() enters the ReAct loop: model generates tool calls,
    // the SDK executes them via MCP, feeds results back to the model,
    // and repeats until the model produces a text response or hits
    // the iteration limit.
    eprintln!("Running agent with prompt: {}", cli.prompt);
    eprintln!("---");

    let result = agent.run(&cli.prompt).await?;

    // -- Step 4: Display results --
    println!("{}", result.response);

    // -- Step 5: Print run summary --
    eprintln!("---");
    eprintln!("Run ID:          {}", result.run_id);
    eprintln!("Iterations:      {}", result.iterations);
    eprintln!("Input tokens:    {}", result.input_tokens);
    eprintln!("Output tokens:   {}", result.output_tokens);
    eprintln!("Tools called:    {}", result.blocks.len());
    eprintln!("Interrupted:     {}", result.interrupted);

    if !result.blocks.is_empty() {
        eprintln!("Tool calls:");
        for block in &result.blocks {
            let status = if block.is_error {
                "ERR"
            } else {
                "OK"
            };
            let duration = block
                .duration_ms
                .map(|d| format!("{d}ms"))
                .unwrap_or_else(|| "?".to_string());
            eprintln!("  - {} [{}] ({})", block.tool_name, status, duration);
        }
    }

    Ok(())
}
