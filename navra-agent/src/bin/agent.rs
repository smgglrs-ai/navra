//! Standalone navra-agent binary for container execution.
//!
//! Reads configuration from environment variables and runs a single
//! agent task against a navra gateway, printing the result as JSON.
//!
//! # Environment variables
//!
//! | Variable | Required | Description |
//! |---|---|---|
//! | `NAVRA_ENDPOINT` | yes | Gateway MCP URL |
//! | `NAVRA_TOKEN` | no | Scoped capability token |
//! | `NAVRA_MODEL_ENDPOINT` | yes | Model server URL (e.g. `http://model-server:8080/v1`) |
//! | `NAVRA_MODEL_NAME` | yes | Model name (e.g. `nemotron-omni`) |
//! | `NAVRA_PERSONA` | no | Persona name (loads from cognitive core) |
//! | `NAVRA_TASK` | yes | Prompt/mandate to execute |
//! | `NAVRA_MAX_ITERATIONS` | no | Iteration cap (default 30) |
//! | `NAVRA_COGNITIVE_CORE` | no | Path to cognitive_core directory |
//! | `NAVRA_OUTPUT_SCHEMA` | no | JSON schema to constrain model output format |

use std::env;
use std::path::Path;
use std::process::ExitCode;

use navra_agent::{Agent, Locality, ModelBackend, OpenAiBackend};

fn required_env(name: &str) -> Result<String, String> {
    env::var(name).map_err(|_| format!("{name} is required but not set"))
}

#[tokio::main]
async fn main() -> ExitCode {
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("warn")),
        )
        .with_target(false)
        .init();

    match run().await {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::FAILURE
        }
    }
}

async fn run() -> Result<(), String> {
    let endpoint = required_env("NAVRA_ENDPOINT")?;
    let model_endpoint = required_env("NAVRA_MODEL_ENDPOINT")?;
    let model_name = required_env("NAVRA_MODEL_NAME")?;
    let task = required_env("NAVRA_TASK")?;

    let token = env::var("NAVRA_TOKEN").ok();
    let persona_name = env::var("NAVRA_PERSONA").ok();
    let cognitive_core_path = env::var("NAVRA_COGNITIVE_CORE").ok();
    let output_schema: Option<serde_json::Value> = env::var("NAVRA_OUTPUT_SCHEMA")
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok());
    let max_iterations: usize = env::var("NAVRA_MAX_ITERATIONS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(30);
    let context_window: Option<u32> = env::var("NAVRA_CONTEXT_WINDOW")
        .ok()
        .and_then(|v| v.parse().ok());

    // Build model backend
    let backend = OpenAiBackend::new(&model_endpoint, &model_name, None, Locality::Remote);
    let backend_context_window = backend.context_window();

    // Start building the agent
    let mut builder = Agent::builder()
        .endpoint(&endpoint)
        .await
        .map_err(|e| format!("endpoint connection failed: {e}"))?;

    if let Some(ref t) = token {
        builder = builder.auth_token(t);
    }

    builder = builder
        .model(backend)
        .max_iterations(max_iterations)
        .temperature(0.3);

    if let Some(cw) = context_window.or(backend_context_window) {
        builder = builder.context_window_tokens(cw);
    }

    if let Some(schema) = output_schema {
        builder = builder.output_json_schema(schema);
    }

    // Load persona if both name and cognitive core path are provided
    if let (Some(ref name), Some(ref core_path)) = (&persona_name, &cognitive_core_path) {
        let forge = navra_cognitive::ForgeService::load(Path::new(core_path))
            .map_err(|e| format!("failed to load cognitive core from {core_path}: {e}"))?;
        builder = builder
            .persona(&forge, name)
            .map_err(|e| format!("failed to load persona '{name}': {e}"))?;
    }

    let mut agent = builder
        .build()
        .await
        .map_err(|e| format!("agent build failed: {e}"))?;

    // Run the task
    let result = agent
        .run(&task)
        .await
        .map_err(|e| format!("agent run failed: {e}"))?;

    // Print result as JSON
    let output = serde_json::json!({
        "output": result.response,
        "iterations": result.iterations,
        "tokens_in": result.input_tokens,
        "tokens_out": result.output_tokens,
        "compressed_chars_saved": result.compressed_chars_saved,
    });
    println!("{}", serde_json::to_string(&output).unwrap());

    Ok(())
}
