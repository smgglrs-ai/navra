//! Standalone smgglrs-agent binary for container execution.
//!
//! Reads configuration from environment variables and runs a single
//! agent task against a smgglrs gateway, printing the result as JSON.
//!
//! # Environment variables
//!
//! | Variable | Required | Description |
//! |---|---|---|
//! | `SMGGLRS_ENDPOINT` | yes | Gateway MCP URL |
//! | `SMGGLRS_TOKEN` | no | Scoped capability token |
//! | `SMGGLRS_MODEL_ENDPOINT` | yes | Model server URL (e.g. `http://model-server:8080/v1`) |
//! | `SMGGLRS_MODEL_NAME` | yes | Model name (e.g. `nemotron-omni`) |
//! | `SMGGLRS_PERSONA` | no | Persona name (loads from cognitive core) |
//! | `SMGGLRS_TASK` | yes | Prompt/mandate to execute |
//! | `SMGGLRS_MAX_ITERATIONS` | no | Iteration cap (default 30) |
//! | `SMGGLRS_COGNITIVE_CORE` | no | Path to cognitive_core directory |
//! | `SMGGLRS_OUTPUT_SCHEMA` | no | JSON schema to constrain model output format |

use std::env;
use std::path::Path;
use std::process::ExitCode;

use smgglrs_agent::{Agent, Locality, OpenAiBackend};

fn required_env(name: &str) -> Result<String, String> {
    env::var(name).map_err(|_| format!("{name} is required but not set"))
}

#[tokio::main]
async fn main() -> ExitCode {
    tracing_subscriber::fmt()
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
    let endpoint = required_env("SMGGLRS_ENDPOINT")?;
    let model_endpoint = required_env("SMGGLRS_MODEL_ENDPOINT")?;
    let model_name = required_env("SMGGLRS_MODEL_NAME")?;
    let task = required_env("SMGGLRS_TASK")?;

    let token = env::var("SMGGLRS_TOKEN").ok();
    let persona_name = env::var("SMGGLRS_PERSONA").ok();
    let cognitive_core_path = env::var("SMGGLRS_COGNITIVE_CORE").ok();
    let output_schema: Option<serde_json::Value> = env::var("SMGGLRS_OUTPUT_SCHEMA")
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok());
    let max_iterations: usize = env::var("SMGGLRS_MAX_ITERATIONS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(30);

    // Build model backend
    let backend = OpenAiBackend::new(&model_endpoint, &model_name, None, Locality::Remote);

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

    if let Some(schema) = output_schema {
        builder = builder.output_json_schema(schema);
    }

    // Load persona if both name and cognitive core path are provided
    if let (Some(ref name), Some(ref core_path)) = (&persona_name, &cognitive_core_path) {
        let forge = smgglrs_cognitive::ForgeService::load(Path::new(core_path))
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
    });
    println!("{}", serde_json::to_string(&output).unwrap());

    Ok(())
}
