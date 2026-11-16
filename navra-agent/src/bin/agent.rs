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
//! | `NAVRA_MODEL_NAME` | no* | Model name (e.g. `nemotron-omni`) |
//! | `NAVRA_PERSONA` | no | Persona name (loads from cognitive core) |
//! | `NAVRA_TASK` | no* | Prompt/mandate to execute |
//! | `NAVRA_MAX_ITERATIONS` | no | Iteration cap (default 30) |
//! | `NAVRA_COGNITIVE_CORE` | no | Path to cognitive_core directory |
//! | `NAVRA_OUTPUT_SCHEMA` | no | JSON schema to constrain model output format |
//!
//! *Poll mode: when `NAVRA_TASK` is not set, the agent polls
//! `GET /api/agent/task` on the gateway (derived from
//! `NAVRA_ENDPOINT`) with its token until a task is assigned, then
//! runs it and publishes the result to `POST /api/agent/result`.
//! This is how warm-pool Sandboxes receive per-spawn tasks without
//! per-spawn env, and how tasks are redelivered after a pod
//! restart. In poll mode the task, model name, persona, and
//! iteration cap come from the task spec; env values (if set) take
//! precedence.

use std::env;
use std::path::Path;
use std::process::ExitCode;
use std::time::Duration;

use navra_agent::{Agent, Locality, ModelBackend, OpenAiBackend};

fn required_env(name: &str) -> Result<String, String> {
    env::var(name).map_err(|_| format!("{name} is required but not set"))
}

/// Task spec served by the gateway's `GET /api/agent/task`.
#[derive(Debug, Default)]
struct TaskSpec {
    task: Option<String>,
    model: Option<String>,
    persona: Option<String>,
    max_iterations: Option<usize>,
    temperature: Option<f32>,
}

impl TaskSpec {
    fn from_json(json: &serde_json::Value) -> Self {
        Self {
            task: json["task"].as_str().map(String::from),
            model: json["model"].as_str().map(String::from),
            persona: json["persona"].as_str().map(String::from),
            max_iterations: json["max_iterations"].as_u64().map(|v| v as usize),
            temperature: json["temperature"].as_f64().map(|v| v as f32),
        }
    }
}

/// Derive a gateway API URL from the MCP endpoint URL
/// (`http://host:9315/mcp` → `http://host:9315{path}`).
fn api_url(endpoint: &str, path: &str) -> String {
    let base = endpoint.strip_suffix("/mcp").unwrap_or(endpoint);
    format!("{base}{path}")
}

/// Poll the gateway until a task is assigned. A 200 response with a
/// null task means the teammate exists but has not been messaged
/// yet — keep polling. 404 is also retried (the teammate may not be
/// registered at the gateway yet). Auth failures are fatal.
async fn fetch_task_spec(endpoint: &str, token: Option<&str>) -> Result<TaskSpec, String> {
    let url = api_url(endpoint, "/api/agent/task");
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(30))
        .build()
        .map_err(|e| format!("http client error: {e}"))?;
    let deadline = Duration::from_secs(
        env::var("NAVRA_TASK_POLL_TIMEOUT_SECS")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(600),
    );
    let started = std::time::Instant::now();

    loop {
        let mut req = client.get(&url);
        if let Some(t) = token {
            req = req.bearer_auth(t);
        }
        let resp = req
            .send()
            .await
            .map_err(|e| format!("task fetch failed: {e}"))?;
        match resp.status() {
            reqwest::StatusCode::OK => {
                let json: serde_json::Value = resp
                    .json()
                    .await
                    .map_err(|e| format!("invalid task spec: {e}"))?;
                let spec = TaskSpec::from_json(&json);
                if spec.task.is_some() {
                    return Ok(spec);
                }
                // No task yet — keep polling below.
            }
            reqwest::StatusCode::UNAUTHORIZED | reqwest::StatusCode::FORBIDDEN => {
                return Err("task fetch unauthorized: token rejected by gateway".to_string());
            }
            reqwest::StatusCode::NOT_FOUND => {
                // Teammate not registered yet — keep polling below.
            }
            status => {
                return Err(format!("task fetch failed with status {status}"));
            }
        }

        if started.elapsed() >= deadline {
            return Err(format!("no task assigned within {}s", deadline.as_secs()));
        }
        tokio::time::sleep(Duration::from_secs(2)).await;
    }
}

/// Publish the run result to the gateway. Failure is logged but not
/// fatal: stdout still carries the JSON result for log-based
/// collectors.
async fn publish_result(endpoint: &str, token: Option<&str>, result: &serde_json::Value) {
    let url = api_url(endpoint, "/api/agent/result");
    let client = match reqwest::Client::builder()
        .timeout(Duration::from_secs(30))
        .build()
    {
        Ok(c) => c,
        Err(e) => {
            eprintln!("warning: result publish client error: {e}");
            return;
        }
    };
    let mut req = client.post(&url).json(result);
    if let Some(t) = token {
        req = req.bearer_auth(t);
    }
    match req.send().await {
        Ok(resp) if resp.status().is_success() => {}
        Ok(resp) => eprintln!(
            "warning: result publish failed with status {}",
            resp.status()
        ),
        Err(e) => eprintln!("warning: result publish failed: {e}"),
    }
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
    let token = env::var("NAVRA_TOKEN").ok();

    // Poll mode when no task is baked into env: warm-pool adoption
    // or restart redelivery.
    let poll_spec = if env::var("NAVRA_TASK").is_err() {
        Some(fetch_task_spec(&endpoint, token.as_deref()).await?)
    } else {
        None
    };

    let task = env::var("NAVRA_TASK")
        .ok()
        .or_else(|| poll_spec.as_ref().and_then(|s| s.task.clone()))
        .ok_or("no task available (set NAVRA_TASK or serve one via the gateway)")?;
    let model_name = env::var("NAVRA_MODEL_NAME")
        .ok()
        .or_else(|| poll_spec.as_ref().and_then(|s| s.model.clone()))
        .ok_or("NAVRA_MODEL_NAME is required but not set")?;
    let persona_name = env::var("NAVRA_PERSONA")
        .ok()
        .or_else(|| poll_spec.as_ref().and_then(|s| s.persona.clone()));
    let cognitive_core_path = env::var("NAVRA_COGNITIVE_CORE").ok();
    let output_schema: Option<serde_json::Value> = env::var("NAVRA_OUTPUT_SCHEMA")
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok());
    let max_iterations: usize = env::var("NAVRA_MAX_ITERATIONS")
        .ok()
        .and_then(|v| v.parse().ok())
        .or_else(|| poll_spec.as_ref().and_then(|s| s.max_iterations))
        .unwrap_or(30);
    let spec_temperature = poll_spec.as_ref().and_then(|s| s.temperature);
    let context_window: Option<u32> = env::var("NAVRA_CONTEXT_WINDOW")
        .ok()
        .and_then(|v| v.parse().ok());

    // Build model backend. The NAVRA_TOKEN (a delegated capability
    // token when spawned by the gateway) authenticates model calls
    // when the model endpoint is the gateway's /v1 proxy — so
    // teammate model traffic flows through the same
    // safety/IFC/audit pipeline as its tool calls. Unauthenticated
    // endpoints (llama.cpp, Ollama direct) ignore the header.
    let model_api_key = env::var("NAVRA_TOKEN").ok();
    let backend = OpenAiBackend::new(
        &model_endpoint,
        &model_name,
        model_api_key,
        Locality::Remote,
    );
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
        .temperature(spec_temperature.unwrap_or(0.3));

    if let Some(cw) = context_window.or(backend_context_window) {
        builder = builder.context_window_tokens(cw);
    }

    if let Some(schema) = output_schema {
        builder = builder.output_json_schema(schema);
    }

    // Load persona if both name and cognitive core path are provided
    if let (Some(name), Some(core_path)) = (&persona_name, &cognitive_core_path) {
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

    // In poll mode the gateway has no log collector pointed at this
    // pod — publish the result over HTTP. (Also prints to stdout for
    // log-based collectors and debugging.)
    if poll_spec.is_some() {
        publish_result(&endpoint, token.as_deref(), &output).await;
    }

    println!("{}", serde_json::to_string(&output).unwrap());

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn api_url_strips_mcp_suffix() {
        assert_eq!(
            api_url("http://gw:9315/mcp", "/api/agent/task"),
            "http://gw:9315/api/agent/task"
        );
    }

    #[test]
    fn api_url_handles_endpoint_without_suffix() {
        assert_eq!(
            api_url("http://gw:9315", "/api/agent/result"),
            "http://gw:9315/api/agent/result"
        );
    }

    #[test]
    fn task_spec_parses_full_json() {
        let spec = TaskSpec::from_json(&serde_json::json!({
            "task": "analyze the dataset",
            "model": "granite3.3:8b",
            "persona": "analyst",
            "max_iterations": 12,
            "temperature": 0.1
        }));
        assert_eq!(spec.task.as_deref(), Some("analyze the dataset"));
        assert_eq!(spec.model.as_deref(), Some("granite3.3:8b"));
        assert_eq!(spec.persona.as_deref(), Some("analyst"));
        assert_eq!(spec.max_iterations, Some(12));
        assert_eq!(spec.temperature, Some(0.1));
    }

    #[test]
    fn task_spec_with_null_task_means_not_assigned() {
        let spec = TaskSpec::from_json(&serde_json::json!({
            "task": serde_json::Value::Null,
            "model": "granite3.3:8b"
        }));
        assert!(spec.task.is_none());
        assert!(spec.model.is_some());
    }
}
