//! S9 Evaluation Runner: start flows, poll completion, collect results.
//!
//! Unlike the shell script that blocks on a single curl call, this
//! binary starts a flow asynchronously, polls flow_status every 30s,
//! and fetches results when done. Handles server restarts between runs.
//!
//! Usage:
//!   navra-eval --endpoint http://localhost:9315/mcp \
//!     --flow review-lite \
//!     --projects /path/to/project1,/path/to/project2 \
//!     --runs 3 \
//!     --output results/s9-eval

use navra_agent::{CallToolResult, McpClient};
use navra_protocol::Upstream;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

fn extract_text(result: &CallToolResult) -> String {
    navra_agent::extract_text(result)
}

struct EvalConfig {
    endpoint: String,
    flow_name: String,
    projects: Vec<(String, PathBuf)>,
    runs_per_project: usize,
    output_dir: PathBuf,
    poll_interval: Duration,
}

impl EvalConfig {
    fn from_env() -> Self {
        let endpoint = std::env::var("NAVRA_ENDPOINT")
            .unwrap_or_else(|_| "http://localhost:9315/mcp".to_string());
        let flow_name = std::env::var("NAVRA_FLOW").unwrap_or_else(|_| "review-lite".to_string());
        let output_dir = PathBuf::from(
            std::env::var("NAVRA_EVAL_OUTPUT").unwrap_or_else(|_| "results/s9-eval".to_string()),
        );
        let runs: usize = std::env::var("NAVRA_EVAL_RUNS")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(3);

        let project_paths = std::env::var("NAVRA_EVAL_PROJECTS").unwrap_or_else(|_| {
            let home = std::env::var("HOME").unwrap_or_default();
            format!(
                "{home}/Code/github.com/fabiendupont/synthos,\
                 {home}/Code/github.com/fabiendupont/edge-ai-sno,\
                 {home}/Code/github.com/fabiendupont/syllogis"
            )
        });

        let projects: Vec<(String, PathBuf)> = project_paths
            .split(',')
            .map(|p| {
                let path = PathBuf::from(p.trim());
                let name = path
                    .file_name()
                    .map(|n| n.to_string_lossy().to_string())
                    .unwrap_or_else(|| "unknown".to_string());
                (name, path)
            })
            .collect();

        Self {
            endpoint,
            flow_name,
            projects,
            runs_per_project: runs,
            output_dir,
            poll_interval: Duration::from_secs(30),
        }
    }
}

async fn connect(endpoint: &str) -> Result<McpClient, String> {
    let upstream = Upstream::http("eval", endpoint)
        .await
        .map_err(|e| format!("connect failed: {e}"))?;
    Ok(McpClient::new(upstream))
}

async fn start_flow(
    client: &mut McpClient,
    flow_name: &str,
    project_name: &str,
    project_path: &Path,
) -> Result<String, String> {
    let args = serde_json::json!({
        "flow_name": flow_name,
        "prompt": format!("Review the {project_name} project for code quality, security, and architecture."),
        "parameters": {
            "target_dir": project_path.to_string_lossy(),
        }
    });

    let result = client
        .call_tool("flow_start", args)
        .await
        .map_err(|e| format!("flow_start failed: {e}"))?;

    let text = extract_text(&result);

    // Extract flow_id from response
    for line in text.lines() {
        if line.starts_with("flow_id:") {
            return Ok(line.trim_start_matches("flow_id:").trim().to_string());
        }
    }

    // flow_start is synchronous — the full result is already here
    Ok(text)
}

async fn poll_flow(
    client: &mut McpClient,
    flow_id: &str,
    poll_interval: Duration,
) -> Result<String, String> {
    loop {
        let args = serde_json::json!({ "flow_id": flow_id });
        let result = client
            .call_tool("flow_status", args)
            .await
            .map_err(|e| format!("flow_status failed: {e}"))?;

        let text = extract_text(&result);
        if text.contains("\"completed\"") || text.contains("\"failed\"") {
            return Ok(text);
        }

        tokio::time::sleep(poll_interval).await;
    }
}

#[tokio::main]
async fn main() {
    let config = EvalConfig::from_env();

    std::fs::create_dir_all(&config.output_dir).expect("create output dir");

    eprintln!("=== S9 Evaluation Runner ===");
    eprintln!("Endpoint: {}", config.endpoint);
    eprintln!("Flow: {}", config.flow_name);
    eprintln!(
        "Projects: {}",
        config
            .projects
            .iter()
            .map(|(n, _)| n.as_str())
            .collect::<Vec<_>>()
            .join(", ")
    );
    eprintln!("Runs per project: {}", config.runs_per_project);
    eprintln!();

    let total_runs = config.projects.len() * config.runs_per_project;
    let mut run_num = 0;

    for (project_name, project_path) in &config.projects {
        for run in 1..=config.runs_per_project {
            run_num += 1;
            let outfile = config
                .output_dir
                .join(format!("{project_name}-run{run}.json"));

            eprintln!("--- [{run_num}/{total_runs}] {project_name} run {run} ---");
            eprintln!("  Start: {}", chrono_now());

            // Connect (reconnect on each run for clean state)
            let mut client = match connect(&config.endpoint).await {
                Ok(c) => c,
                Err(e) => {
                    eprintln!("  ERROR: {e}");
                    let err = serde_json::json!({"error": e});
                    std::fs::write(&outfile, err.to_string()).ok();
                    continue;
                }
            };

            let start = Instant::now();

            // flow_start blocks until the flow completes (current design)
            match start_flow(&mut client, &config.flow_name, project_name, project_path).await {
                Ok(result) => {
                    let duration = start.elapsed();
                    eprintln!("  Done: {} ({:.0}s)", chrono_now(), duration.as_secs_f64());

                    let output = serde_json::json!({
                        "project": project_name,
                        "run": run,
                        "duration_secs": duration.as_secs(),
                        "result": result,
                    });
                    std::fs::write(&outfile, serde_json::to_string_pretty(&output).unwrap())
                        .expect("write result");
                    eprintln!("  Saved: {}", outfile.display());
                }
                Err(e) => {
                    let duration = start.elapsed();
                    eprintln!("  FAILED after {:.0}s: {e}", duration.as_secs_f64());
                    let output = serde_json::json!({
                        "project": project_name,
                        "run": run,
                        "duration_secs": duration.as_secs(),
                        "error": e,
                    });
                    std::fs::write(&outfile, serde_json::to_string_pretty(&output).unwrap()).ok();
                }
            }
        }
    }

    eprintln!();
    eprintln!("=== Evaluation Complete ===");
    eprintln!("Results: {}", config.output_dir.display());
}

fn chrono_now() -> String {
    chrono::Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string()
}
