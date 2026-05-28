//! Build and test execution tool for self-improving flows.
//!
//! Runs `cargo build`, `cargo test`, or `cargo clippy` in a project
//! directory and returns structured results. Used by the self-improve
//! flow to verify fixes don't break the build.

use smgglrs_core::protocol::{CallToolResult, ToolDefinition, ToolInputSchema};
use std::collections::HashMap;

pub fn build_test_tool_def() -> ToolDefinition {
    ToolDefinition {
        name: "build_test".to_string(),
        description: Some(
            "Run cargo build, test, or clippy on a Rust project. \
             Returns structured results with pass/fail counts."
                .to_string(),
        ),
        input_schema: ToolInputSchema {
            schema_type: "object".to_string(),
            properties: Some(HashMap::from([
                (
                    "path".to_string(),
                    serde_json::json!({
                        "type": "string",
                        "description": "Path to the Rust project directory (must contain Cargo.toml)"
                    }),
                ),
                (
                    "command".to_string(),
                    serde_json::json!({
                        "type": "string",
                        "description": "Command to run: 'build', 'test', or 'clippy'",
                        "enum": ["build", "test", "clippy"],
                        "default": "test"
                    }),
                ),
                (
                    "package".to_string(),
                    serde_json::json!({
                        "type": "string",
                        "description": "Optional: run only for a specific package (-p flag)"
                    }),
                ),
            ])),
            required: Some(vec!["path".to_string()]),
        },
        annotations: None,
        ttl_ms: None,
        cache_scope: None,
    }
}

const BUILD_TIMEOUT_SECS: u64 = 300;

pub async fn handle_build_test(
    args: serde_json::Value,
    ctx: smgglrs_core::auth::CallContext,
    perm_engine: std::sync::Arc<smgglrs_core::permissions::PermissionEngine>,
) -> CallToolResult {
    let path = match args.get("path").and_then(|v| v.as_str()) {
        Some(p) => p,
        None => return CallToolResult::error("Missing required parameter: path"),
    };

    let command = args
        .get("command")
        .and_then(|v| v.as_str())
        .unwrap_or("test");

    let package = args.get("package").and_then(|v| v.as_str());

    // Permission check
    let canon = match std::path::Path::new(path).canonicalize() {
        Ok(p) => p,
        Err(e) => return CallToolResult::error(format!("Cannot resolve path: {e}")),
    };

    match perm_engine.check(&ctx.agent.permissions, "build", &canon) {
        smgglrs_core::permissions::PermissionResult::Allowed => {}
        other => {
            return CallToolResult::error(format!("Permission denied: {other:?}"));
        }
    }

    // Verify Cargo.toml exists
    if !canon.join("Cargo.toml").exists() {
        return CallToolResult::error(format!("No Cargo.toml at {}", canon.display()));
    }

    // Build the command
    let mut cmd = tokio::process::Command::new("cargo");
    cmd.arg(command);

    if let Some(pkg) = package {
        cmd.arg("-p").arg(pkg);
    }

    // Set ORT env vars for ONNX Runtime
    cmd.env("ORT_LIB_PATH", "/usr/lib64");
    cmd.env("ORT_PREFER_DYNAMIC_LINK", "1");

    cmd.current_dir(&canon);
    cmd.stdout(std::process::Stdio::piped());
    cmd.stderr(std::process::Stdio::piped());

    tracing::info!(
        path = %canon.display(),
        command = command,
        package = ?package,
        "Running build_test"
    );

    let output = match tokio::time::timeout(
        std::time::Duration::from_secs(BUILD_TIMEOUT_SECS),
        cmd.output(),
    )
    .await
    {
        Ok(Ok(output)) => output,
        Ok(Err(e)) => {
            return CallToolResult::error(format!("Failed to execute cargo: {e}"));
        }
        Err(_) => {
            return CallToolResult::error(format!("Build timed out after {BUILD_TIMEOUT_SECS}s"));
        }
    };

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    let success = output.status.success();

    // Parse test results if command was "test"
    let (passed, failed, ignored) = if command == "test" {
        parse_test_results(&stdout, &stderr)
    } else {
        (0, 0, 0)
    };

    // Truncate output to avoid overwhelming the model
    let max_output = 4096;
    let stdout_trunc = if stdout.len() > max_output {
        format!(
            "{}...\n[truncated, {} total chars]",
            &stdout[..max_output],
            stdout.len()
        )
    } else {
        stdout.to_string()
    };
    let stderr_trunc = if stderr.len() > max_output {
        format!(
            "{}...\n[truncated, {} total chars]",
            &stderr[..max_output],
            stderr.len()
        )
    } else {
        stderr.to_string()
    };

    let result = serde_json::json!({
        "success": success,
        "command": command,
        "exit_code": output.status.code().unwrap_or(-1),
        "passed": passed,
        "failed": failed,
        "ignored": ignored,
        "stdout": stdout_trunc,
        "stderr": stderr_trunc,
    });

    if success {
        CallToolResult::text(result.to_string())
    } else {
        CallToolResult::error(result.to_string())
    }
}

fn parse_test_results(stdout: &str, stderr: &str) -> (u32, u32, u32) {
    let mut passed = 0u32;
    let mut failed = 0u32;
    let mut ignored = 0u32;

    let combined = format!("{stdout}\n{stderr}");
    for line in combined.lines() {
        if line.contains("test result:") {
            // "test result: ok. 145 passed; 0 failed; 2 ignored; ..."
            // Extract numbers preceding "passed", "failed", "ignored"
            let words: Vec<&str> = line.split_whitespace().collect();
            for (i, word) in words.iter().enumerate() {
                if i > 0 {
                    if let Some(n) = words[i - 1].parse::<u32>().ok() {
                        match *word {
                            "passed" | "passed;" => passed += n,
                            "failed" | "failed;" => failed += n,
                            "ignored" | "ignored;" => ignored += n,
                            _ => {}
                        }
                    }
                }
            }
        }
    }

    (passed, failed, ignored)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_test_output() {
        let stdout = "test result: ok. 145 passed; 0 failed; 2 ignored; 0 measured; 0 filtered out";
        let (p, f, i) = parse_test_results(stdout, "");
        assert_eq!(p, 145);
        assert_eq!(f, 0);
        assert_eq!(i, 2);
    }

    #[test]
    fn parse_multiple_test_results() {
        let stdout = "\
test result: ok. 10 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out
test result: ok. 20 passed; 1 failed; 3 ignored; 0 measured; 0 filtered out";
        let (p, f, i) = parse_test_results(stdout, "");
        assert_eq!(p, 30);
        assert_eq!(f, 1);
        assert_eq!(i, 3);
    }

    #[test]
    fn parse_no_results() {
        let (p, f, i) = parse_test_results("compiling...", "warning: unused");
        assert_eq!(p, 0);
        assert_eq!(f, 0);
        assert_eq!(i, 0);
    }

    #[test]
    fn tool_def_has_required_path() {
        let def = build_test_tool_def();
        assert_eq!(def.name, "build_test");
        assert!(def
            .input_schema
            .required
            .as_ref()
            .unwrap()
            .contains(&"path".to_string()));
    }
}
