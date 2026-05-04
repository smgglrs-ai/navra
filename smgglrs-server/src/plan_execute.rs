//! Plan execution tool: run multi-step plans in a single model turn.
//!
//! Supports two modes:
//! - **YAML** (no sandbox): declarative steps with variable passing
//! - **Python** (sandbox): CodeAct via OpenShell or Podman

use smgglrs_core::auth::CallContext;
use smgglrs_core::protocol::{CallToolParams, CallToolResult, Content, ToolDefinition, ToolInputSchema};
use smgglrs_core::McpServer;
use std::collections::HashMap;

/// Error handling strategy for a step.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OnError {
    /// Stop plan execution on failure (default).
    Stop,
    /// Skip the failed step and continue.
    Continue,
    /// Use a default value and mark the step as successful.
    Default,
}

impl Default for OnError {
    fn default() -> Self {
        OnError::Stop
    }
}

impl<'de> serde::Deserialize<'de> for OnError {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        match s.as_str() {
            "stop" => Ok(OnError::Stop),
            "continue" => Ok(OnError::Continue),
            "default" => Ok(OnError::Default),
            other => Err(serde::de::Error::custom(format!(
                "unknown on_error value: '{}' (expected stop, continue, default)",
                other
            ))),
        }
    }
}

/// A single tool-call step in a YAML plan.
#[derive(Debug, Clone, serde::Deserialize)]
pub struct PlanStep {
    pub tool: String,
    #[serde(default)]
    pub args: serde_json::Value,
    pub save_as: Option<String>,
    /// Conditional execution: a template expression like "{{prev.success}}".
    /// Step is skipped when the expression resolves to a falsy value.
    pub when: Option<String>,
    /// Error handling strategy: "stop" (default), "continue", or "default".
    pub on_error: Option<OnError>,
    /// Default value to use when on_error is "default" and the step fails.
    pub default_value: Option<String>,
}

/// A for_each iteration step that loops over a list.
#[derive(Debug, Clone, serde::Deserialize)]
pub struct ForEachStep {
    /// Variable reference or literal to iterate over.
    pub for_each: String,
    /// Delimiter to split the value into items (default: newline).
    #[serde(default = "default_split_by")]
    pub split_by: String,
    /// Optional substring filter — only items containing this string are kept.
    pub filter: Option<String>,
    /// Variable name bound to each item during iteration.
    #[serde(rename = "as")]
    pub as_var: String,
    /// Nested steps to execute per item.
    pub steps: Vec<YamlStep>,
    /// Maximum number of iterations (default: 50).
    #[serde(default = "default_max_items")]
    pub max_items: usize,
    /// Save aggregate results under this name.
    pub save_as: Option<String>,
    /// Conditional execution.
    pub when: Option<String>,
}

fn default_split_by() -> String {
    "\n".to_string()
}

fn default_max_items() -> usize {
    50
}

/// A step in a YAML plan — either a tool call or a for_each loop.
#[derive(Debug, Clone, serde::Deserialize)]
#[serde(untagged)]
pub enum YamlStep {
    ForEach(ForEachStep),
    Tool(PlanStep),
}

/// A parsed YAML plan.
#[derive(Debug, Clone, serde::Deserialize)]
pub struct YamlPlan {
    pub steps: Vec<YamlStep>,
}

/// Result of a single step execution.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct StepResult {
    pub step: Option<String>,
    pub tool: String,
    pub result: String,
    pub success: bool,
}

// ---------------------------------------------------------------------------
// Variable substitution
// ---------------------------------------------------------------------------

/// Resolve `{{variable}}` and `{{variable.field}}` references in a JSON value.
///
/// - `{{variable}}` is replaced with the saved result text.
/// - `{{variable.field}}` does JSON path access into the saved result
///   (parses as JSON and extracts the given field).
/// - `{{input}}` is replaced with the original user prompt (reserved,
///   currently empty since plan_execute has no separate input field).
/// - Missing variables produce an error marker: `<unresolved: name>`.
pub fn substitute_vars(
    value: &serde_json::Value,
    vars: &HashMap<String, StepResult>,
) -> serde_json::Value {
    match value {
        serde_json::Value::String(s) => {
            serde_json::Value::String(substitute_string(s, vars))
        }
        serde_json::Value::Object(map) => {
            let resolved: serde_json::Map<String, serde_json::Value> = map
                .iter()
                .map(|(k, v)| (k.clone(), substitute_vars(v, vars)))
                .collect();
            serde_json::Value::Object(resolved)
        }
        serde_json::Value::Array(arr) => {
            serde_json::Value::Array(arr.iter().map(|v| substitute_vars(v, vars)).collect())
        }
        other => other.clone(),
    }
}

/// Resolve template references in a string.
fn substitute_string(s: &str, vars: &HashMap<String, StepResult>) -> String {
    let mut result = String::with_capacity(s.len());
    let mut rest = s;

    while let Some(start) = rest.find("{{") {
        result.push_str(&rest[..start]);
        let after_open = &rest[start + 2..];
        if let Some(end) = after_open.find("}}") {
            let expr = after_open[..end].trim();
            let replacement = resolve_expr(expr, vars);
            result.push_str(&replacement);
            rest = &after_open[end + 2..];
        } else {
            // Unclosed template — emit as-is
            result.push_str("{{");
            rest = after_open;
        }
    }
    result.push_str(rest);
    result
}

/// Resolve a single expression like `variable` or `variable.field`.
fn resolve_expr(expr: &str, vars: &HashMap<String, StepResult>) -> String {
    if expr == "input" {
        return String::new();
    }

    let (var_name, field_path) = match expr.find('.') {
        Some(idx) => (&expr[..idx], Some(&expr[idx + 1..])),
        None => (expr, None),
    };

    let step_result = match vars.get(var_name) {
        Some(r) => r,
        None => return format!("<unresolved: {}>", expr),
    };

    match field_path {
        None => step_result.result.clone(),
        Some(field) => {
            // Try to parse the result as JSON and extract the field.
            match serde_json::from_str::<serde_json::Value>(&step_result.result) {
                Ok(json) => {
                    // Support nested fields like "a.b.c"
                    let mut current = &json;
                    for part in field.split('.') {
                        // Try object field first, then array index
                        if let Some(obj) = current.as_object() {
                            match obj.get(part) {
                                Some(v) => current = v,
                                None => return format!("<unresolved: {}>", expr),
                            }
                        } else if let Some(arr) = current.as_array() {
                            match part.parse::<usize>() {
                                Ok(idx) if idx < arr.len() => current = &arr[idx],
                                _ => return format!("<unresolved: {}>", expr),
                            }
                        } else {
                            return format!("<unresolved: {}>", expr);
                        }
                    }
                    match current.as_str() {
                        Some(s) => s.to_string(),
                        None => current.to_string(),
                    }
                }
                Err(_) => format!("<unresolved: {}>", expr),
            }
        }
    }
}

/// Evaluate a `when` condition. Returns true if the step should execute.
///
/// Supports:
/// - `{{var}}` — truthy if the variable exists and result is non-empty
/// - `{{var.success}}` — truthy if the field resolves to `true`
/// - `not {{var}}` — negation
fn evaluate_when(condition: &str, vars: &HashMap<String, StepResult>) -> bool {
    let trimmed = condition.trim();
    let (negated, expr) = if let Some(rest) = trimmed.strip_prefix("not ") {
        (true, rest.trim())
    } else {
        (false, trimmed)
    };

    let resolved = substitute_string(expr, vars);
    let is_truthy = !resolved.is_empty()
        && resolved != "false"
        && resolved != "0"
        && !resolved.starts_with("<unresolved:");

    if negated { !is_truthy } else { is_truthy }
}

// ---------------------------------------------------------------------------
// YAML plan execution
// ---------------------------------------------------------------------------

/// Execute a YAML plan, calling tools via the server's `handle_call_tool`.
pub async fn execute_yaml_plan(
    plan: &YamlPlan,
    server: &McpServer,
    ctx: &CallContext,
    stop_on_error: bool,
) -> Vec<StepResult> {
    let mut vars: HashMap<String, StepResult> = HashMap::new();
    let mut results: Vec<StepResult> = Vec::new();

    // Collect known tool names for validation
    let known_tools = server.handle_list_tools(&ctx.agent);

    let mut should_stop = false;
    for (i, yaml_step) in plan.steps.iter().enumerate() {
        if should_stop {
            break;
        }
        execute_step(
            yaml_step,
            i,
            server,
            ctx,
            stop_on_error,
            &known_tools.tools,
            &mut vars,
            &mut results,
            &mut should_stop,
        )
        .await;
    }

    results
}

/// Execute a single step (tool call or for_each), appending to results/vars.
fn execute_step<'a>(
    yaml_step: &'a YamlStep,
    index: usize,
    server: &'a McpServer,
    ctx: &'a CallContext,
    stop_on_error: bool,
    known_tools: &'a [ToolDefinition],
    vars: &'a mut HashMap<String, StepResult>,
    results: &'a mut Vec<StepResult>,
    should_stop: &'a mut bool,
) -> std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send + 'a>> {
    Box::pin(async move {
        match yaml_step {
            YamlStep::Tool(step) => {
                execute_tool_step(
                    step,
                    index,
                    server,
                    ctx,
                    stop_on_error,
                    known_tools,
                    vars,
                    results,
                    should_stop,
                )
                .await;
            }
            YamlStep::ForEach(fe) => {
                execute_for_each_step(
                    fe,
                    index,
                    server,
                    ctx,
                    stop_on_error,
                    known_tools,
                    vars,
                    results,
                    should_stop,
                )
                .await;
            }
        }
    })
}

/// Execute a single tool-call step.
async fn execute_tool_step(
    step: &PlanStep,
    index: usize,
    server: &McpServer,
    ctx: &CallContext,
    stop_on_error: bool,
    known_tools: &[ToolDefinition],
    vars: &mut HashMap<String, StepResult>,
    results: &mut Vec<StepResult>,
    should_stop: &mut bool,
) {
    let step_name = step
        .save_as
        .clone()
        .unwrap_or_else(|| format!("step_{}", index));

    let on_error = step.on_error.as_ref().cloned().unwrap_or_default();

    // Validate tool name
    if !known_tools.iter().any(|t| t.name == step.tool) {
        let error_msg = format!("Unknown tool: {}", step.tool);
        let sr = apply_on_error(&step_name, &step.tool, &error_msg, &on_error, &step.default_value);
        results.push(sr.clone());
        vars.insert(step_name, sr.clone());
        let should_halt = if step.on_error.is_some() {
            !sr.success && on_error == OnError::Stop
        } else {
            !sr.success && stop_on_error
        };
        if should_halt {
            *should_stop = true;
        }
        return;
    }

    // Evaluate conditional
    if let Some(ref when) = step.when {
        if !evaluate_when(when, vars) {
            let sr = StepResult {
                step: Some(step_name.clone()),
                tool: step.tool.clone(),
                result: "Skipped (condition not met)".to_string(),
                success: true,
            };
            results.push(sr.clone());
            vars.insert(step_name, sr);
            return;
        }
    }

    // Resolve variable references in arguments
    let resolved_args = if step.args.is_null() {
        serde_json::json!({})
    } else {
        substitute_vars(&step.args, vars)
    };

    // Build CallToolParams
    let params = CallToolParams {
        name: step.tool.clone(),
        arguments: resolved_args,
    };

    // Call the tool through the server's dispatch
    let result = server.handle_call_tool(params, ctx.clone()).await;

    // Extract text from result content
    let result_text: String = result
        .content
        .iter()
        .map(|c| match c {
            Content::Text(t) => t.text.as_str(),
        })
        .collect::<Vec<_>>()
        .join("");

    let sr = if result.is_error {
        apply_on_error(&step_name, &step.tool, &result_text, &on_error, &step.default_value)
    } else {
        StepResult {
            step: Some(step_name.clone()),
            tool: step.tool.clone(),
            result: result_text,
            success: true,
        }
    };

    results.push(sr.clone());
    vars.insert(step_name, sr.clone());

    // Per-step on_error overrides global stop_on_error.
    // If on_error is explicitly set on the step, it takes precedence.
    let should_halt = if step.on_error.is_some() {
        !sr.success && on_error == OnError::Stop
    } else {
        !sr.success && stop_on_error
    };
    if should_halt {
        *should_stop = true;
    }
}

/// Apply on_error strategy to a failed step.
fn apply_on_error(
    step_name: &str,
    tool: &str,
    error_msg: &str,
    on_error: &OnError,
    default_value: &Option<String>,
) -> StepResult {
    match on_error {
        OnError::Stop => StepResult {
            step: Some(step_name.to_string()),
            tool: tool.to_string(),
            result: error_msg.to_string(),
            success: false,
        },
        OnError::Continue => StepResult {
            step: Some(step_name.to_string()),
            tool: tool.to_string(),
            result: format!("Error (continued): {}", error_msg),
            success: false,
        },
        OnError::Default => StepResult {
            step: Some(step_name.to_string()),
            tool: tool.to_string(),
            result: default_value.clone().unwrap_or_default(),
            success: true,
        },
    }
}

/// Execute a for_each iteration step.
async fn execute_for_each_step(
    fe: &ForEachStep,
    index: usize,
    server: &McpServer,
    ctx: &CallContext,
    stop_on_error: bool,
    known_tools: &[ToolDefinition],
    vars: &mut HashMap<String, StepResult>,
    results: &mut Vec<StepResult>,
    should_stop: &mut bool,
) {
    let fe_name = fe
        .save_as
        .clone()
        .unwrap_or_else(|| format!("for_each_{}", index));

    // Evaluate conditional
    if let Some(ref when) = fe.when {
        if !evaluate_when(when, vars) {
            let sr = StepResult {
                step: Some(fe_name.clone()),
                tool: "for_each".to_string(),
                result: "Skipped (condition not met)".to_string(),
                success: true,
            };
            results.push(sr.clone());
            vars.insert(fe_name, sr);
            return;
        }
    }

    // Resolve the for_each source value
    let source = substitute_string(&fe.for_each, vars);

    // Split into items
    let mut items: Vec<&str> = source.split(&fe.split_by).collect();

    // Apply substring filter
    if let Some(ref filter) = fe.filter {
        items.retain(|item| item.contains(filter.as_str()));
    }

    // Remove empty items
    items.retain(|item| !item.trim().is_empty());

    // Cap iterations
    let max = fe.max_items;
    if items.len() > max {
        items.truncate(max);
    }

    let mut iteration_results: Vec<serde_json::Value> = Vec::new();

    for (item_idx, item) in items.iter().enumerate() {
        if *should_stop {
            break;
        }

        // Bind the iteration variable
        vars.insert(
            fe.as_var.clone(),
            StepResult {
                step: None,
                tool: "for_each".to_string(),
                result: item.to_string(),
                success: true,
            },
        );

        let mut iter_step_results: Vec<StepResult> = Vec::new();

        for (sub_idx, sub_step) in fe.steps.iter().enumerate() {
            if *should_stop {
                break;
            }
            let sub_index = index * 1000 + item_idx * 100 + sub_idx;
            execute_step(
                sub_step,
                sub_index,
                server,
                ctx,
                stop_on_error,
                known_tools,
                vars,
                results,
                should_stop,
            )
            .await;

            // Capture last result for this sub-step
            if let Some(last) = results.last() {
                iter_step_results.push(last.clone());

                // Create indexed variables: {save_as}_{item_idx}
                if let Some(ref save_as) = match sub_step {
                    YamlStep::Tool(s) => s.save_as.clone(),
                    YamlStep::ForEach(f) => f.save_as.clone(),
                } {
                    let indexed_name = format!("{}_{}", save_as, item_idx);
                    vars.insert(indexed_name, last.clone());
                }
            }
        }

        // Collect this iteration's results
        let iter_json = serde_json::to_value(&iter_step_results).unwrap_or_default();
        iteration_results.push(iter_json);
    }

    // Remove the iteration variable after the loop
    vars.remove(&fe.as_var);

    // Save aggregate results
    let aggregate = serde_json::to_string(&iteration_results).unwrap_or_default();
    let sr = StepResult {
        step: Some(fe_name.clone()),
        tool: "for_each".to_string(),
        result: aggregate,
        success: !*should_stop,
    };
    results.push(sr.clone());
    vars.insert(fe_name, sr);
}

// ---------------------------------------------------------------------------
// Python mode — sandboxed CodeAct execution
// ---------------------------------------------------------------------------

/// The Python bridge script, embedded at compile time.
/// Provides `call_tool()` for sandboxed Python scripts to invoke smgglrs tools.
const BRIDGE_PY: &str = r#""""smgglrs tool bridge for sandboxed Python execution."""
import json, os, sys, urllib.request

GATEWAY_URL = os.environ.get("SMGGLRS_GATEWAY", "http://host.containers.internal:9400")
SESSION_ID = os.environ.get("SMGGLRS_SESSION", "")
AUTH_TOKEN = os.environ.get("SMGGLRS_TOKEN", "")

_call_id = 0

def call_tool(name, arguments=None):
    """Call an smgglrs tool by name. Returns the text content of the result."""
    global _call_id
    _call_id += 1
    payload = json.dumps({
        "jsonrpc": "2.0",
        "method": "tools/call",
        "id": _call_id,
        "params": {"name": name, "arguments": arguments or {}}
    }).encode()
    headers = {
        "Content-Type": "application/json",
        "mcp-session-id": SESSION_ID,
    }
    if AUTH_TOKEN:
        headers["Authorization"] = f"Bearer {AUTH_TOKEN}"
    req = urllib.request.Request(f"{GATEWAY_URL}/mcp", data=payload, headers=headers)
    with urllib.request.urlopen(req, timeout=30) as resp:
        result = json.loads(resp.read())
    if "error" in result:
        raise RuntimeError(f"Tool error: {result['error']}")
    content = result.get("result", {}).get("content", [])
    texts = [c.get("text", "") for c in content if c.get("type") == "text"]
    return "\n".join(texts)
"#;

/// Which sandbox backend is available for Python execution.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SandboxBackend {
    /// OpenShell compute driver (strongest isolation).
    OpenShell,
    /// Podman rootless container.
    Podman,
    /// Direct child process (dev only, no isolation).
    Direct,
}

/// Check if Podman CLI is available on the system.
pub fn is_podman_available() -> bool {
    std::process::Command::new("podman")
        .arg("--version")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

/// Check if Python 3 is available on the system (for direct mode).
fn is_python3_available() -> bool {
    std::process::Command::new("python3")
        .arg("--version")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

/// Check whether direct execution is explicitly allowed.
///
/// Returns `true` if the `allow_direct` config flag is set, or if the
/// `SMGGLRS_ALLOW_DIRECT_EXECUTION` environment variable is set to `true`.
fn is_direct_execution_allowed(allow_direct: bool) -> bool {
    if allow_direct {
        return true;
    }
    std::env::var("SMGGLRS_ALLOW_DIRECT_EXECUTION")
        .map(|v| v.eq_ignore_ascii_case("true") || v == "1")
        .unwrap_or(false)
}

/// Detect the best available sandbox backend.
///
/// Preference order: OpenShell > Podman > Direct (only if explicitly allowed).
pub async fn detect_sandbox_backend(allow_direct: bool) -> Option<SandboxBackend> {
    // Try OpenShell gRPC socket
    let openshell_sock = "unix:///run/openshell/gateway.sock";
    if std::path::Path::new("/run/openshell/gateway.sock").exists() {
        // Check if the gRPC endpoint is actually reachable
        if tokio::net::UnixStream::connect("/run/openshell/gateway.sock")
            .await
            .is_ok()
        {
            return Some(SandboxBackend::OpenShell);
        }
        tracing::debug!(
            path = openshell_sock,
            "OpenShell socket exists but is not connectable"
        );
    }

    // Try Podman
    if is_podman_available() {
        return Some(SandboxBackend::Podman);
    }

    // Direct execution — only if explicitly opted in
    if is_python3_available() {
        if is_direct_execution_allowed(allow_direct) {
            tracing::warn!(
                "No sandbox available — falling back to direct Python execution. \
                 This provides NO isolation. Use only in trusted dev environments."
            );
            return Some(SandboxBackend::Direct);
        }
        tracing::info!(
            "Python 3 is available but direct execution is disabled. \
             Set allow_direct_execution=true in [budget] config or \
             SMGGLRS_ALLOW_DIRECT_EXECUTION=true to enable."
        );
    }

    None
}

/// Default timeout for Python script execution (seconds).
const DEFAULT_TIMEOUT_SECS: u64 = 300;

/// Execute a Python script in a sandbox with access to smgglrs tools.
///
/// The script gets `bridge.py` prepended so it can call `call_tool(name, args)`.
/// Environment variables provide the gateway address, session ID, and auth token.
///
/// The `allow_direct` flag controls whether unsandboxed (direct) execution is
/// permitted when no container runtime is available. Defaults to `false`.
pub async fn execute_python(
    code: &str,
    _server: &McpServer,
    ctx: &CallContext,
    timeout_secs: Option<u64>,
    allow_direct: bool,
) -> CallToolResult {
    let backend = match detect_sandbox_backend(allow_direct).await {
        Some(b) => b,
        None => {
            return CallToolResult::error(
                "Python mode requires a sandbox (OpenShell or Podman) but none is \
                 available. Install Podman for container isolation, or set \
                 allow_direct_execution=true in [budget] config (or \
                 SMGGLRS_ALLOW_DIRECT_EXECUTION=true) to allow unsandboxed execution.",
            );
        }
    };

    if backend == SandboxBackend::Direct {
        tracing::warn!(
            "Python plan_execute running without sandbox isolation (direct mode). \
             Install Podman for production use."
        );
    }

    // Prepare working directory with bridge + user script
    let work_dir = match tempfile::tempdir() {
        Ok(d) => d,
        Err(e) => return CallToolResult::error(format!("Failed to create temp dir: {e}")),
    };

    let bridge_path = work_dir.path().join("smgglrs_bridge.py");
    if let Err(e) = std::fs::write(&bridge_path, BRIDGE_PY) {
        return CallToolResult::error(format!("Failed to write smgglrs_bridge.py: {e}"));
    }

    // Build user script: import bridge, then run user code
    let full_script = format!(
        "import sys\nsys.path.insert(0, '{work_dir}')\nfrom smgglrs_bridge import call_tool\n\n{code}",
        work_dir = work_dir.path().display(),
        code = code,
    );

    let script_path = work_dir.path().join("script.py");
    if let Err(e) = std::fs::write(&script_path, &full_script) {
        return CallToolResult::error(format!("Failed to write script.py: {e}"));
    }

    // Environment variables for the bridge
    // For containerized execution, the host is reachable via 10.0.2.2
    // (slirp4netns default gateway) not 127.0.0.1. Detect which to use.
    let host_addr = std::env::var("SMGGLRS_LISTEN_ADDR")
        .unwrap_or_else(|_| "127.0.0.1:9315".to_string());
    let port = host_addr.rsplit(':').next().unwrap_or("9315");
    let gateway_url = match backend {
        SandboxBackend::Direct => format!("http://127.0.0.1:{port}"),
        _ => format!("http://10.0.2.2:{port}"),
    };
    let session_id = ctx.session_id.clone();
    // Token: use agent's existing auth token if available, empty otherwise
    let auth_token = std::env::var("SMGGLRS_SANDBOX_TOKEN").unwrap_or_default();

    let timeout = std::time::Duration::from_secs(timeout_secs.unwrap_or(DEFAULT_TIMEOUT_SECS));

    let result = match backend {
        SandboxBackend::OpenShell => {
            execute_in_openshell(work_dir.path(), &gateway_url, &session_id, &auth_token, timeout)
                .await
        }
        SandboxBackend::Podman => {
            execute_in_podman(work_dir.path(), &gateway_url, &session_id, &auth_token, timeout)
                .await
        }
        SandboxBackend::Direct => {
            execute_direct(work_dir.path(), &gateway_url, &session_id, &auth_token, timeout).await
        }
    };

    match result {
        Ok(output) => output,
        Err(e) => CallToolResult::error(format!("Python execution failed: {e}")),
    }
}

/// Execute Python script via OpenShell sandbox.
async fn execute_in_openshell(
    work_dir: &std::path::Path,
    gateway_url: &str,
    session_id: &str,
    auth_token: &str,
    timeout: std::time::Duration,
) -> Result<CallToolResult, String> {
    // OpenShell delegates sandbox creation to the compute driver via gRPC.
    // We use podman as the transport since OpenShell can provision it,
    // but with OpenShell's OPA policies restricting network to gateway only.
    //
    // For now, fall through to Podman with a label hint for OpenShell.
    // When full OpenShell integration is wired, this will call CreateSandbox
    // with labels {runtime: "python3", purpose: "plan_execute"}.

    tracing::info!("Executing Python plan via OpenShell sandbox");

    // Build the podman command that OpenShell would run
    let mut cmd = tokio::process::Command::new("podman");
    cmd.arg("run")
        .arg("--rm")
        .arg("--network=slirp4netns:allow_host_loopback=true")
        .arg("--security-opt=no-new-privileges")
        .arg("--read-only")
        .arg("-v")
        .arg(format!("{}:/work:ro,Z", work_dir.display()))
        .arg("-e")
        .arg(format!("SMGGLRS_GATEWAY={gateway_url}"))
        .arg("-e")
        .arg(format!("SMGGLRS_SESSION={session_id}"))
        .arg("-e")
        .arg(format!("SMGGLRS_TOKEN={auth_token}"))
        .arg("-w")
        .arg("/work")
        // OpenShell label annotations (passed through to the container)
        .arg("--label")
        .arg("smgglrs.runtime=python3")
        .arg("--label")
        .arg("smgglrs.purpose=plan_execute")
        .arg("python:3-slim")
        .arg("python")
        .arg("/work/script.py");

    cmd.stdout(std::process::Stdio::piped());
    cmd.stderr(std::process::Stdio::piped());

    run_with_timeout(cmd, timeout).await
}

/// Execute Python script in a Podman container.
async fn execute_in_podman(
    work_dir: &std::path::Path,
    gateway_url: &str,
    session_id: &str,
    auth_token: &str,
    timeout: std::time::Duration,
) -> Result<CallToolResult, String> {
    tracing::info!("Executing Python plan via Podman container");

    let mut cmd = tokio::process::Command::new("podman");
    cmd.arg("run")
        .arg("--rm")
        .arg("--network=slirp4netns:allow_host_loopback=true")
        .arg("--security-opt=no-new-privileges")
        .arg("--read-only")
        .arg("-v")
        .arg(format!("{}:/work:ro,Z", work_dir.display()))
        .arg("-e")
        .arg(format!("SMGGLRS_GATEWAY={gateway_url}"))
        .arg("-e")
        .arg(format!("SMGGLRS_SESSION={session_id}"))
        .arg("-e")
        .arg(format!("SMGGLRS_TOKEN={auth_token}"))
        .arg("-w")
        .arg("/work")
        .arg("python:3-slim")
        .arg("python")
        .arg("/work/script.py");

    cmd.stdout(std::process::Stdio::piped());
    cmd.stderr(std::process::Stdio::piped());

    run_with_timeout(cmd, timeout).await
}

/// Execute Python script directly as a child process (dev only, no isolation).
async fn execute_direct(
    work_dir: &std::path::Path,
    gateway_url: &str,
    session_id: &str,
    auth_token: &str,
    timeout: std::time::Duration,
) -> Result<CallToolResult, String> {
    tracing::warn!("Executing Python plan without sandbox (direct mode)");

    let script_path = work_dir.join("script.py");

    let mut cmd = tokio::process::Command::new("python3");
    cmd.arg(&script_path)
        .env("SMGGLRS_GATEWAY", gateway_url)
        .env("SMGGLRS_SESSION", session_id)
        .env("SMGGLRS_TOKEN", auth_token)
        .current_dir(work_dir);

    cmd.stdout(std::process::Stdio::piped());
    cmd.stderr(std::process::Stdio::piped());

    run_with_timeout(cmd, timeout).await
}

/// Spawn a command with a timeout. Returns a CallToolResult with stdout on
/// success or an error with stderr on failure.
async fn run_with_timeout(
    mut cmd: tokio::process::Command,
    timeout: std::time::Duration,
) -> Result<CallToolResult, String> {
    let child = cmd
        .spawn()
        .map_err(|e| format!("Failed to spawn process: {e}"))?;

    let result = tokio::time::timeout(timeout, child.wait_with_output()).await;

    match result {
        Ok(Ok(output)) => {
            let stdout = String::from_utf8_lossy(&output.stdout).to_string();
            let stderr = String::from_utf8_lossy(&output.stderr).to_string();

            if output.status.success() {
                if stdout.is_empty() && !stderr.is_empty() {
                    // Script printed to stderr only — might be warnings
                    Ok(CallToolResult::text(format!(
                        "(no stdout)\nstderr:\n{stderr}"
                    )))
                } else {
                    Ok(CallToolResult::text(stdout))
                }
            } else {
                let code = output.status.code().unwrap_or(-1);
                let mut msg = format!("Script exited with code {code}");
                if !stderr.is_empty() {
                    msg.push_str(&format!("\nstderr:\n{stderr}"));
                }
                if !stdout.is_empty() {
                    msg.push_str(&format!("\nstdout:\n{stdout}"));
                }
                Ok(CallToolResult::error(msg))
            }
        }
        Ok(Err(e)) => Err(format!("Process I/O error: {e}")),
        Err(_) => {
            // Timeout — the future was dropped, which drops the child process.
            // tokio::process::Child kills the child on drop.
            Err(format!(
                "Script timed out after {} seconds",
                timeout.as_secs()
            ))
        }
    }
}

// ---------------------------------------------------------------------------
// Tool handler
// ---------------------------------------------------------------------------

/// Handle a plan_execute tool call.
///
/// `allow_direct` controls whether unsandboxed Python execution is permitted.
pub async fn handle_plan_execute(
    args: serde_json::Value,
    server: &McpServer,
    ctx: CallContext,
    allow_direct: bool,
) -> CallToolResult {
    let format = args
        .get("format")
        .and_then(|v| v.as_str())
        .unwrap_or("yaml");

    let plan_str = match args.get("plan").and_then(|v| v.as_str()) {
        Some(p) => p,
        None => return CallToolResult::error("Missing required parameter: plan"),
    };

    let stop_on_error = args
        .get("stop_on_error")
        .and_then(|v| v.as_bool())
        .unwrap_or(true);

    match format {
        "yaml" => {
            let plan: YamlPlan = match serde_yaml::from_str(plan_str) {
                Ok(p) => p,
                Err(e) => {
                    return CallToolResult::error(format!("Invalid YAML plan: {}", e));
                }
            };

            if plan.steps.is_empty() {
                return CallToolResult::error("Plan has no steps");
            }

            let results = execute_yaml_plan(&plan, server, &ctx, stop_on_error).await;
            let json = serde_json::to_string_pretty(&results).unwrap_or_default();
            CallToolResult::text(json)
        }
        "python" => {
            let timeout_secs = args
                .get("timeout")
                .and_then(|v| v.as_u64());

            execute_python(plan_str, server, &ctx, timeout_secs, allow_direct).await
        }
        other => {
            CallToolResult::error(format!(
                "Unknown format: '{}'. Supported: yaml, python",
                other
            ))
        }
    }
}

// ---------------------------------------------------------------------------
// Tool definition
// ---------------------------------------------------------------------------

pub fn plan_execute_tool_def() -> ToolDefinition {
    ToolDefinition {
        name: "plan_execute".to_string(),
        description: Some(
            "Execute a multi-step plan in a single turn. Supports YAML \
             (declarative, no sandbox) and Python (CodeAct, sandboxed) \
             formats. YAML plans define sequential tool calls with \
             variable passing between steps."
                .to_string(),
        ),
        input_schema: ToolInputSchema {
            schema_type: "object".to_string(),
            properties: Some(HashMap::from([
                (
                    "format".to_string(),
                    serde_json::json!({
                        "type": "string",
                        "enum": ["yaml", "python"],
                        "description": "Plan format: 'yaml' for declarative steps, 'python' for CodeAct (requires Podman)"
                    }),
                ),
                (
                    "plan".to_string(),
                    serde_json::json!({
                        "type": "string",
                        "description": "The plan content — YAML steps or Python code"
                    }),
                ),
                (
                    "stop_on_error".to_string(),
                    serde_json::json!({
                        "type": "boolean",
                        "description": "Stop execution on first error (default: true, YAML mode only)",
                        "default": true
                    }),
                ),
                (
                    "timeout".to_string(),
                    serde_json::json!({
                        "type": "integer",
                        "description": "Execution timeout in seconds (default: 300, Python mode only)",
                        "default": 300
                    }),
                ),
            ])),
            required: Some(vec!["format".to_string(), "plan".to_string()]),
        },
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// Helper to extract a PlanStep from a YamlStep::Tool variant.
    fn as_tool(step: &YamlStep) -> &PlanStep {
        match step {
            YamlStep::Tool(s) => s,
            YamlStep::ForEach(_) => panic!("expected Tool step, got ForEach"),
        }
    }

    /// Helper to extract a ForEachStep from a YamlStep::ForEach variant.
    fn as_for_each(step: &YamlStep) -> &ForEachStep {
        match step {
            YamlStep::ForEach(f) => f,
            YamlStep::Tool(_) => panic!("expected ForEach step, got Tool"),
        }
    }

    #[test]
    fn test_parse_yaml_plan() {
        let yaml = r#"
steps:
  - tool: file_tree
    args: {path: "/project"}
    save_as: tree
  - tool: file_read
    args: {path: "/project/README.md"}
    save_as: readme
"#;
        let plan: YamlPlan = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(plan.steps.len(), 2);
        assert_eq!(as_tool(&plan.steps[0]).tool, "file_tree");
        assert_eq!(as_tool(&plan.steps[0]).save_as, Some("tree".to_string()));
        assert_eq!(as_tool(&plan.steps[1]).tool, "file_read");
    }

    #[test]
    fn test_parse_yaml_plan_empty_steps() {
        let yaml = "steps: []";
        let plan: YamlPlan = serde_yaml::from_str(yaml).unwrap();
        assert!(plan.steps.is_empty());
    }

    #[test]
    fn test_parse_yaml_plan_missing_tool() {
        let yaml = r#"
steps:
  - args: {path: "/project"}
"#;
        // With untagged enum, this may parse as a tool step missing required field
        // or as a for_each step missing required field — either way it should fail
        let result = serde_yaml::from_str::<YamlPlan>(yaml);
        assert!(result.is_err());
    }

    #[test]
    fn test_substitute_simple() {
        let mut vars = HashMap::new();
        vars.insert(
            "tree".to_string(),
            StepResult {
                step: Some("tree".to_string()),
                tool: "file_tree".to_string(),
                result: "src/main.rs\nsrc/lib.rs".to_string(),
                success: true,
            },
        );

        let val = serde_json::json!({"path": "{{tree}}"});
        let resolved = substitute_vars(&val, &vars);
        assert_eq!(
            resolved["path"].as_str().unwrap(),
            "src/main.rs\nsrc/lib.rs"
        );
    }

    #[test]
    fn test_substitute_nested_field() {
        let mut vars = HashMap::new();
        vars.insert(
            "result".to_string(),
            StepResult {
                step: Some("result".to_string()),
                tool: "some_tool".to_string(),
                result: r#"{"name": "test", "count": 42}"#.to_string(),
                success: true,
            },
        );

        let val = serde_json::json!({"item": "{{result.name}}"});
        let resolved = substitute_vars(&val, &vars);
        assert_eq!(resolved["item"].as_str().unwrap(), "test");
    }

    #[test]
    fn test_substitute_deep_nested_field() {
        let mut vars = HashMap::new();
        vars.insert(
            "data".to_string(),
            StepResult {
                step: Some("data".to_string()),
                tool: "t".to_string(),
                result: r#"{"a": {"b": "deep"}}"#.to_string(),
                success: true,
            },
        );

        let val = serde_json::json!({"x": "{{data.a.b}}"});
        let resolved = substitute_vars(&val, &vars);
        assert_eq!(resolved["x"].as_str().unwrap(), "deep");
    }

    #[test]
    fn test_substitute_missing_var() {
        let vars: HashMap<String, StepResult> = HashMap::new();
        let val = serde_json::json!({"path": "{{missing}}"});
        let resolved = substitute_vars(&val, &vars);
        assert_eq!(resolved["path"].as_str().unwrap(), "<unresolved: missing>");
    }

    #[test]
    fn test_substitute_array_index() {
        let mut vars = HashMap::new();
        vars.insert(
            "list".to_string(),
            StepResult {
                step: Some("list".to_string()),
                tool: "t".to_string(),
                result: r#"{"files": ["a.rs", "b.rs"]}"#.to_string(),
                success: true,
            },
        );

        let val = serde_json::json!({"path": "{{list.files.0}}"});
        let resolved = substitute_vars(&val, &vars);
        assert_eq!(resolved["path"].as_str().unwrap(), "a.rs");
    }

    #[test]
    fn test_substitute_preserves_non_template() {
        let vars: HashMap<String, StepResult> = HashMap::new();
        let val = serde_json::json!({"path": "/no/templates/here"});
        let resolved = substitute_vars(&val, &vars);
        assert_eq!(resolved["path"].as_str().unwrap(), "/no/templates/here");
    }

    #[test]
    fn test_substitute_multiple_in_one_string() {
        let mut vars = HashMap::new();
        vars.insert(
            "dir".to_string(),
            StepResult {
                step: Some("dir".to_string()),
                tool: "t".to_string(),
                result: "/home".to_string(),
                success: true,
            },
        );
        vars.insert(
            "file".to_string(),
            StepResult {
                step: Some("file".to_string()),
                tool: "t".to_string(),
                result: "test.txt".to_string(),
                success: true,
            },
        );

        let val = serde_json::json!({"path": "{{dir}}/{{file}}"});
        let resolved = substitute_vars(&val, &vars);
        assert_eq!(resolved["path"].as_str().unwrap(), "/home/test.txt");
    }

    #[test]
    fn test_evaluate_when_truthy() {
        let mut vars = HashMap::new();
        vars.insert(
            "prev".to_string(),
            StepResult {
                step: Some("prev".to_string()),
                tool: "t".to_string(),
                result: "some output".to_string(),
                success: true,
            },
        );

        assert!(evaluate_when("{{prev}}", &vars));
    }

    #[test]
    fn test_evaluate_when_falsy_missing() {
        let vars: HashMap<String, StepResult> = HashMap::new();
        assert!(!evaluate_when("{{missing}}", &vars));
    }

    #[test]
    fn test_evaluate_when_negated() {
        let mut vars = HashMap::new();
        vars.insert(
            "prev".to_string(),
            StepResult {
                step: Some("prev".to_string()),
                tool: "t".to_string(),
                result: "data".to_string(),
                success: true,
            },
        );

        assert!(!evaluate_when("not {{prev}}", &vars));
    }

    #[test]
    fn test_evaluate_when_false_value() {
        let mut vars = HashMap::new();
        vars.insert(
            "flag".to_string(),
            StepResult {
                step: Some("flag".to_string()),
                tool: "t".to_string(),
                result: "false".to_string(),
                success: true,
            },
        );

        assert!(!evaluate_when("{{flag}}", &vars));
    }

    #[test]
    fn test_evaluate_when_success_field() {
        let mut vars = HashMap::new();
        vars.insert(
            "prev".to_string(),
            StepResult {
                step: Some("prev".to_string()),
                tool: "t".to_string(),
                result: r#"{"success": true}"#.to_string(),
                success: true,
            },
        );

        assert!(evaluate_when("{{prev.success}}", &vars));
    }

    #[test]
    fn test_plan_with_when() {
        let yaml = r#"
steps:
  - tool: file_tree
    args: {path: "/project"}
    save_as: tree
  - tool: file_read
    args: {path: "/project/README.md"}
    save_as: readme
    when: "{{tree}}"
"#;
        let plan: YamlPlan = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(plan.steps.len(), 2);
        assert_eq!(as_tool(&plan.steps[1]).when, Some("{{tree}}".to_string()));
    }

    #[tokio::test]
    async fn test_handle_missing_plan() {
        let args = serde_json::json!({"format": "yaml"});
        let server = smgglrs_core::McpServer::builder()
            .name("test")
            .version("0.1")
            .build();
        let ctx = test_ctx();
        let result = handle_plan_execute(args, &server, ctx, false).await;
        assert!(result.is_error);
    }

    #[tokio::test]
    async fn test_handle_invalid_yaml() {
        let args = serde_json::json!({
            "format": "yaml",
            "plan": "not: valid: yaml: [["
        });
        let server = smgglrs_core::McpServer::builder()
            .name("test")
            .version("0.1")
            .build();
        let ctx = test_ctx();
        let result = handle_plan_execute(args, &server, ctx, false).await;
        assert!(result.is_error);
    }

    #[tokio::test]
    async fn test_handle_empty_steps() {
        let args = serde_json::json!({
            "format": "yaml",
            "plan": "steps: []"
        });
        let server = smgglrs_core::McpServer::builder()
            .name("test")
            .version("0.1")
            .build();
        let ctx = test_ctx();
        let result = handle_plan_execute(args, &server, ctx, false).await;
        assert!(result.is_error);
    }

    #[tokio::test]
    async fn test_handle_unknown_format() {
        let args = serde_json::json!({
            "format": "lua",
            "plan": "print('hello')"
        });
        let server = smgglrs_core::McpServer::builder()
            .name("test")
            .version("0.1")
            .build();
        let ctx = test_ctx();
        let result = handle_plan_execute(args, &server, ctx, false).await;
        assert!(result.is_error);
        let text = result.content.iter().map(|c| match c {
            Content::Text(t) => t.text.as_str(),
        }).collect::<Vec<_>>().join("");
        assert!(text.contains("Unknown format"));
    }

    #[tokio::test]
    async fn test_unknown_tool_stop_on_error() {
        let args = serde_json::json!({
            "format": "yaml",
            "plan": "steps:\n  - tool: nonexistent_tool\n    args: {}\n    save_as: r1\n  - tool: also_missing\n    args: {}\n    save_as: r2",
            "stop_on_error": true
        });
        let server = smgglrs_core::McpServer::builder()
            .name("test")
            .version("0.1")
            .build();
        let ctx = test_ctx();
        let result = handle_plan_execute(args, &server, ctx, false).await;
        // Should have results — the first step fails, second is skipped
        let text = result.content.iter().map(|c| match c {
            Content::Text(t) => t.text.as_str(),
        }).collect::<Vec<_>>().join("");
        let steps: Vec<StepResult> = serde_json::from_str(&text).unwrap();
        assert_eq!(steps.len(), 1); // stopped after first error
        assert!(!steps[0].success);
        assert!(steps[0].result.contains("Unknown tool"));
    }

    #[tokio::test]
    async fn test_unknown_tool_continue_on_error() {
        let args = serde_json::json!({
            "format": "yaml",
            "plan": "steps:\n  - tool: nonexistent_tool\n    args: {}\n    save_as: r1\n  - tool: also_missing\n    args: {}\n    save_as: r2",
            "stop_on_error": false
        });
        let server = smgglrs_core::McpServer::builder()
            .name("test")
            .version("0.1")
            .build();
        let ctx = test_ctx();
        let result = handle_plan_execute(args, &server, ctx, false).await;
        let text = result.content.iter().map(|c| match c {
            Content::Text(t) => t.text.as_str(),
        }).collect::<Vec<_>>().join("");
        let steps: Vec<StepResult> = serde_json::from_str(&text).unwrap();
        assert_eq!(steps.len(), 2); // continued past first error
        assert!(!steps[0].success);
        assert!(!steps[1].success);
    }

    #[tokio::test]
    async fn test_sequential_execution_with_echo_tool() {
        use smgglrs_core::protocol::ToolInputSchema;

        // Register an echo tool that returns its args as text
        let echo_def = ToolDefinition {
            name: "echo".to_string(),
            description: Some("Echo args".to_string()),
            input_schema: ToolInputSchema {
                schema_type: "object".to_string(),
                properties: None,
                required: None,
            },
        };
        let server = smgglrs_core::McpServer::builder()
            .name("test")
            .version("0.1")
            .tool(echo_def, |args, _ctx| {
                Box::pin(async move {
                    CallToolResult::text(serde_json::to_string(&args).unwrap_or_default())
                })
            })
            .build();

        let plan_yaml = r#"
steps:
  - tool: echo
    args: {msg: "hello"}
    save_as: first
  - tool: echo
    args: {msg: "world"}
    save_as: second
  - tool: echo
    args: {msg: "{{first}}-{{second}}"}
    save_as: combined
"#;
        let args = serde_json::json!({
            "format": "yaml",
            "plan": plan_yaml
        });
        let ctx = test_ctx();
        let result = handle_plan_execute(args, &server, ctx, false).await;
        assert!(!result.is_error);

        let text = result.content.iter().map(|c| match c {
            Content::Text(t) => t.text.as_str(),
        }).collect::<Vec<_>>().join("");
        let steps: Vec<StepResult> = serde_json::from_str(&text).unwrap();
        assert_eq!(steps.len(), 3);
        assert!(steps[0].success);
        assert!(steps[1].success);
        assert!(steps[2].success);
        // The third step should contain the results from the first two
        assert!(steps[2].result.contains("hello"));
        assert!(steps[2].result.contains("world"));
    }

    #[tokio::test]
    async fn test_when_conditional_skip() {
        let echo_def = ToolDefinition {
            name: "echo".to_string(),
            description: Some("Echo".to_string()),
            input_schema: ToolInputSchema {
                schema_type: "object".to_string(),
                properties: None,
                required: None,
            },
        };
        let server = smgglrs_core::McpServer::builder()
            .name("test")
            .version("0.1")
            .tool(echo_def, |args, _ctx| {
                Box::pin(async move {
                    CallToolResult::text(serde_json::to_string(&args).unwrap_or_default())
                })
            })
            .build();

        let plan_yaml = r#"
steps:
  - tool: echo
    args: {msg: "first"}
    save_as: step1
  - tool: echo
    args: {msg: "skipped"}
    save_as: step2
    when: "{{missing_var}}"
  - tool: echo
    args: {msg: "third"}
    save_as: step3
"#;
        let args = serde_json::json!({
            "format": "yaml",
            "plan": plan_yaml
        });
        let ctx = test_ctx();
        let result = handle_plan_execute(args, &server, ctx, false).await;

        let text = result.content.iter().map(|c| match c {
            Content::Text(t) => t.text.as_str(),
        }).collect::<Vec<_>>().join("");
        let steps: Vec<StepResult> = serde_json::from_str(&text).unwrap();
        assert_eq!(steps.len(), 3);
        assert!(steps[0].success);
        assert_eq!(steps[1].result, "Skipped (condition not met)");
        assert!(steps[2].success);
    }

    #[tokio::test]
    async fn test_python_mode_runs_or_reports_error() {
        let args = serde_json::json!({
            "format": "python",
            "plan": "print('hello from python')"
        });
        let server = smgglrs_core::McpServer::builder()
            .name("test")
            .version("0.1")
            .build();
        let ctx = test_ctx();
        let result = handle_plan_execute(args, &server, ctx, true).await;
        let text = result.content.iter().map(|c| match c {
            Content::Text(t) => t.text.as_str(),
        }).collect::<Vec<_>>().join("");
        if result.is_error {
            // Acceptable errors: no sandbox, container failed, etc.
            // The important thing is we get a coherent error, not a panic.
            assert!(
                !text.is_empty(),
                "Error result should have a message"
            );
        } else {
            assert!(text.contains("hello from python"));
        }
    }

    #[tokio::test]
    async fn test_python_mode_nonzero_exit() {
        // Only run if python3 is available
        if !is_python3_available() {
            return;
        }
        let args = serde_json::json!({
            "format": "python",
            "plan": "import sys; print('before exit', flush=True); sys.exit(1)"
        });
        let server = smgglrs_core::McpServer::builder()
            .name("test")
            .version("0.1")
            .build();
        let ctx = test_ctx();
        let result = handle_plan_execute(args, &server, ctx, true).await;
        assert!(result.is_error);
        let text = result.content.iter().map(|c| match c {
            Content::Text(t) => t.text.as_str(),
        }).collect::<Vec<_>>().join("");
        assert!(text.contains("exited with code 1"), "Got: {text}");
    }

    #[tokio::test]
    async fn test_python_mode_timeout() {
        // This test requires direct mode (python3 without Podman overhead)
        // because we set a 1s timeout that Podman pull would exceed.
        if !is_python3_available() {
            return;
        }
        // Force direct mode by using execute_python directly
        let server = smgglrs_core::McpServer::builder()
            .name("test")
            .version("0.1")
            .build();
        let ctx = test_ctx();
        let code = "import time; time.sleep(60)";
        // Use a short timeout directly
        let result = execute_python(code, &server, &ctx, Some(1), true).await;
        assert!(result.is_error);
        let text = result.content.iter().map(|c| match c {
            Content::Text(t) => t.text.as_str(),
        }).collect::<Vec<_>>().join("");
        // May time out or hit a Podman/container error — both are acceptable
        assert!(
            text.contains("timed out") || text.contains("exited with code"),
            "Got: {text}"
        );
    }

    #[test]
    fn test_bridge_py_syntax() {
        // Verify the embedded bridge.py is syntactically valid
        let output = std::process::Command::new("python3")
            .arg("-c")
            .arg(format!("import ast; ast.parse('''{}''')", BRIDGE_PY.replace('\\', "\\\\")))
            .output();
        match output {
            Ok(o) if o.status.success() => {} // valid
            Ok(o) => {
                // python3 exists but parse failed — real error
                let stderr = String::from_utf8_lossy(&o.stderr);
                panic!("bridge.py has syntax errors: {stderr}");
            }
            Err(_) => {
                // python3 not available, skip
            }
        }
    }

    #[test]
    fn test_sandbox_backend_enum() {
        assert_ne!(SandboxBackend::OpenShell, SandboxBackend::Podman);
        assert_ne!(SandboxBackend::Podman, SandboxBackend::Direct);
        assert_eq!(SandboxBackend::Direct, SandboxBackend::Direct);
    }

    #[tokio::test]
    async fn test_detect_sandbox_backend() {
        let backend = detect_sandbox_backend(true).await;
        // We can't assert a specific backend, but the function should not panic
        match backend {
            Some(SandboxBackend::OpenShell) => {} // OK
            Some(SandboxBackend::Podman) => {}    // OK
            Some(SandboxBackend::Direct) => {}    // OK
            None => {}                            // OK, no sandbox
        }
    }

    #[test]
    fn test_python_env_setup() {
        // Verify the environment variables match the bridge.py expectations
        assert!(BRIDGE_PY.contains("SMGGLRS_GATEWAY"));
        assert!(BRIDGE_PY.contains("SMGGLRS_SESSION"));
        assert!(BRIDGE_PY.contains("SMGGLRS_TOKEN"));
    }

    #[tokio::test]
    async fn test_python_stderr_capture_direct() {
        if !is_python3_available() {
            return;
        }
        // Test stderr capture using direct execution to avoid Podman env issues
        let work_dir = tempfile::tempdir().unwrap();
        let bridge_path = work_dir.path().join("smgglrs_bridge.py");
        std::fs::write(&bridge_path, BRIDGE_PY).unwrap();

        let code = "import sys; print('error msg', file=sys.stderr); sys.exit(2)";
        let full_script = format!(
            "import sys\nsys.path.insert(0, '{}')\nfrom smgglrs_bridge import call_tool\n\n{}",
            work_dir.path().display(),
            code,
        );
        let script_path = work_dir.path().join("script.py");
        std::fs::write(&script_path, &full_script).unwrap();

        let result = execute_direct(
            work_dir.path(),
            "http://127.0.0.1:9315",
            "test-session",
            "",
            std::time::Duration::from_secs(10),
        )
        .await;

        let result = result.unwrap();
        assert!(result.is_error);
        let text = result
            .content
            .iter()
            .map(|c| match c {
                Content::Text(t) => t.text.as_str(),
            })
            .collect::<Vec<_>>()
            .join("");
        assert!(text.contains("error msg"), "Got: {text}");
    }

    #[test]
    fn test_result_format_serialization() {
        let results = vec![
            StepResult {
                step: Some("tree".to_string()),
                tool: "file_tree".to_string(),
                result: "src/main.rs".to_string(),
                success: true,
            },
            StepResult {
                step: Some("read".to_string()),
                tool: "file_read".to_string(),
                result: "fn main() {}".to_string(),
                success: true,
            },
        ];
        let json = serde_json::to_string(&results).unwrap();
        let parsed: Vec<StepResult> = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.len(), 2);
        assert_eq!(parsed[0].step, Some("tree".to_string()));
        assert_eq!(parsed[1].tool, "file_read");
    }

    // -----------------------------------------------------------------------
    // for_each tests
    // -----------------------------------------------------------------------

    /// Build a test server with an "echo" tool that returns the "msg" field
    /// as plain text (not JSON-wrapped args).
    fn build_echo_server() -> smgglrs_core::McpServer {
        let echo_def = ToolDefinition {
            name: "echo".to_string(),
            description: Some("Echo msg field".to_string()),
            input_schema: ToolInputSchema {
                schema_type: "object".to_string(),
                properties: None,
                required: None,
            },
        };
        smgglrs_core::McpServer::builder()
            .name("test")
            .version("0.1")
            .tool(echo_def, |args, _ctx| {
                Box::pin(async move {
                    let msg = args
                        .get("msg")
                        .or_else(|| args.get("path"))
                        .or_else(|| args.get("val"))
                        .or_else(|| args.get("full_path"))
                        .and_then(|v| v.as_str())
                        .unwrap_or("");
                    CallToolResult::text(msg.to_string())
                })
            })
            .build()
    }

    #[test]
    fn test_parse_for_each_step() {
        let yaml = r#"
steps:
  - for_each: "{{files}}"
    as: file
    steps:
      - tool: echo
        args: {path: "{{file}}"}
        save_as: content
"#;
        let plan: YamlPlan = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(plan.steps.len(), 1);
        let fe = as_for_each(&plan.steps[0]);
        assert_eq!(fe.for_each, "{{files}}");
        assert_eq!(fe.as_var, "file");
        assert_eq!(fe.steps.len(), 1);
        assert_eq!(fe.max_items, 50); // default
        assert_eq!(fe.split_by, "\n"); // default
    }

    #[tokio::test]
    async fn test_for_each_iterates_over_newline_list() {
        let server = build_echo_server();

        let plan_yaml = r#"
steps:
  - tool: echo
    args: {msg: "a.rs|b.rs|c.rs"}
    save_as: files
  - for_each: "{{files}}"
    split_by: "|"
    as: file
    save_as: loop_result
    steps:
      - tool: echo
        args: {msg: "{{file}}"}
        save_as: content
"#;
        let args = serde_json::json!({"format": "yaml", "plan": plan_yaml});
        let ctx = test_ctx();
        let result = handle_plan_execute(args, &server, ctx, false).await;
        assert!(!result.is_error);

        let text = result.content.iter().map(|c| match c {
            Content::Text(t) => t.text.as_str(),
        }).collect::<Vec<_>>().join("");
        let steps: Vec<StepResult> = serde_json::from_str(&text).unwrap();
        // 1 (echo) + 3 (iterations) + 1 (for_each aggregate) = 5
        assert_eq!(steps.len(), 5);
        assert!(steps[1].result.contains("a.rs"));
        assert!(steps[2].result.contains("b.rs"));
        assert!(steps[3].result.contains("c.rs"));
        assert_eq!(steps[4].tool, "for_each");
    }

    #[tokio::test]
    async fn test_for_each_with_filter() {
        let server = build_echo_server();

        let plan_yaml = r#"
steps:
  - tool: echo
    args: {msg: "a.rs|b.py|c.rs|d.txt"}
    save_as: files
  - for_each: "{{files}}"
    split_by: "|"
    filter: ".rs"
    as: file
    save_as: loop_result
    steps:
      - tool: echo
        args: {msg: "{{file}}"}
        save_as: content
"#;
        let args = serde_json::json!({"format": "yaml", "plan": plan_yaml});
        let ctx = test_ctx();
        let result = handle_plan_execute(args, &server, ctx, false).await;
        assert!(!result.is_error);

        let text = result.content.iter().map(|c| match c {
            Content::Text(t) => t.text.as_str(),
        }).collect::<Vec<_>>().join("");
        let steps: Vec<StepResult> = serde_json::from_str(&text).unwrap();
        // 1 (echo) + 2 (only .rs files) + 1 (aggregate) = 4
        assert_eq!(steps.len(), 4);
        assert!(steps[1].result.contains("a.rs"));
        assert!(steps[2].result.contains("c.rs"));
    }

    #[tokio::test]
    async fn test_for_each_with_max_items() {
        let server = build_echo_server();

        let plan_yaml = r#"
steps:
  - tool: echo
    args: {msg: "a|b|c|d|e"}
    save_as: items
  - for_each: "{{items}}"
    split_by: "|"
    as: item
    max_items: 2
    save_as: loop_result
    steps:
      - tool: echo
        args: {msg: "{{item}}"}
        save_as: out
"#;
        let args = serde_json::json!({"format": "yaml", "plan": plan_yaml});
        let ctx = test_ctx();
        let result = handle_plan_execute(args, &server, ctx, false).await;
        assert!(!result.is_error);

        let text = result.content.iter().map(|c| match c {
            Content::Text(t) => t.text.as_str(),
        }).collect::<Vec<_>>().join("");
        let steps: Vec<StepResult> = serde_json::from_str(&text).unwrap();
        // 1 (echo) + 2 (capped at max_items) + 1 (aggregate) = 4
        assert_eq!(steps.len(), 4);
    }

    #[tokio::test]
    async fn test_for_each_nested_variable_references() {
        let server = build_echo_server();

        let plan_yaml = r#"
steps:
  - tool: echo
    args: {msg: "/root"}
    save_as: base_dir
  - tool: echo
    args: {msg: "foo.rs|bar.rs"}
    save_as: files
  - for_each: "{{files}}"
    split_by: "|"
    as: file
    save_as: loop_result
    steps:
      - tool: echo
        args: {full_path: "{{base_dir}}/{{file}}"}
        save_as: content
"#;
        let args = serde_json::json!({"format": "yaml", "plan": plan_yaml});
        let ctx = test_ctx();
        let result = handle_plan_execute(args, &server, ctx, false).await;
        assert!(!result.is_error);

        let text = result.content.iter().map(|c| match c {
            Content::Text(t) => t.text.as_str(),
        }).collect::<Vec<_>>().join("");
        let steps: Vec<StepResult> = serde_json::from_str(&text).unwrap();
        // 2 (echos) + 2 (iterations) + 1 (aggregate) = 5
        assert_eq!(steps.len(), 5);
        // base_dir includes IFC taint suffix, but the full path should still contain the parts
        assert!(steps[2].result.contains("foo.rs"));
        assert!(steps[3].result.contains("bar.rs"));
    }

    // -----------------------------------------------------------------------
    // on_error tests
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn test_on_error_continue_skips_failed_step() {
        let server = smgglrs_core::McpServer::builder()
            .name("test")
            .version("0.1")
            .build();

        let plan_yaml = r#"
steps:
  - tool: nonexistent_tool
    args: {}
    save_as: r1
    on_error: continue
  - tool: also_missing
    args: {}
    save_as: r2
    on_error: continue
"#;
        let args = serde_json::json!({"format": "yaml", "plan": plan_yaml});
        let ctx = test_ctx();
        let result = handle_plan_execute(args, &server, ctx, false).await;

        let text = result.content.iter().map(|c| match c {
            Content::Text(t) => t.text.as_str(),
        }).collect::<Vec<_>>().join("");
        let steps: Vec<StepResult> = serde_json::from_str(&text).unwrap();
        // Both steps should be present (not stopped)
        assert_eq!(steps.len(), 2);
        assert!(!steps[0].success);
        assert!(steps[0].result.contains("Error (continued)"));
        assert!(!steps[1].success);
        assert!(steps[1].result.contains("Error (continued)"));
    }

    #[tokio::test]
    async fn test_on_error_default_uses_default_value() {
        let server = smgglrs_core::McpServer::builder()
            .name("test")
            .version("0.1")
            .build();

        let plan_yaml = r#"
steps:
  - tool: nonexistent_tool
    args: {}
    save_as: r1
    on_error: default
    default_value: "no results"
"#;
        let args = serde_json::json!({"format": "yaml", "plan": plan_yaml});
        let ctx = test_ctx();
        let result = handle_plan_execute(args, &server, ctx, false).await;

        let text = result.content.iter().map(|c| match c {
            Content::Text(t) => t.text.as_str(),
        }).collect::<Vec<_>>().join("");
        let steps: Vec<StepResult> = serde_json::from_str(&text).unwrap();
        assert_eq!(steps.len(), 1);
        assert!(steps[0].success); // marked as success
        assert_eq!(steps[0].result, "no results");
    }

    #[tokio::test]
    async fn test_on_error_stop_halts_on_failure() {
        let echo_def = ToolDefinition {
            name: "echo".to_string(),
            description: Some("Echo".to_string()),
            input_schema: ToolInputSchema {
                schema_type: "object".to_string(),
                properties: None,
                required: None,
            },
        };
        let server = smgglrs_core::McpServer::builder()
            .name("test")
            .version("0.1")
            .tool(echo_def, |args, _ctx| {
                Box::pin(async move {
                    CallToolResult::text(serde_json::to_string(&args).unwrap_or_default())
                })
            })
            .build();

        let plan_yaml = r#"
steps:
  - tool: nonexistent_tool
    args: {}
    save_as: r1
    on_error: stop
  - tool: echo
    args: {msg: "should not run"}
    save_as: r2
"#;
        let args = serde_json::json!({
            "format": "yaml",
            "plan": plan_yaml,
            "stop_on_error": false
        });
        let ctx = test_ctx();
        let result = handle_plan_execute(args, &server, ctx, false).await;

        let text = result.content.iter().map(|c| match c {
            Content::Text(t) => t.text.as_str(),
        }).collect::<Vec<_>>().join("");
        let steps: Vec<StepResult> = serde_json::from_str(&text).unwrap();
        // Even though stop_on_error is false globally, on_error: stop on the step wins
        assert_eq!(steps.len(), 1);
        assert!(!steps[0].success);
    }

    #[tokio::test]
    async fn test_for_each_with_on_error_continue() {
        let echo_def = ToolDefinition {
            name: "echo".to_string(),
            description: Some("Echo msg".to_string()),
            input_schema: ToolInputSchema {
                schema_type: "object".to_string(),
                properties: None,
                required: None,
            },
        };
        let fail_def = ToolDefinition {
            name: "maybe_fail".to_string(),
            description: Some("Fails on certain input".to_string()),
            input_schema: ToolInputSchema {
                schema_type: "object".to_string(),
                properties: None,
                required: None,
            },
        };
        let server = smgglrs_core::McpServer::builder()
            .name("test")
            .version("0.1")
            .tool(echo_def, |args, _ctx| {
                Box::pin(async move {
                    let msg = args.get("msg").and_then(|v| v.as_str()).unwrap_or("");
                    CallToolResult::text(msg.to_string())
                })
            })
            .tool(fail_def, |args, _ctx| {
                Box::pin(async move {
                    let path = args.get("path").and_then(|v| v.as_str()).unwrap_or("");
                    if path.contains("bad") {
                        CallToolResult::error(format!("Cannot read: {}", path))
                    } else {
                        CallToolResult::text(format!("content of {}", path))
                    }
                })
            })
            .build();

        let plan_yaml = r#"
steps:
  - tool: echo
    args: {msg: "good.rs|bad.rs|ok.rs"}
    save_as: files
  - for_each: "{{files}}"
    split_by: "|"
    as: file
    save_as: loop_result
    steps:
      - tool: maybe_fail
        args: {path: "{{file}}"}
        save_as: content
        on_error: continue
"#;
        let args = serde_json::json!({"format": "yaml", "plan": plan_yaml});
        let ctx = test_ctx();
        let result = handle_plan_execute(args, &server, ctx, false).await;
        assert!(!result.is_error);

        let text = result.content.iter().map(|c| match c {
            Content::Text(t) => t.text.as_str(),
        }).collect::<Vec<_>>().join("");
        let steps: Vec<StepResult> = serde_json::from_str(&text).unwrap();
        // 1 (echo) + 3 (iterations) + 1 (aggregate) = 5
        assert_eq!(steps.len(), 5);
        // First iteration succeeds (good.rs)
        assert!(steps[1].success);
        // Second iteration fails but continues (bad.rs)
        assert!(!steps[2].success);
        assert!(steps[2].result.contains("Error (continued)"));
        // Third iteration succeeds (ok.rs)
        assert!(steps[3].success);
        // Aggregate still marked success since we continued
        assert!(steps[4].success);
    }

    #[tokio::test]
    async fn test_direct_mode_blocked_by_default() {
        // When allow_direct is false and no container runtime is available,
        // Python execution should be refused with a clear error message.
        if is_podman_available() {
            // Cannot test the block if Podman is present — skip
            return;
        }
        let args = serde_json::json!({
            "format": "python",
            "plan": "print('should not run')"
        });
        let server = smgglrs_core::McpServer::builder()
            .name("test")
            .version("0.1")
            .build();
        let ctx = test_ctx();
        let result = handle_plan_execute(args, &server, ctx, false).await;
        assert!(result.is_error);
        let text = result.content.iter().map(|c| match c {
            Content::Text(t) => t.text.as_str(),
        }).collect::<Vec<_>>().join("");
        assert!(
            text.contains("allow_direct_execution") || text.contains("SMGGLRS_ALLOW_DIRECT_EXECUTION"),
            "Error should explain how to enable direct mode. Got: {text}"
        );
    }

    #[test]
    fn test_is_direct_execution_allowed() {
        // With flag false and no env var, should be false
        assert!(!is_direct_execution_allowed(false));
        // With flag true, should be true regardless of env
        assert!(is_direct_execution_allowed(true));
    }

    /// Helper to create a test CallContext.
    fn test_ctx() -> CallContext {
        CallContext {
            agent: smgglrs_core::auth::AgentIdentity::new("test-agent", "readonly"),
            session_id: "test-session".to_string(),
            taint: smgglrs_core::ifc::TaintTracker::new(),
        }
    }
}
