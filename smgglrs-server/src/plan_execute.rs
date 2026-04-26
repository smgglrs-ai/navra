//! Plan execution tool: run multi-step plans in a single model turn.
//!
//! Supports two modes:
//! - **YAML** (no sandbox): declarative steps with variable passing
//! - **Python** (sandbox required): CodeAct via Podman — stubbed for now

use smgglrs_core::auth::CallContext;
use smgglrs_core::protocol::{CallToolParams, CallToolResult, Content, ToolDefinition, ToolInputSchema};
use smgglrs_core::McpServer;
use std::collections::HashMap;

/// A single step in a YAML plan.
#[derive(Debug, Clone, serde::Deserialize)]
pub struct PlanStep {
    pub tool: String,
    #[serde(default)]
    pub args: serde_json::Value,
    pub save_as: Option<String>,
    /// Conditional execution: a template expression like "{{prev.success}}".
    /// Step is skipped when the expression resolves to a falsy value.
    pub when: Option<String>,
}

/// A parsed YAML plan.
#[derive(Debug, Clone, serde::Deserialize)]
pub struct YamlPlan {
    pub steps: Vec<PlanStep>,
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

    for (i, step) in plan.steps.iter().enumerate() {
        let step_name = step
            .save_as
            .clone()
            .unwrap_or_else(|| format!("step_{}", i));

        // Validate tool name
        if !known_tools.tools.iter().any(|t| t.name == step.tool) {
            let sr = StepResult {
                step: Some(step_name.clone()),
                tool: step.tool.clone(),
                result: format!("Unknown tool: {}", step.tool),
                success: false,
            };
            results.push(sr.clone());
            vars.insert(step_name, sr);
            if stop_on_error {
                break;
            }
            continue;
        }

        // Evaluate conditional
        if let Some(ref when) = step.when {
            if !evaluate_when(when, &vars) {
                let sr = StepResult {
                    step: Some(step_name.clone()),
                    tool: step.tool.clone(),
                    result: "Skipped (condition not met)".to_string(),
                    success: true,
                };
                results.push(sr.clone());
                vars.insert(step_name, sr);
                continue;
            }
        }

        // Resolve variable references in arguments
        let resolved_args = if step.args.is_null() {
            serde_json::json!({})
        } else {
            substitute_vars(&step.args, &vars)
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

        let sr = StepResult {
            step: Some(step_name.clone()),
            tool: step.tool.clone(),
            result: result_text,
            success: !result.is_error,
        };

        results.push(sr.clone());
        vars.insert(step_name, sr.clone());

        if !sr.success && stop_on_error {
            break;
        }
    }

    results
}

// ---------------------------------------------------------------------------
// Python mode (stub)
// ---------------------------------------------------------------------------

/// Check if Podman is available on the system.
pub fn is_podman_available() -> bool {
    std::process::Command::new("podman")
        .arg("--version")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

// ---------------------------------------------------------------------------
// Tool handler
// ---------------------------------------------------------------------------

/// Handle a plan_execute tool call.
pub async fn handle_plan_execute(
    args: serde_json::Value,
    server: &McpServer,
    ctx: CallContext,
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
            if !is_podman_available() {
                return CallToolResult::error(
                    "Python mode requires Podman but it is not available on this system. \
                     Install Podman or use format: yaml instead.",
                );
            }
            CallToolResult::error(
                "Python mode is not yet implemented. Use format: yaml for now.",
            )
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
                        "description": "Stop execution on first error (default: true)",
                        "default": true
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
        assert_eq!(plan.steps[0].tool, "file_tree");
        assert_eq!(plan.steps[0].save_as, Some("tree".to_string()));
        assert_eq!(plan.steps[1].tool, "file_read");
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
        assert_eq!(plan.steps[1].when, Some("{{tree}}".to_string()));
    }

    #[tokio::test]
    async fn test_handle_missing_plan() {
        let args = serde_json::json!({"format": "yaml"});
        let server = smgglrs_core::McpServer::builder()
            .name("test")
            .version("0.1")
            .build();
        let ctx = test_ctx();
        let result = handle_plan_execute(args, &server, ctx).await;
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
        let result = handle_plan_execute(args, &server, ctx).await;
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
        let result = handle_plan_execute(args, &server, ctx).await;
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
        let result = handle_plan_execute(args, &server, ctx).await;
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
        let result = handle_plan_execute(args, &server, ctx).await;
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
        let result = handle_plan_execute(args, &server, ctx).await;
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
        let result = handle_plan_execute(args, &server, ctx).await;
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
        let result = handle_plan_execute(args, &server, ctx).await;

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
    async fn test_python_mode_detection() {
        let args = serde_json::json!({
            "format": "python",
            "plan": "print('hello')"
        });
        let server = smgglrs_core::McpServer::builder()
            .name("test")
            .version("0.1")
            .build();
        let ctx = test_ctx();
        let result = handle_plan_execute(args, &server, ctx).await;
        assert!(result.is_error);
        let text = result.content.iter().map(|c| match c {
            Content::Text(t) => t.text.as_str(),
        }).collect::<Vec<_>>().join("");
        // Should mention either Podman not available or not yet implemented
        assert!(text.contains("Podman") || text.contains("not yet implemented"));
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

    /// Helper to create a test CallContext.
    fn test_ctx() -> CallContext {
        CallContext {
            agent: smgglrs_core::auth::AgentIdentity::new("test-agent", "readonly"),
            session_id: "test-session".to_string(),
            taint: smgglrs_core::ifc::TaintTracker::new(),
        }
    }
}
