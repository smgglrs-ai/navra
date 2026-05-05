use crate::auth::AgentIdentity;
use crate::protocol::{JsonRpcRequest, JsonRpcResponse, JsonRpcError, RequestId};
use crate::server::McpServer;
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

use super::streamable::dispatch::dispatch;

/// Run the MCP server over stdin/stdout (line-delimited JSON-RPC).
///
/// Reads one JSON object per line from stdin, dispatches through the
/// standard MCP handler, and writes the response as a single JSON line
/// to stdout. All diagnostic output goes to stderr via `tracing`.
pub async fn run_stdio_server(
    server: Arc<McpServer>,
    agent: AgentIdentity,
) -> Result<(), Box<dyn std::error::Error>> {
    let stdin = tokio::io::stdin();
    let mut stdout = tokio::io::stdout();
    let mut reader = BufReader::new(stdin);
    let mut line = String::new();
    let mut session_id: Option<String> = None;

    tracing::info!("Stdio transport ready");

    loop {
        line.clear();
        let n = reader.read_line(&mut line).await?;
        if n == 0 {
            tracing::info!("Stdin EOF, shutting down");
            break;
        }

        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }

        let value: serde_json::Value = match serde_json::from_str(trimmed) {
            Ok(v) => v,
            Err(e) => {
                tracing::warn!(error = %e, "Invalid JSON on stdin, skipping");
                let err_resp = JsonRpcResponse::error(
                    RequestId::Number(0),
                    JsonRpcError::parse_error(),
                );
                write_response(&mut stdout, &err_resp).await?;
                continue;
            }
        };

        // Notifications have no "id" field — don't send a response
        let has_id = value.get("id").is_some();

        let request: JsonRpcRequest = match serde_json::from_value(value) {
            Ok(r) => r,
            Err(e) => {
                if has_id {
                    tracing::warn!(error = %e, "Malformed JSON-RPC request");
                    let err_resp = JsonRpcResponse::error(
                        RequestId::Number(0),
                        JsonRpcError::invalid_request("Failed to parse JSON-RPC request"),
                    );
                    write_response(&mut stdout, &err_resp).await?;
                }
                continue;
            }
        };

        let (response, new_session_id) =
            dispatch(server.clone(), request, agent.clone(), session_id.clone()).await;

        if let Some(sid) = new_session_id {
            session_id = Some(sid);
        }

        write_response(&mut stdout, &response).await?;
    }

    Ok(())
}

async fn write_response(
    stdout: &mut tokio::io::Stdout,
    response: &JsonRpcResponse,
) -> Result<(), std::io::Error> {
    let resp_line = serde_json::to_string(response)
        .unwrap_or_else(|_| r#"{"jsonrpc":"2.0","error":{"code":-32603,"message":"serialization failed"},"id":0}"#.to_string());
    stdout.write_all(resp_line.as_bytes()).await?;
    stdout.write_all(b"\n").await?;
    stdout.flush().await
}
