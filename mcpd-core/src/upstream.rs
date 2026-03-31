//! MCP client for upstream servers over stdio transport.
//!
//! An `Upstream` connects to an external MCP server running as a subprocess,
//! communicating via line-delimited JSON-RPC over stdin/stdout.

use crate::protocol::{
    CallToolParams, CallToolResult, GetPromptParams, GetPromptResult, ListPromptsResult,
    ListResourcesResult, ListToolsResult, PromptDefinition, ReadResourceParams,
    ReadResourceResult, ResourceDefinition, ToolDefinition, PROTOCOL_VERSION,
};
use std::path::Path;
use std::sync::atomic::{AtomicI64, Ordering};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader, BufWriter};
use tokio::process::{Child, ChildStdin, ChildStdout, Command};

/// Error type for upstream operations.
#[derive(Debug, thiserror::Error)]
pub enum UpstreamError {
    #[error("failed to spawn upstream '{name}': {source}")]
    Spawn {
        name: String,
        source: std::io::Error,
    },

    #[error("upstream '{name}' has no stdin/stdout")]
    NoStdio { name: String },

    #[error("upstream '{name}': {message}")]
    Protocol { name: String, message: String },

    #[error("upstream '{name}': I/O error: {source}")]
    Io {
        name: String,
        source: std::io::Error,
    },

    #[error("upstream '{name}': JSON error: {source}")]
    Json {
        name: String,
        source: serde_json::Error,
    },

    #[error("upstream '{name}': JSON-RPC error {code}: {message}")]
    JsonRpc {
        name: String,
        code: i64,
        message: String,
    },
}

/// An MCP client connected to an upstream server via stdio.
pub struct Upstream {
    name: String,
    child: Child,
    stdin: BufWriter<ChildStdin>,
    stdout: BufReader<ChildStdout>,
    next_id: AtomicI64,
}

impl Upstream {
    /// Spawn a subprocess and initialize the MCP connection.
    pub async fn spawn(
        name: &str,
        command: &[String],
        cwd: Option<&str>,
    ) -> Result<Self, UpstreamError> {
        if command.is_empty() {
            return Err(UpstreamError::Protocol {
                name: name.to_string(),
                message: "command cannot be empty".to_string(),
            });
        }

        let mut cmd = Command::new(&command[0]);
        if command.len() > 1 {
            cmd.args(&command[1..]);
        }
        if let Some(dir) = cwd {
            cmd.current_dir(Path::new(dir));
        }
        cmd.stdin(std::process::Stdio::piped());
        cmd.stdout(std::process::Stdio::piped());
        cmd.stderr(std::process::Stdio::null());

        let mut child = cmd.spawn().map_err(|e| UpstreamError::Spawn {
            name: name.to_string(),
            source: e,
        })?;

        let child_stdin = child.stdin.take().ok_or_else(|| UpstreamError::NoStdio {
            name: name.to_string(),
        })?;
        let child_stdout =
            child
                .stdout
                .take()
                .ok_or_else(|| UpstreamError::NoStdio {
                    name: name.to_string(),
                })?;

        let mut upstream = Self {
            name: name.to_string(),
            child,
            stdin: BufWriter::new(child_stdin),
            stdout: BufReader::new(child_stdout),
            next_id: AtomicI64::new(1),
        };

        // Initialize the MCP connection
        upstream.initialize().await?;

        Ok(upstream)
    }

    /// Send an initialize request and notifications/initialized.
    async fn initialize(&mut self) -> Result<(), UpstreamError> {
        let params = serde_json::json!({
            "protocolVersion": PROTOCOL_VERSION,
            "capabilities": {},
            "clientInfo": {
                "name": "mcpd",
                "version": "0.1.0"
            }
        });

        let _result = self.call("initialize", Some(params)).await?;

        // Send notifications/initialized (no response expected for notifications,
        // but since we're doing request/response over stdio, send with id)
        let _ack = self
            .call("notifications/initialized", None)
            .await
            .ok(); // ignore errors on notification

        Ok(())
    }

    /// Send a JSON-RPC request and read the response.
    pub async fn call(
        &mut self,
        method: &str,
        params: Option<serde_json::Value>,
    ) -> Result<serde_json::Value, UpstreamError> {
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);

        let mut request = serde_json::json!({
            "jsonrpc": "2.0",
            "method": method,
            "id": id,
        });
        if let Some(p) = params {
            request["params"] = p;
        }

        // Write request as a single JSON line
        let line = serde_json::to_string(&request).map_err(|e| UpstreamError::Json {
            name: self.name.clone(),
            source: e,
        })?;
        self.stdin
            .write_all(line.as_bytes())
            .await
            .map_err(|e| UpstreamError::Io {
                name: self.name.clone(),
                source: e,
            })?;
        self.stdin
            .write_all(b"\n")
            .await
            .map_err(|e| UpstreamError::Io {
                name: self.name.clone(),
                source: e,
            })?;
        self.stdin
            .flush()
            .await
            .map_err(|e| UpstreamError::Io {
                name: self.name.clone(),
                source: e,
            })?;

        // Read response lines until we get a valid JSON-RPC response
        let mut buf = String::new();
        loop {
            buf.clear();
            let n = self
                .stdout
                .read_line(&mut buf)
                .await
                .map_err(|e| UpstreamError::Io {
                    name: self.name.clone(),
                    source: e,
                })?;

            if n == 0 {
                return Err(UpstreamError::Protocol {
                    name: self.name.clone(),
                    message: "upstream closed stdout (EOF)".to_string(),
                });
            }

            let trimmed = buf.trim();
            if trimmed.is_empty() || !trimmed.starts_with('{') {
                continue; // skip non-JSON lines (stderr leakage, etc.)
            }

            let response: serde_json::Value =
                serde_json::from_str(trimmed).map_err(|e| UpstreamError::Json {
                    name: self.name.clone(),
                    source: e,
                })?;

            // Check for JSON-RPC error
            if let Some(error) = response.get("error") {
                let code = error.get("code").and_then(|c| c.as_i64()).unwrap_or(-1);
                let message = error
                    .get("message")
                    .and_then(|m| m.as_str())
                    .unwrap_or("unknown error")
                    .to_string();
                return Err(UpstreamError::JsonRpc {
                    name: self.name.clone(),
                    code,
                    message,
                });
            }

            // Return the result field
            if let Some(result) = response.get("result") {
                return Ok(result.clone());
            }

            return Err(UpstreamError::Protocol {
                name: self.name.clone(),
                message: "response has neither result nor error".to_string(),
            });
        }
    }

    /// Discover tools from the upstream server.
    pub async fn list_tools(&mut self) -> Result<Vec<ToolDefinition>, UpstreamError> {
        let result = self.call("tools/list", None).await?;
        let parsed: ListToolsResult =
            serde_json::from_value(result).map_err(|e| UpstreamError::Json {
                name: self.name.clone(),
                source: e,
            })?;
        Ok(parsed.tools)
    }

    /// Discover prompts from the upstream server.
    pub async fn list_prompts(&mut self) -> Result<Vec<PromptDefinition>, UpstreamError> {
        let result = self.call("prompts/list", None).await?;
        let parsed: ListPromptsResult =
            serde_json::from_value(result).map_err(|e| UpstreamError::Json {
                name: self.name.clone(),
                source: e,
            })?;
        Ok(parsed.prompts)
    }

    /// Discover resources from the upstream server.
    pub async fn list_resources(&mut self) -> Result<Vec<ResourceDefinition>, UpstreamError> {
        let result = self.call("resources/list", None).await?;
        let parsed: ListResourcesResult =
            serde_json::from_value(result).map_err(|e| UpstreamError::Json {
                name: self.name.clone(),
                source: e,
            })?;
        Ok(parsed.resources)
    }

    /// Call a tool on the upstream server.
    pub async fn call_tool(
        &mut self,
        params: CallToolParams,
    ) -> Result<CallToolResult, UpstreamError> {
        let value =
            serde_json::to_value(&params).map_err(|e| UpstreamError::Json {
                name: self.name.clone(),
                source: e,
            })?;
        let result = self.call("tools/call", Some(value)).await?;
        serde_json::from_value(result).map_err(|e| UpstreamError::Json {
            name: self.name.clone(),
            source: e,
        })
    }

    /// Get a prompt from the upstream server.
    pub async fn get_prompt(
        &mut self,
        params: GetPromptParams,
    ) -> Result<GetPromptResult, UpstreamError> {
        let value =
            serde_json::to_value(&params).map_err(|e| UpstreamError::Json {
                name: self.name.clone(),
                source: e,
            })?;
        let result = self.call("prompts/get", Some(value)).await?;
        serde_json::from_value(result).map_err(|e| UpstreamError::Json {
            name: self.name.clone(),
            source: e,
        })
    }

    /// Read a resource from the upstream server.
    pub async fn read_resource(
        &mut self,
        params: ReadResourceParams,
    ) -> Result<ReadResourceResult, UpstreamError> {
        let value =
            serde_json::to_value(&params).map_err(|e| UpstreamError::Json {
                name: self.name.clone(),
                source: e,
            })?;
        let result = self.call("resources/read", Some(value)).await?;
        serde_json::from_value(result).map_err(|e| UpstreamError::Json {
            name: self.name.clone(),
            source: e,
        })
    }

    /// Name of this upstream.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Shut down the upstream subprocess.
    pub fn shutdown(&mut self) {
        // Drop stdin to send EOF, then kill the child
        drop(self.child.stdin.take());
        let _ = self.child.start_kill();
    }
}

impl Drop for Upstream {
    fn drop(&mut self) {
        self.shutdown();
    }
}
