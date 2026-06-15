//! Stdio transport: line-delimited JSON-RPC over subprocess stdin/stdout.

use super::transport::{Transport, UpstreamNotification};
use super::UpstreamError;
use async_trait::async_trait;
use std::path::Path;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader, BufWriter};
use tokio::process::{Child, ChildStdin, ChildStdout, Command};
use tokio::sync::mpsc;

/// Stdio transport backed by a subprocess.
pub struct StdioTransport {
    name: String,
    child: Child,
    stdin: BufWriter<ChildStdin>,
    stdout: BufReader<ChildStdout>,
    /// Handle to the stderr logging task (kept alive while transport lives).
    _stderr_task: Option<tokio::task::JoinHandle<()>>,
    notification_tx: Option<mpsc::UnboundedSender<UpstreamNotification>>,
}

impl StdioTransport {
    /// Spawn a subprocess with piped stdin/stdout.
    pub fn spawn(name: &str, command: &[String], cwd: Option<&str>) -> Result<Self, UpstreamError> {
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
        cmd.stderr(std::process::Stdio::piped());

        let mut child = cmd.spawn().map_err(|e| UpstreamError::Spawn {
            name: name.to_string(),
            source: e,
        })?;

        let child_stdin = child.stdin.take().ok_or_else(|| UpstreamError::NoStdio {
            name: name.to_string(),
        })?;
        let child_stdout = child.stdout.take().ok_or_else(|| UpstreamError::NoStdio {
            name: name.to_string(),
        })?;

        // Spawn a background task to log stderr output from the subprocess.
        // Rate-limited to MAX_STDERR_LINES_PER_SEC to prevent log flooding.
        let stderr_task = if let Some(stderr) = child.stderr.take() {
            let upstream_name = name.to_string();
            Some(tokio::spawn(async move {
                const MAX_STDERR_LINES_PER_SEC: u32 = 10;
                let mut reader = BufReader::new(stderr);
                let mut line = String::new();
                let mut window_start = tokio::time::Instant::now();
                let mut lines_in_window: u32 = 0;
                let mut suppressed: u64 = 0;
                loop {
                    line.clear();
                    match reader.read_line(&mut line).await {
                        Ok(0) => break,
                        Ok(_) => {
                            let trimmed = line.trim_end();
                            if trimmed.is_empty() {
                                continue;
                            }

                            let now = tokio::time::Instant::now();
                            if now.duration_since(window_start)
                                >= std::time::Duration::from_secs(1)
                            {
                                if suppressed > 0 {
                                    tracing::warn!(
                                        upstream = %upstream_name,
                                        "[upstream:{upstream_name}:stderr] {suppressed} lines suppressed (rate-limited)"
                                    );
                                }
                                window_start = now;
                                lines_in_window = 0;
                                suppressed = 0;
                            }

                            lines_in_window += 1;
                            if lines_in_window <= MAX_STDERR_LINES_PER_SEC {
                                tracing::warn!(
                                    upstream = %upstream_name,
                                    "[upstream:{upstream_name}:stderr] {trimmed}"
                                );
                            } else {
                                suppressed += 1;
                            }
                        }
                        Err(_) => break,
                    }
                }
            }))
        } else {
            None
        };

        Ok(Self {
            name: name.to_string(),
            child,
            stdin: BufWriter::new(child_stdin),
            stdout: BufReader::new(child_stdout),
            _stderr_task: stderr_task,
            notification_tx: None,
        })
    }

    /// Check if the subprocess is still running.
    pub fn is_alive(&mut self) -> bool {
        matches!(self.child.try_wait(), Ok(None))
    }
}

#[async_trait]
impl Transport for StdioTransport {
    async fn request(
        &mut self,
        body: serde_json::Value,
    ) -> Result<serde_json::Value, UpstreamError> {
        // Write request as a single JSON line
        let line = serde_json::to_string(&body).map_err(|e| UpstreamError::Json {
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
        self.stdin.flush().await.map_err(|e| UpstreamError::Io {
            name: self.name.clone(),
            source: e,
        })?;

        // Read response lines until we get a JSON-RPC response (not a notification).
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
                continue;
            }

            let parsed: serde_json::Value =
                serde_json::from_str(trimmed).map_err(|e| UpstreamError::Json {
                    name: self.name.clone(),
                    source: e,
                })?;

            // A JSON-RPC notification has "method" but no "id".
            if parsed.get("method").is_some() && parsed.get("id").is_none() {
                if let Some(method) = parsed["method"].as_str() {
                    if method == "notifications/tools/list_changed" {
                        if let Some(ref tx) = self.notification_tx {
                            let _ = tx.send(UpstreamNotification::ToolsListChanged);
                        }
                    }
                }
                continue;
            }

            return Ok(parsed);
        }
    }

    fn shutdown(&mut self) {
        drop(self.child.stdin.take());
        let _ = self.child.start_kill();
    }

    fn set_notification_sender(&mut self, tx: mpsc::UnboundedSender<UpstreamNotification>) {
        self.notification_tx = Some(tx);
    }
}

impl Drop for StdioTransport {
    fn drop(&mut self) {
        self.shutdown();
    }
}
