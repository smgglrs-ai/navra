//! CLI subprocess backend for meta-agent orchestration.
//!
//! Runs an external CLI tool (claude, gemini, codex, goose, or any
//! custom command) as a model backend. The prompt is delivered via
//! stdin and the response is captured from stdout.
//!
//! This enables meta-agent orchestration: an navra agent can
//! delegate to another agent runtime as a "model backend."

use crate::{
    CreateResponseRequest, GenerateRequest, GenerateResponse, Locality, ModelBackend, ModelError,
    ModelResponse,
    chat::{ChatMessage, ChatResponse, ChatRole, FinishReason},
};
use std::time::Duration;
use tokio::process::Command;

/// Default timeout for CLI subprocess execution (5 minutes).
const DEFAULT_TIMEOUT_SECS: u64 = 300;

/// CLI subprocess model backend.
///
/// Spawns a configured CLI command, pipes the prompt via stdin,
/// and captures stdout as the model response. Supports any CLI
/// tool that reads a prompt and writes a response.
///
/// # Examples
///
/// ```no_run
/// use navra_model::CliBackend;
///
/// // Claude Code as a backend
/// let backend = CliBackend::new("claude", vec!["-p".into()]);
///
/// // Gemini CLI
/// let backend = CliBackend::new("gemini", vec![]);
///
/// // Custom command with timeout
/// let backend = CliBackend::builder("goose")
///     .args(vec!["run".into()])
///     .timeout_secs(600)
///     .build();
/// ```
pub struct CliBackend {
    /// The CLI command to execute.
    cli_command: String,
    /// Arguments template. If any arg contains `{prompt}`, the prompt
    /// text replaces that placeholder and stdin is not used.
    cli_args: Vec<String>,
    /// Subprocess timeout.
    timeout: Duration,
}

impl CliBackend {
    /// Create a new CLI backend with the given command and arguments.
    pub fn new(command: impl Into<String>, args: Vec<String>) -> Self {
        Self {
            cli_command: command.into(),
            cli_args: args,
            timeout: Duration::from_secs(DEFAULT_TIMEOUT_SECS),
        }
    }

    /// Create a builder for more detailed configuration.
    pub fn builder(command: impl Into<String>) -> CliBackendBuilder {
        CliBackendBuilder {
            cli_command: command.into(),
            cli_args: Vec::new(),
            timeout_secs: DEFAULT_TIMEOUT_SECS,
        }
    }

    /// Returns the locality of this backend (always Local).
    pub fn locality(&self) -> &Locality {
        &Locality::Local
    }

    /// Format the prompt from a CreateResponseRequest.
    ///
    /// Extracts system instructions and user messages into a single
    /// text prompt suitable for CLI input.
    fn format_prompt(request: &CreateResponseRequest) -> String {
        let mut parts = Vec::new();

        if let Some(ref instructions) = request.instructions {
            parts.push(instructions.clone());
        }

        for item in &request.input {
            match item {
                crate::InputItem::Message(msg) => {
                    let text = msg.text();
                    match msg.role {
                        crate::MessageRole::System | crate::MessageRole::Developer => {
                            parts.push(text.to_string());
                        }
                        crate::MessageRole::User => parts.push(text.to_string()),
                        crate::MessageRole::Assistant => {
                            parts.push(format!("Assistant: {text}"));
                        }
                    }
                }
                crate::InputItem::FunctionCallOutput(fco) => {
                    let text = match &fco.output {
                        crate::FunctionCallOutputContent::Text(t) => t.clone(),
                        crate::FunctionCallOutputContent::Parts(ps) => ps
                            .iter()
                            .filter_map(|p| match p {
                                crate::InputContent::Text(t) => Some(t.text.as_str()),
                                _ => None,
                            })
                            .collect::<Vec<_>>()
                            .join(""),
                    };
                    parts.push(format!("Tool result: {text}"));
                }
                _ => {}
            }
        }

        parts.join("\n\n")
    }

    /// Build the argument list, substituting `{prompt}` if present.
    ///
    /// Returns `(args, use_stdin)`: if any arg contained `{prompt}`,
    /// the prompt is inlined into args and stdin is not needed.
    fn build_args(&self, prompt: &str) -> (Vec<String>, bool) {
        let has_placeholder = self.cli_args.iter().any(|a| a.contains("{prompt}"));
        if has_placeholder {
            let args = self
                .cli_args
                .iter()
                .map(|a| a.replace("{prompt}", prompt))
                .collect();
            (args, false)
        } else {
            (self.cli_args.clone(), true)
        }
    }

    /// Spawn the CLI subprocess and capture its output.
    async fn run_subprocess(&self, prompt: &str) -> Result<String, ModelError> {
        let (args, use_stdin) = self.build_args(prompt);

        let mut cmd = Command::new(&self.cli_command);
        cmd.args(&args);

        if use_stdin {
            cmd.stdin(std::process::Stdio::piped());
        } else {
            cmd.stdin(std::process::Stdio::null());
        }
        cmd.stdout(std::process::Stdio::piped());
        cmd.stderr(std::process::Stdio::piped());

        let mut child = cmd.spawn().map_err(|e| {
            ModelError::Inference(format!("failed to spawn '{}': {e}", self.cli_command))
        })?;

        // Write prompt to stdin if needed.
        // Ignore broken pipe — the subprocess may exit before reading all input
        // (e.g. `echo` outputs its args and exits without reading stdin).
        if use_stdin && let Some(mut stdin) = child.stdin.take() {
            use tokio::io::AsyncWriteExt;
            let _ = stdin.write_all(prompt.as_bytes()).await;
            drop(stdin);
        }

        // Wait with timeout
        let output = tokio::time::timeout(self.timeout, child.wait_with_output())
            .await
            .map_err(|_| {
                ModelError::Inference(format!(
                    "'{}' timed out after {}s",
                    self.cli_command,
                    self.timeout.as_secs()
                ))
            })?
            .map_err(|e| ModelError::Inference(format!("'{}' failed: {e}", self.cli_command)))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            let code = output
                .status
                .code()
                .map(|c| c.to_string())
                .unwrap_or_else(|| "signal".to_string());
            return Err(ModelError::Inference(format!(
                "'{}' exited with {code}: {stderr}",
                self.cli_command
            )));
        }

        let stdout = String::from_utf8(output.stdout)
            .map_err(|e| ModelError::Inference(format!("invalid UTF-8 in stdout: {e}")))?;

        Ok(stdout.trim().to_string())
    }
}

impl ModelBackend for CliBackend {
    fn generate(
        &self,
        request: &GenerateRequest,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<GenerateResponse, ModelError>> + Send + '_>,
    > {
        let mut prompt = String::new();
        if let Some(ref system) = request.system {
            prompt.push_str(system);
            prompt.push_str("\n\n");
        }
        prompt.push_str(&request.prompt);

        Box::pin(async move {
            let text = self.run_subprocess(&prompt).await?;
            Ok(GenerateResponse {
                text,
                prompt_tokens: None,
                completion_tokens: None,
            })
        })
    }

    fn respond(
        &self,
        request: &CreateResponseRequest,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<ModelResponse, ModelError>> + Send + '_>,
    > {
        let prompt = Self::format_prompt(request);

        Box::pin(async move {
            let text = self.run_subprocess(&prompt).await?;

            let chat_resp = ChatResponse {
                message: ChatMessage {
                    role: ChatRole::Assistant,
                    content: Some(text),
                    images: Vec::new(),
                    tool_calls: Vec::new(),
                    tool_call_id: None,
                },
                finish_reason: FinishReason::Stop,
                prompt_tokens: None,
                completion_tokens: None,
            };

            Ok(crate::chat_to_responses("cli", &chat_resp))
        })
    }
}

/// Builder for [`CliBackend`] with optional configuration.
pub struct CliBackendBuilder {
    cli_command: String,
    cli_args: Vec<String>,
    timeout_secs: u64,
}

impl CliBackendBuilder {
    /// Set the CLI arguments.
    ///
    /// Any argument containing `{prompt}` will have the prompt text
    /// substituted in place of the placeholder. If no argument contains
    /// `{prompt}`, the prompt is piped via stdin.
    pub fn args(mut self, args: Vec<String>) -> Self {
        self.cli_args = args;
        self
    }

    /// Set the subprocess timeout in seconds.
    pub fn timeout_secs(mut self, secs: u64) -> Self {
        self.timeout_secs = secs;
        self
    }

    /// Build the [`CliBackend`].
    pub fn build(self) -> CliBackend {
        CliBackend {
            cli_command: self.cli_command,
            cli_args: self.cli_args,
            timeout: Duration::from_secs(self.timeout_secs),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builder_defaults() {
        let backend = CliBackend::builder("claude").build();
        assert_eq!(backend.cli_command, "claude");
        assert!(backend.cli_args.is_empty());
        assert_eq!(backend.timeout, Duration::from_secs(DEFAULT_TIMEOUT_SECS));
        assert_eq!(backend.locality(), &Locality::Local);
    }

    #[test]
    fn builder_custom_config() {
        let backend = CliBackend::builder("gemini")
            .args(vec!["--format".into(), "json".into()])
            .timeout_secs(60)
            .build();
        assert_eq!(backend.cli_command, "gemini");
        assert_eq!(backend.cli_args, vec!["--format", "json"]);
        assert_eq!(backend.timeout, Duration::from_secs(60));
    }

    #[test]
    fn new_constructor() {
        let backend = CliBackend::new("codex", vec!["-q".into()]);
        assert_eq!(backend.cli_command, "codex");
        assert_eq!(backend.cli_args, vec!["-q"]);
        assert_eq!(backend.timeout, Duration::from_secs(DEFAULT_TIMEOUT_SECS));
    }

    #[test]
    fn build_args_with_placeholder() {
        let backend = CliBackend::new("test", vec!["-p".into(), "{prompt}".into()]);
        let (args, use_stdin) = backend.build_args("hello world");
        assert_eq!(args, vec!["-p", "hello world"]);
        assert!(!use_stdin);
    }

    #[test]
    fn build_args_without_placeholder() {
        let backend = CliBackend::new("test", vec!["-q".into()]);
        let (args, use_stdin) = backend.build_args("hello");
        assert_eq!(args, vec!["-q"]);
        assert!(use_stdin);
    }

    #[test]
    fn build_args_placeholder_in_middle() {
        let backend = CliBackend::new(
            "test",
            vec!["ask".into(), "{prompt}".into(), "--json".into()],
        );
        let (args, use_stdin) = backend.build_args("what is rust?");
        assert_eq!(args, vec!["ask", "what is rust?", "--json"]);
        assert!(!use_stdin);
    }

    #[test]
    fn format_prompt_simple() {
        let req = CreateResponseRequest::new(
            String::from("test"),
            vec![crate::InputItem::user("What is Rust?")],
        );
        let prompt = CliBackend::format_prompt(&req);
        assert_eq!(prompt, "What is Rust?");
    }

    #[test]
    fn format_prompt_with_instructions() {
        let mut req =
            CreateResponseRequest::new(String::from("test"), vec![crate::InputItem::user("Hello")]);
        req.instructions = Some("Be concise.".into());
        let prompt = CliBackend::format_prompt(&req);
        assert!(prompt.starts_with("Be concise."));
        assert!(prompt.contains("Hello"));
    }

    #[tokio::test]
    async fn subprocess_echo() {
        // Use echo as a simple CLI backend
        let backend = CliBackend::new("echo", vec!["hello from cli".into()]);
        let req = GenerateRequest {
            prompt: "ignored".into(),
            max_tokens: None,
            temperature: None,
            system: None,
            images: vec![],
        };
        let resp = backend.generate(&req).await.unwrap();
        assert_eq!(resp.text, "hello from cli");
        assert!(resp.prompt_tokens.is_none());
    }

    #[tokio::test]
    async fn subprocess_cat_stdin() {
        // cat reads from stdin and writes to stdout
        let backend = CliBackend::new("cat", vec![]);
        let req = GenerateRequest {
            prompt: "piped text".into(),
            max_tokens: None,
            temperature: None,
            system: None,
            images: vec![],
        };
        let resp = backend.generate(&req).await.unwrap();
        assert_eq!(resp.text, "piped text");
    }

    #[tokio::test]
    async fn subprocess_nonexistent_command() {
        let backend = CliBackend::new("nonexistent_command_xyz", vec![]);
        let req = GenerateRequest {
            prompt: "hello".into(),
            max_tokens: None,
            temperature: None,
            system: None,
            images: vec![],
        };
        let err = backend.generate(&req).await.unwrap_err();
        assert!(matches!(err, ModelError::Inference(_)));
        assert!(format!("{err}").contains("nonexistent_command_xyz"));
    }

    #[tokio::test]
    async fn subprocess_exit_code_error() {
        let backend = CliBackend::new("false", vec![]);
        let req = GenerateRequest {
            prompt: "hello".into(),
            max_tokens: None,
            temperature: None,
            system: None,
            images: vec![],
        };
        let err = backend.generate(&req).await.unwrap_err();
        assert!(matches!(err, ModelError::Inference(_)));
    }

    #[tokio::test]
    async fn subprocess_timeout() {
        let backend = CliBackend::builder("sleep")
            .args(vec!["10".into()])
            .timeout_secs(1)
            .build();
        let req = GenerateRequest {
            prompt: String::new(),
            max_tokens: None,
            temperature: None,
            system: None,
            images: vec![],
        };
        let err = backend.generate(&req).await.unwrap_err();
        assert!(format!("{err}").contains("timed out"));
    }

    #[tokio::test]
    async fn respond_returns_model_response() {
        let backend = CliBackend::new("echo", vec!["cli response".into()]);
        let req =
            CreateResponseRequest::new(String::from("test"), vec![crate::InputItem::user("hello")]);
        let resp = backend.respond(&req).await.unwrap();
        assert_eq!(resp.status, crate::ResponseStatus::Completed);
        assert_eq!(resp.text().unwrap(), "cli response");
    }
}
