use clap::{Parser, Subcommand};

/// Default path for the cognitive core directory.
fn default_cognitive_core_path() -> String {
    dirs::config_dir()
        .unwrap_or_default()
        .join("navra/cognitive_core")
        .to_string_lossy()
        .to_string()
}

#[derive(Parser)]
#[command(
    name = "navra",
    about = "navra \u{2014} secure MCP gateway for AI agents",
    version
)]
pub(crate) struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand)]
pub(crate) enum Commands {
    /// MCP gateway server
    Mcp {
        #[command(subcommand)]
        action: McpAction,
    },
    /// Start the MCP server (deprecated: use `navra mcp serve`)
    #[command(hide = true)]
    Serve {
        /// Path to config file
        #[arg(short, long)]
        config: Option<String>,
        /// Disable system tray icon
        #[arg(long)]
        no_tray: bool,
        /// Enable anonymous access (dev only — do not use in production)
        #[arg(long)]
        dev_mode: bool,
    },
    /// Interactive first-time setup
    Init {
        /// Skip interactive prompts, use defaults + flags
        #[arg(long)]
        quiet: bool,
        /// Agent name (default: auto-detect)
        #[arg(long)]
        agent_name: Option<String>,
        /// Safety level: standard, strict, minimal
        #[arg(long, default_value = "standard")]
        safety: String,
        /// Project type: dev, data, ops, custom
        #[arg(long, default_value = "dev")]
        project: String,
        /// Model backend: ollama, mistral, anthropic, openai-compat, none
        #[arg(long, default_value = "none")]
        model: String,
        /// Base URL for openai-compat backend
        #[arg(long)]
        model_url: Option<String>,
        /// API key for model backend
        #[arg(long)]
        api_key: Option<String>,
        /// Allowed directories (comma-separated globs)
        #[arg(long)]
        allow: Option<String>,
        /// Install systemd user service
        #[arg(long)]
        install_service: bool,
        /// Output config to stdout instead of writing to file
        #[arg(long)]
        dry_run: bool,
        /// Config output path
        #[arg(short, long)]
        output: Option<String>,
        /// Hardware profile: auto, desktop, laptop, headless.
        /// Generates a config optimized for the detected (or specified) hardware.
        /// Overrides model/safety/project flags with profile-tuned defaults.
        #[arg(long)]
        profile: Option<String>,
    },
    /// Run as a stdio MCP server (deprecated: use `navra mcp stdio`)
    #[command(hide = true)]
    Stdio {
        /// Path to config file
        #[arg(short, long)]
        config: Option<String>,
    },
    /// Generate or manage agent tokens
    Token {
        #[command(subcommand)]
        action: TokenAction,
    },
    /// Approve a pending request
    Approve { id: String },
    /// Deny a pending request
    Deny { id: String },
    /// Show server status
    Status,
    /// Print JSON Schema for config.toml
    Schema,
    /// Install systemd user units and enable the service
    Install,
    /// Uninstall systemd user units
    Uninstall,
    /// Manage agent bundles (install, inspect, list, remove)
    Agent {
        #[command(subcommand)]
        action: AgentAction,
    },
    /// Manage ONNX models
    Model {
        #[command(subcommand)]
        action: ModelAction,
    },
    /// Run adversarial security evaluations
    Eval {
        #[command(subcommand)]
        action: EvalAction,
    },
    /// Query the gateway audit blackbox
    Audit {
        /// Number of entries to show (default 20)
        #[arg(short, long, default_value = "20")]
        limit: usize,
        /// Show full args and results
        #[arg(short, long)]
        detail: bool,
        /// Filter by agent name
        #[arg(long)]
        agent: Option<String>,
        /// Filter by tool name
        #[arg(long)]
        tool: Option<String>,
        /// Verify hash chain integrity instead of listing
        #[arg(long)]
        verify: bool,
    },
    /// Analyze flow execution traces for weaknesses and propose improvements
    SelfHarness {
        /// Flow IDs to analyze (default: auto-discover recent flows)
        #[arg(long)]
        flow: Vec<String>,
        /// Output report as JSON
        #[arg(long)]
        json: bool,
        /// Back-edge iteration count considered excessive (default: 3)
        #[arg(long, default_value = "3")]
        retry_threshold: u32,
        /// Tool call duration (ms) considered slow (default: 10000)
        #[arg(long, default_value = "10000")]
        slow_tool_ms: u64,
    },
    /// Manage flows, triggers, and flow execution
    Flow {
        #[command(subcommand)]
        action: FlowAction,
    },
    /// Run an agent task (deprecated: use `navra agent run` or `navra flow run`)
    #[command(hide = true)]
    Run {
        /// Prompt for the agent (or instance/workflow for named workflows)
        prompt: String,
        /// Model to use (default: auto-detect from Ollama)
        #[arg(short, long)]
        model: Option<String>,
        /// Persona to use (default: leader)
        #[arg(short, long, default_value = "leader")]
        persona: String,
        /// navra endpoint URL
        #[arg(short, long, default_value = "http://127.0.0.1:9315/mcp")]
        endpoint: String,
        /// Auth token (reads from MCPD_TOKEN env if not set)
        #[arg(short, long)]
        token: Option<String>,
        /// Max iterations (default 200, set lower for quick tasks)
        #[arg(short = 'n', long, default_value = "200")]
        max_iterations: usize,
        /// Inject an upstream MCP prompt into the system prompt.
        /// Format: "upstream:prompt_name" (e.g., "syllogis:legal_analysis").
        /// Fetched at runtime and appended after the persona's system prompt.
        /// Can be repeated.
        #[arg(long = "upstream-prompt")]
        upstream_prompts: Vec<String>,
        /// Run a named workflow from an agent instance (e.g., work-assistant/day-planner)
        #[arg(long)]
        workflow: Option<String>,
        /// Path to a flow YAML file to execute directly (e.g., examples/flows/review.yaml)
        #[arg(long)]
        flow: Option<String>,
        /// Path to agent instance config (overrides default resolution)
        #[arg(long)]
        config: Option<String>,
        /// Force Ollama API even when local GGUF blob exists
        #[arg(long)]
        no_embedded: bool,
        /// Preview the constructed prompt without executing
        #[arg(long)]
        dry_run: bool,
    },
    /// Manage the PII NER model
    Pii {
        #[command(subcommand)]
        action: PiiAction,
    },
    /// Generate policy suggestions from audit denials (audit2allow pattern)
    Policy {
        #[command(subcommand)]
        action: PolicyAction,
    },
    /// Configuration utilities
    Config {
        #[command(subcommand)]
        action: ConfigAction,
    },
    /// Run autonomous self-improvement cycles (audit→fix→test→verify)
    Improve {
        /// Path to the project to improve
        #[arg(short, long, default_value = ".")]
        target: String,
        /// Number of improvement cycles to run
        #[arg(short, long, default_value_t = 3)]
        cycles: u32,
        /// Git branch name for the worktree
        #[arg(short, long, default_value = "self-improve")]
        branch: String,
        /// Path to config file
        #[arg(long)]
        config: Option<String>,
    },
    /// Validate cognitive core cross-references
    ValidateCognitive {
        /// Path to cognitive core directory
        #[arg(long, default_value_t = default_cognitive_core_path())]
        cognitive_core: String,
    },
    /// Wrap an MCP server with secure-by-default gateway in one command
    Wrap {
        /// Bind address for the gateway (default: 127.0.0.1:9315)
        #[arg(short, long, default_value = "127.0.0.1:9315")]
        bind: String,
        /// Safety profile: standard, block, secrets-only, none
        #[arg(short, long, default_value = "standard")]
        safety: String,
        /// Name for the upstream server (default: derived from command)
        #[arg(short, long)]
        name: Option<String>,
        /// Disable system tray icon
        #[arg(long)]
        no_tray: bool,
        /// Connect, list tools/resources/prompts, suggest policy, then exit
        #[arg(long)]
        discover: bool,
        /// Skip safety filters entirely (fast iteration, no content scanning)
        #[arg(long)]
        allow_all: bool,
        /// Run upstream in a container sandbox (openshell or podman)
        #[arg(long)]
        sandbox: Option<String>,
        /// Allow egress to specific domains (can be repeated, merged with auto-discovered)
        #[arg(long = "allow-domain")]
        allow_domains: Vec<String>,
        /// Command and args to start the upstream MCP server
        #[arg(trailing_var_arg = true, required = true)]
        command: Vec<String>,
    },
    /// Run the end-to-end security audit demo
    Demo {
        /// Path to the demo project (default: examples/payments-app)
        #[arg(short, long, default_value = "examples/payments-app")]
        project: String,
        /// Run with a real LLM (requires Ollama or llama-server)
        #[arg(long)]
        live: bool,
        /// Model to use in live mode (default: granite3.3:2b)
        #[arg(long, default_value = "granite3.3:2b")]
        model: String,
        /// Max analysis rounds (default: 3)
        #[arg(long, default_value = "3")]
        max_rounds: u32,
        /// Files per round (default: 5)
        #[arg(long, default_value = "5")]
        files_per_round: usize,
        /// Min new findings to continue (default: 2)
        #[arg(long, default_value = "2")]
        min_delta: u32,
        /// Custom prompt (overrides the default audit prompt)
        #[arg(long)]
        prompt: Option<String>,
        /// Allow write operations in the project directory
        #[arg(long)]
        writable: bool,
        /// Additional directories to allow reading (can be repeated)
        #[arg(long = "allow-read")]
        allow_read: Vec<String>,
        /// Additional directories to allow writing (can be repeated)
        #[arg(long = "allow-write")]
        allow_write: Vec<String>,
    },
}

#[derive(Subcommand)]
pub(crate) enum ConfigAction {
    /// Import MCP server configs from Claude Desktop, VS Code, or Codex
    ImportMcp {
        /// Path to config file (auto-detects format)
        path: Option<String>,
        /// Auto-discover config files in standard locations
        #[arg(long)]
        discover: bool,
        /// Show secret values instead of redacting them
        #[arg(long)]
        no_redact: bool,
    },
    /// List installed operator libraries and what they provide
    ListLibraries {
        /// Path to config file
        #[arg(short, long)]
        config: Option<String>,
    },
    /// Export config as JSON (for TOML→JSON migration)
    Export {
        /// Source config file (default: auto-detect)
        #[arg(short, long)]
        input: Option<String>,
        /// Output JSON file (default: ~/.config/navra/config.json)
        #[arg(short, long)]
        output: Option<String>,
    },
}

#[derive(Subcommand)]
pub(crate) enum AgentAction {
    /// Install an agent bundle from an OCI registry or local directory
    Install {
        /// OCI reference (e.g., oci://quay.io/navra/agent:v1) or local directory path
        oci_ref: String,
        /// Skip signature verification for this install
        #[arg(long)]
        allow_unsigned: bool,
        /// Permission set to check against (uses its rules as max allowed)
        #[arg(long)]
        max_permissions: Option<String>,
    },
    /// Inspect an agent bundle without installing
    Inspect {
        /// OCI reference
        oci_ref: String,
    },
    /// Initialize an agent instance from an installed bundle
    Init {
        /// Bundle name (must be installed)
        bundle: String,
        /// Instance name (defaults to bundle name)
        #[arg(long)]
        name: Option<String>,
    },
    /// Upgrade an installed agent bundle to a new version
    Upgrade {
        /// Bundle name or OCI reference
        bundle: String,
        /// Skip signature verification
        #[arg(long)]
        allow_unsigned: bool,
    },
    /// List installed agent bundles and instances
    List,
    /// Remove an installed agent bundle
    Remove {
        /// Agent name
        name: String,
    },
    /// Run an agent task against a running navra instance
    Run {
        /// Prompt for the agent
        prompt: String,
        /// Model to use (default: auto-detect from Ollama)
        #[arg(short, long)]
        model: Option<String>,
        /// Persona to use (default: leader)
        #[arg(short, long, default_value = "leader")]
        persona: String,
        /// navra endpoint URL
        #[arg(short, long, default_value = "http://127.0.0.1:9315/mcp")]
        endpoint: String,
        /// Auth token (reads from MCPD_TOKEN env if not set)
        #[arg(short, long)]
        token: Option<String>,
        /// Max iterations (default 200, set lower for quick tasks)
        #[arg(short = 'n', long, default_value = "200")]
        max_iterations: usize,
        /// Inject an upstream MCP prompt into the system prompt.
        /// Format: "upstream:prompt_name" (e.g., "syllogis:legal_analysis").
        #[arg(long = "upstream-prompt")]
        upstream_prompts: Vec<String>,
        /// Run a named workflow from an agent instance
        #[arg(long)]
        workflow: Option<String>,
        /// Path to agent instance config
        #[arg(long)]
        config: Option<String>,
        /// Force Ollama API even when local GGUF blob exists
        #[arg(long)]
        no_embedded: bool,
        /// Preview the constructed prompt without executing
        #[arg(long)]
        dry_run: bool,
    },
}

#[derive(Subcommand)]
pub(crate) enum ModelAction {
    /// Start a standalone model inference server
    Serve {
        /// Path to config file
        #[arg(short, long)]
        config: Option<String>,
        /// Bind address
        #[arg(short, long, default_value = "127.0.0.1:9316")]
        bind: String,
        /// Auto-detect hardware and propose resource allocation
        #[arg(long)]
        auto: bool,
        /// Maximum VRAM budget (e.g., 24GB, 16GB)
        #[arg(long)]
        budget: Option<String>,
    },
    /// Download a model from HuggingFace
    Pull {
        /// Model name (e.g., guardian-hap, granite-embed)
        name: String,
    },
    /// List installed models
    List,
    /// Show available models for download
    Available,
}

#[derive(Subcommand)]
pub(crate) enum PiiAction {
    /// Download a NER model for semantic PII detection
    Download {
        /// Download the multilingual model (xlm-roberta-base-ner-hrl) instead
        /// of the default English-only protectai/bert-base-NER model.
        /// Covers French, German, Spanish, Italian, Portuguese, Dutch, and more.
        #[arg(long)]
        multilingual: bool,
    },
    /// Check if the PII NER model is installed
    Status,
}

#[derive(Subcommand)]
pub(crate) enum PolicyAction {
    /// Generate policy suggestions from audit denials
    Suggest {
        /// Only include denials from the last N hours (default: 24)
        #[arg(long, default_value = "24")]
        hours: u64,
        /// Output format: cedar, toml, or both
        #[arg(long, default_value = "cedar")]
        format: String,
        /// Path to blackbox database (default: ~/.local/share/navra/blackbox.db)
        #[arg(long)]
        db: Option<String>,
        /// Filter by agent name
        #[arg(long)]
        agent: Option<String>,
        /// Minimum denial count to suggest a rule (default: 2)
        #[arg(long, default_value = "3")]
        min_count: usize,
    },
}

#[derive(Subcommand)]
pub(crate) enum EvalAction {
    /// Run AgentDojo IFC defense benchmark (requires agentdojo Python package)
    AgentDojo {
        /// Max user tasks to evaluate
        #[arg(long, default_value = "5")]
        tasks: usize,
        /// AgentDojo task suite
        #[arg(long, default_value = "workspace")]
        suite: String,
        /// LLM model to use (e.g., claude-sonnet-4-6@default, qwen3:8b)
        #[arg(short, long, default_value = "claude-sonnet-4-6@default")]
        model: String,
        /// Defense to test: none, ifc, or both
        #[arg(long, default_value = "both")]
        defense: String,
        /// Attack type
        #[arg(long, default_value = "important_instructions")]
        attack: String,
        /// Output JSON file path
        #[arg(short, long)]
        output: Option<String>,
        /// Python interpreter to use
        #[arg(long, default_value = "python3")]
        python: String,
    },
    /// Run MCPTox tool poisoning detection benchmark
    McpTox {
        /// Path to MCPTox dataset directory (default: /tmp/mcptox)
        #[arg(long, default_value = "/tmp/mcptox")]
        dataset: String,
        /// Output JSON file path
        #[arg(short, long)]
        output: Option<String>,
    },
    /// Generate a markdown comparison report from eval result files
    Report {
        /// Result JSON files to compare
        #[arg(required = true)]
        files: Vec<String>,
        /// Output markdown file (prints to stdout if omitted)
        #[arg(short, long)]
        output: Option<String>,
    },
}

#[derive(Subcommand)]
pub(crate) enum TokenAction {
    /// Generate a new agent token
    Generate {
        #[arg(short, long)]
        name: String,
        #[arg(short, long)]
        permissions: String,
    },
    /// List registered agents
    List,
}

#[derive(Subcommand)]
pub(crate) enum McpAction {
    /// Start the MCP gateway server
    Serve {
        /// Path to config file
        #[arg(short, long)]
        config: Option<String>,
        /// Disable system tray icon
        #[arg(long)]
        no_tray: bool,
        /// Enable anonymous access (dev only — do not use in production)
        #[arg(long)]
        dev_mode: bool,
    },
    /// Run as a stdio MCP server (for Claude Desktop, Cursor, etc.)
    Stdio {
        /// Path to config file
        #[arg(short, long)]
        config: Option<String>,
    },
}

#[derive(Subcommand)]
pub(crate) enum FlowAction {
    /// Execute a flow YAML file
    Run {
        /// Path to the flow YAML file
        file: String,
        /// Prompt / input for the flow
        #[arg(short, long, default_value = "")]
        prompt: String,
        /// navra endpoint URL
        #[arg(short, long, default_value = "http://127.0.0.1:9315/mcp")]
        endpoint: String,
        /// Auth token (reads from MCPD_TOKEN env if not set)
        #[arg(short, long)]
        token: Option<String>,
        /// Model to use
        #[arg(short, long)]
        model: Option<String>,
    },
    /// List available flows from configured directories and agent instances
    List {
        /// Path to config file
        #[arg(short, long)]
        config: Option<String>,
    },
    /// Manage flow triggers (cron, webhook, file-watch)
    Trigger {
        #[command(subcommand)]
        action: TriggerAction,
    },
}

#[derive(Subcommand)]
pub(crate) enum TriggerAction {
    /// Start the trigger engine (loads triggers from config and agent instances)
    Start {
        /// Path to config file
        #[arg(short, long)]
        config: Option<String>,
    },
    /// List configured triggers from config and agent instances
    List {
        /// Path to config file
        #[arg(short, long)]
        config: Option<String>,
    },
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    #[test]
    fn cli_run_upstream_prompt_flag() {
        let cli = Cli::try_parse_from([
            "navra",
            "run",
            "Analyze this case",
            "--upstream-prompt",
            "syllogis:legal_analysis",
            "--upstream-prompt",
            "syllogis:legal_syllogism",
        ])
        .unwrap();

        match cli.command {
            Commands::Run {
                upstream_prompts, ..
            } => {
                assert_eq!(upstream_prompts.len(), 2);
                assert_eq!(upstream_prompts[0], "syllogis:legal_analysis");
                assert_eq!(upstream_prompts[1], "syllogis:legal_syllogism");
            }
            _ => panic!("Expected Run command"),
        }
    }

    #[test]
    fn cli_run_no_upstream_prompt() {
        let cli = Cli::try_parse_from(["navra", "run", "Do something"]).unwrap();

        match cli.command {
            Commands::Run {
                upstream_prompts, ..
            } => {
                assert!(upstream_prompts.is_empty());
            }
            _ => panic!("Expected Run command"),
        }
    }

    #[test]
    fn cli_init_default() {
        let cli = Cli::try_parse_from(["navra", "init"]).unwrap();
        match cli.command {
            Commands::Init {
                quiet,
                safety,
                project,
                model,
                dry_run,
                ..
            } => {
                assert!(!quiet);
                assert_eq!(safety, "standard");
                assert_eq!(project, "dev");
                assert_eq!(model, "none");
                assert!(!dry_run);
            }
            _ => panic!("Expected Init command"),
        }
    }

    #[test]
    fn cli_init_quiet() {
        let cli = Cli::try_parse_from([
            "navra",
            "init",
            "--quiet",
            "--agent-name",
            "foo",
            "--project",
            "data",
            "--safety",
            "strict",
            "--model",
            "ollama",
            "--dry-run",
        ])
        .unwrap();
        match cli.command {
            Commands::Init {
                quiet,
                agent_name,
                safety,
                project,
                model,
                dry_run,
                ..
            } => {
                assert!(quiet);
                assert_eq!(agent_name.as_deref(), Some("foo"));
                assert_eq!(safety, "strict");
                assert_eq!(project, "data");
                assert_eq!(model, "ollama");
                assert!(dry_run);
            }
            _ => panic!("Expected Init command"),
        }
    }

    #[test]
    fn cli_pii_download_default() {
        let cli = Cli::try_parse_from(["navra", "pii", "download"]).unwrap();
        match cli.command {
            Commands::Pii {
                action: PiiAction::Download { multilingual },
            } => {
                assert!(!multilingual);
            }
            _ => panic!("Expected Pii Download command"),
        }
    }

    #[test]
    fn cli_pii_download_multilingual() {
        let cli = Cli::try_parse_from(["navra", "pii", "download", "--multilingual"]).unwrap();
        match cli.command {
            Commands::Pii {
                action: PiiAction::Download { multilingual },
            } => {
                assert!(multilingual);
            }
            _ => panic!("Expected Pii Download command"),
        }
    }

    #[test]
    fn cli_eval_agentdojo_default() {
        let cli = Cli::try_parse_from(["navra", "eval", "agent-dojo"]).unwrap();
        match cli.command {
            Commands::Eval {
                action:
                    EvalAction::AgentDojo {
                        tasks,
                        suite,
                        model,
                        defense,
                        ..
                    },
            } => {
                assert_eq!(tasks, 5);
                assert_eq!(suite, "workspace");
                assert_eq!(model, "claude-sonnet-4-6@default");
                assert_eq!(defense, "both");
            }
            _ => panic!("Expected Eval AgentDojo command"),
        }
    }

    #[test]
    fn cli_eval_mcptox_default() {
        let cli = Cli::try_parse_from(["navra", "eval", "mcp-tox"]).unwrap();
        match cli.command {
            Commands::Eval {
                action: EvalAction::McpTox { dataset, output },
            } => {
                assert_eq!(dataset, "/tmp/mcptox");
                assert!(output.is_none());
            }
            _ => panic!("Expected Eval McpTox command"),
        }
    }

    #[test]
    fn cli_eval_report() {
        let cli =
            Cli::try_parse_from(["navra", "eval", "report", "a.json", "b.json", "-o", "out.md"])
                .unwrap();
        match cli.command {
            Commands::Eval {
                action: EvalAction::Report { files, output },
            } => {
                assert_eq!(files, vec!["a.json", "b.json"]);
                assert_eq!(output.as_deref(), Some("out.md"));
            }
            _ => panic!("Expected Eval Report command"),
        }
    }

    #[test]
    fn cli_mcp_serve() {
        let cli = Cli::try_parse_from(["navra", "mcp", "serve", "--no-tray"]).unwrap();
        match cli.command {
            Commands::Mcp {
                action: McpAction::Serve { no_tray, dev_mode, .. },
            } => {
                assert!(no_tray);
                assert!(!dev_mode);
            }
            _ => panic!("Expected Mcp Serve command"),
        }
    }

    #[test]
    fn cli_mcp_stdio() {
        let cli = Cli::try_parse_from(["navra", "mcp", "stdio"]).unwrap();
        assert!(matches!(
            cli.command,
            Commands::Mcp {
                action: McpAction::Stdio { .. }
            }
        ));
    }

    #[test]
    fn cli_agent_run() {
        let cli = Cli::try_parse_from(["navra", "agent", "run", "hello world"]).unwrap();
        match cli.command {
            Commands::Agent {
                action: AgentAction::Run { prompt, persona, max_iterations, .. },
            } => {
                assert_eq!(prompt, "hello world");
                assert_eq!(persona, "leader");
                assert_eq!(max_iterations, 200);
            }
            _ => panic!("Expected Agent Run command"),
        }
    }

    #[test]
    fn cli_flow_run() {
        let cli =
            Cli::try_parse_from(["navra", "flow", "run", "review.yaml", "-p", "check this"])
                .unwrap();
        match cli.command {
            Commands::Flow {
                action: FlowAction::Run { file, prompt, .. },
            } => {
                assert_eq!(file, "review.yaml");
                assert_eq!(prompt, "check this");
            }
            _ => panic!("Expected Flow Run command"),
        }
    }

    #[test]
    fn cli_flow_list() {
        let cli = Cli::try_parse_from(["navra", "flow", "list"]).unwrap();
        assert!(matches!(
            cli.command,
            Commands::Flow {
                action: FlowAction::List { .. }
            }
        ));
    }

    #[test]
    fn cli_flow_trigger_list() {
        let cli = Cli::try_parse_from(["navra", "flow", "trigger", "list"]).unwrap();
        assert!(matches!(
            cli.command,
            Commands::Flow {
                action: FlowAction::Trigger {
                    action: TriggerAction::List { .. }
                }
            }
        ));
    }

    #[test]
    fn cli_flow_trigger_start() {
        let cli = Cli::try_parse_from(["navra", "flow", "trigger", "start"]).unwrap();
        assert!(matches!(
            cli.command,
            Commands::Flow {
                action: FlowAction::Trigger {
                    action: TriggerAction::Start { .. }
                }
            }
        ));
    }

    #[test]
    fn cli_deprecated_serve_still_parses() {
        let cli = Cli::try_parse_from(["navra", "serve", "--no-tray"]).unwrap();
        assert!(matches!(cli.command, Commands::Serve { .. }));
    }

    #[test]
    fn cli_deprecated_run_still_parses() {
        let cli = Cli::try_parse_from(["navra", "run", "do something"]).unwrap();
        assert!(matches!(cli.command, Commands::Run { .. }));
    }
}
