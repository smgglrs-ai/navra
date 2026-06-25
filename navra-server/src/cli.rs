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
#[command(name = "navra", about = "navra \u{2014} secure MCP gateway for AI agents", version)]
pub(crate) struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand)]
pub(crate) enum Commands {
    /// Start the MCP server
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
    },
    /// Run as a stdio MCP server (for Claude Desktop, Cursor, etc.)
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
        /// Fetched at runtime and appended after the persona's system prompt.
        /// Can be repeated.
        #[arg(long = "upstream-prompt")]
        upstream_prompts: Vec<String>,
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
}

#[derive(Subcommand)]
pub(crate) enum AgentAction {
    /// Install an agent bundle from an OCI registry
    Install {
        /// OCI reference (e.g., oci://quay.io/navra/agent:v1)
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
    /// List installed agent bundles
    List,
    /// Remove an installed agent bundle
    Remove {
        /// Agent name
        name: String,
    },
}

#[derive(Subcommand)]
pub(crate) enum ModelAction {
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

// --- Model management ---

/// A model entry loaded from models/registry.toml.
#[derive(Debug, serde::Deserialize)]
struct RegistryModel {
    name: String,
    description: String,
    repo: String,
    model_file: String,
    license: Option<String>,
    #[serde(default)]
    tokenizer: Option<String>,
    #[serde(default)]
    extra_files: Vec<String>,
    #[serde(default)]
    config: Option<String>,
}

#[derive(Debug, serde::Deserialize)]
struct ModelRegistry {
    models: Vec<RegistryModel>,
}

/// Load the model registry from TOML files.
///
/// Searches in order:
/// 1. `models/registry.toml` relative to the binary (shipped default)
/// 2. `~/.config/navra/models.toml` (user additions)
///
/// Both files are merged — user entries override defaults by name.
fn load_model_registry() -> Vec<RegistryModel> {
    let mut models = Vec::new();
    let mut seen = std::collections::HashSet::new();

    // Try shipped registry (next to the binary or in the repo)
    for path in &[
        std::path::PathBuf::from("models/registry.toml"),
        dirs::config_dir()
            .unwrap_or_default()
            .join("navra/models.toml"),
    ] {
        if let Ok(content) = std::fs::read_to_string(path) {
            match toml::from_str::<ModelRegistry>(&content) {
                Ok(reg) => {
                    for m in reg.models {
                        if seen.insert(m.name.clone()) {
                            models.push(m);
                        }
                    }
                }
                Err(e) => {
                    eprintln!("Warning: failed to parse {}: {e}", path.display());
                }
            }
        }
    }

    models
}

/// Get the models directory.
fn models_dir() -> std::path::PathBuf {
    dirs::data_dir()
        .unwrap_or_else(|| std::path::PathBuf::from("."))
        .join("navra/models")
}

/// Download a file from a URL to a local path with progress.
async fn download_file(url: &str, dest: &std::path::Path) -> anyhow::Result<()> {
    let client = reqwest::Client::new();
    let resp = client.get(url).send().await?;

    if !resp.status().is_success() {
        anyhow::bail!("Download failed: HTTP {}", resp.status());
    }

    let total = resp.content_length();
    let mut file = tokio::fs::File::create(dest).await?;
    let mut stream = resp.bytes_stream();

    use futures_util::StreamExt;
    use tokio::io::AsyncWriteExt;

    let mut downloaded: u64 = 0;
    while let Some(chunk) = stream.next().await {
        let chunk = chunk?;
        file.write_all(&chunk).await?;
        downloaded += chunk.len() as u64;
        if let Some(total) = total {
            eprint!(
                "\r  {:.1} / {:.1} MB",
                downloaded as f64 / 1_048_576.0,
                total as f64 / 1_048_576.0
            );
        } else {
            eprint!("\r  {:.1} MB", downloaded as f64 / 1_048_576.0);
        }
    }
    eprintln!();
    file.flush().await?;
    Ok(())
}

// --- Agent bundle commands ---

pub(crate) async fn agent_install(
    oci_ref: &str,
    allow_unsigned: bool,
    max_permissions: Option<&str>,
    cfg: &crate::config::Config,
) -> anyhow::Result<()> {
    use crate::agent_bundle::{compare, cosign, fetch, install, registry};

    let policy = if allow_unsigned {
        cosign::SignaturePolicy::Skip
    } else {
        cfg.server
            .agent_signature_policy
            .parse::<cosign::SignaturePolicy>()?
    };

    // Gate 1: signature verification
    let signed = cosign::verify_signature(oci_ref, policy).await?;

    // Fetch manifest
    let client = reqwest::Client::new();
    let manifest = fetch::fetch_agent_manifest(&client, oci_ref).await?;

    let token = crate::config::generate_token();
    let hash = navra_core::auth::TokenAuthenticator::hash_token(&token);

    match manifest {
        Some(manifest) => {
            println!("Agent: {} v{}", manifest.meta.name, manifest.meta.version);
            if let Some(publisher) = &manifest.meta.publisher {
                println!("Publisher: {publisher}");
            }
            if let Some(desc) = &manifest.meta.description {
                println!("Description: {desc}");
            }
            println!("Signed: {signed}");
            println!();

            // Gate 2: permission check
            let max_policy = match max_permissions {
                Some(name) => cfg.permissions.get(name).ok_or_else(|| {
                    anyhow::anyhow!("permission set {name:?} not found in config")
                })?,
                None => &crate::config::PermissionSet::default(),
            };

            let diff = compare::compare_permissions(&manifest.permissions, max_policy);
            if !diff.allowed {
                println!("{diff}");
                anyhow::bail!(
                    "Installation aborted — bundle permissions exceed operator policy.\n\
                     Use --max-permissions to specify a more permissive policy, or adjust your config."
                );
            }

            let snippet = install::generate_config_snippet(&manifest, oci_ref, &token, &hash);
            println!("Add to config.toml:\n");
            println!("{snippet}");

            registry::save(&registry::InstalledAgent {
                name: manifest.meta.name.clone(),
                version: manifest.meta.version.clone(),
                publisher: manifest.meta.publisher.clone(),
                oci_ref: oci_ref.to_string(),
                installed_at: {
                    use std::time::SystemTime;
                    let d = SystemTime::now()
                        .duration_since(SystemTime::UNIX_EPOCH)
                        .unwrap_or_default();
                    format!("{}", d.as_secs())
                },
                signed,
            })?;

            if let Some(image) = &manifest.image {
                println!("\nPull container image:");
                println!("  podman pull {image}");
            }
        }
        None => {
            eprintln!("warning: no agent manifest found for {oci_ref}");
            eprintln!("Generating skeleton config — configure permissions manually.\n");
            let snippet = install::generate_skeleton_config(oci_ref, &token, &hash);
            println!("Add to config.toml:\n");
            println!("{snippet}");
        }
    }

    Ok(())
}

pub(crate) async fn agent_inspect(oci_ref: &str) -> anyhow::Result<()> {
    use crate::agent_bundle::fetch;

    let client = reqwest::Client::new();
    let manifest = fetch::fetch_agent_manifest(&client, oci_ref).await?;

    match manifest {
        Some(manifest) => {
            println!("{}", serde_json::to_string_pretty(&manifest)?);
        }
        None => {
            println!("No agent manifest found for {oci_ref}");
        }
    }

    Ok(())
}

pub(crate) fn agent_list() -> anyhow::Result<()> {
    use crate::agent_bundle::registry;

    let agents = registry::list()?;
    if agents.is_empty() {
        println!("No agent bundles installed.");
        return Ok(());
    }

    println!(
        "{:<20} {:<10} {:<15} {:<6} {}",
        "NAME", "VERSION", "PUBLISHER", "SIGNED", "OCI REF"
    );
    println!(
        "{:<20} {:<10} {:<15} {:<6} {}",
        "----", "-------", "---------", "------", "-------"
    );
    for agent in &agents {
        println!(
            "{:<20} {:<10} {:<15} {:<6} {}",
            agent.name,
            agent.version,
            agent.publisher.as_deref().unwrap_or("-"),
            if agent.signed { "yes" } else { "no" },
            agent.oci_ref,
        );
    }

    Ok(())
}

pub(crate) fn agent_remove(name: &str) -> anyhow::Result<()> {
    use crate::agent_bundle::registry;

    if registry::remove(name)? {
        println!("Removed agent bundle: {name}");
        println!("Note: config.toml entries for this agent must be removed manually.");
    } else {
        println!("No installed agent bundle named {name:?}.");
    }

    Ok(())
}

/// Pull a model by name or URI.
///
/// Accepts known model names (guardian-hap, granite-embed) for ONNX models,
/// or any hub URI (ollama://, hf://, oci://, file://) for general models.
pub(crate) async fn model_pull(name: &str) -> anyhow::Result<()> {
    // Check the model registry first
    let registry = load_model_registry();
    if let Some(model) = registry.iter().find(|m| m.name == name) {
        let model_dir = models_dir().join(&model.name);
        std::fs::create_dir_all(&model_dir)?;

        if let Some(license) = &model.license {
            println!("License: {license}");
        }
        println!("Pulling {} ...", model.description);

        // Download main model file
        let model_url = format!(
            "https://huggingface.co/{}/resolve/main/{}",
            model.repo, model.model_file
        );
        let dest_name = if model.model_file.ends_with(".gguf") {
            "model.gguf"
        } else {
            "model.onnx"
        };
        let model_dest = model_dir.join(dest_name);
        if model_dest.exists() {
            println!("  {dest_name} already exists, skipping");
        } else {
            println!("  Downloading {dest_name} ...");
            download_file(&model_url, &model_dest).await?;
        }

        // Download tokenizer if specified
        if let Some(tok_file) = &model.tokenizer {
            let tok_url = format!(
                "https://huggingface.co/{}/resolve/main/{}",
                model.repo, tok_file
            );
            let tok_dest = model_dir.join("tokenizer.json");
            if tok_dest.exists() {
                println!("  tokenizer.json already exists, skipping");
            } else {
                println!("  Downloading tokenizer.json ...");
                download_file(&tok_url, &tok_dest).await?;
            }
        }

        // Download extra files
        for extra in &model.extra_files {
            let extra_url = format!(
                "https://huggingface.co/{}/resolve/main/{}",
                model.repo, extra
            );
            let extra_dest = model_dir.join(extra);
            if extra_dest.exists() {
                println!("  {extra} already exists, skipping");
            } else {
                println!("  Downloading {extra} ...");
                download_file(&extra_url, &extra_dest).await?;
            }
        }

        println!("\nInstalled to: {}", model_dir.display());
        if let Some(config) = &model.config {
            let snippet = config.replace("{model_dir}", &model_dir.to_string_lossy());
            println!("\n{snippet}");
        }
        return Ok(());
    }

    // Otherwise, treat as a hub URI
    let uri = navra_model_hub::ModelUri::parse(name)?;
    let hub = navra_model_hub::ModelHub::new()?;

    println!("Pulling {uri} ...");
    let path = hub.pull(&uri).await?;
    println!("\nCached at: {}", path.display());
    println!("\nAdd to config.toml:\n");
    println!("[models.{}]", uri.cache_key());
    println!("source = \"{}\"", uri);
    println!("task = \"chat\"");
    println!("runtime = \"auto\"  # auto, llama-cpp, llama-cpp-podman, vllm, vllm-podman, llama-cpp-openshell, vllm-openshell, none");
    println!("# format = \"gguf\"  # gguf, safetensors, awq, gptq (auto-detected if omitted)");

    Ok(())
}

/// List installed models (ONNX + hub-cached).
pub(crate) fn model_list() -> anyhow::Result<()> {
    let mut found = false;

    // ONNX models in the legacy directory
    let dir = models_dir();
    if dir.exists() {
        for entry in std::fs::read_dir(&dir)? {
            let entry = entry?;
            if entry.file_type()?.is_dir() {
                let name = entry.file_name();
                let name = name.to_string_lossy();
                let model_path = entry.path().join("model.onnx");
                let has_model = model_path.exists();
                let has_tokenizer = entry.path().join("tokenizer.json").exists();
                let size = if has_model {
                    let meta = std::fs::metadata(&model_path)?;
                    format!("{:.1} MB", meta.len() as f64 / 1_048_576.0)
                } else {
                    "incomplete".to_string()
                };

                let tok_status = if has_tokenizer { "yes" } else { "no" };
                println!("{name:<40} {size:<12} onnx  tokenizer: {tok_status}");
                found = true;
            }
        }
    }

    // Hub-cached models
    if let Ok(hub) = navra_model_hub::ModelHub::new() {
        if let Ok(cached) = hub.list() {
            for model in cached {
                let size = format!("{:.1} MB", model.size as f64 / 1_048_576.0);
                println!("{:<40} {size:<12} hub", model.uri);
                found = true;
            }
        }
    }

    if !found {
        println!("No models installed.");
        println!("Run 'navra model available' to see supported models.");
        println!("Or pull any model: navra model pull ollama://granite3.3:8b");
    }

    Ok(())
}

// --- PII NER model management ---

const PII_NER_REPO: &str = "protectai/bert-base-NER-onnx";
const PII_NER_MODEL_FILE: &str = "model.onnx";
const PII_NER_TOKENIZER_FILE: &str = "tokenizer.json";

const PII_NER_MULTILINGUAL_REPO: &str = "tjruesch/xlm-roberta-base-ner-hrl-onnx";
const PII_NER_MULTILINGUAL_MODEL_FILE: &str = "onnx/model.onnx";
const PII_NER_MULTILINGUAL_TOKENIZER_FILE: &str = "tokenizer.json";
const PII_NER_MULTILINGUAL_LABEL_MAP_FILE: &str = "label_map.json";

/// Download a NER model for semantic PII detection.
///
/// With `multilingual = false` (default): downloads protectai/bert-base-NER-onnx
/// (English-only, faster, smaller).
///
/// With `multilingual = true`: downloads tjruesch/xlm-roberta-base-ner-hrl-onnx
/// (10+ languages including French, German, Spanish).
pub(crate) async fn pii_download(multilingual: bool) -> anyhow::Result<()> {
    if multilingual {
        return pii_download_multilingual().await;
    }
    pii_download_english().await
}

/// Download the protectai/bert-base-NER-onnx model for semantic PII detection.
///
/// This model (dslim/bert-base-NER converted to ONNX by ProtectAI) detects
/// PERSON, LOCATION, ORGANIZATION, and MISC entities in natural language.
async fn pii_download_english() -> anyhow::Result<()> {
    let model_dir = super::config::default_pii_model_dir("pii-ner");
    std::fs::create_dir_all(&model_dir)?;

    println!("Pulling protectai/bert-base-NER-onnx — semantic PII detection (PER, LOC, ORG, MISC)");

    // Download model.onnx
    let model_dest = model_dir.join("model.onnx");
    if model_dest.exists() {
        println!("  model.onnx already exists, skipping");
    } else {
        let model_url = format!(
            "https://huggingface.co/{}/resolve/main/{}",
            PII_NER_REPO, PII_NER_MODEL_FILE
        );
        println!("  Downloading model.onnx ...");
        download_file(&model_url, &model_dest).await?;
    }

    // Download tokenizer.json
    let tok_dest = model_dir.join("tokenizer.json");
    if tok_dest.exists() {
        println!("  tokenizer.json already exists, skipping");
    } else {
        let tok_url = format!(
            "https://huggingface.co/{}/resolve/main/{}",
            PII_NER_REPO, PII_NER_TOKENIZER_FILE
        );
        println!("  Downloading tokenizer.json ...");
        download_file(&tok_url, &tok_dest).await?;
    }

    println!("\nInstalled to: {}", model_dir.display());
    println!("\nThe PII NER model will be automatically loaded on next server start.");
    println!("You can also set the path explicitly in config.toml:");
    println!("\n[server]");
    println!("pii_model_path = \"{}\"", model_dir.display());

    Ok(())
}

/// Download the multilingual NER model for semantic PII detection.
///
/// Uses tjruesch/xlm-roberta-base-ner-hrl-onnx, an ONNX conversion
/// of Davlan/xlm-roberta-base-ner-hrl. Covers 10+ languages including
/// English, French, German, Spanish, Italian, Portuguese, and Dutch.
pub(crate) async fn pii_download_multilingual() -> anyhow::Result<()> {
    let model_dir = super::config::default_pii_model_dir("pii-ner-multilingual");
    std::fs::create_dir_all(&model_dir)?;

    println!(
        "Pulling tjruesch/xlm-roberta-base-ner-hrl-onnx — multilingual NER (PER, LOC, ORG, DATE)"
    );
    println!("Languages: English, French, German, Spanish, Italian, Portuguese, Dutch, and more");

    // Download model.onnx (from onnx/ subdirectory in the repo)
    let model_dest = model_dir.join("model.onnx");
    if model_dest.exists() {
        println!("  model.onnx already exists, skipping");
    } else {
        let model_url = format!(
            "https://huggingface.co/{}/resolve/main/{}",
            PII_NER_MULTILINGUAL_REPO, PII_NER_MULTILINGUAL_MODEL_FILE
        );
        println!("  Downloading model.onnx ...");
        download_file(&model_url, &model_dest).await?;
    }

    // Download tokenizer.json
    let tok_dest = model_dir.join("tokenizer.json");
    if tok_dest.exists() {
        println!("  tokenizer.json already exists, skipping");
    } else {
        let tok_url = format!(
            "https://huggingface.co/{}/resolve/main/{}",
            PII_NER_MULTILINGUAL_REPO, PII_NER_MULTILINGUAL_TOKENIZER_FILE
        );
        println!("  Downloading tokenizer.json ...");
        download_file(&tok_url, &tok_dest).await?;
    }

    // Download label_map.json
    let label_dest = model_dir.join("label_map.json");
    if label_dest.exists() {
        println!("  label_map.json already exists, skipping");
    } else {
        let label_url = format!(
            "https://huggingface.co/{}/resolve/main/{}",
            PII_NER_MULTILINGUAL_REPO, PII_NER_MULTILINGUAL_LABEL_MAP_FILE
        );
        println!("  Downloading label_map.json ...");
        download_file(&label_url, &label_dest).await?;
    }

    println!("\nInstalled to: {}", model_dir.display());
    println!("\nThe multilingual NER model will be automatically loaded on next server start.");
    println!("When both models are installed, the multilingual model is preferred.");
    println!("You can also set the path explicitly in config.toml:");
    println!("\n[server]");
    println!("pii_multilingual_model_path = \"{}\"", model_dir.display());

    Ok(())
}

/// Check if the PII NER model is installed.
pub(crate) fn pii_status() {
    // English model (protectai)
    let model_dir = super::config::default_pii_model_dir("pii-ner");
    let has_model = model_dir.join("model.onnx").exists();
    let has_tokenizer = model_dir.join("tokenizer.json").exists();

    println!("English NER:  protectai/bert-base-NER-onnx");
    println!("Directory:    {}", model_dir.display());

    if has_model && has_tokenizer {
        let model_size = std::fs::metadata(model_dir.join("model.onnx"))
            .map(|m| format!("{:.1} MB", m.len() as f64 / 1_048_576.0))
            .unwrap_or_else(|_| "unknown".to_string());
        println!("Status:       installed ({model_size})");
        println!("Entities:     PER, LOC, ORG, MISC");
    } else {
        println!("Status:       not installed");
        if has_model && !has_tokenizer {
            println!("Detail:       model.onnx present, tokenizer.json missing");
        }
    }

    println!();

    // Multilingual model
    let ml_dir = super::config::default_pii_model_dir("pii-ner-multilingual");
    let ml_has_model = ml_dir.join("model.onnx").exists();
    let ml_has_tokenizer = ml_dir.join("tokenizer.json").exists();

    println!("Multilingual: tjruesch/xlm-roberta-base-ner-hrl-onnx");
    println!("Directory:    {}", ml_dir.display());

    if ml_has_model && ml_has_tokenizer {
        let model_size = std::fs::metadata(ml_dir.join("model.onnx"))
            .map(|m| format!("{:.1} MB", m.len() as f64 / 1_048_576.0))
            .unwrap_or_else(|_| "unknown".to_string());
        println!("Status:       installed ({model_size})");
        println!("Entities:     PER, LOC, ORG, DATE");
        println!("Languages:    EN, FR, DE, ES, IT, PT, NL, and more");
    } else {
        println!("Status:       not installed");
        if ml_has_model && !ml_has_tokenizer {
            println!("Detail:       model.onnx present, tokenizer.json missing");
        }
    }

    // Show install instructions if neither is installed
    if !has_model && !ml_has_model {
        println!();
        println!("Run 'navra pii download' for English-only (faster, smaller).");
        println!("Run 'navra pii download --multilingual' for multilingual support.");
    } else if !ml_has_model {
        println!();
        println!("Run 'navra pii download --multilingual' for multilingual support.");
    } else if !has_model {
        println!();
        println!("Run 'navra pii download' for the English-only model.");
    }
}

/// Show available models for download.
pub(crate) fn model_available() {
    let registry = load_model_registry();
    if registry.is_empty() {
        println!("No models in registry. Add entries to models/registry.toml");
        println!("or ~/.config/navra/models.toml");
    } else {
        println!("Available models (from models/registry.toml):");
        println!("{:<25} {:<15} DESCRIPTION", "NAME", "LICENSE");
        println!("{:<25} {:<15} -----------", "----", "-------");
        for model in &registry {
            let license = model.license.as_deref().unwrap_or("?");
            println!("{:<25} {:<15} {}", model.name, license, model.description);
        }
    }
    println!("\nPull a registry model:  navra model pull <name>");
    println!("\nYou can also pull any model by URI:");
    println!("  navra model pull ollama://granite3.3:8b");
    println!("  navra model pull hf://ibm-granite/granite-3.3-8b-instruct-GGUF");
    println!("  navra model pull oci://quay.io/myorg/mymodel:latest");
    println!("\nEdit models/registry.toml to add your own models.");
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
}
