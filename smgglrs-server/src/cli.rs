use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "smgglrs", about = "Composable MCP server")]
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
    /// Install systemd user units and enable the service
    Install,
    /// Uninstall systemd user units
    Uninstall,
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
    /// Run an agent task against a running smgglrs instance
    Run {
        /// Prompt for the agent
        prompt: String,
        /// Model to use (default: auto-detect from Ollama)
        #[arg(short, long)]
        model: Option<String>,
        /// Persona to use (default: leader)
        #[arg(long, default_value = "leader")]
        persona: String,
        /// smgglrs endpoint URL
        #[arg(long, default_value = "http://127.0.0.1:9315/mcp")]
        endpoint: String,
        /// Auth token (reads from MCPD_TOKEN env if not set)
        #[arg(long)]
        token: Option<String>,
        /// Max iterations (default 200, set lower for quick tasks)
        #[arg(long, default_value = "200")]
        max_iterations: usize,
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

/// A known model in the registry.
struct KnownModel {
    /// Short name for CLI use.
    name: &'static str,
    /// Description.
    description: &'static str,
    /// HuggingFace repo ID.
    repo: &'static str,
    /// ONNX model filename within the repo.
    model_file: &'static str,
    /// Tokenizer filename (if any).
    tokenizer_file: Option<&'static str>,
    /// Config snippet template.
    config_template: &'static str,
}

const KNOWN_MODELS: &[KnownModel] = &[
    KnownModel {
        name: "guardian-hap",
        description: "Granite Guardian HAP 38M — fast safety classifier (Apache 2.0)",
        repo: "KantiArumilli/granite-guardian-hap-38m-onnx",
        model_file: "guardian_model_quantized.onnx",
        tokenizer_file: Some("tokenizer/tokenizer.json"),
        config_template: r#"[models.guardian-hap]
model_path = "{model_dir}/model.onnx"
tokenizer_path = "{model_dir}/tokenizer.json"
task = "classification"
labels = ["safe", "hap"]
threshold = 0.5"#,
    },
    KnownModel {
        name: "granite-embed",
        description: "Granite Embedding R2 — text embeddings, 768-dim (Apache 2.0)",
        repo: "yasserrmd/granite-embedding-r2-onnx",
        model_file: "model.onnx",
        tokenizer_file: Some("tokenizer.json"),
        config_template: r#"[models.granite-embed]
model_path = "{model_dir}/model.onnx"
tokenizer_path = "{model_dir}/tokenizer.json"
task = "embedding"
dimensions = 768"#,
    },
];

/// Get the models directory.
fn models_dir() -> std::path::PathBuf {
    dirs::data_dir()
        .unwrap_or_else(|| std::path::PathBuf::from("."))
        .join("smgglrs/models")
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

/// Pull a model by name or URI.
///
/// Accepts known model names (guardian-hap, granite-embed) for ONNX models,
/// or any hub URI (ollama://, hf://, oci://, file://) for general models.
pub(crate) async fn model_pull(name: &str) -> anyhow::Result<()> {
    // Check if it's a known ONNX model first
    if let Some(model) = KNOWN_MODELS.iter().find(|m| m.name == name) {
        let model_dir = models_dir().join(model.name);
        std::fs::create_dir_all(&model_dir)?;

        println!("Pulling {} ...", model.description);

        let model_url = format!(
            "https://huggingface.co/{}/resolve/main/{}",
            model.repo, model.model_file
        );
        let model_dest = model_dir.join("model.onnx");
        if model_dest.exists() {
            println!("  model.onnx already exists, skipping");
        } else {
            println!("  Downloading model.onnx ...");
            download_file(&model_url, &model_dest).await?;
        }

        if let Some(tok_file) = model.tokenizer_file {
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

        println!("\nInstalled to: {}", model_dir.display());
        println!("\nAdd to config.toml:\n");
        let config_snippet = model
            .config_template
            .replace("{model_dir}", &model_dir.to_string_lossy());
        println!("{config_snippet}");
        return Ok(());
    }

    // Otherwise, treat as a hub URI
    let uri = smgglrs_model_hub::ModelUri::parse(name)?;
    let hub = smgglrs_model_hub::ModelHub::new()?;

    println!("Pulling {uri} ...");
    let path = hub.pull(&uri).await?;
    println!("\nCached at: {}", path.display());
    println!("\nAdd to config.toml:\n");
    println!("[models.{}]", uri.cache_key());
    println!("source = \"{}\"", uri);
    println!("task = \"chat\"");
    println!("runtime = \"auto\"");

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
    if let Ok(hub) = smgglrs_model_hub::ModelHub::new() {
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
        println!("Run 'smgglrs model available' to see supported models.");
        println!("Or pull any model: smgglrs model pull ollama://granite3.3:8b");
    }

    Ok(())
}

/// Show available models for download.
pub(crate) fn model_available() {
    println!("Built-in ONNX models:");
    println!("{:<20} DESCRIPTION", "NAME");
    println!("{:<20} -----------", "----");
    for model in KNOWN_MODELS {
        println!("{:<20} {}", model.name, model.description);
    }
    println!("\nPull a built-in model:  smgglrs model pull <name>");
    println!("\nYou can also pull any model by URI:");
    println!("  smgglrs model pull ollama://granite3.3:8b");
    println!("  smgglrs model pull hf://ibm-granite/granite-3.3-8b-instruct-GGUF");
    println!("  smgglrs model pull oci://quay.io/myorg/mymodel:latest");
}
