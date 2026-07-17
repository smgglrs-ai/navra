// --- Model management CLI commands ---

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
pub(crate) async fn download_file(url: &str, dest: &std::path::Path) -> anyhow::Result<()> {
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
    println!(
        "runtime = \"auto\"  # auto, llama-cpp, llama-cpp-podman, vllm, vllm-podman, llama-cpp-openshell, vllm-openshell, none"
    );
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
    if let Ok(hub) = navra_model_hub::ModelHub::new()
        && let Ok(cached) = hub.list()
    {
        for model in cached {
            let size = format!("{:.1} MB", model.size as f64 / 1_048_576.0);
            println!("{:<40} {size:<12} hub", model.uri);
            found = true;
        }
    }

    if !found {
        println!("No models installed.");
        println!("Run 'navra model available' to see supported models.");
        println!("Or pull any model: navra model pull ollama://granite3.3:8b");
    }

    Ok(())
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
