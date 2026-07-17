// --- PII NER model management CLI commands ---

use crate::cmd_model::download_file;

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
    let model_dir = crate::config::default_pii_model_dir("pii-ner");
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
    let model_dir = crate::config::default_pii_model_dir("pii-ner-multilingual");
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
    let model_dir = crate::config::default_pii_model_dir("pii-ner");
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
    let ml_dir = crate::config::default_pii_model_dir("pii-ner-multilingual");
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
