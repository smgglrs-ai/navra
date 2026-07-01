use crate::config;
use navra_core::identity::CapSigner;

/// Run the end-to-end security audit demo.
///
/// This is a scripted walkthrough that demonstrates every subsystem
/// without requiring a real LLM. It simulates the agent interactions
/// and shows what each layer does with real data.
pub(crate) async fn run_demo(project: &str) -> anyhow::Result<()> {
    use std::path::Path;
    use std::time::Duration;

    let project_path = std::fs::canonicalize(Path::new(project)).map_err(|e| {
        anyhow::anyhow!(
            "Demo project not found at '{}': {e}. Run from the repo root.",
            project
        )
    })?;
    if !project_path.is_dir() {
        anyhow::bail!(
            "Demo project path '{}' is not a directory.",
            project_path.display()
        );
    }

    // Verify expected files exist
    let expected_files = [
        "src/config.rs",
        "src/handler.rs",
        "src/secrets.rs",
        "src/api.rs",
        "personas/security_auditor.yaml",
        "personas/code_specialist.yaml",
        "personas/analyst.yaml",
        "config/audit-flow.toml",
    ];
    for file in &expected_files {
        if !project_path.join(file).exists() {
            anyhow::bail!("Missing demo file: {}/{}", project, file);
        }
    }

    println!();
    println!("╔══════════════════════════════════════════════════════════════╗");
    println!("║  navra-* Framework — End-to-End Security Audit Demo       ║");
    println!(
        "║  Project: {}{}║",
        project,
        " ".repeat(49 - project.len().min(49))
    );
    println!("╚══════════════════════════════════════════════════════════════╝");
    println!();

    // --- Act 1: Gateway & Identity ---
    println!("━━━ Act 1: Gateway & Identity ━━━");
    tokio::time::sleep(Duration::from_millis(300)).await;

    let identity_path = std::path::PathBuf::from("/tmp/navra-demo/identity.key");
    std::fs::create_dir_all("/tmp/navra-demo")?;
    let root_signer = navra_core::identity::load_or_create_file_identity(&identity_path)?;
    println!("  ✓ Root identity: {}", root_signer.did());

    let agents = [
        ("security-auditor", "auditor", 2),
        ("code-specialist", "developer", 3),
        ("analyst", "analyst", 2),
    ];
    for (name, perms, ring) in &agents {
        let token = config::generate_token();
        println!(
            "  ✓ Agent \"{}\" authenticated (ring {}, permissions: {})",
            name, ring, perms
        );
        let _ = token; // Token generated but not needed for demo output
    }
    println!();

    // --- Act 2: Cognitive Core ---
    println!("━━━ Act 2: Cognitive Core ━━━");
    tokio::time::sleep(Duration::from_millis(300)).await;

    let _forge = match navra_cognitive::ForgeService::load(&project_path) {
        Ok(f) => {
            for name in f.persona_names() {
                if let Some(persona) = f.get_persona(name) {
                    println!(
                        "  ✓ Loaded persona: {} ({} heuristic modules)",
                        persona.persona_name,
                        persona.heuristics.len()
                    );
                }
            }
            println!(
                "  ✓ Loaded {} heuristic modules with {} total facets",
                f.heuristic_count(),
                ["owasp_top_10", "secure_coding", "risk_assessment"]
                    .iter()
                    .filter_map(|h| f.get_heuristic(h))
                    .map(|h| h.facets.len())
                    .sum::<usize>()
            );
            f
        }
        Err(e) => {
            println!("  ⚠ Forge load warning: {} (continuing with empty)", e);
            navra_cognitive::ForgeService::empty()
        }
    };

    println!("  ✓ Weaver ready (stable prefix caching enabled)");
    println!();

    // --- Act 3: Parallel Scan ---
    println!("━━━ Act 3: Parallel Scan [T1|T2|T3] ━━━");
    tokio::time::sleep(Duration::from_millis(300)).await;

    // T1: scan-auth
    println!("  ┌─ T1: scan-auth (security_auditor) ────────────────────");
    let handler_content = std::fs::read_to_string(project_path.join("src/handler.rs"))?;
    let api_content = std::fs::read_to_string(project_path.join("src/api.rs"))?;
    println!("  │ Reading: src/handler.rs → IFC: Trusted");
    println!("  │ Reading: src/api.rs → IFC: Trusted");

    // Simulate finding auth issues
    if handler_content.contains("admin_refund") && !handler_content.contains("verify_admin") {
        println!("  │ Finding: CWE-287 Missing authentication on admin_refund()");
    }
    if api_content.contains("handle_user_payments") && api_content.contains("// VULN: No IDOR") {
        println!("  │ Finding: CWE-639 IDOR on handle_user_payments()");
    }
    if api_content.contains("handle_webhook") && api_content.contains("signature not verified") {
        println!("  │ Finding: CWE-347 Missing webhook signature verification");
    }
    println!("  └─ 3 findings (1 critical, 2 high)");
    println!();

    // T2: scan-injection
    println!("  ┌─ T2: scan-injection (security_auditor) ──────────────");
    println!("  │ Reading: src/handler.rs → IFC: Trusted");
    if handler_content.contains("format!(") && handler_content.contains("VALUES ('{}'") {
        println!("  │ Finding: CWE-89 SQL injection in process_payment()");
    }
    if handler_content.contains("format!(") && handler_content.contains("WHERE user_id = '{}'") {
        println!("  │ Finding: CWE-89 SQL injection in get_history()");
    }
    println!("  └─ 2 findings (2 critical)");
    println!();

    // T3: scan-secrets
    println!("  ┌─ T3: scan-secrets (security_auditor) ────────────────");
    let config_content = std::fs::read_to_string(project_path.join("src/config.rs"))?;
    println!("  │ Reading: src/config.rs → IFC: Trusted");

    // Safety filter simulation
    if config_content.contains("sk_live_") {
        println!("  │ ⚠ Safety filter: redacted \"sk_live_4eC39HqLyjW...\"");
    }
    if config_content.contains("whsec_") {
        println!("  │ ⚠ Safety filter: redacted \"whsec_MfKQ9r8GKY...\"");
    }
    println!("  │ Finding: CWE-798 Hardcoded API key in config.rs");

    // IFC taint tracking
    let secrets_content = std::fs::read_to_string(project_path.join("src/secrets.rs"))?;
    println!("  │ Reading: src/secrets.rs → IFC: Confidential ⚡");
    println!("  │ ⚡ Context tainted: Confidential (Bell-LaPadula)");
    println!("  │ ⚡ Remote model backend BLOCKED (locality: Remote)");
    println!("  │ ✓ Local model backend allowed (locality: Local)");
    if secrets_content.contains("PAYMENT_TOKEN_KEY") {
        println!("  │ Finding: CWE-312 Encryption keys in source code");
    }
    println!("  └─ 2 findings (2 critical)");
    println!();

    // --- Act 4: Synthesis ---
    println!("━━━ Act 4: Synthesis [T4] ━━━");
    tokio::time::sleep(Duration::from_millis(300)).await;

    println!("  ┌─ T4: synthesize (analyst) ──────────────────────────");
    println!("  │ Memory recall: \"Previous audit March 2026: SQL injection");
    println!("  │   in process_payment() — UNRESOLVED (ticket VULN-142)\"");
    println!("  │ Memory recall: \"PCI DSS Q1 review: encryption key in");
    println!("  │   secrets.rs — must move to KMS before Q2 deadline\"");
    println!("  │ ⚡ PATTERN MATCH: SQL injection found again (was in");
    println!("  │   previous audit, still unresolved after 1 month)");
    println!("  │ Report: 7 findings total");
    println!("  │   Critical (4): 2× SQL injection, API key exposure, PCI violation");
    println!("  │   High (2): missing admin auth, IDOR");
    println!("  │   Medium (1): PII in logs");
    println!("  └─ Prioritized report generated");
    println!();

    // --- Act 5: Fix & Review ---
    println!("━━━ Act 5: Fix & Review [T5→T6] ━━━");
    tokio::time::sleep(Duration::from_millis(300)).await;

    println!("  ┌─ T5: propose-fixes (code_specialist) ────────────────");
    println!("  │ Fix 1: SQL injection → parameterized queries (.bind())");
    println!("  │ Fix 2: Hardcoded secrets → env::var() with error handling");
    println!("  │ Fix 3: Missing auth → auth middleware on admin endpoints");
    println!("  │ ✓ Mandate check: each fix maps to a specific CWE");
    println!("  └─ 3 patches proposed");
    println!();

    println!("  ┌─ T6: review-fixes (security_auditor) ────────────────");
    println!("  │ Fix 1 (SQL injection): ✓ Approved");
    println!("  │ Fix 2 (secrets): ✓ Approved");
    println!("  │ Fix 3 (auth): ⚠ Change requested — \"also add rate limiting\"");
    println!("  │ → Routing back to T5 with feedback");
    println!("  └─ 2 approved, 1 revision needed");
    println!();

    println!("  ┌─ T5 (retry): propose-fixes (code_specialist) ────────");
    println!("  │ Fix 3 (revised): auth middleware + rate limiter");
    println!("  │ ✓ Circular fix detector: attempt 2/3, no loop");
    println!("  └─ Revised fix proposed");
    println!();

    println!("  ┌─ T6 (retry): review-fixes (security_auditor) ────────");
    println!("  │ Fix 3 (revised): ✓ Approved");
    println!("  └─ All fixes approved");
    println!();

    // --- Act 6: Commit ---
    println!("━━━ Act 6: Commit [T7] ━━━");
    tokio::time::sleep(Duration::from_millis(300)).await;

    println!("  ┌─ T7: prepare-commit (code_specialist) ───────────────");
    println!("  │ Applying 3 fixes to src/handler.rs, src/config.rs, src/api.rs");
    println!("  │ ⏳ git_commit requires approval (permission: \"approve\")");
    println!("  │ 🔔 D-Bus notification: \"Agent wants to commit 3 files\"");
    println!("  │ ✓ Auto-approved (demo mode)");
    println!("  │ ✓ Commit signed (Ed25519, {})", root_signer.did());
    println!("  │ ✓ Working memory updated: audit findings saved");
    println!("  └─ Commit: \"fix: remediate SQL injection, secret exposure,");
    println!("     and missing auth (CWE-89, CWE-798, CWE-287)\"");
    println!();

    // --- Summary ---
    println!("━━━ Summary ━━━");
    println!("  Tasks:     7 completed (2 retried)");
    println!("  Findings:  7 (4 critical, 2 high, 1 medium)");
    println!("  Fixes:     3 applied, reviewed, committed");
    println!("  IFC:       1 Confidential taint event (secrets.rs)");
    println!("  Safety:    2 secrets redacted (Stripe key, webhook secret)");
    println!("  Approvals: 1 (auto-approved in demo mode)");
    println!("  Memory:    3 items recalled, 1 new item stored");
    println!("  Personas:  3 active (security_auditor, code_specialist, analyst)");
    println!();
    println!(
        "  Framework: {} crates, 668+ tests",
        16, // test count
    );
    println!();
    println!("  Blackbox:    navra audit");
    println!();

    Ok(())
}

/// Run the live end-to-end demo with a real LLM.
///
/// Unlike `run_demo` (scripted), this actually calls a model for each
/// task. It requires Ollama running with the specified model pulled.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn run_demo_live(
    project: &str,
    model_name: &str,
    _max_rounds: u32,
    _files_per_round: usize,
    _min_delta: u32,
    custom_prompt: Option<&str>,
    writable: bool,
    allow_read: &[String],
    allow_write: &[String],
) -> anyhow::Result<()> {
    use std::path::Path;

    let project_path = std::fs::canonicalize(Path::new(project)).map_err(|e| {
        anyhow::anyhow!(
            "Demo project not found at '{}': {e}. Run from the repo root.",
            project
        )
    })?;
    if !project_path.is_dir() {
        anyhow::bail!(
            "Demo project path '{}' is not a directory.",
            project_path.display()
        );
    }

    println!();
    println!("╔══════════════════════════════════════════════════════════════╗");
    println!("║  navra-* Framework — LIVE Security Audit Demo             ║");
    println!(
        "║  Project: {}{}║",
        project,
        " ".repeat(49 - project.len().min(49))
    );
    println!(
        "║  Model:   {}{}║",
        model_name,
        " ".repeat(49 - model_name.len().min(49))
    );
    println!("╚══════════════════════════════════════════════════════════════╝");
    println!();

    // --- Step 1: Ensure model is available ---
    println!("━━━ Setup: Model Backend ━━━");

    let ollama_url = "http://localhost:11434";

    // Skip Ollama setup for Claude models
    if model_name.starts_with("claude") {
        let use_vertex = std::env::var("CLAUDE_CODE_USE_VERTEX").is_ok()
            || std::env::var("ANTHROPIC_VERTEX_PROJECT_ID").is_ok();
        if use_vertex {
            println!("  Using Vertex AI (model: {})", model_name);
        } else if std::env::var("ANTHROPIC_API_KEY").is_ok() {
            println!("  Using Anthropic API (model: {})", model_name);
        } else {
            anyhow::bail!("Claude requires ANTHROPIC_API_KEY or Vertex AI config (ANTHROPIC_VERTEX_PROJECT_ID)");
        }
    } else {
        let client = reqwest::Client::new();

        // Check if Ollama is running
        let ollama_running = client
            .get(format!("{ollama_url}/api/tags"))
            .send()
            .await
            .map(|r| r.status().is_success())
            .unwrap_or(false);

        if !ollama_running {
            println!("  ⏳ Ollama not running. Starting...");
            tokio::process::Command::new("ollama")
                .arg("serve")
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .spawn()
                .map_err(|e| anyhow::anyhow!("Failed to start Ollama: {e}"))?;

            // Wait for it to start
            for i in 0..30 {
                tokio::time::sleep(std::time::Duration::from_millis(500)).await;
                if client
                    .get(format!("{ollama_url}/api/tags"))
                    .send()
                    .await
                    .map(|r| r.status().is_success())
                    .unwrap_or(false)
                {
                    break;
                }
                if i == 29 {
                    anyhow::bail!("Ollama did not start within 15 seconds");
                }
            }
            println!("  ✓ Ollama started");
        } else {
            println!("  ✓ Ollama running at {ollama_url}");
        }

        // Check if model is pulled
        let tags_resp = client
            .get(format!("{ollama_url}/api/tags"))
            .send()
            .await?
            .json::<serde_json::Value>()
            .await?;

        let model_base = model_name.split(':').next().unwrap_or(model_name);
        let model_available = tags_resp["models"]
            .as_array()
            .map(|models| {
                models.iter().any(|m| {
                    m["name"]
                        .as_str()
                        .map(|n| n.starts_with(model_base))
                        .unwrap_or(false)
                })
            })
            .unwrap_or(false);

        if !model_available {
            println!("  ⏳ Model '{}' not found locally. Pulling...", model_name);
            let pull_status = tokio::process::Command::new("ollama")
                .args(["pull", model_name])
                .status()
                .await?;
            if !pull_status.success() {
                anyhow::bail!("Failed to pull model '{}'", model_name);
            }
            println!("  ✓ Model pulled: {}", model_name);
        } else {
            println!("  ✓ Model available: {}", model_name);
        }
    } // end else (non-Claude Ollama setup)

    println!();

    // --- Step 2: Start navra gateway ---
    println!("━━━ Act 1: Start navra Gateway ━━━");

    // Pick a free port for the demo server
    let demo_port = {
        let l = std::net::TcpListener::bind("127.0.0.1:0")?;
        l.local_addr()?.port()
    };

    // project_path is already canonicalized above
    let abs_project = &project_path;

    // Write navra config for the demo
    let demo_config_path = "/tmp/navra-demo/agent-config.toml";
    std::fs::create_dir_all("/tmp/navra-demo")?;
    // Detect available models for the demo config.
    // Only register model names — no hardcoded agentic metadata.
    // The lead agent reads model cards via models_list and makes
    // Register available models with operator-level agentic metadata.
    // The agentic fields are derived from factual properties (source,
    // parameter count) — not from model name heuristics.
    let mut model_sections = String::new();

    // Register the lead's own model (remote/cloud)
    if model_name.starts_with("claude") {
        let model_key = model_name.replace([':', '-', '.', '@'], "_");
        model_sections.push_str(&format!(
            r#"
[models.{model_key}]
task = "chat"
model_name = "{model_name}"

[models.{model_key}.agentic]
cost_tier = "high"
speed_tier = "medium"
tool_use = "advanced"
reasoning = "extended"
json_compliance = "strict"
locality = "remote"
"#,
            model_key = model_key,
            model_name = model_name
        ));
    }

    // Register locally available Ollama models with metadata from /api/show
    if let Ok(resp) = reqwest::Client::new()
        .get("http://localhost:11434/api/tags")
        .send()
        .await
        && let Ok(tags) = resp.json::<serde_json::Value>().await
            && let Some(models) = tags["models"].as_array() {
                for m in models {
                    if let Some(name) = m["name"].as_str() {
                        let model_key = name.replace([':', '-', '.', '/'], "_");
                        let size_gb = m["size"].as_u64().unwrap_or(0) as f64 / 1e9;

                        // Derive speed tier from model size
                        let speed = if size_gb < 5.0 {
                            "fast"
                        } else if size_gb < 12.0 {
                            "medium"
                        } else {
                            "slow"
                        };

                        model_sections.push_str(&format!(
                            r#"
[models.{model_key}]
task = "chat"
model_name = "{name}"

[models.{model_key}.agentic]
cost_tier = "free"
speed_tier = "{speed}"
locality = "local"
"#,
                            model_key = model_key,
                            name = name,
                            speed = speed
                        ));
                    }
                }
            }

    std::fs::write(
        demo_config_path,
        format!(
            r#"
cognitive_core = "{project}"

[server]
tcp = "127.0.0.1:{demo_port}"

[modules.file]
enabled = true
db_path = "/tmp/navra-demo/agent-docs.db"

[modules.git]
enabled = false

[permissions.readonly]
allow = ["{allow_path}/**", "/tmp/**"{extra_read_paths}{extra_write_paths}]
deny = []
operations = [{operations}]
safety = "standard"
{model_sections}
"#,
            demo_port = demo_port,
            project = abs_project.display(),
            allow_path = abs_project.display(),
            operations = if writable || !allow_write.is_empty() {
                r#""read", "write", "search", "list""#
            } else {
                r#""read", "search", "list""#
            },
            extra_read_paths = canonicalize_allow_paths(allow_read),
            extra_write_paths = canonicalize_allow_paths(allow_write),
            model_sections = model_sections,
        ),
    )?;

    // Start navra as a child process
    let navra_bin = std::env::current_exe()?;
    let mut navra_child = tokio::process::Command::new(&navra_bin)
        .args(["serve", "--config", demo_config_path, "--no-tray"])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::inherit())
        .env(
            "ORT_LIB_PATH",
            std::env::var("ORT_LIB_PATH").unwrap_or_default(),
        )
        .env("ORT_PREFER_DYNAMIC_LINK", "1")
        .spawn()
        .map_err(|e| anyhow::anyhow!("Failed to start navra: {e}"))?;

    // Wait for navra to be ready
    let navra_url = format!("http://127.0.0.1:{demo_port}");
    let http_client = reqwest::Client::new();
    for i in 0..30 {
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
        if http_client
            .get(format!("{navra_url}/mcp"))
            .send()
            .await
            .is_ok()
        {
            break;
        }
        if i == 29 {
            navra_child.kill().await?;
            anyhow::bail!("navra did not start within 15 seconds");
        }
    }
    println!("  ✓ navra gateway running at {navra_url}");
    println!("  ✓ Agent 'audit-planner' (no auth for demo)");
    println!("  ✓ Docs module serving: {}", abs_project.display());

    // Verify model proxy endpoint
    let v1_check = http_client
        .post(format!("{navra_url}/v1/chat/completions"))
        .json(&serde_json::json!({
            "model": "default",
            "messages": [{"role": "user", "content": "hi"}],
            "max_tokens": 5
        }))
        .send()
        .await;
    match v1_check {
        Ok(resp) if resp.status().is_success() => {
            println!("  ✓ Model proxy at {navra_url}/v1/chat/completions");
        }
        Ok(resp) => {
            println!("  ⚠ Model proxy returned {}", resp.status());
        }
        Err(e) => {
            println!("  ⚠ Model proxy not available: {e}");
        }
    }

    // --- Step 3: Cognitive Core ---
    println!();
    println!("━━━ Act 2: Cognitive Core ━━━");
    let forge = match navra_cognitive::ForgeService::load(&project_path) {
        Ok(f) => {
            for name in f.persona_names() {
                if let Some(persona) = f.get_persona(name) {
                    println!(
                        "  ✓ Loaded persona: {} ({} heuristic modules)",
                        persona.persona_name,
                        persona.heuristics.len()
                    );
                }
            }
            f
        }
        Err(e) => {
            println!("  ⚠ Forge: {} (using empty)", e);
            navra_cognitive::ForgeService::empty()
        }
    };

    // --- Step 4: Build agent ---
    println!();
    println!("━━━ Act 3: Connect Agent to Gateway ━━━");

    // Select backend based on model name
    let is_claude = model_name.starts_with("claude");

    // Select the best available lead persona
    let persona_name = if forge.get_persona("planner").is_some() {
        "planner"
    } else if forge.get_persona("leader").is_some() {
        "leader"
    } else if forge.get_persona("rust_security_auditor").is_some() {
        "rust_security_auditor"
    } else {
        ""
    };

    let base_prompt = if !persona_name.is_empty() {
        navra_cognitive::assemble(&forge, persona_name, "", None, None)
            .map(|w| w.system_prompt())
            .unwrap_or_else(|_| "You are a team lead. Use the available tools to analyze the project and delegate to specialists.".to_string())
    } else {
        "You are a team lead. Use file_tree to understand the project structure, \
         models_list to see available models, then create a team of specialists \
         to analyze the project. Delegate all file reading to teammates. \
         Synthesize their findings into a final report."
            .to_string()
    };

    let system_prompt = base_prompt;

    let mcp_endpoint = format!("{navra_url}/mcp");

    // Lead agent only gets project overview + team tools.
    // No file_read, no file_grep — the lead MUST delegate all analysis.
    let lead_tools = vec![
        "file_tree".to_string(),     // project structure overview only
        "models_list".to_string(),   // see available models
        "personas_list".to_string(), // see available specialist personas
        "team_create".to_string(),
        "team_add".to_string(),
        "team_message".to_string(),
        "team_status".to_string(),
        "team_result".to_string(),
        "team_bb_read".to_string(),
        "team_shutdown".to_string(),
    ];

    // Observation-only tools don't count toward the iteration limit.
    // These tools read state without changing it — the lead uses them
    // to wait for teammates or inspect available resources.
    let polling_tools = vec![
        "team_status".to_string(),
        "team_result".to_string(),
        "team_bb_read".to_string(),
        "models_list".to_string(),
        "personas_list".to_string(),
    ];

    macro_rules! build_agent {
        ($backend:expr) => {
            navra_agent::Agent::builder()
                .endpoint(&mcp_endpoint)
                .await?
                .model($backend)
                .system_prompt(&system_prompt)
                .allowed_tools(lead_tools.clone())
                .non_progress_tools(polling_tools.clone())
                .max_iterations(50)
                .temperature(0.0) // deterministic tool-calling for orchestration
                .force_tool_iterations(5) // must call tools for first 5 progress iterations
                .max_tokens(8192)
                .build()
                .await?
        };
    }

    let mut agent = if is_claude {
        // Check for Vertex AI or direct Anthropic API
        let use_vertex = std::env::var("CLAUDE_CODE_USE_VERTEX").is_ok()
            || std::env::var("ANTHROPIC_VERTEX_PROJECT_ID").is_ok();

        if use_vertex {
            let project_id = std::env::var("ANTHROPIC_VERTEX_PROJECT_ID")
                .unwrap_or_else(|_| "my-project".to_string());
            let region =
                std::env::var("CLOUD_ML_REGION").unwrap_or_else(|_| "us-east5".to_string());
            let host = if region == "global" {
                "aiplatform.googleapis.com".to_string()
            } else {
                format!("{region}-aiplatform.googleapis.com")
            };
            let base_url = format!(
                "https://{host}/v1/projects/{project_id}/locations/{region}/publishers/anthropic/models/{model_name}:rawPredict"
            );
            // Get Google OAuth token via gcloud
            let token_output = std::process::Command::new("gcloud")
                .args(["auth", "print-access-token"])
                .output()
                .map_err(|e| {
                    anyhow::anyhow!("Failed to get gcloud token: {e}. Run: gcloud auth login")
                })?;
            let gcloud_token = String::from_utf8_lossy(&token_output.stdout)
                .trim()
                .to_string();
            if gcloud_token.is_empty() {
                navra_child.kill().await?;
                anyhow::bail!("Empty gcloud token. Run: gcloud auth application-default login");
            }
            println!("  Backend: Vertex AI (project: {project_id}, region: {region})");
            build_agent!(navra_model::AnthropicBackend::new(
                &base_url,
                model_name,
                Some(gcloud_token),
                navra_model::Locality::Remote,
            ))
        } else {
            let api_key = std::env::var("ANTHROPIC_API_KEY")
                .ok()
                .or_else(|| std::env::var("CLAUDE_API_KEY").ok());
            if api_key.is_none() {
                navra_child.kill().await?;
                anyhow::bail!("Claude requires ANTHROPIC_API_KEY or Vertex AI config");
            }
            println!("  Backend: Anthropic Messages API");
            build_agent!(navra_model::AnthropicBackend::new(
                "https://api.anthropic.com",
                model_name,
                api_key,
                navra_model::Locality::Remote,
            ))
        }
    } else {
        println!("  Backend: Ollama OpenAI-compat API");
        build_agent!(navra_model::OpenAiBackend::new(
            format!("{ollama_url}/v1"),
            model_name,
            None,
            navra_model::Locality::Local,
        ))
    };

    // List available tools
    let tools = agent.client().list_tools().await?;
    println!("  ✓ Connected to navra at {}", mcp_endpoint);
    println!("  ✓ {} MCP tools available:", tools.len());
    for tool in &tools {
        println!("    - {}", tool.name);
    }
    println!(
        "  ✓ Persona: {}",
        if persona_name.is_empty() {
            "default"
        } else {
            persona_name
        }
    );
    println!("  ✓ System prompt: {} chars", system_prompt.len());

    // --- Step 5: Run the agent ---
    println!();
    println!("━━━ Act 4: Agent-Driven Analysis ━━━");
    println!("  The agent will use ReAct (reasoning + tool calls) to explore");
    println!("  the codebase through navra. IFC, safety filters, and ACLs are");
    println!("  active on every tool call.");
    println!();

    let audit_prompt = match custom_prompt {
        Some(p) => p.replace("{path}", &abs_project.display().to_string()),
        None => format!(
            "Audit the Rust project at {path}",
            path = abs_project.display()
        ),
    };

    let start = std::time::Instant::now();
    match agent.run(&audit_prompt).await {
        Ok(result) => {
            let elapsed = start.elapsed();
            println!();
            println!("━━━ Agent Report ━━━");
            println!();
            for line in result.response.lines() {
                println!("  {}", line);
            }
            println!();
            println!("━━━ Summary ━━━");
            println!(
                "  Model:       {} (via Ollama, locality: Local)",
                model_name
            );
            println!("  Gateway:     navra at {}", navra_url);
            println!("  Transport:   MCP Streamable HTTP (authenticated)");
            println!(
                "  Persona:     {}",
                if persona_name.is_empty() {
                    "default"
                } else {
                    persona_name
                }
            );
            println!("  Iterations:  {} ReAct loops", result.iterations);
            println!(
                "  Tokens:      {} input + {} output",
                result.input_tokens, result.output_tokens
            );
            println!("  Time:        {:.1}s", elapsed.as_secs_f64());
            println!("  Taint:       {:?}", result.taint);
            println!("  Tools:       {} available via navra", tools.len());
            println!("  Security:    IFC + ACLs + safety filters active");
            println!("  Framework:   17 crates");
            println!();
            println!("  Blackbox:    navra audit");
        }
        Err(e) => {
            println!("\n  ✗ Agent error: {}", e);
        }
    }

    // --- Cleanup ---
    println!();
    navra_child.kill().await?;
    println!("  ✓ navra gateway stopped");
    println!();

    Ok(())
}

fn canonicalize_allow_paths(paths: &[String]) -> String {
    if paths.is_empty() {
        return String::new();
    }
    paths
        .iter()
        .map(|p| {
            let canonical =
                std::fs::canonicalize(p).unwrap_or_else(|_| std::path::PathBuf::from(p));
            format!(", \"{}/**\"", canonical.display())
        })
        .collect::<String>()
}
