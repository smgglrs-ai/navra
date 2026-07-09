//! navra — secure MCP gateway daemon.
//!
//! CLI entry point, configuration loading, module wiring, systemd
//! integration, and system tray. Composes all navra-* crates into
//! a running gateway.

use anyhow::Context as _;

mod acp_agent;
mod agent_bundle;
mod build_tools;
mod cli;
mod config;
mod config_watcher;
mod demo;
mod direct_transport;
mod discover;
mod exec_tools;
mod flow_api;
mod flow_tools;
mod grpc_manager;
mod init;
mod mdns;
mod memory_tools;
mod network_discovery;
mod plan_execute;
mod rag_retriever;
mod registry_tools;
mod session_distillation;
mod team_tools;
mod tray;
mod triggers;
mod ui;
mod ui_agent;
mod ui_events;
pub(crate) mod workspace;

use clap::Parser;
use navra_core::Module;
use navra_core::auth::{AgentIdentity, TokenAuthenticator};
use navra_core::credentials::CredentialStore as _;
use navra_core::identity::{self, CapSigner, Ed25519Signer};
use navra_core::permissions::{PathAcl, PermissionEngine, ToolPermissions, ToolPolicy, ToolRule};
use navra_protocol::compat::CallToolResultExt;
use std::sync::Arc;

use cli::{AgentAction, Cli, Commands, ConfigAction, ModelAction, PiiAction, TokenAction};

/// Wrapper around `Arc<CustomPiiFilter>` that implements `ContentFilter`.
///
/// Allows sharing a single custom PII filter across multiple pipelines.
struct SharedCustomPiiFilter(Arc<navra_core::safety::CustomPiiFilter>);

impl navra_core::safety::ContentFilter for SharedCustomPiiFilter {
    fn name(&self) -> &str {
        self.0.name()
    }

    fn scan(
        &self,
        content: &str,
        ctx: &navra_core::safety::FilterContext,
    ) -> Vec<navra_core::safety::Finding> {
        self.0.scan(content, ctx)
    }
}

fn init_tracing() -> anyhow::Result<()> {
    use tracing_subscriber::layer::SubscriberExt;
    use tracing_subscriber::util::SubscriberInitExt;

    let env_filter =
        tracing_subscriber::EnvFilter::from_default_env().add_directive("navra=info".parse()?);
    let fmt_layer = tracing_subscriber::fmt::layer();

    let registry = tracing_subscriber::registry()
        .with(env_filter)
        .with(fmt_layer);

    #[cfg(feature = "otel")]
    {
        if std::env::var("OTEL_EXPORTER_OTLP_ENDPOINT").is_ok() {
            let exporter = opentelemetry_otlp::SpanExporter::builder()
                .with_tonic()
                .build()?;
            let provider = opentelemetry_sdk::trace::SdkTracerProvider::builder()
                .with_batch_exporter(exporter)
                .with_resource(
                    opentelemetry_sdk::Resource::builder()
                        .with_service_name("navra")
                        .build(),
                )
                .build();
            let otel_layer = tracing_opentelemetry::layer().with_tracer(provider.tracer("navra"));
            registry.with(otel_layer).init();
            return Ok(());
        }
    }

    registry.init();
    Ok(())
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    init_tracing()?;

    match cli.command {
        Commands::Init {
            quiet,
            agent_name,
            safety,
            project,
            model,
            model_url,
            api_key,
            allow,
            install_service,
            dry_run,
            output,
        } => {
            init::run_init(
                quiet,
                agent_name,
                safety,
                project,
                model,
                model_url,
                api_key,
                allow,
                install_service,
                dry_run,
                output,
            )
            .await?;
        }
        Commands::Serve {
            config: config_path,
            no_tray,
            dev_mode,
        } => {
            let cfg = config::Config::load(config_path.as_deref())?;
            if dev_mode {
                tracing::warn!(
                    "--dev-mode enabled: anonymous access allowed without authentication"
                );
            }
            serve(cfg, no_tray, dev_mode).await?;
        }
        Commands::Stdio {
            config: config_path,
        } => {
            let cfg = config::Config::load(config_path.as_deref())?;
            stdio(cfg).await?;
        }
        Commands::Token { action } => match action {
            TokenAction::Generate { name, permissions } => {
                let token = config::generate_token();
                let hash = TokenAuthenticator::hash_token(&token);
                println!("Agent: {name}");
                println!("Permissions: {permissions}");
                println!("Token: {token}");
                println!("Hash:  {hash}");
                println!("\nAdd to config.toml:");
                println!("[[agents]]");
                println!("name = \"{name}\"");
                println!("token_hash = \"{hash}\"");
                println!("permissions = \"{permissions}\"");
            }
            TokenAction::List => {
                let cfg = config::Config::load(None)?;
                if cfg.agents.is_empty() {
                    println!("No agents configured.");
                } else {
                    println!("{:<20} {:<20}", "NAME", "PERMISSIONS");
                    println!("{:<20} {:<20}", "----", "-----------");
                    for agent in &cfg.agents {
                        println!("{:<20} {:<20}", agent.name, agent.permissions);
                    }
                }
            }
        },
        Commands::Approve { id } => {
            let cfg = config::Config::load(None)?;
            let addr = cfg.server.listen_addr();
            approve_or_deny(&addr, &id, true).await?;
        }
        Commands::Deny { id } => {
            let cfg = config::Config::load(None)?;
            let addr = cfg.server.listen_addr();
            approve_or_deny(&addr, &id, false).await?;
        }
        Commands::Status => {
            let cfg = config::Config::load(None)?;
            let addr = cfg.server.listen_addr();
            query_status(&addr).await?;
        }
        Commands::Schema => {
            let schema = schemars::schema_for!(config::Config);
            println!(
                "{}",
                serde_json::to_string_pretty(&schema)
                    .context("failed to serialize config schema")?
            );
        }
        Commands::Install => {
            install_systemd_units()?;
        }
        Commands::Uninstall => {
            uninstall_systemd_units()?;
        }
        Commands::Agent { action } => match action {
            AgentAction::Install {
                oci_ref,
                allow_unsigned,
                max_permissions,
            } => {
                let cfg = config::Config::load(None)?;
                cli::agent_install(&oci_ref, allow_unsigned, max_permissions.as_deref(), &cfg)
                    .await?;
            }
            AgentAction::Inspect { oci_ref } => {
                cli::agent_inspect(&oci_ref).await?;
            }
            AgentAction::Init { bundle, name } => {
                cli::agent_init(&bundle, name.as_deref())?;
            }
            AgentAction::Upgrade {
                bundle,
                allow_unsigned: _,
            } => {
                cli::agent_upgrade(&bundle)?;
            }
            AgentAction::List => {
                cli::agent_list()?;
            }
            AgentAction::Remove { name } => {
                cli::agent_remove(&name)?;
            }
        },
        Commands::Model { action } => match action {
            ModelAction::Serve {
                config: config_path,
                bind,
                auto,
                budget,
            } => {
                model_serve(config_path, bind, auto, budget).await?;
            }
            ModelAction::Pull { name } => {
                cli::model_pull(&name).await?;
            }
            ModelAction::List => {
                cli::model_list()?;
            }
            ModelAction::Available => {
                cli::model_available();
            }
        },
        Commands::Pii { action } => match action {
            PiiAction::Download { multilingual } => {
                cli::pii_download(multilingual).await?;
            }
            PiiAction::Status => {
                cli::pii_status();
            }
        },
        Commands::Config { action } => match action {
            ConfigAction::ImportMcp {
                path,
                discover,
                no_redact,
            } => {
                let redact = !no_redact;
                if discover || path.is_none() {
                    let files = if discover {
                        config::import::discover_config_files()
                    } else {
                        Vec::new()
                    };
                    if let Some(p) = &path {
                        import_mcp_file(p, redact)?;
                    }
                    if files.is_empty() && path.is_none() {
                        eprintln!("Usage: navra config import-mcp <path>");
                        eprintln!("       navra config import-mcp --discover");
                        std::process::exit(1);
                    }
                    for file in &files {
                        import_mcp_file(&file.to_string_lossy(), redact)?;
                    }
                } else if let Some(p) = &path {
                    import_mcp_file(p, redact)?;
                }
            }
            ConfigAction::ListLibraries { config: cfg_path } => {
                let cfg = config::Config::load(cfg_path.as_deref())
                    .unwrap_or_else(|_| config::Config::default());
                let dirs = config::libraries::resolve_dirs(&cfg.libraries.library_dirs);
                let libs = config::libraries::scan_libraries(&dirs)?;
                if libs.is_empty() {
                    println!("No operator libraries found.");
                    println!("Library directories:");
                    for d in &dirs {
                        println!("  {}", d.display());
                    }
                } else {
                    let summaries = config::libraries::summarize_libraries(&libs);
                    for s in &summaries {
                        println!("{}:", s.path.display());
                        for key in &s.keys {
                            println!("  {key}");
                        }
                    }
                }
            }
        },
        Commands::Improve {
            target,
            cycles,
            branch,
            config: _,
        } => {
            println!("navra self-improvement: {} cycles on {}", cycles, target);
            println!("Branch: {branch}");

            let target_path = std::path::Path::new(&target)
                .canonicalize()
                .unwrap_or_else(|e| {
                    eprintln!("Cannot resolve target: {e}");
                    std::process::exit(1);
                });

            // Create git worktree
            let worktree_path = target_path.join(".navra-improve").join(&branch);
            let worktree_result = std::process::Command::new("git")
                .args([
                    "worktree",
                    "add",
                    worktree_path
                        .to_str()
                        .ok_or_else(|| anyhow::anyhow!("worktree path is not valid UTF-8"))?,
                    "-b",
                    &branch,
                ])
                .current_dir(&target_path)
                .output();

            match worktree_result {
                Ok(output) if output.status.success() => {
                    println!("Created worktree at {}", worktree_path.display());
                }
                Ok(output) => {
                    let stderr = String::from_utf8_lossy(&output.stderr);
                    if stderr.contains("already exists") {
                        println!("Worktree already exists at {}", worktree_path.display());
                    } else {
                        eprintln!("Failed to create worktree: {}", stderr);
                        std::process::exit(1);
                    }
                }
                Err(e) => {
                    eprintln!("git worktree failed: {e}");
                    std::process::exit(1);
                }
            }

            // Start the server, run cycles, then stop
            println!("Starting navra for self-improvement...");
            println!("Target: {}", worktree_path.display());
            println!("Cycles: {cycles}");
            println!();
            println!("Use 'navra serve' in another terminal, then call:");
            println!("  flow_start(flow_name=\"self-improve\", prompt=\"Improve the project\",");
            println!(
                "    parameters={{\"target_dir\": \"{}\", \"cycle\": \"1\"}})",
                worktree_path.display()
            );
            println!();
            println!("After each cycle, review the worktree and merge if satisfied:");
            println!("  cd {} && git log --oneline", target_path.display());
            println!("  git merge {branch}");
            println!("  git worktree remove {}", worktree_path.display());
        }
        Commands::ValidateCognitive { cognitive_core } => {
            let path = std::path::Path::new(&cognitive_core);
            if !path.exists() {
                eprintln!("Cognitive core directory not found: {}", path.display());
                std::process::exit(1);
            }
            let forge = navra_cognitive::ForgeService::load(path)?;
            let findings = forge.validate();
            let mut has_errors = false;
            for finding in &findings {
                if finding.severity == navra_cognitive::Severity::Error {
                    has_errors = true;
                }
                println!("[{}] {}", finding.severity, finding.message);
            }
            if findings.is_empty() {
                println!("No issues found.");
            }
            if has_errors {
                std::process::exit(1);
            }
        }
        Commands::Run {
            prompt,
            model,
            persona,
            endpoint,
            token,
            max_iterations,
            upstream_prompts,
            workflow,
            file: _file,
            config: _run_config,
            no_embedded,
            dry_run,
        } => {
            // If prompt looks like instance/workflow, treat as workflow run
            let (prompt, _workflow_name) = if let Some(wf) = workflow {
                (format!("Run workflow: {wf}"), Some(wf))
            } else if prompt.contains('/') && !prompt.contains(' ') {
                let wf = prompt.clone();
                (format!("Run workflow: {wf}"), Some(wf))
            } else {
                (prompt, None)
            };
            if dry_run {
                println!("--- Dry Run ---");
                println!("Endpoint: {endpoint}");
                println!("Model: {}", model.as_deref().unwrap_or("auto-detect"));
                println!("Persona: {persona}");
                println!("Max iterations: {max_iterations}");
                if !upstream_prompts.is_empty() {
                    println!("Upstream prompts: {}", upstream_prompts.join(", "));
                }
                let forge = navra_cognitive::ForgeService::empty();
                match navra_cognitive::assemble(&forge, &persona, &prompt, None, None) {
                    Ok(output) => {
                        println!("\n--- System Prompt ---");
                        println!("{}", output.system_prompt());
                        println!("\n--- User Prompt ---");
                        println!("{prompt}");
                    }
                    Err(e) => {
                        println!("\nPersona '{persona}' not found: {e}");
                        println!("\n--- User Prompt ---");
                        println!("{prompt}");
                    }
                }
            } else {
                run_agent(
                    &prompt,
                    model.as_deref(),
                    &persona,
                    &endpoint,
                    token.as_deref(),
                    max_iterations,
                    &upstream_prompts,
                    no_embedded,
                )
                .await?;
            }
        }
        Commands::Audit {
            limit,
            detail,
            agent,
            tool,
            verify,
        } => {
            audit_command(limit, detail, agent, tool, verify)?;
        }
        Commands::Policy { action } => match action {
            cli::PolicyAction::Suggest {
                hours,
                format,
                db,
                agent,
                min_count,
            } => {
                policy_suggest(hours, &format, db.as_deref(), agent.as_deref(), min_count)?;
            }
        },
        Commands::Wrap {
            bind,
            safety,
            name,
            no_tray,
            discover,
            allow_all,
            sandbox,
            allow_domains,
            command,
        } => {
            wrap_command(
                command,
                bind,
                safety,
                name,
                no_tray,
                discover,
                allow_all,
                sandbox,
                allow_domains,
            )
            .await?;
        }
        Commands::Demo {
            project,
            live,
            model,
            max_rounds,
            files_per_round,
            min_delta,
            prompt,
            writable,
            allow_read,
            allow_write,
        } => {
            if live {
                demo::run_demo_live(
                    &project,
                    &model,
                    max_rounds,
                    files_per_round,
                    min_delta,
                    prompt.as_deref(),
                    writable,
                    &allow_read,
                    &allow_write,
                )
                .await?;
            } else {
                demo::run_demo(&project).await?;
            }
        }
    }

    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn wrap_command(
    command: Vec<String>,
    bind: String,
    safety: String,
    name: Option<String>,
    no_tray: bool,
    discover: bool,
    allow_all: bool,
    sandbox: Option<String>,
    allow_domains: Vec<String>,
) -> anyhow::Result<()> {
    if command.is_empty() {
        anyhow::bail!("No command specified. Usage: navra wrap -- <command> [args...]");
    }

    let upstream_name = name.unwrap_or_else(|| {
        std::path::Path::new(&command[0])
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("upstream")
            .to_string()
    });

    if discover {
        return wrap_discover(&upstream_name, &command).await;
    }

    let effective_safety = if allow_all { "none" } else { &safety };

    let token = config::generate_token();
    let token_hash = TokenAuthenticator::hash_token(&token);

    let command_str = command
        .iter()
        .map(|s| format!("\"{}\"", s.replace('\\', "\\\\").replace('"', "\\\"")))
        .collect::<Vec<_>>()
        .join(", ");

    let sandbox_section = match sandbox.as_deref() {
        Some("openshell") => {
            format!(
                "\n[server]\ntcp = \"{bind}\"\ncontainerized = true\nopenshell_gateway = \"http://127.0.0.1:50051\"\n"
            )
        }
        Some("podman") => {
            format!("\n[server]\ntcp = \"{bind}\"\ncontainerized = true\n")
        }
        Some(other) => {
            anyhow::bail!("Unknown sandbox type '{other}'. Use 'openshell' or 'podman'.");
        }
        None => {
            format!("[server]\ntcp = \"{bind}\"\n")
        }
    };

    // Discover network requirements when sandbox is active
    let mut egress_domains: Vec<String> = allow_domains;
    let egress_active = sandbox.is_some() && !allow_all;

    if egress_active
        && let Some(known) = network_discovery::known_server_domains(&upstream_name, &command)
    {
        for d in known {
            if !egress_domains.contains(&d) {
                egress_domains.push(d);
            }
        }
    }

    let egress_section = if egress_active {
        let domain_list = egress_domains
            .iter()
            .map(|d| format!("\"{d}\""))
            .collect::<Vec<_>>()
            .join(", ");
        format!("egress_deny_all_external = true\negress_allowed_domains = [{domain_list}]\n")
    } else {
        String::new()
    };

    let network_section = if egress_active && !egress_domains.is_empty() {
        let domain_list = egress_domains
            .iter()
            .map(|d| format!("\"{d}\""))
            .collect::<Vec<_>>()
            .join(", ");
        format!(
            "\n[upstream.network]\nallowed_domains = [{domain_list}]\ndeny_all_external = true\n"
        )
    } else if egress_active {
        "\n[upstream.network]\ndeny_all_external = true\n".to_string()
    } else {
        String::new()
    };

    let toml_str = format!(
        r#"{sandbox_section}
[[agents]]
name = "wrap-client"
token_hash = "{token_hash}"
permissions = "wrap"

[permissions.wrap]
safety = "{effective_safety}"
ring = 2
allow = ["*"]
deny = []
operations = ["read", "write"]
{egress_section}
[[upstream]]
name = "{upstream_name}"
transport = "stdio"
command = [{command_str}]
{network_section}"#
    );

    let cfg: config::Config = toml::from_str(&toml_str)?;

    let sandbox_label = sandbox.as_deref().unwrap_or("none (direct)");

    eprintln!("navra wrap: starting secured proxy for '{upstream_name}'");
    eprintln!();
    eprintln!("  Upstream:  {}", command.join(" "));
    eprintln!("  Gateway:   http://{bind}/mcp");
    eprintln!("  Safety:    {effective_safety}");
    eprintln!("  Sandbox:   {sandbox_label}");
    if egress_active {
        if egress_domains.is_empty() {
            eprintln!("  Egress:    deny-all (no domains allowed)");
        } else {
            eprintln!("  Egress:    {} domain(s) allowed", egress_domains.len());
            for d in &egress_domains {
                eprintln!("             - {d}");
            }
        }
    }
    eprintln!("  Token:     {token}");
    if allow_all {
        eprintln!();
        eprintln!("  WARNING: --allow-all disables safety filters and egress filtering");
    }
    eprintln!();
    eprintln!("Use with any MCP client:");
    eprintln!("  export MCPD_TOKEN={token}");
    eprintln!("  # endpoint: http://{bind}/mcp");
    eprintln!();
    eprintln!("Press Ctrl-C to stop.");

    serve(cfg, no_tray, false).await
}

async fn wrap_discover(name: &str, command: &[String]) -> anyhow::Result<()> {
    eprintln!("navra wrap --discover: connecting to '{name}'...");
    eprintln!("  Command: {}", command.join(" "));
    eprintln!();

    let mut cmd = tokio::process::Command::new(&command[0]);
    for arg in &command[1..] {
        cmd.arg(arg);
    }

    let transport = rmcp::transport::TokioChildProcess::new(cmd)
        .map_err(|e| anyhow::anyhow!("Failed to spawn upstream: {e}"))?;

    let client = rmcp::service::ServiceExt::<rmcp::RoleClient>::serve((), transport)
        .await
        .map_err(|e| anyhow::anyhow!("MCP handshake failed: {e}"))?;

    let peer = client.peer().clone();

    let tools = peer
        .list_all_tools()
        .await
        .map_err(|e| anyhow::anyhow!("tools/list failed: {e}"))?;
    let prompts = peer.list_all_prompts().await.unwrap_or_default();
    let resources = peer.list_all_resources().await.unwrap_or_default();

    println!("Upstream: {name}");
    println!("Command: {}", command.join(" "));
    println!();

    // --- Tools ---
    println!("Tools ({}):", tools.len());
    let mut read_tools = Vec::new();
    let mut write_tools = Vec::new();
    let mut unknown_tools = Vec::new();

    for tool in &tools {
        let desc = tool
            .description
            .as_deref()
            .unwrap_or("")
            .chars()
            .take(60)
            .collect::<String>();

        let is_read = tool
            .annotations
            .as_ref()
            .and_then(|a| a.read_only_hint)
            .unwrap_or(false);
        let is_destructive = tool
            .annotations
            .as_ref()
            .and_then(|a| a.destructive_hint)
            .unwrap_or(false);

        let classification = if is_read {
            "read"
        } else if is_destructive {
            "write (destructive)"
        } else if navra_core::ifc::is_write_tool(&tool.name, tool.annotations.as_ref()) {
            "write"
        } else {
            "read"
        };

        println!("  {:<30} [{classification}]  {desc}", tool.name);

        match classification {
            "read" => read_tools.push(tool.name.clone()),
            _ => {
                if classification.contains("write") || classification.contains("destructive") {
                    write_tools.push(tool.name.clone());
                } else {
                    unknown_tools.push(tool.name.clone());
                }
            }
        }
    }

    // --- Prompts ---
    if !prompts.is_empty() {
        println!();
        println!("Prompts ({}):", prompts.len());
        for prompt in &prompts {
            let desc = prompt
                .description
                .as_deref()
                .unwrap_or("")
                .chars()
                .take(60)
                .collect::<String>();
            println!("  {:<30} {desc}", prompt.name);
        }
    }

    // --- Resources ---
    if !resources.is_empty() {
        println!();
        println!("Resources ({}):", resources.len());
        for resource in &resources {
            let desc = resource
                .description
                .as_deref()
                .unwrap_or("")
                .chars()
                .take(60)
                .collect::<String>();
            println!("  {:<30} {desc}", resource.name);
        }
    }

    // --- Network requirements ---
    let net_reqs = network_discovery::discover_all(name, command, &tools);
    println!();
    println!("Network requirements:");
    if net_reqs.is_empty() {
        println!("  No external endpoints detected (likely offline-only).");
    } else {
        for d in &net_reqs.known {
            println!("  {d:<40} (known server registry)");
        }
        for d in &net_reqs.from_descriptions {
            if !net_reqs.known.contains(d) {
                println!("  {d:<40} (extracted from tool description)");
            }
        }
        if !net_reqs.url_accepting_tools.is_empty() {
            println!();
            println!("  Tools that accept URLs (may need arbitrary egress):");
            for t in &net_reqs.url_accepting_tools {
                println!("    - {t}");
            }
        }
    }

    // --- Policy suggestion ---
    println!();
    println!("--- Suggested policy ---");
    println!();
    println!("[[upstream]]");
    println!("name = \"{name}\"");
    println!("transport = \"stdio\"");
    println!(
        "command = [{}]",
        command
            .iter()
            .map(|s| format!("\"{}\"", s.replace('"', "\\\"")))
            .collect::<Vec<_>>()
            .join(", ")
    );
    if !write_tools.is_empty() {
        println!();
        println!("[upstream.tool_overrides]");
        for t in &write_tools {
            println!("{t} = \"write\"");
        }
    }

    let all_domains = net_reqs.all_domains();
    if !all_domains.is_empty() || net_reqs.url_accepting_tools.is_empty() {
        println!();
        println!("[upstream.network]");
        if all_domains.is_empty() {
            println!("# No external endpoints needed — full network isolation recommended.");
            println!("deny_all_external = true");
        } else {
            let domain_list = all_domains
                .iter()
                .map(|d| format!("\"{d}\""))
                .collect::<Vec<_>>()
                .join(", ");
            println!("allowed_domains = [{domain_list}]");
            println!("deny_all_external = true");
        }
    } else {
        println!();
        println!("# [upstream.network]");
        println!("# WARNING: this server accepts URLs as input — cannot determine");
        println!("# a fixed domain allowlist. Review tool usage and add domains manually.");
        println!("# allowed_domains = [\"api.example.com\"]");
        println!("# deny_all_external = true");
    }

    println!();
    println!("[permissions.{name}]");
    println!("safety = \"standard\"");
    println!("ring = 2");
    if write_tools.is_empty() {
        println!("allow = [\"*\"]");
        println!("operations = [\"read\"]");
    } else {
        let read_patterns: Vec<String> = read_tools.iter().map(|t| format!("\"{t}\"")).collect();
        let write_patterns: Vec<String> = write_tools.iter().map(|t| format!("\"{t}\"")).collect();
        println!(
            "allow = [{}]",
            read_tools
                .iter()
                .chain(write_tools.iter())
                .chain(unknown_tools.iter())
                .map(|t| format!("\"{t}\""))
                .collect::<Vec<_>>()
                .join(", ")
        );
        if !read_patterns.is_empty() {
            println!("# Read-only tools: {}", read_patterns.join(", "));
        }
        if !write_patterns.is_empty() {
            println!(
                "# Write tools (review carefully): {}",
                write_patterns.join(", ")
            );
        }
        println!("operations = [\"read\", \"write\"]");
        println!("approve = [{}]", write_patterns.join(", "));
    }
    if !all_domains.is_empty() {
        let domain_list = all_domains
            .iter()
            .map(|d| format!("\"{d}\""))
            .collect::<Vec<_>>()
            .join(", ");
        println!("egress_deny_all_external = true");
        println!("egress_allowed_domains = [{domain_list}]");
    }

    // Shut down the client
    drop(peer);
    drop(client);

    Ok(())
}

fn import_mcp_file(path: &str, redact: bool) -> anyhow::Result<()> {
    let content = std::fs::read_to_string(path)?;
    let (format, servers) = config::import::detect_and_parse(&content)?;
    eprintln!(
        "# {} — detected {} format, {} server(s)",
        path,
        format,
        servers.len()
    );
    print!("{}", config::import::to_toml(&servers, redact));
    Ok(())
}

/// Bootstrap the root identity from config.
///
/// If `[server.identity]` specifies a `key_path`, loads or creates
/// a file-based identity. Otherwise, uses the OS keyring.
async fn bootstrap_identity(cfg: &config::Config) -> anyhow::Result<Ed25519Signer> {
    if let Some(ref identity_cfg) = cfg.server.identity
        && let Some(ref key_path) = identity_cfg.key_path
    {
        let path = std::path::Path::new(key_path);
        return Ok(identity::load_or_create_file_identity(path)?);
    }
    // keyring 4 uses zbus which calls block_on internally —
    // must run on a blocking thread to avoid runtime nesting
    match tokio::task::spawn_blocking(identity::load_or_create_keyring_identity)
        .await
        .map_err(|e| anyhow::anyhow!("keyring task panicked: {e}"))?
    {
        Ok(signer) => Ok(signer),
        Err(e) => {
            tracing::warn!(
                error = %e,
                "Keyring unavailable, falling back to file identity"
            );
            let default_path = dirs::config_dir()
                .ok_or_else(|| {
                    anyhow::anyhow!("Cannot determine config directory for identity key")
                })?
                .join("navra/identity.key");
            Ok(identity::load_or_create_file_identity(&default_path)?)
        }
    }
}

/// Build the permission engine from config.
fn build_perm_engine(cfg: &config::Config) -> PermissionEngine {
    let mut engine = PermissionEngine::new();
    for (name, pset) in &cfg.permissions {
        let acl = PathAcl {
            ring: pset.ring,
            allow: pset.allow.clone(),
            deny: pset.deny.clone(),
            operations: pset.operations.iter().cloned().collect(),
            requires_approval: pset.approve.iter().cloned().collect(),
        };
        engine.add_permission_set(name.clone(), acl);

        if let Some(ring) = pset.ring {
            tracing::info!(
                permission_set = %name,
                ring = ring,
                "Permission ring"
            );
        }
    }

    // When no agents are configured, anonymous access uses the "readonly"
    // permission set. If it's missing, tools will fail with DeniedUnknown.
    // Warn loudly at startup so the operator knows why.
    if cfg.agents.is_empty() && !cfg.permissions.contains_key("readonly") {
        tracing::warn!(
            "No [permissions.readonly] in config. Anonymous agents use the \
             'readonly' permission set — without it, all path-based tools \
             (file_read, file_tree, etc.) will be denied. Add a \
             [permissions.readonly] section to grant access."
        );
    }

    engine.apply_ring_inheritance();
    engine
}

/// Start a shared model server container for containerized agent execution.
///
/// Launches a llama-server container via Podman, mounts the first available
/// GGUF model, and polls `/health` until ready. Returns the endpoint URL
/// (rewritten for container access via `10.0.2.2`) and the container name.
async fn start_model_server_container(
    cfg: &config::Config,
) -> anyhow::Result<(String, u16, String)> {
    // Find the first chat/generate model with a resolved GGUF path
    let hub = navra_model_hub::ModelHub::new().ok();
    let mut model_path: Option<std::path::PathBuf> = None;

    for model_cfg in cfg.models.values() {
        if !matches!(model_cfg.task.as_str(), "chat" | "generate") {
            continue;
        }
        if let Some(ref source) = model_cfg.source {
            if let Some(ref h) = hub
                && let Ok(uri) = navra_model_hub::ModelUri::parse(source)
                && let Ok(p) = h.pull(&uri).await
            {
                model_path = Some(p);
                break;
            }
        } else if let Some(ref path_str) = model_cfg.model_path {
            let expanded = expand_tilde(path_str);
            let p = std::path::PathBuf::from(&expanded);
            if p.exists() {
                model_path = Some(p);
                break;
            }
        }
    }

    let gguf_path = model_path.ok_or_else(|| {
        anyhow::anyhow!("No chat/generate GGUF model found for model server container")
    })?;
    let gguf_str = gguf_path
        .to_str()
        .ok_or_else(|| anyhow::anyhow!("Invalid model path"))?;

    // Pick a free port
    let listener = std::net::TcpListener::bind("127.0.0.1:0")?;
    let port = listener.local_addr()?.port();
    drop(listener);

    let container_name = "navra-model-server".to_string();
    let image = &cfg.server.model_server_image;
    let parallel = cfg.budget.max_parallel.max(2);

    tracing::info!(
        image = %image,
        model = %gguf_str,
        port = port,
        "Starting shared model server container"
    );

    // Stop any leftover container with the same name
    let _ = tokio::process::Command::new("podman")
        .args(["rm", "-f", &container_name])
        .output()
        .await;

    let output = tokio::process::Command::new("podman")
        .arg("run")
        .arg("-d")
        .arg("--rm")
        .arg("--name")
        .arg(&container_name)
        .arg("--device")
        .arg("nvidia.com/gpu=all")
        .arg("-v")
        .arg(format!("{gguf_str}:/model/model.gguf:ro,Z"))
        .arg("-p")
        .arg(format!("127.0.0.1:{port}:8080"))
        .arg(image)
        .arg("-m")
        .arg("/model/model.gguf")
        .arg("-ngl")
        .arg("99")
        .arg("--parallel")
        .arg(parallel.to_string())
        .arg("--ctx-size")
        .arg("8192")
        .arg("--cont-batching")
        .output()
        .await
        .map_err(|e| anyhow::anyhow!("podman run failed: {e}"))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(anyhow::anyhow!("Model server container failed: {stderr}"));
    }

    // Poll /health until ready (up to 120s)
    let client = reqwest::Client::new();
    let health_url = format!("http://127.0.0.1:{port}/health");
    for attempt in 0..240 {
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
        if let Ok(resp) = client.get(&health_url).send().await
            && resp.status().is_success()
        {
            tracing::info!(port = port, "Model server container is ready");
            let endpoint = format!("http://127.0.0.1:{port}/v1");
            return Ok((endpoint, port, container_name));
        }
        if attempt % 20 == 19 {
            tracing::info!(
                attempt = attempt + 1,
                "Still waiting for model server health..."
            );
        }
    }

    // Cleanup on timeout
    let _ = tokio::process::Command::new("podman")
        .args(["stop", &container_name])
        .output()
        .await;
    Err(anyhow::anyhow!(
        "Model server did not become healthy within 120s"
    ))
}

enum TransportMode {
    Http { no_tray: bool },
    Stdio,
}

async fn stdio(cfg: config::Config) -> anyhow::Result<()> {
    serve_inner(cfg, TransportMode::Stdio, false).await
}

async fn model_serve(
    config_path: Option<String>,
    bind: String,
    auto: bool,
    budget: Option<String>,
) -> anyhow::Result<()> {
    let cfg = config::Config::load(config_path.as_deref())?;

    if auto {
        let desktop_res = 2 * 1024 * 1024 * 1024; // 2 GB
        let summary = navra_model_server::hardware::detect(desktop_res);
        navra_model_server::hardware::print_summary(&summary);
        println!();
    }

    let vram_budget = budget
        .map(|b| parse_size_bytes(&b))
        .transpose()?
        .unwrap_or(0);

    let server_config = navra_model_server::ModelServerConfig {
        models: convert_model_configs(&cfg.models),
        bind: bind.clone(),
        vram_budget,
        desktop_reservation: 2 * 1024 * 1024 * 1024,
    };

    let server = navra_model_server::ModelServer::new(server_config).await?;
    server.serve(&bind).await
}

fn parse_size_bytes(s: &str) -> anyhow::Result<u64> {
    let s = s.trim();
    if let Some(gb) = s.strip_suffix("GB").or_else(|| s.strip_suffix("gb")) {
        let n: u64 = gb.trim().parse()?;
        Ok(n * 1024 * 1024 * 1024)
    } else if let Some(mb) = s.strip_suffix("MB").or_else(|| s.strip_suffix("mb")) {
        let n: u64 = mb.trim().parse()?;
        Ok(n * 1024 * 1024)
    } else {
        s.parse::<u64>()
            .map_err(|_| anyhow::anyhow!("invalid size: {s} (use e.g. 24GB, 16GB, 512MB)"))
    }
}

async fn serve(cfg: config::Config, no_tray: bool, dev_mode: bool) -> anyhow::Result<()> {
    serve_inner(cfg, TransportMode::Http { no_tray }, dev_mode).await
}

async fn serve_inner(
    cfg: config::Config,
    mode: TransportMode,
    dev_mode: bool,
) -> anyhow::Result<()> {
    // Branded startup banner (before tracing, so it's always visible)
    {
        let version = env!("CARGO_PKG_VERSION");
        let profile = if cfg!(debug_assertions) {
            "debug"
        } else {
            "release"
        };
        eprintln!("navra v{version} ({profile})");
    }

    tracing::info!("Starting navra");

    // Bootstrap root identity (DID:key from Ed25519)
    let root_signer = Arc::new(bootstrap_identity(&cfg).await?);
    tracing::info!(
        root_did = %root_signer.did(),
        algorithm = %root_signer.algorithm(),
        "Root identity"
    );

    // Build credential store from config mappings
    let credential_store = Arc::new(navra_core::credentials::MappedCredentialStore::new(
        cfg.credentials.clone(),
    ));
    if !cfg.credentials.is_empty() {
        tracing::info!(count = cfg.credentials.len(), "Credential mappings loaded");
    }

    let perm_engine = Arc::new(build_perm_engine(&cfg));

    // Build quota engine from rate limits in permission sets
    let mut quota_engine = navra_core::quota::QuotaEngine::new();
    for (name, pset) in &cfg.permissions {
        if let Some(ref rate_limit_str) = pset.rate_limit
            && let Some((max_str, window_str)) = rate_limit_str.split_once('/')
            && let (Ok(max_calls), Ok(window_secs)) =
                (max_str.parse::<u64>(), window_str.parse::<u64>())
        {
            quota_engine.add_limit(
                name.clone(),
                navra_core::quota::RateLimit {
                    max_calls,
                    window_secs,
                },
            );
            tracing::info!(
                permission_set = %name,
                max_calls = max_calls,
                window_secs = window_secs,
                "Rate limit"
            );
        }
    }

    // Build server, registering enabled modules
    // Shared process table — created early so kernel resource handlers can capture it.
    let process_table = navra_core::process::ProcessTable::new();

    // Shared session store — created early so kernel resource handlers can capture it.
    let session_store: navra_core::session::SessionStore;

    if cfg.server.mcp_version == "2025-03-26" {
        tracing::warn!(
            "MCP version 2025-03-26 is deprecated — stateless dispatch (2026-07-28) is now the default. \
             Remove mcp_version from config.toml to use the new default."
        );
    }

    let metrics = std::sync::Arc::new(navra_core::metrics::Metrics::new());

    let mut builder = navra_core::McpServer::builder()
        .name("navra")
        .version(env!("CARGO_PKG_VERSION"))
        .mcp_version(&cfg.server.mcp_version)
        .hook_timeout(std::time::Duration::from_secs(cfg.server.hook_timeout_secs))
        .process_table(process_table.clone())
        .metrics(metrics.clone());

    // Persistent session store (SQLite) — sessions survive restarts
    {
        let session_db_path = dirs::data_dir()
            .unwrap_or_else(|| std::path::PathBuf::from("."))
            .join("navra/sessions.db");
        if let Some(parent) = session_db_path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        match navra_memory::SqliteSessionBackend::open(&session_db_path) {
            Ok(backend) => {
                let existing = {
                    use navra_core::session::SessionBackend;
                    backend.count()
                };
                let store =
                    navra_core::session::SessionStore::with_backend(std::sync::Arc::new(backend));
                session_store = store.clone();
                builder = builder.session_store(store);
                tracing::info!(
                    path = %session_db_path.display(),
                    sessions = existing,
                    "Persistent session store enabled"
                );
            }
            Err(e) => {
                tracing::warn!(
                    error = %e,
                    "Failed to open session DB, falling back to in-memory sessions"
                );
                session_store = navra_core::session::SessionStore::new();
                builder = builder.session_store(session_store.clone());
            }
        }
    }

    // Gateway blackbox — always on, append-only, hash-chained
    {
        let bb_path = dirs::data_dir()
            .unwrap_or_else(|| std::path::PathBuf::from("."))
            .join("navra/blackbox.db");
        if let Some(parent) = bb_path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        match navra_core::blackbox::Blackbox::open(&bb_path) {
            Ok(bb) => {
                // Attach PII filter to blackbox for sanitizing tool args/results
                let bb = match memory_tools::build_pii_sanitizer(cfg.memory_pii_filter()) {
                    Some(filter) => {
                        tracing::info!("Blackbox PII filter enabled");
                        bb.with_pii_filter(filter)
                    }
                    None => bb,
                };
                // Blackbox retention sweep at startup
                if let Some(days) = cfg.memory_audit_retention_days() {
                    let deleted = bb.expire_older_than(days);
                    if deleted > 0 {
                        tracing::info!(
                            deleted = deleted,
                            days = days,
                            "Retention: expired old blackbox entries"
                        );
                    }
                }
                let count = bb.count();
                builder = builder.blackbox(bb);
                tracing::info!(
                    path = %bb_path.display(),
                    entries = count,
                    "Blackbox enabled (append-only, hash-chained)"
                );
            }
            Err(e) => {
                tracing::error!(error = %e, "Failed to open blackbox — tool calls will NOT be recorded");
            }
        }
    }

    // Wire IFC policies and trusted paths from permission sets
    for (name, pset) in &cfg.permissions {
        let policy = navra_core::ifc::TaintedWritePolicy::from_str(&pset.tainted_write_policy)
            .unwrap_or_else(|e| {
                tracing::error!(permission_set = %name, error = %e, "Invalid IFC config, defaulting to Deny");
                navra_core::ifc::TaintedWritePolicy::Deny
            });
        builder = builder.ifc_policy(name.clone(), policy.clone());
        if policy != navra_core::ifc::TaintedWritePolicy::Allow {
            tracing::info!(
                permission_set = %name,
                policy = %pset.tainted_write_policy,
                "IFC tainted write policy"
            );
        }
        if !pset.trusted_paths.is_empty() {
            tracing::info!(
                permission_set = %name,
                count = pset.trusted_paths.len(),
                "IFC trusted paths configured"
            );
            builder = builder.trusted_paths(name.clone(), pset.trusted_paths.clone());
        }
    }

    // Wire path ACLs for gateway-level enforcement on upstream tools.
    for (name, pset) in &cfg.permissions {
        let acl = PathAcl {
            ring: pset.ring,
            allow: pset.allow.clone(),
            deny: pset.deny.clone(),
            operations: pset.operations.iter().cloned().collect(),
            requires_approval: pset.approve.iter().cloned().collect(),
        };
        builder = builder.path_acl(name.clone(), acl);
    }

    // IFC + stateless mode: taint persists via server-side sessions
    // keyed by agent name ("stateless:{agent_name}"). This means all
    // clients sharing the same agent identity share taint state — if
    // one reads a secret, all are blocked from writing. This is safe
    // (fails closed) but can over-block in multi-client deployments.
    if cfg.server.mcp_version != "2025-03-26" {
        let has_ifc_enforcement = cfg.permissions.values().any(|pset| {
            let p = navra_core::ifc::TaintedWritePolicy::from_str(&pset.tainted_write_policy)
                .unwrap_or(navra_core::ifc::TaintedWritePolicy::Deny);
            p != navra_core::ifc::TaintedWritePolicy::Allow
        });
        if has_ifc_enforcement {
            tracing::warn!(
                "IFC tainted_write_policy is active in stateless mode. \
                 Taint persists via server-side sessions keyed by agent name. \
                 All clients sharing the same identity share taint state — \
                 if one reads sensitive data, all are blocked from writing. \
                 This is safe (fail-closed) but may over-block in multi-client setups. \
                 Use session-based dispatch (mcp_version = \"2025-03-26\") or \
                 capability tokens for per-client taint isolation."
            );
        }
    }

    if quota_engine.has_limits() {
        builder = builder.quota_engine(quota_engine);
    }

    // Register authenticator chain if agents are configured
    if !cfg.agents.is_empty() {
        let has_cap_agents = cfg.agents.iter().any(|a| a.capability_token);

        // Issue capability tokens for agents that request them
        if has_cap_agents {
            let default_ttl = cfg
                .server
                .identity
                .as_ref()
                .map(|i| i.token_ttl)
                .unwrap_or(3600);

            for agent in &cfg.agents {
                if !agent.capability_token {
                    continue;
                }
                let pset = cfg.permissions.get(&agent.permissions);
                let (ring, paths, ops, creds) = match pset {
                    Some(ps) => (
                        ps.ring.unwrap_or(0),
                        ps.allow.clone(),
                        ps.operations.clone(),
                        ps.credentials.clone(),
                    ),
                    None => (0, vec![], vec![], vec![]),
                };
                let ttl = agent.token_ttl.unwrap_or(default_ttl);
                let subject_did = agent
                    .did
                    .clone()
                    .unwrap_or_else(|| format!("agent:{}", agent.name));

                let cap_set = navra_core::auth::capability::CapabilitySet {
                    paths,
                    operations: ops,
                    tools: pset
                        .map(|ps| {
                            ps.tool_rules
                                .iter()
                                .filter(|r| r.policy == "allow")
                                .map(|r| r.tool.clone())
                                .collect::<Vec<_>>()
                        })
                        .filter(|v: &Vec<String>| !v.is_empty())
                        .unwrap_or_else(|| vec!["*".to_string()]),
                    credentials: creds,
                };

                let payload = navra_core::auth::capability::build_payload(
                    root_signer.did(),
                    &subject_did,
                    cap_set,
                    ring,
                    ttl,
                );

                match navra_core::auth::capability::encode_token(&payload, &root_signer) {
                    Ok(token) => {
                        // Log token prefix only — full token is a bearer credential
                        let token_prefix = if token.len() > 20 {
                            format!("{}...", &token[..20])
                        } else {
                            token.clone()
                        };
                        tracing::info!(
                            agent = %agent.name,
                            subject_did = %subject_did,
                            ring = ring,
                            ttl_secs = ttl,
                            token_prefix = %token_prefix,
                            "Issued capability token"
                        );
                    }
                    Err(e) => {
                        tracing::error!(
                            agent = %agent.name,
                            error = %e,
                            "Failed to issue capability token"
                        );
                    }
                }
            }
        }

        let mut blake3_auth = TokenAuthenticator::new();
        for agent in &cfg.agents {
            let perm_set = cfg.permissions.get(&agent.permissions);
            blake3_auth.register_hash(
                &agent.token_hash,
                AgentIdentity {
                    name: agent.name.clone(),
                    permissions: agent.permissions.clone(),
                    signing_key: agent.signing_key.clone(),
                    did: agent.did.clone(),
                    capabilities: None,
                    model: agent
                        .model
                        .clone()
                        .or_else(|| perm_set.and_then(|p| p.model.clone())),
                    allowed_upstreams: if !agent.upstream.is_empty() {
                        agent.upstream.clone()
                    } else {
                        perm_set.map(|p| p.upstream.clone()).unwrap_or_default()
                    },
                    max_concurrent: agent
                        .max_concurrent
                        .or(perm_set.and_then(|p| p.max_concurrent)),
                    max_context: agent.max_context.or(perm_set.and_then(|p| p.max_context)),
                },
            );
            if agent.pubkey.is_some() {
                tracing::debug!(agent = %agent.name, "Agent has pubkey configured");
            }
            tracing::info!(agent = %agent.name, permissions = %agent.permissions, "Registered agent");
        }

        let nonce_cache_ttl = std::time::Duration::from_secs(
            cfg.server
                .identity
                .as_ref()
                .map(|i| i.nonce_cache_ttl_secs)
                .unwrap_or(7200),
        );

        if has_cap_agents {
            // Build ChainAuthenticator: capability tokens first, then BLAKE3
            let cap_auth = navra_core::auth::chain::CapabilityAuthenticator::with_nonce_ttl(
                Box::new(Arc::clone(&root_signer)),
                nonce_cache_ttl,
            );
            let mut chain = navra_core::auth::chain::ChainAuthenticator::new().add(cap_auth);

            // Insert OpenShell authenticator at position 2 if configured
            if let Some(os_config) = cfg.server.openshell_auth.clone() {
                let os_auth = navra_core::auth::openshell::OpenShellAuthenticator::new(os_config);
                chain = chain.add(os_auth);
                tracing::info!("OpenShell identity federation enabled");
            }

            chain = chain.add(blake3_auth);
            builder = builder.authenticator(chain);
            tracing::info!("Authenticator chain: capability tokens + BLAKE3");
        } else {
            builder = builder.authenticator(blake3_auth);
        }
    } else {
        // No agents configured, but flow tasks and teammates use capability
        // tokens minted by the server. Register CapabilityAuthenticator so
        // those tokens are verified (with proper DID identity), falling back
        // to anonymous for external clients.
        let nonce_cache_ttl = std::time::Duration::from_secs(
            cfg.server
                .identity
                .as_ref()
                .map(|i| i.nonce_cache_ttl_secs)
                .unwrap_or(7200),
        );
        let cap_auth = navra_core::auth::chain::CapabilityAuthenticator::with_nonce_ttl(
            Box::new(Arc::clone(&root_signer)),
            nonce_cache_ttl,
        );
        let mut chain = navra_core::auth::chain::ChainAuthenticator::new().add(cap_auth);

        // Insert OpenShell authenticator if configured
        if let Some(os_config) = cfg.server.openshell_auth.clone() {
            let os_auth = navra_core::auth::openshell::OpenShellAuthenticator::new(os_config);
            chain = chain.add(os_auth);
            tracing::info!("OpenShell identity federation enabled");
        }

        if dev_mode {
            let no_auth = navra_core::auth::NoAuthenticator {
                default_identity: AgentIdentity::new("anonymous", "readonly"),
            };
            let chain = chain.add(no_auth);
            builder = builder.authenticator(chain);
            tracing::warn!(
                "DEV MODE: No agents configured — anonymous access enabled. \
                 Do not use in production."
            );
        } else {
            anyhow::bail!(
                "No agents configured and --dev-mode not set. \
                 Add [[agents]] to config.toml, configure OAuth, \
                 or pass --dev-mode for development."
            );
        }
    }

    // --- Load models into registry ---
    // The model registry is owned by navra-model-server and manages
    // model lifecycle (loading, unloading, runtime process tracking).
    // The gateway extracts the model backends for direct use.
    let model_entries = convert_model_configs(&cfg.models);
    let model_registry = navra_model_server::ModelRegistry::from_config(&model_entries)
        .await
        .context("failed to build model registry")?;
    let models = model_registry.models().clone();

    // Keep the registry alive for runtime process management.
    // When the registry is dropped, it logs but doesn't stop runtimes
    // (shutdown is handled below via running_endpoints for backward compat).
    let _model_registry = model_registry;

    // Legacy endpoint tracking for shutdown — still needed for team
    // models added later in containerized mode.
    let mut running_endpoints: Vec<(
        Box<dyn navra_model_runtime::ModelRuntime>,
        navra_model_runtime::Endpoint,
    )> = Vec::new();

    #[cfg(feature = "onnx")]
    let pii_ner_filter: Option<Arc<navra_core::safety::NerFilter>> = {
        let pii_ml_dir = cfg.pii_multilingual_model_dir();
        let pii_en_dir = cfg.pii_model_dir();
        match navra_core::safety::load_ner_filter(&pii_ml_dir) {
            Some(filter) => {
                tracing::info!(
                    dir = %pii_ml_dir.display(),
                    "Multilingual PII NER model loaded (EN, FR, DE, ES, IT, PT, NL)"
                );
                Some(Arc::new(filter))
            }
            None => match navra_core::safety::load_ner_filter(&pii_en_dir) {
                Some(filter) => {
                    tracing::info!(
                        dir = %pii_en_dir.display(),
                        "English PII NER model loaded for semantic entity detection"
                    );
                    Some(Arc::new(filter))
                }
                None => {
                    tracing::info!(
                        "PII NER model not installed. Run 'navra pii download' for semantic PII detection."
                    );
                    None
                }
            },
        }
    };

    #[cfg(feature = "onnx")]
    let privacy_filter: Option<Arc<navra_core::safety::PrivacyFilterModel>> = {
        let privacy_filter_dir = navra_core::safety::default_privacy_filter_model_dir();
        match navra_core::safety::load_privacy_filter(&privacy_filter_dir) {
            Some(filter) => {
                tracing::info!(
                    dir = %privacy_filter_dir.display(),
                    "OpenAI privacy-filter loaded (address, date, secret detection)"
                );
                Some(Arc::new(filter))
            }
            None => {
                tracing::info!(
                    "OpenAI privacy-filter not installed. Download from HuggingFace for address/date/secret PII detection."
                );
                None
            }
        }
    };

    // Build custom PII filter from global pii_patterns config (shared across all pipelines)
    let custom_pii_filter: Option<Arc<navra_core::safety::CustomPiiFilter>> =
        if !cfg.pii_patterns.is_empty() {
            let patterns: Vec<(String, String, String)> = cfg
                .pii_patterns
                .iter()
                .map(|p| (p.name.clone(), p.regex.clone(), p.category.clone()))
                .collect();
            match navra_core::safety::CustomPiiFilter::new(patterns) {
                Ok(filter) => {
                    if filter.has_patterns() {
                        // Register custom categories as PII for IFC labeling
                        navra_core::safety::register_pii_categories(&filter.categories());
                        tracing::info!(
                            patterns = cfg.pii_patterns.len(),
                            categories = ?filter.categories(),
                            "Custom PII patterns loaded"
                        );
                        Some(Arc::new(filter))
                    } else {
                        None
                    }
                }
                Err(e) => {
                    tracing::error!(error = %e, "Failed to compile custom PII patterns");
                    None
                }
            }
        } else {
            None
        };

    // Register safety profiles and per-tool permissions per permission set
    for (name, pset) in &cfg.permissions {
        let mut pipeline = navra_core::safety::build_pipeline(&pset.safety);

        // Add global custom PII filter to profiles that use content filtering
        if let Some(ref pii_filter) = custom_pii_filter {
            match pset.safety.as_str() {
                "standard" | "guardian" | "guardian-deep" | "block" | "multi-label" => {
                    pipeline.add_filter(SharedCustomPiiFilter(Arc::clone(pii_filter)));
                }
                _ => {}
            }
        }

        // Add custom regex patterns if configured
        if !pset.safety_patterns.is_empty() {
            let patterns: Vec<(String, String)> = pset
                .safety_patterns
                .iter()
                .map(|p| (p.category.clone(), p.pattern.clone()))
                .collect();
            let custom = navra_core::safety::CustomFilter::new(patterns);
            if custom.has_patterns() {
                tracing::info!(
                    permission_set = %name,
                    patterns = pset.safety_patterns.len(),
                    "Custom safety patterns"
                );
                pipeline.add_filter(custom);
            }
        }

        // Add ML safety filter from any loaded classification model
        for (model_name, model_cfg) in &cfg.models {
            if model_cfg.task == "classification"
                && let Some(model) = models.get(model_name)
            {
                let classifier: std::sync::Arc<dyn navra_core::safety::Classifier> =
                    std::sync::Arc::new(navra_safety_hooks::bridge::ClassifierBridge::new(
                        model.clone(),
                    ));
                if pset.safety == "multi-label" && !pset.safety_thresholds.is_empty() {
                    // Multi-label filter with per-category thresholds
                    pipeline.add_model_filter(
                        navra_core::safety::MultiLabelFilter::from_thresholds(
                            classifier,
                            pset.safety_thresholds.clone(),
                        ),
                    );
                    tracing::info!(
                        permission_set = %name,
                        categories = pset.safety_thresholds.len(),
                        "Multi-label safety filter"
                    );
                } else {
                    // Single-label (binary) filter
                    let threshold = model_cfg.threshold.unwrap_or(0.5);
                    pipeline.add_model_filter(navra_core::safety::MlFilter::new(
                        classifier,
                        threshold,
                        "ml-unsafe",
                    ));
                }
            }
        }

        #[cfg(feature = "onnx")]
        if let Some(ref ner) = pii_ner_filter {
            match pset.safety.as_str() {
                "standard" | "guardian" | "guardian-deep" | "block" | "multi-label" => {
                    pipeline.add_ner_filter_shared(Arc::clone(ner));
                    tracing::info!(
                        permission_set = %name,
                        "PII NER filter added to safety profile"
                    );
                }
                _ => {}
            }
        }

        #[cfg(feature = "onnx")]
        if let Some(ref pf) = privacy_filter {
            match pset.safety.as_str() {
                "standard" | "guardian" | "guardian-deep" | "block" | "multi-label" => {
                    pipeline.add_privacy_filter_shared(Arc::clone(pf));
                    tracing::info!(
                        permission_set = %name,
                        "Privacy-filter added to safety profile"
                    );
                }
                _ => {}
            }
        }

        tracing::info!(
            permission_set = %name,
            safety = %pset.safety,
            "Safety profile"
        );
        builder = builder.safety_profile(name.clone(), pipeline);

        // Log compliance tags for audit trail
        if !pset.compliance.is_empty() {
            tracing::info!(
                permission_set = %name,
                tags = ?pset.compliance,
                "Compliance tags"
            );
        }

        // Build per-tool permission rules if any are configured
        if !pset.tool_rules.is_empty() {
            let rules: Vec<ToolRule> = pset
                .tool_rules
                .iter()
                .map(|r| ToolRule {
                    tool: r.tool.clone(),
                    policy: match r.policy.as_str() {
                        "deny" => ToolPolicy::Deny,
                        "approve" => ToolPolicy::Approve,
                        _ => ToolPolicy::Allow,
                    },
                })
                .collect();
            let default = match pset.default_tool_policy.as_str() {
                "deny" => ToolPolicy::Deny,
                "approve" => ToolPolicy::Approve,
                _ => ToolPolicy::Allow,
            };
            tracing::info!(
                permission_set = %name,
                rules = rules.len(),
                "Tool permission rules"
            );
            builder = builder.tool_permissions(name.clone(), ToolPermissions::new(rules, default));
        }

        if !pset.operations.is_empty() {
            let ops: std::collections::HashSet<String> = pset.operations.iter().cloned().collect();
            builder = builder.agent_operations(name.clone(), ops);
        }

        if !pset.tool_disclosure_include.is_empty() || !pset.tool_disclosure_exclude.is_empty() {
            let disclosure = navra_core::permissions::ToolDisclosure::new(
                pset.tool_disclosure_include.clone(),
                pset.tool_disclosure_exclude.clone(),
            );
            tracing::info!(
                permission_set = %name,
                include = pset.tool_disclosure_include.len(),
                exclude = pset.tool_disclosure_exclude.len(),
                "Tool disclosure rules"
            );
            builder = builder.tool_disclosure(name.clone(), disclosure);
        }

        // Domain-based permission rules.
        // If explicit domain_rules are configured, use them.
        // Otherwise, synthesize from the operations field so that
        // prompts and resource templates are always enforced.
        let domain_rules = if !pset.domain_rules.is_empty() {
            let mut rules_map = std::collections::HashMap::new();
            for rule in &pset.domain_rules {
                let domain: navra_core::permissions::Domain = match rule.domain.parse() {
                    Ok(d) => d,
                    Err(e) => {
                        tracing::error!(
                            permission_set = %name,
                            domain = %rule.domain,
                            "Invalid domain in domain_rules: {e}, skipping"
                        );
                        continue;
                    }
                };
                let ops: std::collections::HashSet<navra_core::permissions::Operation> = rule
                    .operations
                    .iter()
                    .filter_map(|s| match s.parse() {
                        Ok(o) => Some(o),
                        Err(e) => {
                            tracing::error!(
                                permission_set = %name,
                                operation = %s,
                                "Invalid operation in domain_rules: {e}, skipping"
                            );
                            None
                        }
                    })
                    .collect();
                rules_map.insert(domain, ops);
            }
            tracing::info!(
                permission_set = %name,
                domains = rules_map.len(),
                source = "explicit",
                "Domain permission rules"
            );
            navra_core::permissions::DomainRules::new(rules_map)
        } else {
            // Synthesize from operations field: map string operations
            // to the wildcard domain so all primitives are covered.
            let ops: std::collections::HashSet<navra_core::permissions::Operation> = pset
                .operations
                .iter()
                .filter_map(|s| s.parse().ok())
                .collect();
            let mut rules_map = std::collections::HashMap::new();
            rules_map.insert(navra_core::permissions::Domain::Unknown, ops);
            tracing::info!(
                permission_set = %name,
                operations = ?pset.operations,
                source = "synthesized from operations",
                "Domain permission rules"
            );
            navra_core::permissions::DomainRules::new(rules_map)
        };
        builder = builder.domain_rules(name.clone(), domain_rules);

        // Per-tool classification overrides from permission set config
        if !pset.tool_class.is_empty() {
            let mut classes = std::collections::HashMap::new();
            for (tool_name, tc) in &pset.tool_class {
                match (tc.domain.parse(), tc.operation.parse()) {
                    (Ok(domain), Ok(operation)) => {
                        classes.insert(
                            tool_name.clone(),
                            navra_core::permissions::ResourceClass::new(domain, operation),
                        );
                    }
                    (Err(e), _) | (_, Err(e)) => {
                        tracing::error!(
                            permission_set = %name,
                            tool = %tool_name,
                            "Invalid tool_class: {e}, skipping"
                        );
                    }
                }
            }
            if !classes.is_empty() {
                tracing::info!(
                    permission_set = %name,
                    overrides = classes.len(),
                    "Tool classification overrides"
                );
                builder = builder.merge_tool_classifications(classes);
            }
        }
    }

    // Cost-aware model routing hook
    if cfg.routing.enabled {
        let hook = navra_core::hooks::RoutingHook::from_config(&cfg.routing);
        tracing::info!(
            tiers = cfg.routing.tiers.len(),
            default = %cfg.routing.default_tier,
            "Routing hook enabled"
        );
        builder = builder.hook(hook);
    }

    // Build shared approval infrastructure
    let approvals = Arc::new(navra_core::permissions::ApprovalStore::with_grant_ttl(
        cfg.approval.timeout_secs,
        cfg.approval.grant_ttl_secs,
    ));
    let _notifier: Arc<dyn navra_core::notify::Notifier> = match cfg.approval.notify.as_str() {
        "dbus" => match navra_core::notify::DbusNotifier::new().await {
            Ok(n) => {
                tracing::info!("D-Bus notifier connected");
                Arc::new(n)
            }
            Err(e) => {
                tracing::warn!("D-Bus unavailable ({e}), falling back to CLI-only approvals");
                Arc::new(navra_core::notify::NoopNotifier)
            }
        },
        _ => Arc::new(navra_core::notify::NoopNotifier),
    };

    // --- Resolve named models for modules ---
    // Find the first embedding model in the registry.
    let embedding_model_name = cfg
        .models
        .iter()
        .find(|(_, m)| m.task == "embedding")
        .map(|(name, _)| name.clone());
    let embedding_model = embedding_model_name
        .as_ref()
        .and_then(|name| models.get(name))
        .cloned();

    // --- Git module (upstream MCP server) ---
    // Git tools are provided by docker.io/mcp/git as an upstream MCP server.
    // Gateway-level path ACLs enforce repo_path permissions.
    if cfg.git_enabled() {
        let has_git_upstream = cfg
            .upstream
            .iter()
            .any(|u| u.name == "git" || u.name == "mcp-git");
        if !has_git_upstream {
            tracing::warn!(
                "[modules.git] is enabled but no [[upstream]] named 'git' found. \
                 Add to config.toml:\n\
                 [[upstream]]\n\
                 name = \"git\"\n\
                 transport = \"stdio\"\n\
                 command = [\"podman\", \"run\", \"--rm\", \"-i\", \"docker.io/mcp/git\"]"
            );
        }
    }

    // --- Exec module (OpenShell agent sandboxing) ---
    let exec_module: Option<Arc<exec_tools::ExecState>> =
        if let Some(ref gateway) = cfg.server.openshell_gateway {
            let channel = tonic::transport::Channel::from_shared(gateway.clone())
                .expect("valid OpenShell gateway URL")
                .connect_lazy();
            let client = navra_model_runtime::openshell::ComputeDriverClient::new(channel);
            let state = Arc::new(exec_tools::ExecState::new(client));
            tracing::info!(gateway = %gateway, "Tool 'exec_run' enabled (OpenShell)");
            let (def, handler) = exec_tools::exec_run_tool(Arc::clone(&state));
            builder = builder.tool(def, move |args, ctx| {
                let h = Arc::clone(&handler);
                Box::pin(async move { h(args, ctx).await })
            });
            Some(state)
        } else {
            None
        };

    // --- RAG module ---
    // Keep a shared reference to the chunk store so memory tools can
    // cascade-delete embedding vectors when knowledge entries are erased.
    let mut shared_chunk_store: Option<std::sync::Arc<navra_rag::ChunkStore>> = None;
    let mut rag_context_retriever: Option<Arc<dyn navra_agent::ContextRetriever>> = None;

    if cfg.rag_enabled() {
        if let Some(ref model) = embedding_model {
            let rag_db_path = cfg.rag_db_path();
            let dims = embedding_model_name
                .as_ref()
                .and_then(|name| cfg.models.get(name))
                .and_then(|m| m.dimensions)
                .unwrap_or(768);
            match navra_rag::ChunkStore::open(&rag_db_path, dims) {
                Ok(store) => {
                    // Enable semantic query cache if TTL > 0
                    let cache_ttl = cfg.rag_query_cache_ttl_secs();
                    let store = if cache_ttl > 0 {
                        let cache_config = navra_rag::QueryCacheConfig {
                            capacity: cfg.rag_query_cache_max_entries(),
                            ttl: std::time::Duration::from_secs(cache_ttl),
                            ..navra_rag::QueryCacheConfig::default()
                        };
                        tracing::info!(
                            ttl_secs = cache_ttl,
                            max_entries = cfg.rag_query_cache_max_entries(),
                            "RAG query cache enabled"
                        );
                        store.with_query_cache(cache_config)
                    } else {
                        store
                    };

                    let store_arc = std::sync::Arc::new(store);
                    shared_chunk_store = Some(Arc::clone(&store_arc));

                    // Load cross-encoder reranker if configured
                    let reranker: Arc<dyn navra_rag::Reranker> = {
                        let model_path = cfg.rag_reranker_model_path();
                        let tokenizer_path = cfg.rag_reranker_tokenizer_path();
                        let r = navra_rag::load_reranker(
                            model_path
                                .as_ref()
                                .map(|p| std::path::Path::new(p.as_str())),
                            tokenizer_path
                                .as_ref()
                                .map(|p| std::path::Path::new(p.as_str())),
                        );
                        Arc::from(r)
                    };

                    let chunk_config = navra_rag::ChunkConfig {
                        graphability_threshold: Some(0.3),
                        ..navra_rag::ChunkConfig::default()
                    };
                    let cascade = navra_rag::CascadeConfig {
                        bm25_skip_vector_threshold: Some(0.0000001),
                        vector_skip_rerank_threshold: Some(2.0),
                    };
                    let reranker_for_retriever = reranker.clone();
                    let cascade_for_retriever = cascade.clone();
                    let rag = navra_rag::RagModule::with_reranker(
                        store_arc,
                        model.clone(),
                        chunk_config,
                        perm_engine.clone(),
                        reranker,
                    )
                    .with_cascade(cascade)
                    .with_metrics(metrics.clone());
                    rag_context_retriever =
                        Some(Arc::new(crate::rag_retriever::RagRetriever::new(
                            Arc::clone(
                                shared_chunk_store
                                    .as_ref()
                                    .expect("chunk store must be initialized before RAG retriever"),
                            ),
                            model.clone(),
                            reranker_for_retriever,
                            cascade_for_retriever,
                            Some(metrics.clone()),
                        )));
                    tracing::info!(
                        "Module 'rag' enabled (db: {rag_db_path}, dims: {dims}, cascade: on, graphability: 0.3)"
                    );
                    builder = builder.module(rag);
                }
                Err(e) => {
                    tracing::error!("Failed to open RAG store: {e}");
                }
            }
        } else {
            tracing::warn!("RAG module requires an embedding model, skipping");
        }
    }

    // --- Voice module ---
    if let Some(voice_cfg) = cfg.modules.voice.as_ref().filter(|_| cfg.voice_enabled()) {
        let asr = models.get(&voice_cfg.asr_model).cloned();
        let tts = models.get(&voice_cfg.tts_model).cloned();

        match (asr, tts) {
            (Some(asr_model), Some(tts_model)) => {
                let voice = navra_modal_voice::VoiceModule::with_config(
                    asr_model,
                    tts_model,
                    voice_cfg.vad_threshold,
                    voice_cfg.max_record_secs,
                    voice_cfg.silence_timeout_ms,
                    voice_cfg.voice.clone(),
                    perm_engine.clone(),
                );
                tracing::info!(
                    asr = %voice_cfg.asr_model,
                    tts = %voice_cfg.tts_model,
                    "Module 'voice' enabled"
                );
                builder = builder.module(voice);
            }
            (None, _) => {
                tracing::warn!(
                    model = %voice_cfg.asr_model,
                    "Voice module: ASR model '{}' not found, skipping",
                    voice_cfg.asr_model
                );
            }
            (_, None) => {
                tracing::warn!(
                    model = %voice_cfg.tts_model,
                    "Voice module: TTS model '{}' not found, skipping",
                    voice_cfg.tts_model
                );
            }
        }
    }

    // --- Vision module ---
    if let Some(vision_cfg) = cfg.modules.vision.as_ref().filter(|_| cfg.vision_enabled()) {
        if let Some(vision_model) = models.get(&vision_cfg.model).cloned() {
            let vision = navra_modal_vision::VisionModule::new(vision_model, perm_engine.clone());
            tracing::info!(model = %vision_cfg.model, "Module 'vision' enabled");
            builder = builder.module(vision);
        } else {
            tracing::warn!(
                model = %vision_cfg.model,
                "Vision module: model '{}' not found, skipping",
                vision_cfg.model
            );
        }
    }

    // --- Load ForgeService for persona auto-discovery ---
    // Loaded once here so upstream persona: prompts can be registered
    // before the forge is shared with other subsystems.
    let mut forge = if let Some(ref cc_path) = cfg.cognitive_core {
        let expanded = expand_tilde(cc_path);
        match navra_cognitive::ForgeService::load(std::path::Path::new(&expanded)) {
            Ok(f) => f,
            Err(e) => {
                tracing::warn!(error = %e, "Failed to load cognitive core, using empty forge");
                navra_cognitive::ForgeService::empty()
            }
        }
    } else {
        navra_cognitive::ForgeService::empty()
    };

    // --- AID upstream discovery ---
    if !cfg.discover.is_empty() {
        tracing::info!(
            domains = cfg.discover.len(),
            "Discovering upstream MCP servers via AID"
        );
        let discovery_timeout = cfg
            .server
            .discovery
            .as_ref()
            .map(|d| std::time::Duration::from_secs(d.timeout_secs))
            .unwrap_or_else(|| std::time::Duration::from_secs(10));
        let discovered =
            discover::discover_all_with_timeout(&cfg.discover, discovery_timeout).await;
        for endpoint in &discovered {
            tracing::info!(
                domain = %endpoint.domain,
                url = %endpoint.url,
                description = ?endpoint.description,
                auth = ?endpoint.auth,
                "Discovered MCP endpoint"
            );
            let transport =
                rmcp::transport::StreamableHttpClientTransport::from_uri(endpoint.url.clone());
            match rmcp::service::ServiceExt::<rmcp::RoleClient>::serve((), transport).await {
                Ok(client) => {
                    let peer = client.peer().clone();
                    tokio::spawn(async move {
                        let _ = client.waiting().await;
                    });
                    let module = navra_core::UpstreamModule::discover(
                        &endpoint.domain,
                        peer,
                        None,
                        &Default::default(),
                    )
                    .await;
                    tracing::info!(
                        domain = %endpoint.domain,
                        "Connected discovered upstream (rmcp)"
                    );
                    for prompt_def in module.discovered_prompts() {
                        if let Some(persona_name) = prompt_def.name.strip_prefix("persona:") {
                            let description = prompt_def.description.as_deref().unwrap_or("");
                            forge.register_upstream_persona(
                                persona_name,
                                module.upstream_name(),
                                &prompt_def.name,
                                description,
                            );
                        }
                    }
                    builder = builder.module(module);
                }
                Err(e) => {
                    tracing::warn!(
                        domain = %endpoint.domain,
                        error = %e,
                        "Failed to connect to discovered endpoint"
                    );
                }
            }
        }
        if discovered.is_empty() && !cfg.discover.is_empty() {
            tracing::info!("No MCP endpoints discovered via AID");
        }
    }

    // --- mDNS/DNS-SD LAN discovery ---
    let mdns_enabled = cfg
        .server
        .discovery
        .as_ref()
        .map(|d| d.mdns)
        .unwrap_or(false);
    // Keep the daemon alive for advertising — drop stops it.
    let mut _mdns_daemon: Option<mdns_sd::ServiceDaemon> = None;

    if mdns_enabled {
        let mdns_browse_secs = cfg
            .server
            .discovery
            .as_ref()
            .map(|d| d.mdns_browse_secs)
            .unwrap_or(3);
        tracing::info!("Browsing LAN for MCP servers via mDNS...");
        let lan_servers = mdns::browse(std::time::Duration::from_secs(mdns_browse_secs)).await;

        for server in &lan_servers {
            let url = server.url();
            let transport = rmcp::transport::StreamableHttpClientTransport::from_uri(url.clone());
            match rmcp::service::ServiceExt::<rmcp::RoleClient>::serve((), transport).await {
                Ok(client) => {
                    let peer = client.peer().clone();
                    tokio::spawn(async move {
                        let _ = client.waiting().await;
                    });
                    let module = navra_core::UpstreamModule::discover(
                        &server.name,
                        peer,
                        None,
                        &Default::default(),
                    )
                    .await;
                    tracing::info!(
                        name = %server.name,
                        url = %url,
                        "Connected LAN upstream (rmcp)"
                    );
                    for prompt_def in module.discovered_prompts() {
                        if let Some(persona_name) = prompt_def.name.strip_prefix("persona:") {
                            let description = prompt_def.description.as_deref().unwrap_or("");
                            forge.register_upstream_persona(
                                persona_name,
                                module.upstream_name(),
                                &prompt_def.name,
                                description,
                            );
                        }
                    }
                    builder = builder.module(module);
                }
                Err(e) => {
                    tracing::debug!(
                        name = %server.name,
                        error = %e,
                        "Failed to connect to LAN upstream"
                    );
                }
            }
        }
    }

    // --- Upstream MCP servers ---
    for upstream_cfg in &cfg.upstream {
        if !upstream_cfg.enabled.unwrap_or(true) {
            tracing::info!(upstream = %upstream_cfg.name, "Upstream disabled, skipping");
            continue;
        }

        // OpenAPI bridge — parse spec directly, skip MCP transport
        if let Some(ref spec_source) = upstream_cfg.openapi {
            let auth = resolve_openapi_auth(&upstream_cfg.auth);
            let spec_source = resolve_env_vars(spec_source);
            let timeout = upstream_cfg
                .request_timeout_secs
                .map(std::time::Duration::from_secs);
            let max_response_bytes = upstream_cfg.max_response_bytes.or(Some(32768));
            match navra_openapi::OpenApiModule::from_spec_with_timeout(
                &upstream_cfg.name,
                &spec_source,
                auth,
                &upstream_cfg.tool_filter,
                timeout,
                max_response_bytes,
            )
            .await
            {
                Ok(mut module) => {
                    // Remove denied tools before they reach tools/list
                    if !upstream_cfg.tool_overrides.is_empty() {
                        module.apply_overrides(&upstream_cfg.tool_overrides);
                    }

                    tracing::info!(
                        upstream = %upstream_cfg.name,
                        tools = module.tool_count(),
                        "Connected OpenAPI upstream"
                    );

                    // Merge tool operations (read/write classification)
                    let mut ops = module.tool_operations();
                    for (tool_name, override_str) in &upstream_cfg.tool_overrides {
                        match override_str.as_str() {
                            "read" => {
                                ops.insert(tool_name.clone(), navra_core::ToolOperation::Read);
                            }
                            "write" => {
                                ops.insert(tool_name.clone(), navra_core::ToolOperation::Write);
                            }
                            "deny" => {
                                ops.insert(tool_name.clone(), navra_core::ToolOperation::Deny);
                            }
                            _ => {
                                tracing::warn!(
                                    upstream = %upstream_cfg.name,
                                    tool = %tool_name,
                                    value = %override_str,
                                    "Invalid tool_overrides value, expected read/write/deny"
                                );
                            }
                        }
                    }
                    builder = builder.merge_tool_operations(ops);

                    // Apply tool_class overrides
                    if !upstream_cfg.tool_class.is_empty() {
                        let mut classes = std::collections::HashMap::new();
                        for (tool_name, tc) in &upstream_cfg.tool_class {
                            match (tc.domain.parse(), tc.operation.parse()) {
                                (Ok(domain), Ok(operation)) => {
                                    classes.insert(
                                        tool_name.clone(),
                                        navra_core::permissions::ResourceClass::new(
                                            domain, operation,
                                        ),
                                    );
                                }
                                (Err(e), _) | (_, Err(e)) => {
                                    tracing::error!(
                                        upstream = %upstream_cfg.name,
                                        tool = %tool_name,
                                        "Invalid tool_class: {e}, skipping"
                                    );
                                }
                            }
                        }
                        if !classes.is_empty() {
                            builder = builder.merge_tool_classifications(classes);
                        }
                    }

                    builder = builder.module(module);
                }
                Err(e) => {
                    tracing::error!(
                        upstream = %upstream_cfg.name,
                        error = %e,
                        "Failed to parse OpenAPI spec, skipping"
                    );
                }
            }
            continue;
        }

        let module_result = match upstream_cfg.transport.as_str() {
            "stdio" => {
                let mut cmd = tokio::process::Command::new(&upstream_cfg.command[0]);
                for arg in &upstream_cfg.command[1..] {
                    cmd.arg(arg);
                }
                if let Some(ref cwd) = upstream_cfg.cwd {
                    cmd.current_dir(cwd);
                }
                // Inject plain environment variables
                for (key, val) in &upstream_cfg.env {
                    cmd.env(key, val);
                }
                // Resolve credentials from store and inject as env vars
                for (env_var, label) in &upstream_cfg.credentials {
                    match credential_store.resolve(label) {
                        Ok(secret) => {
                            if let Some(val) = secret.as_str() {
                                cmd.env(env_var, val);
                                tracing::debug!(
                                    upstream = %upstream_cfg.name,
                                    env = %env_var,
                                    label = %label,
                                    "Credential injected"
                                );
                            } else {
                                tracing::warn!(
                                    upstream = %upstream_cfg.name,
                                    label = %label,
                                    "Credential is not valid UTF-8, skipping"
                                );
                            }
                        }
                        Err(e) => {
                            tracing::warn!(
                                upstream = %upstream_cfg.name,
                                label = %label,
                                error = %e,
                                "Failed to resolve credential, upstream may fail"
                            );
                        }
                    }
                }
                match rmcp::transport::TokioChildProcess::new(cmd) {
                    Ok(transport) => {
                        match rmcp::service::ServiceExt::<rmcp::RoleClient>::serve((), transport)
                            .await
                        {
                            Ok(client) => {
                                let peer = client.peer().clone();
                                tokio::spawn(async move {
                                    let _ = client.waiting().await;
                                });
                                Ok(navra_core::UpstreamModule::discover(
                                    &upstream_cfg.name,
                                    peer,
                                    None,
                                    &upstream_cfg.tool_overrides,
                                )
                                .await)
                            }
                            Err(e) => Err(format!("rmcp init failed: {e}")),
                        }
                    }
                    Err(e) => Err(format!("spawn failed: {e}")),
                }
            }
            "http" | "streamable-http" | "sse" => {
                let url = match &upstream_cfg.url {
                    Some(u) => u.as_str(),
                    None => {
                        tracing::error!(
                            upstream = %upstream_cfg.name,
                            "HTTP/SSE upstream requires 'url' field, skipping"
                        );
                        continue;
                    }
                };
                let transport = rmcp::transport::StreamableHttpClientTransport::from_uri(url);
                match rmcp::service::ServiceExt::<rmcp::RoleClient>::serve((), transport).await {
                    Ok(client) => {
                        let peer = client.peer().clone();
                        tokio::spawn(async move {
                            let _ = client.waiting().await;
                        });
                        Ok(navra_core::UpstreamModule::discover(
                            &upstream_cfg.name,
                            peer,
                            None,
                            &upstream_cfg.tool_overrides,
                        )
                        .await)
                    }
                    Err(e) => Err(format!("rmcp init failed: {e}")),
                }
            }
            other => {
                tracing::error!(
                    upstream = %upstream_cfg.name,
                    transport = %other,
                    "Unknown transport type, skipping"
                );
                continue;
            }
        };

        match module_result {
            Ok(module) => {
                tracing::info!(
                    upstream = %upstream_cfg.name,
                    transport = %upstream_cfg.transport,
                    "Connected upstream (rmcp)"
                );

                for prompt_def in module.discovered_prompts() {
                    if let Some(persona_name) = prompt_def.name.strip_prefix("persona:") {
                        let description = prompt_def.description.as_deref().unwrap_or("");
                        forge.register_upstream_persona(
                            persona_name,
                            module.upstream_name(),
                            &prompt_def.name,
                            description,
                        );
                    }
                }

                builder = builder.merge_tool_operations(module.tool_operations().clone());
                builder = builder.merge_tool_classifications(module.tool_classifications().clone());
                builder = builder.upstream_module(&upstream_cfg.name);

                if !upstream_cfg.tool_class.is_empty() {
                    let mut classes = std::collections::HashMap::new();
                    for (tool_name, tc) in &upstream_cfg.tool_class {
                        match (tc.domain.parse(), tc.operation.parse()) {
                            (Ok(domain), Ok(operation)) => {
                                classes.insert(
                                    tool_name.clone(),
                                    navra_core::permissions::ResourceClass::new(domain, operation),
                                );
                            }
                            (Err(e), _) | (_, Err(e)) => {
                                tracing::error!(
                                    upstream = %upstream_cfg.name,
                                    tool = %tool_name,
                                    "Invalid tool_class: {e}, skipping"
                                );
                            }
                        }
                    }
                    if !classes.is_empty() {
                        tracing::info!(
                            upstream = %upstream_cfg.name,
                            overrides = classes.len(),
                            "Upstream tool classification overrides"
                        );
                        builder = builder.merge_tool_classifications(classes);
                    }
                }

                builder = builder.module(module);
            }
            Err(e) => {
                tracing::error!(
                    upstream = %upstream_cfg.name,
                    error = %e,
                    "Failed to connect upstream, skipping"
                );
            }
        }
    }

    // --- gRPC out-of-process modules ---
    let mut _grpc_manager = if !cfg.grpc_modules.is_empty() {
        let mut manager = grpc_manager::GrpcModuleManager::new(cfg.grpc_modules.clone());
        let modules = manager.start_all().await;
        for module in modules {
            tracing::info!(module = module.name(), "Connected gRPC module");
            builder = builder.module(module);
        }
        Some(manager)
    } else {
        None
    };

    // Register cap_delegate tool if any agent can delegate
    if cfg.permissions.values().any(|ps| ps.can_delegate) {
        let delegate_signer = Arc::clone(&root_signer);
        let delegate_permissions = cfg.permissions.clone();
        let max_depth = cfg
            .server
            .identity
            .as_ref()
            .map(|i| i.max_delegation_depth)
            .unwrap_or(3);
        let default_ttl = cfg
            .server
            .identity
            .as_ref()
            .map(|i| i.token_ttl)
            .unwrap_or(3600);

        builder = builder.tool(
            navra_core::protocol::ToolDefinition::new(
                "cap_delegate",
                "Issue an attenuated capability token for a sub-agent. \
                     The new token grants a subset of the caller's capabilities.",
                navra_protocol::compat::tool_input_schema(
                    {
                        let mut props = std::collections::HashMap::new();
                        props.insert(
                            "subject_did".to_string(),
                            serde_json::json!({
                                "type": "string",
                                "description": "DID of the sub-agent receiving the token"
                            }),
                        );
                        props.insert(
                            "ring".to_string(),
                            serde_json::json!({
                                "type": "integer",
                                "description": "Ring level (must be >= caller's ring)"
                            }),
                        );
                        props.insert(
                            "operations".to_string(),
                            serde_json::json!({
                                "type": "array", "items": { "type": "string" },
                                "description": "Operations to grant (subset of caller's)"
                            }),
                        );
                        props.insert(
                            "tools".to_string(),
                            serde_json::json!({
                                "type": "array", "items": { "type": "string" },
                                "description": "Tool globs to grant (subset of caller's)"
                            }),
                        );
                        props.insert(
                            "paths".to_string(),
                            serde_json::json!({
                                "type": "array", "items": { "type": "string" },
                                "description": "Path globs to grant (subset of caller's)"
                            }),
                        );
                        props.insert(
                            "credentials".to_string(),
                            serde_json::json!({
                                "type": "array", "items": { "type": "string" },
                                "description": "Credential labels to grant (subset of caller's)"
                            }),
                        );
                        props.insert(
                            "ttl".to_string(),
                            serde_json::json!({
                                "type": "integer",
                                "description": "Token TTL in seconds"
                            }),
                        );
                        Some(props)
                    },
                    Some(vec!["subject_did".to_string()]),
                ),
            ),
            move |args, ctx| {
                let signer = Arc::clone(&delegate_signer);
                let permissions = delegate_permissions.clone();
                let max_depth = max_depth;
                let default_ttl = default_ttl;
                Box::pin(async move {
                    use navra_core::auth::capability::{
                        CapabilitySet, build_payload, encode_token, validate_delegation,
                    };
                    use navra_core::protocol::CallToolResult;

                    // Check caller has capabilities (must be cap-token authenticated)
                    // Reject callers with wildcard tool access — cap_delegate must
                    // be explicitly listed in the token's tools (CWE-269).
                    let parent_caps = match &ctx.agent.capabilities {
                        Some(caps) => {
                            if !caps.tools.iter().any(|t| t == "cap_delegate") {
                                return CallToolResult::error_msg(
                                    "Permission denied: cap_delegate must be explicitly \
                                     listed in capability token tools (wildcard not accepted)",
                                );
                            }
                            caps
                        }
                        None => {
                            // Legacy agent — check can_delegate via permission set
                            let perm_name = &ctx.agent.permissions;
                            let can_delegate = permissions
                                .get(perm_name)
                                .map(|ps| ps.can_delegate)
                                .unwrap_or(false);
                            if !can_delegate {
                                return CallToolResult::error_msg(
                                    "Permission denied: delegation not allowed for this agent",
                                );
                            }
                            // Build a pseudo-parent from permission set for validation
                            return CallToolResult::error_msg(
                                "Delegation requires a capability token. \
                                 Use a capability-token-authenticated session.",
                            );
                        }
                    };

                    let subject_did = args
                        .get("subject_did")
                        .and_then(|v| v.as_str())
                        .unwrap_or("")
                        .to_string();
                    if subject_did.is_empty() {
                        return CallToolResult::error_msg("subject_did is required");
                    }

                    let ring = args
                        .get("ring")
                        .and_then(|v| v.as_u64())
                        .unwrap_or(parent_caps.ring as u64) as u8;

                    let operations: Vec<String> = args
                        .get("operations")
                        .and_then(|v| v.as_array())
                        .map(|arr| {
                            arr.iter()
                                .filter_map(|v| v.as_str().map(String::from))
                                .collect()
                        })
                        .unwrap_or_else(|| parent_caps.operations.iter().cloned().collect());

                    let tools: Vec<String> = args
                        .get("tools")
                        .and_then(|v| v.as_array())
                        .map(|arr| {
                            arr.iter()
                                .filter_map(|v| v.as_str().map(String::from))
                                .collect()
                        })
                        .unwrap_or_else(|| parent_caps.tools.clone());

                    let paths: Vec<String> = args
                        .get("paths")
                        .and_then(|v| v.as_array())
                        .map(|arr| {
                            arr.iter()
                                .filter_map(|v| v.as_str().map(String::from))
                                .collect()
                        })
                        .unwrap_or_else(|| parent_caps.paths.clone());

                    let credentials: Vec<String> = args
                        .get("credentials")
                        .and_then(|v| v.as_array())
                        .map(|arr| {
                            arr.iter()
                                .filter_map(|v| v.as_str().map(String::from))
                                .collect()
                        })
                        .unwrap_or_else(|| parent_caps.credentials.clone());

                    let ttl = args
                        .get("ttl")
                        .and_then(|v| v.as_u64())
                        .unwrap_or(default_ttl);

                    let cap_set = CapabilitySet {
                        paths,
                        operations,
                        tools,
                        credentials,
                    };

                    let issuer_did = ctx
                        .agent
                        .did
                        .clone()
                        .unwrap_or_else(|| format!("agent:{}", ctx.agent.name));

                    let mut child_payload =
                        build_payload(&issuer_did, &subject_did, cap_set, ring, ttl);

                    // Build parent payload for validation
                    let parent_payload = navra_core::auth::capability::CapabilityPayload {
                        v: 1,
                        iss: signer.did().to_string(),
                        sub: issuer_did.clone(),
                        cap: CapabilitySet {
                            paths: parent_caps.paths.clone(),
                            operations: parent_caps.operations.iter().cloned().collect(),
                            tools: parent_caps.tools.clone(),
                            credentials: parent_caps.credentials.clone(),
                        },
                        ring: parent_caps.ring,
                        iat: 0,
                        exp: parent_caps.expires_at,
                        nonce: navra_core::auth::capability::generate_nonce(),
                        parent: None,
                        obo: None,
                        sandbox: None,
                        aud: None,
                    };

                    // Set parent nonce reference
                    child_payload.parent = Some(parent_payload.nonce);

                    // Validate attenuation
                    if let Err(e) = validate_delegation(&parent_payload, &child_payload, max_depth)
                    {
                        return CallToolResult::error_msg(format!("Delegation denied: {e}"));
                    }

                    // Sign with root key (navra signs all tokens)
                    match encode_token(&child_payload, signer.as_ref()) {
                        Ok(token) => {
                            tracing::info!(
                                issuer = %issuer_did,
                                subject = %subject_did,
                                ring = ring,
                                "Delegated capability token"
                            );
                            CallToolResult::text(token)
                        }
                        Err(e) => CallToolResult::error_msg(format!("Failed to sign token: {e}")),
                    }
                })
            },
        );
        tracing::info!("Registered cap_delegate tool");
    }

    // Register sys_status tool (process table viewer)
    {
        builder = builder.tool(
            navra_core::protocol::ToolDefinition::new(
                "sys_status",
                "Show AI OS process table: active agents, their rings, \
                     call counts, and active tool calls.",
                navra_protocol::compat::tool_input_schema(None, None),
            ),
            |_args, _ctx| {
                // The actual data comes from the server's process table,
                // but the handler doesn't have access to &self.
                // We return a placeholder — the real implementation
                // will be added when we refactor tool handlers to
                // receive a server reference.
                Box::pin(async {
                    navra_core::protocol::CallToolResult::text(
                        "sys_status: use GET /sys/status for process table",
                    )
                })
            },
        );
    }

    // Resolve flow directories (auto-discover if not configured)
    let resolved_flow_dirs = {
        let mut dirs = cfg.flow_dirs.clone();
        if dirs.is_empty() {
            for candidate in &["examples/flows", "flows"] {
                if std::path::Path::new(candidate).is_dir() {
                    dirs.push(candidate.to_string());
                }
            }
        }
        dirs
    };

    // Open audit log early so it can be shared with flow tools and audit_query.
    let audit_db_path = dirs::data_dir()
        .unwrap_or_else(|| std::path::PathBuf::from("."))
        .join("navra/audit.db");
    if let Some(parent) = audit_db_path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    let audit_sanitizer: Option<navra_memory::ContentSanitizer> = {
        let sanitizer_pipeline = memory_tools::build_pii_sanitizer(cfg.memory_pii_filter());
        sanitizer_pipeline.map(|pipeline| -> navra_memory::ContentSanitizer {
            Arc::new(move |content: &str| {
                memory_tools::sanitize_for_storage_sync(content, &Some(Arc::clone(&pipeline)))
            })
        })
    };
    let audit_log: Arc<navra_memory::AuditLog> =
        match navra_memory::audit::AuditLog::open(&audit_db_path) {
            Ok(log) => {
                let log = match audit_sanitizer {
                    Some(sanitizer) => log.with_sanitizer(sanitizer),
                    None => log,
                };
                tracing::info!(path = %audit_db_path.display(), "Audit log enabled");
                Arc::new(log)
            }
            Err(e) => {
                tracing::warn!(error = %e, "Failed to open audit DB, using in-memory");
                match navra_memory::audit::AuditLog::open_memory() {
                    Ok(log) => Arc::new(log),
                    Err(e2) => {
                        anyhow::bail!(
                            "Failed to open audit DB ({e}) and in-memory fallback ({e2})"
                        );
                    }
                }
            }
        };
    if let Some(days) = cfg.memory_audit_retention_days() {
        match audit_log.expire_older_than(days) {
            Ok(n) if n > 0 => tracing::info!(
                deleted = n,
                days = days,
                "Retention: expired old audit entries"
            ),
            _ => {}
        }
    }

    // Register flow orchestration tools
    let flow_registry = Arc::new(flow_tools::FlowRegistry::new());
    {
        // flow_start — registered later, after team_registry is created

        // flow_status — check progress of a flow
        let registry = Arc::clone(&flow_registry);
        builder = builder.tool(flow_tools::flow_status_tool_def(), move |args, _ctx| {
            let registry = Arc::clone(&registry);
            Box::pin(flow_tools::handle_flow_status(args, registry))
        });

        // flow_result — get output from a completed flow or node
        let registry = Arc::clone(&flow_registry);
        let fr_audit = Arc::clone(&audit_log);
        builder = builder.tool(flow_tools::flow_result_tool_def(), move |args, _ctx| {
            let registry = Arc::clone(&registry);
            let audit = Arc::clone(&fr_audit);
            Box::pin(flow_tools::handle_flow_result(args, registry, Some(audit)))
        });

        // flow_list — list available YAML flows from configured directories
        let flow_dirs = resolved_flow_dirs.clone();
        builder = builder.tool(flow_tools::flow_list_tool_def(), move |_args, _ctx| {
            let flow_dirs = flow_dirs.clone();
            Box::pin(flow_tools::handle_flow_list(flow_dirs))
        });

        tracing::info!(
            "Registered flow orchestration tools (flow_start, flow_status, flow_result, flow_list, flow_escalate)"
        );
    }

    // Trigger infrastructure: initialized after flow_ctx is built.
    let mut _trigger_registry: Option<triggers::TriggerRegistry> = None;
    let mut trigger_webhook_router: Option<axum::Router> = None;

    // Register team orchestration tools
    {
        // Pre-fetch Ollama model metadata for all locally running models.
        // This populates vendor fields (family, parameters, context_window)
        // so the lead agent can make informed model selection decisions.
        let mut ollama_meta: std::collections::HashMap<String, serde_json::Value> =
            std::collections::HashMap::new();
        if let Ok(resp) = reqwest::Client::new()
            .get("http://localhost:11434/api/tags")
            .send()
            .await
            && let Ok(tags) = resp.json::<serde_json::Value>().await
            && let Some(models) = tags["models"].as_array()
        {
            for m in models {
                if let Some(name) = m["name"].as_str() {
                    // Query /api/show for detailed model info
                    if let Ok(show_resp) = reqwest::Client::new()
                        .post("http://localhost:11434/api/show")
                        .json(&serde_json::json!({"name": name}))
                        .send()
                        .await
                        && let Ok(info) = show_resp.json::<serde_json::Value>().await
                    {
                        ollama_meta.insert(name.to_string(), info);
                    }
                }
            }
        }
        if !ollama_meta.is_empty() {
            tracing::info!(
                models = ollama_meta.len(),
                "Fetched Ollama model metadata for model cards"
            );
        }

        // Build composite model cards from config + discovered Ollama models.
        // Config entries take precedence; Ollama models not in config are added automatically.
        let mut model_keys: Vec<(String, Option<&config::ModelConfig>)> = cfg
            .models
            .iter()
            .map(|(k, v)| (k.clone(), Some(v)))
            .collect();
        let configured_sources: std::collections::HashSet<String> = cfg
            .models
            .values()
            .filter_map(|m| m.source.as_ref())
            .filter_map(|s| s.strip_prefix("ollama://"))
            .map(|s| s.to_string())
            .collect();
        for name in ollama_meta.keys() {
            if !configured_sources.contains(name) {
                model_keys.push((name.clone(), None));
            }
        }

        let model_cards: Vec<team_tools::ModelCard> = model_keys
            .iter()
            .map(|(name, mcfg_opt)| {
                let mcfg_ref = mcfg_opt.as_ref();
                let display_name = mcfg_ref
                    .and_then(|m| m.model_name.as_deref())
                    .unwrap_or(name);
                let uri_str = mcfg_ref
                    .and_then(|m| m.source.as_deref())
                    .unwrap_or(display_name);
                let mut card = navra_model_hub::ModelCard::new(uri_str);

                // Populate vendor metadata from config (if available)
                if let Some(mcfg) = mcfg_ref {
                    card.vendor.source = Some(
                        if mcfg.source.is_some() {
                            match mcfg.source.as_deref() {
                                Some(s) if s.starts_with("ollama://") => "ollama",
                                Some(s) if s.starts_with("hf://") => "huggingface",
                                Some(s) if s.starts_with("oci://") => "oci",
                                _ => "local",
                            }
                        } else {
                            "local"
                        }
                        .into(),
                    );
                    card.vendor.context_window = mcfg.context_size;
                    card.vendor.tasks = match mcfg.task.as_str() {
                        "chat" | "generate" => vec!["text-generation".into()],
                        "embedding" => vec!["feature-extraction".into()],
                        "classification" => vec!["text-classification".into()],
                        _ => vec![],
                    };
                    if let Some(runtime) = &mcfg.runtime {
                        card.vendor.runtime = Some(runtime.clone());
                    }
                }

                // Enrich with Ollama /api/show metadata if available
                if let Some(info) = ollama_meta.get(display_name) {
                    card.vendor.source = Some("ollama".into());
                    // model_info contains parameter count, architecture, etc.
                    if let Some(model_info) = info.get("model_info") {
                        // Extract context window from model metadata
                        for (key, val) in model_info.as_object().into_iter().flatten() {
                            if key.ends_with(".context_length")
                                && let Some(ctx) = val.as_u64()
                            {
                                card.vendor.context_window = Some(ctx as u32);
                            }
                            if key.ends_with(".embedding_length")
                                && let Some(dim) = val.as_u64()
                            {
                                card.vendor
                                    .custom
                                    .insert("embedding_dim".into(), serde_json::json!(dim));
                            }
                        }
                        // Parameter count from general.parameter_count
                        if let Some(params) = model_info.get("general.parameter_count")
                            && let Some(p) = params.as_u64()
                        {
                            let label = if p >= 1_000_000_000 {
                                format!("{}B", p / 1_000_000_000)
                            } else if p >= 1_000_000 {
                                format!("{}M", p / 1_000_000)
                            } else {
                                format!("{p}")
                            };
                            card.vendor.parameters = Some(label);
                        }
                        // Architecture / family
                        if let Some(arch) = model_info.get("general.architecture")
                            && let Some(a) = arch.as_str()
                        {
                            card.vendor.family = Some(a.to_string());
                        }
                    }
                    // Quantization from details
                    if let Some(details) = info.get("details") {
                        if let Some(quant) = details.get("quantization_level")
                            && let Some(q) = quant.as_str()
                        {
                            card.vendor.quantization = Some(q.to_string());
                        }
                        if let Some(family) = details.get("family")
                            && card.vendor.family.is_none()
                        {
                            card.vendor.family = family.as_str().map(|s| s.to_string());
                        }
                    }
                    // License from license field
                    if let Some(license) = info.get("license")
                        && let Some(l) = license.as_str()
                    {
                        // Take first line as the license identifier
                        card.vendor.license = l.lines().next().map(|s| s.to_string());
                    }
                    card.vendor.format = Some("gguf".into());
                }

                // Detect Claude/Anthropic models
                if display_name.starts_with("claude") {
                    card.vendor.source = Some("anthropic".into());
                    card.vendor.family = Some("claude".into());
                    // Extract parameter hint from model name (e.g. "sonnet", "opus")
                    if display_name.contains("sonnet") {
                        card.vendor.parameters = Some("medium".into());
                    } else if display_name.contains("opus") {
                        card.vendor.parameters = Some("large".into());
                    } else if display_name.contains("haiku") {
                        card.vendor.parameters = Some("small".into());
                    }
                }

                // Merge operator-defined agentic metadata from config
                if let Some(mcfg) = mcfg_ref
                    && let Some(agentic_cfg) = &mcfg.agentic
                {
                    card.merge_agentic(&agentic_cfg.to_agentic_meta());
                }

                card
            })
            .collect();

        let team_registry = Arc::new(team_tools::TeamRegistry::new().with_models(model_cards));

        // Containerized agent execution: detect mode and start shared model server
        let containerized = match cfg.server.containerized {
            Some(true) => {
                if team_tools::is_podman_available() {
                    true
                } else {
                    tracing::warn!(
                        "Containerized mode requested but Podman not available, falling back to in-process"
                    );
                    false
                }
            }
            Some(false) => false,
            None => team_tools::is_podman_available(),
        };

        let model_server_url: Option<String> = if containerized {
            match start_model_server_container(&cfg).await {
                Ok((url, port, name)) => {
                    tracing::info!(url = %url, container = %name, "Shared model server started");
                    // Track container for shutdown
                    running_endpoints.push((
                        Box::new(navra_model_runtime::podman::PodmanRuntime::new(
                            navra_model_runtime::Engine::LlamaCpp,
                        )),
                        navra_model_runtime::Endpoint {
                            url: format!("http://127.0.0.1:{port}"),
                            id: name,
                            backend: navra_model_runtime::RuntimeBackend::new(
                                navra_model_runtime::Engine::LlamaCpp,
                                navra_model_runtime::Isolation::Podman,
                            ),
                        },
                    ));
                    Some(url)
                }
                Err(e) => {
                    tracing::warn!(error = %e, "Failed to start model server container, agents will use Ollama");
                    None
                }
            }
        } else {
            None
        };

        let gpu_semaphore = Arc::new(tokio::sync::Semaphore::new(
            if cfg.budget.max_parallel == 0 {
                64
            } else {
                cfg.budget.max_parallel
            },
        ));

        if containerized {
            tracing::info!(
                agent_image = %cfg.server.agent_image,
                model_server = ?model_server_url,
                "Containerized agent execution enabled"
            );
        }

        // team_create
        let reg = Arc::clone(&team_registry);
        let tc_budget_cfg = cfg.budget.clone();
        builder = builder.tool(team_tools::team_create_def(), move |args, ctx| {
            let reg = Arc::clone(&reg);
            let budget_cfg = tc_budget_cfg.clone();
            let agent_name = ctx.agent.name.clone();
            Box::pin(async move {
                team_tools::handle_team_create(args, reg, &budget_cfg, &agent_name).await
            })
        });

        // team_add
        let reg = Arc::clone(&team_registry);
        builder = builder.tool(team_tools::team_add_def(), move |args, _ctx| {
            let reg = Arc::clone(&reg);
            Box::pin(team_tools::handle_team_add(args, reg))
        });

        // Root capability payload for teammate token delegation.
        // Grants all operations and tools that teammates could possibly use.
        // Individual teammate tokens are scoped down from this via
        // build_delegated_payload (attenuation-only delegation chain).
        let root_cap = navra_core::auth::capability::CapabilitySet {
            paths: vec!["**".to_string()],
            operations: vec![
                "read".to_string(),
                "write".to_string(),
                "search".to_string(),
                "list".to_string(),
                "git.status".to_string(),
                "git.diff".to_string(),
                "git.log".to_string(),
                "git.commit".to_string(),
                "git.branch".to_string(),
            ],
            tools: vec!["*".to_string()],
            credentials: vec![],
        };
        let root_payload = navra_core::auth::capability::build_payload(
            root_signer.did(),
            root_signer.did(),
            root_cap,
            1,
            86400,
        );

        // Build a PII filter for model reasoning text. Uses "standard"
        // safety profile (regex PII + NER) to redact PII that the model
        // echoes in its reasoning even after tool results were redacted.
        let reasoning_pii_filter: Option<Arc<navra_core::safety::FilterPipeline>> = {
            let has_pii_profile = cfg.permissions.values().any(|p| {
                matches!(
                    p.safety.as_str(),
                    "standard" | "guardian" | "guardian-deep" | "block"
                )
            });
            if has_pii_profile {
                let mut pipeline = navra_core::safety::build_pipeline("standard");
                #[cfg(feature = "onnx")]
                if let Some(ref ner) = pii_ner_filter {
                    pipeline.add_ner_filter_shared(Arc::clone(ner));
                }
                #[cfg(feature = "onnx")]
                if let Some(ref pf) = privacy_filter {
                    pipeline.add_privacy_filter_shared(Arc::clone(pf));
                }
                tracing::info!("PII filter enabled for model reasoning text");
                Some(Arc::new(pipeline))
            } else {
                None
            }
        };

        // team_message — async: spawns full agent teammate in background
        let msg_spawn_ctx = Arc::new(team_tools::TeammateSpawnContext {
            team_registry: Arc::clone(&team_registry),
            navra_addr: cfg.server.listen_addr(),
            signer: Arc::clone(&root_signer),
            forge: cfg.cognitive_core.as_ref().and_then(|p| {
                let expanded = expand_tilde(p);
                navra_cognitive::ForgeService::load(std::path::Path::new(&expanded))
                    .map(Arc::new)
                    .ok()
            }),
            root_payload: Some(root_payload.clone()),
            pii_filter: reasoning_pii_filter.clone(),
            audit_log: Some(Arc::clone(&audit_log)),
            cognitive_core_path: cfg.cognitive_core.as_ref().map(|p| expand_tilde(p)),
            model_server_url: model_server_url.clone(),
            gpu_semaphore: Arc::clone(&gpu_semaphore),
            containerized,
            agent_image: cfg.server.agent_image.clone(),
            container_memory: cfg.server.container_memory.clone(),
            container_cpus: cfg.server.container_cpus.clone(),
            container_pids: cfg.server.container_pids,
            embedding_model: embedding_model.clone(),
            openshell_gateway: cfg.server.openshell_gateway.clone(),
            exec_state: exec_module.clone(),
            workspace_provider: None,
            max_tokens_per_run: cfg.budget.max_tokens_per_run,
            compression_start_ratio: cfg.budget.compression_start_ratio,
            compaction_keep_recent: cfg.budget.compaction_keep_recent,
            compaction_trigger_ratio: cfg.budget.compaction_trigger_ratio,
            initial_label: None,
        });
        builder = builder.tool(team_tools::team_message_def(), move |args, _ctx| {
            let spawn_ctx = Arc::clone(&msg_spawn_ctx);
            Box::pin(async move { team_tools::handle_team_message(args, &spawn_ctx).await })
        });

        // team_status
        let reg = Arc::clone(&team_registry);
        builder = builder.tool(team_tools::team_status_def(), move |args, _ctx| {
            let reg = Arc::clone(&reg);
            Box::pin(team_tools::handle_team_status(args, reg))
        });

        // team_result
        let reg = Arc::clone(&team_registry);
        builder = builder.tool(team_tools::team_result_def(), move |args, _ctx| {
            let reg = Arc::clone(&reg);
            Box::pin(team_tools::handle_team_result(args, reg))
        });

        // team_shutdown
        let reg = Arc::clone(&team_registry);
        builder = builder.tool(team_tools::team_shutdown_def(), move |args, _ctx| {
            let reg = Arc::clone(&reg);
            Box::pin(team_tools::handle_team_shutdown(args, reg))
        });

        // agent_signal
        let reg = Arc::clone(&team_registry);
        builder = builder.tool(team_tools::agent_signal_def(), move |args, _ctx| {
            let reg = Arc::clone(&reg);
            Box::pin(team_tools::handle_agent_signal(args, reg))
        });

        // models_list
        let cards = team_registry.model_cards.clone();
        builder = builder.tool(team_tools::models_list_def(), move |_args, _ctx| {
            let cards = cards.clone();
            Box::pin(team_tools::handle_models_list(cards))
        });

        // personas_list
        let persona_data: Vec<serde_json::Value> = if let Some(ref cc_path) = cfg.cognitive_core {
            let expanded = expand_tilde(cc_path);
            match navra_cognitive::ForgeService::load(std::path::Path::new(&expanded)) {
                Ok(forge) => forge
                    .persona_names()
                    .iter()
                    .filter_map(|name| {
                        forge.get_persona(name).map(|p| {
                            serde_json::json!({
                                "name": p.persona_name,
                                "display_name": p.display_name,
                                "mandate": p.core_mandate.lines().next().unwrap_or(""),
                                "heuristics": p.heuristics.len(),
                                "tools": p.tools,
                            })
                        })
                    })
                    .collect(),
                Err(_) => vec![],
            }
        } else {
            vec![]
        };
        builder = builder.tool(team_tools::personas_list_def(), move |_args, _ctx| {
            let data = persona_data.clone();
            Box::pin(team_tools::handle_personas_list(data))
        });

        // team_bb_publish
        let reg = Arc::clone(&team_registry);
        builder = builder.tool(team_tools::team_bb_publish_def(), move |args, ctx| {
            let reg = Arc::clone(&reg);
            let agent_name = ctx.agent.name.clone();
            let label = ctx.taint.level();
            Box::pin(async move {
                team_tools::handle_team_bb_publish(args, reg, &agent_name, label).await
            })
        });

        // team_bb_read
        let reg = Arc::clone(&team_registry);
        builder = builder.tool(team_tools::team_bb_read_def(), move |args, _ctx| {
            let reg = Arc::clone(&reg);
            Box::pin(team_tools::handle_team_bb_read(args, reg))
        });

        // team_bb_notifications
        let reg = Arc::clone(&team_registry);
        builder = builder.tool(team_tools::team_bb_notifications_def(), move |args, ctx| {
            let reg = Arc::clone(&reg);
            let agent_name = ctx.agent.name.clone();
            Box::pin(async move {
                team_tools::handle_team_bb_notifications(args, reg, &agent_name).await
            })
        });

        tracing::info!(
            "Registered team tools (team_create, team_add, team_message, team_status, team_result, team_shutdown, team_bb_publish, team_bb_read, team_bb_notifications, models_list)"
        );

        // Initialize checkpoint store if enabled
        let checkpoint = if cfg.budget.checkpoint {
            let db_path = expand_tilde(&cfg.budget.checkpoint_db);
            match navra_flow::DagCheckpoint::open(std::path::Path::new(&db_path)) {
                Ok(cp) => {
                    tracing::info!(path = %db_path, "Flow checkpoint store opened");
                    if let Ok(incomplete) = cp.list_incomplete()
                        && !incomplete.is_empty()
                    {
                        tracing::info!(
                            count = incomplete.len(),
                            flows = ?incomplete,
                            "Found incomplete flows from previous run (use flow_resume to continue)"
                        );
                    }
                    Some(Arc::new(cp))
                }
                Err(e) => {
                    tracing::warn!(path = %db_path, error = %e, "Failed to open checkpoint store — checkpointing disabled");
                    None
                }
            }
        } else {
            None
        };

        // flow_start and flow_escalate — shared context
        let flow_ctx = Arc::new(flow_tools::FlowContext {
            flow_registry: Arc::clone(&flow_registry),
            team_registry: Arc::clone(&team_registry),
            navra_addr: cfg.server.listen_addr(),
            signer: Arc::clone(&root_signer),
            forge: cfg.cognitive_core.as_ref().and_then(|p| {
                let expanded = expand_tilde(p);
                navra_cognitive::ForgeService::load(std::path::Path::new(&expanded))
                    .ok()
                    .map(Arc::new)
            }),
            budget_cfg: cfg.budget.clone(),
            flow_dirs: resolved_flow_dirs.clone(),
            docs_root: cfg
                .modules
                .file
                .as_ref()
                .and_then(|d| d.default_root.clone())
                .or_else(|| cfg.cognitive_core.clone()),
            root_payload: Some(root_payload.clone()),
            pii_filter: reasoning_pii_filter.clone(),
            audit_log: Some(Arc::clone(&audit_log)),
            cognitive_core_path: cfg.cognitive_core.as_ref().map(|p| expand_tilde(p)),
            model_server_url: model_server_url.clone(),
            gpu_semaphore: Arc::clone(&gpu_semaphore),
            containerized,
            agent_image: cfg.server.agent_image.clone(),
            container_memory: cfg.server.container_memory.clone(),
            container_cpus: cfg.server.container_cpus.clone(),
            container_pids: cfg.server.container_pids,
            embedding_model: embedding_model.clone(),
            openshell_gateway: cfg.server.openshell_gateway.clone(),
            exec_state: exec_module.clone(),
            workspace_provider: None,
            checkpoint,
        });

        // flow_start
        let fs_ctx = Arc::clone(&flow_ctx);
        builder = builder.tool(flow_tools::flow_start_tool_def(), move |args, ctx| {
            let flow_ctx = Arc::clone(&fs_ctx);
            let agent_name = ctx.agent.name.clone();
            Box::pin(
                async move { flow_tools::handle_flow_start(args, flow_ctx, &agent_name).await },
            )
        });

        // flow_escalate
        let fe_ctx = Arc::clone(&flow_ctx);
        builder = builder.tool(flow_tools::flow_escalate_tool_def(), move |args, ctx| {
            let flow_ctx = Arc::clone(&fe_ctx);
            let agent_name = ctx.agent.name.clone();
            Box::pin(
                async move { flow_tools::handle_flow_escalate(args, flow_ctx, &agent_name).await },
            )
        });

        let fr_ctx = Arc::clone(&flow_ctx);
        builder = builder.tool(flow_tools::flow_resume_tool_def(), move |args, ctx| {
            let flow_ctx = Arc::clone(&fr_ctx);
            let agent = ctx.agent.name.clone();
            Box::pin(async move { flow_tools::handle_flow_resume(args, flow_ctx, &agent).await })
        });

        tracing::info!("Registered flow tools (flow_escalate, flow_resume)");

        // --- Event-driven triggers ---
        if !cfg.triggers.is_empty() {
            let (registry, webhook_router) =
                triggers::TriggerRegistry::start(&cfg.triggers, Arc::clone(&flow_ctx));
            tracing::info!(count = cfg.triggers.len(), "Trigger infrastructure started");
            _trigger_registry = Some(registry);
            trigger_webhook_router = Some(webhook_router);
        }
    }

    // --- Knowledge memory tools ---
    let pii_metrics: Option<Arc<navra_core::safety::PiiMetrics>> = {
        let m = Arc::new(navra_core::safety::PiiMetrics::new());
        Some(m)
    };
    let pii_sanitizer = memory_tools::build_pii_sanitizer(cfg.memory_pii_filter());
    if pii_sanitizer.is_some() {
        tracing::info!(
            profile = cfg.memory_pii_filter(),
            "PII filter enabled for memory ingestion and audit logs"
        );
    }

    let knowledge_store: Option<Arc<std::sync::Mutex<navra_memory::KnowledgeStore>>> = {
        let kb_path = dirs::data_dir()
            .unwrap_or_else(|| std::path::PathBuf::from("."))
            .join("navra/knowledge.db");
        if let Some(parent) = kb_path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        match navra_memory::KnowledgeStore::open(&kb_path) {
            Ok(store) => {
                tracing::info!(path = %kb_path.display(), "Knowledge store opened");
                Some(Arc::new(std::sync::Mutex::new(store)))
            }
            Err(e) => {
                tracing::warn!(error = %e, "Failed to open knowledge store, memory tools disabled");
                None
            }
        }
    };

    if let Some(ks) = knowledge_store.clone() {
        let ks_store = Arc::clone(&ks);
        let sanitizer_for_store = pii_sanitizer.clone();
        builder = builder.tool(memory_tools::memory_store_def(), move |args, _ctx| {
            let ks = Arc::clone(&ks_store);
            let sanitizer = sanitizer_for_store.clone();
            Box::pin(memory_tools::handle_memory_store(args, ks, sanitizer))
        });

        let ks_query = Arc::clone(&ks);
        builder = builder.tool(memory_tools::memory_query_def(), move |args, _ctx| {
            let ks = Arc::clone(&ks_query);
            Box::pin(memory_tools::handle_memory_query(args, ks))
        });

        let ks_forget = Arc::clone(&ks);
        let cs_forget = shared_chunk_store.clone();
        builder = builder.tool(memory_tools::memory_forget_def(), move |args, _ctx| {
            let ks = Arc::clone(&ks_forget);
            let cs = cs_forget.clone();
            Box::pin(memory_tools::handle_memory_forget(args, ks, cs))
        });

        let ks_purge = Arc::clone(&ks);
        let sanitizer_for_purge = pii_sanitizer.clone();
        let cs_purge = shared_chunk_store.clone();
        builder = builder.tool(memory_tools::memory_purge_pii_def(), move |args, _ctx| {
            let ks = Arc::clone(&ks_purge);
            let sanitizer = sanitizer_for_purge.clone();
            let cs = cs_purge.clone();
            Box::pin(memory_tools::handle_memory_purge_pii(
                args, ks, sanitizer, cs,
            ))
        });

        let ks_forget_content = Arc::clone(&ks);
        let cs_forget_content = shared_chunk_store.clone();
        builder = builder.tool(
            memory_tools::memory_forget_by_content_def(),
            move |args, _ctx| {
                let ks = Arc::clone(&ks_forget_content);
                let cs = cs_forget_content.clone();
                Box::pin(memory_tools::handle_memory_forget_by_content(args, ks, cs))
            },
        );

        // pii_report
        let ks_report = Arc::clone(&ks);
        let metrics_for_report = pii_metrics.clone();
        let retention_days = cfg.memory_retention_days();
        let pii_retention_days = cfg.memory_pii_retention_days();
        let audit_retention_days = cfg.memory_audit_retention_days();
        builder = builder.tool(memory_tools::pii_report_def(), move |args, _ctx| {
            let ks = Arc::clone(&ks_report);
            let metrics = metrics_for_report.clone();
            Box::pin(memory_tools::handle_pii_report(
                args,
                ks,
                metrics,
                retention_days,
                pii_retention_days,
                audit_retention_days,
            ))
        });

        // memory_consent
        let ks_consent = Arc::clone(&ks);
        builder = builder.tool(memory_tools::memory_consent_def(), move |args, _ctx| {
            let ks = Arc::clone(&ks_consent);
            Box::pin(memory_tools::handle_memory_consent(args, ks))
        });

        // --- Data retention sweep at startup ---
        {
            let store = ks.lock().unwrap_or_else(|e| e.into_inner());
            if let Some(days) = cfg.memory_retention_days() {
                match store.expire_older_than(days) {
                    Ok(n) if n > 0 => tracing::info!(
                        deleted = n,
                        days = days,
                        "Retention: expired old knowledge entries"
                    ),
                    _ => {}
                }
            }
            if let Some(days) = cfg.memory_pii_retention_days() {
                match store.expire_pii_older_than(days) {
                    Ok(n) if n > 0 => tracing::info!(
                        deleted = n,
                        days = days,
                        "Retention: expired PII-flagged knowledge entries"
                    ),
                    _ => {}
                }
            }
        }

        tracing::info!(
            "Registered memory tools (memory_store, memory_query, memory_forget, memory_purge_pii, memory_forget_by_content, pii_report, memory_consent)"
        );
    }

    // --- Registry proxy module ---
    if cfg.registry_enabled() && !cfg.registry.is_empty() {
        let registry_state = Arc::new(registry_tools::RegistryState::new(
            cfg.registry.clone(),
            cfg.registry_cache_ttl_secs(),
        ));

        let rs = Arc::clone(&registry_state);
        builder = builder.tool(registry_tools::registry_search_def(), move |args, _ctx| {
            let rs = Arc::clone(&rs);
            Box::pin(registry_tools::handle_registry_search(args, rs))
        });

        let rs = Arc::clone(&registry_state);
        builder = builder.tool(registry_tools::registry_list_def(), move |args, _ctx| {
            let rs = Arc::clone(&rs);
            Box::pin(registry_tools::handle_registry_list(args, rs))
        });

        let rs = Arc::clone(&registry_state);
        builder = builder.tool(
            registry_tools::registry_describe_def(),
            move |args, _ctx| {
                let rs = Arc::clone(&rs);
                Box::pin(registry_tools::handle_registry_describe(args, rs))
            },
        );

        tracing::info!(
            registries = cfg.registry.len(),
            "Registered registry proxy tools (registry_search, registry_list, registry_describe)"
        );
    }

    // Register audit_query tool (audit_log was created earlier, reuse it)
    {
        let audit = Arc::clone(&audit_log);
        builder = builder.tool(
            navra_core::protocol::ToolDefinition::new(
                "audit_query",
                "Query the structured audit log. Returns tool calls, model calls, \
                     and run summaries from past agent executions. Use to inspect \
                     what tools were called, with what arguments, and what results \
                     were returned.",
                navra_protocol::compat::tool_input_schema(
                    {
                        let mut props = std::collections::HashMap::new();
                        props.insert(
                            "run_id".to_string(),
                            serde_json::json!({
                                "type": "string",
                                "description": "Filter by run ID (returns tool calls for that run)"
                            }),
                        );
                        props.insert("summary".to_string(), serde_json::json!({
                            "type": "boolean",
                            "description": "If true, return a summary instead of individual entries"
                        }));
                        Some(props)
                    },
                    None,
                ),
            ),
            move |args, _ctx| {
                let audit = Arc::clone(&audit);
                Box::pin(async move {
                    use navra_core::protocol::CallToolResult;

                    let run_id = args.get("run_id").and_then(|v| v.as_str());

                    if let Some(rid) = run_id {
                        let summary = args
                            .get("summary")
                            .and_then(|v| v.as_bool())
                            .unwrap_or(false);
                        if summary {
                            match audit.get_summary(rid) {
                                Ok(s) => CallToolResult::text(
                                    serde_json::to_string_pretty(&s).unwrap_or_default(),
                                ),
                                Err(e) => {
                                    CallToolResult::error_msg(format!("Audit query failed: {e}"))
                                }
                            }
                        } else {
                            match audit.get_tool_calls(rid) {
                                Ok(calls) => CallToolResult::text(
                                    serde_json::to_string_pretty(&calls).unwrap_or_default(),
                                ),
                                Err(e) => {
                                    CallToolResult::error_msg(format!("Audit query failed: {e}"))
                                }
                            }
                        }
                    } else {
                        // No run_id — list recent runs
                        match audit.get_run("latest") {
                            Ok(run) => CallToolResult::text(
                                serde_json::to_string_pretty(&run).unwrap_or_default(),
                            ),
                            Err(_) => CallToolResult::text(
                                "No audit runs found. Run a demo first.".to_string(),
                            ),
                        }
                    }
                })
            },
        );
        tracing::info!("Registered audit_query tool");
    }

    // Register plan_execute tool (needs late-bound server reference)
    let server_cell: Arc<std::sync::OnceLock<Arc<navra_core::McpServer>>> =
        Arc::new(std::sync::OnceLock::new());
    {
        let cell = Arc::clone(&server_cell);
        let allow_direct = cfg.server.allow_direct_execution;
        builder = builder.tool(plan_execute::plan_execute_tool_def(), move |args, ctx| {
            let cell = Arc::clone(&cell);
            Box::pin(async move {
                match cell.get() {
                    Some(server) => {
                        plan_execute::handle_plan_execute(args, server, ctx, allow_direct).await
                    }
                    None => navra_core::protocol::CallToolResult::error_msg(
                        "Server not yet initialized",
                    ),
                }
            })
        });
        tracing::info!("Registered plan_execute tool");
    }

    // Register build_test tool for self-improvement flows
    {
        let perm = Arc::clone(&perm_engine);
        builder = builder.tool(build_tools::build_test_tool_def(), move |args, ctx| {
            let perm = Arc::clone(&perm);
            Box::pin(async move { build_tools::handle_build_test(args, ctx, perm).await })
        });
        tracing::info!("Registered build_test tool");
    }

    // Register flow:// resources backed by audit.db.
    // Agents can read specialist outputs via resources/read with
    // URIs like "flow://flow-1/task/sec-auth-audit".
    {
        let flow_audit = Arc::clone(&audit_log);
        builder = builder.resource(
            navra_core::protocol::ResourceDefinition::new(
                navra_protocol::RawResource::new("flow://", "Flow task results")
                    .with_description("Read flow task outputs. Use flow://list for all flows, \
                     flow://<flow_id>/tasks for task list, \
                     flow://<flow_id>/task/<task_id> for a specific output.")
                    .with_mime_type("text/plain"),
                None,
            ),
            std::sync::Arc::new(move |uri: String, _ctx| {
                let audit = Arc::clone(&flow_audit);
                Box::pin(async move {
                    let text = if uri == "flow://" || uri == "flow://list" {
                        match audit.list_flows() {
                            Ok(flows) if !flows.is_empty() => {
                                flows.iter().map(|f| {
                                    format!("{}: {} tasks, {}", f.flow_id, f.task_count, f.status)
                                }).collect::<Vec<_>>().join("\n")
                            }
                            _ => "No flows found.".to_string(),
                        }
                    } else if let Some(rest) = uri.strip_prefix("flow://") {
                        let parts: Vec<&str> = rest.splitn(3, '/').collect();
                        match parts.as_slice() {
                            [flow_id, "tasks"] | [flow_id] => {
                                match audit.get_flow_results(flow_id) {
                                    Ok(results) if !results.is_empty() => {
                                        results.iter().map(|r| {
                                            format!("{} ({}): {} [{} chars]",
                                                r.task_id,
                                                r.specialist.as_deref().unwrap_or("?"),
                                                r.status,
                                                r.output.as_deref().map(|o| o.len()).unwrap_or(0))
                                        }).collect::<Vec<_>>().join("\n")
                                    }
                                    _ => format!("No results for flow {flow_id}"),
                                }
                            }
                            [flow_id, "task", task_id] => {
                                match audit.get_flow_results(flow_id) {
                                    Ok(results) => {
                                        match results.iter().find(|r| r.task_id == *task_id) {
                                            Some(r) => r.output.clone().unwrap_or_else(|| "(no output)".to_string()),
                                            None => format!("Task {task_id} not found in flow {flow_id}"),
                                        }
                                    }
                                    Err(e) => format!("Error reading flow {flow_id}: {e}"),
                                }
                            }
                            _ => format!("Invalid flow URI: {uri}. Use flow://list, flow://<id>/tasks, or flow://<id>/task/<task_id>"),
                        }
                    } else {
                        format!("Invalid URI: {uri}")
                    };
                    navra_core::protocol::ReadResourceResult::new(
                        vec![navra_core::protocol::ResourceContent::TextResourceContents {
                            uri,
                            mime_type: Some("text/plain".to_string()),
                            text,
                            meta: None,
                        }],
                    )
                })
            }),
        );
        tracing::info!("Registered flow:// resources (backed by audit.db)");
    }

    // --- Kernel introspection resources (navra://) ---
    // These expose gateway internal state to agents via MCP resources/read.
    let boot_instant = std::time::Instant::now();

    // navra://proc — Process table (active agents, call counts)
    {
        let pt = process_table.clone();
        builder = builder.resource(
            navra_core::protocol::ResourceDefinition::new(
                navra_protocol::RawResource::new("navra://proc", "Process Table")
                    .with_description("Active agent sessions and call counts")
                    .with_mime_type("application/json"),
                None,
            ),
            Arc::new(move |uri: String, _ctx| {
                let pt = pt.clone();
                Box::pin(async move {
                    let agents = pt.snapshot();
                    let json = serde_json::json!({ "agents": agents });
                    navra_core::protocol::ReadResourceResult::new(vec![
                        navra_core::protocol::ResourceContent::TextResourceContents {
                            uri,
                            mime_type: Some("application/json".to_string()),
                            text: serde_json::to_string_pretty(&json).unwrap_or_default(),
                            meta: None,
                        },
                    ])
                })
            }),
        );
    }

    // navra://sessions — Active sessions
    {
        let ss = session_store.clone();
        builder = builder.resource(
            navra_core::protocol::ResourceDefinition::new(
                navra_protocol::RawResource::new("navra://sessions", "Active Sessions")
                    .with_description("List of active MCP sessions")
                    .with_mime_type("application/json"),
                None,
            ),
            Arc::new(move |uri: String, _ctx| {
                let ss = ss.clone();
                Box::pin(async move {
                    let sessions = ss.list_all();
                    let count = sessions.len();
                    let session_list: Vec<serde_json::Value> = sessions
                        .iter()
                        .map(|s| {
                            serde_json::json!({
                                "id": s.id,
                                "agent": s.agent.name,
                                "created_at": s.created_at,
                            })
                        })
                        .collect();
                    let json = serde_json::json!({
                        "count": count,
                        "sessions": session_list,
                    });
                    navra_core::protocol::ReadResourceResult::new(vec![
                        navra_core::protocol::ResourceContent::TextResourceContents {
                            uri,
                            mime_type: Some("application/json".to_string()),
                            text: serde_json::to_string_pretty(&json).unwrap_or_default(),
                            meta: None,
                        },
                    ])
                })
            }),
        );
    }

    // navra://metrics — Gateway metrics summary
    {
        let pt = process_table.clone();
        let ss = session_store.clone();
        let boot = boot_instant;
        builder = builder.resource(
            navra_core::protocol::ResourceDefinition::new(
                navra_protocol::RawResource::new("navra://metrics", "Gateway Metrics")
                    .with_description("Gateway metrics: call counts, sessions, uptime")
                    .with_mime_type("text/plain"),
                None,
            ),
            Arc::new(move |uri: String, _ctx| {
                let pt = pt.clone();
                let ss = ss.clone();
                Box::pin(async move {
                    let snapshot = pt.snapshot();
                    let total_calls: u64 = snapshot.iter().map(|a| a.call_count).sum();
                    let total_denied: u64 = snapshot.iter().map(|a| a.denied_count).sum();
                    let session_count = ss.count();
                    let uptime = boot.elapsed().as_secs();
                    let text = format!(
                        "# navra gateway metrics\n\
                         navra_uptime_seconds {uptime}\n\
                         navra_sessions_active {session_count}\n\
                         navra_agents_active {}\n\
                         navra_tool_calls_total {total_calls}\n\
                         navra_tool_calls_denied_total {total_denied}\n",
                        snapshot.len(),
                    );
                    navra_core::protocol::ReadResourceResult::new(vec![
                        navra_core::protocol::ResourceContent::TextResourceContents {
                            uri,
                            mime_type: Some("text/plain".to_string()),
                            text,
                            meta: None,
                        },
                    ])
                })
            }),
        );
    }

    // navra://tools — Registered tool list (uses OnceLock, populated after build)
    {
        let cell = Arc::clone(&server_cell);
        builder = builder.resource(
            navra_core::protocol::ResourceDefinition::new(
                navra_protocol::RawResource::new("navra://tools", "Registered Tools")
                    .with_description("List of all registered MCP tools")
                    .with_mime_type("application/json"),
                None,
            ),
            Arc::new(move |uri: String, _ctx| {
                let cell = Arc::clone(&cell);
                Box::pin(async move {
                    let (count, tools) = match cell.get() {
                        Some(server) => {
                            let names = server.tool_names();
                            (names.len(), names)
                        }
                        None => (0, vec!["(server not yet initialized)".to_string()]),
                    };
                    let json = serde_json::json!({
                        "count": count,
                        "tools": tools,
                    });
                    navra_core::protocol::ReadResourceResult::new(vec![
                        navra_core::protocol::ResourceContent::TextResourceContents {
                            uri,
                            mime_type: Some("application/json".to_string()),
                            text: serde_json::to_string_pretty(&json).unwrap_or_default(),
                            meta: None,
                        },
                    ])
                })
            }),
        );
    }

    // navra://version — Server version info
    {
        let boot = boot_instant;
        builder = builder.resource(
            navra_core::protocol::ResourceDefinition::new(
                navra_protocol::RawResource::new("navra://version", "Server Version")
                    .with_description("Server name, version, protocol version, uptime")
                    .with_mime_type("application/json"),
                None,
            ),
            Arc::new(move |uri: String, _ctx| {
                Box::pin(async move {
                    let json = serde_json::json!({
                        "name": "navra",
                        "version": env!("CARGO_PKG_VERSION"),
                        "protocol_version": navra_core::protocol::PROTOCOL_VERSION,
                        "crates": 20,
                        "uptime_secs": boot.elapsed().as_secs(),
                    });
                    navra_core::protocol::ReadResourceResult::new(vec![
                        navra_core::protocol::ResourceContent::TextResourceContents {
                            uri,
                            mime_type: Some("application/json".to_string()),
                            text: serde_json::to_string_pretty(&json).unwrap_or_default(),
                            meta: None,
                        },
                    ])
                })
            }),
        );
    }
    tracing::info!("Registered navra:// kernel introspection resources");

    let broadcaster = navra_core::transport::SseBroadcaster::new();
    let mut builder = builder.broadcaster(broadcaster.clone());

    // Wire BudgetHook for context budget enforcement on tool outputs.
    // When enabled, this also activates the hook pipeline path (instead
    // of the legacy safety_profile path), so we add a SafetyHook too.
    if cfg.budget.max_tool_output_tokens > 0 {
        use navra_core::hooks::{BudgetHook, TruncationStrategy};

        let strategy = match cfg.budget.truncation_strategy.as_str() {
            "truncate" => TruncationStrategy::Truncate,
            "head_tail" => TruncationStrategy::HeadTail {
                head_ratio: cfg.budget.head_ratio,
            },
            "summarize" => TruncationStrategy::Summarize,
            other => {
                tracing::warn!(
                    strategy = %other,
                    "Unknown truncation strategy, defaulting to head_tail"
                );
                TruncationStrategy::HeadTail {
                    head_ratio: cfg.budget.head_ratio,
                }
            }
        };

        // Budget hook runs first in post-hook order (added first, runs
        // last in reverse order — but since we want truncation before
        // safety filtering, we add safety first then budget).
        // Post-hooks run in reverse registration order, so:
        //   registered: [SafetyHook, BudgetHook]
        //   post execution: BudgetHook -> SafetyHook
        // This means truncation happens first, then safety filtering.

        // Collect safety pipelines for the SafetyHook
        let mut safety_hook = navra_core::hooks::SafetyHook::new(std::collections::HashMap::new());
        for (name, pset) in &cfg.permissions {
            let mut pipeline = navra_core::safety::build_pipeline(&pset.safety);
            // Re-add custom PII filter
            if let Some(ref pii_filter) = custom_pii_filter {
                match pset.safety.as_str() {
                    "standard" | "guardian" | "guardian-deep" | "block" | "multi-label" => {
                        pipeline.add_filter(SharedCustomPiiFilter(Arc::clone(pii_filter)));
                    }
                    _ => {}
                }
            }
            // Re-add custom regex patterns
            if !pset.safety_patterns.is_empty() {
                let patterns: Vec<(String, String)> = pset
                    .safety_patterns
                    .iter()
                    .map(|p| (p.category.clone(), p.pattern.clone()))
                    .collect();
                let custom = navra_core::safety::CustomFilter::new(patterns);
                if custom.has_patterns() {
                    pipeline.add_filter(custom);
                }
            }
            // Re-add ML filters
            for (model_name, model_cfg) in &cfg.models {
                if model_cfg.task == "classification"
                    && let Some(model) = models.get(model_name)
                {
                    let classifier: std::sync::Arc<dyn navra_core::safety::Classifier> =
                        std::sync::Arc::new(navra_safety_hooks::bridge::ClassifierBridge::new(
                            model.clone(),
                        ));
                    if pset.safety == "multi-label" && !pset.safety_thresholds.is_empty() {
                        pipeline.add_model_filter(
                            navra_core::safety::MultiLabelFilter::from_thresholds(
                                classifier,
                                pset.safety_thresholds.clone(),
                            ),
                        );
                    } else {
                        let threshold = model_cfg.threshold.unwrap_or(0.5);
                        pipeline.add_model_filter(navra_core::safety::MlFilter::new(
                            classifier,
                            threshold,
                            "ml-unsafe",
                        ));
                    }
                }
            }
            #[cfg(feature = "onnx")]
            if let Some(ref ner) = pii_ner_filter {
                match pset.safety.as_str() {
                    "standard" | "guardian" | "guardian-deep" | "block" | "multi-label" => {
                        pipeline.add_ner_filter_shared(Arc::clone(ner));
                    }
                    _ => {}
                }
            }
            #[cfg(feature = "onnx")]
            if let Some(ref pf) = privacy_filter {
                match pset.safety.as_str() {
                    "standard" | "guardian" | "guardian-deep" | "block" | "multi-label" => {
                        pipeline.add_privacy_filter_shared(Arc::clone(pf));
                    }
                    _ => {}
                }
            }
            safety_hook.add_pipeline(name.clone(), pipeline);
        }
        builder = builder.hook(safety_hook);

        // Egress endpoint filtering from permission set config
        {
            let mut allowed = Vec::new();
            let mut blocked = Vec::new();
            let mut deny_all = false;
            for pset in cfg.permissions.values() {
                allowed.extend(pset.egress_allowed_domains.iter().cloned());
                blocked.extend(pset.egress_blocked_domains.iter().cloned());
                if pset.egress_deny_all_external {
                    deny_all = true;
                }
            }
            if deny_all || !allowed.is_empty() || !blocked.is_empty() {
                let egress_config = navra_core::hooks::EgressConfig {
                    enabled: true,
                    allowed_domains: allowed,
                    blocked_domains: blocked,
                    deny_all_external: deny_all,
                    block_tainted_egress: true,
                };
                builder = builder.hook(navra_core::hooks::EgressFilterHook::new(egress_config));
                tracing::info!("Egress endpoint filtering enabled from permission config");
            }
        }

        builder = builder.hook(BudgetHook::new(cfg.budget.max_tool_output_tokens, strategy));
        tracing::info!(
            max_tokens = cfg.budget.max_tool_output_tokens,
            strategy = %cfg.budget.truncation_strategy,
            "Context budget enforcement enabled"
        );
    }

    // Statistical guardrail hook for anomaly detection
    if cfg.statistical.enabled {
        let hook_config = cfg.statistical.to_hook_config();
        tracing::info!(
            cosine_window = hook_config.cosine_window,
            cosine_z_threshold = hook_config.cosine_z_threshold,
            entropy_window = hook_config.entropy_window,
            entropy_min = hook_config.entropy_min,
            entropy_max = hook_config.entropy_max,
            block_on_anomaly = hook_config.block_on_anomaly,
            "Statistical guardrail enabled"
        );
        builder = builder.hook(navra_core::hooks::StatisticalGuardrailHook::new(
            hook_config,
        ));
    }

    // Temporal behavioral contracts
    if cfg.temporal_contracts.enabled && !cfg.temporal_contracts.contracts.is_empty() {
        let action_log = std::sync::Arc::new(navra_core::hooks::SessionActionLog::new(
            cfg.temporal_contracts.max_history_per_session,
        ));
        let mut contracts = Vec::new();
        for tc in &cfg.temporal_contracts.contracts {
            match serde_json::from_value::<navra_core::hooks::TemporalContract>(serde_json::json!({
                "name": tc.name,
                "description": tc.description,
                "predicate": tc.predicate,
                "action": tc.action,
                "applies_to": tc.applies_to,
            })) {
                Ok(contract) => contracts.push(contract),
                Err(e) => {
                    tracing::warn!(
                        contract = %tc.name,
                        error = %e,
                        "Failed to parse temporal contract — skipping"
                    );
                }
            }
        }
        tracing::info!(
            count = contracts.len(),
            "Temporal behavioral contracts enabled"
        );
        builder = builder.hook(navra_core::hooks::TemporalContractHook::new(
            action_log, contracts,
        ));
    }

    // Memory extraction hook (observation-only, stores tool results as knowledge)
    if let Some(ref ks) = knowledge_store {
        struct KnowledgeExtractionStore(Arc<std::sync::Mutex<navra_memory::KnowledgeStore>>);
        impl navra_core::hooks::ExtractionStore for KnowledgeExtractionStore {
            fn store_extraction(
                &self,
                title: &str,
                content: &str,
                session_id: &str,
                tags: &[String],
            ) {
                if let Ok(store) = self.0.lock() {
                    let now = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_secs() as i64;
                    let entry = navra_memory::MemoryEntry {
                        id: uuid::Uuid::new_v4().to_string(),
                        memory_type: navra_memory::MemoryType::Fact,
                        title: title.to_string(),
                        content: content.to_string(),
                        tags: tags.to_vec(),
                        created_at: now,
                        updated_at: None,
                    };
                    let scope = navra_memory::MemoryScope {
                        session_id: Some(session_id.to_string()),
                        ..Default::default()
                    };
                    let _ = store.store_scoped(&entry, &scope, None);
                }
            }
        }
        let hook = navra_core::hooks::MemoryExtractionHook::new(
            Arc::new(KnowledgeExtractionStore(Arc::clone(ks))),
            navra_core::hooks::MemoryExtractionConfig::default(),
        );
        builder = builder.hook(hook);
        tracing::info!("Memory extraction hook enabled");
    }

    // Causal provenance hook (observation-only, records tool call causality)
    {
        let causal_db_path = dirs::data_dir()
            .unwrap_or_else(|| std::path::PathBuf::from("."))
            .join("navra")
            .join("causal_provenance.db");
        match navra_flow::causal_graph::CausalGraphStore::open(&causal_db_path) {
            Ok(store) => {
                let store = std::sync::Arc::new(store);
                tracing::info!(
                    path = %causal_db_path.display(),
                    "Causal provenance graph enabled"
                );
                builder = builder.hook(navra_core::hooks::ProvenanceHook::new(
                    store as std::sync::Arc<dyn navra_core::hooks::CausalSink>,
                ));
            }
            Err(e) => {
                tracing::warn!(
                    error = %e,
                    "Failed to open causal provenance DB — provenance tracking disabled"
                );
            }
        }
    }

    // Detect-only monitoring agent (NAVRA-099)
    if cfg.monitoring.enabled {
        let (escalation_tx, escalation_rx) =
            navra_core::hooks::escalation_channel(cfg.monitoring.buffer_size);

        builder = builder.hook(navra_core::hooks::MonitoringHook::new(escalation_tx));

        let monitoring_metrics = std::sync::Arc::new(navra_core::hooks::MonitoringMetrics::new());

        // Bridge VerdictSink to the gateway blackbox
        struct BlackboxVerdictSink(Arc<navra_core::blackbox::Blackbox>);
        impl navra_core::hooks::VerdictSink for BlackboxVerdictSink {
            fn record_verdict(
                &self,
                event: &navra_core::hooks::EscalationEvent,
                verdict: &navra_core::hooks::Verdict,
            ) {
                let verdict_json = serde_json::to_string(verdict).unwrap_or_default();
                let event_json = serde_json::to_string(event).unwrap_or_default();
                self.0.record(
                    "monitoring-agent",
                    "read-only",
                    &event.session_id,
                    "monitor_verdict",
                    &event_json,
                    &verdict_json,
                    "verdict",
                    0,
                    "Trusted",
                );
            }
        }

        // Get blackbox reference if available (builder stores it internally)
        let bb_path = dirs::data_dir()
            .unwrap_or_else(|| std::path::PathBuf::from("."))
            .join("navra/blackbox.db");
        let verdict_sink: Option<Arc<dyn navra_core::hooks::VerdictSink>> =
            navra_core::blackbox::Blackbox::open(&bb_path)
                .ok()
                .map(|bb| Arc::new(BlackboxVerdictSink(Arc::new(bb))) as _);

        let mm = monitoring_metrics.clone();
        tokio::spawn(navra_core::hooks::monitoring_loop(
            escalation_rx,
            mm,
            verdict_sink,
        ));

        tracing::info!(
            buffer_size = cfg.monitoring.buffer_size,
            "Monitoring agent enabled (detect-only, async)"
        );
    }

    // Tool usage pruning filter (TW16)
    let usage_tracker = std::sync::Arc::new(navra_core::ToolUsageTracker::new(5));
    builder = builder.tool_filter(navra_core::UsagePruningFilter::new(usage_tracker.clone()));

    // DMN decision table guardrails (business-rule policy engine)
    for (name, perm) in &cfg.permissions {
        if let (Some(dmn_path), Some(dmn_decision)) = (&perm.dmn_policies, &perm.dmn_decision) {
            match navra_core::permissions::DmnEngine::from_file(dmn_path, dmn_decision) {
                Ok(engine) => {
                    tracing::info!(
                        permission_set = %name,
                        path = %dmn_path,
                        decision = %dmn_decision,
                        "DMN decision table loaded"
                    );
                    builder = builder.dmn_engine(engine);
                }
                Err(e) => {
                    tracing::error!(
                        permission_set = %name,
                        path = %dmn_path,
                        error = %e,
                        "Failed to load DMN decision table"
                    );
                }
            }
        }
    }

    let server = Arc::new(builder.build());
    let _ = server_cell.set(Arc::clone(&server));

    // Config watcher for hot reload (K8s ConfigMap pattern)
    let _config_watcher = if cfg.server.config_watch {
        let config_path = config::Config::default_config_path();
        let (tx, _rx) = tokio::sync::watch::channel(std::sync::Arc::new(cfg.clone()));
        match config_watcher::ConfigWatcher::new(
            config_path,
            cfg.server.config_watch_debounce_ms,
            tx,
        ) {
            Ok(w) => Some(w),
            Err(e) => {
                tracing::warn!(error = %e, "Failed to start config watcher");
                None
            }
        }
    } else {
        None
    };

    tracing::info!(
        tools = server.tool_count(),
        prompts = server.prompt_count(),
        resources = server.resource_count(),
        "Server ready"
    );

    match mode {
        TransportMode::Stdio => {
            navra_core::transport::run_stdio_server(server)
                .await
                .map_err(|e| anyhow::anyhow!("{e}"))?;
        }
        TransportMode::Http { no_tray } => {
            // --- mDNS advertising ---
            if mdns_enabled {
                let tcp_port = cfg
                    .server
                    .tcp
                    .as_ref()
                    .and_then(|addr| addr.rsplit(':').next())
                    .and_then(|p| p.parse::<u16>().ok())
                    .unwrap_or(9315);

                match mdns::advertise(&server.server_info().name, tcp_port, "/mcp") {
                    Ok(daemon) => {
                        tracing::info!(port = tcp_port, "Advertising via mDNS on _mcp._tcp.local.");
                        _mdns_daemon = Some(daemon);
                    }
                    Err(e) => {
                        tracing::warn!("mDNS advertising failed: {e}");
                    }
                }
            }

            // --- System tray ---
            if !no_tray {
                match tray::spawn_tray().await {
                    Ok((cmd_rx, handle)) => {
                        tracing::info!("System tray icon active");
                        tokio::spawn(tray::run_tray_updater(
                            handle,
                            approvals.clone(),
                            server.pause_flag(),
                            cmd_rx,
                        ));
                    }
                    Err(e) => {
                        tracing::warn!("System tray unavailable: {e}");
                    }
                }
            }

            // --- Build registry entries ---
            let mut registry_entries: Vec<serde_json::Value> = Vec::new();

            if let Some(ref discovery) = cfg.server.discovery {
                registry_entries.push(serde_json::json!({
                    "server": {
                        "name": server.server_info().name,
                        "description": format!(
                            "{}",
                            discovery.description.as_deref().unwrap_or("navra MCP gateway")
                        ),
                        "version": server.server_info().version,
                        "remotes": [{
                            "type": "streamable-http",
                            "url": &discovery.url,
                        }],
                    },
                    "_meta": {
                        "source": "self",
                    }
                }));
            }

            for entry in &cfg.registry {
                registry_entries.push(serde_json::json!({
                    "server": {
                        "name": &entry.name,
                        "description": &entry.description,
                        "remotes": [{
                            "type": &entry.remote_type,
                            "url": &entry.url,
                        }],
                        "repository": entry.repository.as_ref().map(|r| serde_json::json!({"url": r})),
                    },
                    "_meta": {
                        "source": "whitelist",
                    }
                }));
            }

            if !registry_entries.is_empty() {
                tracing::info!(
                    entries = registry_entries.len(),
                    "Registry serving {} entries at /v0.1/servers",
                    registry_entries.len()
                );
            }

            // --- HTTP transport with SSE broadcaster ---
            let has_discovery = cfg.server.discovery.is_some() || !registry_entries.is_empty();
            let (router, server) = if has_discovery {
                let aid_record = cfg.server.discovery.as_ref().map(|discovery| {
                    let mut aid = serde_json::json!({
                        "v": "aid1",
                        "u": &discovery.url,
                        "p": "mcp",
                        "a": &discovery.auth,
                    });
                    if let Some(ref desc) = discovery.description {
                        aid["s"] = serde_json::json!(desc);
                    }
                    if let Some(ref docs) = discovery.docs_url {
                        aid["d"] = serde_json::json!(docs);
                    }
                    let pubkey_multibase = format!(
                        "z{}",
                        bs58::encode({
                            let mut bytes = vec![0xed, 0x01];
                            bytes.extend_from_slice(&root_signer.public_key_bytes());
                            bytes
                        })
                        .into_string()
                    );
                    aid["k"] = serde_json::json!(pubkey_multibase);
                    aid["i"] = serde_json::json!("root-1");
                    tracing::info!(
                        url = %discovery.url,
                        did = %root_signer.did(),
                        "AID discovery at /.well-known/agent (with PKA)"
                    );
                    aid
                });
                let a2a_endpoint = cfg.server.discovery.as_ref().map(|d| d.url.clone());
                if a2a_endpoint.is_some() {
                    tracing::info!("A2A Agent Card at /.well-known/agent.json");
                }
                let root_did_str = Some(root_signer.did().to_string());
                let api_server_ref = Arc::clone(&server);
                let router = navra_core::transport::build_router_with_discovery(
                    server,
                    broadcaster,
                    aid_record,
                    registry_entries,
                    a2a_endpoint,
                    root_did_str,
                );
                (router, api_server_ref)
            } else {
                let api_server_ref = Arc::clone(&server);
                let router =
                    navra_core::transport::build_router_with_broadcaster(server, broadcaster);
                (router, api_server_ref)
            };

            // --- ACP (Agent Client Protocol) transport ---
            let acp_chat_model: Option<Arc<dyn navra_model::ModelBackend>> = cfg
                .models
                .iter()
                .find(|(_, m)| m.task == "chat" || m.task == "generate")
                .map(|(name, _)| name.clone())
                .and_then(|name| models.get(&name))
                .cloned();

            let acp_flow_summaries: Vec<navra_core::acp::types::FlowSummary> = {
                let mut summaries = Vec::new();
                for dir in &resolved_flow_dirs {
                    let expanded = if dir.starts_with('~') {
                        dirs::home_dir()
                            .map(|h| dir.replacen('~', &h.display().to_string(), 1))
                            .unwrap_or_else(|| dir.clone())
                    } else {
                        dir.clone()
                    };
                    if let Ok(entries) = std::fs::read_dir(&expanded) {
                        for entry in entries.flatten() {
                            let p = entry.path();
                            let ext = p.extension().and_then(|e| e.to_str());
                            if !matches!(ext, Some("yml" | "yaml" | "bpmn")) {
                                continue;
                            }
                            if let Ok(content) = std::fs::read_to_string(&p) {
                                if ext == Some("bpmn") {
                                    if let Ok(dag) =
                                        navra_flow::load_bpmn_file(p.to_str().unwrap_or_default())
                                    {
                                        summaries.push(navra_core::acp::types::FlowSummary {
                                            name: dag.name.clone(),
                                            description: dag
                                                .description
                                                .clone()
                                                .unwrap_or_else(|| dag.name.clone()),
                                            nodes: dag
                                                .tasks
                                                .iter()
                                                .map(|t| navra_core::acp::types::FlowNodeSummary {
                                                    id: t.id.clone(),
                                                    description: t.mandate.clone(),
                                                })
                                                .collect(),
                                        });
                                    }
                                } else if let Ok(flow) = serde_yaml::from_str::<
                                    navra_flow::yaml_loader::FlowFile,
                                >(&content)
                                {
                                    summaries.push(navra_core::acp::types::FlowSummary {
                                        name: flow.name.clone(),
                                        description: flow
                                            .description
                                            .unwrap_or_else(|| flow.name.clone()),
                                        nodes: flow
                                            .tasks
                                            .iter()
                                            .map(|t| navra_core::acp::types::FlowNodeSummary {
                                                id: t.id.clone(),
                                                description: t.mandate.clone(),
                                            })
                                            .collect(),
                                    });
                                }
                            }
                        }
                    }
                }
                summaries
            };

            let acp_router = if let Some(model) = acp_chat_model {
                let dispatcher = Arc::new(crate::acp_agent::AgentDispatcher::new(model));
                tracing::info!(
                    flows = acp_flow_summaries.len(),
                    "ACP agent-driven dispatcher active"
                );
                navra_core::transport::build_acp_router_with_dispatcher(
                    server.clone(),
                    dispatcher,
                    acp_flow_summaries,
                    None,
                )
            } else {
                tracing::info!("ACP tool-only dispatcher (no chat model configured)");
                navra_core::transport::build_acp_router(server.clone())
            };
            let router = router.merge(acp_router);
            tracing::info!("ACP v0.2.0 endpoints at /acp/*");

            // --- Webhook triggers ---
            let router = if let Some(webhook_router) = trigger_webhook_router.take() {
                tracing::info!("Webhook trigger routes merged at /hook/{{name}}");
                router.merge(webhook_router)
            } else {
                router
            };

            // /v1/chat/completions is mounted by ui.rs — agents route model calls
            // through the gateway for safety filters, blackbox audit, and persona injection.

            // --- Flow event log (live visualization) ---
            let flow_event_log = {
                let event_log_path = dirs::data_dir()
                    .unwrap_or_else(|| std::path::PathBuf::from("."))
                    .join("navra")
                    .join("flow_events.db");
                if let Some(parent) = event_log_path.parent() {
                    let _ = std::fs::create_dir_all(parent);
                }
                match navra_flow::event_log::EventLog::open(&event_log_path) {
                    Ok(log) => {
                        tracing::info!(path = %event_log_path.display(), "Flow event log opened");
                        Some(Arc::new(log))
                    }
                    Err(e) => {
                        tracing::warn!(error = %e, "Failed to open flow event log — SSE disabled");
                        None
                    }
                }
            };

            // --- Flow graph API ---
            let flow_api =
                flow_api::flow_api_router(Arc::clone(&flow_registry), flow_event_log.clone());
            let router = router.merge(flow_api);
            tracing::info!(
                "Flow graph API at /flows/{{id}}/graph, /graph/dot, /graph/bpmn, /events"
            );

            // --- Web UI: shared state + API routes ---
            // Detect first available Ollama model for UI chat fallback
            let ollama_fallback: Option<String> = if let Ok(resp) = reqwest::Client::new()
                .get("http://localhost:11434/api/tags")
                .send()
                .await
            {
                resp.json::<serde_json::Value>()
                    .await
                    .ok()
                    .and_then(|tags| tags["models"][0]["name"].as_str().map(String::from))
            } else {
                None
            };
            let ui_broadcaster = Arc::new(ui_events::UiBroadcaster::new(256));
            ui_events::start_polling_bridge(Arc::clone(&ui_broadcaster), Arc::clone(&server));
            let router = ui::attach_ui_routes(
                router,
                &cfg,
                &server,
                &models,
                ollama_fallback.as_deref(),
                Some(ui_broadcaster),
                rag_context_retriever.clone(),
            );

            tracing::info!(
                "Web UI at http://localhost:{}",
                cfg.server
                    .tcp
                    .as_deref()
                    .and_then(|a| a.rsplit(':').next())
                    .unwrap_or("9315")
            );

            // Listen on Unix socket, TCP, or both
            if let Some(ref socket_path) = cfg.server.socket {
                let tcp_addr = cfg.server.tcp.clone();

                if let Some(parent) = std::path::Path::new(socket_path).parent() {
                    std::fs::create_dir_all(parent)?;
                }

                if std::path::Path::new(socket_path).exists() {
                    std::fs::remove_file(socket_path)?;
                }

                let unix_listener = tokio::net::UnixListener::bind(socket_path)?;

                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    std::fs::set_permissions(socket_path, std::fs::Permissions::from_mode(0o600))?;
                }

                tracing::info!("Listening on unix:{socket_path}");

                let shutdown = async {
                    let ctrl_c = tokio::signal::ctrl_c();
                    #[cfg(unix)]
                    let mut sigterm =
                        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
                            .expect("failed to install SIGTERM handler");
                    #[cfg(unix)]
                    tokio::select! {
                        _ = ctrl_c => tracing::info!("Received SIGINT, shutting down"),
                        _ = sigterm.recv() => tracing::info!("Received SIGTERM, shutting down"),
                    }
                    #[cfg(not(unix))]
                    ctrl_c.await.ok();
                };

                if let Some(addr) = tcp_addr {
                    let tcp_listener = tokio::net::TcpListener::bind(&addr).await?;
                    tracing::info!("Listening on tcp:{addr}");

                    let tcp_router = router.clone();
                    tokio::select! {
                        result = axum::serve(unix_listener, router)
                            .with_graceful_shutdown(shutdown) => result?,
                        result = axum::serve(tcp_listener, tcp_router) => result?,
                    }
                } else {
                    axum::serve(unix_listener, router)
                        .with_graceful_shutdown(shutdown)
                        .await?;
                }
            } else {
                let addr = cfg.server.listen_addr();
                let listener = tokio::net::TcpListener::bind(&addr).await?;
                tracing::info!("Listening on tcp:{addr}");

                let shutdown = async {
                    let ctrl_c = tokio::signal::ctrl_c();
                    #[cfg(unix)]
                    let mut sigterm =
                        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
                            .expect("failed to install SIGTERM handler");
                    #[cfg(unix)]
                    tokio::select! {
                        _ = ctrl_c => tracing::info!("Received SIGINT, shutting down"),
                        _ = sigterm.recv() => tracing::info!("Received SIGTERM, shutting down"),
                    }
                    #[cfg(not(unix))]
                    ctrl_c.await.ok();
                };

                axum::serve(listener, router)
                    .with_graceful_shutdown(shutdown)
                    .await?;
            }
        }
    }

    // --- Stop runtime-served models ---
    for (runtime, endpoint) in &running_endpoints {
        tracing::info!(url = %endpoint.url, backend = ?endpoint.backend, "Stopping model runtime");
        if let Err(e) = runtime.stop(endpoint).await {
            tracing::error!(error = %e, "Failed to stop model runtime");
        }
    }

    Ok(())
}

/// Send an approve or deny request to the running server via JSON-RPC.
async fn approve_or_deny(addr: &str, request_id: &str, approve: bool) -> anyhow::Result<()> {
    let tool_name = if approve { "file_approve" } else { "file_deny" };
    let action = if approve { "Approved" } else { "Denied" };

    let client = reqwest::Client::new();
    let url = format!("http://{addr}/mcp");

    let body = serde_json::json!({
        "jsonrpc": "2.0",
        "method": "tools/call",
        "id": 1,
        "params": {
            "name": tool_name,
            "arguments": {
                "request_id": request_id
            }
        }
    });

    let resp = client
        .post(&url)
        .header("Content-Type", "application/json")
        .json(&body)
        .send()
        .await?;

    if !resp.status().is_success() {
        let status = resp.status();
        let text = resp.text().await.unwrap_or_default();
        anyhow::bail!("Server returned {status}: {text}");
    }

    let result: serde_json::Value = resp.json().await?;
    if let Some(error) = result.get("error") {
        let msg = error
            .get("message")
            .and_then(|m| m.as_str())
            .unwrap_or("unknown");
        anyhow::bail!("Server error: {msg}");
    }

    println!("{action} request {request_id}");
    Ok(())
}

/// Query the running server for status via the initialize endpoint.
async fn query_status(addr: &str) -> anyhow::Result<()> {
    let client = reqwest::Client::new();
    let url = format!("http://{addr}/mcp");

    let body = serde_json::json!({
        "jsonrpc": "2.0",
        "method": "initialize",
        "id": 1,
        "params": {
            "protocolVersion": "2025-03-26",
            "capabilities": {},
            "clientInfo": {
                "name": "navra-cli",
                "version": env!("CARGO_PKG_VERSION")
            }
        }
    });

    let resp = client
        .post(&url)
        .header("Content-Type", "application/json")
        .json(&body)
        .send()
        .await;

    match resp {
        Ok(r) if r.status().is_success() => {
            let result: serde_json::Value = r.json().await?;
            if let Some(info) = result.get("result") {
                let name = info
                    .get("serverInfo")
                    .and_then(|s| s.get("name"))
                    .and_then(|n| n.as_str())
                    .unwrap_or("unknown");
                let version = info
                    .get("serverInfo")
                    .and_then(|s| s.get("version"))
                    .and_then(|v| v.as_str())
                    .unwrap_or("unknown");
                let has_tools = info
                    .get("capabilities")
                    .and_then(|c| c.get("tools"))
                    .is_some();
                let has_prompts = info
                    .get("capabilities")
                    .and_then(|c| c.get("prompts"))
                    .is_some();
                let has_resources = info
                    .get("capabilities")
                    .and_then(|c| c.get("resources"))
                    .is_some();

                println!("Server: {name} v{version}");
                println!("Status: running");
                println!("Address: {addr}");
                println!(
                    "Capabilities: {}",
                    [
                        has_tools.then_some("tools"),
                        has_prompts.then_some("prompts"),
                        has_resources.then_some("resources"),
                    ]
                    .into_iter()
                    .flatten()
                    .collect::<Vec<_>>()
                    .join(", ")
                );
            }
        }
        Ok(r) => {
            println!("Server at {addr} returned {}", r.status());
        }
        Err(_) => {
            println!("Server at {addr} is not reachable.");
            println!("Is navra running? Start it with: navra serve");
        }
    }
    Ok(())
}

/// Install systemd user units for navra.
pub(crate) fn install_systemd_units() -> anyhow::Result<()> {
    let unit_dir = dirs::config_dir()
        .ok_or_else(|| anyhow::anyhow!("Cannot determine config directory"))?
        .join("systemd/user");
    std::fs::create_dir_all(&unit_dir)?;

    let service_content = include_str!("../systemd/navra.service");
    let socket_content = include_str!("../systemd/navra.socket");

    let service_path = unit_dir.join("navra.service");
    let socket_path = unit_dir.join("navra.socket");

    std::fs::write(&service_path, service_content)?;
    println!("Installed {}", service_path.display());

    std::fs::write(&socket_path, socket_content)?;
    println!("Installed {}", socket_path.display());

    // Reload systemd and enable
    let reload = std::process::Command::new("systemctl")
        .args(["--user", "daemon-reload"])
        .status();
    if let Ok(status) = reload
        && status.success()
    {
        println!("Reloaded systemd user daemon");
    }

    let enable = std::process::Command::new("systemctl")
        .args(["--user", "enable", "navra.service", "navra.socket"])
        .status();
    if let Ok(status) = enable
        && status.success()
    {
        println!("Enabled navra.service and navra.socket");
    }

    println!("\nTo start now:  systemctl --user start navra.service");
    println!("To check logs: journalctl --user -u navra.service -f");
    Ok(())
}

/// Uninstall systemd user units for navra.
fn uninstall_systemd_units() -> anyhow::Result<()> {
    // Stop and disable first
    let _ = std::process::Command::new("systemctl")
        .args(["--user", "stop", "navra.service", "navra.socket"])
        .status();
    let _ = std::process::Command::new("systemctl")
        .args(["--user", "disable", "navra.service", "navra.socket"])
        .status();

    let unit_dir = dirs::config_dir()
        .ok_or_else(|| anyhow::anyhow!("Cannot determine config directory"))?
        .join("systemd/user");

    let service_path = unit_dir.join("navra.service");
    let socket_path = unit_dir.join("navra.socket");

    if service_path.exists() {
        std::fs::remove_file(&service_path)?;
        println!("Removed {}", service_path.display());
    }
    if socket_path.exists() {
        std::fs::remove_file(&socket_path)?;
        println!("Removed {}", socket_path.display());
    }

    let _ = std::process::Command::new("systemctl")
        .args(["--user", "daemon-reload"])
        .status();

    println!("navra systemd units uninstalled");
    Ok(())
}

macro_rules! authed_transport {
    ($endpoint:expr, $token:expr) => {{
        let mut config =
            rmcp::transport::streamable_http_client::StreamableHttpClientTransportConfig::with_uri(
                $endpoint,
            );
        if let Some(t) = $token {
            config = config.auth_header(t);
        }
        rmcp::transport::StreamableHttpClientTransport::from_config(config)
    }};
}

async fn run_agent(
    prompt: &str,
    model_name: Option<&str>,
    persona_name: &str,
    endpoint: &str,
    token: Option<&str>,
    max_iterations: usize,
    upstream_prompts: &[String],
    #[allow(unused_variables)] no_embedded: bool,
) -> anyhow::Result<()> {
    // Auto-detect model from Ollama if not specified
    let model_name = if let Some(m) = model_name {
        m.to_string()
    } else {
        // Pick first available Ollama model
        let resp = reqwest::Client::new()
            .get("http://localhost:11434/api/tags")
            .send()
            .await
            .ok()
            .and_then(|r| futures_util::FutureExt::now_or_never(r.json::<serde_json::Value>()));
        match resp {
            Some(Ok(tags)) => tags["models"]
                .as_array()
                .and_then(|m| m.first())
                .and_then(|m| m["name"].as_str())
                .unwrap_or("gemma4:26b")
                .to_string(),
            _ => "gemma4:26b".to_string(),
        }
    };

    eprintln!("Model:    {model_name}");
    eprintln!("Persona:  {persona_name}");
    eprintln!("Endpoint: {endpoint}");
    eprintln!();

    // Detect model provider from name
    enum ModelProvider {
        Ollama,
        VertexAI {
            url: String,
            token: Option<String>,
            region: String,
        },
        AnthropicDirect {
            key: String,
        },
    }

    let provider = if model_name.starts_with("claude") {
        let project = std::env::var("ANTHROPIC_VERTEX_PROJECT_ID")
            .or_else(|_| std::env::var("GOOGLE_CLOUD_PROJECT"))
            .unwrap_or_default();
        let region = std::env::var("CLOUD_ML_REGION")
            .or_else(|_| std::env::var("GOOGLE_CLOUD_REGION"))
            .unwrap_or_else(|_| "us-east5".to_string());

        if !project.is_empty() {
            let host = if region == "global" {
                "aiplatform.googleapis.com".to_string()
            } else {
                format!("{region}-aiplatform.googleapis.com")
            };
            let url = format!(
                "https://{host}/v1/projects/{project}/locations/{region}/publishers/anthropic/models/{model_name}:rawPredict"
            );
            let token = std::process::Command::new("gcloud")
                .args(["auth", "print-access-token"])
                .output()
                .ok()
                .and_then(|o| String::from_utf8(o.stdout).ok())
                .map(|s| s.trim().to_string());
            ModelProvider::VertexAI { url, token, region }
        } else if let Ok(key) = std::env::var("ANTHROPIC_API_KEY") {
            ModelProvider::AnthropicDirect { key }
        } else {
            anyhow::bail!(
                "Claude model requested but no ANTHROPIC_VERTEX_PROJECT_ID or ANTHROPIC_API_KEY set"
            );
        }
    } else {
        ModelProvider::Ollama
    };

    // Load persona if cognitive_core exists
    let mut forge = navra_cognitive::ForgeService::load(std::path::Path::new("cognitive_core"))
        .ok()
        .or_else(|| {
            // Try common locations
            for p in ["../cognitive_core", "/etc/navra/cognitive_core"] {
                if let Ok(f) = navra_cognitive::ForgeService::load(std::path::Path::new(p)) {
                    return Some(f);
                }
            }
            None
        });

    // Discover upstream personas from the running navra server
    if let Some(ref mut f) = forge {
        let discover_peer = {
            let transport = authed_transport!(endpoint, token);
            rmcp::service::ServiceExt::<rmcp::RoleClient>::serve((), transport)
                .await
                .ok()
                .map(|c| {
                    let peer = c.peer().clone();
                    tokio::spawn(async move {
                        let _ = c.waiting().await;
                    });
                    peer
                })
        };
        if let Some(peer) = discover_peer {
            let client = navra_agent::McpClient::new(peer);
            if let Ok(prompts) = client.list_prompts().await {
                for p in &prompts {
                    if let Some(persona_name) = p.name.strip_prefix("persona:") {
                        let desc = p.description.as_deref().unwrap_or("");
                        if f.register_upstream_persona(persona_name, "upstream", &p.name, desc) {
                            eprintln!("Discovered upstream persona: {persona_name}");
                        }
                    }
                }
            }
        }
    }

    // Build agent with provider-specific backend
    let base_builder = navra_agent::Agent::builder().endpoint(endpoint).await?;

    let non_progress = vec![
        "team_status".to_string(),
        "team_result".to_string(),
        "team_bb_read".to_string(),
        "team_bb_notifications".to_string(),
        "models_list".to_string(),
        "personas_list".to_string(),
        "flow_status".to_string(),
        "flow_result".to_string(),
    ];

    macro_rules! configure_builder {
        ($b:expr) => {
            $b.max_iterations(max_iterations)
                .temperature(0.0)
                .max_tokens(8192)
                .force_tool_iterations(5)
                .non_progress_tools(non_progress.clone())
        };
    }

    // Embedded runtime state — kept alive for the duration of the agent run
    #[allow(unused_mut)]
    let mut embedded_endpoint: Option<(
        Box<dyn navra_model_runtime::ModelRuntime>,
        navra_model_runtime::Endpoint,
    )> = None;

    let mut builder = match provider {
        ModelProvider::VertexAI {
            url,
            token,
            ref region,
        } => {
            eprintln!("Provider: Vertex AI ({region})");
            let backend = navra_model::AnthropicBackend::new(
                url,
                &model_name,
                token,
                navra_model::Locality::Remote,
            );
            configure_builder!(base_builder.model(backend))
        }
        ModelProvider::AnthropicDirect { key } => {
            eprintln!("Provider: Anthropic API");
            let backend = navra_model::AnthropicBackend::new(
                "https://api.anthropic.com",
                &model_name,
                Some(key),
                navra_model::Locality::Remote,
            );
            configure_builder!(base_builder.model(backend))
        }
        ModelProvider::Ollama => {
            #[cfg(feature = "embedded")]
            if !no_embedded {
                let (m, t) = if let Some(pos) = model_name.find(':') {
                    (&model_name[..pos], &model_name[pos + 1..])
                } else {
                    (model_name.as_str(), "latest")
                };
                if let Some(gguf_path) = navra_model_hub::try_local_ollama(m, t) {
                    let runtime = navra_model_runtime::embedded::EmbeddedRuntime::new();
                    let gpus = navra_model_runtime::gpu::detect_gpus();
                    let target = navra_model_runtime::HardwareTarget::from_gpus(&gpus);
                    let cfg = navra_model_runtime::ServeConfig {
                        model_path: gguf_path,
                        context_size: 8192,
                        gpus,
                        target,
                        ..Default::default()
                    };
                    match runtime.serve(&cfg).await {
                        Ok(ep) => {
                            eprintln!("Provider: embedded (llama.cpp in-process)");
                            embedded_endpoint = Some((Box::new(runtime), ep));
                        }
                        Err(e) => {
                            eprintln!("Embedded runtime failed ({e}), falling back to Ollama API");
                        }
                    }
                }
            }

            if let Some((_, ref ep)) = embedded_endpoint {
                let backend = navra_model::OpenAiBackend::new(
                    format!("{}/v1", ep.url),
                    &model_name,
                    None,
                    navra_model::Locality::Local,
                );
                configure_builder!(base_builder.model(backend))
            } else {
                let ollama_url = std::env::var("OLLAMA_HOST")
                    .unwrap_or_else(|_| "http://localhost:11434".to_string());
                eprintln!("Provider: Ollama ({ollama_url})");
                let backend = navra_model::OpenAiBackend::new(
                    format!("{ollama_url}/v1"),
                    &model_name,
                    None,
                    navra_model::Locality::Local,
                );
                configure_builder!(base_builder.model(backend))
            }
        }
    };

    // Apply auth token
    let auth_token = token
        .map(String::from)
        .or_else(|| std::env::var("MCPD_TOKEN").ok());
    if let Some(ref t) = auth_token {
        builder = builder.auth_token(t.clone());
    }

    // Parse --upstream-prompt flags into McpPromptRef entries
    let cli_prompt_refs: Vec<navra_cognitive::McpPromptRef> = upstream_prompts
        .iter()
        .filter_map(|s| {
            let (upstream, prompt_name) = s.split_once(':')?;
            Some(navra_cognitive::McpPromptRef {
                upstream: upstream.to_string(),
                prompt: prompt_name.to_string(),
                inject_position: navra_cognitive::InjectPosition::AfterExamples,
                arguments: None,
            })
        })
        .collect();

    if !cli_prompt_refs.is_empty() {
        eprintln!("Upstream prompts: {}", cli_prompt_refs.len());
    }

    // Apply persona
    if let Some(ref forge) = forge {
        if let Some(persona) = forge.get_persona(persona_name) {
            // Check if this is an MCP-sourced persona
            let has_source = persona.source.is_some();

            // Collect persona-defined mcp_prompts and CLI-provided ones
            let all_refs: Vec<navra_cognitive::McpPromptRef> = persona
                .mcp_prompts
                .iter()
                .cloned()
                .chain(cli_prompt_refs.iter().cloned())
                .collect();

            if has_source || !all_refs.is_empty() {
                // Need an MCP connection to resolve source and/or prompts
                let resolver_peer = {
                    let transport = authed_transport!(endpoint, token);
                    let c =
                        rmcp::service::ServiceExt::<rmcp::RoleClient>::serve((), transport).await?;
                    let peer = c.peer().clone();
                    tokio::spawn(async move {
                        let _ = c.waiting().await;
                    });
                    peer
                };
                let mut resolver_client = navra_agent::McpClient::new(resolver_peer);

                if has_source {
                    // MCP-sourced persona: resolve source + mcp_prompts together
                    builder = builder
                        .persona_from_mcp(forge, persona_name, &mut resolver_client, prompt)
                        .await?;

                    // Also resolve any CLI-provided upstream prompts
                    if !cli_prompt_refs.is_empty() {
                        let extra_resolved = navra_agent::resolve::resolve_mcp_prompts(
                            &mut resolver_client,
                            &cli_prompt_refs,
                            prompt,
                        )
                        .await?;

                        if !extra_resolved.is_empty() {
                            eprintln!("Resolved {} CLI upstream prompt(s)", extra_resolved.len());
                        }
                    }

                    eprintln!("Loaded MCP-sourced persona: {persona_name}");
                } else {
                    // Local persona with upstream prompts to resolve
                    let resolved = navra_agent::resolve::resolve_mcp_prompts(
                        &mut resolver_client,
                        &all_refs,
                        prompt,
                    )
                    .await?;

                    if !resolved.is_empty() {
                        eprintln!("Resolved {} upstream prompt(s)", resolved.len());
                    }

                    builder = builder.persona_with_prompts(forge, persona_name, &resolved)?;
                }
            } else {
                builder = builder.persona(forge, persona_name)?;
            }

            eprintln!("Loaded persona: {persona_name}");
        }
    } else if !cli_prompt_refs.is_empty() {
        // No persona loaded but CLI prompts were specified — resolve and append
        let resolver_peer = {
            let transport = authed_transport!(endpoint, token);
            let c = rmcp::service::ServiceExt::<rmcp::RoleClient>::serve((), transport).await?;
            let peer = c.peer().clone();
            tokio::spawn(async move {
                let _ = c.waiting().await;
            });
            peer
        };
        let mut resolver_client = navra_agent::McpClient::new(resolver_peer);

        let resolved = navra_agent::resolve::resolve_mcp_prompts(
            &mut resolver_client,
            &cli_prompt_refs,
            prompt,
        )
        .await?;

        if !resolved.is_empty() {
            let extra = resolved
                .iter()
                .map(|rp| format!("## Upstream Prompt: {}\n\n{}", rp.label, rp.content))
                .collect::<Vec<_>>()
                .join("\n\n");

            builder = builder.system_prompt(extra);
            eprintln!(
                "Resolved {} upstream prompt(s) (no persona)",
                resolved.len()
            );
        }
    }

    let mut agent = builder.build().await?;

    // List tools
    let tools = agent.client().list_tools().await?;
    eprintln!("{} tools available", tools.len());
    eprintln!();

    // Run
    let start = std::time::Instant::now();
    match agent.run(prompt).await {
        Ok(result) => {
            // Print report to stdout (pipeable)
            println!("{}", result.response);

            // Print stats to stderr
            eprintln!();
            eprintln!("---");
            eprintln!("Iterations: {}", result.iterations);
            eprintln!(
                "Tokens:     {} in + {} out",
                result.input_tokens, result.output_tokens
            );
            eprintln!("Time:       {:.1}s", start.elapsed().as_secs_f64());
            eprintln!("Taint:      {:?}", result.taint);
            eprintln!("Blackbox:   navra audit");
        }
        Err(e) => {
            eprintln!("Error: {e}");
            std::process::exit(1);
        }
    }

    if let Some((runtime, ep)) = embedded_endpoint {
        let _ = runtime.stop(&ep).await;
    }

    Ok(())
}

pub(crate) fn expand_tilde(path: &str) -> String {
    let mut result = path.to_string();
    if result.starts_with("~/")
        && let Some(home) = dirs::home_dir()
    {
        result = format!("{}{}", home.display(), &result[1..]);
    }
    // Expand $VAR and ${VAR} patterns
    let mut out = String::with_capacity(result.len());
    let mut chars = result.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '$' {
            let braced = chars.peek() == Some(&'{');
            if braced {
                chars.next();
            }
            let var_name: String = chars
                .by_ref()
                .take_while(|&ch| {
                    if braced {
                        ch != '}'
                    } else {
                        ch.is_alphanumeric() || ch == '_'
                    }
                })
                .collect();
            if let Ok(val) = std::env::var(&var_name) {
                out.push_str(&val);
            } else {
                out.push('$');
                if braced {
                    out.push('{');
                }
                out.push_str(&var_name);
                if braced {
                    out.push('}');
                }
            }
        } else {
            out.push(c);
        }
    }
    out
}

fn convert_model_configs(
    models: &std::collections::HashMap<String, config::ModelConfig>,
) -> std::collections::HashMap<String, navra_model_server::config::ModelEntry> {
    models
        .iter()
        .map(|(name, mc)| {
            (
                name.clone(),
                navra_model_server::config::ModelEntry {
                    model_path: mc.model_path.clone(),
                    source: mc.source.clone(),
                    tokenizer_path: mc.tokenizer_path.clone(),
                    task: mc.task.clone(),
                    device: mc.device.clone(),
                    dimensions: mc.dimensions,
                    labels: mc.labels.clone(),
                    threshold: mc.threshold,
                    format: mc.format.clone(),
                    execution_mode: mc.execution_mode,
                    runtime: mc.runtime.clone(),
                    port: mc.port,
                    context_size: mc.context_size,
                    parallel: mc.parallel,
                    model_name: mc.model_name.clone(),
                    cache_type: mc.cache_type,
                    speculative: mc.speculative.as_ref().map(|s| {
                        navra_model_server::config::SpeculativeEntry {
                            draft_model: s.draft_model.clone(),
                            draft_tokens: s.draft_tokens,
                            draft_min_p: s.draft_min_p,
                        }
                    }),
                    base_url: mc.base_url.clone(),
                    api_key: mc.api_key.clone(),
                    locality: mc.locality.clone(),
                },
            )
        })
        .collect()
}

fn audit_command(
    limit: usize,
    detail: bool,
    agent: Option<String>,
    tool: Option<String>,
    verify: bool,
) -> anyhow::Result<()> {
    let bb_path = dirs::data_dir()
        .unwrap_or_else(|| std::path::PathBuf::from("."))
        .join("navra/blackbox.db");
    if !bb_path.exists() {
        anyhow::bail!(
            "No blackbox found at {}. Start the server first.",
            bb_path.display()
        );
    }
    let bb = navra_core::blackbox::Blackbox::open(&bb_path).map_err(|e| anyhow::anyhow!("{e}"))?;

    if verify {
        let (valid, broken) = bb.verify_chain();
        match broken {
            None => println!("Blackbox integrity: OK ({valid} entries, chain valid)"),
            Some(seq) => println!(
                "Blackbox integrity: BROKEN at seq {seq} ({valid} valid entries before break)"
            ),
        }
        return Ok(());
    }

    println!("Blackbox: {} ({} entries)\n", bb_path.display(), bb.count());

    let entries = bb.recent(limit);
    let filtered: Vec<_> = entries
        .iter()
        .rev()
        .filter(|e| agent.as_ref().is_none_or(|a| e.agent_name == *a))
        .filter(|e| tool.as_ref().is_none_or(|t| e.tool_name == *t))
        .collect();

    if detail {
        for e in &filtered {
            println!(
                "seq={} agent={} tool={} outcome={} duration={}us",
                e.seq, e.agent_name, e.tool_name, e.outcome, e.duration_us
            );
            let args_short = if e.tool_args.len() > 120 {
                &e.tool_args[..120]
            } else {
                &e.tool_args
            };
            let result_short = if e.tool_result.len() > 120 {
                &e.tool_result[..120]
            } else {
                &e.tool_result
            };
            println!("  args:   {}", args_short);
            println!("  result: {}", result_short);
            println!("  ifc:    {}", e.ifc_label);
            println!();
        }
    } else {
        println!(
            "{:<6} {:<12} {:<12} {:<20} {:<8} IFC",
            "SEQ", "AGENT", "OUTCOME", "TOOL", "US"
        );
        println!("{}", "-".repeat(80));
        for e in &filtered {
            let ifc_short = e
                .ifc_label
                .replace("DataLabel { integrity: ", "")
                .replace(", confidentiality: ", "/")
                .replace(" }", "");
            println!(
                "{:<6} {:<12} {:<12} {:<20} {:<8} {}",
                e.seq, e.agent_name, e.outcome, e.tool_name, e.duration_us, ifc_short
            );
        }
    }

    println!("\n{} entries shown", filtered.len());
    Ok(())
}

fn policy_suggest(
    hours: u64,
    format: &str,
    db_path: Option<&str>,
    agent_filter: Option<&str>,
    min_count: usize,
) -> anyhow::Result<()> {
    let bb_path = db_path.map(std::path::PathBuf::from).unwrap_or_else(|| {
        dirs::data_dir()
            .unwrap_or_else(|| std::path::PathBuf::from("."))
            .join("navra/blackbox.db")
    });
    if !bb_path.exists() {
        anyhow::bail!(
            "No blackbox found at {}. Start the server first.",
            bb_path.display()
        );
    }
    let bb = navra_core::blackbox::Blackbox::open(&bb_path).map_err(|e| anyhow::anyhow!("{e}"))?;

    let cutoff_ms = {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system clock before UNIX epoch")
            .as_millis() as i64;
        now - (hours as i64 * 3600 * 1000)
    };

    let entries = bb.recent(10000);
    let denials: Vec<_> = entries
        .iter()
        .filter(|e| e.outcome.starts_with("denied"))
        .filter(|e| e.timestamp_ms >= cutoff_ms)
        .filter(|e| agent_filter.is_none_or(|a| e.agent_name == a))
        .collect();

    if denials.is_empty() {
        println!("No denials found in the last {hours} hours.");
        return Ok(());
    }

    // Group by (permissions, tool_name, outcome)
    let mut groups: std::collections::HashMap<
        (String, String, String),
        Vec<&navra_core::blackbox::BlackboxEntry>,
    > = std::collections::HashMap::new();
    for e in &denials {
        let key = (
            e.agent_permissions.clone(),
            e.tool_name.clone(),
            e.outcome.clone(),
        );
        groups.entry(key).or_default().push(e);
    }

    // Sort by count descending
    let mut sorted: Vec<_> = groups.iter().collect();
    sorted.sort_by_key(|b| std::cmp::Reverse(b.1.len()));

    println!(
        "# navra policy suggest — {} denials in last {}h, {} groups\n",
        denials.len(),
        hours,
        sorted.len()
    );

    let show_cedar = format == "cedar" || format == "both";
    let show_toml = format == "toml" || format == "both";

    for ((permissions, tool_name, outcome), entries) in &sorted {
        if entries.len() < min_count {
            continue;
        }

        let agents: Vec<_> = entries
            .iter()
            .map(|e| e.agent_name.as_str())
            .collect::<std::collections::HashSet<_>>()
            .into_iter()
            .collect();

        let is_dangerous = tool_name.contains("exec")
            || tool_name.contains("push")
            || tool_name.contains("delete");

        println!(
            "# {} denials: {} → {} ({})",
            entries.len(),
            agents.join(", "),
            tool_name,
            outcome
        );
        if is_dangerous {
            println!("# ⚠️  WARNING: this is a dangerous operation — review carefully");
        }

        match outcome.as_str() {
            "denied_acl" => {
                if show_cedar {
                    println!(
                        "permit(\n    principal == Agent::\"{}\",\n    action == Action::\"{}\",\n    resource\n);\n",
                        agents.first().unwrap_or(&"*"),
                        tool_name
                    );
                }
                if show_toml {
                    println!(
                        "# [permissions.{}]\n# operations = [..., \"{}\"]\n",
                        permissions,
                        tool_name.split('_').next_back().unwrap_or(tool_name)
                    );
                }
            }
            "denied_ifc" => {
                // Extract common path patterns from args
                let paths: Vec<_> = entries
                    .iter()
                    .filter_map(|e| {
                        serde_json::from_str::<serde_json::Value>(&e.tool_args)
                            .ok()
                            .and_then(|v| v.get("path").and_then(|p| p.as_str().map(String::from)))
                    })
                    .collect();

                let common_prefix = if !paths.is_empty() {
                    common_path_prefix(&paths)
                } else {
                    String::new()
                };

                if show_cedar {
                    println!("# IFC write denial — consider adding trusted path");
                    if !common_prefix.is_empty() {
                        println!(
                            "# or use Cedar context:\n\
                             permit(\n    principal == Agent::\"{}\",\n    \
                             action == Action::\"{}\",\n    resource\n) \
                             when {{ context.trust_state == \"normal\" && \
                             context.approval_granted == \"true\" }};\n",
                            agents.first().unwrap_or(&"*"),
                            tool_name
                        );
                    }
                }
                if show_toml {
                    if !common_prefix.is_empty() {
                        println!(
                            "# [permissions.{}]\n# trusted_paths = [\"{}/**\"]\n",
                            permissions, common_prefix
                        );
                    } else {
                        println!(
                            "# [permissions.{}]\n# tainted_write_policy = \"approve\"  # was: \"deny\"\n",
                            permissions
                        );
                    }
                }
            }
            "denied_rate" => {
                if show_toml {
                    println!(
                        "# [permissions.{}]\n# rate_limit = {{ max_calls = {}, window_secs = 60 }}\n",
                        permissions,
                        entries.len() * 2
                    );
                }
            }
            _ => {
                println!("# No automatic suggestion for outcome: {outcome}\n");
            }
        }
    }

    let skipped = sorted.iter().filter(|(_, v)| v.len() < min_count).count();
    if skipped > 0 {
        println!(
            "# {skipped} groups with <{min_count} denials omitted (use --min-count 1 to see all)"
        );
    }

    Ok(())
}

fn common_path_prefix(paths: &[String]) -> String {
    if paths.is_empty() {
        return String::new();
    }
    let first = &paths[0];
    let mut prefix_len = first.len();
    for path in &paths[1..] {
        prefix_len = first
            .chars()
            .zip(path.chars())
            .take(prefix_len)
            .take_while(|(a, b)| a == b)
            .count();
    }
    // Trim to last '/'
    let prefix = &first[..prefix_len];
    match prefix.rfind('/') {
        Some(pos) => prefix[..pos].to_string(),
        None => String::new(),
    }
}

fn resolve_openapi_auth(
    auth_cfg: &Option<config::OpenApiAuthConfig>,
) -> navra_openapi::auth::AuthConfig {
    let Some(auth) = auth_cfg else {
        return navra_openapi::auth::AuthConfig::default();
    };

    let bearer = auth.bearer.as_deref().map(resolve_env_vars);

    let api_key = match (&auth.api_key_name, &auth.api_key_value) {
        (Some(name), Some(value)) => {
            let location = match auth.api_key_location.as_deref() {
                Some("query") => navra_openapi::auth::ApiKeyLocation::Query,
                _ => navra_openapi::auth::ApiKeyLocation::Header,
            };
            Some(navra_openapi::auth::ApiKeyAuth {
                name: name.clone(),
                value: resolve_env_vars(value),
                location,
            })
        }
        _ => None,
    };

    let basic = match (&auth.basic_username, &auth.basic_password) {
        (Some(user), Some(pass)) => Some(navra_openapi::auth::BasicAuth {
            username: user.clone(),
            password: resolve_env_vars(pass),
        }),
        _ => None,
    };

    navra_openapi::auth::AuthConfig {
        bearer,
        api_key,
        basic,
        oauth: None,
    }
}

fn resolve_env_vars(s: &str) -> String {
    if let Some(var) = s.strip_prefix("${").and_then(|s| s.strip_suffix('}')) {
        std::env::var(var).unwrap_or_else(|_| s.to_string())
    } else {
        s.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use navra_core::protocol::{ReadResourceResult, ResourceContent};
    use navra_protocol::compat::{CallToolResultExt, tool_input_schema};

    fn extract_resource_text(rc: &ResourceContent) -> String {
        match rc {
            ResourceContent::TextResourceContents { text, .. } => text.clone(),
            ResourceContent::BlobResourceContents { blob, .. } => blob.clone(),
        }
    }

    /// Helper: build a resource handler closure for navra://proc.
    fn proc_handler(pt: &navra_core::process::ProcessTable) -> navra_core::ResourceHandler {
        let pt = pt.clone();
        Arc::new(move |uri: String, _ctx| {
            let pt = pt.clone();
            Box::pin(async move {
                let agents = pt.snapshot();
                let json = serde_json::json!({ "agents": agents });
                ReadResourceResult::new(vec![ResourceContent::TextResourceContents {
                    uri,
                    mime_type: Some("application/json".to_string()),
                    text: serde_json::to_string_pretty(&json).unwrap_or_default(),
                    meta: None,
                }])
            })
        })
    }

    /// Helper: build a resource handler closure for navra://sessions.
    fn sessions_handler(ss: &navra_core::session::SessionStore) -> navra_core::ResourceHandler {
        let ss = ss.clone();
        Arc::new(move |uri: String, _ctx| {
            let ss = ss.clone();
            Box::pin(async move {
                let sessions = ss.list_all();
                let count = sessions.len();
                let session_list: Vec<serde_json::Value> = sessions
                    .iter()
                    .map(|s| {
                        serde_json::json!({
                            "id": s.id,
                            "agent": s.agent.name,
                            "created_at": s.created_at,
                        })
                    })
                    .collect();
                let json = serde_json::json!({
                    "count": count,
                    "sessions": session_list,
                });
                ReadResourceResult::new(vec![ResourceContent::TextResourceContents {
                    uri,
                    mime_type: Some("application/json".to_string()),
                    text: serde_json::to_string_pretty(&json).unwrap_or_default(),
                    meta: None,
                }])
            })
        })
    }

    /// Helper: build a resource handler closure for navra://version.
    fn version_handler() -> navra_core::ResourceHandler {
        let boot = std::time::Instant::now();
        Arc::new(move |uri: String, _ctx| {
            Box::pin(async move {
                let json = serde_json::json!({
                    "name": "navra",
                    "version": env!("CARGO_PKG_VERSION"),
                    "protocol_version": navra_core::protocol::PROTOCOL_VERSION,
                    "crates": 20,
                    "uptime_secs": boot.elapsed().as_secs(),
                });
                ReadResourceResult::new(vec![ResourceContent::TextResourceContents {
                    uri,
                    mime_type: Some("application/json".to_string()),
                    text: serde_json::to_string_pretty(&json).unwrap_or_default(),
                    meta: None,
                }])
            })
        })
    }

    #[tokio::test]
    async fn kernel_proc_returns_valid_json() {
        let pt = navra_core::process::ProcessTable::new();
        pt.record_call("claude", "dev", None, None, "file_read");
        pt.complete_call("claude", "file_read");
        pt.record_denied("claude", "dev", None, None);

        let handler = proc_handler(&pt);
        let ctx = navra_core::auth::CallContext::new(
            navra_core::auth::AgentIdentity::new("tester", "dev"),
            "test-session",
        );
        let result = handler("navra://proc".to_string(), ctx).await;

        assert_eq!(result.contents.len(), 1);
        let text = extract_resource_text(&result.contents[0]);
        let parsed: serde_json::Value = serde_json::from_str(&text).unwrap();
        let agents = parsed["agents"].as_array().unwrap();
        assert_eq!(agents.len(), 1);
        assert_eq!(agents[0]["name"], "claude");
        assert_eq!(agents[0]["call_count"], 1);
        assert_eq!(agents[0]["denied_count"], 1);
    }

    #[tokio::test]
    async fn kernel_sessions_returns_valid_json() {
        let ss = navra_core::session::SessionStore::new();
        ss.create(navra_core::session::Session {
            id: "abc-123".to_string(),
            agent: navra_core::auth::AgentIdentity::new("claude", "dev"),
            client_info: navra_core::protocol::ClientInfo::new("test", ""),
            initialized: true,
            context_label: navra_core::ifc::DataLabel::TRUSTED_PUBLIC,
            created_at: 1715000000,
            last_accessed: 1715000000,
        });

        let handler = sessions_handler(&ss);
        let ctx = navra_core::auth::CallContext::new(
            navra_core::auth::AgentIdentity::new("tester", "dev"),
            "test-session",
        );
        let result = handler("navra://sessions".to_string(), ctx).await;

        assert_eq!(result.contents.len(), 1);
        let text = extract_resource_text(&result.contents[0]);
        let parsed: serde_json::Value = serde_json::from_str(&text).unwrap();
        assert_eq!(parsed["count"], 1);
        let sessions = parsed["sessions"].as_array().unwrap();
        assert_eq!(sessions[0]["id"], "abc-123");
        assert_eq!(sessions[0]["agent"], "claude");
        assert_eq!(sessions[0]["created_at"], 1715000000);
    }

    #[tokio::test]
    async fn kernel_version_has_expected_fields() {
        let handler = version_handler();
        let ctx = navra_core::auth::CallContext::new(
            navra_core::auth::AgentIdentity::new("tester", "dev"),
            "test-session",
        );
        let result = handler("navra://version".to_string(), ctx).await;

        assert_eq!(result.contents.len(), 1);
        let text = extract_resource_text(&result.contents[0]);
        let parsed: serde_json::Value = serde_json::from_str(&text).unwrap();
        assert_eq!(parsed["name"], "navra");
        assert!(parsed["version"].is_string());
        assert_eq!(
            parsed["protocol_version"],
            navra_core::protocol::PROTOCOL_VERSION
        );
        assert!(parsed["crates"].is_number());
        assert!(parsed["uptime_secs"].is_number());
    }

    #[tokio::test]
    async fn kernel_tools_via_server() {
        // Build a minimal server with a couple of tools, then verify
        // the tool_names() method that navra://tools relies on.
        use navra_core::protocol::ToolDefinition;

        let server = navra_core::McpServer::builder()
            .name("test")
            .version("0.1.0")
            .allow_anonymous()
            .tool(
                ToolDefinition::new("file_read", "Read a file", tool_input_schema(None, None)),
                |_args, _ctx| Box::pin(async { navra_core::protocol::CallToolResult::text("ok") }),
            )
            .tool(
                ToolDefinition::new("git_status", "Git status", tool_input_schema(None, None)),
                |_args, _ctx| Box::pin(async { navra_core::protocol::CallToolResult::text("ok") }),
            )
            .build();

        let names = server.tool_names();
        assert!(names.contains(&"file_read".to_string()));
        assert!(names.contains(&"git_status".to_string()));
        // Also includes gateway IFC tools registered in build()
        assert!(names.contains(&"navra_var_list".to_string()));
    }
}
