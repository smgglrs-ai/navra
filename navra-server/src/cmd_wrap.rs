//! `navra wrap` subcommand — proxy an upstream MCP server through navra.

use crate::config;
use crate::network_discovery;
use navra_core::auth::TokenAuthenticator;

/// Run `navra wrap`, proxying an upstream MCP server through navra with
/// generated authentication and safety settings.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn wrap_command(
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

    crate::serve(cfg, no_tray, false).await
}

/// Run `navra wrap --discover`, connecting to the upstream to inspect its
/// tools, prompts, resources, and network requirements.
pub(crate) async fn wrap_discover(name: &str, command: &[String]) -> anyhow::Result<()> {
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
