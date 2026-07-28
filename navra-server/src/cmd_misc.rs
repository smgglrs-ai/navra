//! Miscellaneous CLI subcommands: approve/deny, status, systemd, audit, policy.

use crate::config;
use navra_protocol::truncate_str;

/// Send an approve or deny request to the running server via JSON-RPC.
pub(crate) async fn approve_or_deny(
    addr: &str,
    request_id: &str,
    approve: bool,
) -> anyhow::Result<()> {
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
pub(crate) async fn query_status(addr: &str) -> anyhow::Result<()> {
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
pub(crate) fn uninstall_systemd_units() -> anyhow::Result<()> {
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

/// Display blackbox audit trail entries.
pub(crate) fn audit_command(
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
            let args_short = truncate_str(&e.tool_args, 120);
            let result_short = truncate_str(&e.tool_result, 120);
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

/// Suggest policy changes based on recent blackbox denials.
pub(crate) fn policy_suggest(
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

/// Find the longest common directory prefix among a set of paths.
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

/// Import an MCP configuration file (Claude, Cursor, etc.) and print
/// the equivalent navra TOML.
pub(crate) fn import_mcp_file(path: &str, redact: bool) -> anyhow::Result<()> {
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
