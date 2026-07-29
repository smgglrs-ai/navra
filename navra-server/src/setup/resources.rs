//! Resource registration for `flow://` and `navra://` URIs.
//!
//! Registers flow task result resources (backed by audit.db) and
//! kernel introspection resources (proc, sessions, metrics, tools, version).

use std::sync::Arc;

/// Register the `flow://` resource (flow task results from audit.db).
pub(crate) fn wire_flow_resources(
    builder: navra_core::McpServerBuilder,
    audit_log: &Arc<navra_memory::AuditLog>,
) -> navra_core::McpServerBuilder {
    let flow_audit = Arc::clone(audit_log);
    let builder = builder.resource(
        navra_core::protocol::ResourceDefinition::new(
            navra_protocol::RawResource::new("flow://", "Flow task results")
                .with_description(
                    "Read flow task outputs. Use flow://list for all flows, \
                     flow://<flow_id>/tasks for task list, \
                     flow://<flow_id>/task/<task_id> for a specific output.",
                )
                .with_mime_type("text/plain"),
            None,
        ),
        Arc::new(move |uri: String, _ctx| {
            let audit = Arc::clone(&flow_audit);
            Box::pin(async move {
                let text = if uri == "flow://" || uri == "flow://list" {
                    match audit.list_flows() {
                        Ok(flows) if !flows.is_empty() => flows
                            .iter()
                            .map(|f| {
                                format!("{}: {} tasks, {}", f.flow_id, f.task_count, f.status)
                            })
                            .collect::<Vec<_>>()
                            .join("\n"),
                        _ => "No flows found.".to_string(),
                    }
                } else if let Some(rest) = uri.strip_prefix("flow://") {
                    let parts: Vec<&str> = rest.splitn(3, '/').collect();
                    match parts.as_slice() {
                        [flow_id, "tasks"] | [flow_id] => {
                            match audit.get_flow_results(flow_id) {
                                Ok(results) if !results.is_empty() => results
                                    .iter()
                                    .map(|r| {
                                        format!(
                                            "{} ({}): {} [{} chars]",
                                            r.task_id,
                                            r.specialist.as_deref().unwrap_or("?"),
                                            r.status,
                                            r.output.as_deref().map(|o| o.len()).unwrap_or(0)
                                        )
                                    })
                                    .collect::<Vec<_>>()
                                    .join("\n"),
                                _ => format!("No results for flow {flow_id}"),
                            }
                        }
                        [flow_id, "task", task_id] => match audit.get_flow_results(flow_id) {
                            Ok(results) => {
                                match results.iter().find(|r| r.task_id == *task_id) {
                                    Some(r) => r
                                        .output
                                        .clone()
                                        .unwrap_or_else(|| "(no output)".to_string()),
                                    None => {
                                        format!("Task {task_id} not found in flow {flow_id}")
                                    }
                                }
                            }
                            Err(e) => format!("Error reading flow {flow_id}: {e}"),
                        },
                        _ => format!(
                            "Invalid flow URI: {uri}. Use flow://list, flow://<id>/tasks, or flow://<id>/task/<task_id>"
                        ),
                    }
                } else {
                    format!("Invalid URI: {uri}")
                };
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
    tracing::info!("Registered flow:// resources (backed by audit.db)");
    builder
}

/// Register all `navra://` kernel introspection resources.
pub(crate) fn wire_kernel_resources(
    mut builder: navra_core::McpServerBuilder,
    process_table: &navra_core::process::ProcessTable,
    session_store: &navra_core::session::SessionStore,
    server_cell: &Arc<std::sync::OnceLock<Arc<navra_core::McpServer>>>,
    boot_instant: std::time::Instant,
) -> navra_core::McpServerBuilder {
    // navra://proc
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

    // navra://sessions
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

    // navra://metrics
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

    // navra://tools
    {
        let cell = Arc::clone(server_cell);
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

    // navra://version
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

    builder
}
