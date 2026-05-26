use crate::auth::CallContext;
use crate::protocol::{
    CallToolParams, GetPromptParams, InitializeParams, JsonRpcError, JsonRpcRequest,
    JsonRpcResponse, PaginatedRequest, ReadResourceParams,
};
use crate::server::McpServer;
use smgglrs_protocol::permissions::{
    PermissionDenyParams, PermissionGrantParams, PermissionRequestParams,
};
use std::sync::Arc;

/// Returns (response, optional_session_id_for_header).
pub(crate) async fn dispatch(
    server: Arc<McpServer>,
    request: JsonRpcRequest,
    agent: crate::auth::AgentIdentity,
    session_id: Option<String>,
) -> (JsonRpcResponse, Option<String>) {
    let id = request.id.clone();

    // Verify the authenticated agent matches the session's creator
    if let Some(ref sid) = session_id {
        match server.sessions().get(sid) {
            Some(session) => {
                if session.agent.name != agent.name {
                    return (
                        JsonRpcResponse::error(
                            id,
                            JsonRpcError::new(
                                crate::protocol::ErrorCode::Custom(-32000),
                                "Session does not belong to this agent",
                            ),
                        ),
                        None,
                    );
                }
            }
            None => {
                // Session ID provided but session doesn't exist (expired or invalid)
                return (
                    JsonRpcResponse::error(
                        id,
                        JsonRpcError::new(
                            crate::protocol::ErrorCode::Custom(-32001),
                            "Session not found — it may have expired",
                        ),
                    ),
                    None,
                );
            }
        }
    }

    // Require a valid session for all methods except initialize and notifications
    let needs_session = !matches!(
        request.method.as_str(),
        "initialize" | "notifications/initialized"
    );
    if needs_session && session_id.is_none() {
        return (
            JsonRpcResponse::error(
                id,
                JsonRpcError::new(
                    crate::protocol::ErrorCode::Custom(-32002),
                    "Session required — call initialize first",
                ),
            ),
            None,
        );
    }

    match request.method.as_str() {
        "initialize" => {
            let params: InitializeParams =
                match request.params.and_then(|p| serde_json::from_value(p).ok()) {
                    Some(p) => p,
                    None => {
                        return (
                            JsonRpcResponse::error(
                                id,
                                JsonRpcError::invalid_params("Invalid initialize params"),
                            ),
                            None,
                        );
                    }
                };
            match server.handle_initialize(params, agent) {
                Ok((result, new_session_id)) => {
                    let value = serde_json::to_value(&result).unwrap_or_else(|e| {
                        tracing::error!(error = %e, "Failed to serialize response");
                        serde_json::json!({"error": "serialization failed"})
                    });
                    (JsonRpcResponse::success(id, value), Some(new_session_id))
                }
                Err(msg) => (
                    JsonRpcResponse::error(id, JsonRpcError::invalid_params(&msg)),
                    None,
                ),
            }
        }

        "notifications/initialized" => (
            JsonRpcResponse::success(id, serde_json::json!({})),
            session_id,
        ),

        "ping" => (
            JsonRpcResponse::success(id, serde_json::json!({})),
            session_id,
        ),

        "tools/list" => {
            let pagination: PaginatedRequest = request
                .params
                .and_then(|p| serde_json::from_value(p).ok())
                .unwrap_or_default();
            let result = server.handle_list_tools(&agent, &pagination);
            (
                JsonRpcResponse::success(
                    id,
                    serde_json::to_value(&result).unwrap_or_else(|e| {
                        tracing::error!(error = %e, "Failed to serialize response");
                        serde_json::json!({"error": "serialization failed"})
                    }),
                ),
                session_id,
            )
        }

        "tools/call" => {
            let params: CallToolParams =
                match request.params.and_then(|p| serde_json::from_value(p).ok()) {
                    Some(p) => p,
                    None => {
                        return (
                            JsonRpcResponse::error(
                                id,
                                JsonRpcError::invalid_params("Invalid tool call params"),
                            ),
                            session_id,
                        );
                    }
                };
            let sid = match session_id.clone() {
                Some(s) if !s.is_empty() => s,
                _ => {
                    return (
                        JsonRpcResponse::error(
                            id,
                            JsonRpcError::invalid_params(
                                "Session ID required for tools/call. Send initialize first.",
                            ),
                        ),
                        session_id,
                    );
                }
            };
            let mut ctx = CallContext::new(agent, sid.clone());
            // Load persisted context label from session into taint tracker
            let persisted_label = server.sessions().context_label(&sid);
            ctx.taint.absorb(persisted_label);
            let result = server.handle_call_tool(params, ctx).await;
            // Persist the result's label back to the session
            server.sessions().update_context_label(&sid, result.label);
            (
                JsonRpcResponse::success(
                    id,
                    serde_json::to_value(&result).unwrap_or_else(|e| {
                        tracing::error!(error = %e, "Failed to serialize response");
                        serde_json::json!({"error": "serialization failed"})
                    }),
                ),
                session_id,
            )
        }

        "resources/list" => {
            let pagination: PaginatedRequest = request
                .params
                .and_then(|p| serde_json::from_value(p).ok())
                .unwrap_or_default();
            let result = server.handle_list_resources(&agent, &pagination);
            (
                JsonRpcResponse::success(
                    id,
                    serde_json::to_value(&result).unwrap_or_else(|e| {
                        tracing::error!(error = %e, "Failed to serialize response");
                        serde_json::json!({"error": "serialization failed"})
                    }),
                ),
                session_id,
            )
        }

        "resources/templates/list" => {
            let pagination: PaginatedRequest = request
                .params
                .and_then(|p| serde_json::from_value(p).ok())
                .unwrap_or_default();
            let result = server.handle_list_resource_templates(&agent, &pagination);
            (
                JsonRpcResponse::success(
                    id,
                    serde_json::to_value(&result).unwrap_or_else(|e| {
                        tracing::error!(error = %e, "Failed to serialize response");
                        serde_json::json!({"error": "serialization failed"})
                    }),
                ),
                session_id,
            )
        }

        "resources/read" => {
            let params: ReadResourceParams =
                match request.params.and_then(|p| serde_json::from_value(p).ok()) {
                    Some(p) => p,
                    None => {
                        return (
                            JsonRpcResponse::error(
                                id,
                                JsonRpcError::invalid_params("Invalid resource read params"),
                            ),
                            session_id,
                        );
                    }
                };
            let resp = match server.handle_read_resource(params, &agent).await {
                Ok(result) => JsonRpcResponse::success(
                    id,
                    serde_json::to_value(&result).unwrap_or_else(|e| {
                        tracing::error!(error = %e, "Failed to serialize response");
                        serde_json::json!({"error": "serialization failed"})
                    }),
                ),
                Err(msg) => JsonRpcResponse::error(id, JsonRpcError::invalid_params(&msg)),
            };
            (resp, session_id)
        }

        "prompts/list" => {
            let pagination: PaginatedRequest = request
                .params
                .and_then(|p| serde_json::from_value(p).ok())
                .unwrap_or_default();
            let result = server.handle_list_prompts(&agent, &pagination);
            (
                JsonRpcResponse::success(
                    id,
                    serde_json::to_value(&result).unwrap_or_else(|e| {
                        tracing::error!(error = %e, "Failed to serialize response");
                        serde_json::json!({"error": "serialization failed"})
                    }),
                ),
                session_id,
            )
        }

        "prompts/get" => {
            let params: GetPromptParams =
                match request.params.and_then(|p| serde_json::from_value(p).ok()) {
                    Some(p) => p,
                    None => {
                        return (
                            JsonRpcResponse::error(
                                id,
                                JsonRpcError::invalid_params("Invalid prompt get params"),
                            ),
                            session_id,
                        );
                    }
                };
            let resp = match server.handle_get_prompt(params, &agent).await {
                Ok(result) => JsonRpcResponse::success(
                    id,
                    serde_json::to_value(&result).unwrap_or_else(|e| {
                        tracing::error!(error = %e, "Failed to serialize response");
                        serde_json::json!({"error": "serialization failed"})
                    }),
                ),
                Err(msg) => JsonRpcResponse::error(id, JsonRpcError::invalid_params(&msg)),
            };
            (resp, session_id)
        }

        "permissions/request" => {
            let params: PermissionRequestParams =
                match request.params.and_then(|p| serde_json::from_value(p).ok()) {
                    Some(p) => p,
                    None => {
                        return (
                            JsonRpcResponse::error(
                                id,
                                JsonRpcError::invalid_params("Invalid permissions/request params"),
                            ),
                            session_id,
                        );
                    }
                };
            let sid = match session_id.as_deref() {
                Some(s) if !s.is_empty() => s,
                _ => {
                    return (
                        JsonRpcResponse::error(
                            id,
                            JsonRpcError::invalid_params(
                                "Session ID required for permissions/request",
                            ),
                        ),
                        session_id,
                    );
                }
            };
            let result = server.handle_permission_request(params, sid);
            (
                JsonRpcResponse::success(
                    id,
                    serde_json::to_value(&result).unwrap_or_else(|e| {
                        tracing::error!(error = %e, "Failed to serialize response");
                        serde_json::json!({"error": "serialization failed"})
                    }),
                ),
                session_id,
            )
        }

        "permissions/grant" => {
            let params: PermissionGrantParams =
                match request.params.and_then(|p| serde_json::from_value(p).ok()) {
                    Some(p) => p,
                    None => {
                        return (
                            JsonRpcResponse::error(
                                id,
                                JsonRpcError::invalid_params("Invalid permissions/grant params"),
                            ),
                            session_id,
                        );
                    }
                };
            let resp = match server.handle_permission_grant(params, &agent.name) {
                Ok(result) => JsonRpcResponse::success(
                    id,
                    serde_json::to_value(&result).unwrap_or_else(|e| {
                        tracing::error!(error = %e, "Failed to serialize response");
                        serde_json::json!({"error": "serialization failed"})
                    }),
                ),
                Err(msg) => JsonRpcResponse::error(id, JsonRpcError::invalid_params(&msg)),
            };
            (resp, session_id)
        }

        "permissions/deny" => {
            let params: PermissionDenyParams =
                match request.params.and_then(|p| serde_json::from_value(p).ok()) {
                    Some(p) => p,
                    None => {
                        return (
                            JsonRpcResponse::error(
                                id,
                                JsonRpcError::invalid_params("Invalid permissions/deny params"),
                            ),
                            session_id,
                        );
                    }
                };
            let resp = match server.handle_permission_deny(params) {
                Ok(result) => JsonRpcResponse::success(
                    id,
                    serde_json::to_value(&result).unwrap_or_else(|e| {
                        tracing::error!(error = %e, "Failed to serialize response");
                        serde_json::json!({"error": "serialization failed"})
                    }),
                ),
                Err(msg) => JsonRpcResponse::error(id, JsonRpcError::invalid_params(&msg)),
            };
            (resp, session_id)
        }

        "permissions/list" => {
            let sid = match session_id.as_deref() {
                Some(s) if !s.is_empty() => s,
                _ => {
                    return (
                        JsonRpcResponse::error(
                            id,
                            JsonRpcError::invalid_params(
                                "Session ID required for permissions/list",
                            ),
                        ),
                        session_id,
                    );
                }
            };
            let result = server.handle_permission_list(sid);
            (
                JsonRpcResponse::success(
                    id,
                    serde_json::to_value(&result).unwrap_or_else(|e| {
                        tracing::error!(error = %e, "Failed to serialize response");
                        serde_json::json!({"error": "serialization failed"})
                    }),
                ),
                session_id,
            )
        }

        "completion/complete" => {
            let params: crate::protocol::CompleteParams = match request.params.and_then(|p| {
                let ref_obj = p.get("ref")?;
                let argument = p.get("argument")?;
                Some(crate::protocol::CompleteParams {
                    ref_type: ref_obj.get("type")?.as_str()?.to_string(),
                    ref_name: ref_obj.get("name")?.as_str()?.to_string(),
                    argument: serde_json::from_value::<crate::protocol::CompletionArgument>(
                        argument.clone(),
                    )
                    .ok()?,
                })
            }) {
                Some(p) => p,
                None => {
                    return (
                        JsonRpcResponse::error(
                            id,
                            JsonRpcError::invalid_params("Invalid completion/complete params"),
                        ),
                        session_id,
                    );
                }
            };
            let result = server.handle_complete(params);
            (
                JsonRpcResponse::success(
                    id,
                    serde_json::json!({
                        "completion": {
                            "values": result.values,
                            "total": result.total,
                            "hasMore": result.has_more,
                        }
                    }),
                ),
                session_id,
            )
        }

        "logging/setLevel" => {
            let params: crate::protocol::SetLevelParams =
                match request.params.and_then(|p| serde_json::from_value(p).ok()) {
                    Some(p) => p,
                    None => {
                        return (
                            JsonRpcResponse::error(
                                id,
                                JsonRpcError::invalid_params("Invalid logging/setLevel params"),
                            ),
                            session_id,
                        );
                    }
                };
            if let Some(ref sid) = session_id {
                server.handle_set_log_level(params, sid);
            }
            (
                JsonRpcResponse::success(id, serde_json::json!({})),
                session_id,
            )
        }

        "resources/subscribe" => {
            let uri = match request
                .params
                .and_then(|p| p.get("uri").and_then(|u| u.as_str().map(String::from)))
            {
                Some(u) => u,
                None => {
                    return (
                        JsonRpcResponse::error(
                            id,
                            JsonRpcError::invalid_params("Missing 'uri' parameter"),
                        ),
                        session_id,
                    );
                }
            };
            if let Some(ref sid) = session_id {
                if let Err(e) = server.handle_resource_subscribe(&uri, sid) {
                    return (
                        JsonRpcResponse::error(id, JsonRpcError::invalid_params(&e)),
                        session_id,
                    );
                }
            }
            (
                JsonRpcResponse::success(id, serde_json::json!({})),
                session_id,
            )
        }

        "resources/unsubscribe" => {
            let uri = match request
                .params
                .and_then(|p| p.get("uri").and_then(|u| u.as_str().map(String::from)))
            {
                Some(u) => u,
                None => {
                    return (
                        JsonRpcResponse::error(
                            id,
                            JsonRpcError::invalid_params("Missing 'uri' parameter"),
                        ),
                        session_id,
                    );
                }
            };
            if let Some(ref sid) = session_id {
                if let Err(e) = server.handle_resource_unsubscribe(&uri, sid) {
                    return (
                        JsonRpcResponse::error(id, JsonRpcError::invalid_params(&e)),
                        session_id,
                    );
                }
            }
            (
                JsonRpcResponse::success(id, serde_json::json!({})),
                session_id,
            )
        }

        _ => (
            JsonRpcResponse::error(id, JsonRpcError::method_not_found(&request.method)),
            session_id,
        ),
    }
}
