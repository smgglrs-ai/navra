//! Authentication chain wiring.
//!
//! Registers BLAKE3 token authenticators, capability token issuance,
//! OpenShell federation, and dev-mode anonymous access.

use crate::config;
use navra_core::auth::AgentIdentity;
use navra_core::identity::Ed25519Signer;
use std::sync::Arc;

/// Wire the authenticator chain on the server builder.
///
/// Handles three cases:
/// - Agents configured with capability tokens: chain = cap + OpenShell? + BLAKE3
/// - Agents configured without cap tokens: BLAKE3 only (+ OpenShell?)
/// - No agents: cap-only chain for flow/team tokens, with dev-mode fallback
///
/// In dev-mode, if the "readonly" permission set does not exist in the
/// config, a minimal deny-all set is registered so anonymous agents hit
/// explicit tool-level enforcement instead of bypassing ACLs.
pub(crate) fn wire_auth(
    mut builder: navra_core::McpServerBuilder,
    cfg: &mut config::Config,
    root_signer: &Arc<Ed25519Signer>,
    dev_mode: bool,
) -> anyhow::Result<navra_core::McpServerBuilder> {
    // Defense-in-depth: always register a deny-all "default"
    // permission set (tools, paths, safety) so agents whose
    // permission set is missing from the config hit explicit
    // deny-all enforcement instead of fail-open gates. Mirrors the
    // dev-mode "readonly" fallback below.
    if !cfg.permissions.contains_key("default") {
        tracing::warn!(
            "No [permissions.default] configured — registering a \
             deny-all fallback permission set named \"default\"."
        );
        cfg.permissions.insert(
            "default".to_string(),
            config::PermissionSet {
                default_tool_policy: "deny".to_string(),
                ..Default::default()
            },
        );
    }
    builder = builder.path_acl(
        "default",
        navra_auth::permissions::PathAcl {
            ring: None,
            allow: vec![],
            deny: vec![],
            operations: std::collections::HashSet::new(),
            requires_approval: std::collections::HashSet::new(),
        },
    );

    // DNS-rebinding defense: the streamable HTTP transport validates
    // the Host header against an allowlist (bind host + localhost).
    builder = builder.allowed_http_hosts(allowed_http_hosts(cfg));

    if !cfg.agents.is_empty() {
        let has_cap_agents = cfg.agents.iter().any(|a| a.capability_token);

        // Issue capability tokens for agents that request them
        if has_cap_agents {
            issue_capability_tokens(cfg, root_signer);
        }

        let mut blake3_auth = navra_core::auth::TokenAuthenticator::new();
        for agent in &cfg.agents {
            let perm_set = cfg.permissions.get(&agent.permissions);
            blake3_auth
                .register_hash(
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
                        wimse: None,
                    },
                )
                .map_err(|e| {
                    anyhow::anyhow!("invalid token_hash for agent '{}': {e}", agent.name)
                })?;
            if agent.pubkey.is_some() {
                tracing::debug!(agent = %agent.name, "Agent has pubkey configured");
            }
            tracing::info!(agent = %agent.name, permissions = %agent.permissions, "Registered agent");
        }

        let nonce_cache_ttl = nonce_ttl(cfg);

        // The capability authenticator is always in the chain: the
        // gateway mints delegated capability tokens for teammates
        // (teams/flows) regardless of how the configured human agents
        // authenticate. Gating it on has_cap_agents left teammates
        // unauthenticated whenever no agent used capability auth.
        let cap_auth = navra_core::auth::chain::CapabilityAuthenticator::with_nonce_ttl(
            Box::new(Arc::clone(root_signer)),
            nonce_cache_ttl,
        )
        .with_permission_set(capability_default_permission_set(cfg));
        let mut chain = navra_core::auth::chain::ChainAuthenticator::new().add(cap_auth);

        if let Some(wimse_config) = cfg.server.wimse_auth.clone()
            && wimse_config.enabled
        {
            let wimse_auth = navra_core::auth::wimse::WimseAuthenticator::new(wimse_config);
            chain = chain.add(wimse_auth);
            tracing::info!("WIMSE/SPIFFE identity federation enabled");
        }

        if let Some(os_config) = cfg.server.openshell_auth.clone() {
            let os_auth = navra_core::auth::openshell::OpenShellAuthenticator::new(os_config);
            chain = chain.add(os_auth);
            tracing::info!("OpenShell identity federation enabled");
        }

        chain = chain.add(blake3_auth);
        builder = builder.authenticator(chain);
        tracing::info!(
            cap_agents = has_cap_agents,
            "Authenticator chain: capability tokens + BLAKE3"
        );
    } else {
        // No agents configured — capability tokens only (for flow/team tokens)
        let nonce_cache_ttl = nonce_ttl(cfg);
        let cap_auth = navra_core::auth::chain::CapabilityAuthenticator::with_nonce_ttl(
            Box::new(Arc::clone(root_signer)),
            nonce_cache_ttl,
        )
        .with_permission_set(capability_default_permission_set(cfg));
        let mut chain = navra_core::auth::chain::ChainAuthenticator::new().add(cap_auth);

        if let Some(wimse_config) = cfg.server.wimse_auth.clone()
            && wimse_config.enabled
        {
            let wimse_auth = navra_core::auth::wimse::WimseAuthenticator::new(wimse_config);
            chain = chain.add(wimse_auth);
            tracing::info!("WIMSE/SPIFFE identity federation enabled");
        }

        if let Some(os_config) = cfg.server.openshell_auth.clone() {
            let os_auth = navra_core::auth::openshell::OpenShellAuthenticator::new(os_config);
            chain = chain.add(os_auth);
            tracing::info!("OpenShell identity federation enabled");
        }

        if dev_mode {
            // Ensure the "readonly" permission set exists so anonymous
            // agents get explicit deny-all tool enforcement instead of
            // silently matching no ACLs.
            if !cfg.permissions.contains_key("readonly") {
                tracing::warn!(
                    "DEV MODE: No [permissions.readonly] configured — \
                     registering deny-all fallback so anonymous access \
                     is restricted by default."
                );
                let fallback = config::PermissionSet {
                    default_tool_policy: "deny".to_string(),
                    ..Default::default()
                };
                cfg.permissions.insert("readonly".to_string(), fallback);
            }

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

    Ok(builder)
}

/// Issue capability tokens for agents that have `capability_token = true`.
fn issue_capability_tokens(cfg: &config::Config, root_signer: &Arc<Ed25519Signer>) {
    use navra_core::identity::CapSigner;

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
                .unwrap_or_default(),
            // Fail closed: a permission set with no allow rules
            // yields an empty tool list (nothing callable), never a
            // wildcard grant.
            credentials: creds,
        };

        let payload = navra_core::auth::capability::build_payload(
            root_signer.did(),
            &subject_did,
            cap_set,
            ring,
            ttl,
        );

        match navra_core::auth::capability::encode_token(&payload, root_signer.as_ref()) {
            Ok(token) => {
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

/// Compute the HTTP Host-header allowlist: the configured bind host
/// plus localhost variants. Wildcard binds (0.0.0.0, ::) are not
/// hostnames a client may send, so they fall back to the localhost
/// set — operators binding publicly should set `tcp` to a specific
/// hostname.
fn allowed_http_hosts(cfg: &config::Config) -> Vec<String> {
    let mut hosts: Vec<String> = vec![
        "localhost".to_string(),
        "127.0.0.1".to_string(),
        "::1".to_string(),
    ];
    let bind_host = cfg
        .server
        .tcp
        .as_deref()
        .and_then(|addr| addr.rsplit_once(':'))
        .map(|(host, _)| host.trim_start_matches('[').trim_end_matches(']'))
        .unwrap_or("127.0.0.1");
    if !bind_host.is_empty()
        && bind_host != "0.0.0.0"
        && bind_host != "::"
        && bind_host != "*"
        && !hosts.iter().any(|h| h == bind_host)
    {
        hosts.push(bind_host.to_string());
    }
    hosts
}

/// Compute the nonce cache TTL from config.
fn nonce_ttl(cfg: &config::Config) -> std::time::Duration {
    std::time::Duration::from_secs(
        cfg.server
            .identity
            .as_ref()
            .map(|i| i.nonce_cache_ttl_secs)
            .unwrap_or(7200),
    )
}

/// Resolve the permission set assigned to capability-token identities.
///
/// Resolution order:
/// 1. An operator-registered `[permissions.capability]` set takes
///    precedence — capability-token identities are then routed through
///    that registered ACL (which can be the deny-all `default` set if
///    the operator wants capability tokens fully path-restricted).
/// 2. Otherwise the reserved name `cap:token` is used. It is never a
///    registered permission set, so the token's own embedded
///    capabilities are enforced (least privilege: only the operations,
///    tools, and paths granted in the token itself), with the deny-all
///    "default" set's deny rules layered on top by
///    `PermissionEngine::check_with_capabilities`.
///
/// This replaces the former hard-coded `"dev"` default, which silently
/// granted capability-token agents whatever the (potentially
/// permissive) `[permissions.dev]` set allowed.
fn capability_default_permission_set(cfg: &config::Config) -> String {
    if cfg.permissions.contains_key("capability") {
        tracing::info!("Capability-token identities use registered [permissions.capability] set");
        "capability".to_string()
    } else {
        navra_core::auth::chain::DEFAULT_CAP_PERMISSION_SET.to_string()
    }
}
