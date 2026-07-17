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
pub(crate) fn wire_auth(
    mut builder: navra_core::McpServerBuilder,
    cfg: &config::Config,
    root_signer: &Arc<Ed25519Signer>,
    dev_mode: bool,
) -> anyhow::Result<navra_core::McpServerBuilder> {
    if !cfg.agents.is_empty() {
        let has_cap_agents = cfg.agents.iter().any(|a| a.capability_token);

        // Issue capability tokens for agents that request them
        if has_cap_agents {
            issue_capability_tokens(cfg, root_signer);
        }

        let mut blake3_auth = navra_core::auth::TokenAuthenticator::new();
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

        let nonce_cache_ttl = nonce_ttl(cfg);

        if has_cap_agents {
            let cap_auth = navra_core::auth::chain::CapabilityAuthenticator::with_nonce_ttl(
                Box::new(Arc::clone(root_signer)),
                nonce_cache_ttl,
            );
            let mut chain = navra_core::auth::chain::ChainAuthenticator::new().add(cap_auth);

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
        // No agents configured — capability tokens only (for flow/team tokens)
        let nonce_cache_ttl = nonce_ttl(cfg);
        let cap_auth = navra_core::auth::chain::CapabilityAuthenticator::with_nonce_ttl(
            Box::new(Arc::clone(root_signer)),
            nonce_cache_ttl,
        );
        let mut chain = navra_core::auth::chain::ChainAuthenticator::new().add(cap_auth);

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
