//! Gateway-side logic for the teammate task-delivery API
//! (`GET /api/agent/task`, `POST /api/agent/result`).
//!
//! Two caller identities reach the task endpoint:
//!
//! - **Teammate tokens** (`did:teammate:{team}:{mate}`) — the
//!   standard case: the spec is served directly. This is how tasks
//!   are redelivered after a pod restart.
//! - **Warm-pool bootstrap tokens** (`did:pool:{pool}`) — a
//!   pre-warmed Sandbox adopted via SandboxClaim holds no per-spawn
//!   credentials. It presents its pool bootstrap token plus its
//!   sandbox name (downward API) in the `X-Navra-Sandbox` header;
//!   the gateway resolves the teammate registered for that sandbox,
//!   mints a fresh delegated token scoped to that teammate, and
//!   returns it with the task spec. The agent switches to the fresh
//!   token for all subsequent calls.

use std::sync::Arc;

use navra_core::identity::Ed25519Signer;

use crate::agent_spawn::mint_teammate_token;
use crate::team_tools::TeamRegistry;

/// Gateway state for the task-delivery API.
pub(crate) struct AgentTaskApi {
    pub(crate) registry: Arc<TeamRegistry>,
    pub(crate) signer: Arc<Ed25519Signer>,
    /// Root capability payload for delegation chains; `None` falls
    /// back to flat token minting (same as the spawn paths).
    pub(crate) root_payload: Option<navra_core::auth::capability::CapabilityPayload>,
}

/// Why a task fetch was rejected.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum TaskFetchError {
    /// The caller's did is neither a teammate nor a pool identity.
    NotATeammate,
    /// Team/teammate (or sandbox → teammate mapping) not found.
    NotFound,
    /// Pool identity without an `X-Navra-Sandbox` header.
    MissingSandboxHeader,
    /// Token minting failed (surface the error text).
    Mint(String),
}

impl AgentTaskApi {
    /// Serve a task spec for an authenticated caller.
    ///
    /// `did` is the authenticated subject; `sandbox` is the optional
    /// `X-Navra-Sandbox` header value (the caller's Kubernetes
    /// Sandbox name, set via the downward API in the pool template).
    pub(crate) fn task_for(
        &self,
        did: Option<&str>,
        sandbox: Option<&str>,
    ) -> Result<serde_json::Value, TaskFetchError> {
        let did = did.ok_or(TaskFetchError::NotATeammate)?;

        if let Some(rest) = did.strip_prefix("did:teammate:") {
            let (team, mate) = rest.split_once(':').ok_or(TaskFetchError::NotATeammate)?;
            if team.is_empty() || mate.is_empty() {
                return Err(TaskFetchError::NotATeammate);
            }
            return self
                .registry
                .task_spec(team, mate)
                .ok_or(TaskFetchError::NotFound);
        }

        if did.starts_with("did:pool:") {
            // Warm-pool adoption: resolve the teammate by sandbox
            // name, then mint a fresh scoped token.
            let sandbox = sandbox.ok_or(TaskFetchError::MissingSandboxHeader)?;
            let (team, mate) = self
                .registry
                .teammate_by_k8s_sandbox(sandbox)
                .ok_or(TaskFetchError::NotFound)?;

            let (ops, tools, ttl) = self
                .registry
                .teammate_caps(&team, &mate)
                .ok_or(TaskFetchError::NotFound)?;

            let teammate_did = format!("did:teammate:{team}:{mate}");
            let token = mint_teammate_token(
                self.root_payload.as_ref(),
                &self.signer,
                &teammate_did,
                ops,
                tools,
                ttl,
            )
            .map_err(TaskFetchError::Mint)?;

            let mut spec = self
                .registry
                .task_spec(&team, &mate)
                .ok_or(TaskFetchError::NotFound)?;
            spec["token"] = serde_json::json!(token);
            return Ok(spec);
        }

        Err(TaskFetchError::NotATeammate)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn api_with_registry(reg: Arc<TeamRegistry>) -> AgentTaskApi {
        AgentTaskApi {
            registry: reg,
            signer: Arc::new(Ed25519Signer::generate()),
            root_payload: None,
        }
    }

    fn registry_with_claimed_teammate() -> Arc<TeamRegistry> {
        let reg = Arc::new(TeamRegistry::default());
        let team = reg
            .create_team(
                "t",
                None,
                "lead",
                0,
                crate::team_tools::TeamBudget::default(),
            )
            .unwrap();
        reg.add_teammate(
            &team,
            "worker",
            None,
            "granite3.3:8b",
            "local",
            vec!["read".to_string()],
            vec!["team_bb_publish".to_string()],
            None,
            None,
            None,
        )
        .unwrap();
        reg.send_message(&team, "worker", "do the thing").unwrap();
        reg.set_k8s_sandbox(&team, "worker", "navra-agents-abc12".to_string());
        reg
    }

    #[test]
    fn teammate_did_serves_spec_without_token() {
        let reg = registry_with_claimed_teammate();
        let api = api_with_registry(reg);
        let spec = api
            .task_for(Some("did:teammate:team-1:worker"), None)
            .unwrap();
        assert_eq!(spec["task"], "do the thing");
        assert!(spec.get("token").is_none());
    }

    #[test]
    fn pool_identity_adopts_by_sandbox_and_mints_token() {
        let reg = registry_with_claimed_teammate();
        let api = api_with_registry(reg);
        let spec = api
            .task_for(Some("did:pool:navra-agents"), Some("navra-agents-abc12"))
            .unwrap();

        assert_eq!(spec["task"], "do the thing");
        let token = spec["token"].as_str().expect("fresh token in spec");
        assert!(token.starts_with("navra_cap_v1."));

        // The minted token must identify the adopted teammate.
        let payload = navra_core::auth::capability::decode_token(token, api.signer.as_ref())
            .expect("token decodes with the api signer");
        assert_eq!(payload.sub, "did:teammate:team-1:worker");
    }

    #[test]
    fn pool_identity_without_sandbox_header_rejected() {
        let reg = registry_with_claimed_teammate();
        let api = api_with_registry(reg);
        assert_eq!(
            api.task_for(Some("did:pool:navra-agents"), None),
            Err(TaskFetchError::MissingSandboxHeader)
        );
    }

    #[test]
    fn unknown_sandbox_is_not_found() {
        let reg = registry_with_claimed_teammate();
        let api = api_with_registry(reg);
        assert_eq!(
            api.task_for(Some("did:pool:navra-agents"), Some("nope")),
            Err(TaskFetchError::NotFound)
        );
    }

    #[test]
    fn non_teammate_did_rejected() {
        let reg = registry_with_claimed_teammate();
        let api = api_with_registry(reg);
        assert_eq!(
            api.task_for(Some("did:root:human"), None),
            Err(TaskFetchError::NotATeammate)
        );
        assert_eq!(api.task_for(None, None), Err(TaskFetchError::NotATeammate));
    }
}
