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
//!
//! # Adoption security (layered)
//!
//! The sandbox header is self-asserted, so the pool branch is
//! defended in layers:
//!
//! 1. **Pool binding (enforced here)** — the registry binds each
//!    sandbox→teammate mapping to the pool DID that claimed it
//!    ([`TeamRegistry::adopt_k8s_sandbox`]). A caller whose pool DID
//!    does not match the binding is refused; the same pool re-polls
//!    idempotently. This kills cross-pool adoption and sandbox-name
//!    spoofing by holders of other pools' bootstrap tokens.
//! 2. **Short-lived, zero-capability bootstrap tokens** — minted
//!    with a 24h TTL and no operations/tools
//!    (`agent_spawn::mint_pool_bootstrap_token`), so a leaked
//!    bootstrap token is inert beyond the task poll and expires
//!    quickly.
//! 3. **Known limitation / long-term fix** — the `X-Navra-Sandbox`
//!    header is still self-asserted within a pool, and the route
//!    (ui.rs) only forwards the decoded DID, so the task endpoint
//!    cannot yet require the bootstrap-token marker claim or inspect
//!    capabilities. The proper fix is transport-level: issue each
//!    warm pod a SPIFFE X509-SVID (client certificate) bound to the
//!    pod identity, require client certs on the internal listener
//!    (`tls.require_client_cert` / `NAVRA_TLS_REQUIRE_CLIENT_CERT`),
//!    and derive the sandbox identity from the verified SVID instead
//!    of a header. Needs a route-level change (ui.rs) plus agent
//!    SVID wiring — tracked for the lead.

use std::sync::Arc;

use navra_core::identity::Ed25519Signer;

use crate::agent_spawn::{RootPayloadRefresher, mint_teammate_token};
use crate::team_tools::TeamRegistry;

/// Gateway state for the task-delivery API.
pub(crate) struct AgentTaskApi {
    pub(crate) registry: Arc<TeamRegistry>,
    pub(crate) signer: Arc<Ed25519Signer>,
    /// Shared, self-refreshing root capability template for
    /// delegation chains. The SAME instance is shared with the spawn
    /// paths (setup/tools.rs wires one refresher everywhere), so a
    /// refresh performed at any mint site is observed here too;
    /// `None` falls back to flat token minting.
    pub(crate) root_payload: Option<RootPayloadRefresher>,
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
            // name — verifying the caller's pool DID against the
            // mapping's binding (see the module docs on adoption
            // security). Both an unknown sandbox and a cross-pool
            // attempt map to NotFound: the response must not reveal
            // that the sandbox exists.
            let sandbox = sandbox.ok_or(TaskFetchError::MissingSandboxHeader)?;
            let (team, mate) = self
                .registry
                .adopt_k8s_sandbox(sandbox, did)
                .map_err(|_| TaskFetchError::NotFound)?;

            let (ops, tools, ttl) = self
                .registry
                .teammate_caps(&team, &mate)
                .ok_or(TaskFetchError::NotFound)?;

            let teammate_did = format!("did:teammate:{team}:{mate}");
            // Pull the root template through the shared refresher
            // (NOT a startup snapshot): a template that has gone
            // stale since gateway start is re-minted here, so
            // adoption mints never delegate from a dead root.
            let fresh_root = self.root_payload.as_ref().map(|r| r.get());
            let token = mint_teammate_token(
                fresh_root.as_ref(),
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
    use navra_core::identity::CapSigner as _;

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
        // Bound at claim time — the only adoption path the API
        // honors (unbound legacy mappings are refused).
        reg.set_k8s_sandbox_with_pool(
            &team,
            "worker",
            "navra-agents-abc12".to_string(),
            "did:pool:navra-agents".to_string(),
        );
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
    fn same_pool_readoption_is_idempotent() {
        // The adopted pod polls repeatedly (task: null while
        // waiting) and re-fetches after a restart — every poll from
        // the claiming pool must succeed and mint a fresh token.
        let reg = registry_with_claimed_teammate();
        let api = api_with_registry(reg);
        for _ in 0..3 {
            let spec = api
                .task_for(Some("did:pool:navra-agents"), Some("navra-agents-abc12"))
                .unwrap();
            assert_eq!(spec["task"], "do the thing");
            assert!(spec["token"].as_str().is_some());
        }
    }

    #[test]
    fn cross_pool_adoption_is_rejected() {
        // The sandbox was bound to did:pool:navra-agents at claim
        // time; a holder of a different pool's bootstrap token
        // presenting the same sandbox name gets NotFound (no
        // existence leak).
        let reg = registry_with_claimed_teammate();
        reg.set_k8s_sandbox_with_pool(
            "team-1",
            "worker",
            "navra-agents-abc12".to_string(),
            "did:pool:navra-agents".to_string(),
        );
        let api = api_with_registry(reg);
        assert_eq!(
            api.task_for(Some("did:pool:other-pool"), Some("navra-agents-abc12")),
            Err(TaskFetchError::NotFound)
        );
    }

    #[test]
    fn unbound_sandbox_adoption_is_refused() {
        // Legacy mapping without a recorded pool: adoption is refused
        // for every caller (binding to the first caller would be a
        // race any pool-token holder could win). The response is the
        // same NotFound an unknown sandbox gets — no existence leak.
        let reg = registry_with_claimed_teammate();
        // Re-record the sandbox without a pool binding (legacy path).
        reg.set_k8s_sandbox("team-1", "worker", "navra-agents-abc12".to_string());
        let api = AgentTaskApi {
            registry: reg,
            signer: Arc::new(Ed25519Signer::generate()),
            root_payload: None,
        };
        assert_eq!(
            api.task_for(Some("did:pool:pool-a"), Some("navra-agents-abc12")),
            Err(TaskFetchError::NotFound)
        );
        assert_eq!(
            api.task_for(Some("did:pool:pool-b"), Some("navra-agents-abc12")),
            Err(TaskFetchError::NotFound)
        );
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
    fn adoption_mints_from_stale_root_via_refresher() {
        // Regression (audit F1/F3): the adoption mint used a startup
        // snapshot of the root payload, so an adoption after the root
        // expired delegated from a dead parent. The refresher must
        // re-mint the template before delegating.
        let reg = registry_with_claimed_teammate();
        let signer = Arc::new(Ed25519Signer::generate());
        let cap = navra_core::auth::capability::CapabilitySet {
            paths: vec!["**".to_string()],
            // The teammate being adopted holds `read`: delegation
            // refuses operation escalation, so the root template must
            // grant it (an empty-grant root cannot mint children).
            operations: vec!["read".to_string()],
            tools: vec!["*".to_string()],
            credentials: vec![],
        };
        let mut root =
            navra_core::auth::capability::build_payload(signer.did(), signer.did(), cap, 1, 3600);
        // Age the template: a 1h window with only 10 minutes left is
        // below the refresh threshold (a quarter of the window), so
        // the refresher re-mints at adoption-mint time.
        root.iat = crate::agent_spawn::now_unix().saturating_sub(3000);
        root.exp = crate::agent_spawn::now_unix().saturating_add(600);
        let api = AgentTaskApi {
            registry: reg,
            signer: Arc::clone(&signer),
            root_payload: Some(crate::agent_spawn::RootPayloadRefresher::new(root)),
        };

        let spec = api
            .task_for(Some("did:pool:navra-agents"), Some("navra-agents-abc12"))
            .expect("adoption mints from the refreshed root");
        let token = spec["token"].as_str().expect("fresh token in spec");
        let payload =
            navra_core::auth::capability::decode_token(token, signer.as_ref()).expect("decodes");
        // The child outlives the stale template's 600s remaining
        // window: it was minted from a re-minted root (fresh ~1h).
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        assert!(
            payload.exp > now + 600,
            "child exp {} should outlive the stale root (now + 600 = {})",
            payload.exp,
            now + 600
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
