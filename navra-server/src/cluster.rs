//! Coordinator/worker cluster roles (NAVRA-194).
//!
//! The gateway deployment scales horizontally with a control/data
//! split: exactly one **coordinator** replica owns the TeamRegistry,
//! the flow registries, and teammate spawning (kubectl/SandboxClaim
//! tasks live in its process); **worker** replicas serve MCP and the
//! `/v1` model proxy statelessly by forwarding coordinator-owned
//! state to the coordinator over HTTP, passing the caller's
//! credentials through verbatim.
//!
//! Roles are resolved from config (`[server] cluster_role`) with an
//! `auto` mode for StatefulSet deployments: the pod whose hostname
//! is `{cluster_statefulset}-0` is the coordinator; every other
//! ordinal is a worker pointed at `NAVRA_COORDINATOR_URL`.
//!
//! Teammate delegated tokens verify on any replica: verification is
//! stateless (Ed25519 against the root signer's public key), and all
//! replicas share the root signer via `[server.identity] key_path`
//! backed by the same Secret.

use axum::body::Body;
use axum::http::{HeaderMap, Method, StatusCode, Uri};

/// Build a reqwest client with cluster TLS settings (NAVRA-199):
///
/// - `NAVRA_TLS_CA_FILE` — CA bundle (PEM) to trust in addition to
///   the system roots. Set for workers and agents when the gateway
///   serves HTTPS with an internal CA.
/// - `NAVRA_TLS_CLIENT_PEM` — client certificate + key (PEM) for
///   mutual TLS. Set for worker replicas so the coordinator can
///   authenticate them at the transport layer.
///
/// Plain HTTP is unaffected by either.
pub(crate) fn cluster_http_client() -> reqwest::Client {
    cluster_http_client_with_timeout(std::time::Duration::from_secs(120))
}

fn cluster_http_client_with_timeout(timeout: std::time::Duration) -> reqwest::Client {
    let mut builder = reqwest::Client::builder().timeout(timeout);
    if let Ok(ca_path) = std::env::var("NAVRA_TLS_CA_FILE")
        && !ca_path.is_empty()
        && let Ok(pem) = std::fs::read(&ca_path)
        && let Ok(cert) = reqwest::Certificate::from_pem(&pem)
    {
        builder = builder.add_root_certificate(cert);
    } else if let Ok(ca_path) = std::env::var("NAVRA_TLS_CA_FILE")
        && !ca_path.is_empty()
    {
        tracing::warn!(
            path = ca_path,
            "NAVRA_TLS_CA_FILE unreadable — using system roots only"
        );
    }
    if let Ok(pem_path) = std::env::var("NAVRA_TLS_CLIENT_PEM")
        && !pem_path.is_empty()
        && let Ok(pem) = std::fs::read(&pem_path)
    {
        match reqwest::Identity::from_pem(&pem) {
            Ok(identity) => builder = builder.identity(identity),
            Err(e) => {
                tracing::warn!(path = pem_path, error = %e, "NAVRA_TLS_CLIENT_PEM invalid — connecting without a client certificate")
            }
        }
    }
    builder.build().unwrap_or_default()
}

/// The gateway's role in a multi-replica deployment.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ClusterRole {
    /// Single-instance (default): all state local.
    Standalone,
    /// Owning replica: TeamRegistry, flows, spawning, internal
    /// label queries.
    Coordinator,
    /// Stateless replica: forwards coordinator-owned operations.
    Worker {
        /// Base URL of the coordinator, e.g.
        /// `http://navra-gateway-0.navra-gateway-headless.navra.svc:9315`.
        coordinator_url: String,
    },
}

impl ClusterRole {
    /// The coordinator base URL when this replica forwards to one.
    pub(crate) fn coordinator_url(&self) -> Option<&str> {
        match self {
            ClusterRole::Worker { coordinator_url } => Some(coordinator_url),
            _ => None,
        }
    }

    /// True when this replica should skip coordinator-only startup
    /// work (triggers, warm-pool secret ensure, teammate spawning).
    pub(crate) fn is_worker(&self) -> bool {
        matches!(self, ClusterRole::Worker { .. })
    }
}

/// Resolve the cluster role from config and environment.
///
/// `cluster_role` values: `"standalone"` (default when unset),
/// `"coordinator"`, `"worker"`, `"auto"`. In `auto` mode the pod
/// hostname (`HOSTNAME`, set to the pod name by Kubernetes) is
/// matched against `{cluster_statefulset}-{ordinal}`: ordinal 0 is
/// the coordinator, higher ordinals are workers using
/// `NAVRA_COORDINATOR_URL` (set uniformly on the StatefulSet; the
/// coordinator ignores it).
pub(crate) fn resolve_cluster_role(cfg: &crate::config::Config) -> ClusterRole {
    let role = cfg.server.cluster_role.as_deref().unwrap_or("standalone");
    match role {
        "coordinator" => ClusterRole::Coordinator,
        "worker" => match cfg
            .server
            .coordinator_url
            .clone()
            .or_else(env_coordinator_url)
        {
            Some(url) => ClusterRole::Worker {
                coordinator_url: url,
            },
            None => {
                tracing::warn!(
                    "cluster_role = \"worker\" but no coordinator URL — running standalone"
                );
                ClusterRole::Standalone
            }
        },
        "auto" => {
            let Some(sts) = cfg.server.cluster_statefulset.as_deref() else {
                tracing::warn!(
                    "cluster_role = \"auto\" requires cluster_statefulset — running standalone"
                );
                return ClusterRole::Standalone;
            };
            let hostname = std::env::var("HOSTNAME").unwrap_or_default();
            let suffix = hostname.strip_prefix(sts).and_then(|s| s.strip_prefix('-'));
            match suffix.and_then(|s| s.parse::<u32>().ok()) {
                Some(0) => ClusterRole::Coordinator,
                Some(_) => match cfg
                    .server
                    .coordinator_url
                    .clone()
                    .or_else(env_coordinator_url)
                {
                    Some(url) => ClusterRole::Worker {
                        coordinator_url: url,
                    },
                    None => {
                        tracing::warn!(
                            hostname = %hostname,
                            "auto role resolved a worker ordinal but NAVRA_COORDINATOR_URL is unset — running standalone"
                        );
                        ClusterRole::Standalone
                    }
                },
                // Not a StatefulSet pod (or bare hostname): standalone.
                None => ClusterRole::Standalone,
            }
        }
        "standalone" | "" => ClusterRole::Standalone,
        other => {
            tracing::warn!(role = other, "unknown cluster_role — running standalone");
            ClusterRole::Standalone
        }
    }
}

fn env_coordinator_url() -> Option<String> {
    std::env::var("NAVRA_COORDINATOR_URL")
        .ok()
        .filter(|u| !u.is_empty())
}

/// Should a `tools/call` for `tool` be forwarded to the coordinator?
///
/// Coordinator-owned tools are everything backed by the TeamRegistry
/// or the flow registries: team orchestration (which spawns
/// teammates via per-process tokio tasks and kubectl handles),
/// signals (per-process cooperative interrupt handles), and flows
/// (which drive teams). All other tools (file, memory, models,
/// audit) are either stateless or per-replica by design.
pub(crate) fn is_coordinator_owned_tool(tool: &str) -> bool {
    tool.starts_with("team_") || tool.starts_with("flow_") || tool == "agent_signal"
}

/// Forwarding middleware for worker replicas.
///
/// Intercepts, and proxies verbatim (same method, path, headers,
/// and body) to the coordinator:
///
/// - `POST /mcp` requests whose JSON-RPC method is `tools/call` on
///   a coordinator-owned tool. All other MCP traffic (initialize,
///   tools/list, non-team tool calls) is served locally — the
///   worker's tool catalog and stateless tools are identical.
/// - `/api/agent/task` and `/api/agent/result` — the TeamRegistry
///   (task specs, adoption, result collection) lives on the
///   coordinator.
///
/// Verbatim proxying preserves the caller's Authorization header,
/// so the coordinator sees the original identity and applies its
/// full auth → ACL → IFC → safety pipeline.
pub(crate) async fn coordinator_forwarding_middleware(
    coordinator_url: String,
    req: axum::extract::Request,
    next: axum::middleware::Next,
) -> axum::response::Response {
    let method = req.method().clone();
    let uri = req.uri().clone();
    let headers = req.headers().clone();
    let path = uri.path().to_string();

    // /api/agent/* always reaches for the coordinator's registry —
    // forward the whole request without inspection.
    if (path == "/api/agent/task" || path == "/api/agent/result")
        && matches!(method, Method::GET | Method::POST)
    {
        let bytes = match body_bytes(req).await {
            Ok(b) => b,
            Err(e) => {
                return error_response(StatusCode::BAD_REQUEST, &format!("invalid body: {e}"));
            }
        };
        return forward_buffered(&coordinator_url, method, &uri, &headers, bytes).await;
    }

    // /mcp POST: forward only tools/call on coordinator-owned tools.
    if path == "/mcp" && method == Method::POST {
        let bytes = match body_bytes(req).await {
            Ok(b) => b,
            Err(e) => {
                return error_response(StatusCode::BAD_REQUEST, &format!("invalid body: {e}"));
            }
        };
        let is_coordinator_call = serde_json::from_slice::<serde_json::Value>(&bytes)
            .ok()
            .and_then(|json| {
                let tool = json["params"]["name"].as_str()?;
                (json["method"].as_str()? == "tools/call" && is_coordinator_owned_tool(tool))
                    .then_some(())
            })
            .is_some();
        if is_coordinator_call {
            return forward_buffered(&coordinator_url, method, &uri, &headers, bytes).await;
        }
        // Serve locally: rebuild the request with the buffered body.
        let mut req = axum::extract::Request::builder().method(method).uri(uri);
        for (name, value) in headers.iter() {
            req = req.header(name.as_str(), value);
        }
        let req = req
            .body(Body::from(bytes))
            .unwrap_or_else(|e| panic!("request rebuild failed: {e}"));
        return next.run(req).await;
    }

    next.run(req).await
}

/// Buffer a request body into bytes.
async fn body_bytes(req: axum::extract::Request) -> Result<axum::body::Bytes, axum::Error> {
    axum::body::to_bytes(req.into_body(), 16 * 1024 * 1024).await
}

/// Forward a fully-buffered request. Same method, path, query,
/// headers, and body as the original — the coordinator applies its
/// own complete pipeline to the caller's original credentials.
pub(crate) async fn forward_buffered(
    coordinator_url: &str,
    method: Method,
    uri: &Uri,
    headers: &HeaderMap,
    body: axum::body::Bytes,
) -> axum::response::Response {
    let target = format!(
        "{coordinator_url}{}",
        uri.path_and_query().map(|pq| pq.as_str()).unwrap_or("")
    );
    let client = cluster_http_client();
    let mut req = client.request(
        reqwest::Method::from_bytes(method.as_str().as_bytes()).unwrap(),
        &target,
    );
    for (name, value) in headers.iter() {
        // Hop-by-hop headers must not be forwarded.
        if name.as_str().eq_ignore_ascii_case("host")
            || name.as_str().eq_ignore_ascii_case("content-length")
        {
            continue;
        }
        if let Ok(v) = value.to_str() {
            req = req.header(name.as_str(), v);
        }
    }
    let resp = match req.body(body).send().await {
        Ok(r) => r,
        Err(e) => {
            tracing::error!(coordinator = coordinator_url, error = %e, "coordinator unreachable");
            return error_response(
                StatusCode::BAD_GATEWAY,
                &format!("coordinator unreachable: {e}"),
            );
        }
    };

    let status = StatusCode::from_u16(resp.status().as_u16()).unwrap_or(StatusCode::BAD_GATEWAY);
    let content_type = resp
        .headers()
        .get(reqwest::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .map(String::from);
    let bytes = resp.bytes().await.unwrap_or_default();
    let mut response = axum::response::Response::new(Body::from(bytes));
    *response.status_mut() = status;
    if let Some(ct) = content_type
        && let Ok(v) = axum::http::HeaderValue::from_str(&ct)
    {
        response
            .headers_mut()
            .insert(axum::http::header::CONTENT_TYPE, v);
    }
    response
}

fn error_response(status: StatusCode, msg: &str) -> axum::response::Response {
    (status, axum::Json(serde_json::json!({"error": msg}))).into_response()
}

use axum::response::IntoResponse;

/// Fetch the IFC context label for an agent from the coordinator
/// (worker-side `/v1` proxy). Passes the caller's Authorization
/// header through so the coordinator authorizes the query. Returns
/// `None` on any failure — callers fall back to the local (partial)
/// view.
pub(crate) async fn remote_agent_label(
    coordinator_url: &str,
    headers: &HeaderMap,
    agent_name: &str,
) -> Option<navra_core::protocol::label::DataLabel> {
    let url = format!(
        "{coordinator_url}/api/internal/agent-label?agent={}",
        urlencoding_encode(agent_name)
    );
    let client = cluster_http_client_with_timeout(std::time::Duration::from_secs(5));
    let mut req = client.get(&url);
    if let Some(auth) = headers.get("authorization").and_then(|v| v.to_str().ok()) {
        req = req.header("authorization", auth);
    }
    let resp = req.send().await.ok()?;
    if !resp.status().is_success() {
        tracing::warn!(
            coordinator = coordinator_url,
            status = resp.status().as_u16(),
            "agent-label query failed on coordinator; falling back to local sessions"
        );
        return None;
    }
    resp.json().await.ok()
}

/// Minimal percent-encoding for a query value (agent names are
/// DIDs or simple strings; encode conservatively).
fn urlencoding_encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char)
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg(role: Option<&str>, sts: Option<&str>, coord: Option<&str>) -> crate::config::Config {
        let mut c = crate::config::Config::default();
        c.server.cluster_role = role.map(String::from);
        c.server.cluster_statefulset = sts.map(String::from);
        c.server.coordinator_url = coord.map(String::from);
        c
    }

    #[test]
    fn default_is_standalone() {
        assert_eq!(
            resolve_cluster_role(&cfg(None, None, None)),
            ClusterRole::Standalone
        );
    }

    #[test]
    fn explicit_coordinator() {
        assert_eq!(
            resolve_cluster_role(&cfg(Some("coordinator"), None, None)),
            ClusterRole::Coordinator
        );
    }

    #[test]
    fn explicit_worker() {
        assert_eq!(
            resolve_cluster_role(&cfg(Some("worker"), None, Some("http://c:9315"))),
            ClusterRole::Worker {
                coordinator_url: "http://c:9315".to_string()
            }
        );
    }

    #[test]
    fn worker_without_url_falls_back() {
        unsafe { std::env::remove_var("NAVRA_COORDINATOR_URL") };
        assert_eq!(
            resolve_cluster_role(&cfg(Some("worker"), None, None)),
            ClusterRole::Standalone
        );
    }

    #[test]
    fn auto_role_resolution_by_ordinal() {
        // Env mutation is not thread-safe across parallel tests —
        // cover all auto cases sequentially here.
        unsafe {
            std::env::set_var("HOSTNAME", "navra-gateway-0");
        }
        assert_eq!(
            resolve_cluster_role(&cfg(Some("auto"), Some("navra-gateway"), None)),
            ClusterRole::Coordinator
        );

        unsafe {
            std::env::set_var("HOSTNAME", "navra-gateway-2");
            std::env::set_var(
                "NAVRA_COORDINATOR_URL",
                "http://navra-gateway-0.ns.svc:9315",
            );
        }
        assert_eq!(
            resolve_cluster_role(&cfg(Some("auto"), Some("navra-gateway"), None)),
            ClusterRole::Worker {
                coordinator_url: "http://navra-gateway-0.ns.svc:9315".to_string()
            }
        );
        unsafe {
            std::env::remove_var("NAVRA_COORDINATOR_URL");
        }

        // Worker ordinal without a coordinator URL falls back.
        assert_eq!(
            resolve_cluster_role(&cfg(Some("auto"), Some("navra-gateway"), None)),
            ClusterRole::Standalone
        );

        // Not a StatefulSet pod: standalone.
        unsafe {
            std::env::set_var("HOSTNAME", "my-laptop");
        }
        assert_eq!(
            resolve_cluster_role(&cfg(Some("auto"), Some("navra-gateway"), None)),
            ClusterRole::Standalone
        );

        // auto without cluster_statefulset: standalone.
        unsafe {
            std::env::set_var("HOSTNAME", "navra-gateway-0");
        }
        assert_eq!(
            resolve_cluster_role(&cfg(Some("auto"), None, None)),
            ClusterRole::Standalone
        );
    }

    #[test]
    fn coordinator_owned_tools() {
        for tool in ["team_create", "team_bb_read", "flow_status", "agent_signal"] {
            assert!(is_coordinator_owned_tool(tool), "{tool}");
        }
        for tool in ["file_read", "memory_store", "models_list", "doc_write"] {
            assert!(!is_coordinator_owned_tool(tool), "{tool}");
        }
    }

    #[test]
    fn urlencoding() {
        assert_eq!(
            urlencoding_encode("did:teammate:t1:m1"),
            "did%3Ateammate%3At1%3Am1"
        );
        assert_eq!(urlencoding_encode("plain"), "plain");
    }

    // --- Forwarding middleware ---

    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use http_body_util::BodyExt;
    use tower::util::ServiceExt;

    /// Mock coordinator: /mcp echoes the called tool and the
    /// Authorization header it saw; /api/agent/task echoes a marker.
    async fn spawn_mock_coordinator() -> String {
        let app = axum::Router::new()
            .route(
                "/mcp",
                axum::routing::post(|headers: axum::http::HeaderMap, body: String| async move {
                    let json: serde_json::Value = serde_json::from_str(&body).unwrap();
                    axum::Json(serde_json::json!({
                        "forwarded_tool": json["params"]["name"],
                        "saw_auth": headers.get("authorization").and_then(|v| v.to_str().ok()),
                    }))
                }),
            )
            .route(
                "/api/agent/task",
                axum::routing::get(|| async {
                    axum::Json(serde_json::json!({"task": "from-coordinator"}))
                }),
            );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });
        format!("http://{addr}")
    }

    /// Worker-style router: a local /mcp that answers with a marker,
    /// wrapped in the coordinator forwarding layer.
    fn worker_router(coordinator_url: String) -> axum::Router {
        let local = axum::Router::new()
            .route(
                "/mcp",
                axum::routing::post(|| async {
                    axum::Json(serde_json::json!({"served": "locally"}))
                }),
            )
            .route(
                "/api/agent/task",
                axum::routing::get(|| async { axum::Json(serde_json::json!({"task": "local"})) }),
            );
        local.layer(axum::middleware::from_fn(move |req, next| {
            let url = coordinator_url.clone();
            async move { coordinator_forwarding_middleware(url, req, next).await }
        }))
    }

    async fn body_json(resp: axum::response::Response) -> serde_json::Value {
        let bytes = resp.into_body().collect().await.unwrap().to_bytes();
        serde_json::from_slice(&bytes).unwrap_or(serde_json::json!({
            "raw": String::from_utf8_lossy(&bytes).to_string()
        }))
    }

    fn mcp_call(tool: &str) -> Request<Body> {
        Request::builder()
            .method("POST")
            .uri("/mcp")
            .header("content-type", "application/json")
            .header("authorization", "Bearer caller-token")
            .body(Body::from(
                serde_json::json!({
                    "jsonrpc": "2.0",
                    "method": "tools/call",
                    "params": {"name": tool, "arguments": {"team_id": "t1"}},
                    "id": 1
                })
                .to_string(),
            ))
            .unwrap()
    }

    #[tokio::test]
    async fn forwards_coordinator_owned_tool_calls_with_caller_credentials() {
        let coord = spawn_mock_coordinator().await;
        let router = worker_router(coord);

        let resp = router
            .clone()
            .oneshot(mcp_call("team_status"))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let json = body_json(resp).await;
        assert_eq!(json["forwarded_tool"], "team_status");
        assert_eq!(json["saw_auth"], "Bearer caller-token");
    }

    #[tokio::test]
    async fn serves_non_team_tool_calls_locally() {
        let coord = spawn_mock_coordinator().await;
        let router = worker_router(coord);

        let resp = router.clone().oneshot(mcp_call("file_read")).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let json = body_json(resp).await;
        assert_eq!(json["served"], "locally");
    }

    #[tokio::test]
    async fn forwards_agent_task_api() {
        let coord = spawn_mock_coordinator().await;
        let router = worker_router(coord);

        let req = Request::builder()
            .method("GET")
            .uri("/api/agent/task")
            .header("authorization", "Bearer caller-token")
            .body(Body::empty())
            .unwrap();
        let resp = router.clone().oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let json = body_json(resp).await;
        assert_eq!(json["task"], "from-coordinator");
    }

    #[tokio::test]
    async fn non_tools_call_mcp_served_locally() {
        let coord = spawn_mock_coordinator().await;
        let router = worker_router(coord);

        let req = Request::builder()
            .method("POST")
            .uri("/mcp")
            .header("content-type", "application/json")
            .body(Body::from(
                serde_json::json!({"jsonrpc": "2.0", "method": "tools/list", "id": 1}).to_string(),
            ))
            .unwrap();
        let resp = router.clone().oneshot(req).await.unwrap();
        let json = body_json(resp).await;
        assert_eq!(json["served"], "locally");
    }

    #[tokio::test]
    async fn unreachable_coordinator_is_bad_gateway() {
        let router = worker_router("http://127.0.0.1:1".to_string());
        let resp = router
            .clone()
            .oneshot(mcp_call("team_status"))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_GATEWAY);
    }
}
