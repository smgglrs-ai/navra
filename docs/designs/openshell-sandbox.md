# OpenShell Sandbox Integration Design

Implementation-ready design for smgglrs integration with the
OpenShell secure sandbox platform. Covers ROADMAP.md Phase 6
(6a through 6e).

**Status**: Implementation complete (2026-04-25). Containerized
agent execution is operational (2026-05-03) using Podman directly
(shared model server + per-agent sandboxes, `Dockerfile.agent`,
`smgglrs-agent` binary). OpenShell integration remains the target
for production sandbox deployments with full MAC + DAC defense in
depth.

---

## 1. Architecture Overview

### The Sealed Sandbox Unit

An OpenShell sandbox is a self-contained execution environment
where an agent runs with everything it needs: an smgglrs gateway
instance, upstream MCP servers, a local model endpoint, and a
network firewall that blocks everything else.

```
                   Human Operator
                        |
                        | Create sandbox (labels, config)
                        v
  +----------------------------------------------+
  |           OpenShell Supervisor                |
  |  - Compute driver (Podman/libkrun/K8s)        |
  |  - Network namespace + HTTP CONNECT proxy     |
  |  - OPA policy engine (network allowlist)       |
  |  - Landlock + seccomp (OS-level isolation)     |
  |  - Credential delivery channel                |
  |  - Identity token issuer                      |
  +----------------------------------------------+
         |            |             |
         | gRPC       | Identity    | Credentials
         v            v             v
  +----------------------------------------------+
  |           Sandbox Boundary                    |
  |                                               |
  |  +------------------------------------------+ |
  |  |            smgglrs (gateway)             | |
  |  |                                          | |
  |  |  Auth: OpenShellAuthenticator            | |
  |  |  ACLs: deny-wins path + tool rules       | |
  |  |  IFC:  Bell-LaPadula taint propagation   | |
  |  |  Safety: regex + ML content filters      | |
  |  |  Hooks: pre/post tool-call pipeline      | |
  |  |                                          | |
  |  |  Modules:                                | |
  |  |    +-- Built-in (docs, git, rag)         | |
  |  |    +-- Upstream MCP servers (proxied)    | |
  |  |    +-- gRPC modules (out-of-process)     | |
  |  +------------------------------------------+ |
  |       |              |              |          |
  |       | MCP          | A2A          | gRPC     |
  |       v              v              v          |
  |  +---------+  +------------+  +-----------+   |
  |  | Agent   |  | Teammate   |  | Model     |   |
  |  | process |  | sandbox    |  | endpoint  |   |
  |  | (MCP    |  | (via       |  | (llama-   |   |
  |  |  client)|  |  gateway)  |  |  server)  |   |
  |  +---------+  +------------+  +-----------+   |
  |                                               |
  |  Network firewall (proxy-enforced):           |
  |    ALLOW: smgglrs gateway, model endpoint,    |
  |           OpenShell gateway                   |
  |    DENY:  everything else                     |
  +----------------------------------------------+
```

### Microkernel Analogy

The three-layer architecture maps to an operating system:

| OS Layer | Component | Role |
|----------|-----------|------|
| Hardware | OpenShell | Process isolation, memory protection, I/O control |
| Kernel | smgglrs | Syscall interface, capability tokens, IFC, access control |
| Userland | MCP servers, agents | Applications that request kernel services |

OpenShell provides mandatory access control (MAC) at the OS layer.
smgglrs provides discretionary access control (DAC) at the
application layer. Neither is sufficient alone. Together they
implement defense in depth where compromising one layer does not
grant full access.

---

## 2. Identity Federation (Phase 6a)

### Problem

smgglrs currently authenticates agents via `ChainAuthenticator`
with two backends: `CapabilityAuthenticator` (CBOR+Ed25519 tokens)
and `TokenAuthenticator` (BLAKE3 bearer tokens). Both require
smgglrs to manage credentials independently.

Inside an OpenShell sandbox, the supervisor has already established
the agent's identity through the gateway's identity subsystem.
Re-authenticating at the smgglrs layer is redundant.

### OpenShellAuthenticator

A new `Authenticator` implementation that trusts identity tokens
issued by the OpenShell supervisor.

**Chain position:**

```
ChainAuthenticator
  1. CapabilityAuthenticator    (smgglrs-native cap tokens)
  2. OpenShellAuthenticator     (OpenShell identity)  <-- NEW
  3. TokenAuthenticator         (legacy BLAKE3)
  4. NoAuthenticator            (dev-only fallback)
```

The ordering matters: smgglrs-native capability tokens take
priority (they carry inline capabilities). OpenShell tokens are
tried next. Legacy BLAKE3 tokens are the fallback. This ensures
existing deployments work unchanged.

### Supported Token Formats

The OpenShell identity subsystem supports multiple backends.
`OpenShellAuthenticator` handles all of them through a unified
verification path:

```
+------------------+------------------+----------------------------+
| Backend          | Token Format     | Verification               |
+------------------+------------------+----------------------------+
| SPIFFE/SPIRE     | JWT-SVID         | JWKS from SPIRE agent      |
| OIDC/OAuth2      | JWT bearer       | JWKS from IdP endpoint     |
| Local OS         | SO_PEERCRED      | UID/GID from Unix socket   |
| Static RBAC      | OpenShell-signed | Ed25519 verify with        |
|                  | JWT              | gateway signing key        |
+------------------+------------------+----------------------------+
```

All JWT-based paths share the same verification logic (decode +
signature check + expiry + claims extraction). The OS path uses
`SO_PEERCRED` on Unix sockets and is handled separately.

### Identity Mapping

The authenticator extracts claims from the verified token and
maps them to smgglrs's `AgentIdentity`:

```
OpenShell Token Claim              smgglrs AgentIdentity Field
---------------------------------------------------------------
sub (SPIFFE URI or agent name)  -> name
sandbox labels "role=X"         -> permissions (via config map)
sandbox ring/role               -> capabilities.ring
gateway-scoped operations       -> capabilities.operations
```

### Data Types

**File**: `smgglrs-security/src/auth/openshell.rs`

```rust
/// Configuration for OpenShell identity verification.
pub struct OpenShellAuthConfig {
    /// Verification mode.
    pub mode: OpenShellAuthMode,
    /// Maps OpenShell label expressions to smgglrs permission set names.
    /// Example: "role=worker" -> "restricted"
    pub label_mapping: HashMap<String, String>,
    /// Default permission set when no label matches.
    pub default_permissions: String,
}

pub enum OpenShellAuthMode {
    /// Verify JWT-SVID against SPIRE trust bundle.
    Spiffe {
        /// Path to SPIRE agent trust bundle PEM.
        trust_bundle_path: PathBuf,
    },
    /// Verify JWT against OIDC provider JWKS endpoint.
    Oidc {
        /// OIDC issuer URL (JWKS fetched from .well-known/openid-configuration).
        issuer: String,
        /// Expected audience claim.
        audience: Option<String>,
    },
    /// Trust Unix socket peer credentials.
    Local,
    /// Verify JWT signed by OpenShell gateway's Ed25519 key.
    Static {
        /// Path to the gateway's public key PEM.
        public_key_path: PathBuf,
    },
}

/// Authenticator that accepts OpenShell-provided identity tokens.
pub struct OpenShellAuthenticator {
    config: OpenShellAuthConfig,
    /// Cached JWKS keys (refreshed on verification failure).
    jwks_cache: RwLock<Option<JwksCache>>,
}

struct JwksCache {
    keys: jsonwebtoken::jwk::JwkSet,
    fetched_at: Instant,
}
```

### Authenticator Implementation

```rust
impl Authenticator for OpenShellAuthenticator {
    fn authenticate(
        &self,
        headers: &HeaderMap,
    ) -> Result<AgentIdentity, AuthError> {
        let token = extract_bearer_token(headers)?;

        // Skip tokens that belong to other authenticators
        if token.starts_with("smgglrs_cap_v1.") {
            return Err(AuthError::InvalidToken);
        }

        let claims = match &self.config.mode {
            OpenShellAuthMode::Spiffe { trust_bundle_path } => {
                self.verify_spiffe_jwt(token, trust_bundle_path)?
            }
            OpenShellAuthMode::Oidc { issuer, audience } => {
                self.verify_oidc_jwt(token, issuer, audience.as_deref())?
            }
            OpenShellAuthMode::Static { public_key_path } => {
                self.verify_static_jwt(token, public_key_path)?
            }
            OpenShellAuthMode::Local => {
                // Local mode extracts identity from SO_PEERCRED,
                // not from Authorization header. Return InvalidToken
                // to let the chain continue.
                return Err(AuthError::InvalidToken);
            }
        };

        let permissions = self.resolve_permissions(&claims);

        Ok(AgentIdentity {
            name: claims.sub,
            permissions,
            signing_key: None,
            did: claims.spiffe_id.map(|s| format!("spiffe://{s}")),
            capabilities: None, // OpenShell tokens use permission sets, not inline caps
        })
    }
}
```

### Permission Resolution

The authenticator maps OpenShell sandbox labels to smgglrs
permission set names using the configured label mapping:

```rust
fn resolve_permissions(&self, claims: &OpenShellClaims) -> String {
    // Check each label mapping in config
    for (label_expr, perm_set) in &self.config.label_mapping {
        if claims.labels_match(label_expr) {
            return perm_set.clone();
        }
    }
    self.config.default_permissions.clone()
}
```

### Configuration

```toml
[auth.openshell]
enabled = true
mode = "spiffe"
trust_bundle = "/run/spire/agent/bundle.pem"
default_permissions = "restricted"

[auth.openshell.mapping]
"role=worker"  = "restricted"
"role=lead"    = "developer"
"role=admin"   = "admin"
```

### Credential Delegation

Extend `MappedCredentialStore` with an `openshell` backend that
reads credentials from the supervisor's delivery channel:

**File**: `smgglrs-security/src/credentials.rs` (extend existing)

```rust
pub enum CredentialSource {
    /// Existing: read from local keyring
    Keyring { service: String, key: String },
    /// Existing: read from environment variable
    Env { var: String },
    /// NEW: read from OpenShell supervisor credential channel
    OpenShell { label: String },
}
```

The OpenShell source reads from a Unix socket or gRPC endpoint
provided by the supervisor. Credentials are fetched on demand
and cached for the session lifetime.

### Dependencies

- `jsonwebtoken` (JWT decode + verify, already widely used)
- `reqwest` (JWKS endpoint fetch, already in workspace)
- No new crate required

### Implementation Steps

1. Create `smgglrs-security/src/auth/openshell.rs`
2. Add `OpenShellAuthConfig` to `smgglrs-server/src/config/`
3. Wire into `ChainAuthenticator` in `main.rs` (between cap and legacy)
4. Add `OpenShell` variant to `CredentialSource`
5. Unit tests with mock JWT tokens
6. Integration test with mock SPIRE agent

---

## 3. A2A Teammate Mesh (Phase 6b)

### Problem

smgglrs-flow uses three in-process communication primitives:
mailbox (tokio mpsc), blackboard (Arc<RwLock<HashMap>>), and
mesh tools (virtual tools). These cannot span sandbox boundaries.

### A2A Client

**File**: `smgglrs-protocol/src/a2a_client.rs`

```rust
/// Client for outbound A2A (Agent-to-Agent) protocol calls.
pub struct A2aClient {
    /// A2A endpoint URL (e.g., "http://gateway:9315/a2a/teammates/analyst")
    endpoint: String,
    /// Bearer token for authentication
    auth_token: String,
    /// HTTP client with connection pooling
    http: reqwest::Client,
    /// Request timeout
    timeout: Duration,
}

impl A2aClient {
    pub fn new(endpoint: &str, auth_token: &str) -> Self;

    /// Send a message to the remote agent and receive a task.
    pub async fn send_message(&self, msg: Message) -> Result<Task, A2aError>;

    /// Send a message and stream back events (SSE).
    pub async fn stream_message(
        &self,
        msg: Message,
    ) -> Result<impl Stream<Item = Result<StreamingEvent, A2aError>>, A2aError>;

    /// Query the status of a previously sent task.
    pub async fn get_task(&self, task_id: &str) -> Result<Task, A2aError>;

    /// Cancel a running task.
    pub async fn cancel_task(&self, task_id: &str) -> Result<Task, A2aError>;

    /// Fetch the remote agent's Agent Card.
    pub async fn discover(&self) -> Result<AgentCard, A2aError>;
}

#[derive(Debug, thiserror::Error)]
pub enum A2aError {
    #[error("network error: {0}")]
    Network(#[from] reqwest::Error),
    #[error("A2A protocol error: code={code}, message={message}")]
    Protocol { code: i32, message: String },
    #[error("timeout after {0:?}")]
    Timeout(Duration),
    #[error("IFC violation: {0}")]
    IfcViolation(String),
}
```

### In-Process vs A2A Mode

The mesh tool handlers detect teammate location and route
accordingly. This is transparent to the agent.

```
mesh_post("analyst", data)
    |
    +-- Is "analyst" local (in-process)?
    |     YES: tokio mpsc send (existing mailbox)
    |     NO:  A2aClient::send_message() to remote endpoint
    |
    +-- IFC check applied in both paths
```

**File**: `smgglrs-flow/src/mesh.rs` (extend existing)

```rust
pub enum TeammateLocation {
    /// Same process, communicate via tokio channels
    InProcess {
        mailbox: mpsc::Sender<MailboxMessage>,
    },
    /// Remote sandbox, communicate via A2A protocol
    Remote {
        client: A2aClient,
        agent_card: AgentCard,
    },
}

pub struct MeshRouter {
    teammates: HashMap<String, TeammateLocation>,
    ifc_engine: Arc<IfcEngine>,
}

impl MeshRouter {
    /// Route a message to a teammate, enforcing IFC.
    pub async fn send(
        &self,
        from: &str,
        to: &str,
        msg: MailboxMessage,
    ) -> Result<(), MeshError> {
        // Bell-LaPadula: sender's clearance must dominate
        // receiver's label for write-down prevention
        self.ifc_engine.check_write(
            &msg.data_label,
            &self.get_clearance(to)?,
        )?;

        match self.teammates.get(to) {
            Some(TeammateLocation::InProcess { mailbox }) => {
                mailbox.send(msg).await?;
            }
            Some(TeammateLocation::Remote { client, .. }) => {
                let a2a_msg = msg.into_a2a_message();
                client.send_message(a2a_msg).await?;
            }
            None => return Err(MeshError::TeammateNotFound(to.to_string())),
        }
        Ok(())
    }
}
```

### Agent Card Registration

smgglrs maintains a local directory of teammate Agent Cards.
Teammates discover each other through smgglrs, not through
external registries.

**File**: `smgglrs-core/src/transport/a2a.rs` (extend existing)

```rust
/// Local directory of teammate Agent Cards.
pub struct AgentCardDirectory {
    cards: RwLock<HashMap<String, AgentCard>>,
}

impl AgentCardDirectory {
    /// Register a teammate's Agent Card.
    pub fn register(&self, name: &str, card: AgentCard);

    /// Look up a teammate's Agent Card.
    pub fn get(&self, name: &str) -> Option<AgentCard>;

    /// List all registered teammates.
    pub fn list(&self) -> Vec<(String, AgentCard)>;

    /// Remove a teammate's Agent Card.
    pub fn remove(&self, name: &str);
}
```

### Scoped Capability Tokens Per Teammate

When the flow engine creates a teammate, it mints a scoped
capability token that limits what the teammate can do. This uses
the existing delegation mechanism in `smgglrs-security/src/auth/capability.rs`.

```rust
// In the flow engine, when spawning a remote teammate:
let teammate_token = capability::encode_token(
    &capability::build_payload(
        flow_signer.did(),          // issuer: the flow engine
        &teammate_did,               // subject: the teammate
        CapabilitySet {
            paths: teammate_config.allowed_paths.clone(),
            operations: teammate_config.operations.clone(),
            tools: teammate_config.tools.clone(),
            credentials: vec![],
        },
        2,                           // ring 2 (less privileged than lead)
        flow_ttl_secs,               // scoped to flow lifetime
    ),
    flow_signer.as_ref(),
)?;
```

### IFC Enforcement on A2A Messages

A2A messages carry IFC taint labels in a custom header or in the
message metadata:

```
POST /a2a/teammates/analyst HTTP/1.1
Authorization: Bearer <teammate_cap_token>
X-Smgglrs-DataLabel: untrusted:sensitive
Content-Type: application/json

{ "jsonrpc": "2.0", "method": "message/send", ... }
```

The A2A transport handler in smgglrs extracts the label, applies
Bell-LaPadula checks, and propagates taint to the receiving
session's `TaintTracker`.

### Implementation Steps

1. Create `smgglrs-protocol/src/a2a_client.rs` with `A2aClient`
2. Add `TeammateLocation` and `MeshRouter` to `smgglrs-flow`
3. Extend mesh tool handlers to route via `MeshRouter`
4. Add `AgentCardDirectory` to `smgglrs-core`
5. Add `X-Smgglrs-DataLabel` header handling to A2A transport
6. Unit tests with mock A2A server
7. Integration test: two in-process agents communicating via A2A

---

## 4. Sandbox Delegation (Phase 6c)

### Current State

`smgglrs-model-runtime` has three `RuntimeBackend` variants:

| Backend | Status | Code |
|---------|--------|------|
| Direct | Implemented | `direct.rs` - spawns llama-server |
| Podman | Implemented | `podman.rs` - rootless container |
| Libkrun | **Aspirational** | Enum variant exists, zero code |

The `auto_runtime()` function tries Podman then Direct. It never
checks for libkrun.

### Changes

1. **Remove the `Libkrun` variant** from `RuntimeBackend` enum
2. **Add `OpenShell` variant** to `RuntimeBackend`
3. **Add `openshell` feature flag** (replaces `libkrun`)
4. **Implement `OpenShellRuntime`** that delegates to OpenShell's
   compute driver via gRPC

### OpenShell Runtime Backend

**File**: `smgglrs-model-runtime/src/openshell.rs`

```rust
/// Model runtime that delegates sandbox creation to OpenShell.
///
/// smgglrs requests a sandbox with labels (gpu requirements,
/// isolation level). OpenShell's compute driver handles
/// provisioning (Podman, libkrun, K8s, etc.).
pub struct OpenShellRuntime {
    /// gRPC endpoint of the OpenShell gateway.
    gateway: String,
    /// gRPC client (tonic).
    client: OpenShellComputeClient<Channel>,
}

impl OpenShellRuntime {
    pub async fn new(gateway: &str) -> Result<Self, RuntimeError> {
        let channel = Channel::from_shared(gateway.to_string())
            .map_err(|e| RuntimeError::Connection(e.to_string()))?
            .connect()
            .await
            .map_err(|e| RuntimeError::Connection(e.to_string()))?;

        Ok(Self {
            gateway: gateway.to_string(),
            client: OpenShellComputeClient::new(channel),
        })
    }

    pub async fn is_available(gateway: &str) -> bool {
        Channel::from_shared(gateway.to_string())
            .ok()
            .map(|c| c.connect())
            .is_some()
    }
}
```

### gRPC Interface to OpenShell Compute Driver

smgglrs uses a minimal subset of the OpenShell compute driver
gRPC API. The proto definitions are vendored (not generated from
an OpenShell dependency) to avoid version coupling.

**File**: `smgglrs-model-runtime/proto/openshell_compute.proto`

```protobuf
syntax = "proto3";
package openshell.compute.v1;

service ComputeDriver {
    rpc CreateSandbox(CreateSandboxRequest)
        returns (CreateSandboxResponse);
    rpc DestroySandbox(DestroySandboxRequest)
        returns (DestroySandboxResponse);
    rpc SandboxStatus(SandboxStatusRequest)
        returns (SandboxStatusResponse);
}

message CreateSandboxRequest {
    // Labels drive provisioning decisions
    map<string, string> labels = 1;
    // Supervisor config (entrypoint, env vars, mounts)
    SupervisorConfig supervisor = 2;
}

message SupervisorConfig {
    string entrypoint = 1;
    repeated string args = 2;
    map<string, string> env = 3;
    repeated Mount mounts = 4;
}

message Mount {
    string source = 1;
    string target = 2;
    bool read_only = 3;
}

message CreateSandboxResponse {
    string sandbox_id = 1;
    // Endpoint where the model server is reachable
    string endpoint_url = 2;
    SandboxState state = 3;
}

message DestroySandboxRequest {
    string sandbox_id = 1;
}

message DestroySandboxResponse {}

message SandboxStatusRequest {
    string sandbox_id = 1;
}

message SandboxStatusResponse {
    string sandbox_id = 1;
    SandboxState state = 2;
    string endpoint_url = 3;
}

enum SandboxState {
    SANDBOX_STATE_UNSPECIFIED = 0;
    SANDBOX_STATE_CREATING = 1;
    SANDBOX_STATE_RUNNING = 2;
    SANDBOX_STATE_STOPPED = 3;
    SANDBOX_STATE_FAILED = 4;
}
```

### ModelRuntime Implementation

```rust
impl ModelRuntime for OpenShellRuntime {
    fn serve(
        &self,
        config: &ServeConfig,
    ) -> Pin<Box<dyn Future<Output = Result<Endpoint, RuntimeError>> + Send + '_>> {
        Box::pin(async move {
            let mut labels = HashMap::new();
            if !config.gpus.is_empty() {
                labels.insert("gpu".to_string(), "required".to_string());
                labels.insert(
                    "gpu_count".to_string(),
                    config.gpus.len().to_string(),
                );
            }
            labels.insert("isolation".to_string(), "microvm".to_string());

            let resp = self.client.clone()
                .create_sandbox(CreateSandboxRequest {
                    labels,
                    supervisor: Some(SupervisorConfig {
                        entrypoint: "llama-server".to_string(),
                        args: vec![
                            "-m".to_string(),
                            config.model_path.to_string_lossy().to_string(),
                            "--host".to_string(), "0.0.0.0".to_string(),
                            "--port".to_string(), "8080".to_string(),
                            "-c".to_string(), config.context_size.to_string(),
                            "-np".to_string(), config.parallel.to_string(),
                        ],
                        env: HashMap::new(),
                        mounts: vec![Mount {
                            source: config.model_path.to_string_lossy().to_string(),
                            target: config.model_path.to_string_lossy().to_string(),
                            read_only: true,
                        }],
                    }),
                })
                .await
                .map_err(|e| RuntimeError::Serve(e.to_string()))?
                .into_inner();

            Ok(Endpoint {
                url: resp.endpoint_url,
                id: resp.sandbox_id,
                backend: RuntimeBackend::OpenShell,
            })
        })
    }

    fn stop(&self, endpoint: &Endpoint)
        -> Pin<Box<dyn Future<Output = Result<(), RuntimeError>> + Send + '_>>
    {
        let sandbox_id = endpoint.id.clone();
        Box::pin(async move {
            self.client.clone()
                .destroy_sandbox(DestroySandboxRequest { sandbox_id })
                .await
                .map_err(|e| RuntimeError::Stop(e.to_string()))?;
            Ok(())
        })
    }

    fn health(&self, endpoint: &Endpoint)
        -> Pin<Box<dyn Future<Output = Result<bool, RuntimeError>> + Send + '_>>
    {
        let sandbox_id = endpoint.id.clone();
        Box::pin(async move {
            let resp = self.client.clone()
                .sandbox_status(SandboxStatusRequest { sandbox_id })
                .await
                .map_err(|e| RuntimeError::Health(e.to_string()))?
                .into_inner();
            Ok(resp.state == SandboxState::Running as i32)
        })
    }

    fn backend(&self) -> RuntimeBackend {
        RuntimeBackend::OpenShell
    }
}
```

### auto_runtime() Update

```rust
pub async fn auto_runtime() -> Result<Box<dyn ModelRuntime>, RuntimeError> {
    #[cfg(feature = "openshell")]
    {
        // OpenShell gateway socket is at a well-known path
        let gateway = "unix:///run/openshell/gateway.sock";
        if OpenShellRuntime::is_available(gateway).await {
            tracing::info!("Using OpenShell runtime");
            return Ok(Box::new(OpenShellRuntime::new(gateway).await?));
        }
    }

    #[cfg(feature = "podman")]
    {
        if podman::PodmanRuntime::is_available().await {
            tracing::info!("Using Podman runtime");
            return Ok(Box::new(podman::PodmanRuntime::new()));
        }
    }

    #[cfg(feature = "direct")]
    {
        if direct::DirectRuntime::is_available().await {
            tracing::info!("Using direct runtime (no isolation)");
            return Ok(Box::new(direct::DirectRuntime::new()));
        }
    }

    Err(RuntimeError::NoRuntime(
        "no suitable runtime found".to_string(),
    ))
}
```

### Configuration

```toml
[models.llama]
runtime = "openshell"

[models.llama.openshell]
gateway = "unix:///run/openshell/gateway.sock"
sandbox_labels = { gpu = "required", isolation = "microvm" }
```

### Implementation Steps

1. Remove `Libkrun` variant from `RuntimeBackend`, add `OpenShell`
2. Remove `libkrun` feature flag from `Cargo.toml`, add `openshell`
3. Add vendored proto file at `smgglrs-model-runtime/proto/`
4. Create `smgglrs-model-runtime/src/openshell.rs`
5. Update `auto_runtime()` to try OpenShell first
6. Add `tonic` + `prost` + `prost-build` to `Cargo.toml`
7. Add `build.rs` for proto compilation
8. Integration test with mock gRPC compute driver

---

## 5. gRPC Module Architecture (Phase 6d)

### Problem

The `Module` trait is in-process only. Handlers are `Arc<dyn Fn>`
closures called directly. This prevents crash isolation,
multi-node deployment, and language-independent modules.

### GrpcModule Adapter

`GrpcModule` implements the `Module` trait by forwarding calls to
a gRPC service. Same pattern as `UpstreamModule` (which adapts
MCP/JSON-RPC servers) but for gRPC.

```
McpServer
  tools: HashMap<String, RegisteredTool>
      ^              ^               ^
 Local Module   UpstreamModule   GrpcModule
 (in-process)   (MCP/JSON-RPC)   (gRPC)
      |              |               |
 Direct call    JSON-RPC over    gRPC over
 (Arc closure)  stdio/HTTP/SSE   Unix socket/TCP
```

### Proto Service Definition

**File**: `smgglrs-core/proto/module.proto`

```protobuf
syntax = "proto3";
package smgglrs.module.v1;

service ModuleService {
    // Discovery: return all tools, prompts, resources
    rpc GetCapabilities(GetCapabilitiesRequest)
        returns (GetCapabilitiesResponse);

    // Execute a tool call
    rpc CallTool(CallToolRequest)
        returns (CallToolResponse);

    // Render a prompt template
    rpc GetPrompt(GetPromptRequest)
        returns (GetPromptResponse);

    // Read a resource
    rpc ReadResource(ReadResourceRequest)
        returns (ReadResourceResponse);

    // Health check
    rpc Health(HealthRequest) returns (HealthResponse);
}

message GetCapabilitiesRequest {}

message GetCapabilitiesResponse {
    repeated ToolDef tools = 1;
    repeated PromptDef prompts = 2;
    repeated ResourceDef resources = 3;
}

message ToolDef {
    string name = 1;
    string description = 2;
    // JSON Schema as JSON bytes
    bytes input_schema_json = 3;
}

message PromptDef {
    string name = 1;
    string description = 2;
    repeated PromptArgument arguments = 3;
}

message PromptArgument {
    string name = 1;
    string description = 2;
    bool required = 3;
}

message ResourceDef {
    string uri = 1;
    string name = 2;
    string description = 3;
    string mime_type = 4;
}

message CallToolRequest {
    string name = 1;
    // serde_json::Value serialized as JSON bytes
    bytes arguments_json = 2;
    ToolCallContext context = 3;
}

message ToolCallContext {
    string agent_name = 1;
    string session_id = 2;
    string data_label = 3;
    uint32 ring = 4;
}

message CallToolResponse {
    repeated ContentItem content = 1;
    bool is_error = 2;
    // Data label of the result (may differ from request if tool taints)
    string result_data_label = 3;
}

message ContentItem {
    string type = 1;  // "text", "image", "resource"
    string text = 2;
    string mime_type = 3;
    bytes data = 4;
}

message GetPromptRequest {
    string name = 1;
    map<string, string> arguments = 2;
}

message GetPromptResponse {
    string description = 1;
    repeated PromptMessage messages = 2;
}

message PromptMessage {
    string role = 1;
    string content = 2;
}

message ReadResourceRequest {
    string uri = 1;
}

message ReadResourceResponse {
    repeated ContentItem contents = 1;
}

message HealthRequest {}

message HealthResponse {
    bool healthy = 1;
    string message = 2;
}
```

### GrpcModule Implementation

**File**: `smgglrs-core/src/grpc_module.rs`

```rust
use crate::server::{Module, ToolDefinition, ToolHandler, CallToolResult};
use smgglrs_security::auth::CallContext;

pub struct GrpcModule {
    name: String,
    client: ModuleServiceClient<Channel>,
    cached_tools: Vec<ToolDef>,
    cached_prompts: Vec<PromptDef>,
    cached_resources: Vec<ResourceDef>,
}

impl GrpcModule {
    /// Connect to a gRPC module service and discover capabilities.
    pub async fn connect(name: &str, endpoint: &str) -> Result<Self> {
        let channel = Channel::from_shared(endpoint.to_string())?
            .connect()
            .await?;
        let mut client = ModuleServiceClient::new(channel);

        let caps = client
            .get_capabilities(GetCapabilitiesRequest {})
            .await?
            .into_inner();

        Ok(Self {
            name: name.to_string(),
            client,
            cached_tools: caps.tools,
            cached_prompts: caps.prompts,
            cached_resources: caps.resources,
        })
    }

    /// Refresh cached capabilities (call after module restart).
    pub async fn refresh(&mut self) -> Result<()> {
        let caps = self.client
            .get_capabilities(GetCapabilitiesRequest {})
            .await?
            .into_inner();
        self.cached_tools = caps.tools;
        self.cached_prompts = caps.prompts;
        self.cached_resources = caps.resources;
        Ok(())
    }
}

impl Module for GrpcModule {
    fn name(&self) -> &str {
        &self.name
    }

    fn tools(&self) -> Vec<(ToolDefinition, ToolHandler)> {
        self.cached_tools.iter().map(|def| {
            let tool_def = ToolDefinition {
                name: def.name.clone(),
                description: def.description.clone(),
                input_schema: serde_json::from_slice(&def.input_schema_json)
                    .unwrap_or_default(),
            };

            let client = self.client.clone();
            let tool_name = def.name.clone();

            let handler: ToolHandler = Arc::new(move |args, ctx| {
                let mut client = client.clone();
                let name = tool_name.clone();
                Box::pin(async move {
                    let req = CallToolRequest {
                        name,
                        arguments_json: serde_json::to_vec(&args)
                            .unwrap_or_default(),
                        context: Some(ToolCallContext {
                            agent_name: ctx.agent.name.clone(),
                            session_id: ctx.session_id.clone(),
                            data_label: format!("{:?}", ctx.taint.level()),
                            ring: ctx.agent.capabilities
                                .as_ref()
                                .map(|c| c.ring as u32)
                                .unwrap_or(3),
                        }),
                    };
                    match client.call_tool(req).await {
                        Ok(resp) => {
                            let inner = resp.into_inner();
                            if inner.is_error {
                                CallToolResult::error(
                                    inner.content.first()
                                        .map(|c| c.text.clone())
                                        .unwrap_or_default(),
                                )
                            } else {
                                CallToolResult::text(
                                    inner.content.iter()
                                        .map(|c| c.text.clone())
                                        .collect::<Vec<_>>()
                                        .join("\n"),
                                )
                            }
                        }
                        Err(e) => {
                            CallToolResult::error(format!("grpc: {e}"))
                        }
                    }
                })
            });

            (tool_def, handler)
        }).collect()
    }
}
```

### Module Lifecycle Management

**File**: `smgglrs-server/src/grpc_manager.rs`

```rust
/// Manages lifecycle of gRPC module processes.
pub struct GrpcModuleManager {
    modules: HashMap<String, ManagedModule>,
}

struct ManagedModule {
    config: GrpcModuleConfig,
    process: Option<Child>,
    module: Option<GrpcModule>,
    restarts: u32,
}

pub struct GrpcModuleConfig {
    pub name: String,
    pub binary: PathBuf,
    pub socket: PathBuf,
    /// Or TCP address for remote modules
    pub address: Option<String>,
    pub health_interval: Duration,
    pub restart_on_failure: bool,
    pub max_restarts: u32,
}

impl GrpcModuleManager {
    /// Start all configured gRPC modules.
    pub async fn start_all(&mut self) -> Result<Vec<Box<dyn Module>>>;

    /// Health check loop (runs in background).
    pub async fn health_loop(&self, shutdown: CancellationToken);

    /// Restart a failed module.
    async fn restart(&mut self, name: &str) -> Result<()>;
}
```

### Configuration

```toml
# In-process module (existing, unchanged)
[modules.docs]
enabled = true

# gRPC module (new)
[modules.custom_tool]
enabled = true
transport = "grpc"
binary = "/usr/libexec/smgglrs/modules/custom-tool"
socket = "/run/smgglrs/modules/custom-tool.sock"
health_interval_secs = 10
restart_on_failure = true
max_restarts = 3

# Remote gRPC module (TCP)
[modules.vision_remote]
enabled = true
transport = "grpc"
address = "gpu-host:50051"
health_interval_secs = 30
```

### Security

- Unix socket modules: filesystem permissions control access
  (same as OpenShell's driver model)
- TCP modules: require capability token in gRPC metadata
  (`authorization` key in `tonic::Request::metadata()`)
- smgglrs's ACLs still apply: gRPC modules do not bypass the
  permission engine. The `ToolCallContext` carries the agent
  identity through to the module.
- Crash isolation: a failing module process does not crash smgglrs.
  The `GrpcModuleManager` detects the broken connection and
  restarts the module up to `max_restarts` times.

### IFC Propagation

The `CallToolResponse` carries a `result_data_label` field. When
a gRPC module taints its output (e.g., a read tool that accessed
external data), it sets this field. smgglrs merges the returned
label into the session's `TaintTracker` via `absorb()`.

### Dependencies

- `tonic` (gRPC framework)
- `prost` + `prost-build` (protobuf compilation)
- `tower` (middleware for gRPC interceptors, already transitive)

### Implementation Steps

1. Add `smgglrs-core/proto/module.proto`
2. Add `build.rs` to `smgglrs-core` for proto compilation
3. Create `smgglrs-core/src/grpc_module.rs`
4. Create `smgglrs-server/src/grpc_manager.rs`
5. Add `GrpcModuleConfig` to server config
6. Wire gRPC modules into the `McpServer` builder in `main.rs`
7. Unit tests with mock gRPC service
8. Integration test: spawn a module binary, connect, call tool

---

## 6. Network Security Model (Phase 6e)

### Defense in Depth

Two independent security enforcement layers, each insufficient
alone:

```
+----------------------------------------------------------+
|                    Security Layers                        |
|                                                          |
|  Layer 1: OpenShell (MAC - Mandatory Access Control)     |
|  +----------------------------------------------------+  |
|  | Network namespace: process cannot create sockets    |  |
|  | HTTP CONNECT proxy: all outbound traffic filtered   |  |
|  | OPA policies: per-destination allow/deny            |  |
|  | Landlock: filesystem isolation                      |  |
|  | seccomp: syscall filtering                          |  |
|  +----------------------------------------------------+  |
|                                                          |
|  Layer 2: smgglrs (DAC - Discretionary Access Control)   |
|  +----------------------------------------------------+  |
|  | Auth: capability tokens with scoped permissions     |  |
|  | ACLs: deny-wins path rules + per-tool rules         |  |
|  | IFC: Bell-LaPadula taint propagation                |  |
|  | Safety: content filters (regex + ML)                |  |
|  | Hooks: pre/post tool-call pipeline                  |  |
|  | Audit: structured log of every tool call            |  |
|  +----------------------------------------------------+  |
+----------------------------------------------------------+
```

### Why Both Are Necessary

**OpenShell without smgglrs**: The agent can reach smgglrs over
the network, but without smgglrs's ACLs it could call any tool,
read any path, and ignore IFC labels. A compromised agent
process has unrestricted tool access.

**smgglrs without OpenShell**: The agent respects smgglrs's ACLs
at the application layer, but a compromised agent process can
bypass smgglrs entirely: open raw sockets, exfiltrate data to
the internet, read arbitrary files via the OS, or tamper with
other processes.

**Both together**: OpenShell prevents reaching anything except
smgglrs and the model. smgglrs prevents doing anything except
what the capability token allows. Compromise of either layer
alone is insufficient for a full breach.

### Sandbox Network Policy

Each sandbox has exactly three allowed destinations:

```
+---------------+-------------+-------------------------------+
| Destination   | Protocol    | Purpose                       |
+---------------+-------------+-------------------------------+
| Model endpoint| HTTP        | Inference (llama-server, etc) |
| smgglrs       | MCP (HTTP)  | Tool access + A2A mesh        |
|               | + A2A (HTTP)|                               |
| OpenShell GW  | gRPC        | Control plane, credentials    |
+---------------+-------------+-------------------------------+
| Everything    | *           | BLOCKED                       |
| else          |             |                               |
+---------------+-------------+-------------------------------+
```

### OPA Policy Template

**File**: `docs/openshell/opa-sandbox-policy.rego`

```rego
package openshell.sandbox.network

import rego.v1

# Sandbox network policy for smgglrs-managed agents.
# Applied by the OpenShell supervisor's HTTP CONNECT proxy.

default allow := false

# Allow connections to the smgglrs gateway
allow if {
    input.destination.host == data.config.smgglrs_host
    input.destination.port == data.config.smgglrs_port
}

# Allow connections to the model endpoint
allow if {
    input.destination.host == data.config.model_host
    input.destination.port == data.config.model_port
}

# Allow connections to the OpenShell gateway (control plane)
allow if {
    input.destination.host == data.config.gateway_host
    input.destination.port == data.config.gateway_port
}

# Deny everything else (explicit for clarity)
deny if {
    not allow
}
```

### smgglrs Config Template for OpenShell Deployments

**File**: `docs/openshell/smgglrs-sandbox.toml`

```toml
# smgglrs configuration template for OpenShell-managed sandboxes.
# Deployed automatically by the OpenShell supervisor.

[server]
# Unix socket inside sandbox (supervisor connects agents to it)
socket = "/run/smgglrs/smgglrs.sock"
# No TCP listener (not needed inside sandbox)

[auth.openshell]
enabled = true
mode = "spiffe"
trust_bundle = "/run/spire/agent/bundle.pem"
default_permissions = "restricted"

[auth.openshell.mapping]
"role=worker"  = "restricted"
"role=lead"    = "developer"

# Modules enabled for this sandbox
[modules.docs]
enabled = true
[modules.git]
enabled = true

# Upstream MCP servers (deployed alongside smgglrs in sandbox)
[[upstream]]
name = "domain-tools"
transport = "stdio"
command = ["/usr/libexec/sandbox/domain-tool-server"]

# Agent identity (provisioned by supervisor)
[[agents]]
name = "sandbox-agent"
permissions = "restricted"
# Token injected by supervisor at sandbox creation time
# token_hash = "<injected>"

# Restrictive permissions for sandboxed agents
[permissions.restricted]
allow = ["/workspace/**"]
deny = ["**/.env", "**/*secret*", "**/credentials*"]
operations = ["read", "search", "list"]
approve = []
safety = "standard"
default_tool_policy = "allow"

[permissions.developer]
allow = ["/workspace/**"]
deny = ["**/.env", "**/*secret*"]
operations = ["read", "write", "search", "list",
              "git.status", "git.diff", "git.log"]
approve = ["write", "git.commit"]
safety = "standard"
default_tool_policy = "allow"
```

### Integration Test Plan

Tests verify that the combined security model works end-to-end.
These run in CI with a mock OpenShell supervisor.

**Test 1: Network isolation**
- Start a sandbox with the OPA policy
- Agent process attempts `curl` to an external URL
- Verify: connection refused (proxy denies)

**Test 2: Authorized tool call**
- Agent calls `file_read` on an allowed path
- Verify: tool call succeeds, result returned

**Test 3: Denied tool call**
- Agent calls `git_commit` without the operation in its token
- Verify: smgglrs returns permission denied

**Test 4: IFC enforcement across A2A**
- Agent A (tainted with Sensitive data) sends A2A message to
  Agent B (Public clearance)
- Verify: smgglrs rejects the write-down (Bell-LaPadula)

**Test 5: Lateral movement blocked**
- Agent attempts to connect to another sandbox's IP directly
- Verify: network namespace blocks the connection

**Test 6: Credential exfiltration blocked**
- Agent calls a tool that returns credential-like content
- Verify: safety filter redacts the content before returning

### MAC + DAC Analogy (for Papers)

```
+-----------+-------------------+---------------------------+
| Concept   | Traditional OS    | Agent Platform             |
+-----------+-------------------+---------------------------+
| MAC       | SELinux/AppArmor  | OpenShell sandbox          |
|           | System-wide       | Network namespace +        |
|           | mandatory rules   | Landlock + seccomp         |
+-----------+-------------------+---------------------------+
| DAC       | Unix permissions  | smgglrs ACLs + IFC         |
|           | Owner-controlled  | Agent-scoped capability    |
|           | file access       | tokens with deny-wins      |
+-----------+-------------------+---------------------------+
| Kernel    | Linux kernel      | smgglrs gateway            |
|           | Syscall interface | Tool access interface      |
|           | Process isolation | Session isolation          |
+-----------+-------------------+---------------------------+
| Userland  | Applications      | MCP servers + agents       |
|           | Use syscalls      | Use MCP tool calls         |
|           | Subject to DAC    | Subject to ACLs + IFC      |
+-----------+-------------------+---------------------------+
```

---

## 7. Self-Contained Agent Pattern

### MCP-Sourced Personas

Upstream MCP servers can provide not just tools but also prompts
and resources that define agent behavior. A self-contained sandbox
bundles everything the agent needs:

```
Sandbox Contents:
  smgglrs gateway (security + tool aggregation)
  + Upstream MCP server (domain tools + methodology prompt)
  + Persona YAML (agent identity + heuristics)
  + Model endpoint (local inference)
  + Credentials (injected by supervisor)
  = Complete agent, no external dependencies
```

### Runtime Discovery Flow

When a sandbox starts, the agent bootstraps through smgglrs:

```
1. Sandbox created by OpenShell supervisor
   - smgglrs started with sandbox config
   - Model endpoint started
   - Upstream MCP servers started

2. Agent process starts
   |
   +-- Connects to smgglrs (Unix socket)
   |     Authorization: Bearer <supervisor-issued-token>
   |
   +-- Calls initialize
   |     smgglrs returns capabilities
   |
   +-- Calls tools/list
   |     smgglrs returns aggregated tools from:
   |       - Built-in modules (docs, git)
   |       - Upstream MCP servers (domain tools)
   |       - gRPC modules (if any)
   |
   +-- Calls prompts/get("domain_methodology")
   |     smgglrs proxies to upstream, returns methodology prompt
   |     Agent injects into system prompt (Phase 5h)
   |
   +-- Loads persona YAML (from /workspace/.smgglrs/persona.yml
   |     or from smgglrs cognitive module)
   |
   +-- Enters tool-use loop
         Model endpoint provides inference
         smgglrs enforces security on every tool call
```

### No External Config Needed

The sandbox creation request carries all configuration as labels
and supervisor config. The operator specifies what kind of agent
they want; OpenShell provisions everything:

```
CreateSandbox {
    labels: {
        "role": "legal-analyst",
        "gpu": "not-required",
        "isolation": "container",
        "persona": "legal_analyst",
        "upstream": "syllogis",
        "model": "granite3.3:8b",
    },
    supervisor: {
        entrypoint: "/usr/bin/smgglrs",
        args: ["serve", "--config", "/etc/smgglrs/sandbox.toml"],
        env: {
            "SMGGLRS_PERSONA": "legal_analyst",
            "SMGGLRS_MODEL": "granite3.3:8b",
        },
    },
}
```

### Example: Syllogis Legal Analyst Sandbox

```
+-- OpenShell Sandbox: legal-analyst-001 --+
|                                          |
|  smgglrs (gateway)                       |
|    +-- Auth: SPIFFE from supervisor      |
|    +-- ACLs: /workspace/cases/** only    |
|    +-- Safety: PII filter enabled        |
|                                          |
|  Upstream MCP: Syllogis                  |
|    +-- Tools: search_codes, analyze_case |
|    +-- Prompt: legal_analysis            |
|         (methodology, syllogism format)  |
|                                          |
|  Persona: legal_analyst                  |
|    +-- Core mandate: French admin law    |
|    +-- Heuristics: legal reasoning       |
|    +-- MCP prompts: syllogis:legal_*     |
|                                          |
|  Model: granite3.3:8b (local, Ollama)    |
|                                          |
|  Agent process                           |
|    +-- Connects to smgglrs via socket    |
|    +-- Discovers Syllogis tools          |
|    +-- Loads legal_analyst persona       |
|    +-- Injects Syllogis methodology      |
|    +-- Runs analysis in tool loop        |
|                                          |
|  Network: ONLY smgglrs + model + GW      |
+------------------------------------------+
```

---

## 8. Implementation Roadmap

### Dependency Order

```
Phase 6a: Identity Federation
    |  (no dependencies, can start immediately)
    |  OpenShellAuthenticator in smgglrs-security
    |  Credential delegation backend
    v
Phase 6b: A2A Teammate Mesh
    |  (independent of 6a, can run in parallel)
    |  A2aClient in smgglrs-protocol
    |  MeshRouter in smgglrs-flow
    |  AgentCardDirectory in smgglrs-core
    v
Phase 6c: Sandbox Delegation
    |  (depends on 6a for identity in sandboxes)
    |  OpenShellRuntime in smgglrs-model-runtime
    |  Remove libkrun stub
    v
Phase 6d: gRPC Module Architecture
    |  (independent, can run in parallel with 6c)
    |  Proto definitions + tonic setup
    |  GrpcModule adapter in smgglrs-core
    |  GrpcModuleManager in smgglrs-server
    v
Phase 6e: Network Security Model
    (depends on 6a + 6c)
    OPA policy templates
    smgglrs config templates
    Integration test suite
    Paper section (MAC + DAC)
```

### What Can Be Built Without OpenShell

All phases can be developed and tested without a running OpenShell
instance:

| Phase | Mock Strategy |
|-------|---------------|
| 6a | Generate test JWTs locally, mock JWKS endpoint with `wiremock` |
| 6b | Use in-process mode as baseline, test A2A client against smgglrs's own A2A endpoint |
| 6c | Mock gRPC compute driver that spawns a local llama-server (same as Direct backend) |
| 6d | Mock gRPC module service that returns hardcoded tools |
| 6e | Docker Compose setup: two containers (sandbox + gateway) with network policy |

### Integration Test Strategy

```
Level 1: Unit tests (per-crate, no external dependencies)
  - OpenShellAuthenticator with mock JWT
  - A2aClient with mock HTTP server
  - OpenShellRuntime with mock gRPC server
  - GrpcModule with mock module service

Level 2: Integration tests (multi-crate, local processes)
  - ChainAuthenticator with OpenShell slot
  - MeshRouter routing to both local and A2A endpoints
  - GrpcModuleManager starting a real binary
  - Full tool call through gRPC module

Level 3: System tests (containers, network isolation)
  - Two smgglrs instances communicating via A2A
  - Agent in container with network policy
  - End-to-end: sandbox creation -> tool call -> result
```

### Estimated Effort

| Phase | Effort | Key Dependencies |
|-------|--------|------------------|
| 6a: Identity Federation | 3-4 days | `jsonwebtoken` crate |
| 6b: A2A Client + Mesh | 4-5 days | `reqwest` (already in workspace) |
| 6c: Sandbox Delegation | 3-4 days | `tonic` + `prost` |
| 6d: gRPC Modules | 5-6 days | `tonic` + `prost` (shared with 6c) |
| 6e: Network Security | 2-3 days | Depends on 6a + 6c being done |
| **Total** | **17-22 days** | |

Phases 6a and 6b can run in parallel (no dependencies between
them). Phases 6c and 6d can also run in parallel. Phase 6e is
the integration and validation phase that ties everything
together.

### New Dependencies Summary

| Crate | Used By | Purpose |
|-------|---------|---------|
| `jsonwebtoken` | smgglrs-security | JWT decode + verify |
| `tonic` | smgglrs-model-runtime, smgglrs-core | gRPC client/server |
| `prost` | smgglrs-model-runtime, smgglrs-core | Protobuf codegen |
| `prost-build` | smgglrs-model-runtime, smgglrs-core | Build-time proto compile |

### Files Created or Modified

**New files:**
- `smgglrs-security/src/auth/openshell.rs`
- `smgglrs-protocol/src/a2a_client.rs`
- `smgglrs-core/src/grpc_module.rs`
- `smgglrs-core/proto/module.proto`
- `smgglrs-model-runtime/src/openshell.rs`
- `smgglrs-model-runtime/proto/openshell_compute.proto`
- `smgglrs-server/src/grpc_manager.rs`
- `docs/openshell/opa-sandbox-policy.rego`
- `docs/openshell/smgglrs-sandbox.toml`

**Modified files:**
- `smgglrs-security/src/auth/mod.rs` (add `pub mod openshell`)
- `smgglrs-security/src/credentials.rs` (add `OpenShell` source variant)
- `smgglrs-protocol/src/lib.rs` (add `pub mod a2a_client`)
- `smgglrs-core/src/lib.rs` (add `pub mod grpc_module`)
- `smgglrs-core/src/transport/a2a.rs` (add `AgentCardDirectory`)
- `smgglrs-model-runtime/src/lib.rs` (replace `Libkrun` with `OpenShell`)
- `smgglrs-model-runtime/Cargo.toml` (replace `libkrun` feature with `openshell`)
- `smgglrs-flow/src/mesh.rs` (add `TeammateLocation`, `MeshRouter`)
- `smgglrs-server/src/config/` (add OpenShell + gRPC module config structs)
- `smgglrs-server/src/main.rs` (wire OpenShell auth + gRPC modules)

---

## References

- OpenShell RFC 0001 -- Core Architecture (Red Hat/NVIDIA, 2026-07)
- A2A v1.0 (Linux Foundation/AAIF, gRPC transport, signed Agent Cards)
- SPIFFE/SPIRE (CNCF, workload identity via mTLS)
- Terraform provider model (HashiCorp, gRPC plugins)
- Bell-LaPadula model (no-write-down, mandatory access control)
- DESIGN.md -- smgglrs architecture, auth, transport, ACLs
- ROADMAP.md -- Phase 6 (6a-6e) overview
- OPENSHELL.md -- High-level integration design
