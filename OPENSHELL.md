# OpenShell Integration Design

This document describes how smgglrs integrates with OpenShell, the
Red Hat/NVIDIA secure sandbox platform for autonomous agents.

**Status**: Design phase (2026-04-22).

## Relationship

OpenShell and smgglrs operate at different layers of the agent stack:

| Concern | OpenShell | smgglrs |
|---------|-----------|------|
| What it manages | Compute environments (sandboxes) | Tool access (MCP protocol) |
| Security focus | OS-level isolation (Landlock, seccomp, namespaces) | Application-level (ACLs, IFC, safety filters, hooks) |
| Protocol | gRPC (all internal communication) | MCP (JSON-RPC 2.0 over Streamable HTTP + SSE) |
| Extensibility | gRPC drivers as separate processes | Module trait (in-process) + UpstreamModule (JSON-RPC) |
| Agent comms | Sandbox-to-sandbox relay through gateway | smgglrs-flow (mailbox, blackboard, A2A) |
| Isolation | libkrun microVM, Podman, Kata, gVisor | Podman (model runtime only) |

The natural integration: **agents run inside OpenShell sandboxes
and connect to smgglrs for tool access**. OpenShell provides the
"where agents run"; smgglrs provides "what agents can do."

In the AI OS analogy (see Phase 8 papers): OpenShell is the
**process isolation layer** (cgroups, namespaces, microVMs),
smgglrs is the **syscall interface** (tool access control, IFC).

## Defense in depth: network + application firewalling

The combination of OpenShell and smgglrs creates two independent
security enforcement layers. Neither alone is sufficient.

### Sandbox network policy (OpenShell)

The OpenShell supervisor runs an HTTP CONNECT proxy inside every
sandbox. All outbound traffic is forced through it (network
namespace + iptables/nftables). OPA policies evaluate each
connection against the sandbox's allowed destinations.

A teammate sandbox needs access to exactly three things:

| Destination | Protocol | Purpose |
|-------------|----------|---------|
| Model endpoint (llama-server, Ollama, cloud API) | HTTP | Inference |
| smgglrs gateway | MCP (HTTP) + A2A (HTTP) | Tools + teammate mesh |
| OpenShell gateway | gRPC | Control plane (config, policy, credentials) |

Everything else is **blocked** — no internet, no DNS to
arbitrary hosts, no lateral movement to other sandboxes except
through the gateway relay with policy evaluation.

OpenShell's RFC explicitly supports this:
- "Allow sandbox-to-sandbox but deny internet (air-gapped
  collaboration)"
- Sandbox-to-sandbox traffic relays through the gateway (no
  direct peer connections in the initial architecture)
- Policy is evaluated at relay setup time using authenticated
  source and destination sandbox identities

### Application-level enforcement (smgglrs)

Even when a sandbox can reach smgglrs over the network, smgglrs
enforces what the agent inside that sandbox can actually do:

- **Tool ACLs**: agent can only call specific tools (e.g.,
  `docs_read`, `git_status` — not `git_commit`)
- **Path ACLs**: tool calls restricted to specific paths (e.g.,
  `/home/projects/foo/**` — deny wins)
- **IFC taint propagation**: agent tainted with `Sensitive` data
  cannot write to `Public`-clearance teammates (Bell-LaPadula
  no-write-down)
- **Safety filters**: content scanned for secrets, PII, harmful
  content before crossing tool boundaries
- **Capability scoping**: each teammate's token limits operations,
  tools, paths, and credential access

### Combined sandbox model

```
┌─ OpenShell Sandbox (agent teammate) ──────────────┐
│                                                    │
│  Agent process                                     │
│    ├─ model call  → proxy → model endpoint ✅      │
│    ├─ tool call   → proxy → smgglrs gateway ✅        │
│    │                 └─► smgglrs ACL check            │
│    │                 └─► smgglrs IFC check            │
│    │                 └─► smgglrs safety filter         │
│    ├─ A2A message → proxy → OpenShell gateway      │
│    │                 └─► relay policy check         │
│    │                 └─► smgglrs IFC check (at dest)  │
│    ├─ curl google.com → proxy → OPA DENY ❌        │
│    └─ raw IP connect  → netns blocks ❌            │
│                                                    │
│  Supervisor (OS-level security boundary)           │
│    ├─ HTTP CONNECT proxy (all outbound traffic)    │
│    ├─ OPA policy engine (network allowlist)        │
│    ├─ Landlock (filesystem isolation)              │
│    ├─ seccomp (syscall filtering)                  │
│    └─ gRPC → OpenShell gateway (outbound only)     │
└────────────────────────────────────────────────────┘
```

### Why both layers are necessary

**OpenShell without smgglrs**: The agent can reach smgglrs over the
network, but without smgglrs's ACLs it could call any tool, read
any path, and ignore IFC labels. A compromised agent process
has unrestricted tool access.

**smgglrs without OpenShell**: The agent respects smgglrs's ACLs at
the application layer, but a compromised agent process can
bypass smgglrs entirely — open raw sockets, exfiltrate data to
the internet, read arbitrary files via the OS, or tamper with
other processes.

**Both together**: OpenShell prevents the agent from reaching
anything except smgglrs and its model. smgglrs prevents the agent
from doing anything except what its capability token allows.
Compromising either layer alone is insufficient for a full
breach.

This maps to the AI OS analogy: OpenShell is mandatory access
control (SELinux/AppArmor), smgglrs is discretionary access
control (Unix permissions + capability tokens). Defense in
depth requires both.

## 1. OpenShell-provided identity

### Problem

smgglrs currently authenticates agents via two mechanisms:

1. **BLAKE3 tokens** (legacy) — pre-shared bearer tokens hashed
   with BLAKE3, mapped to `AgentIdentity` via config.
2. **Capability tokens** (modern) — self-contained CBOR tokens
   signed with Ed25519, carrying inline capabilities.

Both require smgglrs to manage credentials independently. When an
agent runs inside an OpenShell sandbox, the OpenShell supervisor
has already established the agent's identity through the
gateway's identity subsystem (SPIFFE, OIDC, local OS, or static
RBAC). Re-authenticating at the smgglrs layer is redundant and
creates a credential management burden.

### Design: OpenShellAuthenticator

Add a new `Authenticator` implementation to the `ChainAuthenticator`
that trusts OpenShell-provided identity assertions.

**Identity flow:**

```
Agent (inside OpenShell sandbox)
    |
    | HTTP request with "Authorization: Bearer <openshell-identity-token>"
    v
smgglrs (ChainAuthenticator)
    |-- 1. CapabilityAuthenticator (try smgglrs-native cap tokens)
    |-- 2. OpenShellAuthenticator (try OpenShell identity) <-- NEW
    |-- 3. TokenAuthenticator (try legacy BLAKE3 tokens)
    |-- 4. NoAuthenticator (dev-only fallback)
    v
AgentIdentity resolved
```

**OpenShell identity token format:**

OpenShell's identity subsystem supports multiple backends. The
`OpenShellAuthenticator` accepts tokens from any of them:

| Backend | Token format | Verification |
|---------|-------------|-------------|
| SPIFFE/SPIRE | X.509 SVID (mTLS) or JWT-SVID | Verify against SPIRE agent trust bundle |
| OIDC/OAuth2 | JWT bearer token | Verify signature with IdP JWKS endpoint |
| Local OS | Unix socket peer credentials | Verify UID/GID via SO_PEERCRED |
| Static RBAC | OpenShell-signed JWT | Verify with OpenShell gateway's signing key |

**Token-to-identity mapping:**

The `OpenShellAuthenticator` extracts identity claims from the
OpenShell token and maps them to smgglrs's `AgentIdentity`:

```
OpenShell claim          -> AgentIdentity field
-----------------------------------------------------
spiffe://.../<sandbox-id> -> name (sandbox identifier)
sandbox labels/metadata   -> permissions (mapped via config)
sandbox ring/role         -> capabilities.ring
gateway-scoped operations -> capabilities.operations
```

**Configuration:**

```toml
[auth.openshell]
enabled = true
# How to verify OpenShell identity tokens
mode = "spiffe"  # or "oidc", "local", "static"

# SPIFFE mode: trust bundle from SPIRE agent
trust_bundle = "/run/spire/agent/bundle.pem"

# OIDC mode: IdP endpoint for JWKS
# issuer = "https://keycloak.example.com/realms/agents"

# Permission mapping: OpenShell labels -> smgglrs permission sets
[auth.openshell.mapping]
"role=worker"    = "restricted"
"role=lead"      = "developer"
"role=admin"     = "admin"
```

**Implementation in smgglrs-security:**

- New file: `smgglrs-security/src/auth/openshell.rs`
- New struct: `OpenShellAuthenticator` implementing `Authenticator`
- Add to `ChainAuthenticator` between capability and legacy auth
- Dependencies: `jsonwebtoken` (JWT verification), optionally
  `spiffe` crate for SVID handling

**Credential delegation:**

When OpenShell's credential subsystem resolves secrets (API keys,
tokens), it delivers them to the supervisor. smgglrs's
`MappedCredentialStore` can be extended with an `openshell` backend
that reads credentials from the supervisor's credential delivery
channel instead of the local keyring:

```toml
[credentials.mapping.github-pat]
source = "openshell"
label = "github.pat"
```

This avoids duplicating credential storage between OpenShell and smgglrs.

### Priority

High for OpenShell-managed deployments. No impact on standalone
smgglrs (OpenShellAuthenticator is skipped when not configured).

## 2. A2A protocol for teammate communications

### Problem

smgglrs-flow currently uses three in-process communication
mechanisms for multi-agent coordination:

1. **Mailbox** — tokio mpsc channels, in-memory only
2. **Blackboard** — Arc<RwLock<HashMap>>, in-memory only
3. **Mesh tools** — virtual tools injected into agent tool lists

These work for single-process flows but cannot span process
boundaries, containers, or OpenShell sandboxes. When teammates
run in separate OpenShell sandboxes, they need a network-capable
communication protocol.

### Design: A2A as the teammate protocol

A2A (Agent-to-Agent) is the right protocol for teammate
communication. smgglrs already has:

- A2A server implementation (receive tasks, execute tools, return
  results via `/a2a` endpoint)
- A2A protocol types (Message, Task, Artifact, streaming events)
- Agent Card serving (`/.well-known/agent.json`)

What's missing is an **A2A client** and the **mesh builder**.

**Architecture:**

```
Planner persona (lead agent)
    |
    | Decomposes task into sub-tasks
    | Selects teammates and models
    v
smgglrs (flow engine)
    |
    | Builds A2A mesh:
    |   1. For each teammate, create/assign an A2A endpoint
    |   2. Register teammate Agent Cards in local directory
    |   3. Configure routing rules (who can talk to whom)
    |   4. Mint scoped capability tokens per teammate
    v
┌─────────────────────────────────────────────┐
│              A2A Mesh (built by smgglrs)       │
│                                             │
│  Teammate A ◄──A2A──► Teammate B            │
│      │                    │                 │
│      │         A2A        │                 │
│      └────────────────────┘                 │
│             │                               │
│          A2A│                               │
│             ▼                               │
│        Teammate C                           │
│                                             │
│  All traffic flows through smgglrs gateway     │
│  (IFC enforcement, audit logging, ACLs)     │
└─────────────────────────────────────────────┘
```

**Mesh construction by smgglrs (on behalf of planner persona):**

The planner persona defines the flow (teammates, dependencies,
communication patterns). smgglrs's flow engine translates this into
an A2A mesh:

1. **Teammate registration**: Each teammate gets an A2A endpoint
   on smgglrs (e.g., `/a2a/teammates/{name}`). smgglrs acts as the
   A2A gateway — teammates don't talk directly to each other;
   they send A2A messages through smgglrs, which enforces IFC and
   ACLs before relaying.

2. **Agent Card directory**: smgglrs maintains a local directory of
   teammate Agent Cards. When teammate A needs to discover
   teammate B's capabilities, it queries smgglrs's directory
   (not an external registry).

3. **Capability scoping**: Each teammate receives a scoped
   capability token that limits which other teammates it can
   message, which tools it can call, and which data labels
   it can access. The planner's flow definition drives the
   scoping.

4. **IFC enforcement**: A2A messages between teammates are
   subject to the same Bell-LaPadula no-write-down policy as
   mailbox messages. Taint labels propagate through A2A task
   artifacts.

**A2A client in smgglrs-protocol:**

Add an `A2aClient` struct to `smgglrs-protocol/src/a2a_client.rs`:

```rust
pub struct A2aClient {
    endpoint: String,
    auth_token: String,
    http: reqwest::Client,
}

impl A2aClient {
    pub async fn send_message(&self, msg: Message) -> Result<Task>;
    pub async fn stream_message(&self, msg: Message) -> Result<impl Stream<Item = StreamingResult>>;
    pub async fn get_task(&self, task_id: &str) -> Result<Task>;
    pub async fn cancel_task(&self, task_id: &str) -> Result<Task>;
    pub async fn discover(&self) -> Result<AgentCard>;
}
```

**Migration path from in-process to A2A:**

The flow engine abstracts communication behind the mesh tools
(`mesh_post`, `mesh_recv`, `bb_publish`, `bb_read`). The
implementation can switch between:

- **In-process mode** (current): tokio channels, same process
- **A2A mode** (new): A2A JSON-RPC calls through smgglrs gateway

The mesh tool handlers detect whether a teammate is local
(in-process) or remote (A2A endpoint) and route accordingly.
This preserves backward compatibility.

**OpenShell integration:**

In OpenShell-managed deployments, each teammate runs in its own
sandbox. The A2A mesh maps naturally:

- Each sandbox has a supervisor connection to the OpenShell gateway
- Each sandbox runs an smgglrs instance (or connects to a shared one)
- Teammate-to-teammate A2A traffic flows through the OpenShell
  gateway relay AND through smgglrs's IFC/ACL enforcement
- Double security: OpenShell enforces sandbox-level policy,
  smgglrs enforces tool-level policy

### Priority

Medium-high. Required for multi-node and OpenShell deployments.
In-process mode remains the default for single-node.

## 3. Sandbox mechanism: OpenShell replaces libkrun

### Current state (honest assessment)

`smgglrs-model-runtime` has three isolation backends:

| Backend | Status | Code |
|---------|--------|------|
| **Direct** | Fully implemented | Spawns llama-server as child process, no isolation |
| **Podman** | Fully implemented | Rootless containers with read-only filesystem, network isolation, GPU passthrough |
| **libkrun** | **Stub only** | Feature flag exists (`libkrun = []`) but zero code, zero dependencies, zero conditional compilation |

The libkrun feature flag in `Cargo.toml` and enum variant in
`RuntimeBackend` are aspirational. The `auto_runtime()` function
never checks for libkrun — it tries Podman, then falls back to
Direct.

### Decision: OpenShell as the sandbox mechanism

Instead of implementing our own libkrun integration, delegate
sandboxing to OpenShell:

**Rationale:**

1. **OpenShell already has it**: `openshell-vm` uses libkrun for
   single-player microVM mode. Their Podman compute driver
   provides container isolation. We would be duplicating work.

2. **Defense in depth**: OpenShell provides OS-level isolation
   (Landlock, seccomp, network namespaces, microVMs). smgglrs
   provides application-level security (ACLs, IFC, safety
   filters). These are complementary layers, not redundant.

3. **Scope clarity**: smgglrs is a tool access gateway, not a compute
   platform. Managing sandbox lifecycle is OpenShell's job.

4. **Shared libkrun expertise**: Both projects target libkrun on
   Linux. Coordinating on one implementation avoids divergence.

**What changes in smgglrs:**

- Remove the `libkrun` feature flag from `smgglrs-model-runtime`
  (or mark it explicitly as `# Delegated to OpenShell`)
- Keep Direct and Podman backends for standalone smgglrs (no
  OpenShell dependency required)
- Add an `openshell` backend to `smgglrs-model-runtime` that
  delegates sandbox creation to OpenShell's compute driver:

```toml
[models.llama]
runtime = "openshell"  # or "podman" (standalone) or "direct" (dev)

[models.llama.openshell]
gateway = "unix:///run/openshell/gateway.sock"
sandbox_labels = { gpu = "required", isolation = "microvm" }
```

**OpenShell compute driver interaction:**

```
smgglrs (model serve request)
    |
    | gRPC: CreateSandbox { labels, supervisor_config }
    v
OpenShell Gateway
    |
    | Compute driver (Podman, libkrun, K8s, ...)
    v
Sandbox with llama-server
    |
    | Supervisor connects back to gateway
    | smgglrs connects to llama-server HTTP endpoint
    v
Inference ready
```

smgglrs does NOT need to know which isolation backend OpenShell
uses. It requests a sandbox with labels (e.g., `gpu=required`,
`isolation=microvm`) and OpenShell's compute driver handles the
rest.

### Migration path

1. **Phase 1** (now): Keep Direct + Podman. Remove libkrun
   pretense.
2. **Phase 2** (OpenShell integration): Add `openshell` runtime
   backend that delegates to OpenShell's compute driver via gRPC.
3. **Phase 3** (convergence): For OpenShell-managed deployments,
   `openshell` becomes the default runtime. Standalone smgglrs
   continues to use Podman.

## 4. gRPC module architecture

### Problem

smgglrs's Module trait is purely in-process:

```rust
pub trait Module: Send + Sync + 'static {
    fn name(&self) -> &str;
    fn tools(&self) -> Vec<(ToolDefinition, ToolHandler)>;
    fn prompts(&self) -> Vec<(PromptDefinition, PromptHandler)>;
    fn resources(&self) -> Vec<(ResourceDefinition, ResourceHandler)>;
}
```

Handlers are `Arc<dyn Fn>` closures called directly. This is
fast but limits modules to the smgglrs process. It prevents:

- Running modules as separate processes (crash isolation)
- Running modules on separate nodes (horizontal scaling)
- Writing modules in other languages
- Independent module deployment and versioning

OpenShell's RFC explicitly rejected the in-process trait approach
for their driver interfaces (see Alternatives section 1),
choosing gRPC services instead. The same arguments apply to
smgglrs's module system.

### Design: GrpcModule adapter

Add a `GrpcModule` struct that implements the `Module` trait by
forwarding calls to a gRPC service. This mirrors the existing
`UpstreamModule` pattern (which adapts MCP servers to the Module
trait) but uses gRPC instead of JSON-RPC.

**Architecture:**

```
┌─────────────────────────────────────────────────┐
│              McpServer (smgglrs-core)             │
│  tools: HashMap<String, RegisteredTool>          │
└─────────────────────────────────────────────────┘
         ↑              ↑               ↑
    Local Module   UpstreamModule   GrpcModule
    (in-process)   (MCP/JSON-RPC)   (gRPC)
         │              │               │
    Direct call    JSON-RPC over    gRPC over
    (Arc closure)  stdio/HTTP/SSE   Unix socket/TCP
         │              │               │
    Same process   MCP server      Module service
                   (any language)  (any language)
```

**gRPC service contract:**

```protobuf
syntax = "proto3";
package smgglrs.module.v1;

service ModuleService {
  // Discovery
  rpc GetCapabilities(GetCapabilitiesRequest)
      returns (GetCapabilitiesResponse);

  // Tool execution
  rpc CallTool(CallToolRequest) returns (CallToolResponse);

  // Prompt rendering (optional)
  rpc GetPrompt(GetPromptRequest) returns (GetPromptResponse);

  // Resource access (optional)
  rpc ReadResource(ReadResourceRequest)
      returns (ReadResourceResponse);

  // Health check
  rpc Health(HealthRequest) returns (HealthResponse);
}

message GetCapabilitiesResponse {
  repeated ToolDefinition tools = 1;
  repeated PromptDefinition prompts = 2;
  repeated ResourceDefinition resources = 3;
}

message CallToolRequest {
  string name = 1;
  bytes arguments_json = 2;  // serde_json::Value as JSON bytes
  CallContext context = 3;
}

message CallToolResponse {
  repeated Content content = 1;
  bool is_error = 2;
}

message CallContext {
  string agent_name = 1;
  string session_id = 2;
  string data_label = 3;  // IFC taint label
  uint32 ring = 4;         // Privilege ring
}
```

**Module lifecycle (Terraform/Nomad-style):**

1. smgglrs reads config to determine which modules are gRPC services
2. smgglrs launches each module process (binary on disk)
3. Module starts gRPC server on Unix socket (or TCP port)
4. smgglrs connects as gRPC client, calls `GetCapabilities`
5. smgglrs registers discovered tools/prompts/resources
6. Tool calls forwarded to module via `CallTool` RPC
7. If module process dies, smgglrs detects broken connection and
   restarts it

**Configuration:**

```toml
# In-process module (existing)
[modules.docs]
enabled = true

# gRPC module (new)
[modules.custom_tool]
enabled = true
transport = "grpc"
binary = "/usr/libexec/smgglrs/modules/custom-tool"
socket = "/run/smgglrs/modules/custom-tool.sock"
# Or TCP for remote modules:
# address = "module-host:50051"

# Health check
health_interval_secs = 10
restart_on_failure = true
max_restarts = 3
```

**GrpcModule implementation:**

New crate: `smgglrs-grpc` (or extend `smgglrs-core`)

```rust
pub struct GrpcModule {
    name: String,
    client: ModuleServiceClient<Channel>,
    tools: Vec<ToolDefinition>,
    prompts: Vec<PromptDefinition>,
    resources: Vec<ResourceDefinition>,
}

impl GrpcModule {
    pub async fn connect(name: &str, endpoint: &str) -> Result<Self> {
        let client = ModuleServiceClient::connect(endpoint).await?;
        let caps = client.get_capabilities(()).await?;
        Ok(Self { name, client, tools: caps.tools, ... })
    }
}

impl Module for GrpcModule {
    fn name(&self) -> &str { &self.name }

    fn tools(&self) -> Vec<(ToolDefinition, ToolHandler)> {
        self.tools.iter().map(|def| {
            let client = self.client.clone();
            let handler: ToolHandler = Arc::new(move |args, ctx| {
                let mut client = client.clone();
                Box::pin(async move {
                    let req = CallToolRequest {
                        name: def.name.clone(),
                        arguments_json: serde_json::to_vec(&args)?,
                        context: Some(ctx.into()),
                    };
                    match client.call_tool(req).await {
                        Ok(resp) => resp.into_inner().into(),
                        Err(e) => CallToolResult::error(format!("grpc: {e}")),
                    }
                })
            });
            (def.clone(), handler)
        }).collect()
    }
}
```

**IFC propagation across gRPC:**

The `CallContext` message carries the IFC data label. The module
service must return a `data_label` in the response if the tool
call taints the output. smgglrs merges the returned label into the
session's taint tracker.

**Security:**

- Unix socket modules inherit filesystem permissions (same as
  OpenShell's driver model)
- TCP modules require mTLS or capability token authentication
- smgglrs's ACLs still apply — gRPC modules don't bypass the
  permission engine
- Crash isolation: a failing module process doesn't crash smgglrs

**Dependencies:**

- `tonic` (gRPC framework for Rust)
- `prost` (protobuf code generation)
- Optional: `tower` middleware for gRPC interceptors

### Multi-node scaling

With gRPC modules, smgglrs can scale beyond a single node:

```
Node A (gateway)          Node B (modules)
┌──────────────┐          ┌──────────────┐
│    smgglrs      │──gRPC──►│ docs module  │
│  (gateway)   │          │ git module   │
│              │──gRPC──►│ rag module   │
└──────────────┘          └──────────────┘
       │
       │ gRPC
       ▼
Node C (GPU)
┌──────────────┐
│ vision module│
│ voice module │
└──────────────┘
```

Heavy modules (vision, voice, RAG with large indices) run on
dedicated nodes. The gateway remains lightweight.

### Relationship to OpenShell

OpenShell uses the same pattern for its drivers: separate
processes communicating via gRPC over Unix sockets. The patterns
align:

| OpenShell | smgglrs |
|-----------|------|
| Compute driver | GrpcModule (tool provider) |
| Credentials driver | CredentialStore backend |
| Identity driver | OpenShellAuthenticator |

If smgglrs modules run inside OpenShell sandboxes, the gRPC
transport naturally bridges the sandbox boundary. The OpenShell
supervisor can proxy gRPC connections between smgglrs and its
modules.

### Priority

Medium. The current in-process Module trait is sufficient for
single-node deployments. gRPC modules become important for:

- Multi-node deployments (GPU modules on separate hosts)
- OpenShell integration (modules in sandboxes)
- Third-party module ecosystem (language-independent interface)
- Crash isolation (modules can't crash the gateway)

## Implementation roadmap

Maps to ROADMAP.md Phase 6 (OpenShell integration).

| Phase | Work | Priority | Depends on |
|-------|------|----------|-----------|
| **6a** | OpenShellAuthenticator in smgglrs-security | High | OpenShell identity spec |
| **6b** | A2A client in smgglrs-protocol + mesh builder in smgglrs-flow | High | — |
| **6c** | Remove libkrun stub, add OpenShell compute backend | Medium | OpenShell compute driver spec |
| **6d** | gRPC module protobuf + GrpcModule adapter | Medium | — |
| **6e** | Defense-in-depth network security model (OPA templates, integration tests, paper section) | Medium | 6a, 6c |
| **6f** | OpenShell credential backend for MappedCredentialStore | Low | OpenShell credentials driver spec |

## References

- OpenShell RFC 0001 — Core Architecture (Red Hat/NVIDIA, 2026-07)
- A2A v1.0 (Linux Foundation/AAIF, gRPC transport, signed Agent Cards)
- SPIFFE/SPIRE (CNCF, workload identity via mTLS)
- Terraform provider model (HashiCorp, gRPC plugins)
- DESIGN.md — smgglrs architecture
- DISCOVERY.md — A2A/AID/MCP discovery protocols
