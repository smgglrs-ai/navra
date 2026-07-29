# OpenShell Integration Design

This document describes how navra integrates with OpenShell, the
Red Hat/NVIDIA secure sandbox platform for autonomous agents.

**Status**: Design phase (2026-04-22).

## Relationship

OpenShell and navra operate at different layers of the agent stack:

| Concern | OpenShell | navra |
|---------|-----------|------|
| What it manages | Compute environments (sandboxes) | Tool access (MCP protocol) |
| Security focus | OS-level isolation (Landlock, seccomp, namespaces) | Application-level (ACLs, IFC, safety filters, hooks) |
| Protocol | gRPC (all internal communication) | MCP (JSON-RPC 2.0 over Streamable HTTP + SSE) |
| Extensibility | gRPC drivers as separate processes | Module trait (in-process) + UpstreamModule (JSON-RPC) |
| Agent comms | Sandbox-to-sandbox relay through gateway | navra-flow (mailbox, blackboard, A2A) |
| Isolation | libkrun microVM, Podman, Kata, gVisor | Podman (model runtime only) |

The natural integration: **agents run inside OpenShell sandboxes
and connect to navra for tool access**. OpenShell provides the
"where agents run"; navra provides "what agents can do."

In the AI OS analogy (see Phase 8 papers): OpenShell is the
**process isolation layer** (cgroups, namespaces, microVMs),
navra is the **syscall interface** (tool access control, IFC).

## Defense in depth: network + application firewalling

The combination of OpenShell and navra creates two independent
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
| navra gateway | MCP (HTTP) + A2A (HTTP) | Tools + teammate mesh |
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

### Application-level enforcement (navra)

Even when a sandbox can reach navra over the network, navra
enforces what the agent inside that sandbox can actually do:

- **Tool ACLs**: agent can only call specific tools (e.g.,
  `file_read`, `git_status` — not `git_commit`)
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
│    ├─ tool call   → proxy → navra gateway ✅        │
│    │                 └─► navra ACL check            │
│    │                 └─► navra IFC check            │
│    │                 └─► navra safety filter         │
│    ├─ A2A message → proxy → OpenShell gateway      │
│    │                 └─► relay policy check         │
│    │                 └─► navra IFC check (at dest)  │
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

**OpenShell without navra**: The agent can reach navra over the
network, but without navra's ACLs it could call any tool, read
any path, and ignore IFC labels. A compromised agent process
has unrestricted tool access.

**navra without OpenShell**: The agent respects navra's ACLs at
the application layer, but without OS-level containment the
attack surface depends on what else is in the image. In a
minimal container (agent binary only, no shell, no compiler,
no interpreter), OS-level controls (seccomp, Landlock, network
namespace) already block most bypass vectors. The real threat
is **tool-mediated**: if the agent has access to MCP tools like
`file_write` + `exec_run`, or if the image contains a scripting
runtime (Python, Node), the agent can compose a multi-step
attack through legitimate MCP channels that navra alone governs.

**Both together**: OpenShell prevents the agent from reaching
anything except navra and its model. navra prevents the agent
from doing anything except what its capability token allows.
Compromising either layer alone is insufficient for a full
breach.

This maps to the AI OS analogy: OpenShell is mandatory access
control (SELinux/AppArmor), navra is discretionary access
control (Unix permissions + capability tokens). Defense in
depth requires both.

### Refined threat model: minimal containers

In production, the navra-agent container image contains only the
agent binary — no shell, no compiler, no interpreter, no cURL.
This eliminates the "bypass MCP via raw sockets" threat:

- **seccomp** blocks `socket(SOCK_RAW)` regardless of caller
- **Landlock** prevents writing new executables to disk
- **Network namespace** forces all `SOCK_STREAM` through the
  egress proxy, which enforces OPA policy
- **No toolchain** means nothing to compile or interpret

The layers are not redundant fallbacks for the same threat —
they govern **different attack surfaces entirely**:

- **OpenShell makes MCP the only channel.** The agent cannot
  reach anything except navra's MCP endpoint and its model.
- **navra makes MCP the right channel.** Every tool call is
  checked against ACLs, IFC labels, and safety filters.

#### Tool-mediated attack path

The remaining attack surface is **tool composition through
legitimate MCP channels**. If upstream MCP servers expose both
a write tool and an execution tool, an agent can chain them:

```
1. file_write("/tmp/exfil.py", "import socket; ...")
   → navra ACL: allowed (file_write to /tmp permitted)
   → OpenShell Landlock: allowed (but /tmp is noexec)

2. exec_run("python3 /tmp/exfil.py")
   → navra ACL: allowed (exec_run permitted)
   → OpenShell: BLOCKED — no Python in minimal image

3. If Python IS in the image:
   → python3 opens socket → network namespace → proxy
   → OpenShell OPA: DENIED (destination not in allowlist)
   → Even if destination IS allowed, navra IFC can taint
     the data flowing from step 1 → step 2
```

Each layer catches different steps. The full chain requires
compromising both OpenShell policy (network allowlist) AND
navra policy (ACL + IFC) simultaneously.

#### Interpreter-in-image risk

When the container includes a scripting runtime (for code
execution tools, REPL features, etc.), the attack surface
expands. The agent can `import socket` directly without
writing a file. Mitigations:

| Step | OpenShell | navra |
|------|-----------|-------|
| Open socket | Network namespace → proxy | — |
| Connect out | OPA destination check | — |
| Send data | — | IFC taint on the data's origin |
| Receive response | — | Safety filter on ingested content |

The semantic taint gap applies here: navra tracks explicit
taint labels but cannot detect implicit information flow
through LLM reasoning (see adversarial limits documentation).

## 1. OpenShell-provided identity

### Problem

navra currently authenticates agents via two mechanisms:

1. **BLAKE3 tokens** (legacy) — pre-shared bearer tokens hashed
   with BLAKE3, mapped to `AgentIdentity` via config.
2. **Capability tokens** (modern) — self-contained CBOR tokens
   signed with Ed25519, carrying inline capabilities.

Both require navra to manage credentials independently. When an
agent runs inside an OpenShell sandbox, the OpenShell supervisor
has already established the agent's identity through the
gateway's identity subsystem (SPIFFE, OIDC, local OS, or static
RBAC). Re-authenticating at the navra layer is redundant and
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
navra (ChainAuthenticator)
    |-- 1. CapabilityAuthenticator (try navra-native cap tokens)
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
OpenShell token and maps them to navra's `AgentIdentity`:

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

# Permission mapping: OpenShell labels -> navra permission sets
[auth.openshell.mapping]
"role=worker"    = "restricted"
"role=lead"      = "developer"
"role=admin"     = "admin"
```

**Implementation in navra-security:**

- New file: `navra-security/src/auth/openshell.rs`
- New struct: `OpenShellAuthenticator` implementing `Authenticator`
- Add to `ChainAuthenticator` between capability and legacy auth
- Dependencies: `jsonwebtoken` (JWT verification), optionally
  `spiffe` crate for SVID handling

**Credential delegation:**

When OpenShell's credential subsystem resolves secrets (API keys,
tokens), it delivers them to the supervisor. navra's
`MappedCredentialStore` can be extended with an `openshell` backend
that reads credentials from the supervisor's credential delivery
channel instead of the local keyring:

```toml
[credentials.mapping.github-pat]
source = "openshell"
label = "github.pat"
```

This avoids duplicating credential storage between OpenShell and navra.

### Priority

High for OpenShell-managed deployments. No impact on standalone
navra (OpenShellAuthenticator is skipped when not configured).

## 2. A2A protocol for teammate communications

### Problem

navra-flow currently uses three in-process communication
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
communication. navra already has:

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
navra (flow engine)
    |
    | Builds A2A mesh:
    |   1. For each teammate, create/assign an A2A endpoint
    |   2. Register teammate Agent Cards in local directory
    |   3. Configure routing rules (who can talk to whom)
    |   4. Mint scoped capability tokens per teammate
    v
┌─────────────────────────────────────────────┐
│              A2A Mesh (built by navra)       │
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
│  All traffic flows through navra gateway     │
│  (IFC enforcement, audit logging, ACLs)     │
└─────────────────────────────────────────────┘
```

**Mesh construction by navra (on behalf of planner persona):**

The planner persona defines the flow (teammates, dependencies,
communication patterns). navra's flow engine translates this into
an A2A mesh:

1. **Teammate registration**: Each teammate gets an A2A endpoint
   on navra (e.g., `/a2a/teammates/{name}`). navra acts as the
   A2A gateway — teammates don't talk directly to each other;
   they send A2A messages through navra, which enforces IFC and
   ACLs before relaying.

2. **Agent Card directory**: navra maintains a local directory of
   teammate Agent Cards. When teammate A needs to discover
   teammate B's capabilities, it queries navra's directory
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

**A2A client in navra-protocol:**

Add an `A2aClient` struct to `navra-protocol/src/a2a_client.rs`:

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
- **A2A mode** (new): A2A JSON-RPC calls through navra gateway

The mesh tool handlers detect whether a teammate is local
(in-process) or remote (A2A endpoint) and route accordingly.
This preserves backward compatibility.

**OpenShell integration:**

In OpenShell-managed deployments, each teammate runs in its own
sandbox. The A2A mesh maps naturally:

- Each sandbox has a supervisor connection to the OpenShell gateway
- Each sandbox runs an navra instance (or connects to a shared one)
- Teammate-to-teammate A2A traffic flows through the OpenShell
  gateway relay AND through navra's IFC/ACL enforcement
- Double security: OpenShell enforces sandbox-level policy,
  navra enforces tool-level policy

### Priority

Medium-high. Required for multi-node and OpenShell deployments.
In-process mode remains the default for single-node.

## 3. Sandbox mechanism: OpenShell replaces libkrun

### Current state (honest assessment)

`navra-model-runtime` has three isolation backends:

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
   (Landlock, seccomp, network namespaces, microVMs). navra
   provides application-level security (ACLs, IFC, safety
   filters). These are complementary layers, not redundant.

3. **Scope clarity**: navra is a tool access gateway, not a compute
   platform. Managing sandbox lifecycle is OpenShell's job.

4. **Shared libkrun expertise**: Both projects target libkrun on
   Linux. Coordinating on one implementation avoids divergence.

**What changes in navra:**

- Remove the `libkrun` feature flag from `navra-model-runtime`
  (or mark it explicitly as `# Delegated to OpenShell`)
- Keep Direct and Podman backends for standalone navra (no
  OpenShell dependency required)
- Add an `openshell` backend to `navra-model-runtime` that
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
navra (model serve request)
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
    | navra connects to llama-server HTTP endpoint
    v
Inference ready
```

navra does NOT need to know which isolation backend OpenShell
uses. It requests a sandbox with labels (e.g., `gpu=required`,
`isolation=microvm`) and OpenShell's compute driver handles the
rest.

### Migration path

1. **Phase 1** (now): Keep Direct + Podman. Remove libkrun
   pretense.
2. **Phase 2** (OpenShell integration): Add `openshell` runtime
   backend that delegates to OpenShell's compute driver via gRPC.
3. **Phase 3** (convergence): For OpenShell-managed deployments,
   `openshell` becomes the default runtime. Standalone navra
   continues to use Podman.

## 4. gRPC module architecture

### Problem

navra's Module trait is purely in-process:

```rust
pub trait Module: Send + Sync + 'static {
    fn name(&self) -> &str;
    fn tools(&self) -> Vec<(ToolDefinition, ToolHandler)>;
    fn prompts(&self) -> Vec<(PromptDefinition, PromptHandler)>;
    fn resources(&self) -> Vec<(ResourceDefinition, ResourceHandler)>;
}
```

Handlers are `Arc<dyn Fn>` closures called directly. This is
fast but limits modules to the navra process. It prevents:

- Running modules as separate processes (crash isolation)
- Running modules on separate nodes (horizontal scaling)
- Writing modules in other languages
- Independent module deployment and versioning

OpenShell's RFC explicitly rejected the in-process trait approach
for their driver interfaces (see Alternatives section 1),
choosing gRPC services instead. The same arguments apply to
navra's module system.

### Design: GrpcModule adapter

Add a `GrpcModule` struct that implements the `Module` trait by
forwarding calls to a gRPC service. This mirrors the existing
`UpstreamModule` pattern (which adapts MCP servers to the Module
trait) but uses gRPC instead of JSON-RPC.

**Architecture:**

```
┌─────────────────────────────────────────────────┐
│              McpServer (navra-core)             │
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
package navra.module.v1;

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

1. navra reads config to determine which modules are gRPC services
2. navra launches each module process (binary on disk)
3. Module starts gRPC server on Unix socket (or TCP port)
4. navra connects as gRPC client, calls `GetCapabilities`
5. navra registers discovered tools/prompts/resources
6. Tool calls forwarded to module via `CallTool` RPC
7. If module process dies, navra detects broken connection and
   restarts it

**Configuration:**

```toml
# In-process module (existing)
[modules.file]
enabled = true

# gRPC module (new)
[modules.custom_tool]
enabled = true
transport = "grpc"
binary = "/usr/libexec/navra/modules/custom-tool"
socket = "/run/navra/modules/custom-tool.sock"
# Or TCP for remote modules:
# address = "module-host:50051"

# Health check
health_interval_secs = 10
restart_on_failure = true
max_restarts = 3
```

**GrpcModule implementation:**

New crate: `navra-grpc` (or extend `navra-core`)

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
call taints the output. navra merges the returned label into the
session's taint tracker.

**Security:**

- Unix socket modules inherit filesystem permissions (same as
  OpenShell's driver model)
- TCP modules require mTLS or capability token authentication
- navra's ACLs still apply — gRPC modules don't bypass the
  permission engine
- Crash isolation: a failing module process doesn't crash navra

**Dependencies:**

- `tonic` (gRPC framework for Rust)
- `prost` (protobuf code generation)
- Optional: `tower` middleware for gRPC interceptors

### Multi-node scaling

With gRPC modules, navra can scale beyond a single node:

```
Node A (gateway)          Node B (modules)
┌──────────────┐          ┌──────────────┐
│    navra      │──gRPC──►│ docs module  │
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

| OpenShell | navra |
|-----------|------|
| Compute driver | GrpcModule (tool provider) |
| Credentials driver | CredentialStore backend |
| Identity driver | OpenShellAuthenticator |

If navra modules run inside OpenShell sandboxes, the gRPC
transport naturally bridges the sandbox boundary. The OpenShell
supervisor can proxy gRPC connections between navra and its
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
| **6a** | OpenShellAuthenticator in navra-security | High | OpenShell identity spec |
| **6b** | A2A client in navra-protocol + mesh builder in navra-flow | High | — |
| **6c** | Remove libkrun stub, add OpenShell compute backend | Medium | OpenShell compute driver spec |
| **6d** | gRPC module protobuf + GrpcModule adapter | Medium | — |
| **6e** | Defense-in-depth network security model (OPA templates, integration tests, paper section) | Medium | 6a, 6c |
| **6f** | MCP tunnel compatibility (Anthropic + OpenAI) | High | — |
| **6g** | NemoClaw MCP bridge alternative design | Medium | — |
| **6h** | Privacy Router coordination | Medium | 8e |

## May 2026 updates (Red Hat Summit + Code with Claude)

### Claude self-hosted sandboxes (public beta, 2026-05-19)

Anthropic shipped self-hosted sandboxes for Claude Managed Agents.
Architecture: Anthropic hosts agent loop, customer hosts environment
worker that polls Anthropic's work queue, executes tool calls inside
OpenShell sandboxes, posts results back. Worker uses environment key,
never org API key. Red Hat replaced default `spawn.sh` with OpenShell
sandboxes requiring **no changes to Anthropic's worker model**.

### MCP tunnels (research preview, 2026-05-19)

Outbound-only encrypted connection from customer network to Anthropic's
routing. Agents reach private MCP servers through the tunnel. navra
is the natural target — one tunnel, one gateway, aggregated security.

### Three-mode sandboxing taxonomy

| Mode | What's sandboxed | navra role |
|------|-----------------|--------------|
| **Mode 1** | Entire agent | navra inside sandbox alongside agent |
| **Mode 2** | Execution environment (brain decoupled from hands) | navra as tool execution layer |
| **Mode 3** | Code execution only | navra irrelevant (agent has direct credentials) |

### NemoClaw MCP bridge alternative

NemoClaw Issue #566 proposes per-server MCP bridges (stdio-to-HTTP
proxy per server, each with own egress rule). navra is architecturally
superior: one gateway, one egress rule, aggregated security. The
NemoClaw proposal validates the single-gateway model.

### Layer 0 + Layer 1 architecture (validated)

Deconvolute Labs analysis confirms OpenShell operates at OS/network
layers and **cannot inspect MCP request bodies** (tool names, arguments,
schemas). navra sits at exactly this application layer:
- Layer 0 (OpenShell): kernel sandbox, Landlock, seccomp, namespaces
- Layer 1 (navra): application-layer governance, IFC, ACLs, ML safety

### New competitors at Layer 1

- DefenseClaw (Cisco): admission control + runtime guardrails + OpenShell
  support. Lacks IFC.
- AgentGuard (chitinhq, Issue #1036): governance hooks. Similar thesis,
  less mature.

## Closing the seams: from 100x to 1000x (July 2026)

The Layer 0 + Layer 1 architecture is sound, and the integration
is production-level. But the two layers operate as independent
systems that happen to talk to each other. The gaps below are
where **synergy leaks out** — closing them turns defense-in-depth
into a unified security fabric.

### Gap 1: Unified policy language with formal equivalence

**Problem.** navra evaluates Cedar policies (application-layer
tool governance). OpenShell evaluates OPA/Rego policies
(network-layer egress control). Each system has its own formal
verification:

- **navra**: Kani/Verus prove implementation correctness
  (Rust code). TLA+ specs prove policy properties —
  capability delegation attenuation, taint monotonicity,
  session isolation, flow concurrency safety. Cedar policies
  are validated by the `cedar-policy` engine at load time.
- **OpenShell**: Z3 encodes OPA/Rego network policies as
  constraints and checks for data exfiltration paths and
  write-bypass violations.

Neither checks **consistency between the two systems'
policies**. A navra Cedar rule might permit a tool whose
network calls OpenShell's Rego policy blocks (silent failure),
or OpenShell might permit an endpoint that navra's Cedar
rules and IFC should govern (invisible exfiltration path).

**What breaks.** Operators maintain two policy languages for
the same deployment. Policy drift between them creates gaps
or contradictions that only manifest at runtime. No tooling
catches this at deploy time.

**Solution: dual-engine with proven equivalence.**

navra adds OPA/Rego as a second policy engine alongside Cedar
(same feature-gate pattern). The operator writes policy in
**either** language. navra transpiles the network-relevant
subset between them:

```
Operator writes Cedar          Operator writes Rego
        │                              │
        ▼                              ▼
navra Cedar engine             navra OPA engine
        │                              │
        ├── transpile ─────────────────┤
        │   network subset             │
        ▼                              ▼
OpenShell OPA proxy ◄──── Rego ────── navra exports
```

**Formal equivalence proof.** Both Cedar and Rego have formal
semantics (Cedar: Amazon's Dafny spec; Rego: partial
evaluation to constraint form). For the bounded policy domain
(finite tool names, actions, resource types, context fields),
navra can:

1. Parse both policy representations into an intermediate
   decision model (tool → action → context → permit/deny)
2. Encode both decision models as SMT constraints
3. Prove equivalence: for all inputs, both engines produce
   the same decision
4. If not equivalent, produce a counterexample showing the
   divergent input

This is tractable because the policy domain is finite — not
arbitrary programs. AWS Zelkova proves similar properties for
IAM policies. The `openshell-prover` crate already has Z3
bindings that navra can reuse.

**Consistency check.** Beyond equivalence, the combined model
verifies: (a) every tool navra permits has a reachable network
path through OpenShell, (b) every network path OpenShell
permits is governed by a navra policy rule or IFC label,
(c) no tainted data flows to an unmonitored endpoint.

Ship as `navra policy verify --equivalence` (proof between
Cedar and Rego) and `navra policy verify --combined` (cross-
layer consistency).

### Gap 2: IFC taint visibility at the egress proxy

**Problem.** navra's IFC taint labels travel as MCP-level
metadata (X-Navra-Taint headers, side-channel labels). OpenShell's
egress proxy evaluates OPA policy on network-level attributes
(destination host, port, binary identity, HTTP method/path).
The proxy cannot see taint labels — it doesn't know that the
data in a permitted HTTPS POST carries a `pii` or `secret`
taint.

**What breaks.** An agent reads PII via a tainted tool call,
then sends it to an allowed endpoint (e.g., a logging service
on the allowlist). navra sees the taint but the data leaves
through a channel navra doesn't govern (direct HTTPS, not MCP).
OpenShell allows the connection because the destination is
permitted.

**Solution sketch.** navra publishes taint context to the
sandbox supervisor via a lightweight sidecar protocol (Unix
socket or gRPC stream). The OPA policy gains a `taint_labels`
input that can express rules like "deny egress to logging
endpoints when payload originates from a pii-tainted tool
call." This bridges L0 and L1 without requiring the proxy to
understand MCP.

### Gap 3: Bidirectional policy sync

**Problem.** navra generates OpenShell policy YAML (NAVRA-160),
but there is no feedback loop. If an OpenShell admin tightens
network policy (removes an endpoint), navra continues offering
tools that call that endpoint. Tool calls succeed at the ACL
layer but fail silently at the proxy.

**What breaks.** Agents experience unexplained failures. The
operator sees denials in OpenShell logs but navra reports
success. No single pane of glass shows the conflict.

**Solution sketch.** navra watches OpenShell's policy version
via the supervisor session (already a gRPC stream). On policy
change, navra diffs the effective network allowlist against
its tool→endpoint mapping and either (a) disables tools whose
endpoints are no longer reachable, or (b) emits a warning to
the operator. Symmetric: when navra policy changes, it pushes
an updated network policy hint to OpenShell.

### Gap 4: Unified audit trail

**Problem.** OpenShell logs OCSF security events (network
denials, sandbox lifecycle). navra logs its own audit trail
(tool calls, IFC decisions, safety filter activations). Correlating
"tool call X → network request Y → proxy decision Z" requires
manual timestamp join across two separate event streams.

**What breaks.** Incident response is slow. A security analyst
investigating an exfiltration attempt must cross-reference two
log systems, reconstruct causality manually, and hope the
clocks are synchronized.

**Solution sketch.** navra injects a trace ID (OpenTelemetry
trace context) into every outbound request. The egress proxy
propagates this trace ID into its OCSF events. A shared event
collector (or navra's own audit log) can join on trace ID to
produce a single causal chain: agent intent → tool call →
ACL decision → network request → proxy decision → response →
safety filter. Ship as structured OCSF events from navra
(already partially implemented via navra-ocsf concepts) with
OpenShell trace ID correlation.

### Gap 5: Unified inference routing

**Problem.** OpenShell has `inference.local` (strips agent
credentials, injects backend keys, routes to model APIs).
navra has `navra-model-runtime` (provisions sandboxes, manages
model lifecycle). The two inference paths are independent —
an agent might hit `inference.local` directly (OpenShell
manages credentials) or go through navra's model runtime
(navra manages credentials), with different security policies
applying to each path.

**What breaks.** Credential management is split. Audit trails
diverge. An agent could be denied a model by navra's ACLs but
reach the same model through `inference.local`, or vice versa.

**Solution sketch.** Register navra as the `inference.local`
backend in OpenShell's router configuration. All inference
requests flow: agent → `inference.local` → OpenShell strips
agent creds → navra model runtime → navra applies ACL + IFC +
safety filter → navra injects backend creds → model API.
Single credential store, single audit trail, single policy
enforcement point for inference.

### Summary: gap closure roadmap

| Gap | Effort | Impact | Depends on |
|-----|--------|--------|------------|
| **1. Cedar↔Rego equivalence** | High | Single policy language, proven consistent across layers | OPA engine in navra (NAVRA-184), Z3 bindings |
| **2. Taint at proxy** | Medium | Closes the semantic exfiltration path | Supervisor sidecar protocol |
| **3. Policy sync** | Medium | Eliminates silent tool failures | Supervisor session watch |
| **4. Unified audit** | Low-Medium | Enables single-pane incident response | OTel trace propagation |
| **5. Inference unification** | Medium | Single credential/policy/audit path | OpenShell router config |

Recommended order: **4 → 3 → NAVRA-184 (OPA engine) → 1 → 2 → 5.**
Gaps 4 and 3 are lowest-friction wins. NAVRA-184 (OPA engine)
is the prerequisite for gap 1 and also feeds gap 2 (taint
rules in Rego). Gap 1 is the most ambitious but has the
highest long-term payoff — operators write one policy, both
layers enforce it, and the proof guarantees they agree. Gap 5
is the cleanest architectural simplification.

## References

- OpenShell RFC 0001 — Core Architecture (Red Hat/NVIDIA, 2026-07)
- A2A v1.0 (Linux Foundation/AAIF, gRPC transport, signed Agent Cards)
- SPIFFE/SPIRE (CNCF, workload identity via mTLS)
- Terraform provider model (HashiCorp, gRPC plugins)
- DESIGN.md — navra architecture
- DISCOVERY.md — A2A/AID/MCP discovery protocols
- [Red Hat: Claude self-hosted sandboxes on OpenShell](https://www.redhat.com/en/blog/bringing-claude-self-hosted-sandboxes-to-openshell-on-red-hat-ai)
- [Red Hat: Security-enhanced agent execution](https://www.redhat.com/en/blog/red-hat-ai-and-openshell-driving-security-enhanced-agent-execution-for-enterprise-ai)
- [Anthropic: MCP tunnels and self-hosted sandboxes](https://thenewstack.io/anthropic-mcp-tunnels-sandboxes/)
- [NemoClaw MCP bridge proposal (Issue #566)](https://github.com/NVIDIA/NemoClaw/issues/566)
- [NemoClaw MCPS signing (Issue #204)](https://github.com/NVIDIA/NemoClaw/issues/204)
- [Deconvolute Labs: OpenShell MCP gap](https://deconvoluteai.com/blog/nvidia-openshell-mcp-protocol-layer)
- [DefenseClaw (Cisco)](https://github.com/cisco-ai-defense/defenseclaw)
