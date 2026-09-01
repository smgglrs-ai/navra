# OpenShell Integration Architecture

Internal reference for OpenShell integration designs, gap roadmap,
and competitive analysis. User-facing content is in
`docs/content/docs/learn/openshell-integration.md`.

## OpenShellAuthenticator design

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

OpenShell's identity subsystem supports multiple backends:

| Backend | Token format | Verification |
|---------|-------------|-------------|
| SPIFFE/SPIRE | X.509 SVID (mTLS) or JWT-SVID | Verify against SPIRE agent trust bundle |
| OIDC/OAuth2 | JWT bearer token | Verify signature with IdP JWKS endpoint |
| Local OS | Unix socket peer credentials | Verify UID/GID via SO_PEERCRED |
| Static RBAC | OpenShell-signed JWT | Verify with OpenShell gateway's signing key |

**Token-to-identity mapping:**

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
mode = "spiffe"  # or "oidc", "local", "static"
trust_bundle = "/run/spire/agent/bundle.pem"

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
tokens), navra's `MappedCredentialStore` can be extended with an
`openshell` backend that reads credentials from the supervisor's
credential delivery channel:

```toml
[credentials.mapping.github-pat]
source = "openshell"
label = "github.pat"
```

### Priority

High for OpenShell-managed deployments. No impact on standalone
navra (OpenShellAuthenticator is skipped when not configured).

## A2A teammate mesh design

navra-flow currently uses three in-process communication
mechanisms for multi-agent coordination:

1. **Mailbox** -- tokio mpsc channels, in-memory only
2. **Blackboard** -- Arc<RwLock<HashMap>>, in-memory only
3. **Mesh tools** -- virtual tools injected into agent tool lists

These work for single-process flows but cannot span process
boundaries, containers, or OpenShell sandboxes.

### Architecture

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
+-----------------------------------------+
|              A2A Mesh (built by navra)   |
|                                         |
|  Teammate A <--A2A--> Teammate B        |
|      |                    |             |
|      +--------A2A---------+             |
|             |                           |
|          A2A|                           |
|             v                           |
|        Teammate C                       |
|                                         |
|  All traffic flows through navra gateway |
|  (IFC enforcement, audit logging, ACLs) |
+-----------------------------------------+
```

**Mesh construction by navra (on behalf of planner persona):**

1. **Teammate registration**: Each teammate gets an A2A endpoint
   on navra (e.g., `/a2a/teammates/{name}`). navra acts as the
   A2A gateway -- teammates send messages through navra, which
   enforces IFC and ACLs before relaying.

2. **Agent Card directory**: navra maintains a local directory of
   teammate Agent Cards.

3. **Capability scoping**: Each teammate receives a scoped
   capability token limiting which other teammates it can
   message, which tools it can call, and which data labels
   it can access.

4. **IFC enforcement**: A2A messages between teammates are
   subject to Bell-LaPadula no-write-down policy. Taint labels
   propagate through A2A task artifacts.

**A2A client in navra-protocol:**

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

The flow engine abstracts communication behind mesh tools. The
implementation can switch between in-process mode (tokio channels)
and A2A mode (JSON-RPC calls through navra gateway). Mesh tool
handlers detect whether a teammate is local or remote and route
accordingly.

**OpenShell integration:**

In OpenShell-managed deployments, each teammate runs in its own
sandbox. The A2A mesh maps naturally -- teammate-to-teammate A2A
traffic flows through both the OpenShell gateway relay AND
navra's IFC/ACL enforcement (double security).

### Priority

Medium-high. Required for multi-node and OpenShell deployments.
In-process mode remains the default for single-node.

## Sandbox mechanism: OpenShell replaces libkrun

### Current state

`navra-model-runtime` has three isolation backends:

| Backend | Status |
|---------|--------|
| **Direct** | Fully implemented (child process, no isolation) |
| **Podman** | Fully implemented (rootless containers, GPU passthrough) |
| **libkrun** | Stub only (feature flag exists, zero implementation) |

### Decision

Delegate sandboxing to OpenShell instead of implementing own
libkrun integration:

1. OpenShell already has libkrun (`openshell-vm` for microVM mode)
2. Defense in depth: OS-level + application-level are complementary
3. Scope clarity: navra is a tool gateway, not a compute platform

### Migration path

1. **Phase 1** (done): Keep Direct + Podman
2. **Phase 2** (OpenShell integration): Add `openshell` runtime
   backend that delegates to OpenShell's compute driver via gRPC
3. **Phase 3** (convergence): For OpenShell-managed deployments,
   `openshell` becomes the default runtime

## gRPC module architecture

### Problem

navra's Module trait is purely in-process. This prevents running
modules as separate processes, on separate nodes, in other
languages, or with independent deployment/versioning.

### Design: GrpcModule adapter

Add a `GrpcModule` struct that implements the `Module` trait by
forwarding calls to a gRPC service.

**Architecture:**

```
+-------------------------------------------------+
|              McpServer (navra-core)             |
|  tools: HashMap<String, RegisteredTool>          |
+-------------------------------------------------+
         ^              ^               ^
    Local Module   UpstreamModule   GrpcModule
    (in-process)   (MCP/JSON-RPC)   (gRPC)
         |              |               |
    Direct call    JSON-RPC over    gRPC over
    (Arc closure)  stdio/HTTP/SSE   Unix socket/TCP
```

**gRPC service contract:**

```protobuf
syntax = "proto3";
package navra.module.v1;

service ModuleService {
  rpc GetCapabilities(GetCapabilitiesRequest)
      returns (GetCapabilitiesResponse);
  rpc CallTool(CallToolRequest) returns (CallToolResponse);
  rpc GetPrompt(GetPromptRequest) returns (GetPromptResponse);
  rpc ReadResource(ReadResourceRequest)
      returns (ReadResourceResponse);
  rpc Health(HealthRequest) returns (HealthResponse);
}

message CallToolRequest {
  string name = 1;
  bytes arguments_json = 2;
  CallContext context = 3;
}

message CallContext {
  string agent_name = 1;
  string session_id = 2;
  string data_label = 3;  // IFC taint label
  uint32 ring = 4;         // Privilege ring
}
```

**Configuration:**

```toml
# gRPC module
[modules.custom_tool]
enabled = true
transport = "grpc"
binary = "/usr/libexec/navra/modules/custom-tool"
socket = "/run/navra/modules/custom-tool.sock"
health_interval_secs = 10
restart_on_failure = true
max_restarts = 3
```

**Relationship to OpenShell:**

| OpenShell | navra |
|-----------|-------|
| Compute driver | GrpcModule (tool provider) |
| Credentials driver | CredentialStore backend |
| Identity driver | OpenShellAuthenticator |

### Priority

Medium. Current in-process Module trait is sufficient for
single-node deployments. gRPC modules become important for
multi-node, OpenShell integration, third-party ecosystem.

## Implementation roadmap

Maps to ROADMAP.md Phase 6 (OpenShell integration).

| Phase | Work | Priority | Depends on |
|-------|------|----------|-----------|
| **6a** | OpenShellAuthenticator in navra-security | High | OpenShell identity spec |
| **6b** | A2A client in navra-protocol + mesh builder in navra-flow | High | -- |
| **6c** | Remove libkrun stub, add OpenShell compute backend | Medium | OpenShell compute driver spec |
| **6d** | gRPC module protobuf + GrpcModule adapter | Medium | -- |
| **6e** | Defense-in-depth network security model | Medium | 6a, 6c |
| **6f** | MCP tunnel compatibility (Anthropic + OpenAI) | High | -- |
| **6g** | NemoClaw MCP bridge alternative design | Medium | -- |
| **6h** | Privacy Router coordination | Medium | 8e |

## May 2026 updates (Red Hat Summit + Code with Claude)

### Claude self-hosted sandboxes (public beta, 2026-05-19)

Anthropic shipped self-hosted sandboxes for Claude Managed Agents.
Architecture: Anthropic hosts agent loop, customer hosts environment
worker that polls work queue, executes tool calls inside OpenShell
sandboxes, posts results back. Red Hat replaced default `spawn.sh`
with OpenShell sandboxes requiring no changes to Anthropic's worker
model.

### MCP tunnels (research preview, 2026-05-19)

Outbound-only encrypted connection from customer network to
Anthropic's routing. Agents reach private MCP servers through the
tunnel. navra is the natural target -- one tunnel, one gateway,
aggregated security.

### Three-mode sandboxing taxonomy

| Mode | What's sandboxed | navra role |
|------|-----------------|--------------|
| **Mode 1** | Entire agent | navra inside sandbox alongside agent |
| **Mode 2** | Execution environment (brain decoupled from hands) | navra as tool execution layer |
| **Mode 3** | Code execution only | navra irrelevant |

## Competitor analysis

### NemoClaw MCP bridge alternative

NemoClaw Issue #566 proposes per-server MCP bridges (stdio-to-HTTP
proxy per server, each with own egress rule). navra is
architecturally superior: one gateway, one egress rule, aggregated
security. The NemoClaw proposal validates the single-gateway model.

### Layer 0 + Layer 1 architecture (validated)

Deconvolute Labs analysis confirms OpenShell operates at OS/network
layers and cannot inspect MCP request bodies (tool names, arguments,
schemas). navra sits at exactly this application layer:
- Layer 0 (OpenShell): kernel sandbox, Landlock, seccomp, namespaces
- Layer 1 (navra): application-layer governance, IFC, ACLs, ML safety

### New competitors at Layer 1

- DefenseClaw (Cisco): admission control + runtime guardrails +
  OpenShell support. Lacks IFC.
- AgentGuard (chitinhq, Issue #1036): governance hooks. Similar
  thesis, less mature.

## Gap closure roadmap: from 100x to 1000x (July 2026)

The Layer 0 + Layer 1 architecture is sound. The gaps below are
where synergy leaks out -- closing them turns defense-in-depth
into a unified security fabric.

### Gap 1: Unified policy language with formal equivalence

**Problem.** navra evaluates Cedar policies (application-layer).
OpenShell evaluates OPA/Rego policies (network-layer). Neither
checks consistency between the two systems' policies.

**Solution: dual-engine with proven equivalence.**

navra adds OPA/Rego as a second policy engine alongside Cedar.
The operator writes policy in either language. navra transpiles
the network-relevant subset between them.

**Formal equivalence proof.** Both Cedar and Rego have formal
semantics. For the bounded policy domain, navra can encode both
decision models as SMT constraints and prove equivalence.

Ship as `navra policy verify --equivalence` and
`navra policy verify --combined`.

### Gap 2: IFC taint visibility at the egress proxy

**Problem.** navra's IFC taint labels travel as MCP-level metadata.
OpenShell's egress proxy evaluates on network-level attributes.
The proxy cannot see taint labels.

**Solution.** navra publishes taint context to the sandbox
supervisor via sidecar protocol. The OPA policy gains a
`taint_labels` input.

### Gap 3: Bidirectional policy sync

**Problem.** navra generates OpenShell policy YAML, but there is
no feedback loop. If an OpenShell admin tightens network policy,
navra continues offering tools that call blocked endpoints.

**Solution.** navra watches OpenShell's policy version via the
supervisor session. On change, navra diffs the effective network
allowlist against its tool-to-endpoint mapping and disables
unreachable tools or emits warnings.

### Gap 4: Unified audit trail

**Problem.** OpenShell logs OCSF security events. navra logs its
own audit trail. Correlating them requires manual timestamp join.

**Solution.** navra injects OpenTelemetry trace context into every
outbound request. The egress proxy propagates trace IDs into OCSF
events. A shared collector joins on trace ID.

### Gap 5: Unified inference routing

**Problem.** OpenShell has `inference.local` (strips agent
credentials, injects backend keys). navra has model runtime
(provisions sandboxes, manages lifecycle). The two inference paths
are independent.

**Solution.** Register navra as the `inference.local` backend in
OpenShell's router configuration. Single credential store, single
audit trail, single policy enforcement point.

### Recommended order

| Gap | Effort | Impact | Depends on |
|-----|--------|--------|------------|
| **4. Unified audit** | Low-Medium | Single-pane incident response | OTel trace propagation |
| **3. Policy sync** | Medium | Eliminates silent tool failures | Supervisor session watch |
| **1. Cedar-Rego equivalence** | High | Single policy language, proven consistent | OPA engine (NAVRA-184), Z3 bindings |
| **2. Taint at proxy** | Medium | Closes semantic exfiltration path | Supervisor sidecar protocol |
| **5. Inference unification** | Medium | Single credential/policy/audit path | OpenShell router config |

## References

- OpenShell RFC 0001 -- Core Architecture (Red Hat/NVIDIA, 2026-07)
- A2A v1.0 (Linux Foundation/AAIF, gRPC transport, signed Agent Cards)
- SPIFFE/SPIRE (CNCF, workload identity via mTLS)
- Terraform provider model (HashiCorp, gRPC plugins)
- [Red Hat: Claude self-hosted sandboxes on OpenShell](https://www.redhat.com/en/blog/bringing-claude-self-hosted-sandboxes-to-openshell-on-red-hat-ai)
- [Red Hat: Security-enhanced agent execution](https://www.redhat.com/en/blog/red-hat-ai-and-openshell-driving-security-enhanced-agent-execution-for-enterprise-ai)
- [Anthropic: MCP tunnels and self-hosted sandboxes](https://thenewstack.io/anthropic-mcp-tunnels-sandboxes/)
- [NemoClaw MCP bridge proposal (Issue #566)](https://github.com/NVIDIA/NemoClaw/issues/566)
- [NemoClaw MCPS signing (Issue #204)](https://github.com/NVIDIA/NemoClaw/issues/204)
- [Deconvolute Labs: OpenShell MCP gap](https://deconvoluteai.com/blog/nvidia-openshell-mcp-protocol-layer)
- [DefenseClaw (Cisco)](https://github.com/cisco-ai-defense/defenseclaw)
