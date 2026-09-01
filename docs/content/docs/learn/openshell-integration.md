+++
title = "OpenShell Integration"
description = "MAC + DAC defense in depth with OpenShell sandboxes."
weight = 25
template = "docs/page.html"

[extra]
toc = true
+++

OpenShell is a Red Hat/NVIDIA secure sandbox platform for
autonomous agents. navra integrates with OpenShell to provide
defense in depth: OpenShell handles OS-level isolation while navra
handles application-level tool governance.

## Relationship

OpenShell and navra operate at different layers of the agent stack:

| Concern | OpenShell | navra |
|---------|-----------|-------|
| What it manages | Compute environments (sandboxes) | Tool access (MCP protocol) |
| Security focus | OS-level isolation (Landlock, seccomp, namespaces) | Application-level (ACLs, IFC, safety filters, hooks) |
| Protocol | gRPC (all internal communication) | MCP (JSON-RPC 2.0 over Streamable HTTP + SSE) |
| Extensibility | gRPC drivers as separate processes | Module trait (in-process) + UpstreamModule (JSON-RPC) |
| Agent comms | Sandbox-to-sandbox relay through gateway | navra-flow (mailbox, blackboard, A2A) |
| Isolation | libkrun microVM, Podman, Kata, gVisor | Podman (model runtime only) |

The natural integration: **agents run inside OpenShell sandboxes
and connect to navra for tool access**. OpenShell provides the
"where agents run"; navra provides "what agents can do."

In the AI OS analogy: OpenShell is the **process isolation layer**
(cgroups, namespaces, microVMs), navra is the **syscall interface**
(tool access control, IFC).

## Defense in depth: MAC + DAC

The combination of OpenShell and navra creates two independent
security enforcement layers. Neither alone is sufficient.

### Sandbox network policy (OpenShell -- MAC)

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

Everything else is **blocked** -- no internet, no DNS to
arbitrary hosts, no lateral movement to other sandboxes except
through the gateway relay with policy evaluation.

### Application-level enforcement (navra -- DAC)

Even when a sandbox can reach navra over the network, navra
enforces what the agent inside that sandbox can actually do:

- **Tool ACLs**: agent can only call specific tools (e.g.,
  `file_read`, `git_status` -- not `git_commit`)
- **Path ACLs**: tool calls restricted to specific paths (e.g.,
  `/home/projects/foo/**` -- deny wins)
- **IFC taint propagation**: agent tainted with `Sensitive` data
  cannot write to `Public`-clearance teammates (Bell-LaPadula
  no-write-down)
- **Safety filters**: content scanned for secrets, PII, harmful
  content before crossing tool boundaries
- **Capability scoping**: each teammate's token limits operations,
  tools, paths, and credential access

### Combined sandbox model

```text
+-- OpenShell Sandbox (agent teammate) --------------------+
|                                                          |
|  Agent process                                           |
|    +-- model call  -> proxy -> model endpoint  OK        |
|    +-- tool call   -> proxy -> navra gateway   OK        |
|    |                  +-> navra ACL check                 |
|    |                  +-> navra IFC check                 |
|    |                  +-> navra safety filter              |
|    +-- A2A message -> proxy -> OpenShell gateway          |
|    |                  +-> relay policy check              |
|    |                  +-> navra IFC check (at dest)       |
|    +-- curl google.com -> proxy -> OPA DENY              |
|    +-- raw IP connect  -> netns blocks                   |
|                                                          |
|  Supervisor (OS-level security boundary)                 |
|    +-- HTTP CONNECT proxy (all outbound traffic)         |
|    +-- OPA policy engine (network allowlist)             |
|    +-- Landlock (filesystem isolation)                   |
|    +-- seccomp (syscall filtering)                       |
|    +-- gRPC -> OpenShell gateway (outbound only)         |
+----------------------------------------------------------+
```

### Why both layers are necessary

**OpenShell without navra**: The agent can reach navra over the
network, but without navra's ACLs it could call any tool, read
any path, and ignore IFC labels. A compromised agent process
has unrestricted tool access.

**navra without OpenShell**: The agent respects navra's ACLs at
the application layer, but without OS-level containment a
compromised agent process can bypass navra entirely: open raw
sockets, exfiltrate data, read arbitrary files via the OS.
In a minimal container (agent binary only, no shell, no compiler),
OS-level controls already block most bypass vectors. The real
threat is **tool-mediated**: if the agent has access to tools
like `file_write` + `exec_run`, it can compose a multi-step
attack through legitimate MCP channels.

**Both together**: OpenShell prevents the agent from reaching
anything except navra and its model. navra prevents the agent
from doing anything except what its capability token allows.
Compromising either layer alone is insufficient for a full
breach.

### Microkernel analogy

| OS Concept | Traditional OS | Agent Platform |
|------------|---------------|----------------|
| Hardware | CPU rings, MMU, I/O ports | OpenShell sandbox (namespace, Landlock, seccomp) |
| Kernel | Syscall interface, process isolation | navra gateway (tool access, session isolation, IFC) |
| Userland | Applications using syscalls | MCP servers + agents using tool calls |

This maps MAC (SELinux/AppArmor) to OpenShell's mandatory network
isolation, and DAC (Unix permissions) to navra's capability-scoped
ACLs. The combination is the same defense-in-depth pattern used in
production operating systems.

### Tool-mediated attack paths

The remaining attack surface after both layers are deployed is
**tool composition through legitimate MCP channels**. If upstream
MCP servers expose both a write tool and an execution tool, an
agent can chain them:

```text
1. file_write("/tmp/exfil.py", "import socket; ...")
   -> navra ACL: allowed (file_write to /tmp permitted)
   -> OpenShell Landlock: allowed (but /tmp is noexec)

2. exec_run("python3 /tmp/exfil.py")
   -> navra ACL: allowed (exec_run permitted)
   -> OpenShell: BLOCKED -- no Python in minimal image

3. If Python IS in the image:
   -> python3 opens socket -> network namespace -> proxy
   -> OpenShell OPA: DENIED (destination not in allowlist)
   -> Even if destination IS allowed, navra IFC can taint
     the data flowing from step 1 -> step 2
```

Each layer catches different steps. The full chain requires
compromising both OpenShell policy (network allowlist) AND
navra policy (ACL + IFC) simultaneously.

When the container includes a scripting runtime (for code
execution tools, REPL features), the attack surface expands.
Mitigations by layer:

| Step | OpenShell | navra |
|------|-----------|-------|
| Open socket | Network namespace forces proxy | -- |
| Connect out | OPA destination check | -- |
| Send data | -- | IFC taint on the data's origin |
| Receive response | -- | Safety filter on ingested content |

The semantic taint gap applies: navra tracks explicit taint labels
but cannot detect implicit information flow through LLM reasoning.
See [adversarial limits](@/docs/learn/multi-agent-surface.md) for
details.

## Implementation status

### Model serving (done)

navra-model-runtime supports an `openshell` backend that delegates
sandbox creation to OpenShell's compute driver via gRPC:

```toml
[models.llama]
runtime = "openshell"

[models.llama.openshell]
gateway = "unix:///run/openshell/gateway.sock"
sandbox_labels = { gpu = "required", isolation = "microvm" }
```

### Runtime auto-detection

The `auto_runtime()` function checks backends in priority order:

1. OpenShell (if gateway socket exists)
2. Podman (if `podman` binary available)
3. Direct (child process, no isolation)

### Sandbox execution (done)

Standalone navra uses Podman for container isolation. In
OpenShell-managed deployments, OpenShell handles the sandbox
lifecycle -- navra requests a sandbox with labels and OpenShell's
compute driver (Podman, libkrun, Kubernetes) handles the rest.
navra does not need to know which isolation backend OpenShell uses.

### Authentication (done)

navra's `ChainAuthenticator` supports OpenShell-provided identity.
When an agent runs inside an OpenShell sandbox, the OpenShell
supervisor has already established the agent's identity. navra
can trust this identity assertion instead of requiring separate
credentials.

## Configuration

### OpenShell gateway

```toml
[models.llama]
runtime = "openshell"

[models.llama.openshell]
gateway = "unix:///run/openshell/gateway.sock"
sandbox_labels = { gpu = "required", isolation = "microvm" }
```

### Authentication mapping

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

## References

- [OpenShell RFC 0001 -- Core Architecture (Red Hat/NVIDIA, 2026-07)](https://github.com/openshell/openshell)
- [Red Hat: Claude self-hosted sandboxes on OpenShell](https://www.redhat.com/en/blog/bringing-claude-self-hosted-sandboxes-to-openshell-on-red-hat-ai)
- [Red Hat: Security-enhanced agent execution](https://www.redhat.com/en/blog/red-hat-ai-and-openshell-driving-security-enhanced-agent-execution-for-enterprise-ai)
- [Anthropic: MCP tunnels and self-hosted sandboxes](https://thenewstack.io/anthropic-mcp-tunnels-sandboxes/)
- [Deconvolute Labs: OpenShell MCP gap](https://deconvoluteai.com/blog/nvidia-openshell-mcp-protocol-layer)
