# Upstream issue draft: Policy Information Point (OpenShell feature request)

Filled against NVIDIA/OpenShell's `feature_request.yml` template. File at
https://github.com/NVIDIA/OpenShell/issues/new/choose once reviewed.
Do NOT submit the RFC as a PR first — maintainers assign RFC numbers
from this issue if they decide one is needed.

---

## User Story

I operate navra, an open-source MCP security gateway
(https://github.com/smgglrs-ai/navra), deployed inside OpenShell
sandboxes as the governance layer for agent tool traffic — the
"entire agent sandboxed, gateway alongside" mode. navra tracks
per-session information-flow-control taint labels on tool results:
when an agent reads a patient record or a credential through a
governed tool call, navra labels that data and restricts further
tool calls accordingly.

I directly encountered this: navra can detect that a session has
absorbed sensitive data, but it cannot tell OpenShell's egress
proxy. The agent can still POST that data to any destination on the
sandbox's baseline allowlist — model APIs, collaboration tools,
telemetry endpoints — through channels navra does not mediate. This
defeats the reason I run both layers: semantic detection at the
application layer with no way to act on it at the network layer.

## Problem Statement

OpenShell's egress proxy evaluates OPA policy on network-level
attributes: destination, port, calling binary, L7 request shape.
Application-layer governance software running inside the sandbox —
navra, DefenseClaw, NemoClaw's privacy router, AgentGuard — makes
runtime security decisions (data classification, trust state, scan
verdicts, anomaly scores) that the proxy cannot see. There is no
mechanism for the supervisor to obtain structured security context
from inside the sandbox for use in network policy.

The consequence: a sandbox whose governance layer has detected a
compromise or a sensitive-data exposure keeps its full baseline
allowlist. Detection at the application layer cannot restrict
egress at the network layer.

## Impact / Why This Matters

Without this capability:

- A compromised skill that reads credentials through a governed
  tool call can exfiltrate them to any allowlisted destination.
  The governance framework blocks further tool calls, but the
  proxy still allows the connection. The ClawHavoc campaign
  exfiltrated credentials exactly this way — allowlists blocked
  unknown destinations but could not restrict allowed ones based
  on runtime data sensitivity.
- The Hugging Face agent intrusion post-mortem reached the same
  conclusion at fleet scale: network reachability was far too
  broad relative to the workload's actual runtime behavior, and
  static provisioning-time policy could not adapt.
- Every governance framework on top of OpenShell must choose
  between running its own incomplete network enforcement or
  accepting that its verdicts stop at the application layer.

The composition of OS-level enforcement (OpenShell) and
application-level governance is only as strong as the connection
between the two layers. Today that connection does not exist, and
every Layer 1 framework hits the same wall.

## Proposed Design

A Policy Information Point (PIP) interface, following the NIST SP
800-207 naming: the supervisor — as the trusted policy enforcement
point — queries in-sandbox applications for structured security
context and exposes it to policy as `input.pip`.

User-visible workflow: an application inside the sandbox that
tracks security state serves a small gRPC service on a Unix domain
socket at `/run/openshell/pip/<name>.sock`. The supervisor
discovers the socket, verifies the serving binary's identity, and
holds the latest published context. Policy authors write deny
rules that reference it:

```rego
deny_network if {
    input.pip.data_classification == "phi"
    input.network.host == data.config.analytics_host
}
```

Essential constraints (trust-model requirements, not
implementation preferences):

- The supervisor initiates every connection; the sandbox never
  pushes security-relevant input to the supervisor.
- PIP context may only add deny constraints; it can never expand
  the allowlist. A PIP that disconnects or publishes nothing is
  equivalent to no PIP — baseline policy applies unchanged.
- Properties are opaque string key-value pairs with a publisher
  prefix convention (`navra.data_classification`,
  `defenseclaw.scan_status`).

## Acceptance Criteria

- [ ] A governance application inside a sandbox can publish
      security-context properties that become visible to network
      policy as `input.pip`
- [ ] Policy can deny an otherwise-allowed connection based on
      published context (e.g. `trust_state = "suspended"` denies
      all non-gateway egress)
- [ ] Published context can never cause an allow decision that
      baseline policy would deny
- [ ] A disconnected or absent publisher leaves `input.pip` null
      and policy behavior identical to pre-PIP
- [ ] The supervisor verifies the publisher's binary identity
      before consuming context; a mismatch refuses the connection
      and emits a detection finding
- [ ] OCSF events identify when a denial was influenced by
      in-sandbox context and tag its origin

## Alternatives Considered

- **Supervisor middleware (RFC 0009)** — the closest existing
  extension point, and the right one for content inspection.
  Middleware is content-driven: the supervisor calls
  operator-registered host-side services with request/response
  bodies. It cannot query in-sandbox state (the outer fence
  prevents host services from reaching into the sandbox), and
  composing it for this use (middleware keyed on sandbox_id
  side-querying the framework via `service expose`) has wrong
  failure semantics: middleware `fail_closed` makes the governance
  framework a hard dependency on all egress, `fail_open` lets
  tainted traffic through exactly when the framework is down. The
  PIP degrades to the baseline allowlist on disconnect. Middleware
  and the PIP are complementary: middleware sees traffic content,
  the PIP sees application state.
- **Sandbox service exposure (`service expose`, RFC 0017 draft)** —
  inbound ingress through the gateway relay; wrong direction, and
  RFC 0017 lists replacing egress policy as a non-goal.
- **OPA external data bundles** — require network connectivity
  from inside the sandbox, which the architecture deliberately
  fences.
- **Dynamic policy updates (`openshell policy update`)** —
  control-plane revisions with operator approval; not a runtime
  per-connection signal, and the wrong latency for "this session
  just became tainted."
- **Gateway interceptors (RFC 0010)** — intercept control-plane
  RPCs at the gateway, not per-connection egress in the supervisor.

## Agent Investigation

We explored the supervisor-network codebase and the existing
extension points in detail: OPA input construction
(`crates/openshell-supervisor-network/src/opa.rs` — built
per-request from network/L7 context, no application-state injection
path), the middleware contract (`proto/supervisor_middleware.proto`
— RequestContext carries request correlation, not session security
state), the isolation backend's LoopbackConnect, and the RFC
0009/0010/0017 designs. Two findings worth noting: the supervisor's
only existing dial-into-sandbox connection is the SSH relay socket
(peer-PID-verified), which establishes precedent for
supervisor-initiated connections into the sandbox; and the
LoopbackConnect transport already exists, so only the policy-time
query semantics are missing.

We have a complete RFC draft and a working supervisor-side
prototype (socket discovery, SO_PEERCRED + TOFU SHA256
verification, streaming, `input.pip` injection at every OPA
evaluation point, deny-only enforcement in the baked policy, an
OCSF detection finding on identity mismatch, and tests) ready to
contribute as an RFC and implementation against this issue if
maintainers want to proceed.

## Checklist

- [x] I've reviewed existing issues and the published docs
- [x] This is a design proposal, not a "please build this" request
