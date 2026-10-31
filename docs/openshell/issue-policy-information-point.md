# Upstream issue draft: Policy Information Point (OpenShell feature request)

Filled against NVIDIA/OpenShell's `feature_request.yml` template. File at
https://github.com/NVIDIA/OpenShell/issues/new/choose once reviewed.
Do NOT submit the RFC as a PR first — maintainers assign RFC numbers
from this issue if they decide one is needed.

---

## User Story

I operate navra, an open-source MCP security gateway
(https://github.com/smgglrs-ai/navra), deployed alongside OpenShell as
external infrastructure: agents run inside OpenShell sandboxes and
reach navra through the sandbox's egress proxy — the sandbox policy
allows exactly the navra gateway, the model endpoint, and the
OpenShell gateway, and denies everything else. All MCP tool traffic
flows agent → proxy → navra → upstream servers, so navra sees every
tool call and result.

navra tracks per-session information-flow-control taint labels on
tool results: when an agent reads a patient record or a credential
through a governed tool call, navra labels that data and restricts
further tool calls accordingly.

I directly encountered this: navra can detect that a session has
absorbed sensitive data, but it cannot tell OpenShell's egress proxy.
The agent can still POST that data to any other destination on the
sandbox's allowlist — the model API, collaboration tools, telemetry
endpoints — directly from the sandbox, on a path that never touches
navra. Detection at the gateway cannot restrict egress at the
sandbox.

## Problem Statement

OpenShell's egress proxy evaluates OPA policy on network-level
attributes: destination, port, calling binary, L7 request shape.
Application-layer security context is invisible to it, and it lives
in two places:

1. Governance frameworks running **inside** the sandbox — DefenseClaw
   scan verdicts, NemoClaw's privacy classification, AgentGuard
   governance hooks.
2. Governance infrastructure deployed **outside** the sandbox by the
   operator — like navra — through which the agent's tool traffic
   flows, and which therefore knows things the sandbox itself does
   not (what data the session has absorbed).

There is no mechanism for the supervisor to obtain structured
security context from either place for use in network policy. A
sandbox whose governance layer — internal or external — has detected
a compromise or a sensitive-data exposure keeps its full baseline
allowlist.

## Impact / Why This Matters

Without this capability:

- A compromised skill that reads credentials through a governed tool
  call can exfiltrate them to any allowlisted destination. The
  governance layer blocks further tool calls, but the proxy still
  allows the direct connection. The ClawHavoc campaign exfiltrated
  credentials exactly this way — allowlists blocked unknown
  destinations but could not restrict allowed ones based on runtime
  data sensitivity.
- The Hugging Face agent intrusion post-mortem reached the same
  conclusion at fleet scale: network reachability was far too broad
  relative to the workload's actual runtime behavior, and static
  provisioning-time policy could not adapt.
- Governance frameworks must choose between running their own
  incomplete network enforcement or accepting that their verdicts
  stop at the application layer.

OS-level enforcement (OpenShell) and application-level governance
are only as strong as the connection between the two layers. Today
that connection does not exist, from either side of the sandbox
boundary.

## Proposed Design

A Policy Information Point (PIP) interface, following the NIST SP
800-207 naming: the supervisor — as the trusted policy enforcement
point — queries governance software for structured security context
and exposes it to policy as `input.pip`. One streaming contract
(`StreamContext`, carrying the sandbox id and a property map), two
publisher sources:

- **In-sandbox publishers** (frameworks the operator did not
  deploy): serve a small gRPC service on a Unix domain socket at
  `/run/openshell/pip/<name>.sock` inside the sandbox. The
  supervisor discovers the socket, verifies the serving binary's
  identity, and initiates the stream. Zero configuration.
- **Operator-side publishers** (operator-deployed infrastructure,
  such as an external MCP gateway): publish from outside the sandbox
  via a supervisor-visible endpoint — a Unix socket in a
  supervisor-side directory for same-host deployments, or an
  operator-configured authenticated gRPC endpoint where the
  supervisor and publisher are on different nodes (Kubernetes),
  mirroring how supervisor middleware services are registered and
  authenticated today.

Policy authors write deny rules that reference the context:

```rego
deny_network if {
    input.pip.data_classification == "phi"
    input.network.host == data.config.analytics_host
}
```

Essential constraints (trust-model requirements, not implementation
preferences):

- The supervisor initiates every connection; publishers never push
  security-relevant input to the supervisor.
- PIP context may only add deny constraints; it can never expand the
  allowlist. A PIP that disconnects or publishes nothing is
  equivalent to no PIP — baseline policy applies unchanged.
- Properties are opaque string key-value pairs with a publisher
  prefix convention (`navra.data_classification`,
  `defenseclaw.scan_status`).

## Acceptance Criteria

- [ ] A governance application inside a sandbox can publish
      security-context properties that become visible to network
      policy as `input.pip`
- [ ] Operator-configured infrastructure outside the sandbox can
      publish per-sandbox security context through the same contract
- [ ] Policy can deny an otherwise-allowed connection based on
      published context (e.g. `trust_state = "suspended"` denies all
      non-gateway egress)
- [ ] Published context can never cause an allow decision that
      baseline policy would deny
- [ ] A disconnected or absent publisher leaves `input.pip` null and
      policy behavior identical to pre-PIP
- [ ] The supervisor verifies in-sandbox publishers' binary identity
      before consuming context; a mismatch refuses the connection
      and emits a detection finding. Operator-side publishers are
      authorized at configuration time.
- [ ] OCSF events identify when a denial was influenced by
      publisher context and tag its origin

## Alternatives Considered

- **Supervisor middleware (RFC 0009)** — the closest existing
  extension point, and viable for reaching an external gateway (both
  are operator-side). But it is the content-inspection path, wrong
  for this use in three ways: it would require a per-request
  blocking side-query in the traffic hot path instead of
  supervisor-held streamed state; its failure semantics are wrong
  (middleware `fail_closed` makes the governance infrastructure a
  hard dependency on all egress through the endpoint, `fail_open`
  releases tainted traffic exactly when the infrastructure is down,
  while the PIP degrades to the baseline allowlist on disconnect);
  and middleware chains attach per-endpoint via policy, while
  security context needs to apply to all of a sandbox's evaluations.
  Middleware also receives request bodies it does not need for this.
  Complementary, not sufficient.
- **Sandbox service exposure (`service expose`, RFC 0017 draft)** —
  inbound ingress through the gateway relay; wrong direction, and
  RFC 0017 lists replacing egress policy as a non-goal.
- **OPA external data bundles** — require network connectivity from
  inside the sandbox, which the architecture deliberately fences.
- **Dynamic policy updates (`openshell policy update`)** —
  control-plane revisions with operator approval; not a runtime
  per-connection signal, and the wrong latency for "this session
  just became tainted."
- **Gateway interceptors (RFC 0010)** — intercept control-plane RPCs
  at the gateway, not per-connection egress in the supervisor.

## Agent Investigation

We explored the supervisor-network codebase and the existing
extension points in detail: OPA input construction
(`crates/openshell-supervisor-network/src/opa.rs` — built
per-request from network/L7 context, no application-state injection
path), the middleware contract (`proto/supervisor_middleware.proto`
— RequestContext carries request correlation, not session security
state), the isolation backend's LoopbackConnect, and the RFC
0009/0010/0017 designs. Findings relevant to feasibility:

- The supervisor's only existing dial-into-sandbox connection is the
  SSH relay socket (peer-PID-verified), establishing precedent for
  supervisor-initiated connections into the sandbox.
- The supervisor's `/proc` view spans the sandbox's processes (this
  is how per-connection binary identity already works), so the same
  `SO_PEERCRED` → `/proc/<pid>/exe` → SHA256 verification chain
  extends unchanged to same-host operator-side publishers.
- The LoopbackConnect transport exists, so only the policy-time
  query semantics are missing.

One design consideration we would bring to the discussion: for
operator-side publishers serving many sandboxes, `StreamContext`
carries the sandbox id and the publisher must map it to its own
session state (for navra, most naturally by binding agent
credentials to sandboxes at provisioning time). A publisher that
cannot correlate should publish empty context rather than guess.

We have a complete RFC draft and a working supervisor-side prototype
covering both publisher classes: in-sandbox socket discovery with
SO_PEERCRED + TOFU SHA256 verification; operator-side same-host
publishers under a supervisor-side directory with the same
verification; remote publishers registered in `gateway.toml` with
audience-scoped extension credentials (fail-closed when a credential
is missing); streaming into `input.pip` at every OPA evaluation
point including per-request L7 evaluations on established tunnels;
authored `pip_deny_rules` on network policies with a validator that
rejects operator-supplied Rego referencing `input.pip` (deny-only is
structural); and OCSF denial events tagged with publisher origins —
all tested. Ready to contribute as an RFC and implementation against
this issue if maintainers want to proceed.

## Checklist

- [x] I've reviewed existing issues and the published docs
- [x] This is a design proposal, not a "please build this" request
