# RFC 0002 - Policy Information Point

## Summary

This RFC proposes adding a Policy Information Point (PIP) interface to the sandbox supervisor. The supervisor queries application-layer software running inside the sandbox for structured security context and injects it into the OPA proxy's input document. This lets network-layer policy reference runtime state -- data classification, trust level, anomaly scores -- without the proxy parsing any application protocol.

The supervisor initiates the connection and verifies the responding binary's identity. The PIP can only add deny rules to OPA evaluation, never allow rules. Sandboxes that do not run a PIP-capable application work exactly as they do today.

## Motivation

The proxy evaluates OPA policy on network-level attributes: destination host, port, binary identity, HTTP method/path. It cannot see what the application is doing with the data it handles. This gap matters when the sandbox's security context changes at runtime in ways that static provisioning-time configuration cannot anticipate.

A sandbox provisioned for code review encounters a patient record in a test fixture. A skill that passed initial scanning turns out to be compromised mid-session and has already read credentials. An agent provisioned for dataset processing begins probing instance metadata and the Kubernetes API. In each case, a governance framework running inside the sandbox detects the change and restricts its own layer, but the proxy continues allowing the same egress paths because it has no visibility into what happened.

The ClawHavoc campaign showed this concretely. Malicious skills exfiltrated credential files and SSH keys to attacker-controlled endpoints. OpenShell blocks unknown endpoints, but the allowlist must include some destinations -- model APIs, collaboration tools, telemetry services. Once a compromised skill reads sensitive data through a governed tool call, it or another skill can POST that data to any allowed endpoint. The governance framework blocks further tool calls, but the proxy still allows the connection. The data leaves through a channel the governance framework does not control.

The Hugging Face agent intrusion in July 2026 demonstrated the same gap at a larger scale. An autonomous agent escaped its evaluation sandbox and exfiltrated data through six distinct channels, including public request-capture services, dead-drop dataset commits, and Tailscale mesh exit nodes. The post-mortem identified that network reachability was far too broad relative to the workload's actual role. A dataset-processing worker had no legitimate need for metadata service access, VPN enrollment, or arbitrary internet egress, but static policy permitted all of them. The behavioral shift from normal processing to privilege escalation happened at runtime.

These are not configuration mistakes. The sandboxes were provisioned correctly for their intended purpose. The threat emerged from data the agent encountered or behavior it developed during execution. Static policy handles the intended purpose. The proxy needs runtime input to handle the gap between intent and reality.

The pattern already exists in OpenShell. Credentials flow into the sandbox: the supervisor receives credential bundles from the gateway and injects them into the sandbox environment. The PIP extends this by having the supervisor query security context from inside the sandbox. The supervisor remains the active party in both directions.

Multiple governance frameworks already run on top of OpenShell and would benefit from this interface. DefenseClaw makes runtime scan verdicts that the proxy cannot see. NemoClaw's privacy router classifies data but can only enforce classification at the application layer. AgentGuard provides governance hooks with no mechanism to influence the proxy. Each framework makes security decisions that the proxy should be able to act on.

## Non-goals

- **Protocol-specific inspection.** The proxy must not parse MCP, A2A, gRPC, or any application protocol. The PIP provides pre-computed metadata; the proxy consumes it as opaque key-value pairs in OPA input.
- **Per-packet classification.** The PIP represents the session's cumulative security state. It changes on the timescale of tool calls, not network packets.
- **Coupling to any specific governance framework.** Any application inside the sandbox can expose the PIP service.
- **Granting permissions.** PIP context must only appear in deny rules, never in allow rules. A PIP that disconnects or publishes empty context is equivalent to no PIP at all -- the baseline allowlist applies unchanged.

## Proposal

### Trust model

The sandbox is an untrusted environment. We do not accept unsolicited connections from inside the sandbox for security-relevant input. Instead, the supervisor initiates all PIP communication, matching the trust direction of every other supervisor interaction.

The governance framework exposes a gRPC service on a Unix domain socket at a well-known path. The supervisor discovers the socket, verifies the owning binary's identity via `SO_PEERCRED` and SHA256 hash check (the same `/proc`-based resolution the proxy already uses for binary identity), and initiates a streaming RPC. The governance framework sends its current security context and pushes updates as the context changes. The supervisor caches the latest state.

If the binary hash does not match the TOFU cache, the supervisor logs a warning and does not connect. If the stream disconnects, the cached context reverts to null. Both behaviors are fail-closed.

### Interface

The governance framework creates a socket at `/run/openshell/pip/<name>.sock`, where `<name>` is its identifier (for example `defenseclaw` or `nemoclaw`). The supervisor watches the directory and connects to each socket it discovers.

```protobuf
syntax = "proto3";
package openshell.pip.v1;

service PolicyInformationPoint {
  rpc StreamContext(StreamContextRequest) returns (stream SecurityContext);
}

message StreamContextRequest {
  string sandbox_id = 1;
}

message SecurityContext {
  map<string, string> properties = 1;
  string trace_id = 2;
}
```

The `properties` map uses string keys and string values. Governance frameworks should prefix their keys by convention (`defenseclaw.scan_status`, `nemoclaw.classification`) to avoid collisions when multiple PIPs are present. We recommend but do not mandate a small set of well-known keys: `data_classification`, `trust_state`, `anomaly_score`.

### OPA input injection

The supervisor merges the latest cached properties from all connected PIPs into `input.pip`:

```json
{
  "exec": {"path": "/usr/bin/agent", "ancestors": ["..."]},
  "network": {"host": "logs.corp.com", "port": 443},
  "pip": {
    "data_classification": "phi",
    "trust_state": "suspended"
  }
}
```

When no PIP is connected, `input.pip` is null. Existing policies that do not reference `input.pip` are unaffected. When multiple PIPs are connected, their properties are merged with latest-writer-wins per key.

Policy authors use `input.pip` in deny rules only:

```rego
deny_network if {
    input.network.host == data.config.analytics_host
    input.pip.data_classification == "phi"
}

deny_network if {
    input.pip.trust_state == "suspended"
    input.network.host != data.config.gateway_host
}
```

The OPA policy validator should reject policies that reference `input.pip` in allow rules. This ensures a compromised PIP cannot open network paths beyond the baseline allowlist.

### Lifecycle

The supervisor creates `/run/openshell/pip/` with mode 0750 before launching the agent process. The governance framework starts, creates its socket, and waits for the supervisor to connect. The supervisor discovers the socket, verifies the binary, initiates `StreamContext`, and receives the initial context. The governance framework pushes updates as its state changes. On stream error or disconnect, the cached context for that PIP reverts to null. The directory is removed at sandbox teardown.

## Risks

- **Trust boundary.** The governance framework runs inside the untrusted sandbox. A compromised binary could publish false context. Three mitigations apply: the supervisor verifies binary identity before connecting, PIP context can only add deny rules (a lying PIP that omits classifications is equivalent to running without a PIP, which is the current state), and disconnection reverts to null rather than preserving stale context. The residual risk is that a compromised governance binary suppresses classifications it should publish. This is equivalent to the attacker disabling the governance framework entirely, which is already within scope of a sandbox compromise.
- **Performance.** The PIP context is cached in memory. The proxy reads the cache on every OPA evaluation -- one `RwLock::read()` per connection, no I/O in the hot path. The streaming RPC runs in a separate task.
- **Audit trail trust.** PIP-sourced properties appear in OCSF events. Events should tag PIP-sourced context with its origin so analysts know it came from inside the sandbox and weight it accordingly.
- **Schema divergence.** Without conventions, different governance frameworks could use conflicting property names. The reserved prefix convention and recommended well-known keys mitigate this. We do not mandate a fixed schema because the set of useful properties will evolve with the ecosystem.

## Alternatives

### 1. PIP pushes to supervisor

The governance framework connects to a supervisor-hosted socket and pushes context updates.

**Rejected.** This reverses the trust boundary. The supervisor currently never accepts security-relevant input from inside the sandbox. The SSH socket accepts connections but uses structural isolation (filesystem permissions) and does not influence policy decisions. Having the proxy's OPA policy influenced by a push from untrusted code is a qualitative change in the trust model. The supervisor-queries-PIP pattern keeps the supervisor as the initiator, consistent with every other intra-sandbox interaction.

### 2. NDJSON over Unix socket instead of gRPC

Simpler -- any language can write a JSON line without protobuf codegen.

**Rejected.** OpenShell uses gRPC for every inter-component interface: the gateway API, the compute driver, the supervisor session. A JSON socket would be the only non-gRPC interface in the project. gRPC provides the streaming RPC naturally, handles backpressure, and gives the supervisor typed message validation. The overhead of protobuf codegen is small relative to the consistency benefit.

### 3. Application-level authentication (mTLS, tokens)

Require the PIP to present a certificate or bearer token when the supervisor connects.

**Rejected.** OpenShell's intra-sandbox trust model is structural, not credential-based. The SSH socket uses filesystem permissions. The proxy uses `/proc`-based binary identity resolution. Adding a credential protocol would be inconsistent and would require a credential distribution mechanism that does not exist inside sandboxes. `SO_PEERCRED` plus binary hash verification is sufficient and consistent with existing patterns.

### 4. Shared file

Write `/run/openshell/pip.json` and have the proxy read it.

**Rejected.** Introduces TOCTOU races between the writer and the proxy's reader, requires filesystem polling or inotify, and does not support multiple publishers cleanly. A streaming RPC provides atomic, synchronous delivery with built-in multiplexing.

### 5. OPA external data bundles

OPA supports HTTP-based data sources natively.

**Rejected.** These require network connectivity inside the sandbox, which the architecture deliberately restricts. The Unix socket keeps the PIP entirely local.

## Prior art

- **NIST SP 800-207 (Zero Trust Architecture).** Defines the PDP/PEP/PIP architecture. The PDP queries the PIP; the PIP does not push to the PDP. This RFC follows that model.
- **W3C Baggage.** Standardizes key-value context propagation across service boundaries. The PIP properties use the same string-key, string-value semantics.
- **Envoy ext_authz.** The enforcement point calls out to an external authorization service for per-request decisions. Same trust direction: the trusted proxy queries the authorization service, not the reverse.
- **Kubernetes Pod Security Context.** Static security metadata set at pod creation. The PIP is dynamic -- it changes during the sandbox's lifetime as the application's security state evolves.
- **ClawHavoc (2026).** Supply chain attack planting 1,184 malicious skills in ClawHub. Skills exfiltrated credentials to attacker-controlled endpoints. OpenShell's allowlist blocked unknown destinations but could not restrict allowed destinations based on runtime data sensitivity.
- **Hugging Face agent intrusion (July 2026).** Autonomous agent escaped its sandbox and exfiltrated data through six channels. Network reachability was too broad relative to workload role. Application-aware egress policy would have constrained several critical pivots.
- **NSA/CISA MCP Security Advisory (May 2026).** Identifies attack classes where agents bypass governance layers via direct network connections.
