# navra gateway on Kubernetes

Runs the navra gateway (MCP server, OpenAI-compatible model proxy,
team orchestration, web UI) in-cluster via the Helm chart at
[`deploy/helm/navra`](../helm/navra/), with teammate agents spawned
as `agents.x-k8s.io/v1beta1` Sandbox CRs and an optional
`SandboxWarmPool` of pre-warmed agent pods.

## Prerequisites

- Helm 3.
- The [kubernetes-sigs/agent-sandbox](https://github.com/kubernetes-sigs/agent-sandbox)
  controller **with extensions** (v1.0.11+, cluster-scoped — install
  once per cluster, not per release):

  ```bash
  kubectl apply -f https://github.com/kubernetes-sigs/agent-sandbox/releases/download/v1.0.11/sandbox-with-extensions.yaml
  ```

  The extensions build adds the `extensions.agents.x-k8s.io` CRDs
  (SandboxTemplate, SandboxClaim, SandboxWarmPool) that the warm
  pool needs; the core-only `sandbox.yaml` is enough if you disable
  the pool (`warmPool.enabled=false`).

- The `navra-server` and `navra-agent` images reachable by the
  cluster (defaults are `ghcr.io/smgglrs-ai/*`; override via
  `image.*` / `warmPool.image.*`, and set `image.pullSecrets` for
  private registries).

## Deploy

```bash
helm install navra deploy/helm/navra -n navra --create-namespace \
  --set extraConfig='
[models."qwen2.5:0.5b"]
task = "chat"
base_url = "http://my-ollama:11434"
model_name = "qwen2.5:0.5b"
locality = "local"

[permissions.dev]
operations = ["read", "search", "list"]

[[agents]]
name = "lead"
token_hash = "<blake3 of your token>"
permissions = "dev"
'
```

Application config (models, permissions, agents) is raw TOML in
`extraConfig` — see the chart's `values.yaml` for the full example.
The `[server]` section is chart-managed.

No-Helm escape hatch: `helm template navra deploy/helm/navra |
kubectl apply -f -` (upgrades then require re-applying the rendered
output; prefer Helm for anything long-lived).

## How teammate spawning works

With the warm pool enabled (default), `team_message` claims the
next pre-warmed Sandbox via a `SandboxClaim` (~1s, vs ~30s
cold-create) and the adopted pod — already running and polling
`GET /api/agent/task` — receives its task, model assignment, and a
fresh per-teammate capability token. The pool's bootstrap token
(the `{pool}-bootstrap-token` Secret, maintained by the gateway)
only authenticates the poll. When the pool is drained, the gateway
falls back to cold-create transparently.

Agent pods run with `automountServiceAccountToken: false`; their
only credential is a navra capability token, and their only
interface to the outside world is MCP through the gateway's
permission/IFC/safety pipeline.

## Multi-replica (coordinator/worker split)

`replicas: 2` (default) deploys the NAVRA-194 topology: pod 0 is
the coordinator (team/flow state, spawning, authoritative session
taint); pods 1+ are stateless workers that forward coordinator-
owned tool calls (`team_*`, `flow_*`, `agent_signal`) and the agent
task API to the coordinator over the headless Service, preserving
caller credentials. Delegated tokens verify on any replica via the
shared root identity (release-scoped Secret).

Per-replica worker state (sessions, memory, audit) is local
scratch; the authoritative IFC taint join for model routing is
queried from the coordinator (`/api/internal/agent-label`). Full
state externalization (Redis or equivalent) is future work.

## Multiple deployments

Every resource is release-scoped — `helm install staging ... -n
navra-staging` and `helm install prod ... -n navra-prod` coexist in
one cluster. Each deployment is an independent trust domain: its
own root identity (delegated tokens do not verify across
deployments), teams, sessions, and warm pool. Separate namespaces
are the cleanest tenant boundary; same-namespace releases also
work, but each keeps its own pool of idle agent pods.

## Verify teammate spawning end-to-end

With the gateway deployed and a model reachable, port-forward and
run the example driver with an agent token:

```bash
kubectl -n navra port-forward svc/navra-navra 9315:9315 &
python3 examples/kubernetes/e2e-driver.py \
  --endpoint http://localhost:9315/mcp \
  --token <agent-token> \
  --model qwen2.5:0.5b
```

(The Service name is `{release}-navra` — check `helm status` or the
NOTES output.) The two-replica scenario (create on the coordinator,
collect on a worker) uses `--second-endpoint`; see the chart NOTES.

## Notes and limits

- **No local model runtime**: the image is the gateway only. Point
  `extraConfig` models at a remote API or deploy llama.cpp/Ollama
  separately.
- **Model routing applies**: `[model_routing]` and `[model_ifc]`
  work at the in-cluster `/v1` proxy exactly as on the desktop —
  with `ifc_clearance = "sensitive"` reserved for endpoints that
  are in-cluster or otherwise trusted with sensitive data.
- **Sandbox network isolation**: warm-pool Sandboxes ship
  `networkPolicyManagement: Unmanaged` because OVN-Kubernetes
  breaks cluster DNS for sandbox pods under the controller's
  managed policy regardless of allow rules — same posture as
  cold-created Sandboxes. Tracking + fix: NAVRA-196.
