# navra gateway on Kubernetes

Runs the navra gateway (MCP server, model proxy, team orchestration,
web UI) in-cluster, with teammate agents spawned as
`agents.x-k8s.io/v1beta1` Sandbox CRs.

## Prerequisites

- The [kubernetes-sigs/agent-sandbox](https://github.com/kubernetes-sigs/agent-sandbox)
  controller, v1.0+ (serves v1beta1):

  ```bash
  kubectl apply -f https://github.com/kubernetes-sigs/agent-sandbox/releases/download/v1.0.11/sandbox.yaml
  ```

  For the warm pool (below), install the extensions build instead —
  it adds the `extensions.agents.x-k8s.io` CRDs (SandboxTemplate,
  SandboxClaim, SandboxWarmPool):

  ```bash
  kubectl apply -f https://github.com/kubernetes-sigs/agent-sandbox/releases/download/v1.0.11/sandbox-with-extensions.yaml
  ```

- The `navra-server` and `navra-agent` images reachable by the
  cluster (`ghcr.io/smgglrs-ai/navra-server`, `.../navra-agent`). If
  the packages are private, create an image pull secret and add
  `imagePullSecrets` to the StatefulSet.

## Deploy

```bash
kubectl apply -f deploy/k8s/namespace.yaml
kubectl apply -f deploy/k8s/rbac.yaml
kubectl apply -f deploy/k8s/config-example.yaml   # replace with your config
kubectl apply -f deploy/k8s/gateway.yaml
kubectl -n navra rollout status statefulset/navra-gateway
```

## How teammate spawning works

With `kubernetes_namespace` set, `team_message` spawns each teammate
as a Sandbox CR in the navra namespace: a distroless
`navra-agent` Pod (named after the Sandbox) that connects back to
the gateway through the `navra-gateway` Service with a delegated,
scoped capability token. The gateway's RBAC is namespaced — it can
manage Sandboxes, read their Pods' status and logs, and nothing else.

The agent Pods run with `automountServiceAccountToken: false` and
`restartPolicy: Never`: their only credential is the navra token,
and their only interface to the outside world is MCP through the
gateway's permission/IFC/safety pipeline.

## Warm pool (fast teammate spawn)

Cold teammate spawns cost image pull + pod start + connect-back
(~30s observed). A `SandboxWarmPool` of pre-warmed `navra-agent`
pods cuts the handoff to ~1s: the gateway creates a `SandboxClaim`
that adopts the next warm Sandbox, and the adopted pod — already
running and polling — receives its task, model assignment, and a
fresh per-teammate capability token from the gateway's
`GET /api/agent/task` endpoint.

```bash
kubectl apply -f deploy/k8s/warm-pool.yaml
```

Then enable it in the gateway config:

```toml
[server]
kubernetes_namespace = "navra"
kubernetes_warm_pool = "navra-agents"   # SandboxWarmPool name
```

Notes:

- The `{pool}-bootstrap-token` Secret (referenced by the
  SandboxTemplate) is created and kept current by the gateway —
  it only authenticates warm pods' task polls; a scoped per-
  teammate token is minted at adoption.
- `restartPolicy: OnFailure` in the template means a crashed
  teammate restarts and re-fetches its task (redelivery) instead
  of losing the run.
- When the pool is drained (or the extensions are not installed),
  the gateway falls back to cold-create transparently.

## Verify teammate spawning end-to-end

With the gateway deployed and a model reachable (the `[models.*]`
entry), drive the full loop — port-forward, then run the example
driver with an agent token:

```bash
kubectl -n navra port-forward svc/navra-gateway 9315:9315 &
python3 examples/kubernetes/e2e-driver.py \
  --endpoint http://localhost:9315/mcp \
  --token <agent-token> \
  --model qwen2.5:0.5b
```

The driver runs `team_create` → `team_add` → `team_message` →
`team_result`: the teammate spawns as a Sandbox, connects back to
the gateway with its delegated capability token, runs its ReAct
loop with model calls through the gateway's `/v1` proxy, and the
driver prints the teammate's output. Watch the Sandbox lifecycle
alongside it with `kubectl -n navra get sandboxes -w`.

## Notes and limits

- **Single replica by design**: the TeamRegistry is in-memory and
  sessions/audit live in SQLite on the `/data` volume. Scaling out
  requires externalizing that state first.
- **No local model runtime**: the image is the gateway only. Point
  `[models.*]` at a remote API or deploy llama.cpp separately.
- **Model routing applies**: `[model_routing]` and `[model_ifc]`
  work at the in-cluster `/v1` proxy exactly as on the desktop —
  with `ifc_clearance = "sensitive"` reserved for endpoints that are
  in-cluster or otherwise trusted with sensitive data.
- The Service name must match `[server] kubernetes_gateway_service`
  (default `navra-gateway`).
