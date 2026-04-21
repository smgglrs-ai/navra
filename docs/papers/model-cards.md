# Composite Model Cards for Agentic AI: Bridging Registry Metadata and Runtime Selection

## Abstract

Model registries describe what a model *is* --- architecture, license,
parameter count --- but not what it is *good at* for agentic tasks.
When a lead agent must assign models to teammates in a multi-agent
system, no existing standard provides the agentic capability metadata
needed for informed selection: tool-use proficiency, reasoning depth,
cost tier, speed tier, JSON compliance, or data locality constraints.
We propose a three-layer Composite Model Card schema that combines
vendor-provided metadata (auto-populated from registry APIs), operator-
defined agentic capabilities, and runtime statistics learned from
actual agent executions. We implement this schema in a Rust-based MCP
gateway, demonstrate auto-population from Ollama, HuggingFace Hub,
and OCI registries, and show how a lead agent reads model cards via
an MCP tool to select appropriate models for each teammate. In a
multi-agent security audit, composite model cards enabled a shift from
all-cloud model usage (with rate limits) to mixed local/remote
selection, eliminating rate-limit errors and reducing end-to-end
latency by 3x.

## 1. Introduction

Large language models are increasingly deployed not as standalone
endpoints but as components in multi-agent systems where a lead agent
orchestrates specialist teammates, each performing a distinct subtask
[1]. In such systems, model selection becomes a runtime decision: the
lead must choose which model each teammate should use based on the
task's requirements for reasoning depth, tool-use capability, cost
sensitivity, and data locality.

Existing model registries --- HuggingFace Hub, Ollama, Google Model
Garden, Vertex AI, OpenAI's API --- provide technical metadata about
model architecture and licensing. None provide the agentic capability
metadata an orchestrator needs. An operator who knows that Granite
3.3 8B excels at data gathering but struggles with multi-step
reasoning has no standardized way to express this knowledge in a
machine-readable format that agents can consume.

This gap forces two suboptimal outcomes: (1) operators hardcode model
assignments in flow definitions, eliminating adaptive selection, or
(2) lead agents default to the most capable (and expensive) model for
all teammates, wasting resources and triggering rate limits.

We address this gap with the Composite Model Card, a three-layer
metadata schema that bridges registry metadata and runtime model
selection.

## 2. Survey of Existing Standards

### 2.1 HuggingFace Hub

HuggingFace model cards provide `pipeline_tag` (e.g.,
`text-generation`), `tags` (format, license), `cardData.language`,
and free-text model card content. The API (`/api/models/{org}/{repo}`)
returns these fields programmatically. **Missing**: task suitability,
tool-use proficiency, speed/cost tiers, reasoning depth.

### 2.2 Ollama

Ollama manifests expose layers with media types for model weights,
parameters, templates, and system prompts. The `/api/show` endpoint
returns `family`, `parameter_size`, `quantization_level`, and
`context_length` [2]. **Missing**: all agentic capability fields.

### 2.3 Vertex AI and Google Model Garden

Vertex AI `PublisherModel` resources include supported tasks,
input/output modalities, and pricing. Model Garden provides curated
metadata for first-party and partner models. **Missing**: operator-
customizable fields, runtime statistics, tool-use proficiency ratings.

### 2.4 OpenAI API

The `/v1/models` endpoint returns model IDs and ownership. Context
window sizes and capability differences are documented but not
machine-readable. **Missing**: structured capability metadata of any
kind.

### 2.5 Kubeflow Model Registry / OpenShift AI

The Kubeflow Model Registry [3] stores `RegisteredModel` and
`ModelVersion` objects with a `customProperties` map (`string | int |
double | bool` values). This extensibility mechanism is the closest
existing standard to what agentic metadata requires, but no schema
has been proposed for agentic fields. Issue #449 (model card support)
is stale, with all contributors from Red Hat. The plugin architecture
(#2220) could host an agentic metadata plugin. OpenShift AI inherits
this registry as its model catalog.

## 3. Composite Model Card Schema

We define a three-layer schema where each layer has a distinct source
of truth and update cadence:

### 3.1 Vendor Layer (auto-populated)

Populated at model pull time from registry APIs. Fields:

| Field | Type | Source |
|-------|------|--------|
| `source` | string | Registry identifier (`ollama`, `huggingface`, `oci`, `openai`) |
| `family` | string | Model family (`granite`, `llama`, `gemma`) |
| `parameters` | string | Parameter count (`8B`, `26B`) |
| `quantization` | string | Quantization level (`Q4_K_M`, `fp16`) |
| `context_window` | u32 | Context window in tokens |
| `format` | string | Weight format (`gguf`, `safetensors`, `onnx`) |
| `tasks` | string[] | HuggingFace pipeline tags |
| `license` | string | SPDX identifier |
| `languages` | string[] | ISO 639 codes |
| `custom` | map | Raw registry properties (Kubeflow `customProperties`) |

### 3.2 Agentic Layer (operator-defined)

Set by the system operator in configuration. No existing registry
provides these fields natively. They encode the operator's knowledge
of how models perform in agentic contexts:

| Field | Type | Values |
|-------|------|--------|
| `strengths` | string[] | Free-text capabilities (`code generation`, `fast inference`) |
| `weaknesses` | string[] | Known limitations (`limited reasoning`, `no tool use`) |
| `recommended_tasks` | string[] | Task types the model handles well |
| `avoid_tasks` | string[] | Task types to avoid |
| `tool_use` | enum | `none`, `basic`, `advanced` |
| `cost_tier` | enum | `free`, `low`, `medium`, `high` |
| `speed_tier` | enum | `fast`, `medium`, `slow` |
| `reasoning` | enum | `basic`, `extended` (chain-of-thought) |
| `json_compliance` | enum | `strict`, `best-effort` |
| `locality` | enum | `local` (on-device), `remote` (cloud API) |
| `max_agents` | u32 | Maximum concurrent agents for this model |

### 3.3 Runtime Layer (learned)

Updated after each agent execution via rolling averages:

| Field | Type | Description |
|-------|------|-------------|
| `total_calls` | u64 | Lifetime tool-use calls |
| `total_tokens` | u64 | Lifetime token consumption |
| `avg_latency_ms` | f64 | Rolling average latency |
| `success_rate` | f64 | Rolling success rate (0.0--1.0) |
| `by_task` | map | Per-task-type breakdown (calls, successes, rate) |

### 3.4 OCI Distribution

For OCI-hosted models, the composite card is stored as a side
artifact using the OCI Referrers API (Distribution Spec 1.1 [4]).
The artifact type is `application/vnd.myelix.model-card.v1+json`,
linked to the model manifest via the `subject` descriptor. This
allows cards to travel with model images across registries without
modifying the model artifact itself.

## 4. Auto-Population

Each registry transport implements a `metadata()` method that returns
a `VendorMeta` struct.

**Ollama**: The transport fetches the manifest from
`/v2/library/{model}/manifests/{tag}`, extracts the model family from
the name, parameter count from the tag, and estimates quantization
from file size and parameter count (bytes-per-parameter heuristic).
At demo startup, the gateway queries `/api/show` for each locally
available model to populate `family`, `parameter_size`,
`quantization_level`, and `context_length`, then derives `speed_tier`
from model size on disk.

**HuggingFace**: The transport queries `/api/models/{org}/{repo}`,
extracting `pipeline_tag` as task, `tags` for license and format,
`cardData.language` for languages, and parsing the repository name
for family and parameter count.

**OCI**: The transport fetches the manifest, retrieves the
`Docker-Content-Digest` header, then queries the Referrers API for
side artifacts of type `application/vnd.myelix.model-card.v1+json`.
If found, the full card is deserialized from the referrer blob. If
not, basic metadata (source only) is returned.

Operator-defined agentic fields are configured in TOML under
`[models.<name>.agentic]` and merged into the card at startup.
Non-empty operator fields overwrite auto-populated defaults; empty
fields preserve existing values.

## 5. Agent-Driven Model Selection

The gateway exposes a `models_list` MCP tool whose description
embeds selection guidelines as prompt engineering:

- For file reading and data gathering: prefer `locality=local` and
  `cost_tier=free`
- For synthesis and complex reasoning: use `reasoning=extended` or
  `tool_use=advanced`
- For sensitive data: **must** use `locality=local` (data stays on
  device)
- For simple tasks: prefer `speed_tier=fast` and `cost_tier=free`
- Check `runtime.by_task` when available --- real data beats operator
  assumptions

The lead agent calls `models_list` before creating teammates, reads
the composite cards, and assigns models based on task requirements.
In a security audit demo, the lead assigned `granite3.3:8b`
(`locality=local`, `cost_tier=free`, `speed_tier=fast`) to three
data-gathering teammates scanning source files, and reserved
`gemma4:26b` (`speed_tier=medium`, `reasoning=extended`) for the
synthesis teammate that produced the final report. When Information
Flow Control detected that a teammate accessed confidential data
(e.g., source files containing secrets), the system blocked remote
model backends and required `locality=local`, enforcing data
sovereignty at the infrastructure layer.

## 6. Evaluation

**Before composite cards**: A multi-agent security audit ran all
five teammates on Claude (cloud API). Three data-gathering agents
performing file reads triggered HTTP 429 rate limits within the first
two minutes. The lead had no metadata to inform model selection, so
all teammates received the same expensive model. Total audit time
exceeded 10 minutes with multiple retry cycles.

**After composite cards**: The lead read model cards via
`models_list`, assigned local models for data gathering and reserved
the cloud model for synthesis only. Rate-limit errors dropped to
zero. End-to-end audit time decreased from ~10 minutes to ~3 minutes
(3x improvement). Cost decreased proportionally: three teammates
consumed zero API credits by running on local Ollama models
(`cost_tier=free`). The runtime layer accumulated per-task success
rates, enabling future leads to refine model assignments based on
empirical data rather than operator assumptions alone.

## 7. Upstream Contribution Path

We propose contributing the agentic metadata schema to the Kubeflow
Model Registry. The registry's `customProperties` map on
`RegisteredModel` and `ModelVersion` already supports typed key-value
pairs. We propose a set of well-known keys:

- `agentic.tool_use`: `none | basic | advanced`
- `agentic.cost_tier`: `free | low | medium | high`
- `agentic.speed_tier`: `fast | medium | slow`
- `agentic.reasoning`: `basic | extended`
- `agentic.json_compliance`: `strict | best-effort`
- `agentic.locality`: `local | remote`
- `agentic.strengths`: comma-separated capability tags
- `agentic.recommended_tasks`: comma-separated task types

Issue kubeflow/model-registry#449 (model card metadata) is stale
since 2024, with all contributors from Red Hat. The plugin
architecture (#2220) provides a natural extension point. OpenShift
AI, which uses Kubeflow Model Registry as its catalog, would
immediately benefit from standardized agentic fields for its model
serving infrastructure.

## 8. Conclusion

Model registries must evolve beyond describing what a model *is* to
describing what it is *good at* in agentic contexts. The Composite
Model Card schema --- vendor, agentic, runtime --- provides a
practical bridge between registry metadata and runtime model
selection. Auto-population from existing APIs minimizes operator
burden; the agentic layer captures domain knowledge no registry
currently encodes; the runtime layer enables empirical refinement.
We call for standardized agentic capability metadata across model
registries, starting with well-known keys in Kubeflow Model
Registry's `customProperties` and OCI side artifacts for portable
model cards.

## References

[1] LangChain, "Agentic Engineering: Building Reliable AI Agent
Systems," 2026.

[2] Ollama, "Ollama API Documentation," https://github.com/ollama/ollama/blob/main/docs/api.md

[3] Kubeflow Model Registry, https://github.com/kubeflow/model-registry

[4] Open Container Initiative, "OCI Distribution Specification v1.1,"
https://github.com/opencontainers/distribution-spec/blob/v1.1.0/spec.md

[5] HuggingFace, "Model Cards," https://huggingface.co/docs/hub/model-cards

[6] Google Cloud, "Vertex AI Model Garden,"
https://cloud.google.com/vertex-ai/docs/start/explore-models

[7] Red Hat, "OpenShift AI Model Registry,"
https://docs.redhat.com/en/documentation/red_hat_openshift_ai_self-managed/
