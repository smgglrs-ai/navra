# Configuration Reference

navra reads its configuration from `~/.config/navra/config.toml`.
Override with `navra serve --config /path/to/config.toml`.

All paths support `~` expansion. If the config file does not exist,
navra starts with defaults for all optional fields.

See [examples/config.toml](examples/config.toml) for an annotated
starter config.

## Table of Contents

- [server](#server)
- [modules](#modules)
- [agents](#agents)
- [permissions](#permissions)
- [upstream](#upstream)
- [models](#models)
- [credentials](#credentials)
- [budget](#budget)
- [triggers](#triggers)
- [routing](#routing)
- [statistical](#statistical)
- [temporal_contracts](#temporal-contracts)
- [registry](#registry)
- [Top-level fields](#top-level-fields)

---

## server

Gateway transport and identity configuration.

```toml
[server]
socket = "~/.run/navra/navra.sock"
tcp = "127.0.0.1:9315"
mcp_version = "2026-07-28"
```

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `socket` | string | `~/.run/navra/navra.sock` | Unix domain socket path for MCP transport |
| `tcp` | string | *none* | TCP listen address (e.g. `127.0.0.1:9315`). Binds to localhost only |
| `hook_timeout_secs` | integer | `10` | Per-hook execution timeout in seconds |
| `mcp_version` | string | `2026-07-28` | MCP protocol version. `2026-07-28` (stateless) or `2025-03-26` (legacy sessions) |
| `pii_model_path` | string | *none* | Path to English PII NER ONNX model directory |
| `pii_multilingual_model_path` | string | *none* | Path to multilingual PII NER ONNX model directory |
| `containerized` | boolean | *auto-detect* | Force containerized mode. `true` = always, `false` = never, omit = auto-detect |
| `allow_direct_execution` | boolean | `false` | Allow unsandboxed exec when container runtime is unavailable |
| `agent_image` | string | `localhost/navra-agent:latest` | Container image for agent sandboxes |
| `model_server_image` | string | `ghcr.io/ggerganov/llama.cpp:server-cuda` | Container image for shared GPU model server |
| `openshell_gateway` | string | *none* | OpenShell compute driver gRPC endpoint |
| `container_memory` | string | `2g` | Memory limit per agent container (e.g. `512m`, `4g`) |
| `container_cpus` | string | `2` | CPU limit per agent container (e.g. `0.5`, `4`) |
| `container_pids` | integer | `256` | Maximum PIDs per agent container |
| `config_watch` | boolean | `false` | Watch config file for changes and hot-reload |
| `config_watch_debounce_ms` | integer | `50` | Debounce interval in ms for config file watch events |

### server.discovery

Advertise navra via AID (Agent Identity Discovery) and mDNS.

```toml
[server.discovery]
url = "https://tools.example.com/mcp"
mdns = true
auth = "pat"
```

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `url` | string | *required* | Externally-reachable URL of this navra's MCP endpoint |
| `mdns` | boolean | `false` | Enable mDNS/DNS-SD advertising on local network |
| `auth` | string | `pat` | Auth hint: `none`, `pat`, `apikey`, `oauth2_code`, `mtls` |
| `description` | string | *none* | Human-readable description (max 60 bytes per AID spec) |
| `docs_url` | string | *none* | Documentation URL |
| `timeout_secs` | integer | `10` | Timeout for AID HTTP lookups and mDNS browse |
| `mdns_browse_secs` | integer | `3` | mDNS browse duration in seconds |

### server.identity

Root identity for DID-based authentication and capability token issuance.

```toml
[server.identity]
token_ttl = 3600
max_delegation_depth = 3
```

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `key_path` | string | *none* | Path to Ed25519 seed file. If omitted, OS keyring is used |
| `token_ttl` | integer | `3600` | Default capability token TTL in seconds |
| `max_delegation_depth` | integer | `3` | Maximum delegation chain depth |
| `nonce_cache_ttl_secs` | integer | `7200` | Nonce cache TTL for replay prevention |

---

## modules

Enable or disable built-in modules. Each module is optional.

### modules.file

File tools and FTS5 indexing.

```toml
[modules.file]
enabled = true
db = "~/.local/share/navra/index.db"
watch = ["~/Projects"]
```

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `enabled` | boolean | `true` | Enable file module |
| `db` | string | `~/.local/share/navra/index.db` | Path to FTS5 index database |
| `default_root` | string | *none* | Default root path for `file_tree` |
| `watch` | list of strings | `[]` | Directories to watch for auto-reindexing |

### modules.git

```toml
[modules.git]
enabled = true
```

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `enabled` | boolean | `true` | Enable git tools (status, diff, log, branch, commit) |

### modules.github

```toml
[modules.github]
enabled = true
```

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `enabled` | boolean | `true` | Enable GitHub tools. Requires `gh` CLI authenticated |

### modules.gitlab

```toml
[modules.gitlab]
enabled = true
```

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `enabled` | boolean | `true` | Enable GitLab tools. Requires `glab` CLI authenticated |

### modules.rag

Hybrid FTS5 + vector search with cross-encoder reranking. Can run as a standalone microservice in its own container for composability.

```toml
[modules.rag]
enabled = true
db = "~/.local/share/navra/rag.db"
query_cache_ttl_secs = 300
```

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `enabled` | boolean | `true` | Enable RAG module |
| `db` | string | `~/.local/share/navra/rag.db` | Path to RAG database |
| `reranker_model_path` | string | *none* | Path to ONNX cross-encoder model for reranking |
| `reranker_tokenizer_path` | string | *none* | Path to tokenizer.json for the cross-encoder |
| `query_cache_ttl_secs` | integer | `300` | Query cache TTL in seconds. `0` disables caching |
| `query_cache_max_entries` | integer | `1000` | Maximum cached query entries |

### modules.voice

Speech I/O via ONNX models (ASR + TTS).

```toml
[modules.voice]
enabled = true
asr_model = "asr"
tts_model = "tts"
```

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `enabled` | boolean | `true` | Enable voice module |
| `asr_model` | string | `asr` | Name of ASR model in `[models.*]` |
| `tts_model` | string | `tts` | Name of TTS model in `[models.*]` |
| `vad_threshold` | float | `0.01` | Voice Activity Detection energy threshold (RMS) |
| `max_record_secs` | integer | `30` | Maximum recording duration in seconds |
| `silence_timeout_ms` | integer | `1500` | Silence timeout before auto-stop |
| `voice` | string | *none* | Default TTS voice |

### modules.vision

Image and screen understanding.

```toml
[modules.vision]
enabled = true
model = "vision"
```

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `enabled` | boolean | `true` | Enable vision module |
| `model` | string | `vision` | Name of vision model in `[models.*]` |

### modules.memory

Working memory and knowledge store with PII-aware retention.

```toml
[modules.memory]
pii_filter = "standard"
retention_days = 90
```

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `pii_filter` | string | `standard` | PII filter profile: `standard`, `secrets-only`, `none` |
| `retention_days` | integer | *none* | Auto-delete knowledge entries older than N days |
| `pii_retention_days` | integer | `30` | Stricter TTL for PII-flagged entries |
| `audit_retention_days` | integer | `365` | Auto-delete audit logs older than N days |

### modules.registry

MCP server registry for discovery.

```toml
[modules.registry]
enabled = true
cache_ttl_secs = 3600
```

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `enabled` | boolean | `true` | Enable registry module |
| `cache_ttl_secs` | integer | `3600` | Cache TTL for registry responses |

---

## agents

Each `[[agents]]` block defines an authenticated agent that can connect to navra. Generate tokens with `navra token generate`.

```toml
[[agents]]
name = "claude"
token_hash = "b3a1..."
permissions = "dev"
```

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `name` | string | *required* | Agent identifier |
| `token_hash` | string | *required* | SHA-256 hash of agent token |
| `permissions` | string | *required* | Permission set name (key in `[permissions.*]`) |
| `signing_key` | string | *none* | Path to Ed25519 private key for git commit signing |
| `pubkey` | string | *none* | Path to Ed25519 public key for capability token auth |
| `did` | string | *none* | DID:key identifier (alternative to pubkey file) |
| `capability_token` | boolean | `false` | Enable capability token issuance for this agent |
| `token_ttl` | integer | *none* | Override token TTL for this agent (seconds) |

---

## permissions

Named permission sets referenced by `[[agents]].permissions`. Deny rules always beat allow rules.

```toml
[permissions.dev]
ring = 1
allow = ["git_*", "file_read", "file_write"]
deny = ["exec_run"]
safety = "standard"
default_tool_policy = "allow"
can_delegate = true
rate_limit = "60/60"
```

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `ring` | integer | *none* | Privilege ring (0 = most privileged, 3 = most restricted) |
| `allow` | list of strings | `[]` | Allowed tool glob patterns |
| `deny` | list of strings | `[]` | Denied tool glob patterns. **Deny always wins** |
| `operations` | list of strings | `[]` | High-level operations allowed |
| `approve` | list of strings | `[]` | Operations requiring human-in-the-loop approval |
| `safety` | string | `standard` | Safety profile: `standard`, `pseudonymize`, `secrets-only`, `block`, `multi-label`, `guardian`, `guardian-deep`, `none` |
| `safety_thresholds` | table | `{}` | Per-category confidence thresholds for `multi-label` safety (e.g. `harm = 0.7`) |
| `compliance` | list of strings | `[]` | Compliance tags (e.g. `SOC2-CC6.1`, `GDPR-Art17`) |
| `default_tool_policy` | string | `allow` | Default policy for tools not matching any rule: `allow`, `deny`, `approve` |
| `credentials` | list of strings | `[]` | Credential labels accessible to this permission set |
| `can_delegate` | boolean | `false` | Allow capability token delegation to sub-agents |
| `rate_limit` | string | *none* | Rate limit as `calls/seconds` (e.g. `60/60` = 60 calls per minute) |
| `tainted_write_policy` | string | `allow` | Policy for writes after external reads: `allow`, `approve`, `deny` |
| `trusted_paths` | list of strings | `[]` | Glob patterns for paths that remain Trusted (no IFC taint) |
| `tool_disclosure_include` | list of strings | `[]` | Tool glob patterns to show in `tools/list` |
| `tool_disclosure_exclude` | list of strings | `[]` | Tool glob patterns to hide from `tools/list` |

### permissions.\<name\>.tool_rules

Per-tool policy overrides.

```toml
[[permissions.dev.tool_rules]]
tool = "exec_*"
policy = "approve"
```

| Key | Type | Description |
|-----|------|-------------|
| `tool` | string | Glob pattern matching tool names |
| `policy` | string | `allow`, `deny`, or `approve` |

### permissions.\<name\>.safety_patterns

Custom regex patterns for content safety.

```toml
[[permissions.dev.safety_patterns]]
category = "internal-url"
pattern = "https://internal\\.example\\.com/.*"
```

| Key | Type | Description |
|-----|------|-------------|
| `category` | string | Category name for this pattern |
| `pattern` | string | Regex pattern to match |

---

## upstream

Proxy external MCP servers through navra with safety filtering.

```toml
[[upstream]]
name = "filesystem"
transport = "stdio"
command = ["npx", "-y", "@modelcontextprotocol/server-filesystem", "/tmp"]

[[upstream]]
name = "remote-tools"
transport = "http"
url = "http://localhost:8001/mcp"
```

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `name` | string | *required* | Upstream server name |
| `transport` | string | `stdio` | Transport: `stdio`, `http`, `sse` |
| `command` | list of strings | `[]` | Command for `stdio` transport |
| `cwd` | string | *none* | Working directory for `stdio` transport |
| `url` | string | *none* | URL for `http`/`sse` transport |
| `enabled` | boolean | *none* | Enable or disable this upstream |
| `retry_base_delay_ms` | integer | `1000` | Retry base delay in ms |
| `retry_max_delay_ms` | integer | `30000` | Maximum retry delay in ms |
| `retry_budget_secs` | integer | `600` | Total retry budget in seconds |
| `request_timeout_secs` | integer | `45` | Per-request timeout in seconds |

---

## models

Configure local ONNX models and remote model backends.

```toml
[models.safety]
model_path = "~/.local/share/navra/models/safety.onnx"
task = "classification"
labels = ["safe", "unsafe"]
threshold = 0.5

[models.embeddings]
source = "ollama://nomic-embed-text"
task = "embedding"
dimensions = 768

[models.granite-code]
source = "hf://ibm-granite/granite-3.0-8b-instruct"
task = "chat"
execution_mode = "served"
format = "gguf"
```

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `model_path` | string | *none* | Path to local ONNX model file |
| `source` | string | *none* | Hub source URI: `ollama://`, `hf://`, `oci://` |
| `tokenizer_path` | string | *none* | Path to HuggingFace tokenizer.json |
| `task` | string | `embedding` | Task type: `embedding`, `classification`, `chat`, `generate` |
| `device` | string | *none* | Device: `cpu`, `cuda`, `openvino`, `openvino:AUTO` |
| `dimensions` | integer | *none* | Embedding dimensions |
| `labels` | list of strings | `[]` | Classification labels |
| `threshold` | float | `0.5` | Confidence threshold for safety classification |
| `format` | string | *none* | Model format: `gguf`, `safetensors`, `awq`, `gptq` |
| `execution_mode` | string | *none* | `in_process` (ONNX in navra) or `served` (llama.cpp server) |
| `runtime` | string | *none* | Backend: `auto`, `podman`, `direct`, `none` |
| `context_size` | integer | `4096` | Context window size |
| `parallel` | integer | `1` | Parallel request slots |
| `model_name` | string | *none* | Model name for OpenAI-compatible API |
| `cache_type` | string | *none* | KV cache quantization type |

### models.\<name\>.speculative

Enable speculative decoding with a draft model.

```toml
[models.large.speculative]
draft_model = "small"
draft_tokens = 10
draft_min_p = 0.1
```

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `draft_model` | string | *required* | Draft model identifier (key in `[models.*]`) |
| `draft_tokens` | integer | `5` | Number of draft tokens to generate |
| `draft_min_p` | float | *required* | Minimum probability for draft acceptance |

### models.\<name\>.agentic

Operator-defined model capabilities for runtime selection.

```toml
[models.granite-code.agentic]
strengths = ["code generation", "fast inference"]
weaknesses = ["limited reasoning"]
recommended_tasks = ["code review"]
tool_use = "basic"
cost_tier = "free"
speed_tier = "fast"
```

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `strengths` | list of strings | `[]` | Model strengths |
| `weaknesses` | list of strings | `[]` | Model weaknesses |
| `recommended_tasks` | list of strings | `[]` | Recommended task types |
| `avoid_tasks` | list of strings | `[]` | Tasks to avoid |
| `tool_use` | string | *none* | Tool use level |
| `cost_tier` | string | *none* | Cost tier: `free`, `cheap`, `expensive` |
| `speed_tier` | string | *none* | Speed tier: `fast`, `medium`, `slow` |
| `max_agents` | integer | *none* | Maximum concurrent agents using this model |
| `reasoning` | string | *none* | Reasoning capability level |
| `json_compliance` | string | *none* | JSON output compliance level |
| `locality` | string | *none* | Execution locality |

---

## credentials

Map credential labels to backend sources. Used by permission sets via the `credentials` field.

```toml
[credentials."github.pat"]
source = "env"
var = "GITHUB_TOKEN"

[credentials."ssh.key"]
source = "keyring"
path = "navra/ssh-private-key"
```

| Key | Type | Description |
|-----|------|-------------|
| `source` | string | Backend: `keyring` or `env` |
| `path` | string | Keyring path (for `source = "keyring"`) |
| `var` | string | Environment variable name (for `source = "env"`) |

---

## budget

Resource limits for multi-agent flows and teams.

```toml
[budget]
max_agents = 50
max_depth = 5
timeout_secs = 3600
max_iterations = 200
max_parallel = 4
checkpoint = true
```

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `max_agents` | integer | `50` | Total agents across all teams/flows |
| `max_depth` | integer | `5` | Maximum escalation nesting depth |
| `timeout_secs` | integer | `3600` | Timeout per flow tree in seconds |
| `max_iterations` | integer | `200` | Maximum ReAct iterations per agent |
| `max_parallel` | integer | `2` | Maximum concurrent agents (GPU-bound) |
| `max_tool_output_tokens` | integer | `0` | Max output tokens before truncation. `0` = disabled |
| `truncation_strategy` | string | `head_tail` | Strategy: `truncate`, `head_tail`, `summarize` |
| `head_ratio` | float | `0.7` | Head/tail ratio for `head_tail` strategy |
| `checkpoint` | boolean | `false` | Enable SQLite checkpointing for crash recovery |
| `checkpoint_db` | string | `~/.local/share/navra/checkpoints.db` | Path to checkpoint database |

---

## triggers

Event-driven triggers that start flows automatically.

### Webhook trigger

```toml
[[triggers]]
type = "webhook"
path = "/hook/deploy"
secret = "hmac-secret-here"
flow_name = "deploy-flow"
```

| Key | Type | Description |
|-----|------|-------------|
| `type` | `"webhook"` | Trigger type |
| `path` | string | URL path suffix |
| `secret` | string | HMAC-SHA256 secret for verification |
| `flow_name` | string | Flow to start when triggered |

### Cron trigger

```toml
[[triggers]]
type = "cron"
schedule = "0 9 * * 1-5"
flow_name = "daily-review"
```

| Key | Type | Description |
|-----|------|-------------|
| `type` | `"cron"` | Trigger type |
| `schedule` | string | Cron expression: `minute hour dom month dow` |
| `flow_name` | string | Flow to start on schedule |

### File watch trigger

```toml
[[triggers]]
type = "file_watch"
path = "~/Documents/inbox"
pattern = "*.pdf"
flow_name = "process-document"
debounce_ms = 500
```

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `type` | `"file_watch"` | | Trigger type |
| `path` | string | *required* | Directory to watch (supports `~`) |
| `pattern` | string | *none* | Glob filter (e.g. `*.pdf`) |
| `flow_name` | string | *required* | Flow to start when files change |
| `debounce_ms` | integer | `500` | Debounce interval in ms |

---

## routing

Cost-aware model routing. Routes tool calls to different model tiers based on complexity.

```toml
[routing]
enabled = true
default_tier = "medium"

[[routing.tiers]]
name = "small"
model = "qwen2.5:3b"
max_tokens = 1000
patterns = ["embedding_*"]

[[routing.tiers]]
name = "large"
model = "granite-20b"
max_tokens = 10000
patterns = ["reasoning_*"]
```

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `enabled` | boolean | `false` | Enable cost-aware routing |
| `default_tier` | string | `medium` | Default tier when no rule matches |

**Tier fields:**

| Key | Type | Description |
|-----|------|-------------|
| `name` | string | Tier name (e.g. `small`, `medium`, `large`) |
| `model` | string | Model identifier for this tier |
| `max_tokens` | integer | Maximum estimated input tokens for this tier |
| `patterns` | list of strings | Tool name glob patterns routed to this tier |

---

## statistical

Statistical guardrail hook for anomaly detection in agent behavior.

```toml
[statistical]
enabled = true
cosine_window = 50
cosine_z_threshold = 3.0
entropy_window = 20
entropy_min = 0.5
entropy_max = 4.0
block_on_anomaly = false
```

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `enabled` | boolean | `false` | Enable statistical guardrails |
| `cosine_window` | integer | `50` | Sliding window for cosine drift detection |
| `cosine_z_threshold` | float | `3.0` | Z-score threshold for drift anomalies |
| `entropy_window` | integer | `20` | Sliding window for entropy monitoring |
| `entropy_min` | float | `0.5` | Minimum acceptable entropy (below = fixation) |
| `entropy_max` | float | `4.0` | Maximum acceptable entropy (above = scatter) |
| `block_on_anomaly` | boolean | `false` | Block tool calls on anomaly (vs warn only) |
| `transition_window` | integer | `50` | Window for transition analysis |
| `transition_min_observations` | integer | `10` | Minimum observations before transition detection |

---

## temporal_contracts

Trajectory-level behavioral contracts that enforce tool call ordering.

```toml
[temporal_contracts]
enabled = true
max_history_per_session = 200

[[temporal_contracts.contracts]]
name = "read-before-write"
description = "Must read a file before writing"
predicate = { type = "requires", tool = "file_write", prerequisite = "file_read" }
action = { type = "block", value = "Read the file first" }
applies_to = ["*"]
```

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `enabled` | boolean | `false` | Enable temporal contracts |
| `max_history_per_session` | integer | `200` | Max action history entries per session |

**Contract fields:**

| Key | Type | Description |
|-----|------|-------------|
| `name` | string | Contract name |
| `description` | string | Human-readable description |
| `predicate` | table | Predicate definition (JSON object) |
| `action` | table | Action on violation (JSON object) |
| `applies_to` | list of strings | Tool/agent glob patterns this applies to |

---

## registry

Whitelisted external MCP server registries.

```toml
[[registry]]
name = "company-tools"
registry_type = "mcp"
remote_type = "streamable-http"
url = "https://tools.example.com/mcp"
```

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `name` | string | *required* | Registry name |
| `description` | string | *none* | Human-readable description |
| `registry_type` | string | `mcp` | Type: `mcp`, `http`, `aws_agent_registry` |
| `remote_type` | string | `streamable-http` | Transport: `streamable-http`, `sse`, `stdio` |
| `url` | string | *required* | Registry endpoint URL |
| `repository` | string | *none* | Source repository URL |
| `search_url` | string | *none* | URL template for search (`{query}` placeholder) |
| `results_path` | string | *none* | JSON path to results (e.g. `data.results`) |

---

## Top-level fields

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `cognitive_core` | string | *none* | Path to cognitive core directory (personas, heuristics, directives) |
| `flow_dirs` | list of strings | `[]` | Directories containing flow YAML definitions |
| `discover` | list of strings | `[]` | Domains to query for AID upstream discovery at startup |

---

## approval

Human-in-the-loop approval configuration.

```toml
[approval]
timeout_secs = 300
notify = "dbus"
```

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `timeout_secs` | integer | `300` | Approval request timeout in seconds |
| `grant_ttl_secs` | integer | `300` | TTL for cached approval grants |
| `notify` | string | `dbus` | Notification backend |

---

## pii_patterns

Custom PII patterns applied globally to all safety pipelines.

```toml
[[pii_patterns]]
name = "employee-id"
regex = "EMP-\\d{6}"
category = "employee-id"
```

| Key | Type | Description |
|-----|------|-------------|
| `name` | string | Human-readable pattern name |
| `regex` | string | Regex pattern to match |
| `category` | string | PII category name |
