+++
title = "Configuration"
description = "config.toml reference — server, permissions, modules, agents, upstream."
weight = 40
template = "docs/section.html"

[extra]
toc = true
+++

Default path: `~/.config/navra/config.toml`

## Server

```toml
[server]
socket = "/run/user/1000/navra/navra.sock"
tcp = "127.0.0.1:9315"
hook_timeout_secs = 10
mcp_version = "2026-07-28"
agent_signature_policy = "warn"
config_watch = false
config_watch_debounce_ms = 50
```

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `socket` | string | `$XDG_RUNTIME_DIR/navra/navra.sock` | Unix socket path |
| `tcp` | string | -- | TCP listen address (used instead of socket when set) |
| `hook_timeout_secs` | u64 | `10` | Per-hook timeout in seconds |
| `mcp_version` | string | `"2026-07-28"` | MCP protocol version (`2026-07-28` or `2025-03-26`) |
| `agent_signature_policy` | string | `"warn"` | Bundle signature policy: `enforce`, `warn`, `skip` |
| `ws_ping_interval_secs` | u64 | `30` | WebSocket ping interval |
| `ws_idle_timeout_secs` | u64 | `600` | WebSocket idle timeout (10 min) |
| `config_watch` | bool | `false` | Watch config file for changes and hot-reload |
| `config_watch_debounce_ms` | u64 | `50` | Debounce interval for config file watch events |

### PII models

```toml
[server]
pii_model_path = "~/.local/share/navra/models/pii-ner"
pii_multilingual_model_path = "~/.local/share/navra/models/pii-ner-multilingual"
```

Install PII NER models with `navra pii download` (English) or
`navra pii download --multilingual`.

### Container settings

```toml
[server]
containerized = true              # true/false/absent (auto-detect)
allow_direct_execution = false    # allow unsandboxed execution when no runtime found
agent_image = "localhost/navra-agent:latest"
model_server_image = "ghcr.io/ggerganov/llama.cpp:server-cuda"
container_memory = "2g"
container_cpus = "2"
container_pids = 256
openshell_gateway = "unix:///run/openshell/gateway.sock"
```

### Identity and discovery

```toml
[server.identity]
key_path = "~/.config/navra/root.key"   # Ed25519 seed file (or OS keyring)
token_ttl = 3600                         # capability token TTL in seconds
max_delegation_depth = 3
nonce_cache_ttl_secs = 7200

[server.discovery]
url = "https://tools.example.com/mcp"
mdns = true
auth = "pat"
description = "Code analysis tools"
docs_url = "https://docs.example.com"
timeout_secs = 10
mdns_browse_secs = 3
```

## Permissions

Permission sets define what agents can do. Each set specifies allowed
operations, tools, paths, and safety profiles.

```toml
[permissions.default]
operations = ["read", "search", "list"]
tools = ["file_tree", "file_read", "file_grep"]

[permissions.developer]
operations = ["read", "write", "search", "list"]
tools = ["file_tree", "file_read", "file_write", "file_edit", "file_grep"]
paths = ["/home/user/projects"]
safety = "standard"
```

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `ring` | u8 | -- | Privilege ring (0 = most, 3 = least privileged) |
| `allow` | string[] | `[]` | Allowed file path globs |
| `deny` | string[] | `[]` | Denied file path globs (deny wins) |
| `operations` | string[] | `[]` | Allowed operation namespaces |
| `approve` | string[] | `[]` | Operations requiring human approval |
| `safety` | string | `"standard"` | Safety profile (see below) |
| `default_tool_policy` | string | `"allow"` | Default for unmatched tools: `allow`, `deny`, `approve` |
| `can_delegate` | bool | `false` | Whether agents can delegate capabilities |

### Safety profiles

| Profile | Description |
|---------|-------------|
| `standard` | Regex-based secret and PII detection |
| `secrets-only` | Only detect secrets (API keys, passwords) |
| `pseudonymize` | Replace PII with pseudonyms |
| `block` | Block content containing PII or secrets |
| `multi-label` | Multi-label classifier with per-category thresholds |
| `guardian` | Guardian HAP safety model |
| `guardian-deep` | Guardian with deeper analysis |
| `none` | No content filtering |

### Safety thresholds (multi-label)

```toml
[permissions.dev.safety_thresholds]
harm = 0.7
jailbreak = 0.9
pii = 0.5
refusal = 0.8
```

### Custom safety patterns

```toml
[[permissions.dev.safety_patterns]]
category = "internal-url"
pattern = "https?://internal\\.example\\.com/.*"
```

### Rate limiting

```toml
[permissions.agent]
rate_limit = "60/60"   # 60 tool calls per 60-second window
```

The format is `<calls>/<seconds>`. When the limit is exceeded, tool
calls are rejected until the window resets.

### Tool rules

```toml
[permissions.developer]
default_tool_policy = "deny"
tool_rules = [
  { tool = "file_read", policy = "allow" },
  { tool = "file_write", policy = "approve" },
  { tool = "shell_*", policy = "deny" },
]
```

Tool name patterns support glob matching (`*` suffix).

### Domain rules

Semantic domain-based access control, evaluated before tool rules:

```toml
[permissions.readonly]
domain_rules = [
  { domain = "filesystem", operations = ["read"] },
  { domain = "git", operations = ["read"] },
  { domain = "shell", operations = [] },      # deny all shell
  { domain = "*", operations = ["read"] },     # default for unlisted domains
]
```

### Tool classification overrides

Override auto-classification for specific tools:

```toml
[permissions.readonly.tool_class]
zip_files = { domain = "filesystem", operation = "write" }
```

### IFC (Information Flow Control)

```toml
[permissions.dev]
tainted_write_policy = "approve"   # "allow", "approve", or "deny"
trusted_paths = ["~/Code/myproject/**", "~/Documents/**"]
```

When an agent reads external data (taint rises to Untrusted), the
`tainted_write_policy` controls whether subsequent writes are allowed.
Paths in `trusted_paths` keep their Trusted integrity label.

### Tool disclosure

Control which tools appear in `tools/list` responses (UI-level only):

```toml
[permissions.limited]
tool_disclosure_include = ["file_*", "rag_*"]
tool_disclosure_exclude = ["file_delete"]
```

### Egress filtering

```toml
[permissions.sandboxed]
egress_deny_all_external = true
egress_allowed_domains = ["api.github.com", "*.googleapis.com"]
egress_blocked_domains = ["evil.example.com"]
```

### Compliance tags

```toml
[permissions.hipaa]
compliance = ["SOC2-CC6.1", "EU-AI-Act-Art-14", "HIPAA-164.312"]
```

Informational tags logged at startup for audit trail.

### PII patterns (global)

Custom PII patterns applied globally across all safety pipelines:

```toml
[[pii_patterns]]
name = "employee-id"
regex = "EMP-[0-9]{6}"
category = "employee-id"
```

Categories defined here are treated as PII for IFC labeling.

## Agents

Agent definitions bind a name and permission set to an identity.

```toml
[[agents]]
name = "claude"
token_hash = "sha256_hash_of_token"
permissions = "developer"
```

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `name` | string | -- | Unique agent identifier |
| `token_hash` | string | -- | SHA-256 hash of the agent's bearer token |
| `permissions` | string | -- | Permission set name from `[permissions]` |
| `signing_key` | string | -- | Ed25519 key path for git commit signing |
| `pubkey` | string | -- | Ed25519 public key for capability token auth |
| `did` | string | -- | DID:key identifier (alternative to pubkey) |
| `capability_token` | bool | `false` | Enable capability token issuance |
| `token_ttl` | u64 | -- | Override token TTL for this agent (seconds) |

Generate a token:

```bash
navra token generate --name claude --permissions developer
```

## Upstream MCP Servers

Connect external MCP servers through the gateway's security pipeline.

```toml
[[upstream]]
name = "github"
transport = "stdio"
command = ["npx", "-y", "@modelcontextprotocol/server-github"]
env = { GITHUB_TOKEN = "${credential:github_token}" }

[[upstream]]
name = "jira"
openapi = "https://jira.example.com/v3/api-docs"
[upstream.auth]
bearer = "${JIRA_TOKEN}"
tool_filter = ["get_*", "*_search"]

[[upstream]]
name = "remote-server"
transport = "http"
url = "http://localhost:3200/mcp"
request_timeout_secs = 60
```

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `name` | string | -- | Upstream identifier |
| `transport` | string | `"stdio"` | Transport: `stdio`, `http`, `sse` |
| `command` | string[] | `[]` | Stdio server command and arguments |
| `cwd` | string | -- | Working directory for stdio transport |
| `url` | string | -- | URL for http/sse transport |
| `enabled` | bool | `true` | Enable or disable this upstream |
| `request_timeout_secs` | u64 | `45` | Request timeout |
| `retry_base_delay_ms` | u64 | `1000` | Retry base delay |
| `retry_max_delay_ms` | u64 | `30000` | Maximum retry delay |
| `retry_budget_secs` | u64 | `600` | Total retry budget |
| `tool_filter` | string[] | `[]` | Glob patterns to filter exposed tools |
| `tool_overrides` | map | `{}` | Per-tool operation overrides: `read`, `write`, `deny` |
| `max_response_bytes` | usize | `32768` | Max response body size for OpenAPI upstreams |
| `openapi` | string | -- | OpenAPI 3.x spec URL or file path |
| `env` | map | `{}` | Environment variables (`${credential:label}` for keyring) |
| `credentials` | map | `{}` | Env var name to keyring label mappings |

### Upstream tool classification

```toml
[upstream.tool_class]
zip_files = { domain = "filesystem", operation = "write" }
```

### OpenAPI authentication

```toml
[[upstream]]
name = "jira"
openapi = "https://jira.example.com/v3/api-docs"

[upstream.auth]
bearer = "${JIRA_TOKEN}"
# Or API key:
# api_key_name = "X-API-Key"
# api_key_value = "${API_KEY}"
# api_key_location = "header"   # or "query"
# Or basic auth:
# basic_username = "user"
# basic_password = "${PASSWORD}"
```

### Upstream OAuth 2.1

```toml
[[upstream]]
name = "secure-server"
transport = "http"
url = "https://mcp.example.com/mcp"

[upstream.oauth]
client_id = "navra-client"
client_secret = "${OAUTH_SECRET}"
flow = "auto"     # "auto", "code", "client_credentials", "device"
scopes = ["read", "write"]
```

### Network policy (sandboxed upstreams)

```toml
[[upstream]]
name = "restricted-server"
command = ["python3", "-m", "server"]

[upstream.network]
deny_all_external = true
allowed_domains = ["*.googleapis.com"]
blocked_domains = ["evil.example.com"]
allowed_ips = ["10.0.0.0/8"]
```

## Modules

### File module

```toml
[modules.file]
enabled = true
db = "~/.local/share/navra/index.db"
default_root = "~/Code"
watch = ["~/Code/myproject"]
```

### Git module

```toml
[modules.git]
enabled = true
```

### RAG module

```toml
[modules.rag]
enabled = true
db = "~/.local/share/navra/rag.db"
reranker_model_path = "~/.local/share/navra/models/reranker/model.onnx"
reranker_tokenizer_path = "~/.local/share/navra/models/reranker/tokenizer.json"
query_cache_ttl_secs = 300
query_cache_max_entries = 1000
```

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `enabled` | bool | `true` | Enable the RAG module |
| `db` | string | `~/.local/share/navra/rag.db` | SQLite database path |
| `reranker_model_path` | string | -- | ONNX cross-encoder model for reranking |
| `reranker_tokenizer_path` | string | -- | Tokenizer for the reranker model |
| `query_cache_ttl_secs` | u64 | `300` | Query cache TTL (0 = no caching) |
| `query_cache_max_entries` | usize | `1000` | Maximum cached query entries |

### Memory module

```toml
[modules.memory]
pii_filter = "standard"
retention_days = 90
pii_retention_days = 30
audit_retention_days = 365
auto_distill = true
```

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `pii_filter` | string | `"standard"` | PII filter profile: `standard`, `secrets-only`, `none` |
| `retention_days` | u32 | -- | Auto-delete knowledge entries after N days |
| `pii_retention_days` | u32 | `30` | Stricter TTL for PII-flagged entries |
| `audit_retention_days` | u32 | `365` | Audit log retention |
| `auto_distill` | bool | `true` | Distill facts from conversations on session end |

### Voice module

```toml
[modules.voice]
enabled = true
asr_model = "asr"
tts_model = "tts"
vad_threshold = 0.01
max_record_secs = 30
silence_timeout_ms = 1500
voice = "af_heart"
```

### Vision module

```toml
[modules.vision]
enabled = true
model = "vision"
```

### Registry module

```toml
[modules.registry]
enabled = true
cache_ttl_secs = 3600
```

## Models

Model configuration for local and remote backends.

```toml
[models.embed]
model_path = "~/.local/share/navra/models/granite-embed/model.onnx"
tokenizer_path = "~/.local/share/navra/models/granite-embed/tokenizer.json"
task = "embedding"
dimensions = 768

[models.granite-chat]
source = "ollama://granite3.3:8b"
task = "chat"
runtime = "auto"
context_size = 8192
```

See [Model server](/docs/guides/model-server/) for the full field
reference, runtime options, and speculative decoding configuration.

## Model Server

When set, the gateway connects to an external model server instead
of loading models in-process.

```toml
model_server = "http://127.0.0.1:9316"
```

Start the server with `navra model serve`. See the
[Model server guide](/docs/guides/model-server/) for deployment details.

## Budget

Resource limits for agent teams and flow execution.

```toml
[budget]
max_agents = 50
max_depth = 5
timeout_secs = 3600
max_iterations = 200
max_parallel = 2
max_tool_output_tokens = 0
truncation_strategy = "head_tail"
head_ratio = 0.7
max_tokens_per_run = 500000
checkpoint = true
checkpoint_db = "~/.local/share/navra/checkpoints.db"
```

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `max_agents` | u32 | `50` | Total agents across all teams/subflows |
| `max_depth` | u32 | `5` | Escalation nesting depth |
| `timeout_secs` | u64 | `3600` | Timeout per flow tree (30 min) |
| `max_iterations` | usize | `200` | ReAct iterations per agent |
| `max_parallel` | usize | `2` | Concurrent agents (GPU bound) |
| `max_tool_output_tokens` | usize | `0` | Tool output token limit (0 = unlimited) |
| `truncation_strategy` | string | `"head_tail"` | `truncate`, `head_tail`, `summarize` |
| `head_ratio` | f32 | `0.7` | Head ratio for head_tail truncation |
| `max_tokens_per_run` | u64 | -- | Total token circuit breaker per agent run |
| `compression_start_ratio` | f32 | -- | Context fill ratio to start compressing tool output |
| `compaction_keep_recent` | usize | -- | Recent items kept verbatim during compaction |
| `compaction_trigger_ratio` | f32 | -- | Context fill ratio to trigger conversation compaction |
| `checkpoint` | bool | `false` | Enable SQLite checkpointing for crash recovery |
| `checkpoint_db` | string | `~/.local/share/navra/checkpoints.db` | Checkpoint database path |

## Approval

Human-in-the-loop approval workflow.

```toml
[approval]
timeout_secs = 300
grant_ttl_secs = 300
notify = "dbus"
```

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `timeout_secs` | u64 | `300` | Timeout for human approval responses |
| `grant_ttl_secs` | u64 | `300` | TTL for cached approval grants |
| `notify` | string | `"dbus"` | Notification backend: `dbus` or `none` |

## Monitoring

Detect-only agent that observes tool calls without blocking.

```toml
[monitoring]
enabled = true
buffer_size = 256
```

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `enabled` | bool | `false` | Enable the monitoring agent |
| `buffer_size` | usize | `256` | Escalation channel buffer size |

## Statistical Guardrails

Anomaly detection for agent behavior using statistical signals.

```toml
[statistical]
enabled = true
cosine_window = 50
cosine_z_threshold = 3.0
entropy_window = 20
entropy_min = 0.5
entropy_max = 4.0
block_on_anomaly = false
transition_window = 50
transition_min_observations = 10
```

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `enabled` | bool | `false` | Enable statistical guardrails |
| `cosine_window` | usize | `50` | Sliding window for cosine drift detection |
| `cosine_z_threshold` | f64 | `3.0` | Z-score threshold for anomaly detection |
| `entropy_window` | usize | `20` | Sliding window for entropy monitoring |
| `entropy_min` | f64 | `0.5` | Minimum acceptable entropy (below = fixation) |
| `entropy_max` | f64 | `4.0` | Maximum acceptable entropy (above = scatter) |
| `block_on_anomaly` | bool | `false` | Block tool calls on anomaly (vs. warn) |
| `transition_window` | usize | `50` | Window for tool-transition anomaly detection |
| `transition_min_observations` | usize | `10` | Minimum observations before flagging |

## Temporal Contracts

Trajectory-level behavioral contracts that enforce ordering and
frequency constraints on tool calls.

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

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `enabled` | bool | `false` | Enable temporal contracts |
| `max_history_per_session` | usize | `200` | Action history entries per session |
| `contracts` | array | `[]` | List of contract definitions |

## Cost-Aware Routing

Route tool calls to different model tiers based on complexity.

```toml
[routing]
enabled = true
default_tier = "medium"

[[routing.tiers]]
name = "small"
model = "granite-2b"
max_tokens = 2048
patterns = ["file_read", "file_tree", "file_grep"]

[[routing.tiers]]
name = "medium"
model = "granite-8b"
max_tokens = 4096
patterns = ["*"]

[[routing.tiers]]
name = "large"
model = "granite-34b"
max_tokens = 8192
patterns = ["code_review_*", "planning_*"]
```

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `enabled` | bool | `false` | Enable cost-aware routing |
| `default_tier` | string | `"medium"` | Default tier for unmatched tools |
| `tiers` | array | `[]` | Ordered tier definitions |

Each tier specifies:

| Field | Type | Description |
|-------|------|-------------|
| `name` | string | Tier name for logging |
| `model` | string | Model identifier from `[models.*]` |
| `max_tokens` | usize | Maximum output tokens for this tier |
| `patterns` | string[] | Tool name glob patterns that route here |

## Credentials

Credential label to backend source mappings. Only credentials listed
here are accessible to agents.

```toml
[credentials]
github_token = { source = "keyring", label = "navra/github" }
api_key = { source = "env", var = "MY_API_KEY" }
```

## Cognitive Core

```toml
cognitive_core = "~/.config/navra/cognitive_core"
```

Path to the directory containing personas, heuristics, and directives.

## Flow Directories

```toml
flow_dirs = ["~/.config/navra/flows", "/etc/navra/flows.d"]
```

Directories containing flow TOML files for DAG-based multi-agent
orchestration.

## gRPC Modules

Out-of-process gRPC modules:

```toml
[[grpc_modules]]
name = "custom-tool"
address = "unix:///run/navra/custom.sock"
```

## Enterprise Auth

Enterprise-managed authorization via ID-JAG (corporate IdP
integration):

```toml
[enterprise_auth]
issuer = "https://idp.example.com"
audience = "navra"
```

## Operator Libraries

Drop TOML fragments into library directories for config composition.

```toml
[libraries]
library_dirs = ["~/.config/navra/libraries", "/etc/navra/libraries.d"]
```

Library files in these directories are deep-merged into the main
config at startup. Main config wins on key conflicts. Duplicate keys
across libraries produce a startup error.

See `navra config list-libraries` to inspect installed libraries.

## Discovery

Agent discovery via DNS-AID or mDNS.

```toml
discover = ["example.com", "tools.internal.net"]
```

Domains to query for AID upstream discovery at startup.

## Registry

Whitelisted MCP servers for the registry endpoint.

```toml
[[registry]]
name = "community"
url = "https://registry.mcp.run/mcp"
registry_type = "mcp"
remote_type = "streamable-http"

[[registry]]
name = "custom-http"
url = "https://registry.example.com"
registry_type = "http"
search_url = "https://registry.example.com/api/search?q={query}"
results_path = "data.results"
```

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `name` | string | -- | Server name (unique) |
| `url` | string | -- | Remote endpoint URL |
| `registry_type` | string | `"mcp"` | `mcp`, `http`, `aws_agent_registry` |
| `remote_type` | string | `"streamable-http"` | Transport: `streamable-http`, `sse`, `stdio` |
| `description` | string | -- | Human-readable description |
| `repository` | string | -- | Repository URL |
| `search_url` | string | -- | URL template for search (`{query}` placeholder) |
| `results_path` | string | -- | JSON path to extract results from HTTP response |
