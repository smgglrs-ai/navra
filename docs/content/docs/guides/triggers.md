+++
title = "Event-Driven Triggers"
description = "Automate flow execution with webhooks, cron schedules, and file system watchers."
weight = 40
template = "docs/page.html"

[extra]
toc = true
+++

Triggers start flows automatically in response to external events.
Instead of running `navra flow run` manually, you configure triggers
that fire when a webhook arrives, a cron schedule ticks, or a file
changes on disk.

All three trigger types share the same lifecycle: navra reads the
`[[triggers]]` array from your config, starts background tasks for
each entry, and dispatches matching events to the named flow via the
same `handle_flow_start` path used by the CLI.

## Trigger types

### Cron

Runs a flow on a repeating schedule using standard 5-field cron
expressions: `minute hour day-of-month month day-of-week`.

```toml
[[triggers]]
type = "cron"
schedule = "0 9 * * 1-5"
flow_name = "daily-review"
```

This fires `daily-review` at 09:00 UTC every weekday. The flow
receives a prompt of the form `Scheduled execution: 0 9 * * 1-5`.

Supported cron syntax:

| Syntax | Example | Meaning |
|--------|---------|---------|
| Exact value | `30` | Minute 30 |
| Wildcard | `*` | Every value in range |
| Range | `1-5` | Values 1 through 5 |
| List | `0,15,30,45` | Those specific values |
| Step | `*/10` | Every 10th value from 0 |

Field ranges: minute 0-59, hour 0-23, day-of-month 1-31,
month 1-12, day-of-week 0-6 (0 = Sunday).

Invalid expressions (wrong field count, out-of-range values, zero
step) are logged as errors at startup and the trigger is skipped.

### Webhook

Registers an HTTP POST endpoint on the navra server. External
services (GitHub, GitLab, CI systems) send a POST request to fire
the associated flow.

```toml
[[triggers]]
type = "webhook"
path = "/hook/deploy"
secret = "hmac-shared-secret"
flow_name = "deploy-review"
```

The path is normalized to start with `/hook/`. A request to
`POST /hook/deploy` triggers the `deploy-review` flow. The request
body is passed to the flow as a `webhook_body` parameter, and the
webhook name as `webhook_name`.

When `secret` is omitted, the endpoint accepts any POST request
without verification. See the [security](#webhook-hmac-verification)
section below for HMAC setup.

### File watch

Monitors a directory for file creation and modification events.
When a matching file changes, the associated flow starts with the
list of changed file paths.

```toml
[[triggers]]
type = "file_watch"
path = "~/Documents/inbox"
pattern = "*.pdf"
flow_name = "process-document"
debounce_ms = 1000
```

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `path` | string | -- | Directory to watch (supports `~` expansion) |
| `pattern` | string | `*` | Glob pattern to filter by filename |
| `flow_name` | string | -- | Flow to start on match |
| `debounce_ms` | u64 | `500` | Minimum interval between trigger firings (ms) |

The watcher is recursive -- subdirectories are included. Only
`Create` and `Modify` events are considered; deletions and renames
are ignored. The glob pattern matches against the filename only
(not the full path).

When multiple files change within the debounce window, they are
batched into a single flow invocation. The flow receives a
`changed_files` parameter with newline-separated paths.

If the watch path does not exist at startup, the trigger fails
with an error log and does not retry.

## Configuration

Triggers are defined as a `[[triggers]]` array in your navra
config file. Each entry must have a `type` field (`webhook`,
`cron`, or `file_watch`) and a `flow_name` that references a flow
discoverable from your `flow_dirs`.

```toml
# ~/.config/navra/config.toml

flow_dirs = ["~/.config/navra/flows"]

# Run a code review flow every weekday morning
[[triggers]]
type = "cron"
schedule = "0 9 * * 1-5"
flow_name = "daily-review"

# Accept deploy webhooks from GitHub
[[triggers]]
type = "webhook"
path = "/hook/deploy"
secret = "your-hmac-secret"
flow_name = "deploy-review"

# Process new PDFs dropped into an inbox folder
[[triggers]]
type = "file_watch"
path = "~/Documents/inbox"
pattern = "*.pdf"
flow_name = "process-document"
debounce_ms = 1000
```

### Flow name resolution

The `flow_name` field must match the name of a flow YAML file
(without extension) in one of the directories listed in `flow_dirs`.
For example, `flow_name = "deploy-review"` resolves to
`~/.config/navra/flows/deploy-review.yaml`.

Flows from agent instances are also discoverable. See the
[flow authoring guide](@/docs/guides/flows.md) for flow YAML
format details.

## CLI

### Starting the trigger engine

```bash
navra flow trigger start
navra flow trigger start --config /path/to/config.toml
```

This loads all `[[triggers]]` entries from the config, starts
background tasks for cron and file-watch triggers, and merges
webhook routes into the HTTP server. The trigger engine runs until
the process is stopped.

### Listing configured triggers

```bash
navra flow trigger list
navra flow trigger list --config /path/to/config.toml
```

Displays all triggers from the config and agent instances, showing
the type, schedule or path, and target flow for each.

## Security

### Webhook HMAC verification

When a webhook trigger has a `secret` field, navra verifies every
incoming request using HMAC-SHA256. The request must include a
signature header:

- `x-signature-256: sha256=<hex>` (navra native)
- `x-hub-signature-256: sha256=<hex>` (GitHub-compatible)

navra computes `HMAC-SHA256(secret, request_body)` and compares it
against the header value using constant-time comparison. Requests
with a missing or invalid signature receive a `401 Unauthorized`
response.

The `sha256=` prefix is optional -- bare hex signatures are also
accepted.

**Setting up with GitHub:**

1. Set `secret` in your trigger config to a random string.
2. In your GitHub repository, go to Settings > Webhooks > Add
   webhook.
3. Set the Payload URL to
   `http://your-navra-host:9315/hook/deploy`.
4. Set the Content type to `application/json`.
5. Paste the same secret string into the Secret field.
6. GitHub sends an `x-hub-signature-256` header that navra
   verifies automatically.

**Without a secret**, the endpoint is open to any POST request.
This is acceptable for development but should not be used in
production.

### File watch path restrictions

File watch triggers monitor the specified directory recursively.
Consider the following when configuring watched paths:

- Watch only directories you intend to process. Watching `/` or
  `$HOME` generates excessive events and may impact performance.
- The glob pattern filters by filename only, not by path. A
  pattern of `*.pdf` matches PDFs in any subdirectory.
- The watched directory must exist when the trigger starts.
  navra does not create directories or retry on missing paths.
- File watch triggers run with the navra process's filesystem
  permissions. They do not bypass navra's permission system --
  the flow itself is still subject to the agent's permission set.

## How triggers connect to flows

When a trigger fires, it calls the same `handle_flow_start`
function used by `navra flow run`. The trigger passes:

- `flow_name`: the configured flow name
- `prompt`: a description of the trigger event (e.g.,
  `Triggered by webhook: deploy` or
  `File change detected: /home/user/inbox/report.pdf`)
- `parameters`: trigger-specific context (webhook body, changed
  file paths)

The flow executes asynchronously -- the trigger does not block on
completion. For cron triggers, this means a new flow instance
starts on each tick even if the previous one is still running. For
webhooks, the HTTP response returns immediately with the flow start
result.

Cron and file-watch triggers spawn their flow invocations in
separate tokio tasks, so a slow flow does not block the next
trigger event. Webhook handlers return the flow start response
directly to the HTTP client.
