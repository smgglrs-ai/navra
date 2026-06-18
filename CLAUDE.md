# navra

Secure MCP gateway daemon for Linux desktops. Rust workspace.

## Build

Requires ONNX Runtime installed system-wide (Fedora: `onnxruntime-devel`).

```bash
# Build
ORT_LIB_PATH=/usr/lib64 ORT_PREFER_DYNAMIC_LINK=1 cargo build

# Run
ORT_LIB_PATH=/usr/lib64 ORT_PREFER_DYNAMIC_LINK=1 cargo run -- serve
```

These environment variables are required because `ort` is configured
with `default-features = false` (no bundled download) and the system
package only provides shared libraries.

## Workspace

22-crate Rust workspace. See `DESIGN.md` for the full crate table,
dependency layering, architecture diagrams, and design decisions.

## Agent Workflow (MANDATORY)

### Commit after every verified feature

After tests pass for a feature, commit immediately. Never accumulate
unstaged changes across multiple features. One feature = one commit.

```bash
git add -A && git commit -s -m "description"
```

### Agents must commit in their worktrees

Every agent prompt MUST include this instruction:

> Before finishing, commit all your changes:
> `git add -A && git commit -s -m "your summary"`

This ensures the worktree branch survives cleanup. Without a commit,
worktree removal destroys all agent work.

### Merge agent work via git merge, not file copy

When an agent completes in a worktree, merge its branch:

```bash
git merge --no-ff worktree-agent-xxx -m "Merge: feature description"
```

Do NOT copy files manually — that loses history, misses files, and
creates merge conflicts with other agents.

### Never let worktrees accumulate

Merge or discard each worktree as soon as the agent completes.
Stale worktrees with uncommitted changes will be lost on cleanup.

See `AGENTS.md` for parallel development rules.

## Conventions

### Naming

- Tool names are prefixed with module name: `file_read`, `git_status`
- Operations are string-based, module-namespaced: `"read"`, `"git.commit"`
- Config fields use snake_case in TOML

### Error Handling

- Modules return `CallToolResult::error(msg)` for user-facing errors
- Infrastructure errors use `anyhow::Result` in server code
- Model loading failures are logged and skipped (graceful degradation)

### Testing

2400+ tests. See TESTING.md for per-crate unit/integration/e2e
breakdown.

Tests that spawn `navra serve` (adversarial_eval, e2e) will OOM
if run in parallel. Split strategy for workspace tests:

```bash
# Step 1: all crates except navra-server (parallel OK)
ORT_LIB_PATH=/usr/lib64 ORT_PREFER_DYNAMIC_LINK=1 cargo test --workspace --exclude navra-server

# Step 2: navra-server alone (MUST serialize)
ORT_LIB_PATH=/usr/lib64 ORT_PREFER_DYNAMIC_LINK=1 cargo test -p navra-server -- --test-threads=1
```

When in doubt, serialize. OOM is a regression — always investigate.

Doc-test convention: use `no_run` for examples needing cross-crate
types, `text` for illustrative examples. Never use `ignore`.

Prerequisites:
- ONNX Runtime (`onnxruntime-devel` on Fedora)
- Ollama with any model for 1 e2e test (`ollama pull qwen2.5:0.5b`)

```bash
# Unit + integration tests
ORT_LIB_PATH=/usr/lib64 ORT_PREFER_DYNAMIC_LINK=1 cargo test --workspace

# Single crate
ORT_LIB_PATH=/usr/lib64 ORT_PREFER_DYNAMIC_LINK=1 cargo test -p navra-core

# E2e tests (require Ollama running)
ORT_LIB_PATH=/usr/lib64 ORT_PREFER_DYNAMIC_LINK=1 cargo test -p navra-server --test e2e

# Build with OTel trace export
ORT_LIB_PATH=/usr/lib64 ORT_PREFER_DYNAMIC_LINK=1 cargo build --features otel
# Then: OTEL_EXPORTER_OTLP_ENDPOINT=http://localhost:4317 navra serve
```

Conventions:
- Unit tests live in `#[cfg(test)] mod tests` at the bottom of each file
- Integration tests in `tests/` directories per crate
- `echo_tool_def()` and `test_ctx()` helpers are defined locally
  in `navra-core/src/server/tests.rs`; other crates define their own
  `test_ctx()` for constructing `CallContext` in tests
- All async tests use `#[tokio::test]`

See `DESIGN.md` for adding modules and tools.

## Config

Default path: `~/.config/navra/config.toml`

Key sections: `[server]`, `[modules.*]`, `[models.*]`, `[[agents]]`,
`[permissions.*]`, `[[upstream]]`, `discover`, `[[registry]]`.

See DESIGN.md for full config reference.

## Resource Limits

- Agents using Ollama: serialize, max one concurrent
- Single GPU: serialize with high timeouts
- Background processes: immediately capture PID, verify before using
- Never use `pkill` — find and kill specific PIDs
- Ollama IS available — don't exclude Ollama-dependent tests

## Work Tracking

Work items live in `.lean/items/*.yml` (source of truth).
`plan.yml` is a generated index — regenerate with `bash ~/.claude/lean/scripts/generate-plan.sh`.
