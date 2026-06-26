# navra

Secure MCP gateway daemon for Linux desktops. Rust workspace.

## Build

ONNX Runtime is bundled automatically via the `ort` crate's
`download-binaries` feature — no system packages required.

```bash
# Build
cargo build

# Run
cargo run -- serve
```

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

2400+ tests. **Always use `just` to run tests** — it sets ORT
environment variables, serializes navra-server tests one binary at
a time, and cleans up leaked server processes between runs.

```bash
# All tests (workspace parallel + server serialized)
just test

# Workspace only (excludes navra-server)
just test-workspace

# navra-server only (one binary at a time with cleanup)
just test-server

# Single crate
just test-crate navra-core
```

**NEVER run raw `cargo test -p navra-server`** — it spawns multiple
server processes that OOM the machine. The pre-commit hook blocks
this, but use `just` to avoid the issue entirely.

Doc-test convention: use `no_run` for examples needing cross-crate
types, `text` for illustrative examples. Never use `ignore`.

Prerequisites:
- Ollama with any model for 1 e2e test (`ollama pull qwen2.5:0.5b`)

```bash
# Build with OTel trace export
just build
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
