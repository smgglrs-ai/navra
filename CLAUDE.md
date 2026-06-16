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

## Parallel Development

See `AGENTS.md` for the full agent rules. This section covers
when and how to use parallel workflows.

### When to use parallel agents

- **Yes**: independent crate work (e.g., add tests to navra-rag
  while documenting navra-security)
- **Yes**: cross-cutting work with clear file ownership (frontend
  agent + backend agent, each in their own crate)
- **No**: sequential changes where step 2 depends on step 1
- **No**: changes to the same files (will conflict)

### Decomposition by crate boundary

The 22-crate workspace is designed for parallel work. Each crate
has clear file ownership. Decompose tasks along crate boundaries:

```
Task: "Add embedding support to RAG and voice modules"
  Agent 1 (worktree): navra-rag — embedding integration
  Agent 2 (worktree): navra-modal-voice — embedding integration
  Lead (main): Cargo.toml workspace changes, merge results
```

### Plan on main, implement in worktrees

1. Design the approach in the main session
2. Decompose into crate-scoped work packages
3. Spawn agents with `isolation: worktree`, one per crate
4. Each agent implements, tests, and commits in its worktree
5. Lead merges each branch (prefer fast-forward when linear)
6. Lead runs full workspace tests after all merges

### Team coordination

For complex features spanning 3+ crates, use Claude Code teams:

1. Lead creates a task list with one task per crate
2. Lead spawns teammates, each assigned to specific crates
3. Teammates work in worktrees, message the lead on completion
4. Lead merges, resolves conflicts, runs integration tests

Keep teams to 3-5 agents. More than that creates merge overhead
that outweighs the parallelism gains.

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
if run in parallel. Use `--test-threads=1` for those tests.

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

### Adding a Module

1. Create crate implementing `Module` trait (from `navra-core`)
2. Add dependency in `navra-server/Cargo.toml`
3. Add config struct in `config.rs`
4. Add `if cfg.xxx_enabled() { builder = builder.module(xxx); }` in `main.rs`

### Adding a Tool

Tools within a module (manual):
1. Define `ToolDefinition` with name, description, input schema
2. Create handler: `Arc<dyn Fn(Value, CallContext) -> Pin<Box<dyn Future<Output = CallToolResult> + Send>> + Send + Sync>`
3. Return `(definition, handler)` pair from `Module::tools()`
4. Tool name must be prefixed with module name

Or use the `#[tool]` proc macro from `navra-macros`:

```rust
#[navra::tool(name = "file_read", description = "Read a file")]
async fn file_read(
    #[arg(description = "Path to the file")] path: String,
    ctx: CallContext,
) -> CallToolResult {
    // ...
}
```

## Config

Default path: `~/.config/navra/config.toml`

Key sections: `[server]`, `[modules.*]`, `[models.*]`, `[[agents]]`,
`[permissions.*]`, `[[upstream]]`, `discover`, `[[registry]]`.

See DESIGN.md for full config reference.

## Roadmap

- **`roadmap.json`** — Machine-readable dependency graph. Every work
  item has an id, priority, status, dependencies, gates, and feeds.
- **`ROADMAP.md`** — Human-readable context, design rationale.
  Never duplicate content between the two files.

### Picking next work

Parse `roadmap.json`: status == "pending", no uncleared gate,
all depends_on completed. Sort by priority then effort.

Set status to `"in_progress"` when starting, `"completed"` when
done. Commit the JSON change with the feature commit.

### After a tech watch

New items get `TW` prefix IDs. Add to both roadmap.json and
ROADMAP.md dependency graph section.

## Reference Documents

- `DESIGN.md` — Crate table, dependency layering, architecture,
  security model, config reference
- `TESTING.md` — Test prerequisites, running tests, crate counts (2400+)
- `.lean/items/*.yml` — Work items (source of truth, 71 items)
- `.lean/plan.yml` — Generated index (do not edit, regenerate with `bash ~/.claude/lean/scripts/generate-plan.sh`)
- `MODELS.md` — Model tiers, hardware profiles
- `DISCOVERY.md` — AID, A2A, MCP Server Cards
- `OPENSHELL.md` — OpenShell integration
- `docs/acp.md` — ACP v0.2.0 implementation
- `docs/mcp-tunnels.md` — MCP tunnel compatibility
- `docs/ecosystem-positioning.md` — Competitive landscape, *Claw analysis
- `docs/review-flows.md` — DAG-based review and improvement flows
- `docs/pii-handling.md` — PII pipeline design (regex, NER, pseudonymization, GDPR)
