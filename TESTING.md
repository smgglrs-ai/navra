# Testing

navra has 2750+ tests across 22 crates: unit tests, integration
tests, and end-to-end tests that spawn a real server process.

## Prerequisites

### Required

- **Rust stable** (1.91+)
- **ONNX Runtime** — system-wide shared library

  ```bash
  # Fedora
  sudo dnf install onnxruntime-devel
  ```

  Set environment variables before every `cargo test` / `cargo build`:

  ```bash
  export ORT_LIB_PATH=/usr/lib64
  export ORT_PREFER_DYNAMIC_LINK=1
  ```

### Required for e2e tests

- **Ollama** — one e2e test (`v1_chat_completions_returns_openai_format`)
  proxies a chat request through navra to Ollama. It auto-detects
  the first available model. Any model works, including tiny ones:

  ```bash
  # Install
  curl -fsSL https://ollama.com/install.sh | sh

  # Pull the smallest available model (~400 MB)
  ollama pull qwen2.5:0.5b
  ```

  Without Ollama running, 11 of 12 e2e tests pass. Only the chat
  completion proxy test requires it. All unit and integration tests
  (2700+) pass without Ollama.

## Running tests

```bash
# Full workspace
cargo test --workspace

# Full workspace (don't stop on first failure)
cargo test --workspace --no-fail-fast

# Single crate
cargo test -p navra-core

# Single test
cargo test -p navra-server v1_chat_completions

# E2e tests only
cargo test -p navra-server --test e2e

# Benchmarks (Criterion, not counted in test totals)
cargo bench -p benchmarks
```

## Test structure

| Layer | Location | What it tests |
|---|---|---|
| Unit | `#[cfg(test)] mod tests` in each `.rs` file | Individual functions, types, logic |
| Integration | `tests/` directory per crate | Cross-module interactions within a crate |
| E2e | `navra-server/tests/e2e.rs` | Full server process: auth, MCP protocol, tools, chat proxy |

### Test helpers

- `echo_tool_def()` and `test_ctx()` in `navra-core/src/server/tests.rs`
  provide a minimal `ToolDefinition` and `CallContext` for server tests.
  Other crates define their own local `test_ctx()`.
- All async tests use `#[tokio::test]`.

## Crate test counts

Run `cargo test --workspace --no-fail-fast` for exact numbers.

| Crate | Unit | Integration | E2e | Total |
|---|---|---|---|---|
| navra-auth | 405 | 3 | — | 408 |
| navra-core | 256 | 49 | — | 305 |
| navra-safety-hooks | 241 | 15 | — | 256 |
| navra-flow | 223 | 31 | — | 254 |
| navra-server | 219 | — | 12 | 231 |
| navra-safety | 195 | — | — | 195 |
| navra-protocol | 154 | — | — | 154 |
| navra-memory | 151 | — | — | 151 |
| navra-rag | 118 | 13 | — | 131 |
| navra-agent | 117 | 11 | — | 128 |
| navra-cognitive | 122 | 5 | — | 127 |
| navra-model | 74 | 27 | — | 101 |
| navra-model-runtime | 70 | — | — | 70 |
| navra-security | 17 | 39 | — | 56 |
| navra-openapi | 43 | 6 | — | 49 |
| navra-modal-vision | 40 | — | — | 40 |
| navra-model-hub | 33 | — | — | 33 |
| navra-responses | 26 | — | — | 26 |
| navra-macros | — | 19 | — | 19 |
| navra-tools-gitlab | 10 | — | — | 10 |
| navra-modal-voice | 9 | — | — | 9 |
| navra-tools-exec | 8 | — | — | 8 |
| **Total** | **2591** | **218** | **12** | **2821** |

Totals exclude doc-tests (~15). Full `cargo test --workspace` runs 2750+.

Crates removed since previous count: navra-tools-file (replaced by
upstream Filesystem MCP), navra-tools-git (replaced by upstream git
MCP server). New crates: navra-auth (split from navra-security),
navra-safety-hooks, navra-openapi.

## Known caveats

- **Performance tests** (`navra-core/tests/bench_tokens.rs`) assert
  wall-clock thresholds (e.g. `< 10ms`). They can fail on loaded
  machines or in CI. These are informational benchmarks, not
  correctness tests.
- **OpenShell integration tests** (`navra-server/tests/openshell_integration.rs`)
  are `#[ignore]`d by default — they require a running OpenShell
  gRPC endpoint.
