# Testing

smgglrs has 2110+ tests across 22 crates: unit tests, integration
tests, and end-to-end tests that spawn a real server process.

## Prerequisites

### Required

- **Rust stable** (1.75+)
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
  proxies a chat request through smgglrs to Ollama. It auto-detects
  the first available model. Any model works, including tiny ones:

  ```bash
  # Install
  curl -fsSL https://ollama.com/install.sh | sh

  # Pull the smallest available model (~400 MB)
  ollama pull qwen2.5:0.5b
  ```

  Without Ollama running, 11 of 12 e2e tests pass. Only the chat
  completion proxy test requires it. All unit and integration tests
  (2000+) pass without Ollama.

## Running tests

```bash
# Full workspace
cargo test --workspace

# Full workspace (don't stop on first failure)
cargo test --workspace --no-fail-fast

# Single crate
cargo test -p smgglrs-core

# Single test
cargo test -p smgglrs-server v1_chat_completions

# E2e tests only
cargo test -p smgglrs-server --test e2e

# Benchmarks (Criterion, not counted in test totals)
cargo bench -p benchmarks
```

## Test structure

| Layer | Location | What it tests |
|---|---|---|
| Unit | `#[cfg(test)] mod tests` in each `.rs` file | Individual functions, types, logic |
| Integration | `tests/` directory per crate | Cross-module interactions within a crate |
| E2e | `smgglrs-server/tests/e2e.rs` | Full server process: auth, MCP protocol, tools, chat proxy |

### Test helpers

- `echo_tool_def()` and `test_ctx()` in `smgglrs-core/src/server/tests.rs`
  provide a minimal `ToolDefinition` and `CallContext` for server tests.
  Other crates define their own local `test_ctx()`.
- All async tests use `#[tokio::test]`.

## Crate test counts

Run `cargo test --workspace --no-fail-fast` for exact numbers.

| Crate | Unit | Integration | E2e | Total |
|---|---|---|---|---|
| smgglrs-security | 525 | 39 | — | 564 |
| smgglrs-server | 195 | 6 | 12 | 213 |
| smgglrs-core | 193 | 45 | — | 238 |
| smgglrs-flow | 194 | 12 | — | 206 |
| smgglrs-memory | 122 | — | — | 122 |
| smgglrs-agent | 96 | — | — | 96 |
| smgglrs-cognitive | 92 | 5 | — | 97 |
| smgglrs-protocol | 128 | — | — | 128 |
| smgglrs-model | 55 | 10 | — | 65 |
| smgglrs-rag | 49 | 13 | — | 62 |
| smgglrs-tools-file | 54 | 11 | — | 65 |
| smgglrs-tools-git | 25 | 27 | — | 52 |
| smgglrs-tools-github | 21 | — | — | 21 |
| smgglrs-modal-vision | 40 | — | — | 40 |
| smgglrs-model-hub | 30 | — | — | 30 |
| smgglrs-responses | 26 | — | — | 26 |
| smgglrs-model-runtime | 19 | — | — | 19 |
| smgglrs-macros | — | 19 | — | 19 |
| smgglrs-modal-voice | 9 | 12 | — | 21 |
| smgglrs-tools-exec | 6 | — | — | 6 |
| smgglrs-tools-gitlab | 5 | — | — | 5 |
| **Total** | **1884** | **199** | **12** | **2095+** |

Totals exclude doc-tests (~15). Full `cargo test --workspace` runs 2110+.

## Known caveats

- **Performance tests** (`smgglrs-core/tests/bench_tokens.rs`) assert
  wall-clock thresholds (e.g. `< 10ms`). They can fail on loaded
  machines or in CI. These are informational benchmarks, not
  correctness tests.
- **OpenShell integration tests** (`smgglrs-server/tests/openshell_integration.rs`)
  are `#[ignore]`d by default — they require a running OpenShell
  gRPC endpoint.
