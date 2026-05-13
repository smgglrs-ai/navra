# Testing

smgglrs has ~1700 tests across 20 crates: unit tests, integration
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

- **Ollama** — the e2e tests in `smgglrs-server/tests/e2e.rs` spawn
  a real smgglrs server that auto-detects the first available Ollama
  model for chat completion tests.

  ```bash
  # Install
  curl -fsSL https://ollama.com/install.sh | sh

  # Pull a small model (~400 MB)
  ollama pull qwen2.5:0.5b
  ```

  Without Ollama, unit and integration tests still pass; only the
  `v1_chat_completions_returns_openai_format` e2e test will fail.

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

Approximate counts (run `cargo test --workspace --no-fail-fast` for
exact numbers):

| Crate | Tests |
|---|---|
| smgglrs-security | ~380 |
| smgglrs-core | ~180 |
| smgglrs-flow | ~170 |
| smgglrs-server | ~170 |
| smgglrs-memory | ~110 |
| smgglrs-cognitive | ~90 |
| smgglrs-agent | ~75 |
| smgglrs-model | ~55 |
| smgglrs-protocol | ~75 |
| smgglrs-rag | ~45 |
| smgglrs-tools-file | ~30 |
| smgglrs-responses | ~25 |
| smgglrs-tools-git | ~20 |
| smgglrs-modal-voice | ~10 |
| smgglrs-modal-vision | ~25 |
| smgglrs-macros | ~5 |

## Known caveats

- **Performance tests** (`smgglrs-core/tests/bench_tokens.rs`) assert
  wall-clock thresholds (e.g. `< 10ms`). They can fail on loaded
  machines or in CI. These are informational benchmarks, not
  correctness tests.
- **OpenShell integration tests** (`smgglrs-server/tests/openshell_integration.rs`)
  are `#[ignore]`d by default — they require a running OpenShell
  gRPC endpoint.
