# Testing

navra has 2110+ tests across 22 crates: unit tests, integration
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
  (2000+) pass without Ollama.

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
| navra-security | 525 | 39 | — | 564 |
| navra-server | 195 | 6 | 12 | 213 |
| navra-core | 193 | 45 | — | 238 |
| navra-flow | 194 | 12 | — | 206 |
| navra-memory | 122 | — | — | 122 |
| navra-agent | 96 | — | — | 96 |
| navra-cognitive | 92 | 5 | — | 97 |
| navra-protocol | 128 | — | — | 128 |
| navra-model | 55 | 10 | — | 65 |
| navra-rag | 49 | 13 | — | 62 |
| navra-tools-file | 54 | 11 | — | 65 |
| navra-tools-git | 25 | 27 | — | 52 |
| navra-modal-vision | 40 | — | — | 40 |
| navra-model-hub | 30 | — | — | 30 |
| navra-responses | 26 | — | — | 26 |
| navra-model-runtime | 19 | — | — | 19 |
| navra-macros | — | 19 | — | 19 |
| navra-modal-voice | 9 | 12 | — | 21 |
| navra-tools-exec | 6 | — | — | 6 |
| navra-tools-gitlab | 5 | — | — | 5 |
| **Total** | **1884** | **199** | **12** | **2095+** |

Totals exclude doc-tests (~15). Full `cargo test --workspace` runs 2110+.

## Known caveats

- **Performance tests** (`navra-core/tests/bench_tokens.rs`) assert
  wall-clock thresholds (e.g. `< 10ms`). They can fail on loaded
  machines or in CI. These are informational benchmarks, not
  correctness tests.
- **OpenShell integration tests** (`navra-server/tests/openshell_integration.rs`)
  are `#[ignore]`d by default — they require a running OpenShell
  gRPC endpoint.
