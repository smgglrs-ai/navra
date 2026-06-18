export ORT_LIB_PATH := "/usr/lib64"
export ORT_PREFER_DYNAMIC_LINK := "1"

# Build the workspace
build:
    cargo build

# Run all tests (serialized to prevent OOM from concurrent server instances)
test:
    cargo test --workspace --exclude navra-server
    cargo test -p navra-server -- --test-threads=1

# Run tests for a single crate
test-crate crate:
    cargo test -p {{crate}}

# Run navra-server tests only (serialized)
test-server:
    cargo test -p navra-server -- --test-threads=1

# Run clippy with warnings as errors
clippy:
    cargo clippy -- -D warnings

# Format all code
fmt:
    cargo fmt

# Check formatting without modifying files
fmt-check:
    cargo fmt -- --check

# Run all checks: format, clippy, tests
check: fmt-check clippy test

# Clean build artifacts
clean:
    cargo clean

# Run a demo
demo *ARGS:
    cargo run -- demo {{ARGS}}

# Run end-to-end live tests (protocol-only, no LLM needed)
e2e:
    ./scripts/e2e-live.sh

# Run end-to-end live tests with agent smoke test (needs Ollama)
e2e-agent *ARGS:
    ./scripts/e2e-live.sh --with-agent {{ARGS}}

# Run full multi-agent live demo test (needs Ollama, 1-5 min)
e2e-demo *ARGS:
    ./scripts/e2e-live.sh --live-demo {{ARGS}}

# Run ASSERT compliance evaluation (needs Ollama + assert-ai)
assert-eval *ARGS:
    ./eval/assert/run-compliance.sh {{ARGS}}

# Validate ASSERT config and behavior specs
assert-check:
    ./eval/assert/run-compliance.sh --dry-run
