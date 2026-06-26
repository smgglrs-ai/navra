# Build the workspace
build:
    cargo build

# Run all tests safely (workspace parallel, then server serialized one binary at a time)
test: test-workspace test-server

# Run workspace tests (excludes navra-server)
test-workspace:
    cargo test --workspace --exclude navra-server

# Run navra-server tests (one binary at a time, serialized, with cleanup)
test-server:
    #!/usr/bin/env bash
    set -euo pipefail
    cleanup() { pkill -f 'target/debug/navra' 2>/dev/null || true; }
    trap cleanup EXIT
    for bin in e2e adversarial_eval ifc_benchmark_e2e openshell_integration; do
        echo "=== navra-server: $bin ==="
        cargo test -p navra-server --test "$bin" -- --test-threads=1
        cleanup
        sleep 1
    done
    echo "=== navra-server: unit tests ==="
    cargo test -p navra-server --bin navra -- --test-threads=1

# Run tests for a single crate
test-crate crate:
    cargo test -p {{crate}}

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

# Kill any leaked navra test processes
kill-leaked:
    pkill -f 'target/debug/navra' 2>/dev/null || echo "no leaked processes"

# Build docs site (Zola + llms.txt)
docs:
    cd docs && zola build
    ./scripts/generate-llms-txt.sh

# Generate llms.txt and llms-full.txt without rebuilding the site
llms-txt:
    ./scripts/generate-llms-txt.sh
