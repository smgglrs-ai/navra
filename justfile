export ORT_LIB_PATH := "/usr/lib64"
export ORT_PREFER_DYNAMIC_LINK := "1"

# Build the workspace
build:
    cargo build

# Run all tests
test:
    cargo test

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
