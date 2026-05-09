#!/bin/bash
# S9 Statistical Evaluation: run review flows on 3 projects × 3 runs.
#
# Prerequisites:
#   - Release build: cargo build --release
#   - Vertex AI: ANTHROPIC_VERTEX_PROJECT_ID and CLOUD_ML_REGION set
#   - gcloud auth: gcloud auth print-access-token works
#
# Usage:
#   ./scripts/eval-s9.sh
#
# Output:
#   results/s9-eval/  — one JSON per flow run

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT_DIR="$(dirname "$SCRIPT_DIR")"
SMGGLRS_BIN="$ROOT_DIR/target/release/smgglrs"
EVAL_BIN="$ROOT_DIR/target/release/eval"
SOCK="/run/user/$(id -u)/smgglrs/smgglrs.sock"
LOG="/tmp/smgglrs-s9-eval.log"

# Check binaries exist
if [ ! -x "$SMGGLRS_BIN" ] || [ ! -x "$EVAL_BIN" ]; then
    echo "Building release binaries..."
    ORT_LIB_PATH=/usr/lib64 ORT_PREFER_DYNAMIC_LINK=1 cargo build --release -p smgglrs-server -p smgglrs-agent
fi

# Write config
mkdir -p ~/.config/smgglrs
cat > ~/.config/smgglrs/config.toml << 'TOML'
[server]
tcp = "127.0.0.1:9315"
containerized = false

[budget]
max_parallel = 1
max_iterations = 30
timeout_secs = 3600
max_agents = 10

[permissions.readonly]
paths = ["**"]
operations = ["read", "search", "list"]

[permissions.developer]
paths = ["**"]
operations = ["read", "write", "search", "list", "git.status", "git.diff", "git.log"]
TOML

cleanup() {
    echo "Stopping server..."
    pkill -f "smgglrs serve" 2>/dev/null || true
    sleep 2
}
trap cleanup EXIT

# Start server
echo "Starting smgglrs (release)..."
pkill -f "smgglrs serve" 2>/dev/null || true
sleep 2
rm -f "$LOG" "$SOCK"
NO_COLOR=1 ORT_LIB_PATH=/usr/lib64 ORT_PREFER_DYNAMIC_LINK=1 RUST_LOG=smgglrs=info \
    "$SMGGLRS_BIN" serve &>"$LOG" &
SERVER_PID=$!
echo "Server PID: $SERVER_PID"

# Wait for ready
for i in $(seq 1 30); do
    if kill -0 $SERVER_PID 2>/dev/null && grep -qa "Listening" "$LOG" 2>/dev/null; then
        echo "Server ready."
        break
    fi
    sleep 1
done

if ! kill -0 $SERVER_PID 2>/dev/null; then
    echo "ERROR: Server died. Log:"
    tail -20 "$LOG"
    exit 1
fi

# Run evaluation
echo ""
echo "=== Starting S9 Evaluation ==="
echo ""

SMGGLRS_ENDPOINT="http://localhost:9315/mcp" \
SMGGLRS_FLOW="review-lite" \
SMGGLRS_EVAL_RUNS=3 \
SMGGLRS_EVAL_OUTPUT="$ROOT_DIR/results/s9-eval" \
    "$EVAL_BIN"

echo ""
echo "=== Results ==="
ls -la "$ROOT_DIR/results/s9-eval/"*.json 2>/dev/null
