#!/bin/bash
# S9 Statistical Evaluation: run review flows on 3 projects × 3 runs.
#
# Prerequisites:
#   - Release build: cargo build --release
#   - Config: ~/.config/smgglrs/config.toml with containerized=false
#   - Vertex AI: ANTHROPIC_VERTEX_PROJECT_ID and CLOUD_ML_REGION set
#   - gcloud auth: gcloud auth print-access-token works
#
# Usage:
#   ./scripts/eval-s9.sh
#
# Output:
#   results/s9-eval/  — one JSON per flow run + summary

set -euo pipefail

SMGGLRS_BIN="$(dirname "$0")/../target/release/smgglrs"
SOCK="/run/user/$(id -u)/smgglrs/smgglrs.sock"
RESULTS_DIR="$(dirname "$0")/../results/s9-eval"
LOG="/tmp/smgglrs-s9-eval.log"

PROJECTS=(
    "/home/fdupont/Code/github.com/fabiendupont/synthos"
    "/home/fdupont/Code/github.com/fabiendupont/edge-ai-sno"
    "/home/fdupont/Code/github.com/fabiendupont/syllogis"
)
PROJECT_NAMES=("synthos" "edge-ai-sno" "syllogis")
RUNS_PER_PROJECT=3

mkdir -p "$RESULTS_DIR"

# Ensure config limits parallelism
mkdir -p ~/.config/smgglrs
cat > ~/.config/smgglrs/config.toml << 'TOML'
[server]
tcp = "127.0.0.1:9315"
containerized = false

[budget]
max_parallel = 1
max_iterations = 10
timeout_secs = 300

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

mcp_call() {
    local session="$1"
    local method="$2"
    local params="$3"
    curl -s --max-time 900 --unix-socket "$SOCK" http://localhost/mcp \
        -X POST \
        -H "Content-Type: application/json" \
        -H "Mcp-Session-Id: $session" \
        -d "{\"jsonrpc\":\"2.0\",\"method\":\"$method\",\"id\":1,\"params\":$params}"
}

init_session() {
    local resp
    resp=$(curl -s -D - --unix-socket "$SOCK" http://localhost/mcp \
        -X POST \
        -H "Content-Type: application/json" \
        -d '{"jsonrpc":"2.0","method":"initialize","id":1,"params":{"protocolVersion":"2025-03-26","capabilities":{},"clientInfo":{"name":"eval","version":"1.0"}}}' 2>&1)
    echo "$resp" | grep -i "mcp-session-id" | tr -d '\r' | awk '{print $2}'
}

echo "=== S9 Evaluation Run ==="
echo "Date: $(date -Iseconds)"
echo "Projects: ${PROJECT_NAMES[*]}"
echo "Runs per project: $RUNS_PER_PROJECT"
echo ""

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
    if grep -qa "Listening" "$LOG" 2>/dev/null; then
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

# Run flows
total_runs=0
for pi in "${!PROJECTS[@]}"; do
    project="${PROJECTS[$pi]}"
    name="${PROJECT_NAMES[$pi]}"

    for run in $(seq 1 $RUNS_PER_PROJECT); do
        total_runs=$((total_runs + 1))
        outfile="$RESULTS_DIR/${name}-run${run}.json"
        echo ""
        echo "--- [$total_runs/$(( ${#PROJECTS[@]} * RUNS_PER_PROJECT ))] $name run $run ---"
        echo "  Start: $(date -Iseconds)"

        # Check server is alive
        if ! kill -0 $SERVER_PID 2>/dev/null; then
            echo "  Server died. Restarting..."
            rm -f "$LOG" "$SOCK"
            NO_COLOR=1 ORT_LIB_PATH=/usr/lib64 ORT_PREFER_DYNAMIC_LINK=1 RUST_LOG=smgglrs=info \
                "$SMGGLRS_BIN" serve &>"$LOG" &
            SERVER_PID=$!
            sleep 5
        fi

        # Init session
        session=$(init_session)
        if [ -z "$session" ]; then
            echo "  ERROR: Failed to init session"
            echo '{"error": "session init failed"}' > "$outfile"
            continue
        fi

        # Start flow
        start_ts=$(date +%s)
        result=$(mcp_call "$session" "tools/call" "{
            \"name\": \"flow_start\",
            \"arguments\": {
                \"flow_name\": \"review\",
                \"prompt\": \"Review the $name project for code quality, security, and architecture.\",
                \"parameters\": {\"target_dir\": \"$project\"}
            }
        }" 2>&1)
        end_ts=$(date +%s)
        duration=$((end_ts - start_ts))

        echo "$result" > "$outfile"
        echo "  End: $(date -Iseconds) (${duration}s)"

        # Extract metrics
        flow_text=$(echo "$result" | python3 -c "
import sys, json
try:
    d = json.load(sys.stdin)
    text = d.get('result',{}).get('content',[{}])[0].get('text','')
    print(text[:500])
except:
    print('(parse error)')
" 2>/dev/null)
        echo "  $flow_text" | head -5

        # Memory check
        rss_kb=$(ps -o rss= -p $SERVER_PID 2>/dev/null || echo "0")
        rss_mb=$((rss_kb / 1024))
        echo "  Server RSS: ${rss_mb}MB"

        # Restart server between runs to free memory
        echo "  Restarting server to free memory..."
        kill $SERVER_PID 2>/dev/null || true
        sleep 3
        rm -f "$LOG" "$SOCK"
        NO_COLOR=1 ORT_LIB_PATH=/usr/lib64 ORT_PREFER_DYNAMIC_LINK=1 RUST_LOG=smgglrs=info \
            "$SMGGLRS_BIN" serve &>"$LOG" &
        SERVER_PID=$!
        sleep 5
    done
done

echo ""
echo "=== Evaluation Complete ==="
echo "Results in: $RESULTS_DIR"
ls -la "$RESULTS_DIR"/*.json 2>/dev/null
echo ""
echo "To analyze: run the summarize tool on the JSON files"
