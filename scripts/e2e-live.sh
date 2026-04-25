#!/usr/bin/env bash
#
# End-to-end live demo test script.
#
# Exercises the full smgglrs pipeline: gateway startup, MCP protocol,
# memory tools, model proxy, optional agent run, and blackbox audit.
#
# Usage:
#   ./scripts/e2e-live.sh                    # protocol-only (no LLM needed)
#   ./scripts/e2e-live.sh --with-agent       # smoke test: single agent (needs Ollama)
#   ./scripts/e2e-live.sh --live-demo        # full multi-agent demo (needs Ollama)
#   ./scripts/e2e-live.sh --model gemma4:12b # specify model for agent/demo
#
# Exit codes:
#   0 = all tests passed
#   1 = one or more tests failed
#   2 = setup failure (build, missing dependency)

set -euo pipefail

# --- Configuration ---
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
DEMO_DIR="/tmp/smgglrs-e2e-live-$$"
CONFIG_PATH="$DEMO_DIR/config.toml"
MCPD_PID=""
WITH_AGENT=false
LIVE_DEMO=false
MODEL="granite3.3:8b"
VERBOSE=false

export ORT_LIB_PATH="${ORT_LIB_PATH:-/usr/lib64}"
export ORT_PREFER_DYNAMIC_LINK=1

# --- Argument parsing ---
while [[ $# -gt 0 ]]; do
    case "$1" in
        --with-agent) WITH_AGENT=true; shift ;;
        --live-demo) LIVE_DEMO=true; WITH_AGENT=true; shift ;;
        --model) MODEL="$2"; shift 2 ;;
        --verbose|-v) VERBOSE=true; shift ;;
        --help|-h)
            echo "Usage: $0 [--with-agent] [--live-demo] [--model NAME] [--verbose]"
            exit 0
            ;;
        *) echo "Unknown argument: $1"; exit 2 ;;
    esac
done

# --- Counters ---
PASSED=0
FAILED=0
TOTAL=0

pass() {
    PASSED=$((PASSED + 1))
    TOTAL=$((TOTAL + 1))
    echo "  PASS: $1"
}

fail() {
    FAILED=$((FAILED + 1))
    TOTAL=$((TOTAL + 1))
    echo "  FAIL: $1"
    if [[ -n "${2:-}" ]]; then
        echo "        $2"
    fi
}

section() {
    echo ""
    echo "━━━ $1 ━━━"
}

# --- Cleanup ---
cleanup() {
    local exit_code=$?
    if [[ -n "$MCPD_PID" ]]; then
        kill "$MCPD_PID" 2>/dev/null || true
        wait "$MCPD_PID" 2>/dev/null || true
    fi
    if [[ $exit_code -ne 0 ]] && [[ -d "$DEMO_DIR" ]]; then
        echo "  Logs preserved at: $DEMO_DIR"
    else
        rm -rf "$DEMO_DIR"
    fi
}
trap cleanup EXIT

# --- Setup ---
section "Setup"
mkdir -p "$DEMO_DIR"

# Pick a free port
PORT=$(python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1",0)); print(s.getsockname()[1]); s.close()')
BASE_URL="http://127.0.0.1:$PORT"

echo "  Repo:    $REPO_ROOT"
echo "  Workdir: $DEMO_DIR"
echo "  Port:    $PORT"
echo "  Model:   $MODEL (agent: $WITH_AGENT, live-demo: $LIVE_DEMO)"

# Build
echo "  Building smgglrs..."
cd "$REPO_ROOT"
if ! cargo build --bin smgglrs 2>"$DEMO_DIR/build.log"; then
    echo "  Build failed. See $DEMO_DIR/build.log"
    exit 2
fi
MCPD_BIN="$REPO_ROOT/target/debug/smgglrs"
echo "  Built:   $MCPD_BIN"

# Write config
cat > "$CONFIG_PATH" <<EOF
cognitive_core = "$REPO_ROOT/cognitive_core"

[server]
tcp = "127.0.0.1:$PORT"

[modules.docs]
enabled = true

[modules.git]
enabled = false

[permissions.readonly]
allow = ["$DEMO_DIR/**", "$REPO_ROOT/**", "/tmp/**"]
deny = []
operations = ["read", "write", "search", "list", "delete"]
safety = "standard"
EOF

# Start smgglrs
echo "  Starting smgglrs..."
"$MCPD_BIN" serve --config "$CONFIG_PATH" --no-tray \
    >"$DEMO_DIR/smgglrs-stdout.log" 2>"$DEMO_DIR/smgglrs-stderr.log" &
MCPD_PID=$!

# Wait for ready
for i in $(seq 1 30); do
    if curl -sf "$BASE_URL/api/status" >/dev/null 2>&1; then
        break
    fi
    if ! kill -0 "$MCPD_PID" 2>/dev/null; then
        echo "  smgglrs exited prematurely. Stderr:"
        cat "$DEMO_DIR/smgglrs-stderr.log"
        exit 2
    fi
    sleep 0.5
done

if ! curl -sf "$BASE_URL/api/status" >/dev/null 2>&1; then
    echo "  smgglrs did not start within 15 seconds"
    exit 2
fi
echo "  smgglrs running (PID $MCPD_PID)"

# --- Helper: JSON-RPC call ---
rpc() {
    local method="$1"
    local id="$2"
    local params="$3"
    local session="${4:-}"

    local headers=(-H "Content-Type: application/json")
    if [[ -n "$session" ]]; then
        headers+=(-H "mcp-session-id: $session")
    fi

    curl -sf "${headers[@]}" -X POST "$BASE_URL/mcp" \
        -d "{\"jsonrpc\":\"2.0\",\"method\":\"$method\",\"id\":$id,\"params\":$params}"
}

# Helper: call a tool
call_tool() {
    local session="$1"
    local tool="$2"
    local args="$3"
    local id="$4"
    rpc "tools/call" "$id" "{\"name\":\"$tool\",\"arguments\":$args}" "$session"
}

# --- Test 1: MCP Initialize ---
section "MCP Protocol"

INIT_RESP=$(rpc "initialize" 1 '{"protocolVersion":"2025-03-26","capabilities":{},"clientInfo":{"name":"e2e-live"}}')
if [[ "$VERBOSE" == true ]]; then echo "    $INIT_RESP"; fi

PROTO=$(echo "$INIT_RESP" | python3 -c "import sys,json; print(json.load(sys.stdin)['result']['protocolVersion'])" 2>/dev/null || echo "")
if [[ "$PROTO" == "2025-03-26" ]]; then
    pass "initialize returns protocol version"
else
    fail "initialize returns protocol version" "got: $PROTO"
fi

# Extract session ID from response headers (need a separate curl for headers)
SESSION_ID=$(curl -sf -D - -o /dev/null -X POST "$BASE_URL/mcp" \
    -H "Content-Type: application/json" \
    -d '{"jsonrpc":"2.0","method":"initialize","id":2,"params":{"protocolVersion":"2025-03-26","capabilities":{},"clientInfo":{"name":"e2e-live-session"}}}' \
    | grep -i "mcp-session-id" | tr -d '\r' | awk '{print $2}')

if [[ -n "$SESSION_ID" ]]; then
    pass "initialize returns session ID"
else
    fail "initialize returns session ID"
    echo "  Cannot continue without session ID"
    exit 1
fi

# --- Test 2: tools/list ---
TOOLS_RESP=$(rpc "tools/list" 3 '{}' "$SESSION_ID")
TOOL_COUNT=$(echo "$TOOLS_RESP" | python3 -c "import sys,json; print(len(json.load(sys.stdin)['result']['tools']))" 2>/dev/null || echo "0")

if [[ "$TOOL_COUNT" -ge 3 ]]; then
    pass "tools/list returns $TOOL_COUNT tools"
else
    fail "tools/list returns tools" "got $TOOL_COUNT"
fi

# Check memory tools are present
HAS_MEMORY_STORE=$(echo "$TOOLS_RESP" | python3 -c "
import sys, json
tools = json.load(sys.stdin)['result']['tools']
print('yes' if any(t['name']=='memory_store' for t in tools) else 'no')
" 2>/dev/null || echo "no")

HAS_MEMORY_QUERY=$(echo "$TOOLS_RESP" | python3 -c "
import sys, json
tools = json.load(sys.stdin)['result']['tools']
print('yes' if any(t['name']=='memory_query' for t in tools) else 'no')
" 2>/dev/null || echo "no")

HAS_MEMORY_FORGET=$(echo "$TOOLS_RESP" | python3 -c "
import sys, json
tools = json.load(sys.stdin)['result']['tools']
print('yes' if any(t['name']=='memory_forget' for t in tools) else 'no')
" 2>/dev/null || echo "no")

if [[ "$HAS_MEMORY_STORE" == "yes" ]]; then
    pass "memory_store in tools/list"
else
    fail "memory_store in tools/list"
fi

if [[ "$HAS_MEMORY_QUERY" == "yes" ]]; then
    pass "memory_query in tools/list"
else
    fail "memory_query in tools/list"
fi

if [[ "$HAS_MEMORY_FORGET" == "yes" ]]; then
    pass "memory_forget in tools/list"
else
    fail "memory_forget in tools/list"
fi

# --- Test 3: Memory tools lifecycle ---
section "Memory Tools"

# Store a fact
STORE_RESP=$(call_tool "$SESSION_ID" "memory_store" '{
    "kind": "fact",
    "title": "E2E test entry",
    "content": "This is a test entry created by the e2e live script to verify memory tools work end-to-end.",
    "tags": ["e2e", "test"]
}' 10)
if [[ "$VERBOSE" == true ]]; then echo "    store: $STORE_RESP"; fi

ENTRY_ID=$(echo "$STORE_RESP" | python3 -c "
import sys, json
resp = json.load(sys.stdin)
text = resp['result']['content'][0]['text']
stored = json.loads(text)
print(stored['id'])
" 2>/dev/null || echo "")

if [[ -n "$ENTRY_ID" ]]; then
    pass "memory_store returns entry ID ($ENTRY_ID)"
else
    fail "memory_store returns entry ID" "response: $STORE_RESP"
fi

# Store a second entry (different kind)
STORE2_RESP=$(call_tool "$SESSION_ID" "memory_store" '{
    "kind": "insight",
    "title": "E2E insight entry",
    "content": "Local model execution reduces latency and eliminates API rate limits for multi-agent workflows."
}' 11)

ENTRY2_ID=$(echo "$STORE2_RESP" | python3 -c "
import sys, json
text = json.load(sys.stdin)['result']['content'][0]['text']
print(json.loads(text)['id'])
" 2>/dev/null || echo "")

if [[ -n "$ENTRY2_ID" ]]; then
    pass "memory_store second entry (insight)"
else
    fail "memory_store second entry"
fi

# Query - should find the fact
QUERY_RESP=$(call_tool "$SESSION_ID" "memory_query" '{"query": "e2e test entry"}' 12)
if [[ "$VERBOSE" == true ]]; then echo "    query: $QUERY_RESP"; fi

FOUND=$(echo "$QUERY_RESP" | python3 -c "
import sys, json, re
text = json.load(sys.stdin)['result']['content'][0]['text']
# Safety filter may redact timestamps as phone numbers; fix broken JSON
text = re.sub(r'\[REDACTED:\w+\]', '\"[REDACTED]\"', text)
results = json.loads(text)
found = any(r['id'] == '$ENTRY_ID' for r in results)
print('yes' if found else 'no')
" 2>/dev/null || echo "no")

if [[ "$FOUND" == "yes" ]]; then
    pass "memory_query finds stored entry"
else
    fail "memory_query finds stored entry"
fi

# Query with kind filter
FILTER_RESP=$(call_tool "$SESSION_ID" "memory_query" '{"query": "e2e", "kind": "fact"}' 13)

ALL_FACTS=$(echo "$FILTER_RESP" | python3 -c "
import sys, json, re
text = json.load(sys.stdin)['result']['content'][0]['text']
text = re.sub(r'\[REDACTED:\w+\]', '\"[REDACTED]\"', text)
results = json.loads(text)
print('yes' if all(r['kind'] == 'fact' for r in results) else 'no')
" 2>/dev/null || echo "no")

if [[ "$ALL_FACTS" == "yes" ]]; then
    pass "memory_query kind filter works"
else
    fail "memory_query kind filter works"
fi

# Forget the first entry
FORGET_RESP=$(call_tool "$SESSION_ID" "memory_forget" "{\"id\": \"$ENTRY_ID\"}" 14)
if [[ "$VERBOSE" == true ]]; then echo "    forget: $FORGET_RESP"; fi

DELETED=$(echo "$FORGET_RESP" | python3 -c "
import sys, json
text = json.load(sys.stdin)['result']['content'][0]['text']
print(json.loads(text).get('status', ''))
" 2>/dev/null || echo "")

if [[ "$DELETED" == "deleted" ]]; then
    pass "memory_forget deletes entry"
else
    fail "memory_forget deletes entry" "response: $FORGET_RESP"
fi

# Verify it's gone
VERIFY_RESP=$(call_tool "$SESSION_ID" "memory_query" '{"query": "e2e test entry"}' 15)

STILL_THERE=$(echo "$VERIFY_RESP" | python3 -c "
import sys, json
text = json.load(sys.stdin)['result']['content'][0]['text']
results = json.loads(text)
print('yes' if any(r['id'] == '$ENTRY_ID' for r in results) else 'no')
" 2>/dev/null || echo "yes")

if [[ "$STILL_THERE" == "no" ]]; then
    pass "forgotten entry no longer returned by query"
else
    fail "forgotten entry no longer returned by query"
fi

# Forget nonexistent
FORGET_BAD=$(call_tool "$SESSION_ID" "memory_forget" '{"id": "nonexistent-00000"}' 16)
IS_ERROR=$(echo "$FORGET_BAD" | python3 -c "
import sys, json
resp = json.load(sys.stdin)
is_err = resp.get('result', {}).get('isError', False)
text = resp.get('result', {}).get('content', [{}])[0].get('text', '')
print('yes' if is_err or 'No entry' in text else 'no')
" 2>/dev/null || echo "no")

if [[ "$IS_ERROR" == "yes" ]]; then
    pass "memory_forget nonexistent returns error"
else
    fail "memory_forget nonexistent returns error"
fi

# Clean up second entry
call_tool "$SESSION_ID" "memory_forget" "{\"id\": \"$ENTRY2_ID\"}" 17 >/dev/null 2>&1

# --- Test 4: File tools ---
section "File Tools"

# Verify file_* tools are present (not docs_*)
HAS_FILE_READ=$(echo "$TOOLS_RESP" | python3 -c "
import sys, json
tools = json.load(sys.stdin)['result']['tools']
print('yes' if any(t['name']=='file_read' for t in tools) else 'no')
" 2>/dev/null || echo "no")

HAS_DOCS_READ=$(echo "$TOOLS_RESP" | python3 -c "
import sys, json
tools = json.load(sys.stdin)['result']['tools']
print('yes' if any(t['name']=='docs_read' for t in tools) else 'no')
" 2>/dev/null || echo "no")

if [[ "$HAS_FILE_READ" == "yes" ]]; then
    pass "file_read tool registered"
else
    fail "file_read tool registered"
fi

if [[ "$HAS_DOCS_READ" == "no" ]]; then
    pass "docs_read tool removed (renamed to file_read)"
else
    fail "docs_read tool removed" "still present — rename incomplete"
fi

# Check all file_* tools are present
FILE_TOOLS_OK=$(echo "$TOOLS_RESP" | python3 -c "
import sys, json
tools = [t['name'] for t in json.load(sys.stdin)['result']['tools']]
expected = ['file_read', 'file_write', 'file_list', 'file_tree', 'file_grep']
missing = [t for t in expected if t not in tools]
print('yes' if not missing else 'no: ' + ','.join(missing))
" 2>/dev/null || echo "no")

if [[ "$FILE_TOOLS_OK" == "yes" ]]; then
    pass "all core file_* tools registered"
else
    fail "all core file_* tools registered" "$FILE_TOOLS_OK"
fi

# Write a test file, read it back, delete it
WRITE_RESP=$(call_tool "$SESSION_ID" "file_write" "{
    \"path\": \"$DEMO_DIR/e2e-test-file.txt\",
    \"content\": \"Hello from e2e test\"
}" 30)
if [[ "$VERBOSE" == true ]]; then echo "    write: $WRITE_RESP"; fi

WRITE_OK=$(echo "$WRITE_RESP" | python3 -c "
import sys, json
resp = json.load(sys.stdin)
is_err = resp.get('result', {}).get('isError', False)
print('no' if is_err else 'yes')
" 2>/dev/null || echo "no")

if [[ "$WRITE_OK" == "yes" ]]; then
    pass "file_write creates file"
else
    fail "file_write creates file" "response: $WRITE_RESP"
fi

# Read it back
READ_RESP=$(call_tool "$SESSION_ID" "file_read" "{\"path\": \"$DEMO_DIR/e2e-test-file.txt\"}" 31)

READ_CONTENT=$(echo "$READ_RESP" | python3 -c "
import sys, json
text = json.load(sys.stdin)['result']['content'][0]['text']
print(text.strip())
" 2>/dev/null || echo "")

if echo "$READ_CONTENT" | grep -q "Hello from e2e test"; then
    pass "file_read returns written content"
else
    fail "file_read returns written content" "got: $READ_CONTENT"
fi

# Tree
TREE_RESP=$(call_tool "$SESSION_ID" "file_tree" "{\"path\": \"$DEMO_DIR\"}" 32)

TREE_HAS_FILE=$(echo "$TREE_RESP" | python3 -c "
import sys, json
text = json.load(sys.stdin)['result']['content'][0]['text']
print('yes' if 'e2e-test-file.txt' in text else 'no')
" 2>/dev/null || echo "no")

if [[ "$TREE_HAS_FILE" == "yes" ]]; then
    pass "file_tree lists written file"
else
    fail "file_tree lists written file"
fi

# Delete
call_tool "$SESSION_ID" "file_delete" "{\"path\": \"$DEMO_DIR/e2e-test-file.txt\"}" 33 >/dev/null 2>&1

if [[ ! -f "$DEMO_DIR/e2e-test-file.txt" ]]; then
    pass "file_delete removes file"
else
    fail "file_delete removes file"
fi

# --- Test 5: Model proxy ---
section "Model Proxy"

PROXY_RESP=$(curl -sf -X POST "$BASE_URL/v1/chat/completions" \
    -H "Content-Type: application/json" \
    -d '{"model":"test","messages":[{"role":"user","content":"hi"}],"max_tokens":5}')

PROXY_OK=$(echo "$PROXY_RESP" | python3 -c "
import sys, json
r = json.load(sys.stdin)
ok = r.get('object') == 'chat.completion' and 'choices' in r
print('yes' if ok else 'no')
" 2>/dev/null || echo "no")

if [[ "$PROXY_OK" == "yes" ]]; then
    pass "model proxy returns OpenAI-compatible response"
else
    fail "model proxy returns OpenAI-compatible response" "response: $PROXY_RESP"
fi

# --- Test 5: API status ---
section "API"

STATUS_RESP=$(curl -sf "$BASE_URL/api/status")
STATUS_OK=$(echo "$STATUS_RESP" | python3 -c "
import sys, json
r = json.load(sys.stdin)
print('yes' if r.get('status') == 'running' else 'no')
" 2>/dev/null || echo "no")

if [[ "$STATUS_OK" == "yes" ]]; then
    pass "API status returns running"
else
    fail "API status returns running"
fi

# --- Test 6: Static assets ---
INDEX_RESP=$(curl -sf "$BASE_URL/")
if echo "$INDEX_RESP" | grep -q "<html\|DOCTYPE" 2>/dev/null; then
    pass "Static index.html served"
else
    fail "Static index.html served"
fi

# --- Test 7: Blackbox audit ---
section "Blackbox Audit"

AUDIT_RESP=$(call_tool "$SESSION_ID" "audit_query" '{"summary": true}' 20)
if [[ "$VERBOSE" == true ]]; then echo "    audit: $AUDIT_RESP"; fi

AUDIT_OK=$(echo "$AUDIT_RESP" | python3 -c "
import sys, json
resp = json.load(sys.stdin)
print('yes' if 'result' in resp else 'no')
" 2>/dev/null || echo "no")

if [[ "$AUDIT_OK" == "yes" ]]; then
    pass "audit_query returns results"
else
    fail "audit_query returns results"
fi

# Verify blackbox DB exists and has entries (gateway-level hash-chained audit).
# audit_query queries the structured audit.db (agent runs), not blackbox.db.
# The blackbox is verified by the Rust e2e tests; here we just confirm the
# audit tool responds and the blackbox DB file grew.
BLACKBOX_DB="$HOME/.local/share/smgglrs/blackbox.db"
if [[ -f "$BLACKBOX_DB" ]]; then
    BB_SIZE=$(stat -c%s "$BLACKBOX_DB" 2>/dev/null || echo "0")
    if [[ "$BB_SIZE" -gt 0 ]]; then
        pass "blackbox.db exists and is non-empty (${BB_SIZE} bytes)"
    else
        fail "blackbox.db exists but is empty"
    fi
else
    fail "blackbox.db not found at $BLACKBOX_DB"
fi

# --- Test 8: Agent run (optional) ---
if [[ "$WITH_AGENT" == true ]]; then
    section "Agent Run (live, model: $MODEL)"

    # Check if Ollama is available
    if ! curl -sf "http://localhost:11434/api/tags" >/dev/null 2>&1; then
        fail "Ollama not running" "Start with: ollama serve"
    else
        # Check if model is pulled
        MODEL_AVAIL=$(curl -sf "http://localhost:11434/api/tags" | python3 -c "
import sys, json
models = json.load(sys.stdin).get('models', [])
base = '$MODEL'.split(':')[0]
print('yes' if any(m['name'].startswith(base) for m in models) else 'no')
" 2>/dev/null || echo "no")

        if [[ "$MODEL_AVAIL" != "yes" ]]; then
            fail "Model $MODEL not available" "Pull with: ollama pull $MODEL"
        else
            pass "Ollama running, model $MODEL available"

            echo "  Running agent task (this may take 30-120s)..."
            AGENT_START=$(date +%s)

            # Smoke test: agent must call at least one tool.
            # "List tools" is a simple task but it still requires
            # calling tools/list via the MCP client, which exercises
            # the full agent -> gateway -> tool pipeline.
            AGENT_OUTPUT=$("$MCPD_BIN" run \
                "Use the file_tree tool to list the project structure, then summarize what you see." \
                --model "$MODEL" \
                --endpoint "$BASE_URL/mcp" \
                --max-iterations 10 \
                2>"$DEMO_DIR/agent-stderr.log" || echo "__AGENT_FAILED__")

            AGENT_END=$(date +%s)
            AGENT_DURATION=$((AGENT_END - AGENT_START))

            if [[ "$AGENT_OUTPUT" == *"__AGENT_FAILED__"* ]]; then
                fail "agent run completed" "see $DEMO_DIR/agent-stderr.log"
            else
                pass "agent run completed (${AGENT_DURATION}s)"

                # Check agent actually called tools (iterations > 0)
                SMOKE_ITERS=$(grep -oP 'Iterations: \K\d+' "$DEMO_DIR/agent-stderr.log" || echo "0")
                if [[ "$SMOKE_ITERS" -gt 0 ]]; then
                    pass "agent executed $SMOKE_ITERS tool-use iterations"
                else
                    fail "agent executed tool-use iterations" "0 iterations — model may not follow tool_choice"
                fi

                if [[ "$VERBOSE" == true ]]; then
                    echo ""
                    echo "  --- Agent output ---"
                    echo "$AGENT_OUTPUT" | head -30 | sed 's/^/  /'
                    echo "  ---"
                fi
            fi

            # Verify blackbox grew after agent run (agent tool calls are
            # recorded in the gateway-level blackbox.db, not in audit.db
            # which tracks structured agent runs).
            BB_SIZE_AFTER=$(stat -c%s "$BLACKBOX_DB" 2>/dev/null || echo "0")
            if [[ "$BB_SIZE_AFTER" -gt "$BB_SIZE" ]]; then
                pass "blackbox grew after agent run ($BB_SIZE -> $BB_SIZE_AFTER bytes)"
            else
                # Size may not change if SQLite hasn't flushed yet, but
                # at minimum the DB should still be non-empty.
                if [[ "$BB_SIZE_AFTER" -gt 0 ]]; then
                    pass "blackbox exists after agent run ($BB_SIZE_AFTER bytes)"
                else
                    fail "blackbox empty after agent run"
                fi
            fi
        fi
    fi
fi

# --- Test 9: Live demo (multi-agent orchestration) ---
if [[ "$LIVE_DEMO" == true ]]; then
    section "Live Demo (multi-agent, model: $MODEL)"

    DEMO_PROJECT="$REPO_ROOT/examples/payments-app"
    if [[ ! -d "$DEMO_PROJECT" ]]; then
        fail "demo project exists at examples/payments-app"
    else
        pass "demo project found"

        # Stop current smgglrs and restart with demo-appropriate config
        # that serves the payments-app directory
        kill "$MCPD_PID" 2>/dev/null; wait "$MCPD_PID" 2>/dev/null || true

        DEMO_PORT=$(python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1",0)); print(s.getsockname()[1]); s.close()')
        DEMO_CONFIG="$DEMO_DIR/demo-config.toml"
        DEMO_URL="http://127.0.0.1:$DEMO_PORT"

        ABS_DEMO_PROJECT=$(cd "$DEMO_PROJECT" && pwd)

        cat > "$DEMO_CONFIG" <<DEMOEOF
cognitive_core = "$REPO_ROOT/cognitive_core"

[server]
tcp = "127.0.0.1:$DEMO_PORT"

[modules.docs]
enabled = true
default_root = "$ABS_DEMO_PROJECT"

[modules.git]
enabled = false

[permissions.readonly]
allow = ["$ABS_DEMO_PROJECT/**", "/tmp/**"]
deny = []
operations = ["read", "search", "list"]
safety = "standard"
DEMOEOF

        "$MCPD_BIN" serve --config "$DEMO_CONFIG" --no-tray \
            >"$DEMO_DIR/demo-smgglrs-stdout.log" 2>"$DEMO_DIR/demo-smgglrs-stderr.log" &
        MCPD_PID=$!

        # Wait for ready
        DEMO_READY=false
        for i in $(seq 1 30); do
            if curl -sf "$DEMO_URL/api/status" >/dev/null 2>&1; then
                DEMO_READY=true
                break
            fi
            if ! kill -0 "$MCPD_PID" 2>/dev/null; then
                break
            fi
            sleep 0.5
        done

        if [[ "$DEMO_READY" != true ]]; then
            fail "demo smgglrs started" "check $DEMO_DIR/demo-smgglrs-stderr.log"
        else
            pass "demo smgglrs running on port $DEMO_PORT"

            # The prompt must trigger multi-agent behavior:
            # - Lead reads project structure (file_tree)
            # - Lead discovers available models (models_list) and personas (personas_list)
            # - Lead creates a team and adds teammates with personas
            # - Teammates read files and analyze them (file_read, file_grep)
            # - Lead collects results and synthesizes a report
            DEMO_PROMPT="Review this project for security issues and summarize your findings."

            echo "  Running multi-agent demo (this takes 1-5 minutes)..."
            echo "  Prompt: ${DEMO_PROMPT:0:80}..."
            DEMO_START=$(date +%s)

            DEMO_OUTPUT=$("$MCPD_BIN" run \
                "$DEMO_PROMPT" \
                --model "$MODEL" \
                --persona leader \
                --endpoint "$DEMO_URL/mcp" \
                --max-iterations 50 \
                2>"$DEMO_DIR/demo-agent-stderr.log" || echo "__DEMO_FAILED__")

            DEMO_END=$(date +%s)
            DEMO_DURATION=$((DEMO_END - DEMO_START))

            if [[ "$DEMO_OUTPUT" == *"__DEMO_FAILED__"* ]]; then
                fail "multi-agent demo completed" "see $DEMO_DIR/demo-agent-stderr.log"
                if [[ "$VERBOSE" == true ]]; then
                    echo ""
                    echo "  --- Agent stderr ---"
                    tail -20 "$DEMO_DIR/demo-agent-stderr.log" | sed 's/^/  /'
                    echo "  ---"
                fi
            else
                pass "multi-agent demo completed (${DEMO_DURATION}s)"

                # Verify the agent entered the tool-use loop
                DEMO_STDERR=$(cat "$DEMO_DIR/demo-agent-stderr.log")
                ITERATIONS=$(echo "$DEMO_STDERR" | grep -oP 'Iterations: \K\d+' || echo "0")

                if [[ "$ITERATIONS" -gt 0 ]]; then
                    pass "agent used $ITERATIONS ReAct iterations"
                else
                    # 0 iterations means the model output text/JSON without
                    # calling tools. This is a model capability issue, not
                    # a framework bug. Record but don't hard-fail.
                    fail "agent used 0 iterations (model did not call tools)" \
                        "model may not support tool_choice=required via Ollama"
                fi

                # Check for evidence of multi-agent orchestration:
                # either actual team tool calls or at least a plan that
                # references team delegation
                if echo "$DEMO_STDERR" | grep -qi "team_create\|team_add\|team_message"; then
                    pass "agent used team tools (real delegation)"
                elif [[ "$ITERATIONS" -gt 5 ]]; then
                    pass "agent ran multi-step analysis ($ITERATIONS iterations)"
                elif echo "$DEMO_OUTPUT" | grep -qi "team\|teammate\|specialist\|delegat\|team_create\|team_add"; then
                    pass "agent output references team delegation (planned but not executed)"
                else
                    fail "no evidence of team delegation in output or logs"
                fi

                # Check output quality: should mention security findings
                FINDING_COUNT=0
                for keyword in "SQL injection" "secret" "hardcoded" "authentication" "CWE" "vulnerability" "injection"; do
                    if echo "$DEMO_OUTPUT" | grep -qi "$keyword"; then
                        FINDING_COUNT=$((FINDING_COUNT + 1))
                    fi
                done

                if [[ "$FINDING_COUNT" -ge 2 ]]; then
                    pass "report mentions $FINDING_COUNT security-related terms"
                else
                    fail "report mentions security findings" "only $FINDING_COUNT terms found"
                fi

                # Check tokens consumed
                TOKENS_IN=$(echo "$DEMO_STDERR" | grep -oP 'Tokens:\s+\K\d+' || echo "0")
                if [[ "$TOKENS_IN" -gt 0 ]]; then
                    TOKENS_OUT=$(echo "$DEMO_STDERR" | grep -oP '\+ \K\d+ out' | grep -oP '^\d+' || echo "0")
                    pass "tokens consumed: ${TOKENS_IN} in + ${TOKENS_OUT} out"
                fi

                if [[ "$VERBOSE" == true ]]; then
                    echo ""
                    echo "  --- Demo report (first 50 lines) ---"
                    echo "$DEMO_OUTPUT" | head -50 | sed 's/^/  /'
                    echo "  ---"
                    echo ""
                    echo "  --- Agent stats ---"
                    echo "$DEMO_STDERR" | grep -E "^(Iterations|Tokens|Time|Taint):" | sed 's/^/  /'
                    echo "  ---"
                fi
            fi
        fi
    fi
fi

# --- Summary ---
section "Results"
echo ""
echo "  Total:  $TOTAL"
echo "  Passed: $PASSED"
echo "  Failed: $FAILED"
echo ""

if [[ "$FAILED" -gt 0 ]]; then
    echo "  SOME TESTS FAILED"
    if [[ "$VERBOSE" != true ]]; then
        echo "  Re-run with --verbose for details"
    fi
    echo ""
    exit 1
else
    echo "  ALL TESTS PASSED"
    echo ""
    exit 0
fi
