#!/usr/bin/env bash
#
# Benchmark local models for agent task performance.
#
# Measures: tool call success rate, iteration count, token usage,
# latency, and output quality for a standardized task.
#
# Usage:
#   ./scripts/benchmark-models.sh                     # benchmark all Ollama models
#   ./scripts/benchmark-models.sh gemma4:e4b qwen3:8b # benchmark specific models
#
# Prerequisites:
#   - smgglrs running (smgglrs serve)
#   - Ollama running with models pulled
#   - A project directory to analyze (default: examples/payments-app)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
ENDPOINT="${SMGGLRS_ENDPOINT:-http://127.0.0.1:9315/mcp}"
PROJECT="${BENCHMARK_PROJECT:-$REPO_ROOT/examples/payments-app}"
RESULTS_DIR="$REPO_ROOT/benchmarks/model-results"
TIMESTAMP=$(date +%Y%m%d-%H%M%S)

export ORT_LIB_PATH="${ORT_LIB_PATH:-/usr/lib64}"
export ORT_PREFER_DYNAMIC_LINK=1

mkdir -p "$RESULTS_DIR"

# Standard benchmark task: read a file tree, read 3 specific files,
# grep for a pattern. Tests tool calling reliability.
BENCHMARK_PROMPT="Use file_tree to list the project structure. \
Then use file_read to read the first 3 source files you find. \
Then use file_grep to search for 'password' across the project. \
Report what you found."

# Models to test: either from args or auto-detect from Ollama
if [[ $# -gt 0 ]]; then
    MODELS=("$@")
else
    MODELS=($(curl -sf http://localhost:11434/api/tags 2>/dev/null | \
        python3 -c "import sys,json; [print(m['name']) for m in json.load(sys.stdin).get('models',[])]" 2>/dev/null))
fi

if [[ ${#MODELS[@]} -eq 0 ]]; then
    echo "No models found. Is Ollama running?"
    exit 1
fi

echo "╔══════════════════════════════════════════════════════╗"
echo "║  smgglrs Model Benchmark                            ║"
echo "╠══════════════════════════════════════════════════════╣"
echo "║  Endpoint: $ENDPOINT"
echo "║  Project:  $PROJECT"
echo "║  Models:   ${#MODELS[@]}"
echo "║  Task:     Tool calling reliability"
echo "╚══════════════════════════════════════════════════════╝"
echo ""

RESULTS_FILE="$RESULTS_DIR/benchmark-$TIMESTAMP.csv"
echo "model,iterations,tokens_in,tokens_out,time_secs,tool_calls,file_reads,exit_reason" > "$RESULTS_FILE"

for MODEL in "${MODELS[@]}"; do
    echo "━━━ Testing: $MODEL ━━━"

    START=$(date +%s)

    OUTPUT=$(cargo run -- run \
        "$BENCHMARK_PROMPT" \
        --model "$MODEL" \
        --persona principal_engineer \
        --endpoint "$ENDPOINT" \
        --max-iterations 20 \
        2>/tmp/benchmark-stderr.txt || echo "__FAILED__")

    END=$(date +%s)
    DURATION=$((END - START))

    # Parse stats from stderr
    ITERATIONS=$(grep -oP 'Iterations:\s+\K\d+' /tmp/benchmark-stderr.txt 2>/dev/null || echo "0")
    TOKENS_IN=$(grep -oP 'Tokens:\s+\K\d+' /tmp/benchmark-stderr.txt 2>/dev/null || echo "0")
    TOKENS_OUT=$(grep -oP '\+ \K\d+(?= out)' /tmp/benchmark-stderr.txt 2>/dev/null || echo "0")

    # Count tool calls from the blackbox
    TOOL_CALLS=$(cargo run -- audit --limit 50 --tool file_read --tool file_tree --tool file_grep 2>/dev/null | grep -c "tool=" || echo "0")
    FILE_READS=$(cargo run -- audit --limit 50 --tool file_read 2>/dev/null | grep -c "tool=file_read" || echo "0")

    # Determine exit reason
    if echo "$OUTPUT" | grep -q "__FAILED__"; then
        EXIT_REASON="error"
    elif [[ "$ITERATIONS" == "0" ]]; then
        EXIT_REASON="no_tools"
    else
        EXIT_REASON="completed"
    fi

    echo "  Iterations: $ITERATIONS"
    echo "  Tokens:     $TOKENS_IN in + $TOKENS_OUT out"
    echo "  Time:       ${DURATION}s"
    echo "  Tool calls: $TOOL_CALLS (file_read: $FILE_READS)"
    echo "  Exit:       $EXIT_REASON"
    echo ""

    echo "$MODEL,$ITERATIONS,$TOKENS_IN,$TOKENS_OUT,$DURATION,$TOOL_CALLS,$FILE_READS,$EXIT_REASON" >> "$RESULTS_FILE"
done

echo "━━━ Results ━━━"
echo ""
column -t -s',' "$RESULTS_FILE"
echo ""
echo "Saved to: $RESULTS_FILE"
