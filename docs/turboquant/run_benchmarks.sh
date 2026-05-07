#!/bin/bash
# Run multi-turn tool calling benchmarks across KV cache configurations.
#
# Usage: ./run_benchmarks.sh [model_path] [runs_per_config]
#
# Results are saved to results/ directory.

set -euo pipefail

TURBOQUANT="/home/fdupont/Code/github.com/craftogrammer/llama.cpp-adaptive-turboquant"
MODEL="${1:-/home/fdupont/.local/share/smgglrs/models/qwen3-8b.gguf}"
RUNS="${2:-5}"
PORT=8090
BENCH_SCRIPT="$(dirname "$0")/tool_calling_bench.py"
RESULTS_DIR="$(dirname "$0")/results"

mkdir -p "$RESULTS_DIR"

export LD_LIBRARY_PATH="$TURBOQUANT/build-container/bin:$TURBOQUANT/build-container/cuda-libs:${LD_LIBRARY_PATH:-}"

SERVER="$TURBOQUANT/build-container/bin/llama-server"

CONFIGS=(
    "f16:f16"
    "q8_0:q8_0"
    "q4_0:q4_0"
    "turbo4:turbo4"
    "turbo3:turbo3"
    "turbo2:turbo2"
    "q8_0:turbo4"
    "q8_0:turbo3"
    "q8_0:turbo2"
)

start_server() {
    local ctk="$1"
    local ctv="$2"

    echo "Starting server: K=$ctk V=$ctv"
    $SERVER \
        --model "$MODEL" \
        --ctx-size 8192 \
        --cache-type-k "$ctk" \
        --cache-type-v "$ctv" \
        --host 127.0.0.1 \
        --port "$PORT" \
        --n-gpu-layers 999 \
        --flash-attn on \
        &
    SERVER_PID=$!

    # Wait for server to be ready
    for i in $(seq 1 30); do
        if curl -s "http://127.0.0.1:$PORT/health" | grep -q "ok"; then
            echo "Server ready (PID $SERVER_PID)"
            return 0
        fi
        sleep 1
    done

    echo "Server failed to start"
    kill $SERVER_PID 2>/dev/null || true
    return 1
}

stop_server() {
    if [ -n "${SERVER_PID:-}" ]; then
        kill $SERVER_PID 2>/dev/null || true
        wait $SERVER_PID 2>/dev/null || true
        unset SERVER_PID
        sleep 2
    fi
}

trap stop_server EXIT

echo "=== Multi-Turn Tool Calling Benchmark ==="
echo "Model: $MODEL"
echo "Runs per config: $RUNS"
echo "Results dir: $RESULTS_DIR"
echo ""

for config in "${CONFIGS[@]}"; do
    ctk="${config%%:*}"
    ctv="${config##*:}"
    label="${ctk}-${ctv}"

    echo ""
    echo "=========================================="
    echo "Config: K=$ctk V=$ctv"
    echo "=========================================="

    stop_server

    if ! start_server "$ctk" "$ctv"; then
        echo "SKIP: server failed to start for $label"
        continue
    fi

    python3 "$BENCH_SCRIPT" \
        --url "http://127.0.0.1:$PORT" \
        --runs "$RUNS" \
        --turns 5 \
        --label "$label" \
        --output "$RESULTS_DIR/${label}.json" \
        -v

    stop_server
done

echo ""
echo "=== All benchmarks complete ==="
echo "Results in: $RESULTS_DIR/"
ls -la "$RESULTS_DIR/"*.json 2>/dev/null
