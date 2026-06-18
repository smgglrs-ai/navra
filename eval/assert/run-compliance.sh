#!/usr/bin/env bash
# Run navra ASSERT compliance evaluation.
#
# Modes:
#   ./run-compliance.sh              # full pipeline for all behaviors
#   ./run-compliance.sh --traces     # judge pre-collected OTel traces
#   ./run-compliance.sh --dry-run    # validate configs without running
#   ./run-compliance.sh --single F   # run a single config file
#
# Prerequisites:
#   - pip install assert-ai
#   - Ollama running with qwen2.5:7b

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"
CONFIGS_DIR="$SCRIPT_DIR/configs"
TRACES_FILE="${TRACES_FILE:-$SCRIPT_DIR/traces/adversarial_eval.json}"

cd "$PROJECT_DIR"

if ! command -v assert-ai &>/dev/null; then
    echo "ERROR: assert-ai not found. Install with: pip install assert-ai"
    exit 1
fi

run_config() {
    local config="$1"
    local mode="${2:-full}"
    local name
    name="$(basename "$config" .yaml)"

    case "$mode" in
        full)
            echo "=== Running: $name ==="
            assert-ai run --config "$config"
            ;;
        traces)
            echo "=== Judging traces: $name ==="
            assert-ai judge-traces \
                --traces "$TRACES_FILE" \
                --config "$config" \
                --output "$SCRIPT_DIR/results/$name"
            ;;
        dry-run)
            echo "=== Validating: $name ==="
            python3 -c "
from assert_ai.config import load_config
from pathlib import Path
cfg = load_config(Path('$config'))
print(f'  Config valid: suite={cfg.get(\"suite\")}, run={cfg.get(\"run\")}')
print(f'  Behavior: {cfg.get(\"behavior\", {}).get(\"name\", \"?\")}')
"
            ;;
    esac
}

case "${1:-full}" in
    --traces)
        if [[ ! -f "$TRACES_FILE" ]]; then
            echo "ERROR: Traces file not found: $TRACES_FILE"
            echo "Collect traces first with OTel export enabled."
            exit 1
        fi
        for config in "$CONFIGS_DIR"/navra-*.yaml; do
            run_config "$config" traces
        done
        ;;
    --dry-run)
        for config in "$CONFIGS_DIR"/navra-*.yaml; do
            run_config "$config" dry-run
        done
        ;;
    --single)
        shift
        run_config "$1" full
        ;;
    full|"")
        for config in "$CONFIGS_DIR"/navra-*.yaml; do
            run_config "$config" full
        done
        ;;
    *)
        echo "Usage: $0 [--traces|--dry-run|--single FILE|full]"
        exit 1
        ;;
esac

echo "Done."
