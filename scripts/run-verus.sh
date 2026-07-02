#!/bin/bash
# Run Verus deductive verification on inline verus!{} blocks.
#
# Proofs live directly in the source files alongside the code they verify.
# Ghost code (spec fn, proof fn) is erased at compile time by vstd —
# regular cargo build is unaffected.

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

CARGO_VERUS="${VERUS_PATH:-$HOME/.local/verus/verus-x86-linux}/cargo-verus"

if [ ! -x "$CARGO_VERUS" ]; then
    echo "Error: cargo-verus not found at $CARGO_VERUS"
    echo "Download from: https://github.com/verus-lang/verus/releases"
    exit 1
fi

cd "$PROJECT_ROOT"

echo "=== Drift Detection ==="
KANI_COUNT=$(grep -rn '#\[kani::proof\]' --include='*.rs' \
    "$PROJECT_ROOT" --exclude-dir='.claude' --exclude-dir='target' | wc -l)
VERUS_COUNT=$(grep -rn 'proof fn' --include='*.rs' \
    "$PROJECT_ROOT" --exclude-dir='.claude' --exclude-dir='target' | wc -l)
echo "Kani harnesses: $KANI_COUNT"
echo "Verus proofs:   $VERUS_COUNT"

echo ""
echo "=== Running Verus Verification ==="

TOTAL_VERIFIED=0
TOTAL_ERRORS=0

# Touch all verified crates to force re-verification
for dir in "$PROJECT_ROOT"/navra-*/src; do
    [ -f "$dir/lib.rs" ] && touch "$dir/lib.rs"
done

# Verify via navra-server (depends on everything)
CRATES=(navra-server)
for crate in "${CRATES[@]}"; do
    OUTPUT=$("$CARGO_VERUS" verus verify -p "$crate" "$@" 2>&1)

    while IFS= read -r line; do
        echo "$line"
        V=$(echo "$line" | grep -oP '\d+ verified' | grep -oP '\d+' || true)
        E=$(echo "$line" | grep -oP '\d+ errors' | grep -oP '\d+' || true)
        [ -n "$V" ] && TOTAL_VERIFIED=$((TOTAL_VERIFIED + V))
        [ -n "$E" ] && TOTAL_ERRORS=$((TOTAL_ERRORS + E))
    done < <(echo "$OUTPUT" | grep 'verification results')

    if echo "$OUTPUT" | grep -q 'error\[E'; then
        echo "$OUTPUT" | grep -B1 -A5 'error\[E'
        exit 1
    fi
done

echo ""
echo "=== Summary ==="
echo "Total: $TOTAL_VERIFIED verified, $TOTAL_ERRORS errors"

[ "$TOTAL_ERRORS" -gt 0 ] && exit 1
exit 0
