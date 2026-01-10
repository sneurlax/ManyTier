#!/bin/bash
# DIAGNOSTIC TOOLING: not part of core manytier build. See README.md.
#
# Driver script for the upstream _doHELLO offline replay harness.
# Iterates over every tx-hello-*.bin in DUMP_DIR, runs the replay binary
# against each, and prints a summary with the drop_branch label for each file.
#
# Override DUMP_DIR or HARNESS via environment:
#   DUMP_DIR=... HARNESS=... bash ./run.sh

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

DUMP_DIR="${DUMP_DIR:-$REPO_ROOT/tests/shadow/artifacts/run-20260411T151745/host-assisted-fallback/manytier-client/manytier-data/udp-dumps}"
HARNESS="${HARNESS:-$SCRIPT_DIR/replay}"

if [ ! -x "$HARNESS" ]; then
    echo "error: harness binary not found or not executable: $HARNESS" >&2
    echo "       run 'make' in $SCRIPT_DIR first" >&2
    exit 1
fi

if [ ! -d "$DUMP_DIR" ]; then
    echo "error: dump directory not found: $DUMP_DIR" >&2
    echo "       override with DUMP_DIR=... bash run.sh" >&2
    exit 1
fi

shopt -s nullglob
FILES=("$DUMP_DIR"/tx-hello-*.bin)
shopt -u nullglob

if [ ${#FILES[@]} -eq 0 ]; then
    echo "error: no tx-hello-*.bin files in $DUMP_DIR" >&2
    exit 1
fi

echo "=========================================================="
echo "upstream-dohello-replay run"
echo "DUMP_DIR: $DUMP_DIR"
echo "HARNESS:  $HARNESS"
echo "FILES:    ${#FILES[@]} tx-hello-*.bin files"
echo "=========================================================="

ACCEPTED=0
DROPPED=0
SUMMARY=""

for f in "${FILES[@]}"; do
    BASE="$(basename "$f")"
    echo ""
    echo "=== $BASE ==="
    # Capture stdout (drop_branch=...) and stderr (trace)
    if OUTPUT=$("$HARNESS" "$f" 2>&1); then
        echo "$OUTPUT"
        LABEL=$(echo "$OUTPUT" | grep -oE 'drop_branch=[a-z_]+' | tail -1 || echo "drop_branch=harness_error")
    else
        echo "$OUTPUT"
        LABEL="drop_branch=harness_error"
    fi
    SUMMARY="${SUMMARY}${BASE}: ${LABEL}"$'\n'
    if [ "$LABEL" = "drop_branch=accepted" ]; then
        ACCEPTED=$((ACCEPTED + 1))
    else
        DROPPED=$((DROPPED + 1))
    fi
done

echo ""
echo "=========================================================="
echo "SUMMARY"
echo "=========================================================="
echo "$SUMMARY"
echo "Accepted: $ACCEPTED / ${#FILES[@]}"
echo "Dropped:  $DROPPED / ${#FILES[@]}"
