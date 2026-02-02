#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"

# shellcheck source=tests/shadow/validation-paths.sh
source "$ROOT/tests/shadow/validation-paths.sh"

slugify() {
  printf '%s' "$1" | tr '[:upper:]' '[:lower:]' | sed 's/[^a-z0-9]/-/g; s/-\{2,\}/-/g; s/^-//; s/-$//'
}

fixture_path_for_version() {
  local version="$1"
  printf '%s/zerotier-one-%s\n' "$(manytier_validation_repo_relative "$(manytier_validation_fixture_root)")" "$version"
}

ensure_fixture() {
  local version="$1"
  local fixture_rel
  fixture_rel="$(fixture_path_for_version "$version")"
  local fixture_abs
  fixture_abs="$(manytier_validation_resolve_path "$fixture_rel")"
  if [[ ! -x "$fixture_abs" ]]; then
    ./tests/fixtures/download-zerotier.sh --version "$version" --output "$fixture_rel" >&2
  fi
  printf '%s\n' "$fixture_rel"
}

classify_cell() {
  local cell_dir="$1"
  local probe_log="$cell_dir/probe.log"
  local run_log="$cell_dir/run.log"

  if [[ -f "$probe_log" ]] && grep -q '^\[FAIL\]' "$probe_log"; then
    printf 'environment|%s\n' "$(grep '^\[FAIL\]' "$probe_log" | head -n 1 | sed 's/^[[:space:]]*//')"
    return
  fi

  if [[ ! -f "$run_log" ]]; then
    printf 'harness|run.log missing; container wrapper did not preserve strict-lane output\n'
    return
  fi

  if ! grep -q 'FAILED:' "$run_log"; then
    printf 'passed|strict lane completed without FAILED markers\n'
    return
  fi

  local protocol_note
  protocol_note="$(grep -E 'PROTOCOL:|PROTOCOL FAILURE' "$run_log" | head -n 1 || true)"
  if [[ -n "$protocol_note" ]]; then
    printf 'protocol|%s\n' "$(printf '%s' "$protocol_note" | sed 's/^[[:space:]]*//')"
    return
  fi

  local harness_note
  harness_note="$(grep 'INITMOON HARNESS FAILURE:' "$run_log" | head -n 1 || true)"
  if [[ -n "$harness_note" ]]; then
    printf 'harness|%s\n' "$(printf '%s' "$harness_note" | sed 's/^[[:space:]]*//')"
    return
  fi

  harness_note="$(grep 'failed to parse moon json' "$run_log" | head -n 1 || true)"
  if [[ -n "$harness_note" ]]; then
    printf 'harness|%s\n' "$(printf '%s' "$harness_note" | sed 's/^[[:space:]]*//')"
    return
  fi

  local infra_note
  infra_note="$(grep 'INFRA:' "$run_log" | head -n 1 || true)"
  if [[ -n "$infra_note" ]]; then
    printf 'harness|%s\n' "$(printf '%s' "$infra_note" | sed 's/^[[:space:]]*//')"
    return
  fi

  local failed_note
  failed_note="$(grep 'FAILED:' "$run_log" | head -n 1 || true)"
  if [[ -n "$failed_note" ]]; then
    printf 'harness|%s\n' "$(printf '%s' "$failed_note" | sed 's/^[[:space:]]*//')"
    return
  fi

  printf 'harness|strict lane failed without a more specific classification\n'
}

TIMESTAMP="$(manytier_validation_timestamp)"
if [[ -n "${MANYTIER_BURNIN_ARTIFACT_ROOT:-}" ]]; then
  ARTIFACT_ROOT="$(manytier_validation_ensure_repo_local "burn-in artifact root" "$MANYTIER_BURNIN_ARTIFACT_ROOT")"
elif [[ -n "${MANYTIER_VALIDATION_ARTIFACT_ROOT:-}" ]]; then
  ARTIFACT_ROOT="$(manytier_validation_ensure_repo_local "validation artifact root" "$MANYTIER_VALIDATION_ARTIFACT_ROOT")"
else
  ARTIFACT_ROOT="$(manytier_validation_artifact_parent)/run-${TIMESTAMP}-self-hosted-burnin"
fi
CELLS_DIR="$ARTIFACT_ROOT/cells"
SUMMARY_PATH="$ARTIFACT_ROOT/burnin-matrix-summary.md"
ROOTLESS_PROBE_LOG="$ARTIFACT_ROOT/rootless-probe.log"

mkdir -p "$CELLS_DIR"

read -r -a VERSIONS <<< "${MANYTIER_BURNIN_VERSIONS:-1.14.2 1.16.1}"
read -r -a IMAGES <<< "${MANYTIER_BURNIN_IMAGES:-ubuntu:24.04 debian:bookworm}"

if [[ "${#VERSIONS[@]}" -lt 1 ]] || [[ "${#IMAGES[@]}" -lt 1 ]]; then
  echo "Need at least one version and one image for burn-in matrix." >&2
  exit 1
fi

declare -a MATRIX_CELLS=()
if [[ "${MANYTIER_BURNIN_FULL_MATRIX:-0}" = "1" ]]; then
  for version in "${VERSIONS[@]}"; do
    for image in "${IMAGES[@]}"; do
      MATRIX_CELLS+=("${version}|${image}")
    done
  done
else
  MATRIX_CELLS+=("${VERSIONS[0]}|${IMAGES[0]}")
  if [[ "${#IMAGES[@]}" -gt 1 ]]; then
    MATRIX_CELLS+=("${VERSIONS[0]}|${IMAGES[1]}")
  fi
  if [[ "${#VERSIONS[@]}" -gt 1 ]]; then
    MATRIX_CELLS+=("${VERSIONS[1]}|${IMAGES[0]}")
  fi
fi

echo "Artifacts will be collected in: $ARTIFACT_ROOT"
echo "Running plain-shell probe..."
if ./tests/shadow/probe-environment.sh >"$ROOTLESS_PROBE_LOG" 2>&1; then
  ROOTLESS_STATUS="passed"
  ROOTLESS_NOTE="plain-shell probe passed"
else
  ROOTLESS_STATUS="environment"
  ROOTLESS_NOTE="$(grep '^\[FAIL\]' "$ROOTLESS_PROBE_LOG" | head -n 1 | sed 's/^[[:space:]]*//' || true)"
  ROOTLESS_NOTE="${ROOTLESS_NOTE:-plain-shell probe failed}"
fi

{
  echo "# Self-Hosted Burn-In Matrix Summary"
  echo
  echo "- generated: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
  echo "- artifact_root: $ARTIFACT_ROOT"
  echo "- control_sample: tests/shadow/artifacts/run-20260412T205726/"
  echo
  echo "| Cell | Official Version | Environment Shape | Status | Artifact Root | Notes |"
  echo "|------|------------------|-------------------|--------|---------------|-------|"
  echo "| plain-shell-probe | n/a | host shell | $ROOTLESS_STATUS | $ROOTLESS_PROBE_LOG | $ROOTLESS_NOTE |"
} >"$SUMMARY_PATH"

for cell in "${MATRIX_CELLS[@]}"; do
  version="${cell%%|*}"
  image="${cell#*|}"
  fixture_rel="$(ensure_fixture "$version")"
  fixture_abs="$(manytier_validation_resolve_path "$fixture_rel")"
  cell_label="$(slugify "zt-${version}__${image}")"
  cell_dir="$CELLS_DIR/$cell_label"
  cell_rel="$(manytier_validation_repo_relative "$cell_dir")"
  mkdir -p "$cell_dir"

  echo "Running matrix cell $cell_label (version=$version image=$image)..."
  if MANYTIER_ARTIFACT_ROOT="$cell_rel" \
     MANYTIER_ZEROTIER_ONE_BIN="$fixture_rel" \
     MANYTIER_PRIV_LIVE_IMAGE="$image" \
     ./tests/shadow/run-privileged-live-docker.sh >"$cell_dir/docker-wrapper.log" 2>&1; then
    true
  else
    # The wrapper can fail for Docker / packaging reasons before the strict lane runs.
    if [[ ! -f "$cell_dir/run.log" ]]; then
      printf 'harness|docker wrapper failed before strict-lane artifacts were created\n' >"$cell_dir/classification.txt"
    fi
  fi

  if [[ ! -f "$cell_dir/classification.txt" ]]; then
    classify_cell "$cell_dir" >"$cell_dir/classification.txt"
  fi
  IFS='|' read -r status note <"$cell_dir/classification.txt"
  {
    printf '| %s | %s | `%s` | %s | `%s` | %s |\n' \
      "$cell_label" "$version" "$image" "$status" "$cell_dir" "$note"
  } >>"$SUMMARY_PATH"

  {
    echo "cell_label=$cell_label"
    echo "official_version=$version"
    echo "official_bin=$fixture_abs"
    echo "image=$image"
    echo "status=$status"
    echo "notes=$note"
  } >"$cell_dir/cell-metadata.txt"
done

echo
echo "Burn-in matrix complete."
echo "Summary: $SUMMARY_PATH"
