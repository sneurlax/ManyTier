#!/usr/bin/env bash
set -euo pipefail

manytier_validation_repo_root() {
  if [[ -n "${MANYTIER_VALIDATION_REPO_ROOT:-}" ]]; then
    printf '%s\n' "$MANYTIER_VALIDATION_REPO_ROOT"
    return
  fi

  local script_dir
  script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
  printf '%s\n' "$(cd "$script_dir/../.." && pwd)"
}

MANYTIER_VALIDATION_REPO_ROOT="$(manytier_validation_repo_root)"
export MANYTIER_VALIDATION_REPO_ROOT

manytier_validation_resolve_path() {
  local value="$1"
  if [[ "$value" = /* ]]; then
    printf '%s\n' "$value"
  else
    printf '%s\n' "$MANYTIER_VALIDATION_REPO_ROOT/$value"
  fi
}

manytier_validation_repo_relative() {
  local path
  path="$(manytier_validation_resolve_path "$1")"
  if [[ "$path" == "$MANYTIER_VALIDATION_REPO_ROOT" ]]; then
    printf '.\n'
    return
  fi
  if [[ "$path" == "$MANYTIER_VALIDATION_REPO_ROOT/"* ]]; then
    printf '%s\n' "${path#$MANYTIER_VALIDATION_REPO_ROOT/}"
    return
  fi

  echo "Path must stay inside the repo root: $path" >&2
  return 1
}

manytier_validation_ensure_repo_local() {
  local label="$1"
  local path
  path="$(manytier_validation_resolve_path "$2")"
  if [[ "$path" != "$MANYTIER_VALIDATION_REPO_ROOT/"* ]]; then
    echo "$label must stay inside the repo root:" >&2
    echo "  $path" >&2
    return 1
  fi
  printf '%s\n' "$path"
}

manytier_validation_artifact_parent() {
  manytier_validation_resolve_path "${MANYTIER_VALIDATION_ARTIFACT_PARENT:-tests/shadow/artifacts}"
}

manytier_validation_scratch_root() {
  manytier_validation_resolve_path "${MANYTIER_VALIDATION_SCRATCH_ROOT:-tests/shadow/artifacts/scratch}"
}

manytier_validation_fixture_root() {
  manytier_validation_resolve_path "${MANYTIER_VALIDATION_FIXTURE_ROOT:-tests/fixtures}"
}

manytier_validation_target_dir() {
  local configured="${CARGO_TARGET_DIR:-${MANYTIER_VALIDATION_BUILD_ROOT:-target-user}}"
  manytier_validation_resolve_path "$configured"
}

manytier_validation_default_official_bin() {
  if [[ -n "${MANYTIER_ZEROTIER_ONE_BIN:-}" ]]; then
    manytier_validation_resolve_path "$MANYTIER_ZEROTIER_ONE_BIN"
    return
  fi
  printf '%s\n' "$(manytier_validation_fixture_root)/zerotier-one"
}

manytier_validation_timestamp() {
  date -u +%Y%m%dT%H%M%SZ
}
