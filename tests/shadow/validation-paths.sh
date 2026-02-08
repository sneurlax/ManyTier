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

manytier_validation_path_is_repo_local() {
  local path
  path="$(manytier_validation_resolve_path "$1")"
  [[ "$path" == "$MANYTIER_VALIDATION_REPO_ROOT" || "$path" == "$MANYTIER_VALIDATION_REPO_ROOT/"* ]]
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

manytier_validation_system_official_bin() {
  if [[ -n "${MANYTIER_SYSTEM_ZEROTIER_ONE_BIN:-}" ]]; then
    manytier_validation_resolve_path "$MANYTIER_SYSTEM_ZEROTIER_ONE_BIN"
    return
  fi

  command -v zerotier-one 2>/dev/null || true
}

manytier_validation_official_bin_version() {
  local path="${1:-}"
  local version
  if [[ -z "$path" || ! -x "$path" ]]; then
    printf 'unknown\n'
    return
  fi

  version="$("$path" -v 2>/dev/null | head -n 1 | tr -d '\r')"
  if [[ -n "$version" ]]; then
    printf '%s\n' "$version"
  else
    printf 'unknown\n'
  fi
}

manytier_validation_supported_official_versions() {
  printf '%s\n' "1.14.2" "1.16.1"
}

manytier_validation_official_version_supported() {
  local version="${1:-}"
  case "$version" in
    1.14.2|1.16.1)
      return 0
      ;;
    *)
      return 1
      ;;
  esac
}

manytier_validation_official_bin_source() {
  local path
  local system_path
  path="$(manytier_validation_resolve_path "$1")"
  system_path="$(manytier_validation_system_official_bin)"

  if [[ "$path" == "$(manytier_validation_fixture_root)"/zerotier-one* ]]; then
    printf 'fixture\n'
  elif [[ -n "$system_path" && "$path" == "$system_path" ]]; then
    printf 'system\n'
  else
    printf 'custom\n'
  fi
}

manytier_validation_default_official_bin() {
  if [[ -n "${MANYTIER_ZEROTIER_ONE_BIN:-}" ]]; then
    manytier_validation_resolve_path "$MANYTIER_ZEROTIER_ONE_BIN"
    return
  fi
  printf '%s\n' "$(manytier_validation_fixture_root)/zerotier-one"
}

manytier_validation_shadow_bin() {
  if [[ -n "${MANYTIER_SHADOW_BIN:-}" ]]; then
    manytier_validation_resolve_path "$MANYTIER_SHADOW_BIN"
    return
  fi

  command -v shadow 2>/dev/null || true
}

manytier_validation_shadow_version() {
  local path="${1:-$(manytier_validation_shadow_bin)}"
  local version
  if [[ -z "$path" || ! -x "$path" ]]; then
    printf 'unknown\n'
    return
  fi

  version="$("$path" --version 2>/dev/null | head -n 1 | tr -d '\r')"
  if [[ -n "$version" ]]; then
    printf '%s\n' "$version"
  else
    printf 'unknown\n'
  fi
}

manytier_validation_host_label() {
  if [[ -n "${MANYTIER_VALIDATION_HOST_LABEL:-}" ]]; then
    printf '%s\n' "$MANYTIER_VALIDATION_HOST_LABEL"
    return
  fi

  hostname 2>/dev/null || printf 'unknown\n'
}

manytier_validation_os_pretty_name() {
  if [[ -r /etc/os-release ]]; then
    # shellcheck disable=SC1091
    . /etc/os-release
    printf '%s\n' "${PRETTY_NAME:-${NAME:-unknown}}"
    return
  fi

  uname -srvmo 2>/dev/null || printf 'unknown\n'
}

manytier_validation_recommended_official_bin() {
  local system_path
  local system_version

  if [[ -n "${MANYTIER_ZEROTIER_ONE_BIN:-}" ]]; then
    manytier_validation_default_official_bin
    return
  fi

  system_path="$(manytier_validation_system_official_bin)"
  if [[ -n "$system_path" && -x "$system_path" ]]; then
    system_version="$(manytier_validation_official_bin_version "$system_path")"
    if manytier_validation_official_version_supported "$system_version"; then
      printf '%s\n' "$system_path"
      return
    fi
  fi

  printf '%s\n' "$(manytier_validation_fixture_root)/zerotier-one"
}

manytier_validation_timestamp() {
  date -u +%Y%m%dT%H%M%SZ
}
