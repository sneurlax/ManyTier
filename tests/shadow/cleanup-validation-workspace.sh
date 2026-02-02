#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"

# shellcheck source=tests/shadow/validation-paths.sh
source "$ROOT/tests/shadow/validation-paths.sh"

DRY_RUN=0
REMOVE_FIXTURES=0
KEEP_PATHS=()

usage() {
  cat <<'EOF'
Usage:
  tests/shadow/cleanup-validation-workspace.sh [--dry-run] [--fixtures] [--keep <path> ...]

Options:
  --dry-run   Show what would be removed without deleting anything.
  --fixtures  Remove cached official zerotier-one fixture binaries too.
  --keep      Preserve a specific artifact bundle (repeatable). The path must live in-repo.
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --dry-run)
      DRY_RUN=1
      shift
      ;;
    --fixtures)
      REMOVE_FIXTURES=1
      shift
      ;;
    --keep)
      if [[ $# -lt 2 ]]; then
        echo "--keep requires a path" >&2
        usage >&2
        exit 1
      fi
      KEEP_PATHS+=("$(manytier_validation_ensure_repo_local "keep path" "$2")")
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "Unexpected argument: $1" >&2
      usage >&2
      exit 1
      ;;
  esac
done

artifact_parent="$(manytier_validation_artifact_parent)"
scratch_root="$(manytier_validation_scratch_root)"
fixture_root="$(manytier_validation_fixture_root)"
legacy_shadow_root="$ROOT/tests/shadow/shadow-node/tests/shadow"

declare -a CANDIDATES=()

should_keep() {
  local candidate="$1"
  local keep
  for keep in "${KEEP_PATHS[@]}"; do
    if [[ "$candidate" == "$keep" ]]; then
      return 0
    fi
  done
  return 1
}

append_candidate() {
  local candidate="$1"
  if [[ -e "$candidate" || -L "$candidate" ]]; then
    CANDIDATES+=("$candidate")
  fi
}

shopt -s nullglob
for path in "$artifact_parent"/run-* "$artifact_parent"/verify-*; do
  append_candidate "$path"
done
shopt -u nullglob

append_candidate "$scratch_root"
append_candidate "$legacy_shadow_root"

shopt -s nullglob
for path in "$ROOT"/*.moon "$ROOT"/moon.json "$ROOT"/planet.bin "$ROOT"/planet.bin.new; do
  append_candidate "$path"
done
if [[ "$REMOVE_FIXTURES" == "1" ]]; then
  for path in "$fixture_root"/zerotier-one "$fixture_root"/zerotier-one-*; do
    append_candidate "$path"
  done
fi
shopt -u nullglob

echo "Validation cleanup roots:"
echo "  artifact parent: $artifact_parent"
echo "  scratch root:    $scratch_root"
echo "  fixture root:    $fixture_root"
echo

if [[ "${#CANDIDATES[@]}" -eq 0 ]]; then
  echo "Nothing to clean."
  exit 0
fi

for candidate in "${CANDIDATES[@]}"; do
  if should_keep "$candidate"; then
    echo "keep  $candidate"
    continue
  fi

  echo "remove $candidate"
  if [[ "$DRY_RUN" == "0" ]]; then
    rm -rf "$candidate"
  fi
done
