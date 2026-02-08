#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"

# shellcheck source=tests/shadow/validation-paths.sh
source "$ROOT/tests/shadow/validation-paths.sh"

DIRECTION="manytier-client-official-controller"
BASELINE_JSON="${MANYTIER_PORTABLE_BASELINE_JSON:-}"
RUNNER_LABEL="${MANYTIER_PORTABLE_RUNNER_LABEL:-$(manytier_validation_host_label)}"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --direction)
      DIRECTION="$2"
      shift 2
      ;;
    --baseline-json)
      BASELINE_JSON="$2"
      shift 2
      ;;
    --runner-label)
      RUNNER_LABEL="$2"
      shift 2
      ;;
    *)
      echo "Unknown argument: $1" >&2
      exit 1
      ;;
  esac
done

if [[ -z "$BASELINE_JSON" ]]; then
  echo "--baseline-json is required so the portable runner can record the install delta from the workstation baseline." >&2
  exit 1
fi

BASELINE_JSON="$(manytier_validation_resolve_path "$BASELINE_JSON")"

TIMESTAMP="$(manytier_validation_timestamp)"
if [[ -n "${MANYTIER_PORTABLE_REFRESH_ARTIFACT_ROOT:-}" ]]; then
  ARTIFACT_ROOT="$(manytier_validation_ensure_repo_local "portable refresh artifact root" "$MANYTIER_PORTABLE_REFRESH_ARTIFACT_ROOT")"
else
  ARTIFACT_ROOT="$(manytier_validation_artifact_parent)/run-${TIMESTAMP}-${DIRECTION}-portable-refresh"
fi
mkdir -p "$ARTIFACT_ROOT"

PORTABLE_PREFLIGHT_ROOT="$ARTIFACT_ROOT/portable-preflight"
MANYTIER_PORTABLE_PREFLIGHT_ARTIFACT_ROOT="$PORTABLE_PREFLIGHT_ROOT" \
  ./tests/shadow/preflight-portable-self-hosted.sh \
    --baseline-json "$BASELINE_JSON" \
    --runner-label "$RUNNER_LABEL" >/dev/null

PORTABLE_PREFLIGHT_JSON="$PORTABLE_PREFLIGHT_ROOT/portable-self-hosted-environment-report.json"
PORTABLE_PREFLIGHT_MD="$PORTABLE_PREFLIGHT_ROOT/portable-self-hosted-environment-report.md"
CLASSIFICATION="$(node -e "const fs=require('fs'); const data=JSON.parse(fs.readFileSync(process.argv[1],'utf8')); process.stdout.write(data.classification || 'unknown');" "$PORTABLE_PREFLIGHT_JSON")"
NOTE="$(node -e "const fs=require('fs'); const data=JSON.parse(fs.readFileSync(process.argv[1],'utf8')); process.stdout.write(data.note || 'portable runner report missing note');" "$PORTABLE_PREFLIGHT_JSON")"

case "$DIRECTION" in
  manytier-client-official-controller)
    OUTPUT_BASENAME="manytier-client-official-controller-portable-refresh.md"
    TITLE="Portable Refresh: ManyTier Client -> Official Controller"
    ;;
  official-client-manytier-controller)
    OUTPUT_BASENAME="official-client-manytier-controller-portable-refresh.md"
    TITLE="Portable Refresh: Official Client -> ManyTier Controller"
    ;;
  *)
    echo "Unsupported direction: $DIRECTION" >&2
    exit 1
    ;;
esac

REPORT_PATH="$ARTIFACT_ROOT/$OUTPUT_BASENAME"

if [[ "$CLASSIFICATION" != "ready" ]]; then
  cat >"$REPORT_PATH" <<EOF
# $TITLE

- generated: $(date -u +%Y-%m-%dT%H:%M:%SZ)
- artifact_root: $ARTIFACT_ROOT
- direction: $DIRECTION
- classification: environment
- portable_preflight_report: $PORTABLE_PREFLIGHT_MD
- note: $NOTE
- hosted_policy: Hosted official-network execution remains deferred for v1.7.

## Result

Portable refresh did not run because the current environment does not satisfy the portable-runner
contract yet.
EOF
  printf '%s\n' "$REPORT_PATH"
  exit 1
fi

BASELINE_REFRESH_ROOT="$ARTIFACT_ROOT/baseline-refresh"
MANYTIER_BASELINE_REFRESH_ARTIFACT_ROOT="$BASELINE_REFRESH_ROOT" \
MANYTIER_PORTABLE_PREFLIGHT_REPORT_JSON="$PORTABLE_PREFLIGHT_JSON" \
MANYTIER_PORTABLE_PREFLIGHT_REPORT_MD="$PORTABLE_PREFLIGHT_MD" \
  ./tests/shadow/run-self-hosted-baseline-refresh.sh --direction "$DIRECTION"
