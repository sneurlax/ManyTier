#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"

# shellcheck source=tests/shadow/validation-paths.sh
source "$ROOT/tests/shadow/validation-paths.sh"

DIRECTION="manytier-client-official-controller"
while [[ $# -gt 0 ]]; do
  case "$1" in
    --direction)
      DIRECTION="$2"
      shift 2
      ;;
    *)
      echo "Unknown argument: $1" >&2
      exit 1
      ;;
  esac
done

case "$DIRECTION" in
  manytier-client-official-controller)
    REPORT_BASENAME="tool-parity-manytier-client-official-controller.md"
    OUTPUT_BASENAME="manytier-client-official-controller-baseline-refresh.md"
    TITLE="Self-Hosted Baseline Refresh: ManyTier Client -> Official Controller"
    ;;
  official-client-manytier-controller)
    REPORT_BASENAME="tool-parity-official-client-manytier-controller.md"
    OUTPUT_BASENAME="official-client-manytier-controller-baseline-refresh.md"
    TITLE="Self-Hosted Baseline Refresh: Official Client -> ManyTier Controller"
    ;;
  *)
    echo "Unsupported direction: $DIRECTION" >&2
    exit 1
    ;;
esac

TIMESTAMP="$(manytier_validation_timestamp)"
if [[ -n "${MANYTIER_BASELINE_REFRESH_ARTIFACT_ROOT:-}" ]]; then
  ARTIFACT_ROOT="$(manytier_validation_ensure_repo_local "baseline refresh artifact root" "$MANYTIER_BASELINE_REFRESH_ARTIFACT_ROOT")"
else
  ARTIFACT_ROOT="$(manytier_validation_artifact_parent)/run-${TIMESTAMP}-${DIRECTION}-baseline-refresh"
fi
mkdir -p "$ARTIFACT_ROOT"

OFFICIAL_BIN="$(manytier_validation_recommended_official_bin)"
OFFICIAL_SOURCE="$(manytier_validation_official_bin_source "$OFFICIAL_BIN")"
OFFICIAL_VERSION="$(manytier_validation_official_bin_version "$OFFICIAL_BIN")"
RUNNER="./tests/shadow/run-privileged-live.sh"
ENVIRONMENT_SHAPE="current-shell"

if ./tests/shadow/probe-environment.sh >"$ARTIFACT_ROOT/direct-probe.log" 2>&1; then
  :
elif command -v docker >/dev/null 2>&1 && docker info >/dev/null 2>&1; then
  RUNNER="./tests/shadow/run-privileged-live-docker.sh"
  ENVIRONMENT_SHAPE="privileged-docker"
else
  cat >"$ARTIFACT_ROOT/$OUTPUT_BASENAME" <<EOF
# $TITLE

- generated: $(date -u +%Y-%m-%dT%H:%M:%SZ)
- artifact_root: $ARTIFACT_ROOT
- classification: environment
- note: No strict-lane runner is available on this workstation.
- direct_probe_log: $ARTIFACT_ROOT/direct-probe.log
- portable_environment_report: ${MANYTIER_PORTABLE_PREFLIGHT_REPORT_MD:-<missing>}
- hosted_policy: Hosted official-network execution remains deferred for v1.7.
EOF
  printf '%s\n' "$ARTIFACT_ROOT/$OUTPUT_BASENAME"
  exit 1
fi

RUN_STATUS=0
if MANYTIER_ARTIFACT_ROOT="$ARTIFACT_ROOT" \
   MANYTIER_ZEROTIER_ONE_BIN="$OFFICIAL_BIN" \
   MANYTIER_VALIDATION_OFFICIAL_SOURCE="$OFFICIAL_SOURCE" \
   MANYTIER_VALIDATION_OFFICIAL_HOST_PATH="$OFFICIAL_BIN" \
   MANYTIER_VALIDATION_ENVIRONMENT_SHAPE="$ENVIRONMENT_SHAPE" \
   "$RUNNER" >"$ARTIFACT_ROOT/baseline-refresh-run.log" 2>&1; then
  RUN_STATUS=0
else
  RUN_STATUS=$?
fi

REPORT_PATH="$ARTIFACT_ROOT/$REPORT_BASENAME"
MANIFEST_PATH="$ARTIFACT_ROOT/self-hosted-validation-manifest.json"
CLASSIFICATION="harness"
NOTE="Strict lane failed before the direction-specific report passed."
if grep -q '^\[FAIL\]' "$ARTIFACT_ROOT/probe.log" 2>/dev/null; then
  CLASSIFICATION="environment"
  NOTE="$(grep '^\[FAIL\]' "$ARTIFACT_ROOT/probe.log" | head -n 1 | sed 's/^[[:space:]]*//')"
elif grep -Eq 'PROTOCOL FAILURE|LIVE FAILURE' "$ARTIFACT_ROOT/run.log" 2>/dev/null; then
  CLASSIFICATION="protocol"
  NOTE="$(grep -E 'PROTOCOL FAILURE|LIVE FAILURE' "$ARTIFACT_ROOT/run.log" | head -n 1 | sed 's/^[[:space:]]*//')"
elif grep -Eq 'INFRASTRUCTURE FAILURE|LANE MISCONFIGURATION|FAILED:' "$ARTIFACT_ROOT/run.log" 2>/dev/null; then
  CLASSIFICATION="harness"
  NOTE="$(grep -E 'INFRASTRUCTURE FAILURE|LANE MISCONFIGURATION|FAILED:' "$ARTIFACT_ROOT/run.log" | head -n 1 | sed 's/^[[:space:]]*//')"
fi

RESULT_STATUS="<missing>"
NETWORK_ID="<missing>"
ASSIGNED_IPV4="<missing>"
if [[ -f "$REPORT_PATH" ]]; then
  RESULT_STATUS="$(sed -n 's/^overall_result: //p' "$REPORT_PATH" | head -n 1)"
  NETWORK_ID="$(sed -n 's/^network_id: //p' "$REPORT_PATH" | head -n 1)"
  ASSIGNED_IPV4="$(sed -n 's/^assigned_ipv4: //p' "$REPORT_PATH" | head -n 1)"
  if [[ "$RESULT_STATUS" == "passed" ]]; then
    CLASSIFICATION="passed"
    NOTE="Fresh assigned-address evidence is preserved in the direction-specific tool-parity report."
  fi
fi

cat >"$ARTIFACT_ROOT/$OUTPUT_BASENAME" <<EOF
# $TITLE

- generated: $(date -u +%Y-%m-%dT%H:%M:%SZ)
- artifact_root: $ARTIFACT_ROOT
- direction: $DIRECTION
- strict_lane_runner: $RUNNER
- environment_shape: $ENVIRONMENT_SHAPE
- official_binary: $OFFICIAL_BIN
- official_binary_source: $OFFICIAL_SOURCE
- official_binary_version: $OFFICIAL_VERSION
- strict_lane_exit_code: $RUN_STATUS
- classification: $CLASSIFICATION
- note: $NOTE
- portable_environment_report: ${MANYTIER_PORTABLE_PREFLIGHT_REPORT_MD:-<missing>}
- report: $REPORT_PATH
- manifest: $MANIFEST_PATH
- network_id: $NETWORK_ID
- assigned_ipv4: $ASSIGNED_IPV4
- hosted_policy: Hosted official-network execution remains deferred for v1.7.
EOF

printf '%s\n' "$ARTIFACT_ROOT/$OUTPUT_BASENAME"
if [[ "$CLASSIFICATION" != "passed" ]]; then
  exit 1
fi
