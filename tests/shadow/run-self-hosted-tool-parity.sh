#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"

# shellcheck source=tests/shadow/validation-paths.sh
source "$ROOT/tests/shadow/validation-paths.sh"

TIMESTAMP="$(manytier_validation_timestamp)"
if [[ -n "${MANYTIER_TOOL_PARITY_ARTIFACT_ROOT:-}" ]]; then
  ARTIFACT_ROOT="$(manytier_validation_ensure_repo_local "tool parity artifact root" "$MANYTIER_TOOL_PARITY_ARTIFACT_ROOT")"
elif [[ -n "${MANYTIER_VALIDATION_ARTIFACT_ROOT:-}" ]]; then
  ARTIFACT_ROOT="$(manytier_validation_ensure_repo_local "validation artifact root" "$MANYTIER_VALIDATION_ARTIFACT_ROOT")"
else
  ARTIFACT_ROOT="$(manytier_validation_artifact_parent)/run-${TIMESTAMP}-self-hosted-tool-parity"
fi
ARTIFACT_ROOT_REL="$(manytier_validation_repo_relative "$ARTIFACT_ROOT")"
IMAGE="${MANYTIER_TOOL_PARITY_IMAGE:-ubuntu:24.04}"
OFFICIAL_BIN="$(manytier_validation_default_official_bin)"
RUN_LOG="$ARTIFACT_ROOT/tool-parity-run.log"
SUMMARY_PATH="$ARTIFACT_ROOT/self-hosted-tool-parity-summary.md"
M2O_REPORT="$ARTIFACT_ROOT/tool-parity-manytier-client-official-controller.md"
O2M_REPORT="$ARTIFACT_ROOT/tool-parity-official-client-manytier-controller.md"
MANIFEST_PATH="$ARTIFACT_ROOT/self-hosted-validation-manifest.json"

mkdir -p "$ARTIFACT_ROOT"

echo "Artifacts will be collected in: $ARTIFACT_ROOT"
echo "Privileged image: $IMAGE"
echo "Official zerotier-one binary: $OFFICIAL_BIN"

lane_status=0
if MANYTIER_ARTIFACT_ROOT="$ARTIFACT_ROOT_REL" \
   MANYTIER_PRIV_LIVE_IMAGE="$IMAGE" \
   MANYTIER_ZEROTIER_ONE_BIN="$OFFICIAL_BIN" \
   ./tests/shadow/run-privileged-live-docker.sh >"$RUN_LOG" 2>&1; then
  lane_status=0
else
  lane_status=$?
fi

if [[ -f "$M2O_REPORT" ]]; then
  m2o_result="$(sed -n 's/^overall_result: //p' "$M2O_REPORT" | head -n 1)"
else
  m2o_result=""
fi
if [[ -f "$O2M_REPORT" ]]; then
  o2m_result="$(sed -n 's/^overall_result: //p' "$O2M_REPORT" | head -n 1)"
else
  o2m_result=""
fi

cat >"$SUMMARY_PATH" <<EOF
# Self-Hosted Tool Parity Summary

- generated: $(date -u +%Y-%m-%dT%H:%M:%SZ)
- artifact_root: $ARTIFACT_ROOT
- privileged_image: $IMAGE
- official_binary: $OFFICIAL_BIN
- privileged_lane_exit_code: $lane_status
- privileged_lane_log: $RUN_LOG
- validation_manifest: $MANIFEST_PATH
- manytier_client_vs_official_controller_report: $M2O_REPORT
- official_client_vs_manytier_controller_report: $O2M_REPORT
- manytier_client_vs_official_controller_result: ${m2o_result:-<missing>}
- official_client_vs_manytier_controller_result: ${o2m_result:-<missing>}

## Result

$(if [[ "$lane_status" -eq 0 && "$m2o_result" = "passed" && "$o2m_result" = "passed" ]]; then
    printf '%s\n' 'Self-hosted tool parity passed in both official directions. The privileged lane preserved fresh CLI/API/controller snapshots and per-direction proof reports.'
  else
    printf '%s\n' 'Self-hosted tool parity is incomplete. Inspect the privileged lane log and the per-direction reports before considering any hosted-official work.'
  fi)
EOF

echo "Summary: $SUMMARY_PATH"

if [[ "$lane_status" -ne 0 ]]; then
  exit "$lane_status"
fi
if [[ "$m2o_result" != "passed" || "$o2m_result" != "passed" ]]; then
  exit 1
fi
