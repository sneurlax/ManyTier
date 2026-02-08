#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"

# shellcheck source=tests/shadow/validation-paths.sh
source "$ROOT/tests/shadow/validation-paths.sh"

TIMESTAMP="$(manytier_validation_timestamp)"
if [[ -n "${MANYTIER_PORTABLE_SELF_HOSTED_ARTIFACT_ROOT:-}" ]]; then
  ARTIFACT_ROOT="$(manytier_validation_ensure_repo_local "portable self-hosted artifact root" "$MANYTIER_PORTABLE_SELF_HOSTED_ARTIFACT_ROOT")"
else
  ARTIFACT_ROOT="$(manytier_validation_artifact_parent)/run-${TIMESTAMP}-portable-self-hosted"
fi
mkdir -p "$ARTIFACT_ROOT"

WORKSTATION_BASELINE_ROOT="$ARTIFACT_ROOT/workstation-baseline"
MANYTIER_SELF_HOSTED_PREFLIGHT_ARTIFACT_ROOT="$WORKSTATION_BASELINE_ROOT" \
  ./tests/shadow/preflight-self-hosted-official.sh >/dev/null

PORTABLE_CONTRACT_ROOT="$ARTIFACT_ROOT/portable-contract"
MANYTIER_PORTABLE_PREFLIGHT_ARTIFACT_ROOT="$PORTABLE_CONTRACT_ROOT" \
  ./tests/shadow/preflight-portable-self-hosted.sh \
    --baseline-json "$WORKSTATION_BASELINE_ROOT/self-hosted-environment-report.json" \
    --runner-label "${MANYTIER_PORTABLE_RUNNER_LABEL:-portable-runner}" >/dev/null

REPORT_PATH="$ARTIFACT_ROOT/portable-self-hosted-report.md"
cat >"$REPORT_PATH" <<EOF
# Portable Self-Hosted Validation Report

- generated: $(date -u +%Y-%m-%dT%H:%M:%SZ)
- artifact_root: $ARTIFACT_ROOT
- status: blocked
- classification: environment
- documented_path: VM or non-loopback runner
- workstation_read: The current workstation has a working privileged Docker lane, but no separate VM or non-loopback runner is configured yet.
- workstation_baseline_report: $WORKSTATION_BASELINE_ROOT/self-hosted-environment-report.md
- portable_contract_report: $PORTABLE_CONTRACT_ROOT/portable-self-hosted-environment-report.md
- next_step_guidance: ./tests/shadow/provision-portable-self-hosted-runner.sh --dry-run
- hosted_policy: Hosted official-network execution remains deferred for v1.7.

## Accepted Outcome

A classified blocker is allowed when the alternate environment path is not yet available. This
artifact preserves that blocker explicitly instead of silently reusing the Docker/localhost proof
shape.
EOF

printf '%s\n' "$REPORT_PATH"
