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

PREFLIGHT_ROOT="$ARTIFACT_ROOT/preflight"
MANYTIER_SELF_HOSTED_PREFLIGHT_ARTIFACT_ROOT="$PREFLIGHT_ROOT" \
  ./tests/shadow/preflight-self-hosted-official.sh >/dev/null

REPORT_PATH="$ARTIFACT_ROOT/portable-self-hosted-report.md"
cat >"$REPORT_PATH" <<EOF
# Portable Self-Hosted Validation Report

- generated: $(date -u +%Y-%m-%dT%H:%M:%SZ)
- artifact_root: $ARTIFACT_ROOT
- status: blocked
- classification: environment
- documented_path: VM or non-loopback runner
- workstation_read: The current workstation has a working privileged Docker lane, but no separate VM or non-loopback runner is configured yet.
- preflight_report: $PREFLIGHT_ROOT/self-hosted-environment-report.md
- next_step_guidance: Provision a Linux VM or remote runner with /dev/net/tun, CAP_NET_ADMIN, Docker or host execution access, and either the installed system zerotier-one binary or a supported pinned fixture.
- hosted_policy: Hosted official-network execution remains deferred for v1.6.

## Accepted Outcome

A classified blocker is allowed when the alternate environment path is not yet available. This
artifact preserves that blocker explicitly instead of silently reusing the Docker/localhost proof
shape.
EOF

printf '%s\n' "$REPORT_PATH"
