#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"

# shellcheck source=tests/shadow/validation-paths.sh
source "$ROOT/tests/shadow/validation-paths.sh"

TIMESTAMP="$(manytier_validation_timestamp)"
if [[ -n "${MANYTIER_SELF_HOSTED_PREFLIGHT_ARTIFACT_ROOT:-}" ]]; then
  ARTIFACT_ROOT="$(manytier_validation_ensure_repo_local "preflight artifact root" "$MANYTIER_SELF_HOSTED_PREFLIGHT_ARTIFACT_ROOT")"
else
  ARTIFACT_ROOT="$(manytier_validation_artifact_parent)/run-${TIMESTAMP}-self-hosted-preflight"
fi
mkdir -p "$ARTIFACT_ROOT"

PROBE_LOG="$ARTIFACT_ROOT/current-shell-probe.log"
REPORT_MD="$ARTIFACT_ROOT/self-hosted-environment-report.md"
REPORT_JSON="$ARTIFACT_ROOT/self-hosted-environment-report.json"
GENERATED_AT="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

SYSTEM_BIN="$(manytier_validation_system_official_bin)"
SYSTEM_VERSION="unknown"
SYSTEM_SUPPORTED="false"
if [[ -n "$SYSTEM_BIN" && -x "$SYSTEM_BIN" ]]; then
  SYSTEM_VERSION="$(manytier_validation_official_bin_version "$SYSTEM_BIN")"
  if manytier_validation_official_version_supported "$SYSTEM_VERSION"; then
    SYSTEM_SUPPORTED="true"
  fi
fi

DEFAULT_FIXTURE="$(manytier_validation_fixture_root)/zerotier-one"
DEFAULT_FIXTURE_VERSION="$(manytier_validation_official_bin_version "$DEFAULT_FIXTURE")"
FIXTURE_114="$(manytier_validation_fixture_root)/zerotier-one-1.14.2"
FIXTURE_116="$(manytier_validation_fixture_root)/zerotier-one-1.16.1"
FIXTURE_114_VERSION="$(manytier_validation_official_bin_version "$FIXTURE_114")"
FIXTURE_116_VERSION="$(manytier_validation_official_bin_version "$FIXTURE_116")"

if ./tests/shadow/probe-environment.sh >"$PROBE_LOG" 2>&1; then
  DIRECT_STATUS="ready"
  DIRECT_NOTE="current shell can run the strict lane directly"
else
  DIRECT_STATUS="blocked"
  DIRECT_NOTE="$(grep '^\[FAIL\]' "$PROBE_LOG" | head -n 1 | sed 's/^[[:space:]]*//' || true)"
  DIRECT_NOTE="${DIRECT_NOTE:-current shell probe failed}"
fi

DOCKER_VERSION="missing"
DOCKER_AVAILABLE="false"
if command -v docker >/dev/null 2>&1 && docker info >/dev/null 2>&1; then
  DOCKER_AVAILABLE="true"
  DOCKER_VERSION="$(docker --version 2>/dev/null | head -n 1 | tr -d '\r')"
fi

RECOMMENDED_BIN="$(manytier_validation_recommended_official_bin)"
RECOMMENDED_VERSION="$(manytier_validation_official_bin_version "$RECOMMENDED_BIN")"
RECOMMENDED_SOURCE="$(manytier_validation_official_bin_source "$RECOMMENDED_BIN")"
RECOMMENDED_ENVIRONMENT="blocked"
RECOMMENDATION_REASON="No supported self-hosted execution path detected."
if [[ "$DIRECT_STATUS" == "ready" ]]; then
  RECOMMENDED_ENVIRONMENT="current-shell"
  RECOMMENDATION_REASON="The current shell passes the TUN probe, so the strict lane can run without Docker."
elif [[ "$DOCKER_AVAILABLE" == "true" ]]; then
  RECOMMENDED_ENVIRONMENT="privileged-docker"
  RECOMMENDATION_REASON="The current shell fails the TUN probe, but Docker is available for the privileged wrapper."
fi

export REPORT_JSON GENERATED_AT ARTIFACT_ROOT PROBE_LOG
export SYSTEM_BIN SYSTEM_VERSION SYSTEM_SUPPORTED
export DEFAULT_FIXTURE DEFAULT_FIXTURE_VERSION FIXTURE_114 FIXTURE_114_VERSION FIXTURE_116 FIXTURE_116_VERSION
export DIRECT_STATUS DIRECT_NOTE DOCKER_AVAILABLE DOCKER_VERSION
export RECOMMENDED_BIN RECOMMENDED_VERSION RECOMMENDED_SOURCE RECOMMENDED_ENVIRONMENT RECOMMENDATION_REASON

node <<'EOF'
const fs = require('fs');

const maybe = (value) => {
  if (!value) return null;
  const trimmed = value.trim();
  return trimmed === '' ? null : trimmed;
};

const data = {
  generated_at: process.env.GENERATED_AT,
  artifact_root: process.env.ARTIFACT_ROOT,
  current_shell: {
    status: process.env.DIRECT_STATUS,
    note: process.env.DIRECT_NOTE,
    probe_log: process.env.PROBE_LOG,
  },
  docker: {
    available: process.env.DOCKER_AVAILABLE === 'true',
    version: maybe(process.env.DOCKER_VERSION),
  },
  system_official_binary: {
    path: maybe(process.env.SYSTEM_BIN),
    version: process.env.SYSTEM_VERSION,
    supported: process.env.SYSTEM_SUPPORTED === 'true',
  },
  fixture_binaries: [
    {
      label: 'default',
      path: process.env.DEFAULT_FIXTURE,
      version: process.env.DEFAULT_FIXTURE_VERSION,
    },
    {
      label: '1.14.2',
      path: process.env.FIXTURE_114,
      version: process.env.FIXTURE_114_VERSION,
    },
    {
      label: '1.16.1',
      path: process.env.FIXTURE_116,
      version: process.env.FIXTURE_116_VERSION,
    },
  ],
  recommendation: {
    environment_shape: process.env.RECOMMENDED_ENVIRONMENT,
    official_binary_path: process.env.RECOMMENDED_BIN,
    official_binary_version: process.env.RECOMMENDED_VERSION,
    official_binary_source: process.env.RECOMMENDED_SOURCE,
    reason: process.env.RECOMMENDATION_REASON,
  },
  policy: 'Hosted official-network execution remains out of scope for v1.6.',
};

fs.writeFileSync(process.env.REPORT_JSON, `${JSON.stringify(data, null, 2)}\n`);
EOF

cat >"$REPORT_MD" <<EOF
# Self-Hosted Official Environment Report

- generated: $GENERATED_AT
- artifact_root: $ARTIFACT_ROOT
- current_shell_status: $DIRECT_STATUS
- current_shell_note: $DIRECT_NOTE
- current_shell_probe_log: $PROBE_LOG
- docker_available: $DOCKER_AVAILABLE
- docker_version: $DOCKER_VERSION
- system_official_binary: ${SYSTEM_BIN:-<missing>}
- system_official_version: $SYSTEM_VERSION
- system_official_supported: $SYSTEM_SUPPORTED
- recommended_environment_shape: $RECOMMENDED_ENVIRONMENT
- recommended_official_binary: $RECOMMENDED_BIN
- recommended_official_binary_version: $RECOMMENDED_VERSION
- recommended_official_binary_source: $RECOMMENDED_SOURCE

## Fixture Inventory

- default fixture: $DEFAULT_FIXTURE ($DEFAULT_FIXTURE_VERSION)
- versioned fixture 1.14.2: $FIXTURE_114 ($FIXTURE_114_VERSION)
- versioned fixture 1.16.1: $FIXTURE_116 ($FIXTURE_116_VERSION)

## Recommendation

$RECOMMENDATION_REASON

Interpretation:

- If the current shell status is \`ready\`, you can run the strict lane directly with
  \`./tests/shadow/run-privileged-live.sh\`.
- If the current shell status is \`blocked\` but Docker is available, prefer
  \`./tests/shadow/run-privileged-live-docker.sh\`; it can mount either the recommended system
  binary or a pinned fixture into the privileged wrapper.
- If neither path is available, this workstation needs a different environment shape before any
  self-hosted proof run starts.

## Policy Guardrail

Hosted official-network execution remains out of scope for v1.6. This report only selects between
the current workstation's self-hosted options.
EOF

printf '%s\n' "$REPORT_MD"
