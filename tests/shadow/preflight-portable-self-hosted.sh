#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"

# shellcheck source=tests/shadow/validation-paths.sh
source "$ROOT/tests/shadow/validation-paths.sh"

BASELINE_JSON="${MANYTIER_PORTABLE_BASELINE_JSON:-}"
RUNNER_LABEL="${MANYTIER_PORTABLE_RUNNER_LABEL:-$(manytier_validation_host_label)}"

while [[ $# -gt 0 ]]; do
  case "$1" in
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

if [[ -n "$BASELINE_JSON" ]]; then
  BASELINE_JSON="$(manytier_validation_resolve_path "$BASELINE_JSON")"
fi

TIMESTAMP="$(manytier_validation_timestamp)"
if [[ -n "${MANYTIER_PORTABLE_PREFLIGHT_ARTIFACT_ROOT:-}" ]]; then
  ARTIFACT_ROOT="$(manytier_validation_ensure_repo_local "portable preflight artifact root" "$MANYTIER_PORTABLE_PREFLIGHT_ARTIFACT_ROOT")"
else
  ARTIFACT_ROOT="$(manytier_validation_artifact_parent)/run-${TIMESTAMP}-portable-self-hosted-preflight"
fi
mkdir -p "$ARTIFACT_ROOT"

CURRENT_PREFLIGHT_ROOT="$ARTIFACT_ROOT/current-runner"
MANYTIER_SELF_HOSTED_PREFLIGHT_ARTIFACT_ROOT="$CURRENT_PREFLIGHT_ROOT" \
  ./tests/shadow/preflight-self-hosted-official.sh >/dev/null

CURRENT_JSON="$CURRENT_PREFLIGHT_ROOT/self-hosted-environment-report.json"
OUTPUT_JSON="$ARTIFACT_ROOT/portable-self-hosted-environment-report.json"
OUTPUT_MD="$ARTIFACT_ROOT/portable-self-hosted-environment-report.md"
GENERATED_AT="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
RUST_TOOLCHAIN="$(awk -F'"' '/^channel = / { print $2; exit }' "$ROOT/rust-toolchain.toml")"

export GENERATED_AT ARTIFACT_ROOT BASELINE_JSON CURRENT_JSON OUTPUT_JSON OUTPUT_MD RUNNER_LABEL RUST_TOOLCHAIN

node <<'EOF'
const fs = require('fs');

const readJson = (filePath) => {
  if (!filePath) return null;
  try {
    return JSON.parse(fs.readFileSync(filePath, 'utf8'));
  } catch {
    return null;
  }
};

const baseline = readJson(process.env.BASELINE_JSON);
const current = readJson(process.env.CURRENT_JSON);
const runnerLabel = process.env.RUNNER_LABEL;
const rustToolchain = process.env.RUST_TOOLCHAIN || 'stable';

const currentShellStatus = current?.current_shell?.status ?? 'unknown';
const dockerAvailable = current?.docker?.available === true;
const sameHost =
  Boolean(baseline?.host?.label) &&
  Boolean(current?.host?.label) &&
  baseline.host.label === current.host.label;

let classification = 'blocked';
let note = 'Portable runner contract could not be established.';

if (!baseline) {
  classification = 'baseline_missing';
  note =
    'Portable runner observations were captured, but the workstation baseline JSON is missing, so the install delta cannot be confirmed yet.';
} else if (sameHost) {
  classification = 'blocked';
  note =
    'Current host still matches the workstation baseline; provision a separate VM or remote runner before claiming a portable proof.';
} else if (currentShellStatus === 'ready' || dockerAvailable) {
  classification = 'ready';
  note =
    'Separate runner detected with at least one supported self-hosted execution mode.';
} else {
  classification = 'blocked';
  note =
    'Separate runner detected, but it still lacks a supported self-hosted execution mode.';
}

const supportedPortableContract = {
  supported_runner: 'Ubuntu 24.04 Linux VM or remote runner',
  supported_execution_modes: ['direct-host', 'privileged-docker'],
  required_packages: {
    direct_host: [
      'build-essential',
      'ca-certificates',
      'curl',
      'git',
      'iproute2',
      'iputils-ping',
      'libglib2.0-0',
      'make',
      'pkg-config',
      'python3',
      'zerotier-one',
    ],
    privileged_docker_host: [
      'ca-certificates',
      'curl',
      'docker.io (or Docker Engine)',
      'git',
      'zerotier-one',
    ],
  },
  required_binaries: {
    rust_toolchain: rustToolchain,
    shadow: 'Shadow 3.2.x on PATH or via MANYTIER_SHADOW_BIN',
    official_binary_policy:
      'Prefer the installed system zerotier-one when the version is supported; otherwise point MANYTIER_ZEROTIER_ONE_BIN at a repo fixture.',
  },
  required_capabilities: [
    '/dev/net/tun available to the execution context',
    'CAP_NET_ADMIN for direct-host mode or privileged Docker access on the runner',
    'Repo checkout available on the runner',
    'Local UDP/API ports available for the self-hosted fallback harness',
    'Hosted official-network execution remains out of scope for v1.7',
  ],
};

const workstationBaseline = baseline
  ? {
      host_label: baseline.host?.label ?? null,
      host_os: baseline.host?.os ?? null,
      current_shell_status: baseline.current_shell?.status ?? null,
      docker_available: baseline.docker?.available ?? null,
      recommended_environment_shape: baseline.recommendation?.environment_shape ?? null,
      system_official_binary: baseline.system_official_binary ?? null,
      shadow_binary: baseline.shadow_binary ?? null,
      cargo: baseline.cargo ?? null,
    }
  : null;

const observedDifferences = [];
if (baseline) {
  const pairs = [
    [
      'host label',
      baseline.host?.label ?? null,
      current?.host?.label ?? null,
    ],
    [
      'host os',
      baseline.host?.os ?? null,
      current?.host?.os ?? null,
    ],
    [
      'current shell status',
      baseline.current_shell?.status ?? null,
      current?.current_shell?.status ?? null,
    ],
    [
      'docker availability',
      baseline.docker?.available ?? null,
      current?.docker?.available ?? null,
    ],
    [
      'system zerotier-one version',
      baseline.system_official_binary?.version ?? null,
      current?.system_official_binary?.version ?? null,
    ],
    [
      'shadow version',
      baseline.shadow_binary?.version ?? null,
      current?.shadow_binary?.version ?? null,
    ],
    [
      'cargo version',
      baseline.cargo?.version ?? null,
      current?.cargo?.version ?? null,
    ],
  ];

  for (const [label, before, after] of pairs) {
    if (before !== after) {
      observedDifferences.push(
        `${label}: workstation=${before ?? '<missing>'} portable=${after ?? '<missing>'}`
      );
    }
  }
}

const portableRunnerRequiredSoftware = Array.from(
  new Set([
    ...supportedPortableContract.required_packages.direct_host,
    ...supportedPortableContract.required_packages.privileged_docker_host,
    supportedPortableContract.required_binaries.rust_toolchain,
    supportedPortableContract.required_binaries.shadow,
  ])
);

const data = {
  generated_at: process.env.GENERATED_AT,
  artifact_root: process.env.ARTIFACT_ROOT,
  runner_label: runnerLabel,
  classification,
  note,
  supported_portable_contract: supportedPortableContract,
  workstation_baseline: workstationBaseline,
  current_runner: current,
  install_delta_from_workstation: {
    workstation_extra_installs_for_current_lane: [],
    portable_runner_additions_beyond_workstation_lane: [
      'One separate Ubuntu 24.04 VM or remote runner',
      'Non-loopback environment shape for self-hosted proof execution',
      '/dev/net/tun and CAP_NET_ADMIN on that runner',
      'Repo checkout and artifact storage on that runner',
    ],
    portable_runner_required_software: portableRunnerRequiredSoftware,
    observed_differences: observedDifferences,
  },
  inputs: {
    baseline_json: process.env.BASELINE_JSON || null,
    current_runner_json: process.env.CURRENT_JSON,
  },
};

fs.writeFileSync(process.env.OUTPUT_JSON, `${JSON.stringify(data, null, 2)}\n`);
EOF

cat >"$OUTPUT_MD" <<EOF
# Portable Self-Hosted Environment Report

- generated: $GENERATED_AT
- artifact_root: $ARTIFACT_ROOT
- runner_label: $RUNNER_LABEL
- classification: $(sed -n 's/^  "classification": "\(.*\)",$/\1/p' "$OUTPUT_JSON" | head -n 1)
- baseline_json: ${BASELINE_JSON:-<missing>}
- current_runner_json: $CURRENT_JSON

## Supported Portable Contract

- supported_runner: Ubuntu 24.04 Linux VM or remote runner
- supported_execution_modes:
  - direct-host
  - privileged-docker
- direct_host_packages:
  - build-essential
  - ca-certificates
  - curl
  - git
  - iproute2
  - iputils-ping
  - libglib2.0-0
  - make
  - pkg-config
  - python3
  - zerotier-one
- privileged_docker_host_packages:
  - ca-certificates
  - curl
  - docker.io (or Docker Engine)
  - git
  - zerotier-one
- required_binaries:
  - Rust toolchain: $RUST_TOOLCHAIN
  - Shadow: PATH or \`MANYTIER_SHADOW_BIN\`
  - Official binary policy: prefer installed system \`zerotier-one\` when supported, otherwise use a repo fixture
- required_capabilities:
  - /dev/net/tun
  - CAP_NET_ADMIN or privileged Docker access
  - repo checkout on the runner
  - local UDP/API ports available for the fallback harness

## Install Delta From The Current Workstation

- current_docker_lane_extra_installs: none
- portable_runner_additions:
  - one separate Ubuntu 24.04 VM or remote runner
  - a non-loopback environment shape for the self-hosted proof
  - /dev/net/tun and CAP_NET_ADMIN on that runner
  - repo checkout and artifact storage on that runner

## Notes

$(node -e "const fs=require('fs'); const data=JSON.parse(fs.readFileSync(process.argv[1],'utf8')); console.log(data.note);" "$OUTPUT_JSON")

## Nested Runner Read

- report: $CURRENT_PREFLIGHT_ROOT/self-hosted-environment-report.md
- json: $CURRENT_JSON

## Policy Guardrail

Hosted official-network execution remains out of scope for v1.7.
EOF

printf '%s\n' "$OUTPUT_MD"
