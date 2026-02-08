#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"

# shellcheck source=tests/shadow/validation-paths.sh
source "$ROOT/tests/shadow/validation-paths.sh"

ARTIFACT_ROOT="${MANYTIER_ARTIFACT_ROOT:-}"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --artifact-root)
      ARTIFACT_ROOT="$2"
      shift 2
      ;;
    *)
      echo "Unknown argument: $1" >&2
      exit 1
      ;;
  esac
done

if [[ -z "$ARTIFACT_ROOT" ]]; then
  echo "--artifact-root is required" >&2
  exit 1
fi

ARTIFACT_ROOT="$(manytier_validation_resolve_path "$ARTIFACT_ROOT")"
OUTPUT_JSON="$ARTIFACT_ROOT/self-hosted-validation-manifest.json"
OUTPUT_MD="$ARTIFACT_ROOT/self-hosted-validation-manifest.md"
RUN_LOG="$ARTIFACT_ROOT/run.log"
PROBE_LOG="$ARTIFACT_ROOT/probe.log"
HOST_ASSISTED_ROOT="$ARTIFACT_ROOT/host-assisted-fallback"
GENERATED_AT="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
HOST_LABEL="$(manytier_validation_host_label)"
HOST_OS="$(manytier_validation_os_pretty_name)"

read_report_field() {
  local path="$1"
  local field="$2"
  if [[ ! -f "$path" ]]; then
    return 0
  fi
  sed -n "s/^${field}: //p" "$path" | head -n 1
}

read_identity() {
  local path="$1"
  if [[ -f "$path" ]]; then
    head -n 1 "$path" | tr -d '\r'
  fi
}

read_args_port() {
  local path="$1"
  local flag="$2"
  if [[ ! -f "$path" ]]; then
    return 0
  fi
  sed -n "s/^args: .*${flag} \\([0-9][0-9]*\\).*$/\\1/p" "$path" | head -n 1
}

read_official_udp_port() {
  local path="$1"
  if [[ ! -f "$path" ]]; then
    return 0
  fi
  sed -n 's/.*"primaryPort":\([0-9][0-9]*\).*/\1/p' "$path" | head -n 1
}

read_file_value() {
  local path="$1"
  if [[ -f "$path" ]]; then
    tr -d '\r\n' <"$path"
  fi
}

read_probe_status() {
  if [[ ! -f "$PROBE_LOG" ]]; then
    printf 'missing\n'
  elif grep -q '^\[FAIL\]' "$PROBE_LOG"; then
    printf 'failed\n'
  else
    printf 'passed\n'
  fi
}

read_probe_note() {
  if [[ ! -f "$PROBE_LOG" ]]; then
    printf 'probe log missing\n'
    return
  fi
  if grep -q '^\[FAIL\]' "$PROBE_LOG"; then
    grep '^\[FAIL\]' "$PROBE_LOG" | head -n 1 | sed 's/^[[:space:]]*//'
  else
    printf 'environment probe passed\n'
  fi
}

read_runlog_field() {
  local field="$1"
  if [[ ! -f "$RUN_LOG" ]]; then
    return 0
  fi
  sed -n "s/^${field}=//p" "$RUN_LOG" | head -n 1
}

OFFICIAL_BIN_RUNTIME="${MANYTIER_ZEROTIER_ONE_BIN:-$(manytier_validation_default_official_bin)}"
OFFICIAL_BIN_HOST="${MANYTIER_VALIDATION_OFFICIAL_HOST_PATH:-$OFFICIAL_BIN_RUNTIME}"
OFFICIAL_SOURCE="${MANYTIER_VALIDATION_OFFICIAL_SOURCE:-$(manytier_validation_official_bin_source "$OFFICIAL_BIN_HOST")}"
OFFICIAL_VERSION="$(read_runlog_field "official_bin_version")"
if [[ -z "$OFFICIAL_VERSION" ]]; then
  OFFICIAL_VERSION="$(manytier_validation_official_bin_version "$OFFICIAL_BIN_HOST")"
fi
OFFICIAL_SUPPORTED="false"
if manytier_validation_official_version_supported "$OFFICIAL_VERSION"; then
  OFFICIAL_SUPPORTED="true"
fi

ENVIRONMENT_SHAPE="${MANYTIER_VALIDATION_ENVIRONMENT_SHAPE:-unknown}"
RUNNER_KIND="${MANYTIER_VALIDATION_RUNNER_KIND:-unknown}"
SHADOW_BIN="$(manytier_validation_shadow_bin)"
SHADOW_VERSION="$(manytier_validation_shadow_version "$SHADOW_BIN")"
PORTABLE_PREFLIGHT_JSON="${MANYTIER_PORTABLE_PREFLIGHT_REPORT_JSON:-}"
PORTABLE_PREFLIGHT_MD="${MANYTIER_PORTABLE_PREFLIGHT_REPORT_MD:-}"
if [[ -z "$PORTABLE_PREFLIGHT_MD" && -n "$PORTABLE_PREFLIGHT_JSON" ]]; then
  PORTABLE_PREFLIGHT_MD="${PORTABLE_PREFLIGHT_JSON%.json}.md"
fi
POLICY_NOTE="Hosted official-network execution remains deferred for v1.7."

M2O_REPORT="$ARTIFACT_ROOT/tool-parity-manytier-client-official-controller.md"
O2M_REPORT="$ARTIFACT_ROOT/tool-parity-official-client-manytier-controller.md"

M2O_STATUS="$(read_report_field "$M2O_REPORT" "overall_result")"
M2O_NETWORK_ID="$(read_report_field "$M2O_REPORT" "network_id")"
M2O_ASSIGNED_IPV4="$(read_report_field "$M2O_REPORT" "assigned_ipv4")"
M2O_CLIENT_IDENTITY="$(read_identity "$HOST_ASSISTED_ROOT/manytier-client/manytier-data/identity.public")"
M2O_CLIENT_API_PORT="$(read_args_port "$HOST_ASSISTED_ROOT/manytier-client/evidence.txt" "--api-port")"
M2O_CLIENT_UDP_PORT="$(read_args_port "$HOST_ASSISTED_ROOT/manytier-client/evidence.txt" "--udp-port")"
M2O_CONTROLLER_IDENTITY="$(read_identity "$HOST_ASSISTED_ROOT/official-zerotier-one-controller/zerotier-one-home/identity.public")"
M2O_CONTROLLER_API_PORT="$(read_file_value "$HOST_ASSISTED_ROOT/official-zerotier-one-controller/zerotier-one-home/zerotier-one.port")"
M2O_CONTROLLER_UDP_PORT="$(read_official_udp_port "$HOST_ASSISTED_ROOT/official-zerotier-one-controller/zerotier-one-home/local.conf")"

O2M_STATUS="$(read_report_field "$O2M_REPORT" "overall_result")"
O2M_NETWORK_ID="$(read_report_field "$O2M_REPORT" "network_id")"
O2M_ASSIGNED_IPV4="$(read_report_field "$O2M_REPORT" "assigned_ipv4")"
O2M_CLIENT_IDENTITY="$(read_identity "$HOST_ASSISTED_ROOT/official-zerotier-one-client/zerotier-one-home/identity.public")"
O2M_CLIENT_API_PORT="$(read_file_value "$HOST_ASSISTED_ROOT/official-zerotier-one-client/zerotier-one-home/zerotier-one.port")"
O2M_CLIENT_UDP_PORT="$(read_official_udp_port "$HOST_ASSISTED_ROOT/official-zerotier-one-client/zerotier-one-home/local.conf")"
O2M_CONTROLLER_IDENTITY="$(read_identity "$HOST_ASSISTED_ROOT/manytier-controller/manytier-data/identity.public")"
O2M_CONTROLLER_API_PORT="$(read_args_port "$HOST_ASSISTED_ROOT/manytier-controller/evidence.txt" "--api-port")"
O2M_CONTROLLER_UDP_PORT="$(read_args_port "$HOST_ASSISTED_ROOT/manytier-controller/evidence.txt" "--udp-port")"

export OUTPUT_JSON GENERATED_AT ARTIFACT_ROOT ENVIRONMENT_SHAPE RUNNER_KIND POLICY_NOTE
export HOST_LABEL HOST_OS SHADOW_BIN SHADOW_VERSION PORTABLE_PREFLIGHT_JSON PORTABLE_PREFLIGHT_MD
export OFFICIAL_BIN_RUNTIME OFFICIAL_BIN_HOST OFFICIAL_SOURCE OFFICIAL_VERSION OFFICIAL_SUPPORTED
export PROBE_STATUS="$(read_probe_status)"
export PROBE_NOTE="$(read_probe_note)"
export M2O_REPORT O2M_REPORT
export M2O_STATUS M2O_NETWORK_ID M2O_ASSIGNED_IPV4 M2O_CLIENT_IDENTITY M2O_CLIENT_API_PORT
export M2O_CLIENT_UDP_PORT M2O_CONTROLLER_IDENTITY M2O_CONTROLLER_API_PORT M2O_CONTROLLER_UDP_PORT
export O2M_STATUS O2M_NETWORK_ID O2M_ASSIGNED_IPV4 O2M_CLIENT_IDENTITY O2M_CLIENT_API_PORT
export O2M_CLIENT_UDP_PORT O2M_CONTROLLER_IDENTITY O2M_CONTROLLER_API_PORT O2M_CONTROLLER_UDP_PORT

node <<'EOF'
const fs = require('fs');

const maybe = (value) => {
  if (!value) return null;
  const trimmed = value.trim();
  return trimmed === '' ? null : trimmed;
};

const readJsonIfPresent = (filePath) => {
  const resolved = maybe(filePath);
  if (!resolved) return null;
  if (!fs.existsSync(resolved)) return null;
  return JSON.parse(fs.readFileSync(resolved, 'utf8'));
};

const portablePreflight = readJsonIfPresent(process.env.PORTABLE_PREFLIGHT_JSON);

const data = {
  generated_at: process.env.GENERATED_AT,
  artifact_root: process.env.ARTIFACT_ROOT,
  host: {
    label: process.env.HOST_LABEL,
    os: process.env.HOST_OS,
  },
  environment_shape: process.env.ENVIRONMENT_SHAPE,
  runner_kind: process.env.RUNNER_KIND,
  probe: {
    status: process.env.PROBE_STATUS,
    note: process.env.PROBE_NOTE,
  },
  official_binary: {
    runtime_path: process.env.OFFICIAL_BIN_RUNTIME,
    host_path: process.env.OFFICIAL_BIN_HOST,
    source: process.env.OFFICIAL_SOURCE,
    version: process.env.OFFICIAL_VERSION,
    supported: process.env.OFFICIAL_SUPPORTED === 'true',
  },
  shadow_binary: {
    path: maybe(process.env.SHADOW_BIN),
    version: maybe(process.env.SHADOW_VERSION),
  },
  hosted_policy: process.env.POLICY_NOTE,
  portable_environment: portablePreflight
    ? {
        report_json: maybe(process.env.PORTABLE_PREFLIGHT_JSON),
        report_md: maybe(process.env.PORTABLE_PREFLIGHT_MD),
        runner_label: portablePreflight.runner_label ?? null,
        classification: portablePreflight.classification ?? null,
        note: portablePreflight.note ?? null,
        install_delta_from_workstation: portablePreflight.install_delta_from_workstation ?? null,
      }
    : null,
  directions: {
    manytier_client_official_controller: {
      status: maybe(process.env.M2O_STATUS),
      network_id: maybe(process.env.M2O_NETWORK_ID),
      assigned_ipv4: maybe(process.env.M2O_ASSIGNED_IPV4),
      report: maybe(process.env.M2O_REPORT),
      manytier_client: {
        identity: maybe(process.env.M2O_CLIENT_IDENTITY),
        api_port: maybe(process.env.M2O_CLIENT_API_PORT),
        udp_port: maybe(process.env.M2O_CLIENT_UDP_PORT),
      },
      official_controller: {
        identity: maybe(process.env.M2O_CONTROLLER_IDENTITY),
        api_port: maybe(process.env.M2O_CONTROLLER_API_PORT),
        udp_port: maybe(process.env.M2O_CONTROLLER_UDP_PORT),
      },
    },
    official_client_manytier_controller: {
      status: maybe(process.env.O2M_STATUS),
      network_id: maybe(process.env.O2M_NETWORK_ID),
      assigned_ipv4: maybe(process.env.O2M_ASSIGNED_IPV4),
      report: maybe(process.env.O2M_REPORT),
      official_client: {
        identity: maybe(process.env.O2M_CLIENT_IDENTITY),
        api_port: maybe(process.env.O2M_CLIENT_API_PORT),
        udp_port: maybe(process.env.O2M_CLIENT_UDP_PORT),
      },
      manytier_controller: {
        identity: maybe(process.env.O2M_CONTROLLER_IDENTITY),
        api_port: maybe(process.env.O2M_CONTROLLER_API_PORT),
        udp_port: maybe(process.env.O2M_CONTROLLER_UDP_PORT),
      },
    },
  },
};

fs.writeFileSync(process.env.OUTPUT_JSON, `${JSON.stringify(data, null, 2)}\n`);
EOF

cat >"$OUTPUT_MD" <<EOF
# Self-Hosted Validation Manifest

- generated: $GENERATED_AT
- artifact_root: $ARTIFACT_ROOT
- host_label: $HOST_LABEL
- host_os: $HOST_OS
- environment_shape: $ENVIRONMENT_SHAPE
- runner_kind: $RUNNER_KIND
- probe_status: $(read_probe_status)
- probe_note: $(read_probe_note)
- official_binary_runtime_path: $OFFICIAL_BIN_RUNTIME
- official_binary_host_path: $OFFICIAL_BIN_HOST
- official_binary_source: $OFFICIAL_SOURCE
- official_binary_version: $OFFICIAL_VERSION
- official_binary_supported: $OFFICIAL_SUPPORTED
- shadow_binary_path: ${SHADOW_BIN:-<missing>}
- shadow_binary_version: $SHADOW_VERSION
- portable_environment_report_json: ${PORTABLE_PREFLIGHT_JSON:-<missing>}
- portable_environment_report_md: ${PORTABLE_PREFLIGHT_MD:-<missing>}
- hosted_policy: $POLICY_NOTE

## ManyTier Client -> Official Controller

- status: ${M2O_STATUS:-<missing>}
- network_id: ${M2O_NETWORK_ID:-<missing>}
- assigned_ipv4: ${M2O_ASSIGNED_IPV4:-<missing>}
- report: $M2O_REPORT
- manytier_client_identity: ${M2O_CLIENT_IDENTITY:-<missing>}
- manytier_client_api_port: ${M2O_CLIENT_API_PORT:-<missing>}
- manytier_client_udp_port: ${M2O_CLIENT_UDP_PORT:-<missing>}
- official_controller_identity: ${M2O_CONTROLLER_IDENTITY:-<missing>}
- official_controller_api_port: ${M2O_CONTROLLER_API_PORT:-<missing>}
- official_controller_udp_port: ${M2O_CONTROLLER_UDP_PORT:-<missing>}

## Official Client -> ManyTier Controller

- status: ${O2M_STATUS:-<missing>}
- network_id: ${O2M_NETWORK_ID:-<missing>}
- assigned_ipv4: ${O2M_ASSIGNED_IPV4:-<missing>}
- report: $O2M_REPORT
- official_client_identity: ${O2M_CLIENT_IDENTITY:-<missing>}
- official_client_api_port: ${O2M_CLIENT_API_PORT:-<missing>}
- official_client_udp_port: ${O2M_CLIENT_UDP_PORT:-<missing>}
- manytier_controller_identity: ${O2M_CONTROLLER_IDENTITY:-<missing>}
- manytier_controller_api_port: ${O2M_CONTROLLER_API_PORT:-<missing>}
- manytier_controller_udp_port: ${O2M_CONTROLLER_UDP_PORT:-<missing>}
EOF

printf '%s\n' "$OUTPUT_MD"
