#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
ARTIFACT_PARENT="$REPO_ROOT/tests/shadow/artifacts"
TIMESTAMP="$(date -u +%Y%m%dT%H%M%SZ)"

ARTIFACT_ROOT="${ARTIFACT_ROOT:-$ARTIFACT_PARENT/run-${TIMESTAMP}-hosted-official-validation}"
NETWORK_ID="${MANYTIER_HOSTED_NETWORK_ID:-}"
API_PORT="${MANYTIER_HOSTED_API_PORT:-19093}"
UDP_PORT="${MANYTIER_HOSTED_UDP_PORT:-19993}"
TIMEOUT_SECONDS="${MANYTIER_HOSTED_TIMEOUT_SECONDS:-90}"
TARGET_DIR="${CARGO_TARGET_DIR:-$REPO_ROOT/target-user}"
BINARY="$TARGET_DIR/debug/manytier"
DATA_DIR="$ARTIFACT_ROOT/manytier-data"

AUTHORIZATION_CHECKPOINT="${MANYTIER_HOSTED_AUTHORIZATION_CHECKPOINT:-off}"
AUTHORIZATION_WAIT_SECONDS="${MANYTIER_HOSTED_AUTHORIZATION_WAIT_SECONDS:-300}"
RUN_OFFICIAL_CONTROL="${MANYTIER_HOSTED_RUN_OFFICIAL_CONTROL:-on-failure}"
OFFICIAL_BIN="${MANYTIER_HOSTED_OFFICIAL_BIN:-$REPO_ROOT/tests/fixtures/zerotier-one}"
OFFICIAL_PORT="${MANYTIER_HOSTED_OFFICIAL_PORT:-19094}"

ROOT_LOG="$ARTIFACT_ROOT/01-root-hello.log"
BUILD_LOG="$ARTIFACT_ROOT/00-build.log"
SERVICE_STDOUT="$ARTIFACT_ROOT/02-service.stdout"
SERVICE_STDERR="$ARTIFACT_ROOT/03-service.stderr"
JOIN_LOG="$ARTIFACT_ROOT/04-join.log"
NETWORKS_JSON="$ARTIFACT_ROOT/05-networks.json"
LISTNETWORKS_LOG="$ARTIFACT_ROOT/06-listnetworks.log"
STATUS_PREJOIN_LOG="$ARTIFACT_ROOT/07-status-pre-join.log"
PEERS_PREJOIN_LOG="$ARTIFACT_ROOT/08-peers-pre-join.log"
STATUS_PREJOIN_JSON="$ARTIFACT_ROOT/09-status-pre-join.json"
PEER_PREJOIN_JSON="$ARTIFACT_ROOT/10-peer-pre-join.json"
STATUS_POSTJOIN_LOG="$ARTIFACT_ROOT/11-status-post-join.log"
PEERS_POSTJOIN_LOG="$ARTIFACT_ROOT/12-peers-post-join.log"
STATUS_POSTJOIN_JSON="$ARTIFACT_ROOT/13-status-post-join.json"
PEER_POSTJOIN_JSON="$ARTIFACT_ROOT/14-peer-post-join.json"
STATUS_POSTAUTH_LOG="$ARTIFACT_ROOT/15-status-post-auth.log"
PEERS_POSTAUTH_LOG="$ARTIFACT_ROOT/16-peers-post-auth.log"
STATUS_POSTAUTH_JSON="$ARTIFACT_ROOT/17-status-post-auth.json"
PEER_POSTAUTH_JSON="$ARTIFACT_ROOT/18-peer-post-auth.json"
AUTH_CHECKPOINT_PATH="$ARTIFACT_ROOT/authorization-checkpoint.md"
AUTH_APPROVED_FLAG="$ARTIFACT_ROOT/authorization-approved.flag"

OFFICIAL_CONTROL_DIR="$ARTIFACT_ROOT/official-control"
OFFICIAL_CONTROL_HOME="$OFFICIAL_CONTROL_DIR/home"
OFFICIAL_CONTROL_STDOUT="$OFFICIAL_CONTROL_DIR/01-official.stdout"
OFFICIAL_CONTROL_STDERR="$OFFICIAL_CONTROL_DIR/02-official.stderr"
OFFICIAL_CONTROL_INFO="$OFFICIAL_CONTROL_DIR/03-info.txt"
OFFICIAL_CONTROL_PEERS="$OFFICIAL_CONTROL_DIR/04-peers.txt"
OFFICIAL_CONTROL_JOIN="$OFFICIAL_CONTROL_DIR/05-join.txt"
OFFICIAL_CONTROL_LISTNETWORKS="$OFFICIAL_CONTROL_DIR/06-listnetworks.txt"

REPORT_PATH="$ARTIFACT_ROOT/hosted-validation-report.md"
BLOCKER_PATH="$ARTIFACT_ROOT/hosted-validation-blocker.md"
METADATA_PATH="$ARTIFACT_ROOT/metadata.txt"

SERVICE_PID=""
OFFICIAL_PID=""
AUTHORIZATION_RESULT="not_requested"
OFFICIAL_CONTROL_RESULT="not_run"
OFFICIAL_CONTROL_NETWORK_PRESENT="unknown"
OFFICIAL_CONTROL_ASSIGNED_ADDRESSES="unknown"
NODE_ADDRESS=""

cleanup() {
  if [[ -n "$SERVICE_PID" ]] && kill -0 "$SERVICE_PID" >/dev/null 2>&1; then
    kill "$SERVICE_PID" >/dev/null 2>&1 || true
    wait "$SERVICE_PID" >/dev/null 2>&1 || true
  fi
  if [[ -n "$OFFICIAL_PID" ]] && kill -0 "$OFFICIAL_PID" >/dev/null 2>&1; then
    kill "$OFFICIAL_PID" >/dev/null 2>&1 || true
    wait "$OFFICIAL_PID" >/dev/null 2>&1 || true
  fi
}

api_get() {
  local endpoint="$1"
  local output="$2"
  curl -fsS \
    -H "X-ZT1-Auth: $AUTH_TOKEN" \
    "http://127.0.0.1:$API_PORT${endpoint}" \
    >"$output" 2>/dev/null || true
}

capture_manytier_state() {
  local status_log="$1"
  local peers_log="$2"
  local status_json="$3"
  local peer_json="$4"

  "$BINARY" --auth-token "$AUTH_TOKEN" --port "$API_PORT" status >"$status_log" 2>&1 || true
  "$BINARY" --auth-token "$AUTH_TOKEN" --port "$API_PORT" peers >"$peers_log" 2>&1 || true
  api_get "/status" "$status_json"
  api_get "/peer" "$peer_json"
}

extract_node_address() {
  local status_json="$1"
  local status_log="$2"

  if command -v jq >/dev/null 2>&1 && [[ -s "$status_json" ]]; then
    jq -r '.address // empty' "$status_json" 2>/dev/null || true
    return
  fi

  sed -n 's/^200 info //p' "$status_log" 2>/dev/null | head -1 || true
}

write_blocker() {
  local reason="$1"
  cat >"$BLOCKER_PATH" <<EOF
# Hosted Validation Blocker

- artifact_root: $ARTIFACT_ROOT
- root_preflight_log: $ROOT_LOG
- service_stdout: $SERVICE_STDOUT
- service_stderr: $SERVICE_STDERR
- join_log: $JOIN_LOG
- networks_json: $NETWORKS_JSON
- listnetworks_log: $LISTNETWORKS_LOG
- authorization_checkpoint: $AUTH_CHECKPOINT_PATH
- authorization_approved_flag: $AUTH_APPROVED_FLAG
- official_control_dir: $OFFICIAL_CONTROL_DIR

## Blocker

$reason

## Current Read

- Official-root HELLO preflight was attempted before the hosted join path.
- ManyTier status and peer snapshots were preserved before join, after join, and after any authorization wait.
- Authorization checkpoint mode: $AUTHORIZATION_CHECKPOINT ($AUTHORIZATION_RESULT)
- Official control sample: $OFFICIAL_CONTROL_RESULT
- Official control network presence: $OFFICIAL_CONTROL_NETWORK_PRESENT
- Official control assigned addresses: $OFFICIAL_CONTROL_ASSIGNED_ADDRESSES
- Resume with:

\`\`\`bash
MANYTIER_HOSTED_NETWORK_ID=<16-hex-network-id> \\
MANYTIER_HOSTED_AUTHORIZATION_CHECKPOINT=manual \\
MANYTIER_HOSTED_RUN_OFFICIAL_CONTROL=on-failure \\
./tests/shadow/run-hosted-official-validation.sh
\`\`\`
EOF
}

write_authorization_checkpoint() {
  cat >"$AUTH_CHECKPOINT_PATH" <<EOF
# Hosted Authorization Checkpoint

- artifact_root: $ARTIFACT_ROOT
- network_id: $NETWORK_ID
- node_address: ${NODE_ADDRESS:-unknown}
- approval_flag: $AUTH_APPROVED_FLAG

## Action Required

Authorize the pending ManyTier member for the hosted network, then resume the same run.

If this shell is interactive, press Enter after authorization is complete.
If this shell is non-interactive, signal approval with:

\`\`\`bash
touch "$AUTH_APPROVED_FLAG"
\`\`\`

## Evidence Available

- pre-join status: $STATUS_PREJOIN_LOG
- pre-join peers: $PEERS_PREJOIN_LOG
- post-join status: $STATUS_POSTJOIN_LOG
- post-join peers: $PEERS_POSTJOIN_LOG
- join log: $JOIN_LOG
EOF
}

wait_for_authorization() {
  if [[ "$AUTHORIZATION_CHECKPOINT" != "manual" ]]; then
    AUTHORIZATION_RESULT="not_requested"
    return 0
  fi

  write_authorization_checkpoint

  if [[ "$AUTHORIZATION_WAIT_SECONDS" == "0" ]]; then
    AUTHORIZATION_RESULT="checkpoint_written_only"
    return 0
  fi

  if [[ -t 0 && -t 1 ]]; then
    printf 'Hosted authorization checkpoint written to %s\n' "$AUTH_CHECKPOINT_PATH"
    printf 'Authorize node %s for network %s, then press Enter to continue.\n' \
      "${NODE_ADDRESS:-unknown}" "$NETWORK_ID"
    read -r _
    AUTHORIZATION_RESULT="interactive_ack"
    return 0
  fi

  local deadline=$((SECONDS + AUTHORIZATION_WAIT_SECONDS))
  while (( SECONDS < deadline )); do
    if [[ -f "$AUTH_APPROVED_FLAG" ]]; then
      AUTHORIZATION_RESULT="approval_flag_observed"
      return 0
    fi
    sleep 2
  done

  AUTHORIZATION_RESULT="timed_out_waiting_for_authorization"
  return 0
}

run_official_control_sample() {
  if [[ "$RUN_OFFICIAL_CONTROL" == "never" ]]; then
    OFFICIAL_CONTROL_RESULT="skipped_by_config"
    return 0
  fi

  if [[ ! -x "$OFFICIAL_BIN" ]]; then
    OFFICIAL_CONTROL_RESULT="official_binary_missing"
    return 0
  fi

  mkdir -p "$OFFICIAL_CONTROL_DIR" "$OFFICIAL_CONTROL_HOME"

  "$OFFICIAL_BIN" -U -p"$OFFICIAL_PORT" "$OFFICIAL_CONTROL_HOME" \
    >"$OFFICIAL_CONTROL_STDOUT" 2>"$OFFICIAL_CONTROL_STDERR" &
  OFFICIAL_PID="$!"

  sleep 10

  "$OFFICIAL_BIN" -q -D"$OFFICIAL_CONTROL_HOME" -p"$OFFICIAL_PORT" info \
    >"$OFFICIAL_CONTROL_INFO" 2>&1 || true
  "$OFFICIAL_BIN" -q -D"$OFFICIAL_CONTROL_HOME" -p"$OFFICIAL_PORT" peers \
    >"$OFFICIAL_CONTROL_PEERS" 2>&1 || true
  "$OFFICIAL_BIN" -q -D"$OFFICIAL_CONTROL_HOME" -p"$OFFICIAL_PORT" join "$NETWORK_ID" \
    >"$OFFICIAL_CONTROL_JOIN" 2>&1 || true
  sleep 5
  "$OFFICIAL_BIN" -q -D"$OFFICIAL_CONTROL_HOME" -p"$OFFICIAL_PORT" listnetworks \
    >"$OFFICIAL_CONTROL_LISTNETWORKS" 2>&1 || true

  if grep -Fq "$NETWORK_ID" "$OFFICIAL_CONTROL_LISTNETWORKS" 2>/dev/null; then
    OFFICIAL_CONTROL_NETWORK_PRESENT="yes"
  else
    OFFICIAL_CONTROL_NETWORK_PRESENT="no"
  fi

  if grep -Eq '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+/[0-9]+' "$OFFICIAL_CONTROL_LISTNETWORKS" 2>/dev/null; then
    OFFICIAL_CONTROL_ASSIGNED_ADDRESSES="present"
  else
    OFFICIAL_CONTROL_ASSIGNED_ADDRESSES="absent"
  fi

  OFFICIAL_CONTROL_RESULT="captured"

  if [[ -n "$OFFICIAL_PID" ]] && kill -0 "$OFFICIAL_PID" >/dev/null 2>&1; then
    kill "$OFFICIAL_PID" >/dev/null 2>&1 || true
    wait "$OFFICIAL_PID" >/dev/null 2>&1 || true
  fi
  OFFICIAL_PID=""
}

trap cleanup EXIT

mkdir -p "$ARTIFACT_ROOT" "$DATA_DIR"

cat >"$METADATA_PATH" <<EOF
artifact_root=$ARTIFACT_ROOT
repo_root=$REPO_ROOT
network_id=${NETWORK_ID:-<unset>}
api_port=$API_PORT
udp_port=$UDP_PORT
timeout_seconds=$TIMEOUT_SECONDS
target_dir=$TARGET_DIR
authorization_checkpoint=$AUTHORIZATION_CHECKPOINT
authorization_wait_seconds=$AUTHORIZATION_WAIT_SECONDS
run_official_control=$RUN_OFFICIAL_CONTROL
official_bin=$OFFICIAL_BIN
official_port=$OFFICIAL_PORT
EOF

(
  cd "$REPO_ROOT"
  CARGO_TARGET_DIR="$TARGET_DIR" cargo build -p zerotier-cli --bin manytier
) >"$BUILD_LOG" 2>&1

(
  cd "$REPO_ROOT"
  cargo test -p zerotier-node --test official_root -- \
    --ignored --exact test_official_root_hello_exchange --nocapture
) >"$ROOT_LOG" 2>&1 || {
  write_blocker "official-root preflight failed; this shell still cannot prove hosted validation prerequisites"
  exit 1
}

if [[ -z "$NETWORK_ID" ]]; then
  write_blocker "missing hosted network ID / authorization path"
  exit 2
fi

"$BINARY" service \
  --data-dir "$DATA_DIR" \
  --api-port "$API_PORT" \
  --udp-port "$UDP_PORT" \
  >"$SERVICE_STDOUT" 2>"$SERVICE_STDERR" &
SERVICE_PID="$!"

TOKEN_PATH="$DATA_DIR/authtoken.secret"
for _ in $(seq 1 30); do
  if [[ -f "$TOKEN_PATH" ]]; then
    break
  fi
  sleep 1
done

if [[ ! -f "$TOKEN_PATH" ]]; then
  write_blocker "manytier service did not create authtoken.secret within 30 seconds"
  exit 3
fi

AUTH_TOKEN="$(tr -d '\r\n' < "$TOKEN_PATH")"

capture_manytier_state \
  "$STATUS_PREJOIN_LOG" \
  "$PEERS_PREJOIN_LOG" \
  "$STATUS_PREJOIN_JSON" \
  "$PEER_PREJOIN_JSON"

"$BINARY" --auth-token "$AUTH_TOKEN" --port "$API_PORT" join "$NETWORK_ID" \
  >"$JOIN_LOG" 2>&1 || true

capture_manytier_state \
  "$STATUS_POSTJOIN_LOG" \
  "$PEERS_POSTJOIN_LOG" \
  "$STATUS_POSTJOIN_JSON" \
  "$PEER_POSTJOIN_JSON"

NODE_ADDRESS="$(extract_node_address "$STATUS_POSTJOIN_JSON" "$STATUS_POSTJOIN_LOG")"

wait_for_authorization

capture_manytier_state \
  "$STATUS_POSTAUTH_LOG" \
  "$PEERS_POSTAUTH_LOG" \
  "$STATUS_POSTAUTH_JSON" \
  "$PEER_POSTAUTH_JSON"

ASSIGNED_ADDRESSES=""
DEADLINE=$((SECONDS + TIMEOUT_SECONDS))

while (( SECONDS < DEADLINE )); do
  api_get "/network" "$NETWORKS_JSON"

  "$BINARY" --auth-token "$AUTH_TOKEN" --port "$API_PORT" listnetworks \
    >"$LISTNETWORKS_LOG" 2>&1 || true

  if command -v jq >/dev/null 2>&1 && [[ -s "$NETWORKS_JSON" ]]; then
    ASSIGNED_ADDRESSES="$(jq -r \
      --arg nwid "$NETWORK_ID" \
      'map(select(.id == $nwid)) | first | .assignedAddresses // [] | join(",")' \
      "$NETWORKS_JSON" 2>/dev/null || true)"
  elif [[ -s "$NETWORKS_JSON" ]] && grep -Eq '"assignedAddresses"[[:space:]]*:[[:space:]]*\[[[:space:]]*"[^"]+' "$NETWORKS_JSON"; then
    ASSIGNED_ADDRESSES="present"
  fi

  if [[ -n "$ASSIGNED_ADDRESSES" ]] && [[ "$ASSIGNED_ADDRESSES" != "null" ]]; then
    break
  fi

  sleep 2
done

if [[ -n "$ASSIGNED_ADDRESSES" ]] && [[ "$ASSIGNED_ADDRESSES" != "null" ]]; then
  if [[ "$RUN_OFFICIAL_CONTROL" == "always" ]]; then
    run_official_control_sample
  fi

  cat >"$REPORT_PATH" <<EOF
# Hosted Validation Report

- artifact_root: $ARTIFACT_ROOT
- network_id: $NETWORK_ID
- api_port: $API_PORT
- udp_port: $UDP_PORT
- assigned_addresses: $ASSIGNED_ADDRESSES
- authorization_checkpoint: $AUTHORIZATION_CHECKPOINT ($AUTHORIZATION_RESULT)
- official_control: $OFFICIAL_CONTROL_RESULT

## Result

Hosted validation reached assigned-config evidence.

## Evidence

- root_preflight_log: $ROOT_LOG
- join_log: $JOIN_LOG
- networks_json: $NETWORKS_JSON
- listnetworks_log: $LISTNETWORKS_LOG
- service_stdout: $SERVICE_STDOUT
- service_stderr: $SERVICE_STDERR
- pre_join_status: $STATUS_PREJOIN_LOG
- post_join_status: $STATUS_POSTJOIN_LOG
- post_auth_status: $STATUS_POSTAUTH_LOG
- official_control_dir: $OFFICIAL_CONTROL_DIR
EOF
  exit 0
fi

if [[ "$RUN_OFFICIAL_CONTROL" == "always" || "$RUN_OFFICIAL_CONTROL" == "on-failure" ]]; then
  run_official_control_sample
fi

if grep -Eq 'failed to create TUN device|Operation not permitted' "$SERVICE_STDERR"; then
  write_blocker "hosted join did not reach assigned config before timeout; TUN creation also failed in this shell, but root preflight passed"
elif [[ "$AUTHORIZATION_RESULT" == "timed_out_waiting_for_authorization" ]]; then
  write_blocker "hosted join did not reach assigned config before timeout; manual authorization checkpoint was issued but not confirmed during this run"
elif [[ "$AUTHORIZATION_CHECKPOINT" == "manual" ]]; then
  write_blocker "hosted join did not reach assigned config before timeout; inspect authorization checkpoint, ManyTier snapshots, and official control artifacts before classifying a hosted-only blocker"
else
  write_blocker "hosted join did not reach assigned config before timeout; inspect ManyTier snapshots and official control artifacts for a hosted-only blocker"
fi

exit 4
