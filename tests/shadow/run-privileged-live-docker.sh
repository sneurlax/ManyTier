#!/bin/bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"

# shellcheck source=tests/shadow/validation-paths.sh
source "$ROOT/tests/shadow/validation-paths.sh"

# Run the privileged live lane inside a known-good privileged container.
# This is useful when your current shell (e.g., a devcontainer/distrobox) cannot
# acquire CAP_NET_ADMIN even as root, causing TUNSETIFF EPERM.

IMAGE="${MANYTIER_PRIV_LIVE_IMAGE:-ubuntu:24.04}"
HOST_UID="${HOST_UID:-$(id -u)}"
HOST_GID="${HOST_GID:-$(id -g)}"
TARGET_DIR_REL="$(manytier_validation_repo_relative "${CARGO_TARGET_DIR:-${MANYTIER_VALIDATION_BUILD_ROOT:-target-user}}")"
SCRATCH_ROOT_REL="$(manytier_validation_repo_relative "$(manytier_validation_scratch_root)")"
OFFICIAL_BIN_HOST="$(manytier_validation_default_official_bin)"
OFFICIAL_SOURCE="${MANYTIER_VALIDATION_OFFICIAL_SOURCE:-$(manytier_validation_official_bin_source "$OFFICIAL_BIN_HOST")}"
OFFICIAL_BIN_CONTAINER=""
declare -a OFFICIAL_BIN_MOUNT=()
ARTIFACT_ROOT_REL=""
if [[ -n "${MANYTIER_ARTIFACT_ROOT:-}" ]]; then
  ARTIFACT_ROOT_REL="$(manytier_validation_repo_relative "$MANYTIER_ARTIFACT_ROOT")"
elif [[ -n "${MANYTIER_VALIDATION_ARTIFACT_ROOT:-}" ]]; then
  ARTIFACT_ROOT_REL="$(manytier_validation_repo_relative "$MANYTIER_VALIDATION_ARTIFACT_ROOT")"
fi

if [[ ! -x "$OFFICIAL_BIN_HOST" ]]; then
  echo "Official zerotier-one binary is missing or not executable: $OFFICIAL_BIN_HOST" >&2
  exit 1
fi

if manytier_validation_path_is_repo_local "$OFFICIAL_BIN_HOST"; then
  OFFICIAL_BIN_CONTAINER="$(manytier_validation_repo_relative "$OFFICIAL_BIN_HOST")"
else
  OFFICIAL_BIN_CONTAINER="/opt/manytier-official/zerotier-one"
  OFFICIAL_BIN_MOUNT=(-v "$OFFICIAL_BIN_HOST:$OFFICIAL_BIN_CONTAINER:ro")
fi

if docker run --rm --privileged --user 0:0 --device /dev/net/tun \
  -v "$PWD":/workspace \
  -v /home/user/.cargo:/home/user/.cargo:ro \
  -v /home/user/.rustup:/home/user/.rustup:ro \
  -v /home/user/.local/bin/shadow:/usr/local/bin/shadow:ro \
  "${OFFICIAL_BIN_MOUNT[@]}" \
  -e HOST_UID="$HOST_UID" \
  -e HOST_GID="$HOST_GID" \
  -e MANYTIER_DUMP_UDP="${MANYTIER_DUMP_UDP:-}" \
  -e MANYTIER_ARTIFACT_ROOT="$ARTIFACT_ROOT_REL" \
  -e MANYTIER_ZEROTIER_ONE_BIN="$OFFICIAL_BIN_CONTAINER" \
  -e MANYTIER_VALIDATION_OFFICIAL_HOST_PATH="$OFFICIAL_BIN_HOST" \
  -e MANYTIER_VALIDATION_OFFICIAL_SOURCE="$OFFICIAL_SOURCE" \
  -e MANYTIER_VALIDATION_SCRATCH_ROOT="$SCRATCH_ROOT_REL" \
  -e MANYTIER_VALIDATION_ENVIRONMENT_SHAPE="${MANYTIER_VALIDATION_ENVIRONMENT_SHAPE:-privileged-docker}" \
  -e MANYTIER_VALIDATION_RUNNER_KIND="${MANYTIER_VALIDATION_RUNNER_KIND:-docker}" \
  -e MANYTIER_SKIP_LOCAL_MANIFEST=1 \
  -e MANYTIER_WORKSPACE_ROOT=/workspace \
  -e HOME=/home/user \
  -e RUSTUP_HOME=/home/user/.rustup \
  -e PATH=/home/user/.cargo/bin:/usr/local/bin:/usr/bin:/bin \
  -e CARGO_TARGET_DIR="/workspace/$TARGET_DIR_REL" \
  -w /workspace "$IMAGE" \
  bash -lc 'set -euo pipefail
    export HOME=/home/user \
    RUSTUP_HOME=/home/user/.rustup \
    PATH=/home/user/.cargo/bin:/usr/local/bin:/usr/bin:/bin \
    CARGO_TARGET_DIR=/workspace/'"$TARGET_DIR_REL"' && \
    cleanup() {
      chown -R "$HOST_UID:$HOST_GID" /workspace/tests/shadow/artifacts /workspace/'"$TARGET_DIR_REL"' 2>/dev/null || true
    }
    trap cleanup EXIT
    apt-get update >/dev/null && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
      ca-certificates gcc g++ make pkg-config iproute2 iputils-ping \
      libglib2.0-0 python3 curl >/dev/null && \
    command -v cargo >/dev/null 2>&1 && \
    ./tests/shadow/run-privileged-live.sh'; then
  DOCKER_STATUS=0
else
  DOCKER_STATUS=$?
fi

if [[ -n "$ARTIFACT_ROOT_REL" ]]; then
  if ! MANYTIER_ARTIFACT_ROOT="$ARTIFACT_ROOT_REL" \
       MANYTIER_ZEROTIER_ONE_BIN="$OFFICIAL_BIN_CONTAINER" \
       MANYTIER_VALIDATION_OFFICIAL_HOST_PATH="$OFFICIAL_BIN_HOST" \
       MANYTIER_VALIDATION_OFFICIAL_SOURCE="$OFFICIAL_SOURCE" \
       MANYTIER_VALIDATION_ENVIRONMENT_SHAPE="${MANYTIER_VALIDATION_ENVIRONMENT_SHAPE:-privileged-docker}" \
       MANYTIER_VALIDATION_RUNNER_KIND="${MANYTIER_VALIDATION_RUNNER_KIND:-docker}" \
       ./tests/shadow/write-self-hosted-validation-manifest.sh --artifact-root "$ARTIFACT_ROOT_REL" >/dev/null 2>&1; then
    echo "WARNING: failed to generate self-hosted validation manifest on host" >&2
  fi
fi

exit "$DOCKER_STATUS"
