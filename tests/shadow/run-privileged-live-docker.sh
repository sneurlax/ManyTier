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
ARTIFACT_ROOT_REL=""
if [[ -n "${MANYTIER_ARTIFACT_ROOT:-}" ]]; then
  ARTIFACT_ROOT_REL="$(manytier_validation_repo_relative "$MANYTIER_ARTIFACT_ROOT")"
elif [[ -n "${MANYTIER_VALIDATION_ARTIFACT_ROOT:-}" ]]; then
  ARTIFACT_ROOT_REL="$(manytier_validation_repo_relative "$MANYTIER_VALIDATION_ARTIFACT_ROOT")"
fi
OFFICIAL_BIN_REL="$(manytier_validation_repo_relative "$(manytier_validation_default_official_bin)")"

docker run --rm --privileged --user 0:0 --device /dev/net/tun \
  -v "$PWD":/workspace \
  -v /home/user/.cargo:/home/user/.cargo:ro \
  -v /home/user/.rustup:/home/user/.rustup:ro \
  -v /home/user/.local/bin/shadow:/usr/local/bin/shadow:ro \
  -e HOST_UID="$HOST_UID" \
  -e HOST_GID="$HOST_GID" \
  -e MANYTIER_DUMP_UDP="${MANYTIER_DUMP_UDP:-}" \
  -e MANYTIER_ARTIFACT_ROOT="$ARTIFACT_ROOT_REL" \
  -e MANYTIER_ZEROTIER_ONE_BIN="$OFFICIAL_BIN_REL" \
  -e MANYTIER_VALIDATION_SCRATCH_ROOT="$SCRATCH_ROOT_REL" \
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
    ./tests/shadow/run-privileged-live.sh'
