#!/bin/bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"

# Run the privileged live lane inside a known-good privileged container.
# This is useful when your current shell (e.g., a devcontainer/distrobox) cannot
# acquire CAP_NET_ADMIN even as root, causing TUNSETIFF EPERM.

IMAGE="${MANYTIER_PRIV_LIVE_IMAGE:-ubuntu:24.04}"
HOST_UID="${HOST_UID:-$(id -u)}"
HOST_GID="${HOST_GID:-$(id -g)}"

docker run --rm --privileged --user 0:0 --device /dev/net/tun \
  -v "$PWD":/workspace \
  -v /home/user/.cargo:/home/user/.cargo:ro \
  -v /home/user/.rustup:/home/user/.rustup:ro \
  -v /home/user/.local/bin/shadow:/usr/local/bin/shadow:ro \
  -e HOST_UID="$HOST_UID" \
  -e HOST_GID="$HOST_GID" \
  -e MANYTIER_DUMP_UDP="${MANYTIER_DUMP_UDP:-}" \
  -e MANYTIER_ARTIFACT_ROOT="${MANYTIER_ARTIFACT_ROOT:-}" \
  -e MANYTIER_ZEROTIER_ONE_BIN="${MANYTIER_ZEROTIER_ONE_BIN:-}" \
  -e HOME=/home/user \
  -e RUSTUP_HOME=/home/user/.rustup \
  -e PATH=/home/user/.cargo/bin:/usr/local/bin:/usr/bin:/bin \
  -e CARGO_TARGET_DIR=/workspace/target \
  -w /workspace "$IMAGE" \
  bash -lc 'export HOME=/home/user \
    RUSTUP_HOME=/home/user/.rustup \
    PATH=/home/user/.cargo/bin:/usr/local/bin:/usr/bin:/bin \
    CARGO_TARGET_DIR=/workspace/target && \
    apt-get update >/dev/null && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
      ca-certificates gcc g++ make pkg-config iproute2 iputils-ping \
      libglib2.0-0 python3 curl >/dev/null && \
    command -v cargo >/dev/null 2>&1 && \
    ./tests/shadow/run-privileged-live.sh; \
    chown -R "$HOST_UID:$HOST_GID" /workspace/tests/shadow/artifacts /workspace/target/shadow-tests || true'
