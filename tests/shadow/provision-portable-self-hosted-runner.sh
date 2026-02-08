#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"

# shellcheck source=tests/shadow/validation-paths.sh
source "$ROOT/tests/shadow/validation-paths.sh"

MODE="direct-host"
APPLY="false"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --mode)
      MODE="$2"
      shift 2
      ;;
    --apply)
      APPLY="true"
      shift
      ;;
    --dry-run)
      APPLY="false"
      shift
      ;;
    *)
      echo "Unknown argument: $1" >&2
      exit 1
      ;;
  esac
done

case "$MODE" in
  direct-host|privileged-docker)
    ;;
  *)
    echo "Unsupported mode: $MODE" >&2
    echo "Use --mode direct-host or --mode privileged-docker." >&2
    exit 1
    ;;
esac

RUST_TOOLCHAIN="$(awk -F'"' '/^channel = / { print $2; exit }' "$ROOT/rust-toolchain.toml")"
BASE_PACKAGES=(
  build-essential
  ca-certificates
  curl
  git
  iproute2
  iputils-ping
  libglib2.0-0
  make
  pkg-config
  python3
  zerotier-one
)
DOCKER_PACKAGES=(docker.io)

PACKAGE_LIST=("${BASE_PACKAGES[@]}")
if [[ "$MODE" == "privileged-docker" ]]; then
  PACKAGE_LIST+=("${DOCKER_PACKAGES[@]}")
fi

print_plan() {
  cat <<EOF
# Portable Self-Hosted Runner Provisioning Plan

Mode: $MODE
Target OS: Ubuntu 24.04
Rust toolchain: ${RUST_TOOLCHAIN:-stable}

Packages:
$(printf -- '- %s\n' "${PACKAGE_LIST[@]}")

Additional requirements:
- Shadow 3.2.x available on PATH or exported as MANYTIER_SHADOW_BIN
- /dev/net/tun present on the runner
- CAP_NET_ADMIN for direct-host mode or privileged Docker access for privileged-docker mode
- repo checkout available on the runner
- official zerotier-one binary available at /usr/sbin/zerotier-one or supplied via MANYTIER_ZEROTIER_ONE_BIN

Commands:
- sudo apt-get update
- sudo apt-get install -y ${PACKAGE_LIST[*]}
- if cargo is missing: curl https://sh.rustup.rs -sSf | sh -s -- -y --profile minimal --default-toolchain ${RUST_TOOLCHAIN:-stable}
- verify shadow --version, zerotier-one -v, and ./tests/shadow/preflight-portable-self-hosted.sh
EOF
}

if [[ "$APPLY" != "true" ]]; then
  print_plan
  exit 0
fi

if [[ "$(id -u)" -ne 0 ]]; then
  echo "--apply must be run as root." >&2
  exit 1
fi

if [[ -r /etc/os-release ]]; then
  # shellcheck disable=SC1091
  . /etc/os-release
  if [[ "${ID:-}" != "ubuntu" || "${VERSION_ID:-}" != "24.04" ]]; then
    echo "This provisioning helper currently supports Ubuntu 24.04 only." >&2
    exit 1
  fi
fi

apt-get update
apt-get install -y "${PACKAGE_LIST[@]}"

if ! command -v cargo >/dev/null 2>&1; then
  curl https://sh.rustup.rs -sSf | sh -s -- -y --profile minimal --default-toolchain "${RUST_TOOLCHAIN:-stable}"
fi

if [[ -z "$(manytier_validation_shadow_bin)" ]]; then
  echo "Shadow is still missing. Install Shadow 3.2.x or export MANYTIER_SHADOW_BIN before running the portable lane." >&2
  exit 1
fi

cat <<EOF
Portable runner base provisioning is complete.

Next steps:
1. Ensure the repo is available on this runner.
2. Run ./tests/shadow/preflight-portable-self-hosted.sh --baseline-json <workstation-baseline-json>.
3. Use ./tests/shadow/run-portable-self-hosted-refresh.sh for direction-specific proofs.
EOF
