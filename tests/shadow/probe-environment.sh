#!/bin/bash
set -euo pipefail

echo "=== ManyTier Privileged Lane Probe ==="

PROBE_TUN=""
PROBE_ERR=""

cleanup() {
    if [ -n "$PROBE_TUN" ]; then
        ip tuntap del mode tun name "$PROBE_TUN" >/dev/null 2>&1 || true
    fi
    if [ -n "$PROBE_ERR" ]; then
        rm -f "$PROBE_ERR" >/dev/null 2>&1 || true
    fi
}

trap cleanup EXIT

# 1. Check for /dev/net/tun
if [ -e "/dev/net/tun" ]; then
    echo "[OK] /dev/net/tun exists"
else
    echo "[FAIL] /dev/net/tun does not exist. Is the TUN/TAP driver loaded?"
    exit 1
fi

# 2. Check for permissions on /dev/net/tun
if [ -r "/dev/net/tun" ] && [ -w "/dev/net/tun" ]; then
    echo "[OK] /dev/net/tun is readable and writable"
else
    echo "[FAIL] Insufficient permissions for /dev/net/tun. Are you root or in the 'netdev' group?"
    exit 1
fi

# 3. Check for actual TUN/TAP creation ability
# The strict live lane ultimately relies on the same kernel capability that
# `NativeTun::create(...)` needs, so probing must require a real dummy device
# instead of trusting ambient capability reporting alone.
PROBE_TUN="mtprobe$(printf "%05x" $RANDOM)"
TMPBASE="${TMPDIR:-/tmp}"
mkdir -p "$TMPBASE" >/dev/null 2>&1 || true
PROBE_ERR="$(mktemp -p "$TMPBASE" manytier-probe.XXXXXX 2>/dev/null || true)"
if [ -z "$PROBE_ERR" ]; then
    # As a last resort, fall back to a per-PID path in the current directory.
    PROBE_ERR="./manytier-probe.$$.err"
    : >"$PROBE_ERR" 2>/dev/null || true
fi

if ip tuntap add mode tun name "$PROBE_TUN" 2>"$PROBE_ERR"; then
    echo "[OK] Created dummy tun device $PROBE_TUN"
    if ip link set dev "$PROBE_TUN" up 2>>"$PROBE_ERR"; then
        echo "[OK] Dummy tun device $PROBE_TUN can be brought up"
    else
        echo "[FAIL] Dummy tun device $PROBE_TUN was created but could not be brought up:"
        sed 's/^/  /' "$PROBE_ERR" || true
        exit 1
    fi
else
    echo "[FAIL] Unable to create a dummy tun device required by the privileged lane."
    sed 's/^/  /' "$PROBE_ERR" || true
    if command -v capsh &>/dev/null; then
        echo "[INFO] capsh reports:"
        capsh --print | sed 's/^/  /'
    fi
    echo "[HINT] This almost always means the process lacks CAP_NET_ADMIN in its current namespace."
    echo "       If you are inside a containerized dev shell, run the lane inside a privileged container"
    echo "       or run on the host with real NET_ADMIN."
    exit 1
fi
rm -f "$PROBE_ERR" >/dev/null 2>&1 || true
PROBE_ERR=""

# 4. Check for zerotier-one binary
if [ -x "tests/fixtures/zerotier-one" ]; then
    echo "[OK] tests/fixtures/zerotier-one is present and executable"
else
    echo "[FAIL] tests/fixtures/zerotier-one is missing or not executable. Run 'tests/fixtures/download-zerotier.sh'?"
    exit 1
fi

echo "[SUCCESS] Environment is capable of running the privileged lane."
exit 0
