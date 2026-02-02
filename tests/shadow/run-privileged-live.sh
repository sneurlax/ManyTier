#!/bin/bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"

# shellcheck source=tests/shadow/validation-paths.sh
source "$ROOT/tests/shadow/validation-paths.sh"

# Allow explicit override (useful for CI).
CARGO_BIN="${MANYTIER_CARGO_BIN:-cargo}"
OWNER_UID="${SUDO_UID:-}"
OWNER_GID="${SUDO_GID:-}"
TARGET_DIR="$(manytier_validation_target_dir)"
SCRATCH_ROOT="$(manytier_validation_scratch_root)"

fix_ownership_on_exit() {
    if [ "$(id -u)" -ne 0 ]; then
        return
    fi
    if [ -z "$OWNER_UID" ] || [ -z "$OWNER_GID" ]; then
        return
    fi
    # Root runs can leave behind root-owned build artifacts and logs, which then
    # break normal developer workflows. Best-effort chown back to the invoking user.
    chown -R "$OWNER_UID:$OWNER_GID" "$TARGET_DIR" 2>/dev/null || true
    if [ -n "${ARTIFACT_ROOT:-}" ]; then
        chown -R "$OWNER_UID:$OWNER_GID" "$ARTIFACT_ROOT" 2>/dev/null || true
    fi
    if [ -n "${MANYTIER_VALIDATION_SCRATCH_ROOT:-}" ]; then
        chown -R "$OWNER_UID:$OWNER_GID" "$MANYTIER_VALIDATION_SCRATCH_ROOT" 2>/dev/null || true
    fi
}

trap fix_ownership_on_exit EXIT

# When this script is invoked under `sudo`, the default PATH often picks up the
# distro `cargo` (e.g. Ubuntu's 1.75.0), which is too old for some crates we
# depend on. Prefer the invoking user's rustup toolchain if available.
if [ "$(id -u)" -eq 0 ] && [ -n "${SUDO_USER:-}" ]; then
    SUDO_HOME="$(getent passwd "$SUDO_USER" | cut -d: -f6 2>/dev/null || true)"
    if [ -n "$SUDO_HOME" ]; then
        # Prefer the repo-pinned toolchain if it's installed for the invoking user.
        PINNED_TOOLCHAIN="$(
            sed -n 's/^channel = \"\\([^\"]*\\)\"$/\\1/p' "$ROOT/rust-toolchain.toml" 2>/dev/null | head -n 1
        )"
        if [ -n "$PINNED_TOOLCHAIN" ]; then
            for tdir in "$SUDO_HOME/.rustup/toolchains/$PINNED_TOOLCHAIN-"* "$SUDO_HOME/.rustup/toolchains/$PINNED_TOOLCHAIN"; do
                if [ -x "$tdir/bin/cargo" ]; then
                    CARGO_BIN="$tdir/bin/cargo"
                    break
                fi
            done
        fi

        # Best option: use the real toolchain cargo (no rustup proxy).
        TOOLCHAIN=""
        if [ -r "$SUDO_HOME/.rustup/settings.toml" ]; then
            TOOLCHAIN="$(
                sed -n 's/^default_toolchain = \"\\([^\"]*\\)\"$/\\1/p' \
                    "$SUDO_HOME/.rustup/settings.toml" | head -n 1
            )"
        fi
        if [ "$CARGO_BIN" = "cargo" ] && [ -n "$TOOLCHAIN" ] && [ -x "$SUDO_HOME/.rustup/toolchains/$TOOLCHAIN/bin/cargo" ]; then
            CARGO_BIN="$SUDO_HOME/.rustup/toolchains/$TOOLCHAIN/bin/cargo"
        elif [ "$CARGO_BIN" = "cargo" ] && [ -x "$SUDO_HOME/.cargo/bin/cargo" ]; then
            # Fallback: rustup proxy.
            export RUSTUP_HOME="${RUSTUP_HOME:-$SUDO_HOME/.rustup}"
            export PATH="$SUDO_HOME/.cargo/bin:$PATH"
            CARGO_BIN="cargo"
        fi
    fi
fi

# 1. Setup Artifacts
TIMESTAMP="$(manytier_validation_timestamp)"
if [[ -n "${MANYTIER_ARTIFACT_ROOT:-}" ]]; then
    ARTIFACT_ROOT="$(manytier_validation_ensure_repo_local "privileged artifact root" "$MANYTIER_ARTIFACT_ROOT")"
elif [[ -n "${MANYTIER_VALIDATION_ARTIFACT_ROOT:-}" ]]; then
    ARTIFACT_ROOT="$(manytier_validation_ensure_repo_local "validation artifact root" "$MANYTIER_VALIDATION_ARTIFACT_ROOT")"
else
    ARTIFACT_ROOT="$(manytier_validation_artifact_parent)/run-$TIMESTAMP"
fi
OFFICIAL_BIN="$(manytier_validation_default_official_bin)"
export CARGO_TARGET_DIR="$TARGET_DIR"
export MANYTIER_WORKSPACE_ROOT="$ROOT"
export MANYTIER_VALIDATION_SCRATCH_ROOT="$SCRATCH_ROOT"
mkdir -p "$ARTIFACT_ROOT" "$TARGET_DIR" "$SCRATCH_ROOT"
mkdir -p "$ARTIFACT_ROOT"

echo "Artifacts will be collected in: $ARTIFACT_ROOT"
echo "Validation scratch root: $SCRATCH_ROOT"
echo "Cargo target dir: $TARGET_DIR"
echo "Official zerotier-one binary: $OFFICIAL_BIN"

export MANYTIER_PRIVILEGED_LIVE=1
export MANYTIER_ARTIFACT_ROOT="$ARTIFACT_ROOT"
export MANYTIER_ZEROTIER_ONE_BIN="$OFFICIAL_BIN"
export TMPDIR="$ARTIFACT_ROOT/tmp"
mkdir -p "$TMPDIR"

# Avoid picking up root's global cargo config (source replacement, proxies, etc).
# Keep cargo's registry/cache isolated to this run.
if [ "$(id -u)" -eq 0 ]; then
    export CARGO_HOME="$ARTIFACT_ROOT/cargo-home"
    mkdir -p "$CARGO_HOME"
fi

# 2. Environment Probing
if ! tests/shadow/probe-environment.sh 2>&1 | tee "$ARTIFACT_ROOT/probe.log"; then
    echo "LANE MISCONFIGURATION: The current environment is missing the required capabilities."
    echo "Check $ARTIFACT_ROOT/probe.log for details."
    exit 1
fi

cat <<EOF
Running the privileged live interop lane.
Output is being mirrored to $ARTIFACT_ROOT/run.log
EOF

# 3. Run Tests
{
    echo "--- Start of Privileged Live Run $TIMESTAMP ---"
    if command -v "$CARGO_BIN" >/dev/null 2>&1; then
        echo "cargo=$CARGO_BIN version=$($CARGO_BIN -V)"
    else
        echo "cargo=<missing> (CARGO_BIN=$CARGO_BIN)"
    fi
    if [ -n "${MANYTIER_ZEROTIER_ONE_BIN:-}" ] && [ -x "${MANYTIER_ZEROTIER_ONE_BIN}" ]; then
        echo "official_bin_version=$("${MANYTIER_ZEROTIER_ONE_BIN}" -v 2>/dev/null || echo unknown)"
    fi

    echo "Running test_manytier_joins_manytier_controller_fallback..."
    "$CARGO_BIN" test -p shadow-node --test shadow_harness \
      harness::tests::test_manytier_joins_manytier_controller_fallback \
      -- --ignored --exact --nocapture || echo "FAILED: test_manytier_joins_manytier_controller_fallback"

    echo "Running test_official_joins_manytier_controller_fallback..."
    "$CARGO_BIN" test -p shadow-node --test shadow_harness \
      harness::tests::test_official_joins_manytier_controller_fallback \
      -- --ignored --exact --nocapture || echo "FAILED: test_official_joins_manytier_controller_fallback"

    echo "Running test_manytier_joins_official_controller_fallback..."
    "$CARGO_BIN" test -p shadow-node --test shadow_harness \
      harness::tests::test_manytier_joins_official_controller_fallback \
      -- --ignored --exact --nocapture || echo "FAILED: test_manytier_joins_official_controller_fallback"

    echo "--- End of Privileged Live Run $TIMESTAMP ---"
} 2>&1 | tee "$ARTIFACT_ROOT/run.log"
