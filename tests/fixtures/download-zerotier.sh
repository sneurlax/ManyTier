#!/bin/bash
# Download official zerotier-one binaries for interop testing.
# Legacy behavior is preserved: running with no arguments downloads the pinned
# 1.14.2 binary to tests/fixtures/zerotier-one.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

# shellcheck source=tests/shadow/validation-paths.sh
source "$ROOT/tests/shadow/validation-paths.sh"

DEFAULT_VERSION="1.14.2"
VERSION="${MANYTIER_ZEROTIER_ONE_VERSION:-$DEFAULT_VERSION}"
ARCH="${MANYTIER_ZEROTIER_ONE_ARCH:-amd64}"
OUTPUT_DIR=""
OUTPUT=""
LEGACY_OUTPUT_DIR=""

usage() {
    cat <<EOF
Usage:
  tests/fixtures/download-zerotier.sh [output-dir]
  tests/fixtures/download-zerotier.sh --version <version> [--output <path>] [--arch <arch>]
  tests/fixtures/download-zerotier.sh --version <version> [--output-dir <dir>] [--arch <arch>]

Examples:
  tests/fixtures/download-zerotier.sh
  tests/fixtures/download-zerotier.sh tests/fixtures
  tests/fixtures/download-zerotier.sh --version 1.16.1 --output tests/fixtures/zerotier-one-1.16.1
EOF
}

while [ "$#" -gt 0 ]; do
    case "$1" in
        --version)
            VERSION="$2"
            shift 2
            ;;
        --arch)
            ARCH="$2"
            shift 2
            ;;
        --output)
            OUTPUT="$2"
            shift 2
            ;;
        --output-dir)
            OUTPUT_DIR="$2"
            shift 2
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            if [ -z "$LEGACY_OUTPUT_DIR" ]; then
                LEGACY_OUTPUT_DIR="$1"
                shift
            else
                echo "Unexpected argument: $1" >&2
                usage >&2
                exit 1
            fi
            ;;
    esac
done

if [ -z "$OUTPUT" ]; then
    DEFAULT_OUTPUT_DIR="$(manytier_validation_repo_relative "$(manytier_validation_fixture_root)")"
    OUTPUT_DIR="${OUTPUT_DIR:-${LEGACY_OUTPUT_DIR:-$DEFAULT_OUTPUT_DIR}}"
    if [ "$VERSION" = "$DEFAULT_VERSION" ] && [ -z "$LEGACY_OUTPUT_DIR" ] && [ -z "${MANYTIER_ZEROTIER_ONE_VERSION:-}" ]; then
        OUTPUT="$OUTPUT_DIR/zerotier-one"
    else
        OUTPUT="$OUTPUT_DIR/zerotier-one-$VERSION"
    fi
fi

OUTPUT="$(manytier_validation_resolve_path "$OUTPUT")"
mkdir -p "$(dirname "$OUTPUT")"

if [ -f "$OUTPUT" ]; then
    echo "zerotier-one ${VERSION} already exists at $OUTPUT"
    exit 0
fi

URL="https://download.zerotier.com/debian/noble/pool/main/z/zerotier-one/zerotier-one_${VERSION}_${ARCH}.deb"
TEMP=$(mktemp -d)
trap "rm -rf $TEMP" EXIT

echo "Downloading zerotier-one ${VERSION}..."
curl -fsSL "$URL" -o "$TEMP/zt.deb"

cd "$TEMP"
ar x zt.deb
tar xf data.tar.* ./usr/sbin/zerotier-one 2>/dev/null || tar xf data.tar.* ./usr/sbin/zerotier-one
cp usr/sbin/zerotier-one "$OUTPUT"
chmod +x "$OUTPUT"

echo "zerotier-one ${VERSION} downloaded to $OUTPUT"
