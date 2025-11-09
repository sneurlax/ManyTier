#!/bin/bash
# Download pinned zerotier-one binary for interop testing
# Pinned to version 1.14.2 
set -euo pipefail

VERSION="1.14.2"
ARCH="amd64"
OUTPUT_DIR="${1:-tests/fixtures}"
OUTPUT="$OUTPUT_DIR/zerotier-one"

if [ -f "$OUTPUT" ]; then
    echo "zerotier-one already exists at $OUTPUT"
    exit 0
fi

# Download from official releases
URL="https://download.zerotier.com/debian/noble/pool/main/z/zerotier-one/zerotier-one_${VERSION}_${ARCH}.deb"
TEMP=$(mktemp -d)
trap "rm -rf $TEMP" EXIT

echo "Downloading zerotier-one ${VERSION}..."
curl -fsSL "$URL" -o "$TEMP/zt.deb"

# Extract binary from .deb
cd "$TEMP"
ar x zt.deb
tar xf data.tar.* ./usr/sbin/zerotier-one 2>/dev/null || tar xf data.tar.* ./usr/sbin/zerotier-one
cp usr/sbin/zerotier-one "$OLDPWD/$OUTPUT"
chmod +x "$OLDPWD/$OUTPUT"

echo "zerotier-one ${VERSION} downloaded to $OUTPUT"
