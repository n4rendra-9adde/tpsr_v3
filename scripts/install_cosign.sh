#!/bin/bash
set -eo pipefail

# TPSR Cosign Installation Script
# This script downloads a pinned, official release of Sigstore Cosign,
# verifies its SHA-256 checksum, and installs it to the local bin/ directory.
# License: Apache 2.0 (Cosign)

COSIGN_VERSION="v2.4.0"
COSIGN_OS="linux"
COSIGN_ARCH="amd64"
COSIGN_BINARY="cosign-${COSIGN_OS}-${COSIGN_ARCH}"
COSIGN_URL="https://github.com/sigstore/cosign/releases/download/${COSIGN_VERSION}/${COSIGN_BINARY}"
COSIGN_SHA256="4bcce3eb8ce9a3ed9c7f66a87754b7c6c4c6a6669910dcdbba23101d293122c6" # Expected checksum for v2.4.0 linux-amd64

TARGET_DIR="./bin"
TARGET_FILE="${TARGET_DIR}/cosign"

echo "Installing Sigstore Cosign ${COSIGN_VERSION}..."

# Create target directory
mkdir -p "${TARGET_DIR}"

# Download binary to a temporary file
TMP_FILE=$(mktemp)
echo "Downloading from ${COSIGN_URL}..."
curl -sL "${COSIGN_URL}" -o "${TMP_FILE}"

# Verify checksum
echo "Verifying SHA-256 checksum..."
ACTUAL_SHA256=$(sha256sum "${TMP_FILE}" | awk '{print $1}')

if [ "${ACTUAL_SHA256}" != "${COSIGN_SHA256}" ]; then
  echo "ERROR: Checksum mismatch!"
  echo "Expected: ${COSIGN_SHA256}"
  echo "Actual:   ${ACTUAL_SHA256}"
  rm -f "${TMP_FILE}"
  exit 1
fi

echo "Checksum verified successfully."

# Install binary
mv "${TMP_FILE}" "${TARGET_FILE}"
chmod +x "${TARGET_FILE}"

echo "Cosign installed to ${TARGET_FILE}"
