#!/bin/bash
set -e

echo "=== TPSR Chaincode Deployment ==="

# Require exactly four arguments
if [ "$#" -ne 4 ]; then
  echo "Usage: ./deploy-chaincode.sh <channel_name> <chaincode_name> <chaincode_version> <chaincode_sequence>"
  exit 1
fi

CHANNEL_NAME="$1"
CHAINCODE_NAME="$2"
CHAINCODE_VERSION="$3"
CHAINCODE_SEQUENCE="$4"

echo "Channel: ${CHANNEL_NAME}"
echo "Chaincode: ${CHAINCODE_NAME} v${CHAINCODE_VERSION} seq${CHAINCODE_SEQUENCE}"

# Check required binaries
for BINARY in peer docker; do
  if ! command -v "${BINARY}" > /dev/null; then
    echo "Error: ${BINARY} binary not found in PATH"
    exit 1
  fi
done

# Navigate to the network directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
NETWORK_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
cd "${NETWORK_DIR}"

export FABRIC_CFG_PATH="${NETWORK_DIR}/../config"

echo "Working directory: $(pwd)"

# Verify required files and directories
if [ ! -d "./crypto-config" ]; then
  echo "Error: crypto-config directory not found"
  exit 1
fi

if [ ! -f "./channel-artifacts/${CHANNEL_NAME}.block" ]; then
  echo "Error: channel block ./channel-artifacts/${CHANNEL_NAME}.block not found"
  exit 1
fi

if [ ! -d "../chaincode/sbom" ]; then
  echo "Error: chaincode source directory ../chaincode/sbom not found"
  exit 1
fi

if [ ! -f "../chaincode/sbom/go.mod" ]; then
  echo "Error: chaincode go.mod file ../chaincode/sbom/go.mod not found"
  exit 1
fi

echo "Pre-flight file checks passed"

# Verify required containers
REQUIRED_CONTAINERS=(
  "orderer0.orderer.tpsr.com"
  "peer0.vendor.tpsr.com"
  "peer0.security.tpsr.com"
  "peer0.auditor.tpsr.com"
)

for CONTAINER in "${REQUIRED_CONTAINERS[@]}"; do
  if ! docker ps --format '{{.Names}}' | grep -q "^${CONTAINER}$"; then
    echo "Error: required container ${CONTAINER} is not running"
    exit 1
  fi
done

echo "All required containers are running"

# TLS CA paths
ORDERER_CA="${NETWORK_DIR}/crypto-config/ordererOrganizations/orderer.tpsr.com/orderers/orderer0.orderer.tpsr.com/tls/ca.crt"
VENDOR_TLS_CA="${NETWORK_DIR}/crypto-config/peerOrganizations/vendor.tpsr.com/peers/peer0.vendor.tpsr.com/tls/ca.crt"
SECURITY_TLS_CA="${NETWORK_DIR}/crypto-config/peerOrganizations/security.tpsr.com/peers/peer0.security.tpsr.com/tls/ca.crt"
AUDITOR_TLS_CA="${NETWORK_DIR}/crypto-config/peerOrganizations/auditor.tpsr.com/peers/peer0.auditor.tpsr.com/tls/ca.crt"

# Peer environment helper functions
set_vendor_peer_env() {
  export CORE_PEER_LOCALMSPID=VendorMSP
  export CORE_PEER_ADDRESS=peer0.vendor.tpsr.com:7051
  export CORE_PEER_TLS_ENABLED=true
  export CORE_PEER_TLS_ROOTCERT_FILE="${NETWORK_DIR}/crypto-config/peerOrganizations/vendor.tpsr.com/peers/peer0.vendor.tpsr.com/tls/ca.crt"
  export CORE_PEER_MSPCONFIGPATH="${NETWORK_DIR}/crypto-config/peerOrganizations/vendor.tpsr.com/users/Admin@vendor.tpsr.com/msp"
}

set_security_peer_env() {
  export CORE_PEER_LOCALMSPID=SecurityMSP
  export CORE_PEER_ADDRESS=peer0.security.tpsr.com:8051
  export CORE_PEER_TLS_ENABLED=true
  export CORE_PEER_TLS_ROOTCERT_FILE="${NETWORK_DIR}/crypto-config/peerOrganizations/security.tpsr.com/peers/peer0.security.tpsr.com/tls/ca.crt"
  export CORE_PEER_MSPCONFIGPATH="${NETWORK_DIR}/crypto-config/peerOrganizations/security.tpsr.com/users/Admin@security.tpsr.com/msp"
}

set_auditor_peer_env() {
  export CORE_PEER_LOCALMSPID=AuditorMSP
  export CORE_PEER_ADDRESS=peer0.auditor.tpsr.com:9051
  export CORE_PEER_TLS_ENABLED=true
  export CORE_PEER_TLS_ROOTCERT_FILE="${NETWORK_DIR}/crypto-config/peerOrganizations/auditor.tpsr.com/peers/peer0.auditor.tpsr.com/tls/ca.crt"
  export CORE_PEER_MSPCONFIGPATH="${NETWORK_DIR}/crypto-config/peerOrganizations/auditor.tpsr.com/users/Admin@auditor.tpsr.com/msp"
}

# Check if already committed
set_vendor_peer_env
if peer lifecycle chaincode querycommitted -C "${CHANNEL_NAME}" | grep -q "Name: ${CHAINCODE_NAME}, Version: ${CHAINCODE_VERSION}"; then
  echo "Chaincode ${CHAINCODE_NAME} v${CHAINCODE_VERSION} is already committed on ${CHANNEL_NAME}. Skipping deployment."
  exit 0
fi

# Package chaincode
echo "Packaging chaincode..."
peer lifecycle chaincode package \
  "./channel-artifacts/${CHAINCODE_NAME}_${CHAINCODE_VERSION}.tar.gz" \
  --path ../chaincode/sbom \
  --lang golang \
  --label "${CHAINCODE_NAME}_${CHAINCODE_VERSION}" || true

echo "Chaincode packaged: ./channel-artifacts/${CHAINCODE_NAME}_${CHAINCODE_VERSION}.tar.gz"

# Install on vendor peer
echo "Installing chaincode on vendor peer..."
set_vendor_peer_env
peer lifecycle chaincode install \
  "./channel-artifacts/${CHAINCODE_NAME}_${CHAINCODE_VERSION}.tar.gz" || true

# Install on security peer
echo "Installing chaincode on security peer..."
set_security_peer_env
peer lifecycle chaincode install \
  "./channel-artifacts/${CHAINCODE_NAME}_${CHAINCODE_VERSION}.tar.gz" || true

# Install on auditor peer
echo "Installing chaincode on auditor peer..."
set_auditor_peer_env
peer lifecycle chaincode install \
  "./channel-artifacts/${CHAINCODE_NAME}_${CHAINCODE_VERSION}.tar.gz" || true

echo "Chaincode installed on all peers"

# Query installed and extract package ID
echo "Querying installed chaincodes..."
set_vendor_peer_env
PACKAGE_ID=$(peer lifecycle chaincode queryinstalled | grep "${CHAINCODE_NAME}_${CHAINCODE_VERSION}" | sed -n 's/^Package ID: \(.*\), Label:.*$/\1/p')

if [ -z "${PACKAGE_ID}" ]; then
  echo "Error: failed to determine chaincode package ID"
  exit 1
fi

echo "Package ID: ${PACKAGE_ID}"

# Approve for vendor
echo "Approving chaincode for VendorOrg..."
set_vendor_peer_env
peer lifecycle chaincode approveformyorg \
  -o orderer0.orderer.tpsr.com:7050 \
  --ordererTLSHostnameOverride orderer0.orderer.tpsr.com \
  --tls \
  --cafile "${ORDERER_CA}" \
  --channelID "${CHANNEL_NAME}" \
  --name "${CHAINCODE_NAME}" \
  --version "${CHAINCODE_VERSION}" \
  --package-id "${PACKAGE_ID}" \
  --sequence "${CHAINCODE_SEQUENCE}"

# Approve for security
echo "Approving chaincode for SecurityOrg..."
set_security_peer_env
peer lifecycle chaincode approveformyorg \
  -o orderer0.orderer.tpsr.com:7050 \
  --ordererTLSHostnameOverride orderer0.orderer.tpsr.com \
  --tls \
  --cafile "${ORDERER_CA}" \
  --channelID "${CHANNEL_NAME}" \
  --name "${CHAINCODE_NAME}" \
  --version "${CHAINCODE_VERSION}" \
  --package-id "${PACKAGE_ID}" \
  --sequence "${CHAINCODE_SEQUENCE}"

# Approve for auditor
echo "Approving chaincode for AuditorOrg..."
set_auditor_peer_env
peer lifecycle chaincode approveformyorg \
  -o orderer0.orderer.tpsr.com:7050 \
  --ordererTLSHostnameOverride orderer0.orderer.tpsr.com \
  --tls \
  --cafile "${ORDERER_CA}" \
  --channelID "${CHANNEL_NAME}" \
  --name "${CHAINCODE_NAME}" \
  --version "${CHAINCODE_VERSION}" \
  --package-id "${PACKAGE_ID}" \
  --sequence "${CHAINCODE_SEQUENCE}"

echo "Chaincode approved by all organizations"

# Check commit readiness
echo "Checking commit readiness..."
set_vendor_peer_env
peer lifecycle chaincode checkcommitreadiness \
  --channelID "${CHANNEL_NAME}" \
  --name "${CHAINCODE_NAME}" \
  --version "${CHAINCODE_VERSION}" \
  --sequence "${CHAINCODE_SEQUENCE}" \
  --output json \
  --tls \
  --cafile "${ORDERER_CA}" \
  -o orderer0.orderer.tpsr.com:7050 \
  --ordererTLSHostnameOverride orderer0.orderer.tpsr.com

# Commit chaincode definition
echo "Committing chaincode definition..."
set_vendor_peer_env
peer lifecycle chaincode commit \
  -o orderer0.orderer.tpsr.com:7050 \
  --ordererTLSHostnameOverride orderer0.orderer.tpsr.com \
  --tls \
  --cafile "${ORDERER_CA}" \
  --channelID "${CHANNEL_NAME}" \
  --name "${CHAINCODE_NAME}" \
  --version "${CHAINCODE_VERSION}" \
  --sequence "${CHAINCODE_SEQUENCE}" \
  --peerAddresses peer0.vendor.tpsr.com:7051 \
  --tlsRootCertFiles "${VENDOR_TLS_CA}" \
  --peerAddresses peer0.security.tpsr.com:8051 \
  --tlsRootCertFiles "${SECURITY_TLS_CA}" \
  --peerAddresses peer0.auditor.tpsr.com:9051 \
  --tlsRootCertFiles "${AUDITOR_TLS_CA}"

echo "Chaincode definition committed"

# Verify committed definition from each peer
echo "Verifying committed chaincode from vendor peer..."
set_vendor_peer_env
if ! peer lifecycle chaincode querycommitted --channelID "${CHANNEL_NAME}" --name "${CHAINCODE_NAME}" > /dev/null 2>&1; then
  echo "Error: chaincode ${CHAINCODE_NAME} is not committed correctly on peer0.vendor.tpsr.com"
  exit 1
fi
echo "  [OK] peer0.vendor.tpsr.com"

echo "Verifying committed chaincode from security peer..."
set_security_peer_env
if ! peer lifecycle chaincode querycommitted --channelID "${CHANNEL_NAME}" --name "${CHAINCODE_NAME}" > /dev/null 2>&1; then
  echo "Error: chaincode ${CHAINCODE_NAME} is not committed correctly on peer0.security.tpsr.com"
  exit 1
fi
echo "  [OK] peer0.security.tpsr.com"

echo "Verifying committed chaincode from auditor peer..."
set_auditor_peer_env
if ! peer lifecycle chaincode querycommitted --channelID "${CHANNEL_NAME}" --name "${CHAINCODE_NAME}" > /dev/null 2>&1; then
  echo "Error: chaincode ${CHAINCODE_NAME} is not committed correctly on peer0.auditor.tpsr.com"
  exit 1
fi
echo "  [OK] peer0.auditor.tpsr.com"

echo "Chaincode ${CHAINCODE_NAME} deployed and verified successfully on channel ${CHANNEL_NAME}"
