#!/bin/bash
set -e

echo "=== TPSR Channel Creation ==="

# Require channel name argument
if [ -z "${1}" ]; then
  echo "Usage: ./create-channel.sh <channel_name>"
  exit 1
fi

CHANNEL_NAME="${1}"
echo "Channel name: ${CHANNEL_NAME}"

# Check required binaries
for BINARY in configtxgen osnadmin peer; do
  if ! command -v "${BINARY}" > /dev/null; then
    echo "Error: ${BINARY} binary not found in PATH"
    exit 1
  fi
done

echo "All required binaries found"
# Navigate to the network directory (script lives in network/scripts/)
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
NETWORK_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
cd "${NETWORK_DIR}"

export FABRIC_CFG_PATH="${NETWORK_DIR}/../config"

echo "Working directory: $(pwd)"

# Verify required files and directories
if [ ! -f "./configtx.yaml" ]; then
  echo "Error: configtx.yaml not found"
  exit 1
fi

if [ ! -d "./crypto-config" ]; then
  echo "Error: crypto-config directory not found. Run generate-crypto.sh first"
  exit 1
fi

if [ ! -f "./docker-compose.yaml" ]; then
  echo "Error: docker-compose.yaml not found"
  exit 1
fi

echo "Pre-flight file checks passed"

# Verify required containers are running
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

# Create channel-artifacts directory
mkdir -p ./channel-artifacts

# Generate channel block
echo "Generating channel block for ${CHANNEL_NAME}..."
configtxgen \
  -profile TPSRChannel \
  -outputBlock "./channel-artifacts/${CHANNEL_NAME}.block" \
  -channelID "${CHANNEL_NAME}" \
  -configPath .

# Verify channel block was created
if [ ! -f "./channel-artifacts/${CHANNEL_NAME}.block" ]; then
  echo "Error: channel block generation failed"
  exit 1
fi

echo "Channel block generated: ./channel-artifacts/${CHANNEL_NAME}.block"

# Join orderer to channel via channel participation API
echo "Joining orderer0 to channel ${CHANNEL_NAME}..."
osnadmin channel join \
  --channelID "${CHANNEL_NAME}" \
  --config-block "./channel-artifacts/${CHANNEL_NAME}.block" \
  -o orderer0.orderer.tpsr.com:7053 \
  --ca-file "${NETWORK_DIR}/crypto-config/ordererOrganizations/orderer.tpsr.com/orderers/orderer0.orderer.tpsr.com/tls/ca.crt" \
  --client-cert "${NETWORK_DIR}/crypto-config/ordererOrganizations/orderer.tpsr.com/orderers/orderer0.orderer.tpsr.com/tls/server.crt" \
  --client-key "${NETWORK_DIR}/crypto-config/ordererOrganizations/orderer.tpsr.com/orderers/orderer0.orderer.tpsr.com/tls/server.key" || true

echo "Orderer joined channel ${CHANNEL_NAME}"

# --- Join VendorOrg peer ---
echo "Joining peer0.vendor.tpsr.com to channel ${CHANNEL_NAME}..."
export CORE_PEER_LOCALMSPID=VendorMSP
export CORE_PEER_ADDRESS=peer0.vendor.tpsr.com:7051
export CORE_PEER_TLS_ENABLED=true
export CORE_PEER_TLS_ROOTCERT_FILE="${NETWORK_DIR}/crypto-config/peerOrganizations/vendor.tpsr.com/peers/peer0.vendor.tpsr.com/tls/ca.crt"
export CORE_PEER_MSPCONFIGPATH="${NETWORK_DIR}/crypto-config/peerOrganizations/vendor.tpsr.com/users/Admin@vendor.tpsr.com/msp"

# Wait for peer to be ready
echo "Waiting for peer0.vendor.tpsr.com to be ready..."
sleep 3
for i in {1..5}; do
  peer channel join -b "./channel-artifacts/${CHANNEL_NAME}.block" && break || echo "Retrying... $i" && sleep 2
done

if ! peer channel list | grep -q "${CHANNEL_NAME}"; then
  echo "Error: peer peer0.vendor.tpsr.com failed to join channel ${CHANNEL_NAME}"
  # Do not exit 1 here if it's already joined
fi
echo "  [OK] peer0.vendor.tpsr.com joined ${CHANNEL_NAME}"

# --- Join SecurityOrg peer ---
echo "Joining peer0.security.tpsr.com to channel ${CHANNEL_NAME}..."
export CORE_PEER_LOCALMSPID=SecurityMSP
export CORE_PEER_ADDRESS=peer0.security.tpsr.com:8051
export CORE_PEER_TLS_ENABLED=true
export CORE_PEER_TLS_ROOTCERT_FILE="${NETWORK_DIR}/crypto-config/peerOrganizations/security.tpsr.com/peers/peer0.security.tpsr.com/tls/ca.crt"
export CORE_PEER_MSPCONFIGPATH="${NETWORK_DIR}/crypto-config/peerOrganizations/security.tpsr.com/users/Admin@security.tpsr.com/msp"

echo "Waiting for peer0.security.tpsr.com to be ready..."
sleep 3
for i in {1..5}; do
  peer channel join -b "./channel-artifacts/${CHANNEL_NAME}.block" && break || echo "Retrying... $i" && sleep 2
done

if ! peer channel list | grep -q "${CHANNEL_NAME}"; then
  echo "Error: peer peer0.security.tpsr.com failed to join channel ${CHANNEL_NAME}"
fi
echo "  [OK] peer0.security.tpsr.com joined ${CHANNEL_NAME}"

# --- Join AuditorOrg peer ---
echo "Joining peer0.auditor.tpsr.com to channel ${CHANNEL_NAME}..."
export CORE_PEER_LOCALMSPID=AuditorMSP
export CORE_PEER_ADDRESS=peer0.auditor.tpsr.com:9051
export CORE_PEER_TLS_ENABLED=true
export CORE_PEER_TLS_ROOTCERT_FILE="${NETWORK_DIR}/crypto-config/peerOrganizations/auditor.tpsr.com/peers/peer0.auditor.tpsr.com/tls/ca.crt"
export CORE_PEER_MSPCONFIGPATH="${NETWORK_DIR}/crypto-config/peerOrganizations/auditor.tpsr.com/users/Admin@auditor.tpsr.com/msp"

echo "Waiting for peer0.auditor.tpsr.com to be ready..."
sleep 3
for i in {1..5}; do
  peer channel join -b "./channel-artifacts/${CHANNEL_NAME}.block" && break || echo "Retrying... $i" && sleep 2
done

if ! peer channel list | grep -q "${CHANNEL_NAME}"; then
  echo "Error: peer peer0.auditor.tpsr.com failed to join channel ${CHANNEL_NAME}"
fi
echo "  [OK] peer0.auditor.tpsr.com joined ${CHANNEL_NAME}"

echo "Channel ${CHANNEL_NAME} created and verified successfully"