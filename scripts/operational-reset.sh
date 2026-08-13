#!/usr/bin/env bash
set -euo pipefail

# Find repository root
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

if [ "${TPSR_CONFIRM_RESET:-false}" != "true" ]; then
  echo "[TPSR] WARNING: This is a DESTRUCTIVE action."
  echo "This will destroy the PostgreSQL database, Fabric volumes, and API wallets."
  echo "To proceed, run this script with TPSR_CONFIRM_RESET=true"
  exit 1
fi

echo "[TPSR] WARNING: Destructive reset of development environment!"

# 1. Stop existing TPSR containers safely
echo "[TPSR] Stopping API..."
if [ -f /tmp/tpsr-api.pid ]; then
  if kill -0 $(cat /tmp/tpsr-api.pid) 2>/dev/null; then
    kill $(cat /tmp/tpsr-api.pid) || true
  fi
  rm -f /tmp/tpsr-api.pid
fi

echo "[TPSR] Stopping containers..."
docker compose -f db/docker-compose.postgres.yaml down -v || true
docker compose -f network/docker-compose.yaml down -v || true
# Stop orderer and couchdb containers created by scripts
docker stop $(docker ps -a -q --filter name=orderer.example.com --filter name=couchdb --filter name=peer0.org1.example.com --filter name=cli) 2>/dev/null || true
docker rm $(docker ps -a -q --filter name=orderer.example.com --filter name=couchdb --filter name=peer0.org1.example.com --filter name=cli) 2>/dev/null || true

echo "[TPSR] Cleaning up API wallet and Fabric crypto..."
rm -rf api/wallet || true
rm -rf network/crypto-config || true
rm -rf network/channel-artifacts || true

echo "[TPSR] Recreating disposable development volumes once..."
docker volume prune -f

echo "[TPSR] Reset complete. You may now run scripts/operational-bootstrap.sh."
