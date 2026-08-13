#!/usr/bin/env bash
set -euo pipefail

# Find repository root
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

echo "[TPSR] Normal Operational Shutdown initiated..."

# 1. Stop existing TPSR API securely
echo "[TPSR] Stopping API server..."
if [ -f /tmp/tpsr-api.pid ]; then
  if kill -0 $(cat /tmp/tpsr-api.pid) 2>/dev/null; then
    kill $(cat /tmp/tpsr-api.pid) || true
  fi
  rm -f /tmp/tpsr-api.pid
else
  echo "[TPSR] API PID not found. Searching process list..."
  pkill -f "npm start" || true
  pkill -f "node src/server.js" || true
fi

# 2. Stop databases and network (preserve volumes)
echo "[TPSR] Stopping databases safely..."
docker compose -f db/docker-compose.postgres.yaml down || true

echo "[TPSR] Stopping Fabric network safely..."
docker compose -f network/docker-compose.yaml down || true

# Shut down Fabric specific containers that might have been spawned
docker stop $(docker ps -q --filter name=orderer.example.com --filter name=couchdb --filter name=peer0.org1.example.com --filter name=cli) 2>/dev/null || true

echo "[TPSR] Operational Shutdown complete. All data preserved."
