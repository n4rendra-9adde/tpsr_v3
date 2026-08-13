#!/usr/bin/env bash
set -euo pipefail

# Find repository root regardless of calling directory
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

echo "[TPSR] Starting Operational Bootstrap..."
export PATH="$REPO_ROOT/bin:$PATH"

# 1. Validate host prerequisites
for cmd in docker npm node jq curl; do
  if ! command -v "$cmd" &> /dev/null; then
    echo "Error: $cmd is required but not installed."
    exit 1
  fi
done

if [ "${FABRIC_ENABLED:-false}" = "true" ]; then
  if [ ! -f "$REPO_ROOT/bin/peer" ]; then
    echo "Error: Fabric binaries are required but not found in bin/"
    exit 1
  fi
fi

# 2. Validate configuration without printing secrets
if [ ! -f "$REPO_ROOT/api/.env" ]; then
  echo "Error: api/.env not found."
  exit 1
fi

# 3. Start PostgreSQL
echo "[TPSR] Starting PostgreSQL..."
docker compose -f db/docker-compose.postgres.yaml up -d
echo "[TPSR] Waiting for PostgreSQL readiness..."
timeout=30
while ! docker exec tpsr-postgres psql -U tpsr -d tpsr -c "SELECT 1" > /dev/null 2>&1; do
  timeout=$((timeout - 1))
  if [ "$timeout" -le 0 ]; then
    echo " Timeout waiting for PostgreSQL."
    exit 1
  fi
  echo -n "."
  sleep 2
done
echo " Ready."

# 4. Apply migrations using a migration ledger
echo "[TPSR] Applying migrations..."
docker exec -i tpsr-postgres psql -U tpsr -d tpsr -v ON_ERROR_STOP=1 -c "CREATE TABLE IF NOT EXISTS schema_migrations (version varchar(255) PRIMARY KEY, applied_at timestamp DEFAULT current_timestamp);" > /dev/null

for file in $(ls -1 db/migrations/*.sql | sort); do
  filename=$(basename "$file")
  is_applied=$(docker exec -i tpsr-postgres psql -U tpsr -d tpsr -t -c "SELECT count(*) FROM schema_migrations WHERE version='$filename';" | tr -d '[:space:]')
  if [ "$is_applied" = "0" ]; then
    echo "Applying $filename"
    docker exec -i tpsr-postgres psql -U tpsr -d tpsr -v ON_ERROR_STOP=1 < "$file"
    docker exec -i tpsr-postgres psql -U tpsr -d tpsr -v ON_ERROR_STOP=1 -c "INSERT INTO schema_migrations (version) VALUES ('$filename');" > /dev/null
  else
    echo "Skipping $filename (already applied)"
  fi
done
echo "[TPSR] Migrations complete."

# 5. Start Fabric (if required)
if [ "${FABRIC_ENABLED:-false}" = "true" ]; then
  echo "[TPSR] Starting Fabric network..."
  if [ ! -d "network/crypto-config" ]; then
    ./network/scripts/generate-crypto.sh
  fi
  ./network/scripts/start-network.sh
  ./network/scripts/create-channel.sh tpsrchannel
  ./network/scripts/deploy-chaincode.sh tpsrchannel sbom 1.0 1
  
  # Initialize identities
  cd api
  npm install
  node importIdentities.js || true
  cd ..
else
  echo "[TPSR] Running in DEGRADED/OFFLINE mode without Fabric. Outbox events will remain in RETRY_PENDING."
fi

# 6. Start API and Workers
echo "[TPSR] Installing API dependencies..."
cd api
npm install

echo "[TPSR] Starting API server..."
# Prevent duplicate processes
if [ -f /tmp/tpsr-api.pid ]; then
  if kill -0 $(cat /tmp/tpsr-api.pid) 2>/dev/null; then
    echo "[TPSR] API server already running."
  else
    npm start > /tmp/tpsr-api.log 2>&1 &
    echo $! > /tmp/tpsr-api.pid
  fi
else
  npm start > /tmp/tpsr-api.log 2>&1 &
  echo $! > /tmp/tpsr-api.pid
fi
cd ..

# 7. Wait for API readiness
echo "[TPSR] Waiting for API readiness..."
timeout=30
while ! curl -s -f http://localhost:3000/readiness > /dev/null; do
  timeout=$((timeout - 1))
  if [ "$timeout" -le 0 ]; then
    echo " Timeout waiting for API readiness."
    exit 1
  fi
  echo -n "."
  sleep 2
done
echo " API is ready."

echo "[TPSR] Operational Bootstrap complete."
echo "API Base URL: http://localhost:3000"
echo "Development Auth: Use headers x-user-id and x-user-role (e.g., x-user-role: security)"
