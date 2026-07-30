#!/bin/bash
set -euo pipefail

if ! command -v curl >/dev/null 2>&1; then
  echo "Error: curl is required"
  exit 1
fi

if ! command -v python3 >/dev/null 2>&1; then
  echo "Error: python3 is required"
  exit 1
fi

export TPSR_API_BASE_URL="${TPSR_API_BASE_URL:-http://localhost:3000/api}"
API_BASE="${TPSR_API_BASE_URL%/}"
HEALTH_URL="${API_BASE%/api}/health"

SUBMIT_USER_ID="tpsr-functional-submit"
SUBMIT_ROLE="developer"
VERIFY_USER_ID="tpsr-functional-verify"
VERIFY_ROLE="auditor"
HISTORY_USER_ID="tpsr-functional-history"
HISTORY_ROLE="auditor"
COMPLIANCE_USER_ID="tpsr-functional-compliance"
COMPLIANCE_ROLE="admin"

EPOCH=$(date +%s)
SBOM_ID="tpsr-functional-$EPOCH"
BUILD_ID="build-$EPOCH"
TEMP_DIR=$(mktemp -d)

trap 'rm -rf "$TEMP_DIR"' EXIT

SBOM_FILE="$TEMP_DIR/sbom.json"
PAYLOAD_FILE="$TEMP_DIR/payload.json"
REQ_BODY="$TEMP_DIR/req_body.json"
RESP_BODY="$TEMP_DIR/resp_body.json"
RESP_STATUS="$TEMP_DIR/resp_status.txt"

cat << 'EOF' > "$SBOM_FILE"
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.4",
  "metadata": {},
  "components": []
}
EOF

http_call() {
  local method="$1"
  local url="$2"
  local out_body="$3"
  local out_status="$4"
  shift 4

  curl -s -w "%{http_code}" -X "$method" "$url" -o "$out_body" "$@" > "$out_status"
}

echo "Starting TPSR functional tests..."

echo "TEST 1: Health check"
http_call GET "$HEALTH_URL" "$RESP_BODY" "$RESP_STATUS"
st=$(cat "$RESP_STATUS")
if [ "$st" -ne 200 ]; then
  echo "FAIL: Health check failed with HTTP $st"
  exit 1
fi
if ! python3 -c '
import sys, json
try:
  with open(sys.argv[1]) as f:
    d = json.load(f)
  if d.get("status") != "ok":
    sys.exit(1)
except Exception:
  sys.exit(1)
' "$RESP_BODY"; then
  echo "FAIL: Health check response validation failed"
  exit 1
fi
echo "PASS: Health check"

echo "TEST 2: Submit without auth should fail"
echo "{}" > "$REQ_BODY"
http_call POST "$API_BASE/submit" "$RESP_BODY" "$RESP_STATUS" -H "Content-Type: application/json" -d @"$REQ_BODY"
st=$(cat "$RESP_STATUS")
if [ "$st" -ne 403 ]; then
  echo "FAIL: Expected HTTP 403, got $st"
  exit 1
fi
if ! python3 -c '
import sys, json
try:
  with open(sys.argv[1]) as f:
    d = json.load(f)
  if d.get("error") != "Missing required authentication headers":
    sys.exit(1)
except Exception:
  sys.exit(1)
' "$RESP_BODY"; then
  echo "FAIL: Submit without auth error message mismatch"
  exit 1
fi
echo "PASS: Submit without auth should fail"

echo "TEST 3: Valid SBOM submission"
python3 -c '
import sys, json
with open(sys.argv[1]) as f:
  sbom_content = f.read().strip()
payload = {
  "sbomID": sys.argv[2],
  "sbom": sbom_content,
  "buildID": sys.argv[3],
  "softwareName": "FunctionalTestApp",
  "softwareVersion": "1.0.0",
  "format": "CycloneDX",
  "offChainRef": "ipfs://functional-test",
  "signatures": ["sig-functional-1", "sig-functional-2"]
}
with open(sys.argv[4], "w") as f:
  json.dump(payload, f)
' "$SBOM_FILE" "$SBOM_ID" "$BUILD_ID" "$PAYLOAD_FILE"

http_call POST "$API_BASE/submit" "$RESP_BODY" "$RESP_STATUS" \
  -H "Content-Type: application/json" \
  -H "x-user-id: $SUBMIT_USER_ID" \
  -H "x-user-role: $SUBMIT_ROLE" \
  -d @"$PAYLOAD_FILE"

st=$(cat "$RESP_STATUS")
if [ "$st" -ne 201 ]; then
  echo "FAIL: Valid submit expected HTTP 201, got $st"
  cat "$RESP_BODY"
  exit 1
fi
if ! python3 -c '
import sys, json
try:
  with open(sys.argv[1]) as f:
    d = json.load(f)
  if d.get("message") != "SBOM submitted successfully":
    sys.exit(1)
  if d.get("sbomID") != sys.argv[2]:
    sys.exit(1)
  if not d.get("hash"):
    sys.exit(1)
except Exception as e:
  sys.exit(1)
' "$RESP_BODY" "$SBOM_ID"; then
  echo "FAIL: Valid submit response validation failed"
  exit 1
fi
echo "PASS: Valid SBOM submission"

echo "TEST 4: Valid verification"
python3 -c '
import sys, json
with open(sys.argv[1]) as f:
  sbom_content = f.read().strip()
payload = {
  "sbomID": sys.argv[2],
  "sbom": sbom_content
}
with open(sys.argv[3], "w") as f:
  json.dump(payload, f)
' "$SBOM_FILE" "$SBOM_ID" "$PAYLOAD_FILE"

http_call POST "$API_BASE/verify" "$RESP_BODY" "$RESP_STATUS" \
  -H "Content-Type: application/json" \
  -H "x-user-id: $VERIFY_USER_ID" \
  -H "x-user-role: $VERIFY_ROLE" \
  -d @"$PAYLOAD_FILE"

st=$(cat "$RESP_STATUS")
if [ "$st" -ne 200 ]; then
  echo "FAIL: Valid verify expected HTTP 200, got $st"
  cat "$RESP_BODY"
  exit 1
fi
if ! python3 -c '
import sys, json
try:
  with open(sys.argv[1]) as f:
    d = json.load(f)
  if d.get("message") != "SBOM verification completed":
    sys.exit(1)
  v = d.get("verification", {})
  if v.get("sbomID") != sys.argv[2]:
    sys.exit(1)
  if v.get("match") is not True:
    sys.exit(1)
  if not v.get("status"):
    sys.exit(1)
except Exception:
  sys.exit(1)
' "$RESP_BODY" "$SBOM_ID"; then
  echo "FAIL: Valid verify response validation failed"
  exit 1
fi
echo "PASS: Valid verification"

echo "TEST 5: Valid history lookup"
http_call GET "$API_BASE/history/$SBOM_ID" "$RESP_BODY" "$RESP_STATUS" \
  -H "x-user-id: $HISTORY_USER_ID" \
  -H "x-user-role: $HISTORY_ROLE"

st=$(cat "$RESP_STATUS")
if [ "$st" -ne 200 ]; then
  echo "FAIL: History lookup expected HTTP 200, got $st"
  cat "$RESP_BODY"
  exit 1
fi
if ! python3 -c '
import sys, json
try:
  with open(sys.argv[1]) as f:
    d = json.load(f)
  if d.get("message") != "SBOM history retrieved successfully":
    sys.exit(1)
  if d.get("sbomID") != sys.argv[2]:
    sys.exit(1)
  hist = d.get("history")
  if not isinstance(hist, list) or len(hist) < 1:
    sys.exit(1)
  latest = hist[-1]
  if "txID" not in latest or "timestamp" not in latest:
    sys.exit(1)
except Exception:
  sys.exit(1)
' "$RESP_BODY" "$SBOM_ID"; then
  echo "FAIL: History lookup response validation failed"
  exit 1
fi
echo "PASS: Valid history lookup"

echo "TEST 6: Valid compliance report lookup"
http_call POST "$API_BASE/compliance-report" "$RESP_BODY" "$RESP_STATUS" \
  -H "Content-Type: application/json" \
  -H "x-user-id: $COMPLIANCE_USER_ID" \
  -H "x-user-role: $COMPLIANCE_ROLE" \
  -d @"$PAYLOAD_FILE"

st=$(cat "$RESP_STATUS")
if [ "$st" -ne 200 ]; then
  echo "FAIL: Compliance report expected HTTP 200, got $st"
  cat "$RESP_BODY"
  exit 1
fi
if ! python3 -c '
import sys, json
try:
  with open(sys.argv[1]) as f:
    d = json.load(f)
  if d.get("message") != "Compliance report generated successfully":
    sys.exit(1)
  rep = d.get("report", {})
  if rep.get("sbomID") != sys.argv[2]:
    sys.exit(1)
  if rep.get("integrityMatch") is not True:
    sys.exit(1)
  if not rep.get("ledgerStatus"):
    sys.exit(1)
  if "historyCount" not in rep:
    sys.exit(1)
  if "compliant" not in rep:
    sys.exit(1)
except Exception:
  sys.exit(1)
' "$RESP_BODY" "$SBOM_ID"; then
  echo "FAIL: Compliance report response validation failed"
  exit 1
fi
echo "PASS: Valid compliance report lookup"

echo "TPSR functional tests completed successfully"
exit 0
