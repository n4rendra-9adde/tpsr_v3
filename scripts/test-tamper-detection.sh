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

SUBMIT_USER_ID="tpsr-tamper-submit"
SUBMIT_ROLE="developer"
VERIFY_USER_ID="tpsr-tamper-verify"
VERIFY_ROLE="auditor"
COMPLIANCE_USER_ID="tpsr-tamper-compliance"
COMPLIANCE_ROLE="admin"
HISTORY_USER_ID="tpsr-tamper-history"
HISTORY_ROLE="auditor"

EPOCH=$(date +%s)
SBOM_ID="tpsr-tamper-$EPOCH"
BUILD_ID="build-$EPOCH"
TEMP_DIR=$(mktemp -d)

trap 'rm -rf "$TEMP_DIR"' EXIT

ORIGINAL_SBOM_FILE="$TEMP_DIR/sbom_original.json"
TAMPERED_SBOM_FILE="$TEMP_DIR/sbom_tampered.json"
PAYLOAD_FILE="$TEMP_DIR/payload.json"
RESP_BODY="$TEMP_DIR/resp_body.json"
RESP_STATUS="$TEMP_DIR/resp_status.txt"

cat << 'EOF' > "$ORIGINAL_SBOM_FILE"
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.4",
  "metadata": {},
  "components": [
    {"name":"tamper-test-component","version":"1.0"}
  ]
}
EOF

cat << 'EOF' > "$TAMPERED_SBOM_FILE"
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.4",
  "metadata": {},
  "components": [
    {"name":"tamper-test-component","version":"1.1-MALICIOUS"}
  ]
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

echo "Starting TPSR tamper detection validation..."

echo "TEST 1: Valid original SBOM submission"
python3 -c '
import sys, json
with open(sys.argv[1]) as f:
  sbom_content = f.read().strip()
payload = {
  "sbomID": sys.argv[2],
  "sbom": sbom_content,
  "buildID": sys.argv[3],
  "softwareName": "TPSR Tamper Test App",
  "softwareVersion": "1.0.0",
  "format": "CycloneDX",
  "offChainRef": "ipfs://tpsr-tamper-test",
  "signatures": ["sig-tamper-1", "sig-tamper-2"]
}
with open(sys.argv[4], "w") as f:
  json.dump(payload, f)
' "$ORIGINAL_SBOM_FILE" "$SBOM_ID" "$BUILD_ID" "$PAYLOAD_FILE"

http_call POST "$API_BASE/submit" "$RESP_BODY" "$RESP_STATUS" \
  -H "Content-Type: application/json" \
  -H "x-user-id: $SUBMIT_USER_ID" \
  -H "x-user-role: $SUBMIT_ROLE" \
  -d @"$PAYLOAD_FILE"

st=$(cat "$RESP_STATUS")
if [ "$st" -ne 201 ]; then
  echo "FAIL: Expected HTTP 201, got $st"
  cat "$RESP_BODY"
  exit 1
fi
if ! python3 -c '
import sys, json
try:
  with open(sys.argv[1]) as f:
    d = json.load(f)
  if d.get("message") != "SBOM submitted successfully": sys.exit(1)
  if d.get("sbomID") != sys.argv[2]: sys.exit(1)
  if not d.get("hash"): sys.exit(1)
except Exception:
  sys.exit(1)
' "$RESP_BODY" "$SBOM_ID"; then
  echo "FAIL: Test 1 verification failed"
  exit 1
fi
echo "PASS: Test 1"

echo "TEST 2: Original SBOM verification must succeed"
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
' "$ORIGINAL_SBOM_FILE" "$SBOM_ID" "$PAYLOAD_FILE"

http_call POST "$API_BASE/verify" "$RESP_BODY" "$RESP_STATUS" \
  -H "Content-Type: application/json" \
  -H "x-user-id: $VERIFY_USER_ID" \
  -H "x-user-role: $VERIFY_ROLE" \
  -d @"$PAYLOAD_FILE"

st=$(cat "$RESP_STATUS")
if [ "$st" -ne 200 ]; then
  echo "FAIL: Expected HTTP 200, got $st"
  exit 1
fi
if ! python3 -c '
import sys, json
try:
  with open(sys.argv[1]) as f:
    d = json.load(f)
  if d.get("message") != "SBOM verification completed": sys.exit(1)
  v = d.get("verification", {})
  if v.get("sbomID") != sys.argv[2]: sys.exit(1)
  if v.get("match") is not True: sys.exit(1)
  if not v.get("status"): sys.exit(1)
except Exception:
  sys.exit(1)
' "$RESP_BODY" "$SBOM_ID"; then
  echo "FAIL: Test 2 verification failed"
  exit 1
fi
echo "PASS: Test 2"

echo "TEST 3: Tampered SBOM verification must fail"
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
' "$TAMPERED_SBOM_FILE" "$SBOM_ID" "$PAYLOAD_FILE"

http_call POST "$API_BASE/verify" "$RESP_BODY" "$RESP_STATUS" \
  -H "Content-Type: application/json" \
  -H "x-user-id: $VERIFY_USER_ID" \
  -H "x-user-role: $VERIFY_ROLE" \
  -d @"$PAYLOAD_FILE"

st=$(cat "$RESP_STATUS")
if [ "$st" -ne 200 ]; then
  echo "FAIL: Expected HTTP 200, got $st"
  exit 1
fi
if ! python3 -c '
import sys, json
try:
  with open(sys.argv[1]) as f:
    d = json.load(f)
  if d.get("message") != "SBOM verification completed": sys.exit(1)
  v = d.get("verification", {})
  if v.get("sbomID") != sys.argv[2]: sys.exit(1)
  if v.get("match") is not False: sys.exit(1)
  if not v.get("storedHash"): sys.exit(1)
  if not v.get("submittedHash"): sys.exit(1)
  if v.get("storedHash") == v.get("submittedHash"): sys.exit(1)
except Exception:
  sys.exit(1)
' "$RESP_BODY" "$SBOM_ID"; then
  echo "FAIL: Test 3 verification failed"
  exit 1
fi
echo "PASS: Test 3"

echo "TEST 4: Compliance report for original SBOM"
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
' "$ORIGINAL_SBOM_FILE" "$SBOM_ID" "$PAYLOAD_FILE"

http_call POST "$API_BASE/compliance-report" "$RESP_BODY" "$RESP_STATUS" \
  -H "Content-Type: application/json" \
  -H "x-user-id: $COMPLIANCE_USER_ID" \
  -H "x-user-role: $COMPLIANCE_ROLE" \
  -d @"$PAYLOAD_FILE"

st=$(cat "$RESP_STATUS")
if [ "$st" -ne 200 ]; then
  echo "FAIL: Expected HTTP 200, got $st"
  exit 1
fi
if ! python3 -c '
import sys, json
try:
  with open(sys.argv[1]) as f:
    d = json.load(f)
  if d.get("message") != "Compliance report generated successfully": sys.exit(1)
  r = d.get("report", {})
  if r.get("sbomID") != sys.argv[2]: sys.exit(1)
  if r.get("integrityMatch") is not True: sys.exit(1)
  if not r.get("ledgerStatus"): sys.exit(1)
  if "compliant" not in r: sys.exit(1)
except Exception:
  sys.exit(1)
' "$RESP_BODY" "$SBOM_ID"; then
  echo "FAIL: Test 4 report generation failed"
  exit 1
fi
echo "PASS: Test 4"

echo "TEST 5: Compliance report for tampered SBOM"
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
' "$TAMPERED_SBOM_FILE" "$SBOM_ID" "$PAYLOAD_FILE"

http_call POST "$API_BASE/compliance-report" "$RESP_BODY" "$RESP_STATUS" \
  -H "Content-Type: application/json" \
  -H "x-user-id: $COMPLIANCE_USER_ID" \
  -H "x-user-role: $COMPLIANCE_ROLE" \
  -d @"$PAYLOAD_FILE"

st=$(cat "$RESP_STATUS")
if [ "$st" -ne 200 ]; then
  echo "FAIL: Expected HTTP 200, got $st"
  exit 1
fi
if ! python3 -c '
import sys, json
try:
  with open(sys.argv[1]) as f:
    d = json.load(f)
  if d.get("message") != "Compliance report generated successfully": sys.exit(1)
  r = d.get("report", {})
  if r.get("sbomID") != sys.argv[2]: sys.exit(1)
  if r.get("integrityMatch") is not False: sys.exit(1)
  if r.get("compliant") is not False: sys.exit(1)
  if not r.get("storedHash"): sys.exit(1)
  if not r.get("computedHash"): sys.exit(1)
  if r.get("storedHash") == r.get("computedHash"): sys.exit(1)
except Exception:
  sys.exit(1)
' "$RESP_BODY" "$SBOM_ID"; then
  echo "FAIL: Test 5 report generation failed"
  exit 1
fi
echo "PASS: Test 5"

echo "TEST 6: History lookup after tamper validation"
http_call GET "$API_BASE/history/$SBOM_ID" "$RESP_BODY" "$RESP_STATUS" \
  -H "x-user-id: $HISTORY_USER_ID" \
  -H "x-user-role: $HISTORY_ROLE"

st=$(cat "$RESP_STATUS")
if [ "$st" -ne 200 ]; then
  echo "FAIL: Expected HTTP 200, got $st"
  exit 1
fi
if ! python3 -c '
import sys, json
try:
  with open(sys.argv[1]) as f:
    d = json.load(f)
  if d.get("message") != "SBOM history retrieved successfully": sys.exit(1)
  if d.get("sbomID") != sys.argv[2]: sys.exit(1)
  h = d.get("history", [])
  if not isinstance(h, list) or len(h) < 1: sys.exit(1)
except Exception:
  sys.exit(1)
' "$RESP_BODY" "$SBOM_ID"; then
  echo "FAIL: Test 6 history retrieval failed"
  exit 1
fi
echo "PASS: Test 6"

echo "TPSR tamper detection validation completed successfully"
exit 0
