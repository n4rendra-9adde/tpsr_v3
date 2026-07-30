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

DEV_USER_ID="tpsr-security-dev"
DEV_ROLE="developer"
SEC_USER_ID="tpsr-security-sec"
SEC_ROLE="security"
AUDITOR_USER_ID="tpsr-security-auditor"
AUDITOR_ROLE="auditor"
ADMIN_USER_ID="tpsr-security-admin"
ADMIN_ROLE="admin"

EPOCH=$(date +%s)
SBOM_ID="tpsr-security-$EPOCH"
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
  "components": [{"name":"security-test","version":"1.0"}]
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

python3 -c '
import sys, json
with open(sys.argv[1]) as f:
  sbom_content = f.read().strip()
payload = {
  "sbomID": sys.argv[2],
  "sbom": sbom_content,
  "buildID": sys.argv[3],
  "softwareName": "TPSR Security Test App",
  "softwareVersion": "1.0.0",
  "format": "CycloneDX",
  "offChainRef": "ipfs://tpsr-security-test",
  "signatures": ["sig-security-1", "sig-security-2"]
}
with open(sys.argv[4], "w") as f:
  json.dump(payload, f)
' "$SBOM_FILE" "$SBOM_ID" "$BUILD_ID" "$PAYLOAD_FILE"


echo "Starting TPSR security tests..."

echo "TEST 1: Submit without auth must be rejected"
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
  echo "FAIL: Test 1 message mismatch"
  exit 1
fi
echo "PASS: Test 1"

echo "TEST 2: Submit with invalid role must be rejected"
echo "{}" > "$REQ_BODY"
http_call POST "$API_BASE/submit" "$RESP_BODY" "$RESP_STATUS" \
  -H "Content-Type: application/json" \
  -H "x-user-id: invalid-role-user" \
  -H "x-user-role: manager" \
  -d @"$REQ_BODY"
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
  if d.get("error") != "Invalid role":
    sys.exit(1)
except Exception:
  sys.exit(1)
' "$RESP_BODY"; then
  echo "FAIL: Test 2 message mismatch"
  exit 1
fi
echo "PASS: Test 2"

echo "TEST 3: Submit with insufficient role must be rejected"
echo "{}" > "$REQ_BODY"
http_call POST "$API_BASE/submit" "$RESP_BODY" "$RESP_STATUS" \
  -H "Content-Type: application/json" \
  -H "x-user-id: $AUDITOR_USER_ID" \
  -H "x-user-role: $AUDITOR_ROLE" \
  -d @"$REQ_BODY"
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
  if d.get("error") != "Insufficient permissions":
    sys.exit(1)
except Exception:
  sys.exit(1)
' "$RESP_BODY"; then
  echo "FAIL: Test 3 message mismatch"
  exit 1
fi
echo "PASS: Test 3"

echo "TEST 4: Valid submit as developer must succeed"
http_call POST "$API_BASE/submit" "$RESP_BODY" "$RESP_STATUS" \
  -H "Content-Type: application/json" \
  -H "x-user-id: $DEV_USER_ID" \
  -H "x-user-role: $DEV_ROLE" \
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
  echo "FAIL: Test 4 message mismatch"
  exit 1
fi
echo "PASS: Test 4"

echo "TEST 5: Duplicate submit must be rejected"
http_call POST "$API_BASE/submit" "$RESP_BODY" "$RESP_STATUS" \
  -H "Content-Type: application/json" \
  -H "x-user-id: $DEV_USER_ID" \
  -H "x-user-role: $DEV_ROLE" \
  -d @"$PAYLOAD_FILE"
st=$(cat "$RESP_STATUS")
if [ "$st" != "400" ] && [ "$st" != "409" ] && [ "$st" != "500" ]; then
  echo "FAIL: Expected duplicate to fail with 400, 409, or 500, got $st"
  exit 1
fi
if ! python3 -c '
import sys, json
try:
  with open(sys.argv[1]) as f:
    d = json.load(f)
  err = d.get("error", "")
  det = d.get("details", "")
  if "already exists" in err or "already exists" in det or "duplicate" in err or "duplicate" in det:
    sys.exit(0)
  if "error" in d:
    sys.exit(0)
  sys.exit(1)
except Exception:
  sys.exit(1)
' "$RESP_BODY"; then
  echo "FAIL: Test 5 duplicate rejection format mismatch"
  exit 1
fi
echo "PASS: Test 5"

echo "TEST 6: Verify without auth must be rejected"
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
' "$SBOM_FILE" "$SBOM_ID" "$TEMP_DIR/verify_payload.json"

http_call POST "$API_BASE/verify" "$RESP_BODY" "$RESP_STATUS" \
  -H "Content-Type: application/json" \
  -d @"$TEMP_DIR/verify_payload.json"
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
  if d.get("error") != "Missing required authentication headers": sys.exit(1)
except Exception:
  sys.exit(1)
' "$RESP_BODY"; then
  echo "FAIL: Test 6 message mismatch"
  exit 1
fi
echo "PASS: Test 6"

echo "TEST 7: Verify with allowed role must succeed"
http_call POST "$API_BASE/verify" "$RESP_BODY" "$RESP_STATUS" \
  -H "Content-Type: application/json" \
  -H "x-user-id: $AUDITOR_USER_ID" \
  -H "x-user-role: $AUDITOR_ROLE" \
  -d @"$TEMP_DIR/verify_payload.json"
st=$(cat "$RESP_STATUS")
if [ "$st" -ne 200 ]; then
  echo "FAIL: Expected HTTP 200, got $st"
  cat "$RESP_BODY"
  exit 1
fi
if ! python3 -c '
import sys, json
try:
  with open(sys.argv[1]) as f:
    d = json.load(f)
  if d.get("message") != "SBOM verification completed": sys.exit(1)
  if d.get("verification", {}).get("match") is not True: sys.exit(1)
except Exception:
  sys.exit(1)
' "$RESP_BODY"; then
  echo "FAIL: Test 7 verification result mismatch"
  exit 1
fi
echo "PASS: Test 7"

echo "TEST 8: History with insufficient role must be rejected"
http_call GET "$API_BASE/history/$SBOM_ID" "$RESP_BODY" "$RESP_STATUS" \
  -H "x-user-id: $DEV_USER_ID" \
  -H "x-user-role: $DEV_ROLE"
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
  if d.get("error") != "Insufficient permissions": sys.exit(1)
except Exception:
  sys.exit(1)
' "$RESP_BODY"; then
  echo "FAIL: Test 8 message mismatch"
  exit 1
fi
echo "PASS: Test 8"

echo "TEST 9: History with allowed role must succeed"
http_call GET "$API_BASE/history/$SBOM_ID" "$RESP_BODY" "$RESP_STATUS" \
  -H "x-user-id: $AUDITOR_USER_ID" \
  -H "x-user-role: $AUDITOR_ROLE"
st=$(cat "$RESP_STATUS")
if [ "$st" -ne 200 ]; then
  echo "FAIL: Expected HTTP 200, got $st"
  cat "$RESP_BODY"
  exit 1
fi
if ! python3 -c '
import sys, json
try:
  with open(sys.argv[1]) as f:
    d = json.load(f)
  if d.get("message") != "SBOM history retrieved successfully": sys.exit(1)
  h = d.get("history")
  if not isinstance(h, list) or len(h) < 1: sys.exit(1)
except Exception:
  sys.exit(1)
' "$RESP_BODY"; then
  echo "FAIL: Test 9 history result mismatch"
  exit 1
fi
echo "PASS: Test 9"

echo "TEST 10: Compliance with insufficient role must be rejected"
http_call POST "$API_BASE/compliance-report" "$RESP_BODY" "$RESP_STATUS" \
  -H "Content-Type: application/json" \
  -H "x-user-id: $DEV_USER_ID" \
  -H "x-user-role: $DEV_ROLE" \
  -d @"$TEMP_DIR/verify_payload.json"
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
  if d.get("error") != "Insufficient permissions": sys.exit(1)
except Exception:
  sys.exit(1)
' "$RESP_BODY"; then
  echo "FAIL: Test 10 message mismatch"
  exit 1
fi
echo "PASS: Test 10"

echo "TEST 11: Compliance with allowed role must succeed"
http_call POST "$API_BASE/compliance-report" "$RESP_BODY" "$RESP_STATUS" \
  -H "Content-Type: application/json" \
  -H "x-user-id: $ADMIN_USER_ID" \
  -H "x-user-role: $ADMIN_ROLE" \
  -d @"$TEMP_DIR/verify_payload.json"
st=$(cat "$RESP_STATUS")
if [ "$st" -ne 200 ]; then
  echo "FAIL: Expected HTTP 200, got $st"
  cat "$RESP_BODY"
  exit 1
fi
if ! python3 -c '
import sys, json
try:
  with open(sys.argv[1]) as f:
    d = json.load(f)
  if d.get("message") != "Compliance report generated successfully": sys.exit(1)
  if d.get("report", {}).get("sbomID") != sys.argv[2]: sys.exit(1)
  if d.get("report", {}).get("integrityMatch") is not True: sys.exit(1)
except Exception:
  sys.exit(1)
' "$RESP_BODY" "$SBOM_ID"; then
  echo "FAIL: Test 11 compliance report mismatch"
  exit 1
fi
echo "PASS: Test 11"

echo "TEST 12: Submit input validation: invalid format"
python3 -c '
import sys, json
try:
  with open(sys.argv[1]) as f:
    payload = json.load(f)
  payload["format"] = "XML"
  with open(sys.argv[2], "w") as f:
    json.dump(payload, f)
except Exception:
  sys.exit(1)
' "$PAYLOAD_FILE" "$TEMP_DIR/bad_format.json"

http_call POST "$API_BASE/submit" "$RESP_BODY" "$RESP_STATUS" \
  -H "Content-Type: application/json" \
  -H "x-user-id: $DEV_USER_ID" \
  -H "x-user-role: $DEV_ROLE" \
  -d @"$TEMP_DIR/bad_format.json"
st=$(cat "$RESP_STATUS")
if [ "$st" -ne 400 ]; then
  echo "FAIL: Expected HTTP 400, got $st"
  exit 1
fi
if ! python3 -c '
import sys, json
try:
  with open(sys.argv[1]) as f:
    d = json.load(f)
  if d.get("error") != "format must be SPDX or CycloneDX": sys.exit(1)
except Exception:
  sys.exit(1)
' "$RESP_BODY"; then
  echo "FAIL: Test 12 error message mismatch"
  exit 1
fi
echo "PASS: Test 12"

echo "TEST 13: Submit input validation: bad signatures"
python3 -c '
import sys, json
try:
  with open(sys.argv[1]) as f:
    payload = json.load(f)
  payload["signatures"] = []
  with open(sys.argv[2], "w") as f:
    json.dump(payload, f)
except Exception:
  sys.exit(1)
' "$PAYLOAD_FILE" "$TEMP_DIR/bad_sigs.json"

http_call POST "$API_BASE/submit" "$RESP_BODY" "$RESP_STATUS" \
  -H "Content-Type: application/json" \
  -H "x-user-id: $DEV_USER_ID" \
  -H "x-user-role: $DEV_ROLE" \
  -d @"$TEMP_DIR/bad_sigs.json"
st=$(cat "$RESP_STATUS")
if [ "$st" -ne 400 ]; then
  echo "FAIL: Expected HTTP 400, got $st"
  exit 1
fi
if ! python3 -c '
import sys, json
try:
  with open(sys.argv[1]) as f:
    d = json.load(f)
  if d.get("error") != "signatures must be a non-empty array of non-empty strings": sys.exit(1)
except Exception:
  sys.exit(1)
' "$RESP_BODY"; then
  echo "FAIL: Test 13 error message mismatch"
  exit 1
fi
echo "PASS: Test 13"

echo "TPSR security tests completed successfully"
exit 0
