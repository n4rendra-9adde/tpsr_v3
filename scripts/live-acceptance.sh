#!/bin/bash
set -euo pipefail

echo "=== STARTING LIVE_ACCEPTANCE ==="
BASE_URL="http://localhost:3000/api"
V1_URL="http://localhost:3000/api/v1"
SBOM_ID="live-sbom-$(date +%s)"
VALID_UNTIL=$(date -u -d "+10 days" +"%Y-%m-%dT%H:%M:%SZ")

assert_status() {
  local expected=$1
  local actual=$2
  local msg=$3
  if [ "$expected" != "$actual" ]; then
    echo "FAIL: $msg (Expected $expected, got $actual)"
    exit 1
  fi
}

echo "=== 1. HEALTH AND AUTH ==="
curl -s -w "%{http_code}" -o /tmp/health.json "http://localhost:3000/health" > /tmp/health_status.txt
assert_status "200" "$(cat /tmp/health_status.txt)" "Health check"

curl -s -w "%{http_code}" -o /tmp/readiness.json "http://localhost:3000/readiness" > /tmp/readiness_status.txt
assert_status "200" "$(cat /tmp/readiness_status.txt)" "Readiness check"

# Missing auth
curl -s -w "%{http_code}" -o /tmp/submit_no_auth.json -X POST "$BASE_URL/submit" -H "Content-Type: application/json" -d "{}" > /tmp/submit_no_auth_status.txt
assert_status "403" "$(cat /tmp/submit_no_auth_status.txt)" "Missing auth"

# Unknown role
curl -s -w "%{http_code}" -o /tmp/submit_bad_role.json -X POST "$BASE_URL/submit" -H "x-user-id:ops" -H "x-user-role:unknown" -H "Content-Type: application/json" -d "{}" > /tmp/submit_bad_role_status.txt
assert_status "403" "$(cat /tmp/submit_bad_role_status.txt)" "Unknown role"

echo "=== 2. SBOM ==="
USER_HEADER="-H x-user-id:ops -H x-user-role:developer"
curl -s -w "%{http_code}" -o /tmp/sbom_submit_res.json -X POST "$BASE_URL/submit" $USER_HEADER -H "Content-Type: application/json" -d "{
  \"sbomID\": \"$SBOM_ID\",
  \"buildID\": \"build-123\",
  \"softwareName\": \"test-app\",
  \"softwareVersion\": \"1.0.0\",
  \"format\": \"SPDX\",
  \"offChainRef\": \"http://example.com/sbom\",
  \"signatures\": [\"sig1\"],
  \"artifactName\": \"app.tar.gz\",
  \"artifactType\": \"ARCHIVE\",
  \"artifactHash\": \"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855\",
  \"sbom\": { \"name\": \"test-app\", \"version\": \"1.0.0\", \"components\": [] }
}" > /tmp/sbom_submit_status.txt
assert_status "201" "$(cat /tmp/sbom_submit_status.txt)" "SBOM submit"

# Verify retrieve
curl -s -w "%{http_code}" -o /tmp/sbom_verify_res.json -X POST "$BASE_URL/verify" -H "x-user-id:auditor1" -H "x-user-role:auditor" -H "Content-Type: application/json" -d "{
  \"sbomID\": \"$SBOM_ID\",
  \"sbom\": { \"name\": \"test-app\", \"version\": \"1.0.0\", \"components\": [] }
}" > /tmp/sbom_verify_status.txt
assert_status "200" "$(cat /tmp/sbom_verify_status.txt)" "SBOM verify"

echo "=== 4. TRUST DECISION ==="
USER_HEADER="-H x-user-id:ops -H x-user-role:security"
curl -s -w "%{http_code}" -o /tmp/trust_eval_res.json -X POST "$V1_URL/sbom/$SBOM_ID/trust-evaluation" $USER_HEADER -H "Content-Type: application/json" -d "{
  \"idempotencyKey\": \"test-eval-$(date +%s)\"
}" > /tmp/trust_eval_status.txt
# Trust evaluation returns 201 or 200, wait, it returns 201 if created!
ST="$(cat /tmp/trust_eval_status.txt)"
if [ "$ST" != "201" ] && [ "$ST" != "200" ]; then
  echo "FAIL: Trust eval (Expected 2xx, got $ST)"
  cat /tmp/trust_eval_res.json
  exit 1
fi

echo "=== 6. CONTEXT ==="
curl -s -w "%{http_code}" -o /tmp/context_res.json -X POST "$V1_URL/sbom/$SBOM_ID/context/assertions" $USER_HEADER -H "Content-Type: application/json" -d "{
  \"assertion\": {
    \"cveId\": \"CVE-2023-1234\",
    \"status\": \"not_affected\",
    \"environment\": \"PRODUCTION\",
    \"evidenceSource\": \"Manual Review\",
    \"justification\": \"Vulnerable code not executed\"
  }
}" > /tmp/context_status.txt
assert_status "201" "$(cat /tmp/context_status.txt)" "Context assertion"

echo "=== 7. EXCEPTION ==="
# Request exception
curl -s -w "%{http_code}" -o /tmp/exc_req_res.json -X POST "$V1_URL/sbom/$SBOM_ID/exceptions" $USER_HEADER -H "Content-Type: application/json" -d "{
  \"policyRuleId\": \"CAECTD-R017\",
  \"reasonCode\": \"LEGACY_EXC\",
  \"justification\": \"Legacy system\",
  \"remediationPlan\": \"Will fix next month\",
  \"residualRisk\": \"LOW\",
  \"validUntil\": \"$VALID_UNTIL\"
}" > /tmp/exc_req_status.txt
assert_status "201" "$(cat /tmp/exc_req_status.txt)" "Exception request"
EXC_ID=$(jq -r .id < /tmp/exc_req_res.json)

# Self-approval by requester A rejected
curl -s -w "%{http_code}" -o /tmp/exc_self_app_res.json -X POST "$V1_URL/sbom/$SBOM_ID/exceptions/$EXC_ID/approve" $USER_HEADER > /tmp/exc_self_app_status.txt
assert_status "403" "$(cat /tmp/exc_self_app_status.txt)" "Exception self-approval"

# Approve exception as different user
curl -s -w "%{http_code}" -o /tmp/exc_app_res.json -X POST "$V1_URL/sbom/$SBOM_ID/exceptions/$EXC_ID/approve" -H "x-user-id:approver1" -H "x-user-role:security" > /tmp/exc_app_status.txt
assert_status "200" "$(cat /tmp/exc_app_status.txt)" "Exception approval"

# Revocation by authorized principal
curl -s -w "%{http_code}" -o /tmp/exc_rev_res.json -X POST "$V1_URL/sbom/$SBOM_ID/exceptions/$EXC_ID/revoke" -H "x-user-id:approver1" -H "x-user-role:security" -H "Content-Type: application/json" -d "{\"revocationReason\": \"No longer needed\"}" > /tmp/exc_rev_status.txt
assert_status "200" "$(cat /tmp/exc_rev_status.txt)" "Exception revocation"

echo "=== 8. POLICY LIFECYCLE ==="
curl -s -w "%{http_code}" -o /tmp/policy_reload.json -X POST "$V1_URL/policy/reload" -H "x-user-id:adminUser" -H "x-user-role:admin" > /tmp/policy_reload_status.txt
assert_status "200" "$(cat /tmp/policy_reload_status.txt)" "Policy reload"

echo "=== 9 & 10. SNAPSHOT AND REPLAY ==="
SNAP_ID=$(jq -r .snapshotId < /tmp/trust_eval_res.json)
if [ "$SNAP_ID" != "null" ]; then
  curl -s -w "%{http_code}" -o /tmp/snapshot_verify.json -X POST "$V1_URL/replay/$SNAP_ID/verify" -H "x-user-id:auditor1" -H "x-user-role:auditor" > /tmp/snapshot_verify_status.txt
  assert_status "200" "$(cat /tmp/snapshot_verify_status.txt)" "Snapshot verify"
else
  echo "FAIL: Snapshot ID missing from trust evaluation"
  exit 1
fi

echo "LIVE_ACCEPTANCE script complete. All workflows passed."
