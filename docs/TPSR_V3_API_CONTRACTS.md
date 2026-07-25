# TPSR v3 Formal API Contracts

This document defines the authoritative OpenAPI 3.0 compatible request/response contracts for all TPSR v3 endpoints. All authoritative mutation endpoints require standard TPSR authentication (`x-user-id`, `x-user-role`) and enforce strict schema validation via Ajv.

---

## 1. Provenance Attestation Submission
**Endpoint:** `POST /api/v1/sbom/:sbomId/provenance`  
**Description:** Submits a SLSA-compatible build provenance attestation (in-toto v0.1/v1 envelope with `https://slsa.dev/provenance/v1` or v0.2 predicate) and binds it to the target SBOM document and artifact hash.

### Headers
- `x-user-id`: string (required) - Submitter identity
- `x-user-role`: string (required) - Role (`developer`, `build-system`, `admin`)
- `Content-Type`: `application/json` (required)
- `Idempotency-Key`: string (optional UUID)

### Request Body
```json
{
  "attestationPayload": {
    "_type": "https://in-toto.io/Statement/v0.1",
    "subject": [
      {
        "name": "test-artifact.jar",
        "digest": {
          "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        }
      }
    ],
    "predicateType": "https://slsa.dev/provenance/v1",
    "predicate": {
      "buildDefinition": {
        "buildType": "https://actions.github.io/buildtypes/workflow/v1",
        "externalParameters": {
          "workflow": {
            "ref": "refs/tags/v1.0.0",
            "repository": "https://github.com/org/repo"
          }
        },
        "internalParameters": {
          "github": {
            "runner_environment": "github-hosted"
          }
        },
        "resolvedDependencies": []
      },
      "runDetails": {
        "builder": {
          "id": "https://github.com/actions/runner/github-hosted"
        },
        "metadata": {
          "invocationId": "7343609804"
        }
      }
    }
  },
  "attestationType": "SLSA_PROVENANCE_V1",
  "buildEnvironment": "GITHUB_ACTIONS",
  "builderIdentity": "https://github.com/actions/runner/github-hosted"
}
```

### Response (201 Created)
```json
{
  "message": "Provenance attestation submitted successfully",
  "evidenceId": "91541d62-fe09-4f30-9307-c766e8509a88",
  "sbomId": "demo-approve-001",
  "attestationHash": "a1b2c3d4...",
  "slsaLevel": "SLSA_BUILD_LEVEL_3",
  "status": "VALID"
}
```

---

## 2. Cryptographic Signature Verification
**Endpoint:** `POST /api/v1/sbom/:sbomId/signatures`  
**Description:** Verifies a cryptographic signature against an artifact hash using Sigstore Cosign CLI (supports `offline-keyed` or `keyless` bundle verification).

### Headers
- `x-user-id`: string (required)
- `x-user-role`: string (required) - Role (`developer`, `security`, `admin`)
- `Content-Type`: `application/json` (required)

### Request Body (`offline-keyed`)
```json
{
  "signatureType": "OFFLINE_KEYED",
  "signatureValue": "MEUCIQDx...base64...",
  "publicKey": "-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE...\n-----END PUBLIC KEY-----",
  "artifactHash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
  "signerIdentity": "build-officer@tpsr.com"
}
```

### Request Body (`keyless`)
```json
{
  "signatureType": "KEYLESS",
  "bundleJson": {
    "mediaType": "application/vnd.dev.sigstore.bundle+json;version=0.1",
    "verificationMaterial": {
      "certificate": {
        "rawBytes": "...base64..."
      }
    },
    "messageSignature": {
      "messageDigest": {
        "algorithm": "SHA256",
        "digest": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
      },
      "signature": "...base64..."
    }
  },
  "expectedIssuer": "https://token.actions.githubusercontent.com",
  "expectedSubject": "https://github.com/org/repo/.github/workflows/build.yml@refs/tags/v1.0.0"
}
```

### Response (201 Created)
```json
{
  "message": "Signature verified and recorded successfully",
  "verificationId": "183e5444-59dd-4cdd-866c-48e85a9d8dbc",
  "sbomId": "demo-approve-001",
  "verificationStatus": "VERIFIED",
  "signatureHash": "f8e7d6...",
  "signerIdentity": "https://github.com/org/repo/.github/workflows/build.yml@refs/tags/v1.0.0",
  "verifiedAt": "2026-07-25T17:20:00Z"
}
```

---

## 3. VEX Statement Overlay Submission
**Endpoint:** `POST /api/v1/sbom/:sbomId/vex`  
**Description:** Submits an OpenVEX or CSAF VEX statement as a non-destructive applicability overlay. Preserves raw CVSS scores and original vulnerabilities while applying authorized policy impact adjustments.

### Headers
- `x-user-id`: string (required)
- `x-user-role`: string (required) - Role (`security`, `admin`)
- `Content-Type`: `application/json` (required)

### Request Body
```json
{
  "statementPayload": {
    "@context": "https://openvex.dev/ns/v0.2.0",
    "@id": "https://openvex.dev/docs/public/vex-91541d62",
    "author": "security-team@tpsr.com",
    "timestamp": "2026-07-25T17:00:00Z",
    "version": 1,
    "statements": [
      {
        "vulnerability": {
          "name": "CVE-2023-12345"
        },
        "products": [
          {
            "@id": "pkg:maven/com.example/test-artifact@1.0.0"
          }
        ],
        "status": "not_affected",
        "justification": "vulnerable_code_not_reachable",
        "impact_statement": "The vulnerable method is never invoked in our execution path."
      }
    ]
  },
  "policyValidUntil": "2027-07-25T17:00:00Z",
  "issuerIdentity": "security-team@tpsr.com"
}
```

### Response (201 Created)
```json
{
  "message": "VEX statement overlay applied successfully",
  "vexId": "82736451-aaee-4f30-9307-c766e8509a88",
  "sbomId": "demo-approve-001",
  "vulnerabilityId": "CVE-2023-12345",
  "originalSeverity": "HIGH",
  "originalCvss": 7.8,
  "applicabilityStatus": "NOT_AFFECTED",
  "policyImpact": "SUPPRESSED_BY_OVERLAY",
  "justification": "VULNERABLE_CODE_NOT_REACHABLE"
}
```

---

## 4. Deployment Context Registration
**Endpoint:** `POST /api/v1/sbom/:sbomId/context`  
**Description:** Registers deployment environment context (`PRODUCTION`, `STAGING`, `ISOLATED_EDGE`) and network exposure characteristics (`PUBLIC_INTERNET`, `INTERNAL_ONLY`, `AIR_GAPPED`) to adjust context-aware vulnerability risk scoring.

### Headers
- `x-user-id`: string (required)
- `x-user-role`: string (required) - Role (`developer`, `security`, `admin`, `devops`)
- `Content-Type`: `application/json` (required)

### Request Body
```json
{
  "environment": "PRODUCTION",
  "networkExposure": "INTERNAL_ONLY",
  "dataSensitivity": "CONFIDENTIAL",
  "privilegeLevel": "NON_ROOT",
  "compensatingControls": [
    "WAF_ENABLED",
    "MTLS_REQUIRED",
    "READ_ONLY_ROOT_FILESYSTEM"
  ]
}
```

### Response (201 Created)
```json
{
  "message": "Deployment context registered successfully",
  "contextId": "55443322-1100-4f30-9307-c766e8509a88",
  "sbomId": "demo-approve-001",
  "riskMultiplier": 0.65,
  "effectiveEnvironment": "PRODUCTION"
}
```

---

## 5. Security Policy Exception Request
**Endpoint:** `POST /api/v1/sbom/:sbomId/exceptions`  
**Description:** Submits a time-bound security exception for a specific vulnerability or policy violation. Requires role `security` or `admin` and must include an explicit expiration date and risk acceptance justification.

### Headers
- `x-user-id`: string (required)
- `x-user-role`: string (required) - Role (`security`, `admin`)
- `Content-Type`: `application/json` (required)

### Request Body
```json
{
  "violationId": "CVE-2023-99999",
  "violationType": "VULNERABILITY_SEVERITY_EXCEEDED",
  "justification": "Patch scheduled for Q3 release; mitigating WAF rules deployed under ticket SEC-1024.",
  "validUntil": "2026-08-25T17:00:00Z",
  "compensatingControls": "WAF rule block ID #4092 active on gateway"
}
```

### Response (201 Created)
```json
{
  "message": "Policy exception recorded successfully",
  "exceptionId": "77889900-aabb-4f30-9307-c766e8509a88",
  "sbomId": "demo-approve-001",
  "status": "APPROVED",
  "validUntil": "2026-08-25T17:00:00Z"
}
```

---

## 6. Authoritative Trust Evaluation
**Endpoint:** `POST /api/v1/sbom/:sbomId/trust-evaluation`  
**Description:** Triggers the authoritative 13-step trust evaluation engine. Computes an immutable trust decision (`TRUSTED`, `CONDITIONALLY_ACCEPTED`, `REVIEW_REQUIRED`, `REJECTED`), stores the audit snapshot in PostgreSQL, and enqueues an outbox record for Fabric anchoring. Enforces mandatory idempotency.

### Headers
- `x-user-id`: string (required)
- `x-user-role`: string (required) - Role (`auditor`, `security`, `admin`)
- `Idempotency-Key`: string (required UUID)
- `Content-Type`: `application/json` (required)

### Request Body
```json
{
  "evaluationTrigger": "MANUAL_AUDIT",
  "policyVersion": "v3.0.0-20260725",
  "includeEvidenceSummary": true
}
```

### Response (200 OK / 201 Created)
```json
{
  "message": "Trust evaluation completed successfully",
  "decisionId": "11223344-5566-4f30-9307-c766e8509a88",
  "sbomId": "demo-approve-001",
  "trustStatus": "TRUSTED",
  "reasonCode": "GOV-001",
  "reasonDescription": "All provenance, signature, and vulnerability compliance policies passed.",
  "evaluatedAt": "2026-07-25T17:22:00Z",
  "outboxStatus": "PENDING",
  "outboxId": "99887766-5544-4f30-9307-c766e8509a88",
  "evidenceSummary": {
    "provenanceSlsaLevel": "SLSA_BUILD_LEVEL_3",
    "signatureCount": 2,
    "verifiedSignatures": 2,
    "activeVexOverlays": 1,
    "effectiveRiskScore": 2.4,
    "activeExceptions": 0
  }
}
```

---

## 7. Get Latest Trust Decision
**Endpoint:** `GET /api/v1/sbom/:sbomId/trust-decision`  
**Description:** Retrieves the current authoritative trust decision and ledger outbox anchoring status for the specified SBOM ID.

### Headers
- `x-user-id`: string (required)
- `x-user-role`: string (required) - Role (`developer`, `auditor`, `security`, `admin`, `devops`)

### Response (200 OK)
```json
{
  "sbomId": "demo-approve-001",
  "decisionId": "11223344-5566-4f30-9307-c766e8509a88",
  "trustStatus": "TRUSTED",
  "reasonCode": "GOV-001",
  "reasonDescription": "All provenance, signature, and vulnerability compliance policies passed.",
  "evaluatedAt": "2026-07-25T17:22:00Z",
  "evaluatedBy": "tpsr-security-sec",
  "outboxStatus": "COMPLETED",
  "fabricTxId": "02e8cf6ca469c1e557db4b57b4a1c55801888d49bed330166686f6d31ccb6f74",
  "ledgerAnchoredAt": "2026-07-25T17:22:05Z"
}
```

---

## 8. Get Trust Evidence History
**Endpoint:** `GET /api/v1/sbom/:sbomId/trust-evidence`  
**Description:** Retrieves the complete historical timeline of trust evaluations, provenance submissions, signature verifications, and VEX statements for the specified SBOM ID.

### Headers
- `x-user-id`: string (required)
- `x-user-role`: string (required) - Role (`auditor`, `security`, `admin`)

### Response (200 OK)
```json
{
  "sbomId": "demo-approve-001",
  "currentTrustStatus": "TRUSTED",
  "evidenceHistory": [
    {
      "eventType": "TRUST_EVALUATION",
      "eventId": "11223344-5566-4f30-9307-c766e8509a88",
      "timestamp": "2026-07-25T17:22:00Z",
      "status": "TRUSTED",
      "reasonCode": "GOV-001",
      "actorId": "tpsr-security-sec"
    },
    {
      "eventType": "VEX_OVERLAY_APPLIED",
      "eventId": "82736451-aaee-4f30-9307-c766e8509a88",
      "timestamp": "2026-07-25T17:18:00Z",
      "status": "NOT_AFFECTED",
      "details": "CVE-2023-12345 suppressed by overlay justification VULNERABLE_CODE_NOT_REACHABLE",
      "actorId": "security-team@tpsr.com"
    }
  ]
}
```

---

## 9. Admin Outbox Requeue
**Endpoint:** `POST /api/v1/admin/outbox/:outboxId/requeue`  
**Description:** Allows an authorized administrator (`admin` role only) to requeue a failed ledger outbox record from `FAILED_REQUIRES_REVIEW` back to `PENDING` for worker retry after addressing infrastructure or network connectivity issues.

### Headers
- `x-user-id`: string (required)
- `x-user-role`: `admin` (required)
- `Content-Type`: `application/json` (required)

### Request Body
```json
{
  "reason": "Peer node network connectivity restored after firewall maintenance."
}
```

### Response (200 OK)
```json
{
  "message": "Outbox record requeued successfully",
  "outboxId": "99887766-5544-4f30-9307-c766e8509a88",
  "previousStatus": "FAILED_REQUIRES_REVIEW",
  "newStatus": "PENDING",
  "requeuedAt": "2026-07-25T17:25:00Z",
  "requeuedBy": "tpsr-security-admin"
}
```
