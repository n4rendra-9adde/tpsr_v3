package main

import (
	"fmt"
	"strings"

	"github.com/hyperledger/fabric-contract-api-go/contractapi"
)

type SBOMContract struct {
	contractapi.Contract
}

type SBOMRecord struct {
	SBOMID               string   `json:"sbomID"`
	Hash                 string   `json:"hash"`
	Timestamp            int64    `json:"timestamp"`
	SubmitterID          string   `json:"submitterID"`
	BuildID              string   `json:"buildID"`
	SoftwareName         string   `json:"softwareName"`
	SoftwareVersion      string   `json:"softwareVersion"`
	Format               string   `json:"format"`
	Status               string   `json:"status"`
	OffChainRef          string   `json:"offChainRef"`
	Signatures           []string `json:"signatures"`
	PolicyStatus         string   `json:"policyStatus"`
	PolicyReason         string   `json:"policyReason"`
	PolicyViolations     []string `json:"policyViolations"`
	PolicyEvaluationMode string   `json:"policyEvaluationMode"`
	TrustStatus          string   `json:"trustStatus,omitempty"`
	TrustReasonCode      string   `json:"trustReasonCode,omitempty"`
	TrustReasonDesc      string   `json:"trustReasonDesc,omitempty"`
	TrustEvaluatedAt     int64    `json:"trustEvaluatedAt,omitempty"`
	TrustEvaluatedBy     string   `json:"trustEvaluatedBy,omitempty"`
	ProvenanceHash       string   `json:"provenanceHash,omitempty"`
	SignatureHashes      []string `json:"signatureHashes"`
	ActiveVexIds         []string `json:"activeVexIds"`
	EffectiveRiskScore   float64  `json:"effectiveRiskScore,omitempty"`
}

func (r *SBOMRecord) EnsureSlices() {
	if r.Signatures == nil {
		r.Signatures = []string{}
	}
	if r.PolicyViolations == nil {
		r.PolicyViolations = []string{}
	}
	if r.SignatureHashes == nil {
		r.SignatureHashes = []string{}
	}
	if r.ActiveVexIds == nil {
		r.ActiveVexIds = []string{}
	}
}

type VerificationResult struct {
	SBOMID        string `json:"sbomID"`
	SubmittedHash string `json:"submittedHash"`
	StoredHash    string `json:"storedHash"`
	Match         bool   `json:"match"`
	Status        string `json:"status"`
}

type HistoryRecord struct {
	TxID      string      `json:"txID"`
	Timestamp int64       `json:"timestamp"`
	IsDelete  bool        `json:"isDelete"`
	Record    *SBOMRecord `json:"record,omitempty"`
}

type RecordTrustEvidenceInput struct {
	Version         string `json:"version"`
	SBOMID          string `json:"sbomID"`
	EvidenceType    string `json:"evidenceType"`
	EvidenceHash    string `json:"evidenceHash"`
	EvidenceId      string `json:"evidenceId"`
	EvidencePayload string `json:"evidencePayload,omitempty"`
}

type RecordTrustDecisionInput struct {
	Version            string   `json:"version"`
	SBOMID             string   `json:"sbomID"`
	DecisionId         string   `json:"decisionId"`
	TrustStatus        string   `json:"trustStatus"`
	ReasonCode         string   `json:"reasonCode"`
	ReasonDescription  string   `json:"reasonDescription"`
	PolicyVersion      string   `json:"policyVersion"`
	IdempotencyKey     string   `json:"idempotencyKey"`
	ProvenanceHash     string   `json:"provenanceHash,omitempty"`
	SignatureHashes    []string `json:"signatureHashes,omitempty"`
	ActiveVexIds       []string `json:"activeVexIds,omitempty"`
	EffectiveRiskScore float64  `json:"effectiveRiskScore,omitempty"`
}

type TrustEvidenceRecord struct {
	EvidenceId      string `json:"evidenceId"`
	SBOMID          string `json:"sbomID"`
	EvidenceType    string `json:"evidenceType"`
	EvidenceHash    string `json:"evidenceHash"`
	EvidencePayload string `json:"evidencePayload,omitempty"`
	RecordedAt      int64  `json:"recordedAt"`
	RecordedBy      string `json:"recordedBy"`
}

type TrustDecisionPointer struct {
	DecisionId         string   `json:"decisionId"`
	SBOMID             string   `json:"sbomID"`
	TrustStatus        string   `json:"trustStatus"`
	ReasonCode         string   `json:"reasonCode"`
	ReasonDescription  string   `json:"reasonDescription"`
	PolicyVersion      string   `json:"policyVersion"`
	IdempotencyKey     string   `json:"idempotencyKey"`
	ProvenanceHash     string   `json:"provenanceHash,omitempty"`
	SignatureHashes    []string `json:"signatureHashes,omitempty"`
	ActiveVexIds       []string `json:"activeVexIds,omitempty"`
	EffectiveRiskScore float64  `json:"effectiveRiskScore,omitempty"`
	RecordedAt         int64    `json:"recordedAt"`
	RecordedBy         string   `json:"recordedBy"`
}

// TrustDecisionResponse is a stable query-return contract that preserves the shape
// of the stored TrustDecisionPointer but guarantees that optional or sparse fields
// are always present in the generated Fabric Contract API schema and response payload.
// Empty slices and zero values are returned explicitly, meaning "not supplied", not "verified".
type TrustDecisionResponse struct {
	DecisionId         string   `json:"decisionId"`
	SBOMID             string   `json:"sbomID"`
	TrustStatus        string   `json:"trustStatus"`
	ReasonCode         string   `json:"reasonCode"`
	ReasonDescription  string   `json:"reasonDescription"`
	PolicyVersion      string   `json:"policyVersion"`
	IdempotencyKey     string   `json:"idempotencyKey"`
	ProvenanceHash     string   `json:"provenanceHash"`
	SignatureHashes    []string `json:"signatureHashes"`
	ActiveVexIds       []string `json:"activeVexIds"`
	EffectiveRiskScore float64  `json:"effectiveRiskScore"`
	RecordedAt         int64    `json:"recordedAt"`
	RecordedBy         string   `json:"recordedBy"`
}

const (
	StatusRegistered       = "REGISTERED"
	StatusReviewPending    = "REVIEW_PENDING"
	StatusSecurityReviewed = "SECURITY_REVIEWED"
	StatusCompliant        = "COMPLIANT"
	StatusApproved         = "APPROVED"
	StatusActive           = "ACTIVE"
	StatusSuperseded       = "SUPERSEDED"
	StatusRejected         = "REJECTED"

	// Authoritative TPSR v3 trust decisions (four-state model)
	TrustStatusTrusted               = "TRUSTED"
	TrustStatusConditionallyAccepted = "CONDITIONALLY_ACCEPTED"
	TrustStatusReviewRequired        = "REVIEW_REQUIRED"
	TrustStatusRejected              = "REJECTED"

	// UNEVALUATED is allowed only as a cached/presentation status for records
	// that have not undergone authoritative TPSR v3 evaluation.
	TrustStatusUnevaluated = "UNEVALUATED"

	// TrustStatusUntrustedLegacy is a READ-ONLY compatibility alias for historical
	// records stored before the v3 enum migration. It must never be written as an
	// authoritative decision. New evaluations must use TrustStatusRejected.
	TrustStatusUntrustedLegacy = "UNTRUSTED"
)

// validateSHA256Digest enforces canonical SHA-256 formatting.
func validateSHA256Digest(digest string) error {
	if digest == "" {
		return fmt.Errorf("digest cannot be empty")
	}
	if !strings.HasPrefix(digest, "sha256:") {
		return fmt.Errorf("digest must start with 'sha256:' prefix")
	}
	hexPart := strings.TrimPrefix(digest, "sha256:")
	if len(hexPart) != 64 {
		return fmt.Errorf("digest hexadecimal part must be exactly 64 characters long")
	}
	for _, c := range hexPart {
		if !(c >= '0' && c <= '9') && !(c >= 'a' && c <= 'f') {
			return fmt.Errorf("digest hexadecimal part must contain only lowercase hex characters [0-9a-f]")
		}
	}
	return nil
}

// validateOptionalSHA256Digest validates a SHA-256 digest only if it is not empty.
func validateOptionalSHA256Digest(digest string) error {
	if digest == "" {
		return nil
	}
	return validateSHA256Digest(digest)
}

type SBOMRecordResponse struct {
	SBOMID               string   `json:"sbomID"`
	Hash                 string   `json:"hash"`
	Timestamp            int64    `json:"timestamp"`
	SubmitterID          string   `json:"submitterID"`
	BuildID              string   `json:"buildID"`
	SoftwareName         string   `json:"softwareName"`
	SoftwareVersion      string   `json:"softwareVersion"`
	Format               string   `json:"format"`
	Status               string   `json:"status"`
	OffChainRef          string   `json:"offChainRef"`
	Signatures           []string `json:"signatures"`
	PolicyStatus         string   `json:"policyStatus"`
	PolicyReason         string   `json:"policyReason"`
	PolicyViolations     []string `json:"policyViolations"`
	PolicyEvaluationMode string   `json:"policyEvaluationMode"`
	TrustStatus          string   `json:"trustStatus"`
	TrustReasonCode      string   `json:"trustReasonCode"`
	TrustReasonDesc      string   `json:"trustReasonDesc"`
	TrustEvaluatedAt     int64    `json:"trustEvaluatedAt"`
	TrustEvaluatedBy     string   `json:"trustEvaluatedBy"`
	ProvenanceHash       string   `json:"provenanceHash"`
	SignatureHashes      []string `json:"signatureHashes"`
	ActiveVexIds         []string `json:"activeVexIds"`
	EffectiveRiskScore   float64  `json:"effectiveRiskScore"`
}

type HistoryRecordResponse struct {
	TxID      string              `json:"txID"`
	Timestamp int64               `json:"timestamp"`
	IsDelete  bool                `json:"isDelete"`
	Record    *SBOMRecordResponse `json:"record"`
}
