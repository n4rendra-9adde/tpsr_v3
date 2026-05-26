package main

import (
	"github.com/hyperledger/fabric-contract-api-go/contractapi"
)

type SBOMContract struct {
	contractapi.Contract
}

type SBOMRecord struct {
	SBOMID          string   `json:"sbomID"`
	Hash            string   `json:"hash"`
	Timestamp       int64    `json:"timestamp"`
	SubmitterID     string   `json:"submitterID"`
	BuildID         string   `json:"buildID"`
	SoftwareName    string   `json:"softwareName"`
	SoftwareVersion string   `json:"softwareVersion"`
	Format          string   `json:"format"`
	Status          string   `json:"status"`
	OffChainRef          string   `json:"offChainRef"`
	Signatures           []string `json:"signatures"`
	PolicyStatus         string   `json:"policyStatus"`
	PolicyReason         string   `json:"policyReason"`
	PolicyViolations     []string `json:"policyViolations"`
	PolicyEvaluationMode string   `json:"policyEvaluationMode"`
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

const (
	StatusRegistered       = "REGISTERED"
	StatusReviewPending    = "REVIEW_PENDING"
	StatusSecurityReviewed = "SECURITY_REVIEWED"
	StatusCompliant        = "COMPLIANT"
	StatusApproved         = "APPROVED"
	StatusActive           = "ACTIVE"
	StatusSuperseded       = "SUPERSEDED"
	StatusRejected         = "REJECTED"
)
