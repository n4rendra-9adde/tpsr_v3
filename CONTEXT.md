# TPSR Project Context — Read This First
## Project
Tamper-Proof SBOM Registry — Blockchain-Based SBOM Integrity System
## Background Document
Full requirements and system design are in the uploaded file TPSR_Requirements_SystemDesign.docx
## Implementation Progress
### COMPLETED STEPS
Step 1.1 — Folder structure created and verified
Step 1.2 — go.mod initialized with module github.com/tpsr/chaincode/sbom, Go 1.22, fabric-contract-api-go v1.2.1, fabric-chaincode-go v0.6.0
Step 1.3 — Initialize Node.js API package.json
Step 1.4 — Initialize React dashboard package.json
Step 2.1 — Create crypto-config.yaml
Step 2.2 — Create configtx.yaml
Step 2.3 — Create docker-compose.yaml
Step 2.4 — Generate certificates
Step 2.5 — Start network and verify
Step 2.6 — Create channel and verify
Step 3.1 — Define chaincode data structures
Step 3.2 — Write SubmitSBOM function
Step 3.3 — Write VerifyIntegrity function
Step 3.4 — Write GetHistory function
Step 3.5 — Write error handling
Step 3.6 — Write unit tests
Step 3.6A — Create chaincode main.go
Step 3.7 — Deploy and test chaincode
Step 4.1 — Setup Express server
Step 4.2 — Setup Fabric SDK connection
Step 4.3 — Write canonicalization module
Step 4.4 — Write SHA-256 hashing module
Step 4.5 — Write submit endpoint
Step 4.6 — Write verify endpoint
Step 4.7 — Write history endpoint
Step 4.8 — Write compliance report endpoint
Step 4.9 — Write authentication middleware
Step 4.10 — Test all endpoints
Step 5.1 — Setup React project
Step 5.2 — Build SBOM list component
Step 5.3 — Build verification component
Step 5.4 — Build history component
Step 5.5 — Build compliance report component
Step 5.6 — Connect components to REST API
Step 6.1 — Write Jenkins plugin
Step 6.2 — Write GitLab CI plugin
Step 6.3 — Write verification CLI
Step 7.1 — Functional testing
Step 7.2 — Performance testing
Step 7.3 — Security testing
Step 7.4 — Tamper detection validation
*** Testing Phase Complete ***
Step 8.1 — Create deployment runbook (tpsr/DEPLOYMENT.md)
Step 8.2 — Create project README (tpsr/README.md)
Step 8.3 — Add /api/sboms endpoint + complete dashboard live integration
Step 8.4 — Production hardening and final deployment packaging
*** Deployment Packaging Phase Complete ***
Step 9.1 — Deploy the packaged system (tpsr/deployment/deploy.sh + deploy.env.example + DEPLOYMENT-EXECUTION.md)
Step 9.2 — Validate live deployment (tpsr/deployment/VALIDATION.md)
Step 9.3 — Final system audit and project closure
*** Phase 1 Complete ***
Phase 2 — Hybrid Storage and Provenance Layer
Step 2.1B — Create initial PostgreSQL migration (tpsr/db/migrations/001_init_postgresql.sql)
Step 2.1C — Add PostgreSQL environment placeholders and DB connection module (tpsr/api/src/config/database.js)
Step 2.1D — Create PostgreSQL local runtime configuration (tpsr/db/docker-compose.postgres.yaml)
Step 2.1E — Start local PostgreSQL runtime and verify readiness
Step 2.1F — Apply the initial PostgreSQL migration and verify schema creation
Step 2.1G — Wire PostgreSQL startup validation into the API (tpsr/api/src/server.js)
Step 2.1H — Start TPSR API with PostgreSQL enabled and verify startup
Step 2.2A — Create PostgreSQL data-access module for SBOM documents and artifact records
Step 2.2B — Extend repository with SBOM document finalization update
Step 2.2C — Extend repository with rollback delete helper
Step 2.2D — Integrate PostgreSQL into submit route with rollback-safe two-phase persistence
Step 2.2E — Extend repository with SBOM list query for PostgreSQL-backed /api/sboms
Step 2.2F — Rewire `/api/sboms` route to PostgreSQL-backed listing
Step 2.2G — Start API and verify PostgreSQL-backed `/api/sboms` runtime
Step 2.2H — Runtime validate the new two-phase submit flow (PostgreSQL + Fabric)
Step 2.2I.1 — Extend repository with verification event insert helper
Step 2.2I.2 — Rewire `verify.js` to use PostgreSQL + Fabric hybrid verification
Step 2.2I.3 — Runtime validate hybrid verification and verification event persistence
Step 2.2J.1 — Extend repository with compliance report insert helper
Step 2.2J.2 — Rewire `compliance-report.js` to use PostgreSQL + Fabric hybrid compliance persistence
Step 2.2J.3 — Runtime validate hybrid compliance report and compliance report persistence
Step 2.2K — Rewire `history.js` to use PostgreSQL + Fabric hybrid history
Step 2.2K.1 — Runtime validate hybrid history response
Step 2.2L — Capture and persist Fabric transaction ID in PostgreSQL finalization
Step 2.2L.1 — Runtime validate Fabric transaction ID persistence
Step 2.2M — Capture and persist Fabric submitter identity in PostgreSQL finalization
Step 2.2M.1 — Runtime validate submitterID persistence
Step 2.2N — Runtime regression validate the complete hybrid API flow
Step 2.3A — Extend Jenkins shared library to submit Phase-2 artifact and provenance fields
Step 2.3B — Update Jenkins test pipeline to call the Phase-2 shared library fields
Step 2.3C — Runtime validate Jenkins Phase-2 submission path
Step 2.3D.1 — Runtime validate SBOM document fetch/download endpoint
Step 2.3E — Add dashboard actions to view / copy / download stored SBOM JSON

Step 2.3E.1 — Runtime validate dashboard View / Copy / Download SBOM actions
Step 2.4A — Enhance Jenkins submission to pass richer provenance fields
Step 2.4A.1 — Runtime validate Jenkins richer provenance fields
Step 2.4B — Add Requested By and Job Name to dashboard SBOM list
Step 2.5A — Add minimal SBOM lifecycle approval flow
Step 2.5A.1 — Runtime validate SBOM lifecycle approval flow
Step 2.7A — Basic performance measurements for TPSR
Step 2.7B — Add dashboard Approve button with role-aware access control

### CURRENT STEP
Waiting for next Phase-2 instructions
## Key Architecture Decisions
Blockchain — Hyperledger Fabric 2.5 with Raft consensus
Organizations — Vendor, Security Team, Auditor
Chaincode language — Go
State database — CouchDB
Consensus — Raft CFT sufficient for permissioned network
Off-chain storage — IPFS for raw SBOM files, PostgreSQL for parsed metadata
XML handling — Convert XML to JSON before canonicalization
Multi-signature — Two stage pipeline, developer automated, security team manual approval gate
Verification modes — API mode and direct Fabric CLI mode for true zero-trust
Channel vs PDC — Single channel now, PDC-compatible design for future
## Data Structure — SBOM Record on Blockchain
sbomID — unique ID combining software name and build number
hash — SHA-256 hash of canonicalized SBOM
timestamp — Unix timestamp of submission
submitterID — X.509 identity of submitter
buildID — CI/CD build number
softwareName — name of software product
softwareVersion — version of software product
format — SPDX or CycloneDX
status — PENDING, APPROVED, ACTIVE, or SUPERSEDED
offChainRef — IPFS CID or PostgreSQL reference
signatures — array of cryptographic signatures
## Technology Versions
Hyperledger Fabric — 2.5.0
Go — 1.22.2
Node.js — 18.x
React — 18.x
Docker — 29.3.0
Ubuntu — 22.04 LTS
fabric-contract-api-go — v1.2.1
fabric-chaincode-go — v0.6.0
fabric-network npm — 2.2.20
## Important Rules
Never move to next step without approval
Always read this file at start of every session
Update COMPLETED STEPS and CURRENT STEP after every approved step
Never hallucinate function names or API calls
Always refer to the uploaded requirements document for specifications
