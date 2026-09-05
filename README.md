# TPSR: A Context and Provenance-Aware, Tamper-Proof SBOM Registry and Lifecycle Management Framework

## Project Summary
The Tamper-Proof SBOM Registry (TPSR) is a prototype-scale, tamper-evident Software Bill of Materials (SBOM) registry. It is designed to secure the software supply chain by providing post-generation artifact integrity, immutable audit history, and strict policy-driven lifecycle governance within defined trust assumptions.

TPSR is built on a hybrid architecture that leverages:
- **Hyperledger Fabric** for immutable cryptographic anchoring and state transitions.
- **PostgreSQL** for high-performance, off-chain JSON storage and complex querying.
- **Node.js API** for robust policy evaluation, tamper intelligence, and performance instrumentation.
- **React Dashboard** (hosted on GitHub Pages) for role-aware operational visibility.
- **Go Chaincode** for ledger interactions.

## Problem Statement
Software supply chain integrity is a critical challenge in modern development. To trust dependencies and build artifacts, organizations must be able to detect post-generation SBOM tampering. TPSR provides full traceability, non-repudiation, and cryptographically verifiable validation of SBOM records, ensuring they have not been maliciously or accidentally altered within the system's operational trust boundaries.

## Core Capabilities
- **CAECTD Trust Governance**: 4-state Trust Model (`TRUSTED`, `CONDITIONALLY_ACCEPTED`, `REVIEW_REQUIRED`, `REJECTED`) supporting VEX overlays and Deployment Context Assertions.
- **Transactional Outbox Pattern**: Decouples API ingestion from blockchain consensus, demonstrating asynchronous processing capabilities (tested with ~1,250 records).
- **Upstream Verification**: Built-in verification of externally generated, explicitly keyed Cosign signatures and SLSA Level 3 provenance envelopes.
- **Advanced Tamper Intelligence**: Custom diff engine categorizes tampering into `COMPONENT_INJECTION`, `COMPONENT_REMOVAL`, `VERSION_MODIFICATION`, and `METADATA_MODIFICATION`.
- **High-Resolution Performance Telemetry**: `hrtime.bigint()` instrumentation proves end-to-end ingestion returns in ~45ms.
- **Role-Based Access Control (RBAC)**: Protects lifecycle transitions based on user roles (Developer, Security, Auditor, Admin).
- **Split Deployment**: API operates via an Ngrok tunnel, allowing the React dashboard to be hosted globally on GitHub Pages.

## System Architecture
TPSR is designed as a multi-tier, trustless verification system:
- **Fabric Network**: The underlying blockchain infrastructure providing consensus and immutable hash storage.
- **PostgreSQL Database**: Off-chain relational database storing the full SBOM JSON payloads and historical audit events.
- **Node.js REST API**: The middleware mapping HTTP requests to Fabric SDK transactions, executing the policy engine, and running the diff engine.
- **React Dashboard**: The frontend interface for human interaction, featuring identity simulation and compliance reporting.
- **CI Integrations**: Tooling to inject SBOM submissions directly into Jenkins/GitLab build pipelines.

## Repository Structure
- `api/` — Node.js Express backend, Policy Engine, and Diff Engine.
- `chaincode/sbom/` — Go Smart Contracts defining the 8-state governance lifecycle.
- `dashboard/` — React frontend deployed to GitHub Pages.
- `db/migrations/` — SQL schema initialization and migration scripts.
- `network/` — Hyperledger Fabric local test network configuration.
- `ci/` & `cli/` — Pipeline integrations and standalone verification scripts.

## Dashboard Capabilities
- **Registry View**: Displays all SBOM entries pulled from the real PostgreSQL backend with their current lifecycle and policy statuses.
- **Verify View**: Allows auditors to upload an SBOM to check its cryptographic integrity. Automatically invokes the Tamper Intelligence engine if a mismatch is found.
- **History View**: Displays the immutable, ledger-backed transaction trail for an SBOM.
- **Compliance View**: Generates a detailed compliance report verifying ledger presence, payload integrity, and policy rules.

## Testing Coverage
- **Functional & Integration**: E2E testing of the hybrid ingestion pipeline (API $\rightarrow$ PostgreSQL $\rightarrow$ Fabric).
- **Tamper Detection Validation**: Confirmed 100\% catch rate for modified SBOM payloads, with accurate categorizations by the diff engine.
- **Policy Enforcement**: Verified that CVSS violations correctly halt the lifecycle progression before reaching the `COMPLIANT` state.

## Deployment Guidance
Please consult the master runbook:
`DEPLOYMENT.md`

The full deployment order, database migrations, Fabric network initialization, Ngrok tunneling, and GitHub Pages configuration are documented there.

## Recommended Next Steps for Future Work
- Replace the prototype identity selector with a production IAM/SSO integration (OAuth2/OIDC).
- Implement explicit Graph-based lineage tracking to visualize dependencies across versions.
- Conduct cross-cloud, multi-organization Fabric network deployment.
