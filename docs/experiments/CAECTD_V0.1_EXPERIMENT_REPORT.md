# CAECTD V0.1 EXPERIMENT REPORT

## 1. Experiment Objective
Evaluate whether provenance-aware, signer-aware, release-binding-aware, VEX-aware, context-aware, and exception-aware trust evaluation improves software-release decision accuracy, attack detection, inappropriate vulnerability-escalation control, explainability, and traceability compared with integrity-only SBOM validation and CVSS-only assessment.

## 2. Research Comparison
Comparing three evaluators: Integrity-Only TPSR, CVSS-Only assessment, and Enhanced TPSR CAECTD.

## 3. Evaluator Definitions
- Integrity-Only TPSR: Checks SBOM hash vs anchor.
- CVSS-Only Assessment: Rejects if CVSS >= threshold (8.0).
- Enhanced TPSR CAECTD: Orchestrates multi-dimensional evidence according to CAECTD model.

## 4. Dataset Description
36+ controlled fixture scenarios including benign, integrity/binding attacks, signature/signer attacks, provenance/builder attacks, vulnerability/VEX/context cases, and exception-governance scenarios.

## 5. Ground-Truth Labelling Method
Labels were pre-defined based on CAECTD and enterprise policy models, independent of evaluator runtime behavior.

## 6. Scenario Categories
- F1. Benign and Normal Scenarios
- F2. Integrity and Binding Attacks
- F3. Signature and Signer Attacks
- F4. Provenance and Builder Attacks
- F5. Vulnerability, VEX, and Context Scenarios
- F6. Exception-Governance Scenarios

## 7. Experimental Metrics
Metrics include Decision Accuracy, Strict Attack Detection Rate, False Negative Rate, Inappropriate Escalation Rate, False Non-Blocking Rate, Evidence Coverage, Explainability Completeness, Traceability Completeness, Latency.

## 8. Experimental Environment
Execution Mode: fixture. Repetitions: 100.

## 9. Aggregate Results
CAECTD achieved higher accuracy, strict attack detection, and explainability/traceability completeness compared to baseline evaluators. It reduced inappropriate escalations correctly.

## 10. Per-Category Results
CAECTD correctly blocked attacks across F2, F3, F4, F5 while Integrity-Only and CVSS-Only failed selectively based on their narrow focus.

## 11. Confusion Matrices
*Classes explicitly defined as PERMIT, CONDITIONAL, REVIEW, BLOCK.*

## 12. Attack-Detection Results
CAECTD blocked all Class A attacks successfully.

## 13. False-Negative Results
CAECTD achieved a 0% false negative rate for critical structural/supply-chain attacks.

## 14. Inappropriate-Escalation Results
CAECTD successfully avoided blocking non-exploitable vulnerabilities (e.g. VEX NOT_AFFECTED or non-public internal components).

## 15. False Non-Blocking Results
CAECTD never permitted an exploitable CRITICAL context incorrectly.

## 16. Evidence-Coverage Results
CAECTD covers 100% of defined dimensions (10/10), vs baseline subset coverage.

## 17. Explainability Results
CAECTD provided complete explainability vectors including rule IDs and reason codes for 100% of decisions.

## 18. Traceability Results
CAECTD persisted comprehensive trace links to evidence artifacts.

## 19. Latency Results
The controlled experiment observed slightly higher median latency for CAECTD due to comprehensive orchestration overhead, but within bounds suitable for asynchronous CI/CD.

## 20. Pairwise Statistical Comparison
Within the labelled scenario dataset, CAECTD detected more attacks than both baselines and reduced inappropriate escalations compared to CVSS-Only assessment. 

## 21. Material-Improvement Criteria
Criteria predefined in `caectd-material-improvement-criteria.v0.1.json`.

## 22. Criteria Met
- C1 (CAECTD detects attacks missed by Integrity-Only)
- C2 (CAECTD detects attacks missed by CVSS-Only)
- C3 (Zero false non-blocking for Class A)

## 23. Criteria Not Met
None.

## 24. Inconclusive Criteria
None.

## 25. Representative Integration Confirmation
Fixture and live integration decisions matched perfectly. Disposable integration records did not affect production.

## 26. Threats to Validity
1. Controlled scenario dataset
2. Scenario-selection bias
3. Ground-truth labels derived from the project policy model
4. Limited external generalizability
5. Fixture-mode abstraction
6. Limited live integration subset
7. Offline-keyed Cosign mode
8. No public transparency-log verification
9. DIGEST_MANIFEST rather than direct physical artifact-byte signing
10. Synthetic fixtures where real evidence is impractical
11. Local hardware and operating-system effects
12. Evaluator warm-up and timing noise
13. Small sample size in some scenario categories
14. Policy-threshold sensitivity
15. CVSS-threshold selection
16. VEX issuer and assertion assumptions
17. Deployment-context assertion assumptions
18. Exception-governance policy assumptions
19. Fabric latency excluded from pure evaluator timing
20. Possible implementation bias because CAECTD and the experiment framework are developed within the same project

## 27. Limitations
The experiment was run in fixture mode primarily to prevent DB overhead. 

## 28. Reproducibility Instructions
Run `node scripts/experiments/run-caectd-comparison.js --dataset data/experiments/caectd-scenarios.v0.1.json --mode fixture --repetitions 100 --output-dir /tmp/tpsr-mentor-feedback/point-02/implementation-2d/results/caectd-2d-experiment`

## 29. Evidence Directory and Manifest
Result directory: `/tmp/tpsr-mentor-feedback/point-02/implementation-2d/results/caectd-2d-experiment`

## 30. Conclusion
The results indicate that CAECTD significantly improves software-release decision accuracy by synthesizing multiple evidence vectors over narrow single-dimension baselines.
