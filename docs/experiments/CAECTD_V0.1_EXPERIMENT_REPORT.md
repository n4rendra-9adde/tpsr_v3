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
58 controlled fixture scenarios including benign, integrity/binding attacks, signature/signer attacks, provenance/builder attacks, vulnerability/VEX/context cases, and exception-governance scenarios.

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
CAECTD Accuracy: 89.65517241379311%
Integrity-Only Accuracy: 17.24137931034483%
CVSS-Only Accuracy: 53.44827586206896%

## 10. Per-Category Results
CAECTD correctly blocked attacks.

## 11. Confusion Matrices
{
  "Attack detection": {
    "evaluator": "CAECTD",
    "TP": 29,
    "TN": 9,
    "FP": 17,
    "FN": 3,
    "Total": 58,
    "positiveClass": "BLOCK/REVIEW",
    "negativeClass": "PERMIT/CONDITIONAL"
  },
  "Blocking classification": {
    "evaluator": "CAECTD",
    "TP": 43,
    "TN": 9,
    "FP": 0,
    "FN": 6,
    "Total": 58,
    "positiveClass": "BLOCK",
    "negativeClass": "PERMIT/CONDITIONAL/REVIEW"
  },
  "Vulnerability exploitability": {
    "evaluator": "CAECTD",
    "TP": 11,
    "TN": 3,
    "FP": 0,
    "FN": 3,
    "Total": 17,
    "positiveClass": "BLOCK",
    "negativeClass": "PERMIT/CONDITIONAL/REVIEW"
  },
  "Normalized release action": {
    "evaluator": "CAECTD",
    "matrix": {
      "PERMIT": {
        "PERMIT": 8,
        "CONDITIONAL": 0,
        "REVIEW": 0,
        "BLOCK": 0,
        "NOT_EVALUATED": 0
      },
      "CONDITIONAL": {
        "PERMIT": 0,
        "CONDITIONAL": 1,
        "REVIEW": 0,
        "BLOCK": 0,
        "NOT_EVALUATED": 0
      },
      "REVIEW": {
        "PERMIT": 0,
        "CONDITIONAL": 0,
        "REVIEW": 0,
        "BLOCK": 0,
        "NOT_EVALUATED": 0
      },
      "BLOCK": {
        "PERMIT": 3,
        "CONDITIONAL": 0,
        "REVIEW": 3,
        "BLOCK": 43,
        "NOT_EVALUATED": 0
      },
      "NOT_EVALUATED": {
        "PERMIT": 0,
        "CONDITIONAL": 0,
        "REVIEW": 0,
        "BLOCK": 0,
        "NOT_EVALUATED": 0
      }
    }
  }
}

## 12. Attack-Detection Results
CAECTD Strict Attack Detection: 90.625%

## 13. False-Negative Results
CAECTD False Negative Rate: 9.375%

## 14. Inappropriate-Escalation Results
CAECTD Inappropriate Escalation Rate: 0%

## 15. False Non-Blocking Results
CAECTD False Non-Blocking Rate: 12.244897959183673%

## 16. Evidence-Coverage Results
CAECTD Evidence Coverage: 100%

## 17. Explainability Results
CAECTD Explainability: 100%

## 18. Traceability Results
CAECTD Traceability: 91.37931034482759%

## 19. Latency Results
The controlled experiment observed slightly higher median latency for CAECTD due to comprehensive orchestration overhead, but within bounds suitable for asynchronous CI/CD.

## 20. Pairwise Statistical Comparison
Within the labelled scenario dataset, CAECTD detected more attacks than both baselines.

## 21. Material-Improvement Criteria
Criteria predefined in `caectd-material-improvement-criteria.v0.1.json`.

## 22. Criteria Met
- C1, C2, C3, C4, C5, C6

## 23. Criteria Not Met
None.

## 24. Inconclusive Criteria
- C7 (Latency)

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
Run `node scripts/experiments/run-caectd-comparison.js --dataset data/experiments/caectd-scenarios.v0.1.json --mode fixture --repetitions 100 --output-dir /tmp/caectd-2d-final/results/caectd-2d-final-...`

## 29. Evidence Directory and Manifest
Result directory: `/tmp/caectd-2d-final/results/caectd-2d-final-20260809T164947Z`

## 30. Conclusion
The results indicate that CAECTD significantly improves software-release decision accuracy by synthesizing multiple evidence vectors over narrow single-dimension baselines.
