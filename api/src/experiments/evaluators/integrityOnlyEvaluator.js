'use strict';

/**
 * Integrity-Only TPSR Evaluator (Capstone 1 Baseline)
 * 
 * Rules:
 * 1. Missing SBOM or missing required hash: NOT_EVALUATED
 * 2. Canonical hash equals ledger anchor: ACCEPT
 * 3. Canonical hash differs from ledger anchor: REJECT
 */
function evaluate(input) {
  if (!input || !input.sbomPresent || !input.canonicalSbomHash || !input.ledgerAnchorHash) {
    return { outcome: 'NOT_EVALUATED', decision: 'NOT_EVALUATED' };
  }

  if (input.canonicalSbomHash === input.ledgerAnchorHash) {
    return { outcome: 'PERMIT', decision: 'ACCEPT' };
  } else {
    return { outcome: 'BLOCK', decision: 'REJECT' };
  }
}

module.exports = { evaluate };
