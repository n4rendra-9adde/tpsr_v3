'use strict';

/**
 * Common Evidence Assurance State Mapper (CAECTD 0.1)
 *
 * Normalizes heterogeneous evidence results into 9 formal assurance states:
 * VERIFIED_TRUSTED, VERIFIED_UNTRUSTED, INVALID, MISSING, STALE, REPLAYED,
 * CONFLICTING, NOT_APPLICABLE, NOT_EVALUATED.
 */

const ASSURANCE_STATES = {
  VERIFIED_TRUSTED: 'VERIFIED_TRUSTED',
  VERIFIED_UNTRUSTED: 'VERIFIED_UNTRUSTED',
  INVALID: 'INVALID',
  MISSING: 'MISSING',
  STALE: 'STALE',
  REPLAYED: 'REPLAYED',
  CONFLICTING: 'CONFLICTING',
  NOT_APPLICABLE: 'NOT_APPLICABLE',
  NOT_EVALUATED: 'NOT_EVALUATED'
};

function mapSignatureEvidence(evidence) {
  if (!evidence) {
    return { original: null, normalized: ASSURANCE_STATES.MISSING };
  }
  const original = evidence.verification_status || evidence.verificationStatus;
  if (!original) {
    return { original: 'UNKNOWN', normalized: ASSURANCE_STATES.NOT_EVALUATED };
  }
  
  // Signature Replay is unsupported in current implementation
  // Signature Freshness is unsupported in current implementation
  
  if (original === 'VERIFIED') {
    // Current implementation evaluates trust based on the presence of a valid signature bundle
    return { original, normalized: ASSURANCE_STATES.VERIFIED_TRUSTED };
  } else if (original === 'UNTRUSTED') {
    return { original, normalized: ASSURANCE_STATES.VERIFIED_UNTRUSTED };
  }
  
  return { original, normalized: ASSURANCE_STATES.INVALID };
}

function mapProvenanceEvidence(evidence) {
  if (!evidence) {
    return { original: null, normalized: ASSURANCE_STATES.MISSING };
  }
  const original = evidence.status;
  if (!original) {
    return { original: 'UNKNOWN', normalized: ASSURANCE_STATES.NOT_EVALUATED };
  }
  
  if (original === 'VALID') {
    return { original, normalized: ASSURANCE_STATES.VERIFIED_TRUSTED };
  } else if (original === 'UNTRUSTED') {
    return { original, normalized: ASSURANCE_STATES.VERIFIED_UNTRUSTED };
  }
  
  return { original, normalized: ASSURANCE_STATES.INVALID };
}

function mapVexEvidence(evidence) {
  if (!evidence) {
    return { original: null, normalized: ASSURANCE_STATES.MISSING };
  }
  const original = evidence.status || evidence.applicability_status;
  if (!original) {
    return { original: 'UNKNOWN', normalized: ASSURANCE_STATES.NOT_EVALUATED };
  }
  
  if (original === 'not_affected' || original === 'fixed') {
    return { original, normalized: ASSURANCE_STATES.VERIFIED_TRUSTED };
  } else if (original === 'affected') {
    return { original, normalized: ASSURANCE_STATES.VERIFIED_TRUSTED };
  } else if (original === 'under_investigation') {
    return { original, normalized: ASSURANCE_STATES.NOT_EVALUATED };
  } else if (original === 'CONFLICTING') {
    return { original, normalized: ASSURANCE_STATES.CONFLICTING };
  } else if (original === 'STALE') {
    return { original, normalized: ASSURANCE_STATES.STALE };
  } else if (original === 'INVALID') {
    return { original, normalized: ASSURANCE_STATES.INVALID };
  }
  
  return { original, normalized: ASSURANCE_STATES.NOT_EVALUATED };
}

function mapContextEvidence(evidence) {
  if (!evidence) {
    return { original: null, normalized: ASSURANCE_STATES.MISSING };
  }
  // Context assertions are currently unauthenticated
  const original = 'UNAUTHENTICATED';
  return { original, normalized: ASSURANCE_STATES.VERIFIED_UNTRUSTED };
}

function mapExceptionEvidence(evidence) {
  if (!evidence) {
    return { original: null, normalized: ASSURANCE_STATES.MISSING };
  }
  const original = evidence.status;
  if (!original) {
    return { original: 'UNKNOWN', normalized: ASSURANCE_STATES.NOT_EVALUATED };
  }
  
  if (original === 'APPROVED') {
    const validUntil = evidence.valid_until ? new Date(evidence.valid_until) : null;
    if (validUntil && validUntil < new Date()) {
      return { original: 'EXPIRED', normalized: ASSURANCE_STATES.STALE };
    }
    return { original, normalized: ASSURANCE_STATES.VERIFIED_TRUSTED };
  } else if (original === 'REVOKED') {
    return { original, normalized: ASSURANCE_STATES.INVALID };
  }
  
  return { original, normalized: ASSURANCE_STATES.INVALID };
}

module.exports = {
  ASSURANCE_STATES,
  mapSignatureEvidence,
  mapProvenanceEvidence,
  mapVexEvidence,
  mapContextEvidence,
  mapExceptionEvidence
};
