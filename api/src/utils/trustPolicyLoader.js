'use strict';

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

let cachedTrustPolicy = null;

function normalizeFingerprint(keyStr) {
  if (typeof keyStr !== 'string') {
    throw new Error('TRUST_POLICY_INVALID_FINGERPRINT');
  }
  return crypto.createHash('sha256').update(keyStr.trim()).digest('hex');
}

function normalizeBuilder(b) {
  if (typeof b !== 'string' || !b.trim()) {
    throw new Error('TRUST_POLICY_INVALID_BUILDER');
  }
  return b.trim();
}

function normalizeSource(s) {
  if (typeof s !== 'string' || !s.trim()) {
    throw new Error('TRUST_POLICY_INVALID_SOURCE');
  }
  // Source must look like a repo or URL, we can enforce some basic structure
  // For this, we just reject if it has query tricks or isn't a string.
  if (s.includes('?') || s.includes('#')) {
    throw new Error('TRUST_POLICY_INVALID_SOURCE');
  }
  return s.trim();
}

/**
 * @param {Object} options
 * @param {Object} [options.injectedPolicy] - For testing
 * @param {string} [options.policyPath] - For testing alternative files
 * @param {boolean} [options.forceReload] - Ignore cache
 */
function getTrustPolicy(options = {}) {
  if (cachedTrustPolicy && !options.injectedPolicy && !options.policyPath && !options.forceReload) {
    return cachedTrustPolicy;
  }

  let parsed;
  if (options.injectedPolicy) {
    parsed = JSON.parse(JSON.stringify(options.injectedPolicy)); // deep copy
  } else {
    const policyPath = options.policyPath || path.join(__dirname, '../../../docs/TRUST_POLICY.json');
    if (!fs.existsSync(policyPath)) {
      throw new Error('TRUST_POLICY_MISSING');
    }
    try {
      const data = fs.readFileSync(policyPath, 'utf8');
      parsed = JSON.parse(data);
    } catch (e) {
      throw new Error('TRUST_POLICY_MALFORMED');
    }
  }

  if (parsed.schemaVersion !== 'v1.0' && parsed.schemaVersion !== 'v1.1') throw new Error('TRUST_POLICY_UNSUPPORTED_SCHEMA');
  if (!parsed.policyId || typeof parsed.policyId !== 'string' || !parsed.policyId.trim()) {
    throw new Error('TRUST_POLICY_MISSING_ID');
  }

  if (!parsed.signaturePolicy || !parsed.signaturePolicy.trustedPublicKeys || typeof parsed.signaturePolicy.trustedPublicKeys !== 'object') {
    throw new Error('TRUST_POLICY_MISSING_SIGNER_DIMENSION');
  }

  if (!parsed.provenancePolicy || !Array.isArray(parsed.provenancePolicy.approvedBuilders)) {
    throw new Error('TRUST_POLICY_MISSING_BUILDER_DIMENSION');
  }

  if (!Array.isArray(parsed.provenancePolicy.approvedSourceRepositories)) {
    throw new Error('TRUST_POLICY_MISSING_SOURCE_DIMENSION');
  }

  const signers = parsed.signaturePolicy.trustedPublicKeys;
  const signerIds = Object.keys(signers);
  if (signerIds.length === 0) {
    throw new Error('TRUST_POLICY_EMPTY_SIGNER_LIST');
  }

  const builderList = parsed.provenancePolicy.approvedBuilders;
  if (builderList.length === 0) {
    throw new Error('TRUST_POLICY_EMPTY_BUILDER_LIST');
  }

  const sourceList = parsed.provenancePolicy.approvedSourceRepositories;
  if (sourceList.length === 0) {
    throw new Error('TRUST_POLICY_EMPTY_SOURCE_LIST');
  }

  const normalizedFingerprints = new Set();
  const normalizedSigners = {};
  for (const id of signerIds) {
    const fp = normalizeFingerprint(signers[id]);
    if (normalizedFingerprints.has(fp)) {
      throw new Error('TRUST_POLICY_DUPLICATE_KEYS');
    }
    normalizedFingerprints.add(fp);
    normalizedSigners[id] = fp;
  }

  const normalizedBuilders = [];
  const builderSet = new Set();
  for (const b of builderList) {
    const nb = normalizeBuilder(b);
    if (builderSet.has(nb)) {
      throw new Error('TRUST_POLICY_DUPLICATE_BUILDERS');
    }
    builderSet.add(nb);
    normalizedBuilders.push(nb);
  }

  const normalizedSources = [];
  const sourceSet = new Set();
  for (const s of sourceList) {
    const ns = normalizeSource(s);
    if (sourceSet.has(ns)) {
      throw new Error('TRUST_POLICY_DUPLICATE_SOURCES');
    }
    sourceSet.add(ns);
    normalizedSources.push(ns);
  }

  const normalizedPolicy = {
    ...parsed,
    schemaVersion: parsed.schemaVersion,
    policyId: parsed.policyId.trim(),
    signaturePolicy: {
      ...parsed.signaturePolicy,
      normalizedSigners,
      rawKeys: signers // Keep raw keys for signature verification if needed
    },
    provenancePolicy: {
      ...parsed.provenancePolicy,
      approvedBuilders: normalizedBuilders,
      approvedSourceRepositories: normalizedSources
    }
  };

  if (parsed.schemaVersion === 'v1.1' && parsed.vexPolicy) {
    if (!parsed.vexPolicy.authorizedIssuers || typeof parsed.vexPolicy.authorizedIssuers !== 'object') {
      throw new Error('TRUST_POLICY_MISSING_VEX_ISSUER_DIMENSION');
    }
    const vexIssuers = parsed.vexPolicy.authorizedIssuers;
    const normalizedVexIssuers = {};
    const vexFpSet = new Set();
    for (const [id, cfg] of Object.entries(vexIssuers)) {
      if (!cfg.publicKey) throw new Error('TRUST_POLICY_MISSING_VEX_ISSUER_DIMENSION');
      const fp = normalizeFingerprint(cfg.publicKey);
      if (vexFpSet.has(fp)) throw new Error('TRUST_POLICY_DUPLICATE_VEX_KEYS');
      vexFpSet.add(fp);
      normalizedVexIssuers[id] = {
        ...cfg,
        publicKey: cfg.publicKey,
        fingerprint: fp,
        globalAuthority: cfg.globalAuthority === true,
        allowedProducts: Array.isArray(cfg.allowedProducts) ? cfg.allowedProducts : []
      };
    }
    normalizedPolicy.vexPolicy = {
      ...parsed.vexPolicy,
      authorizedIssuers: normalizedVexIssuers
    };
  }

  if (parsed.contextAuthorizationRules) {
    const rules = parsed.contextAuthorizationRules;
    const knownOperations = ['assert_environment', 'assert_exposure', 'assert_criticality', 'assert_component_state', 'request_exception', 'approve_exception', 'reject_exception', 'revoke_exception', 'supersede_exception', 'apply_exception', 'revoke_assertion', 'supersede_assertion', 'view_context_history', 'view_exception_history'];

    // Known roles check - hardcoded list or fetch from somewhere. We'll use a hardcoded list of known roles for validation
    const knownRoles = ['developer', 'security', 'auditor', 'admin', 'release_manager', 'network_admin', 'asset_owner', 'system'];

    for (const op of Object.keys(rules)) {
      if (!knownOperations.includes(op)) {
        throw new Error('TRUST_POLICY_UNKNOWN_OPERATION');
      }

      if (op === 'assert_environment') {
        for (const env of Object.keys(rules[op])) {
          const envConf = rules[op][env];
          if (!envConf.allowedRoles || envConf.allowedRoles.length === 0) throw new Error('TRUST_POLICY_EMPTY_ROLES');
          if (envConf.allowedRoles.includes('*')) throw new Error('TRUST_POLICY_WILDCARD_SCOPE_UNSAFE');
          if (!envConf.maximumValidityHours || envConf.maximumValidityHours <= 0) throw new Error('TRUST_POLICY_INVALID_LIFETIME');
          for (const r of envConf.allowedRoles) {
            if (!knownRoles.includes(r)) throw new Error('TRUST_POLICY_UNKNOWN_ROLE');
          }
        }
      } else {
        const opConf = rules[op];
        if (!opConf.allowedRoles || opConf.allowedRoles.length === 0) throw new Error('TRUST_POLICY_EMPTY_ROLES');
        if (opConf.allowedRoles.includes('*')) throw new Error('TRUST_POLICY_WILDCARD_SCOPE_UNSAFE');
        for (const r of opConf.allowedRoles) {
          if (!knownRoles.includes(r)) throw new Error('TRUST_POLICY_UNKNOWN_ROLE');
        }
      }
    }
  }

  if (parsed.exceptionGovernance) {
    const gov = parsed.exceptionGovernance;
    if (gov.allowCriticalRiskExceptions && !gov.requireIndependentApprover) {
       throw new Error('TRUST_POLICY_SELF_APPROVAL_PROHIBITED');
    }
  }

  if (!options.injectedPolicy && !options.policyPath) {
    cachedTrustPolicy = normalizedPolicy;
  }

  return normalizedPolicy;
}

module.exports = {
  getTrustPolicy,
  normalizeFingerprint,
  normalizeBuilder,
  normalizeSource
};
