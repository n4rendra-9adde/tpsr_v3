'use strict';

function getRecommendationSuggestions({ ruleIds = [], reasonCodes = [], blockingFindings = [], reviewFindings = [] }) {
  const suggestions = [];
  const addedIds = new Set();
  
  function addSuggestion(suggestion) {
    if (!addedIds.has(suggestion.suggestionId)) {
      suggestions.push(suggestion);
      addedIds.add(suggestion.suggestionId);
    }
  }
  
  // Deterministic mapping based on priority
  for (let i = 0; i < reasonCodes.length; i++) {
    const code = reasonCodes[i];
    const rule = ruleIds[i] || 'UNKNOWN_RULE';
    
    if (code === 'PROV-001' || code === 'PROV-002') {
      addSuggestion({
        suggestionId: `sug-prov-missing-${rule}`,
        ruleId: rule,
        reasonCode: code,
        message: 'Submit provenance from an approved builder.',
        priority: 10,
        requiredRole: 'developer',
        targetRoute: '/provenance',
        requiredEvidenceType: 'PROVENANCE',
        exceptionable: true
      });
    } else if (code === 'PROV-003') {
      addSuggestion({
        suggestionId: `sug-prov-unauth-${rule}`,
        ruleId: rule,
        reasonCode: code,
        message: 'Generate provenance using a builder authorized by the active trust policy.',
        priority: 11,
        requiredRole: 'developer',
        targetRoute: '/provenance',
        requiredEvidenceType: 'PROVENANCE',
        exceptionable: true
      });
    } else if (code === 'SIG-001') {
      addSuggestion({
        suggestionId: `sug-sig-missing-${rule}`,
        ruleId: rule,
        reasonCode: code,
        message: 'Provide the required artifact signature.',
        priority: 20,
        requiredRole: 'release_manager',
        targetRoute: '/signatures',
        requiredEvidenceType: 'SIGNATURE',
        exceptionable: true
      });
    } else if (code === 'SIG-003' || code === 'SIG-002') {
      addSuggestion({
        suggestionId: `sug-sig-unauth-${rule}`,
        ruleId: rule,
        reasonCode: code,
        message: 'Sign the artifact using an authorized release-signing identity.',
        priority: 21,
        requiredRole: 'release_manager',
        targetRoute: '/signatures',
        requiredEvidenceType: 'SIGNATURE',
        exceptionable: true
      });
    } else if (code === 'INT-001' || code === 'INT-005') {
      addSuggestion({
        suggestionId: `sug-int-fail-${rule}`,
        ruleId: rule,
        reasonCode: code,
        message: 'Regenerate the artifact and SBOM, then verify their complete digests.',
        priority: 1,
        requiredRole: 'developer',
        targetRoute: '/upload',
        requiredEvidenceType: 'ARTIFACT',
        exceptionable: false
      });
    } else if (code === 'VULN-001' || code === 'VULN-002' || code === 'VEX-003' || code === 'VEX-002') {
      addSuggestion({
        suggestionId: `sug-cve-crit-${rule}`,
        ruleId: rule,
        reasonCode: code,
        message: 'Patch or upgrade the affected component, or provide authoritative exact-scope VEX evidence.',
        priority: 30,
        requiredRole: 'security_officer',
        targetRoute: '/vex',
        requiredEvidenceType: 'VEX',
        exceptionable: true
      });
    } else if (code === 'VEX-004') {
      addSuggestion({
        suggestionId: `sug-vex-stale-${rule}`,
        ruleId: rule,
        reasonCode: code,
        message: 'Obtain a fresh VEX statement from an authorized issuer.',
        priority: 31,
        requiredRole: 'security_officer',
        targetRoute: '/vex',
        requiredEvidenceType: 'VEX',
        exceptionable: true
      });
    } else if (code === 'VEX-001') {
      addSuggestion({
        suggestionId: `sug-vex-wrongscope-${rule}`,
        ruleId: rule,
        reasonCode: code,
        message: 'Submit VEX matching the exact artifact digest, version, and vulnerability.',
        priority: 32,
        requiredRole: 'security_officer',
        targetRoute: '/vex',
        requiredEvidenceType: 'VEX',
        exceptionable: true
      });
    } else if (code === 'CTX-001' || code === 'CTX-002') {
      addSuggestion({
        suggestionId: `sug-ctx-missing-${rule}`,
        ruleId: rule,
        reasonCode: code,
        message: 'Submit an authorized deployment-context assertion.',
        priority: 40,
        requiredRole: 'compliance_officer',
        targetRoute: '/context',
        requiredEvidenceType: 'CONTEXT',
        exceptionable: true
      });
    } else if (code === 'CTX-017') {
      addSuggestion({
        suggestionId: `sug-ctx-017-${rule}`,
        ruleId: rule,
        reasonCode: code,
        message: 'Review the conflicting context assertions and supersede the incorrect one.',
        priority: 41,
        requiredRole: 'compliance_officer',
        targetRoute: '/context',
        requiredEvidenceType: 'CONTEXT',
        exceptionable: true
      });
    } else if (code === 'EXC-002' || code === 'EXC-003') {
      addSuggestion({
        suggestionId: `sug-exc-block-${rule}`,
        ruleId: rule,
        reasonCode: code,
        message: 'This control cannot be overridden through a standard exception.',
        priority: 5,
        requiredRole: 'security_officer',
        targetRoute: '/governance',
        requiredEvidenceType: 'EXCEPTION',
        exceptionable: false
      });
    } else {
      addSuggestion({
        suggestionId: `sug-fallback-${rule}`,
        ruleId: rule,
        reasonCode: code,
        message: 'Review the recorded rule evidence and provide the missing authoritative evidence.',
        priority: 99,
        requiredRole: 'developer',
        targetRoute: '/evidence',
        requiredEvidenceType: 'UNKNOWN',
        exceptionable: true
      });
    }
  }

  // Ensure non-exceptionable generic blocker triggers if not already
  if (blockingFindings.some(f => f.includes('Non-exceptionable'))) {
    addSuggestion({
      suggestionId: 'sug-exc-block-generic',
      ruleId: 'GENERIC',
      reasonCode: 'BLOCK',
      message: 'This control cannot be overridden through a standard exception.',
      priority: 5,
      requiredRole: 'security_officer',
      targetRoute: '/governance',
      requiredEvidenceType: 'EXCEPTION',
      exceptionable: false
    });
  }

  // Sort by priority ASC (lower number = higher priority), then by rule ID alphabetically to be deterministic
  suggestions.sort((a, b) => {
    if (a.priority !== b.priority) {
      return a.priority - b.priority;
    }
    return a.ruleId.localeCompare(b.ruleId);
  });

  return suggestions;
}

module.exports = {
  getRecommendationSuggestions
};
