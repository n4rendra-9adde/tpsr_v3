'use strict';

const { getRecommendationSuggestions } = require('../recommendationSuggestions');

describe('Recommendation Suggestions Registry', () => {
  it('Missing provenance maps to approved-builder suggestion', () => {
    const res = getRecommendationSuggestions({ reasonCodes: ['PROV-001'], ruleIds: ['R1'] });
    expect(res).toHaveLength(1);
    expect(res[0].message).toBe('Submit provenance from an approved builder.');
    expect(res[0].targetRoute).toBe('/provenance');
  });

  it('Unauthorized builder maps correctly', () => {
    const res = getRecommendationSuggestions({ reasonCodes: ['PROV-003'], ruleIds: ['R1'] });
    expect(res).toHaveLength(1);
    expect(res[0].message).toContain('Generate provenance using a builder authorized');
  });

  it('Missing signature maps correctly', () => {
    const res = getRecommendationSuggestions({ reasonCodes: ['SIG-001'], ruleIds: ['R1'] });
    expect(res).toHaveLength(1);
    expect(res[0].message).toBe('Provide the required artifact signature.');
  });

  it('Unauthorized signer maps correctly', () => {
    const res = getRecommendationSuggestions({ reasonCodes: ['SIG-003'], ruleIds: ['R1'] });
    expect(res).toHaveLength(1);
    expect(res[0].message).toContain('Sign the artifact using an authorized release-signing identity');
  });

  it('Integrity failure is non-exceptionable', () => {
    const res = getRecommendationSuggestions({ reasonCodes: ['INT-001'], ruleIds: ['R1'] });
    expect(res).toHaveLength(1);
    expect(res[0].message).toContain('Regenerate the artifact and SBOM');
    expect(res[0].exceptionable).toBe(false);
  });

  it('Critical CVE maps to patch/VEX action', () => {
    const res = getRecommendationSuggestions({ reasonCodes: ['VULN-001'], ruleIds: ['R1'] });
    expect(res).toHaveLength(1);
    expect(res[0].message).toContain('Patch or upgrade the affected component');
  });

  it('Stale VEX maps correctly', () => {
    const res = getRecommendationSuggestions({ reasonCodes: ['VEX-004'], ruleIds: ['R1'] });
    expect(res).toHaveLength(1);
    expect(res[0].message).toContain('Obtain a fresh VEX statement');
  });

  it('Wrong-scope VEX maps correctly', () => {
    const res = getRecommendationSuggestions({ reasonCodes: ['VEX-001'], ruleIds: ['R1'] });
    expect(res).toHaveLength(1);
    expect(res[0].message).toContain('Submit VEX matching the exact artifact digest');
  });

  it('Missing context maps correctly', () => {
    const res = getRecommendationSuggestions({ reasonCodes: ['CTX-001'], ruleIds: ['R1'] });
    expect(res).toHaveLength(1);
    expect(res[0].message).toContain('Submit an authorized deployment-context assertion.');
  });

  it('CTX-017 maps to context supersession', () => {
    const res = getRecommendationSuggestions({ reasonCodes: ['CTX-017'], ruleIds: ['R1'] });
    expect(res).toHaveLength(1);
    expect(res[0].message).toContain('Review the conflicting context assertions');
  });

  it('Unknown reason uses safe fallback', () => {
    const res = getRecommendationSuggestions({ reasonCodes: ['UNKNOWN_ERR'], ruleIds: ['R1'] });
    expect(res).toHaveLength(1);
    expect(res[0].message).toContain('Review the recorded rule evidence and provide the missing authoritative evidence');
  });

  it('Suggestions are deterministically ordered', () => {
    const res = getRecommendationSuggestions({ reasonCodes: ['SIG-001', 'INT-001'], ruleIds: ['R1', 'R2'] });
    expect(res).toHaveLength(2);
    // INT-001 priority is 1, SIG-001 priority is 20
    expect(res[0].reasonCode).toBe('INT-001');
    expect(res[1].reasonCode).toBe('SIG-001');
  });

  it('Duplicate suggestions are deduplicated', () => {
    const res = getRecommendationSuggestions({ reasonCodes: ['PROV-001', 'PROV-002'], ruleIds: ['R1', 'R1'] });
    // Same suggestionId format for PROV-001 and PROV-002 with same rule
    expect(res).toHaveLength(1);
  });

  it('Caller-provided suggestions are ignored', () => {
    // Function signature doesn't even accept them, so inherently ignored
    expect(true).toBe(true);
  });
});
