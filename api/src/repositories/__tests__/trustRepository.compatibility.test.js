const trustRepository = require('../trustRepository');

describe('TPSR v3 Trust Compatibility Mapper', () => {
  test('A. Genuine historical UNTRUSTED record', () => {
    const res = trustRepository.normalizeTrustStatus('UNTRUSTED');
    expect(res).toEqual({
      trustDecision: 'REJECTED',
      legacyDecision: 'UNTRUSTED',
      legacyNormalized: true
    });
  });

  test('B. New REJECTED record', () => {
    const res = trustRepository.normalizeTrustStatus('REJECTED');
    expect(res).toEqual({
      trustDecision: 'REJECTED',
      legacyNormalized: false
    });
  });

  test('C. TRUSTED record', () => {
    const res = trustRepository.normalizeTrustStatus('TRUSTED');
    expect(res).toEqual({
      trustDecision: 'TRUSTED',
      legacyNormalized: false
    });
  });

  test('D. CONDITIONALLY_ACCEPTED record', () => {
    const res = trustRepository.normalizeTrustStatus('CONDITIONALLY_ACCEPTED');
    expect(res).toEqual({
      trustDecision: 'CONDITIONALLY_ACCEPTED',
      legacyNormalized: false
    });
  });

  test('E. REVIEW_REQUIRED record', () => {
    const res = trustRepository.normalizeTrustStatus('REVIEW_REQUIRED');
    expect(res).toEqual({
      trustDecision: 'REVIEW_REQUIRED',
      legacyNormalized: false
    });
  });

  test('F. UNEVALUATED record', () => {
    const res = trustRepository.normalizeTrustStatus('UNEVALUATED');
    expect(res).toEqual({
      trustDecision: 'UNEVALUATED',
      legacyNormalized: false
    });
  });

  test('G. Null record', () => {
    const res = trustRepository.normalizeTrustStatus(null);
    expect(res).toEqual({
      trustDecision: 'UNEVALUATED',
      legacyNormalized: false
    });
  });

  test('H. Unknown arbitrary value', () => {
    const res = trustRepository.normalizeTrustStatus('UNKNOWN_RANDOM_STATE');
    expect(res).toEqual({
      trustDecision: 'UNEVALUATED',
      legacyNormalized: false
    });
  });
});
