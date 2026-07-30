'use strict';

const trustRepository = require('../trustRepository');

describe('Trust Repository - normalizeTrustStatus', () => {
  test('Normalizes UNTRUSTED -> REJECTED with legacy flag', () => {
    const res = trustRepository.normalizeTrustStatus('UNTRUSTED');
    expect(res).toEqual({
      trustDecision: 'REJECTED',
      legacyDecision: 'UNTRUSTED',
      legacyNormalized: true
    });
  });

  test('Passes TRUSTED -> TRUSTED', () => {
    expect(trustRepository.normalizeTrustStatus('TRUSTED')).toEqual({ trustDecision: 'TRUSTED' });
  });

  test('Passes CONDITIONALLY_ACCEPTED -> CONDITIONALLY_ACCEPTED', () => {
    expect(trustRepository.normalizeTrustStatus('CONDITIONALLY_ACCEPTED')).toEqual({ trustDecision: 'CONDITIONALLY_ACCEPTED' });
  });

  test('Passes REVIEW_REQUIRED -> REVIEW_REQUIRED', () => {
    expect(trustRepository.normalizeTrustStatus('REVIEW_REQUIRED')).toEqual({ trustDecision: 'REVIEW_REQUIRED' });
  });

  test('Passes REJECTED -> REJECTED', () => {
    expect(trustRepository.normalizeTrustStatus('REJECTED')).toEqual({ trustDecision: 'REJECTED' });
  });

  test('Passes UNEVALUATED -> UNEVALUATED', () => {
    expect(trustRepository.normalizeTrustStatus('UNEVALUATED')).toEqual({ trustDecision: 'UNEVALUATED' });
  });

  test('Unknown string returns UNEVALUATED', () => {
    expect(trustRepository.normalizeTrustStatus('UNKNOWN_STATUS')).toEqual({ trustDecision: 'UNEVALUATED' });
  });

  test('Null returns UNEVALUATED', () => {
    expect(trustRepository.normalizeTrustStatus(null)).toEqual({ trustDecision: 'UNEVALUATED' });
  });

  test('Undefined returns UNEVALUATED', () => {
    expect(trustRepository.normalizeTrustStatus(undefined)).toEqual({ trustDecision: 'UNEVALUATED' });
  });
});
