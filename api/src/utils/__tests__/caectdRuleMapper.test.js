'use strict';

const { getRuleById } = require('../caectdRuleMapper');

describe('caectdRuleMapper', () => {
  it('maps CAECTD-R002 correctly', () => {
    const rule = getRuleById('CAECTD-R002');
    expect(rule.failureClass).toBe('Class A');
    expect(rule.reasonCodes).toContain('INT-002');
  });

  it('maps CAECTD-R016 correctly', () => {
    const rule = getRuleById('CAECTD-R016');
    expect(rule.failureClass).toBe('None');
    expect(rule.defaultDecisionEffect).toBe('NON_BLOCKING');
  });

  it('maps CAECTD-R031 correctly', () => {
    const rule = getRuleById('CAECTD-R031');
    expect(rule.defaultDecisionEffect).toBe('TRUSTED');
  });

  it('returns null for unknown rule', () => {
    expect(getRuleById('UNKNOWN-RULE')).toBeNull();
  });
});
