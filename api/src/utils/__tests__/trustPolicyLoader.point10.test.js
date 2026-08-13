'use strict';

const { getTrustPolicy } = require('../trustPolicyLoader');
const fs = require('fs');
const path = require('path');

describe('Point 10 Trust Policy Loader Validation', () => {
  let basePolicy;

  beforeAll(() => {
    basePolicy = JSON.parse(fs.readFileSync(path.join(__dirname, '../../../../docs/TRUST_POLICY.json'), 'utf8'));
  });

  test('validates known operations and fails unknown operation', () => {
    const policy = JSON.parse(JSON.stringify(basePolicy));
    policy.contextAuthorizationRules['hack_system'] = { allowedRoles: ['security'] };
    expect(() => getTrustPolicy({ injectedPolicy: policy, forceReload: true })).toThrow('TRUST_POLICY_UNKNOWN_OPERATION');
  });

  test('fails if allowedRoles is empty', () => {
    const policy = JSON.parse(JSON.stringify(basePolicy));
    policy.contextAuthorizationRules.assert_exposure.allowedRoles = [];
    expect(() => getTrustPolicy({ injectedPolicy: policy, forceReload: true })).toThrow('TRUST_POLICY_EMPTY_ROLES');
  });

  test('fails on wildcard scope', () => {
    const policy = JSON.parse(JSON.stringify(basePolicy));
    policy.contextAuthorizationRules.assert_component_state.allowedRoles = ['*'];
    expect(() => getTrustPolicy({ injectedPolicy: policy, forceReload: true })).toThrow('TRUST_POLICY_WILDCARD_SCOPE_UNSAFE');
  });

  test('fails on unknown role', () => {
    const policy = JSON.parse(JSON.stringify(basePolicy));
    policy.contextAuthorizationRules.request_exception.allowedRoles = ['hacker'];
    expect(() => getTrustPolicy({ injectedPolicy: policy, forceReload: true })).toThrow('TRUST_POLICY_UNKNOWN_ROLE');
  });

  test('fails if max lifetime is missing or invalid in assert_environment', () => {
    const policy = JSON.parse(JSON.stringify(basePolicy));
    delete policy.contextAuthorizationRules.assert_environment.PRODUCTION.maximumValidityHours;
    expect(() => getTrustPolicy({ injectedPolicy: policy, forceReload: true })).toThrow('TRUST_POLICY_INVALID_LIFETIME');

    policy.contextAuthorizationRules.assert_environment.PRODUCTION.maximumValidityHours = 0;
    expect(() => getTrustPolicy({ injectedPolicy: policy, forceReload: true })).toThrow('TRUST_POLICY_INVALID_LIFETIME');
  });

  test('fails if critical risk is allowed but self-approval is not prohibited', () => {
    const policy = JSON.parse(JSON.stringify(basePolicy));
    if (!policy.exceptionGovernance) policy.exceptionGovernance = {};
    policy.exceptionGovernance.allowCriticalRiskExceptions = true;
    policy.exceptionGovernance.requireIndependentApprover = false;
    expect(() => getTrustPolicy({ injectedPolicy: policy, forceReload: true })).toThrow('TRUST_POLICY_SELF_APPROVAL_PROHIBITED');
  });
});
