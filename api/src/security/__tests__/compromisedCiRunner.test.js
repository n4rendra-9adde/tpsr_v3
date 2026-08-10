const { buildAdversarialFixture, runAdversarialScenarios } = require('../adversarialScenarioRunner');
const { evaluateTrust } = require('../../utils/trustEngine');
const path = require('path');

test('Compromised CI Runner - ADV-01', async () => {
  const bundle = buildAdversarialFixture('ADV-01');
  const res = await evaluateTrust(bundle);
  expect(res.trustStatus).toBe('REJECTED');
  expect(res.triggeredRuleIds).toContain('CAECTD-R007');
  expect(res.reasonCode).toBe('PRV-004');
  expect(res.evidenceDependencies.provenance.assuranceState).toBe('INVALID');
});
