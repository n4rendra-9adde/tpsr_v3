const { buildAdversarialFixture } = require('../adversarialScenarioRunner');
const { evaluateTrust } = require('../../utils/trustEngine');

test('Falsified VEX - ADV-07', async () => {
  const bundle = buildAdversarialFixture('ADV-07');
  const res = await evaluateTrust(bundle);
  expect(res.trustStatus).toBe('REJECTED');
  expect(res.triggeredRuleIds).toContain('CR-001');
  expect(res.reasonCode).toContain('CTX-001');
  expect(res.evidenceDependencies.contextRisk.contextReasonCodes).toContain('VEX-010');
  expect(res.evidenceDependencies.contextRisk).toBeDefined();
});
