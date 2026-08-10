const { buildAdversarialFixture } = require('../adversarialScenarioRunner');
const { evaluateTrust } = require('../../utils/trustEngine');

test('Stale VEX - ADV-06', async () => {
  const bundle = buildAdversarialFixture('ADV-06');
  const res = await evaluateTrust(bundle);
  expect(res.trustStatus).toBe('REJECTED');
  expect(res.triggeredRuleIds).toContain('CR-001');
  expect(res.reasonCode).toContain('CTX-001');
  expect(res.evidenceDependencies.contextRisk.contextReasonCodes).toContain('VEX-007');
  expect(res.evidenceDependencies.contextRisk).toBeDefined();
});
