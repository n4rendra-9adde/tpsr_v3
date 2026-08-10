const { buildAdversarialFixture } = require('../adversarialScenarioRunner');
const { evaluateTrust } = require('../../utils/trustEngine');

test('Exception Abuse - ADV-09', async () => {
  const bundle = buildAdversarialFixture('ADV-09');
  const res = await evaluateTrust(bundle);
  expect(res.trustStatus).toBe('REJECTED');
  expect(res.triggeredRuleIds).toContain('CR-001');
  expect(res.reasonCode).toContain('CTX-001');
  // Check that the exception specifically was flagged
  expect(res.evidenceDependencies.contextRisk.contextReasonCodes).toContain('EXC-002');
  expect(res.evidenceDependencies.contextRisk).toBeDefined();
});
