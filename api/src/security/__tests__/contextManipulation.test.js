const { buildAdversarialFixture } = require('../adversarialScenarioRunner');
const { evaluateTrust } = require('../../utils/trustEngine');

test('Context Manipulation - ADV-08', async () => {
  const bundle = buildAdversarialFixture('ADV-08');
  const res = await evaluateTrust(bundle);
  expect(res.trustStatus).toBe('REVIEW_REQUIRED');
  expect(res.triggeredRuleIds).toContain('CAECTD-R025');
  expect(res.reasonCode).toBe('CTX-017');
  expect(res.evidenceDependencies.contextRisk).toBeDefined();
});
