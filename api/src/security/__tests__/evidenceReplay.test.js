const { buildAdversarialFixture } = require('../adversarialScenarioRunner');
const { evaluateTrust } = require('../../utils/trustEngine');

test('Evidence Replay - ADV-10', async () => {
  const bundle = buildAdversarialFixture('ADV-10');
  const res = await evaluateTrust(bundle);
  expect(res.trustStatus).toBe('REJECTED');
  expect(res.triggeredRuleIds).toContain('CAECTD-R004');
  expect(res.reasonCode).toBe('SIG-002');
  expect(res.evidenceDependencies.signature).toBeDefined();
});
