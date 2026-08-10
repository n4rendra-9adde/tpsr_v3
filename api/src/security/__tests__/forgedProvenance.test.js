const { buildAdversarialFixture } = require('../adversarialScenarioRunner');
const { evaluateTrust } = require('../../utils/trustEngine');

test('Forged Provenance - ADV-02', async () => {
  const bundle = buildAdversarialFixture('ADV-02');
  const res = await evaluateTrust(bundle);
  expect(res.trustStatus).toBe('REJECTED');
  expect(res.triggeredRuleIds).toContain('CAECTD-R008');
  expect(res.reasonCode).toBe('PRV-006');
  expect(res.evidenceDependencies.provenance).toBeDefined();
});
