const { buildAdversarialFixture } = require('../adversarialScenarioRunner');
const { evaluateTrust } = require('../../utils/trustEngine');

test('SBOM Substitution - ADV-05', async () => {
  const bundle = buildAdversarialFixture('ADV-05');
  const res = await evaluateTrust(bundle);
  expect(res.trustStatus).toBe('REJECTED');
  expect(res.triggeredRuleIds).toContain('CAECTD-R001');
  expect(res.reasonCode).toBe('INT-002');
  expect(res.evidenceDependencies.integrity).toBeDefined();
});
