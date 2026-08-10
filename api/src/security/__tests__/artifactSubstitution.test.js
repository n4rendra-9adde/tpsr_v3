const { buildAdversarialFixture } = require('../adversarialScenarioRunner');
const { evaluateTrust } = require('../../utils/trustEngine');

test('Artifact Substitution - ADV-04', async () => {
  const bundle = buildAdversarialFixture('ADV-04');
  const res = await evaluateTrust(bundle);
  expect(res.trustStatus).toBe('REJECTED');
  expect(res.triggeredRuleIds).toContain('CAECTD-R007');
  expect(res.reasonCode).toBe('BND-002');
  expect(res.evidenceDependencies.provenance).toBeDefined();
});
