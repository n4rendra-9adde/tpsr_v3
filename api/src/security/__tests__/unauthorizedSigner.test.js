const { buildAdversarialFixture } = require('../adversarialScenarioRunner');
const { evaluateTrust } = require('../../utils/trustEngine');

test('Unauthorized Signer - ADV-03', async () => {
  const bundle = buildAdversarialFixture('ADV-03');
  const res = await evaluateTrust(bundle);
  expect(res.trustStatus).toBe('REJECTED');
  expect(res.triggeredRuleIds).toContain('CAECTD-R005');
  expect(res.reasonCode).toBe('SIG-003');
  expect(res.evidenceDependencies.signature).toBeDefined();
});
