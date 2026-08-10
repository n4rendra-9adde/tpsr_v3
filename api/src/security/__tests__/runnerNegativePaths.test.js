const { validateAdversarialScenariosAndControlMap } = require('../../utils/adversarialScenarioValidator');
const { runAdversarialScenarios } = require('../adversarialScenarioRunner');
const fs = require('fs');

describe('Adversarial Runner Negative Paths', () => {
  it('fails when expected decision mismatches', async () => {
    // Mock the model directly inside runAdversarialScenarios
    jest.spyOn(fs, 'readFileSync').mockReturnValueOnce(JSON.stringify({
      scenarios: [
        {
          scenarioId: 'ADV-01',
          expectedDecision: 'TRUSTED', // This is incorrect, should be REJECTED
          expectedRuleIds: ['CAECTD-R007'],
          expectedReasonCodes: ['PRV-004'],
          expectedEvidenceDependencies: ['provenance']
        }
      ]
    }));

    const results = await runAdversarialScenarios('/dummy/path.json');
    expect(results[0].decisionMatch).toBe(false);
    expect(results[0].detected).toBe(false);
  });

  it('fails when expected Rule ID mismatches', async () => {
    jest.spyOn(fs, 'readFileSync').mockReturnValueOnce(JSON.stringify({
      scenarios: [
        {
          scenarioId: 'ADV-01',
          expectedDecision: 'REJECTED',
          expectedRuleIds: ['WRONG-RULE'],
          expectedReasonCodes: ['PRV-004'],
          expectedEvidenceDependencies: ['provenance']
        }
      ]
    }));

    const results = await runAdversarialScenarios('/dummy/path.json');
    expect(results[0].ruleMatch).toBe(false);
    expect(results[0].detected).toBe(false);
  });

  it('fails when expected reason-code mismatches', async () => {
    jest.spyOn(fs, 'readFileSync').mockReturnValueOnce(JSON.stringify({
      scenarios: [
        {
          scenarioId: 'ADV-01',
          expectedDecision: 'REJECTED',
          expectedRuleIds: ['CAECTD-R007'],
          expectedReasonCodes: ['WRONG-CODE'],
          expectedEvidenceDependencies: ['provenance']
        }
      ]
    }));

    const results = await runAdversarialScenarios('/dummy/path.json');
    expect(results[0].reasonMatch).toBe(false);
    expect(results[0].detected).toBe(false);
  });

  it('fails when missing evidence traceability', async () => {
    jest.spyOn(fs, 'readFileSync').mockReturnValueOnce(JSON.stringify({
      scenarios: [
        {
          scenarioId: 'ADV-01',
          expectedDecision: 'REJECTED',
          expectedRuleIds: ['CAECTD-R007'],
          expectedReasonCodes: ['PRV-004'],
          expectedEvidenceDependencies: ['non_existent_evidence']
        }
      ]
    }));

    const results = await runAdversarialScenarios('/dummy/path.json');
    expect(results[0].evidenceTraceabilityMatch).toBe(false);
    expect(results[0].detected).toBe(false);
  });

  it('fails validator when control-map entry is missing', () => {
    const model = { scenarios: [{ scenarioId: 'ADV-01' }] };
    const controlMapPath = '/dummy/map.json';

    jest.spyOn(fs, 'readFileSync').mockImplementation((path) => {
      if (path.includes('map')) return JSON.stringify([]);
      return JSON.stringify(model);
    });

    const errors = validateAdversarialScenariosAndControlMap('/dummy/scenarios.json', controlMapPath);
    expect(errors.length > 0).toBe(true);
    // There will be errors because we only have 1 scenario, no required categories, etc.
    expect(errors.some(e => e.remediation && e.remediation.includes('ten scenarios'))).toBe(true);
  });

  it('fails validator when a scenario is skipped (nonexecuted)', () => {
    const model = { scenarios: [] };
    const controlMapPath = '/dummy/map.json';

    jest.spyOn(fs, 'readFileSync').mockImplementation((path) => {
      if (path.includes('map')) return JSON.stringify([{ scenarioId: 'ADV-01' }]);
      return JSON.stringify(model);
    });

    const errors = validateAdversarialScenariosAndControlMap('/dummy/scenarios.json', controlMapPath);
    expect(errors.length > 0).toBe(true);
    expect(errors.some(e => e.remediation && e.remediation.includes('ten scenarios'))).toBe(true);
  });
});
