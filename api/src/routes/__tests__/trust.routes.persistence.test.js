const request = require('supertest');
const express = require('express');
const trustRoutes = require('../trust.routes');
const sbomRepository = require('../../repositories/sbomRepository');
const trustRepository = require('../../repositories/trustRepository');

const app = express();
app.use(express.json());
app.use('/api', trustRoutes);

jest.mock('../../repositories/sbomRepository');
jest.mock('../../repositories/trustRepository');

describe('Trust Routes Persistence & Reload', () => {
  beforeEach(() => {
    jest.clearAllMocks();
  });

  it('Sanitizes and returns context-risk result properly', async () => {
    sbomRepository.getSBOMDocumentBySBOMID.mockResolvedValue({ id: '1', sbom_hash: 'abc' });
    trustRepository.getTrustDecisionHistoryBySBOMID.mockResolvedValue([
      {
        id: '1',
        sbom_id: '1',
        trust_status: 'CONDITIONALLY_ACCEPTED',
        evidence_summary: JSON.stringify({
          vulnerabilities: [{ effectiveCvssScore: 9.8, effectiveSeverity: 'CRITICAL', suppressedByVex: true, foo: 'bar' }]
        }),
        evidence_dependencies: JSON.stringify({
          contextRisk: {
            modelVersion: '0.1',
            contextAssertionId: 'ctx-1',
            contextAssuranceState: 'AUTHENTICATED',
            normalizedContextVector: { environment: 'PRODUCTION' },
            exploitability: 'NOT_EXPLOITABLE',
            vulnerabilityIds: ['CVE-1'],
            originalCvss: [9.8],
            originalSeverities: ['CRITICAL']
          }
        })
      }
    ]);

    const res = await request(app).get('/api/v1/sbom/1/trust-decision');
    expect(res.status).toBe(200);
    const latest = res.body.latestDecision;
    
    // Check original vulnerabilities
    expect(latest.originalVulnerabilities).toHaveLength(1);
    expect(latest.originalVulnerabilities[0].vulnerabilityId).toBe('CVE-1');
    expect(latest.originalVulnerabilities[0].originalCvss).toBe(9.8);
    expect(latest.originalVulnerabilities[0].originalSeverity).toBe('CRITICAL');

    // Check context risk
    expect(latest.contextRisk).toBeDefined();
    expect(latest.contextRisk.contextModelVersion).toBe('0.1');
    expect(latest.contextRisk.contextAssertionId).toBe('ctx-1');
    expect(latest.contextRisk.environment).toBe('PRODUCTION');
    expect(latest.contextRisk.exploitability).toBe('NOT_EXPLOITABLE');

    // Check forbidden fields removed
    expect(latest.evidence_summary.vulnerabilities[0].effectiveCvssScore).toBeUndefined();
    expect(latest.evidence_summary.vulnerabilities[0].effectiveSeverity).toBeUndefined();
    expect(latest.evidence_summary.vulnerabilities[0].suppressedByVex).toBeUndefined();
    expect(latest.evidence_summary.vulnerabilities[0].foo).toBe('bar');
    
    // Raw evidence dependencies removed
    expect(latest.evidence_dependencies).toBeUndefined();
  });

  it('Historical decisions without contextRisk remain readable', async () => {
    sbomRepository.getSBOMDocumentBySBOMID.mockResolvedValue({ id: '1', sbom_hash: 'abc' });
    trustRepository.getTrustDecisionHistoryBySBOMID.mockResolvedValue([
      {
        id: '2',
        sbom_id: '1',
        trust_status: 'TRUSTED',
        evidence_summary: JSON.stringify({ vulnerabilities: [] }),
        evidence_dependencies: JSON.stringify({ provenance: { required: true } }) // NO contextRisk
      }
    ]);

    const res = await request(app).get('/api/v1/sbom/1/trust-decision');
    expect(res.status).toBe(200);
    const latest = res.body.latestDecision;
    
    expect(latest.contextRisk).toBeNull();
    expect(latest.originalVulnerabilities).toEqual([]);
    expect(latest.evidence_dependencies).toBeUndefined();
  });
});
