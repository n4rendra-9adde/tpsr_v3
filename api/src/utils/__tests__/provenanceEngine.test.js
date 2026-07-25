const { verifyProvenance } = require('../provenanceEngine');

describe('5-Stage SLSA Provenance Verification Engine', () => {
  const validHash = 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855';

  const validAttestation = {
    _type: 'https://in-toto.io/Statement/v0.1',
    subject: [
      {
        name: 'test-artifact.jar',
        digest: {
          sha256: validHash
        }
      }
    ],
    predicateType: 'https://slsa.dev/provenance/v1',
    predicate: {
      buildDefinition: {
        buildType: 'https://actions.github.io/buildtypes/workflow/v1'
      },
      runDetails: {
        builder: {
          id: 'https://github.com/actions/runner/github-hosted'
        }
      }
    }
  };

  test('Stage 1: Rejects invalid or missing attestation envelope', () => {
    const res = verifyProvenance(null, validHash);
    expect(res.status).toBe('INVALID');
    expect(res.reasonCode).toBe('PRV-004');
  });

  test('Stage 2: Rejects attestation when subject digest does not match artifact hash', () => {
    const res = verifyProvenance(validAttestation, '0000000000000000000000000000000000000000000000000000000000000000');
    expect(res.status).toBe('INVALID');
    expect(res.reasonCode).toBe('BND-002');
  });

  test('Stage 3: Rejects attestation from unauthorized builder runner', () => {
    const unauthorizedAtt = JSON.parse(JSON.stringify(validAttestation));
    unauthorizedAtt.predicate.runDetails.builder.id = 'https://unauthorized-runner.example.com';
    const res = verifyProvenance(unauthorizedAtt, validHash);
    expect(res.status).toBe('INVALID');
    expect(res.reasonCode).toBe('PRV-003');
  });

  test('Stage 4 & 5: Successfully verifies valid SLSA Level 3 provenance attestation', () => {
    const res = verifyProvenance(validAttestation, validHash);
    expect(res.status).toBe('VALID');
    expect(res.slsaLevel).toBe('SLSA_BUILD_LEVEL_3');
    expect(res.reasonCode).toBe('PRV-001');
    expect(res.builderId).toBe('https://github.com/actions/runner/github-hosted');
  });
});
