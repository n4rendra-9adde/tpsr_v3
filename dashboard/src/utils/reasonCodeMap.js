export const reasonCodeMap = {
  'PRV-001': 'Valid SLSA Build Level 3 provenance.',
  'PRV-002': 'Provenance signature verification failed.',
  'PRV-003': 'Builder runner identity not in approved whitelist.',
  'PRV-004': 'Provenance predicate schema is unsupported.',
  'PRV-005': 'No build provenance attestation found.',
  'SIG-001': 'Valid Cosign signature bundle verified.',
  'SIG-002': 'Cosign signature verification failed.',
  'SIG-003': 'Keyless certificate OIDC issuer does not match trust policy.',
  'SIG-004': 'Keyless certificate subject identity does not match build workflow.',
  'SIG-005': 'Signature verification timestamp outside validity window.',
  'GOV-001': 'Full v3 trust evaluation passed.',
  'GOV-002': 'v3 trust evaluation not yet executed.',
  'GOV-003': 'Lifecycle transition blocked.',
  'CTX-010': 'Invalid, untrusted, or unauthorized authenticated assertion.',
  'CTX-014': 'Assertor role unauthorized for the declared environment.',
  'INT-001': 'SBOM hash matches ledger exactly.',
  'INT-002': 'SBOM hash mismatch between database and payload.',
  'INT-003': 'SBOM hash mismatch between database and Fabric ledger.',
  'BND-001': 'Three-way cryptographic digest binding verified.',
  'BND-002': 'Provenance subject digest does not match artifact hash.',
  'VEX-001': 'VEX applicability overlay successfully evaluated.',
  'VEX-002': 'VEX statement issued by an unauthorized identity.',
  'EXC-001': 'Active exception covers all vulnerabilities.',
  'EXC-002': 'Policy exception has expired.',
  'EXC-003': 'Policy exception requested by an unauthorized role.'
};

export function getReasonDescription(code) {
  if (!code) return '';
  if (Array.isArray(code)) {
    return code.map(c => `${c}: ${reasonCodeMap[c] || 'Unknown reason'}`).join(' | ');
  }
  return code.split(',').map(c => {
    const trimmed = c.trim();
    return `${trimmed}: ${reasonCodeMap[trimmed] || 'Unknown reason'}`;
  }).join(' | ');
}
