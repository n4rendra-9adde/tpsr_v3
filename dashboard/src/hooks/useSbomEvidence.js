import { useState, useCallback } from 'react';
import axios from 'axios';

const API_BASE_URL = process.env.REACT_APP_API_URL || 'http://localhost:3000/api';

export function useSbomEvidence() {
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  
  // Normalized Models
  const [documentData, setDocumentData] = useState(null);
  const [signatureData, setSignatureData] = useState(null);
  const [provenanceData, setProvenanceData] = useState(null);
  const [vexData, setVexData] = useState([]);
  const [contextAssertionData, setContextAssertionData] = useState(null);
  const [exceptionsData, setExceptionsData] = useState([]);
  const [trustDecisionData, setTrustDecisionData] = useState(null);
  
  // Diagnostics
  const [diagnostics, setDiagnostics] = useState([]);

  const reset = useCallback(() => {
    setDocumentData(null);
    setSignatureData(null);
    setProvenanceData(null);
    setVexData([]);
    setContextAssertionData(null);
    setExceptionsData([]);
    setTrustDecisionData(null);
    setError(null);
    setDiagnostics([]);
  }, []);

  const fetchEvidence = useCallback(async (sbomId, identity) => {
    if (!sbomId || !identity) return;
    
    setLoading(true);
    reset();

    const headers = { 
      'x-user-id': identity.userId, 
      'x-user-role': identity.role 
    };

    const endpoints = [
      { name: 'document', url: `${API_BASE_URL}/sboms/${encodeURIComponent(sbomId)}/document` },
      { name: 'signatures', url: `${API_BASE_URL}/v1/sbom/${encodeURIComponent(sbomId)}/signatures` },
      { name: 'provenance', url: `${API_BASE_URL}/v1/sbom/${encodeURIComponent(sbomId)}/provenance` },
      { name: 'vex', url: `${API_BASE_URL}/v1/sbom/${encodeURIComponent(sbomId)}/vex` },
      { name: 'contextAssertions', url: `${API_BASE_URL}/v1/sbom/${encodeURIComponent(sbomId)}/context/assertions` },
      { name: 'exceptions', url: `${API_BASE_URL}/v1/sbom/${encodeURIComponent(sbomId)}/exceptions` },
      { name: 'trustDecision', url: `${API_BASE_URL}/v1/sbom/${encodeURIComponent(sbomId)}/trust-decision` }
    ];

    try {
      const results = await Promise.allSettled(
        endpoints.map(ep => axios.get(ep.url, { headers }))
      );

      const logs = [];

      results.forEach((res, index) => {
        const ep = endpoints[index];
        let status = 'Error';
        let count = 0;
        let emptyReason = null;
        let parseError = null;

        if (res.status === 'fulfilled') {
          status = res.value.status;
          const data = res.value.data;
          
          try {
            if (ep.name === 'document') {
              count = 1;
              setDocumentData(data);
            } else if (ep.name === 'signatures') {
              const records = data.signatures || [];
              count = records.length;
              if (count > 0) {
                const rec = records[0];
                setSignatureData({
                  verificationStatus: rec.verification_status || rec.verificationStatus,
                  verificationMode: rec.verification_mode || rec.verificationMode,
                  signatureType: rec.signature_type || rec.signatureType,
                  targetType: rec.target_type || rec.targetType,
                  targetDigest: rec.target_digest || rec.targetDigest || rec.artifact_hash || rec.artifactHash,
                  signerIdentity: rec.signer_identity || rec.signerIdentity,
                  publicKeyFingerprint: rec.public_key_fingerprint || rec.publicKeyFingerprint,
                  transparencyLogVerified: rec.transparency_log_verified !== undefined ? rec.transparency_log_verified : rec.transparencyLogVerified,
                  verifiedAt: rec.verified_at || rec.verifiedAt,
                  reasonCodes: rec.reason_codes || rec.reasonCodes,
                  failureReason: rec.failure_reason || rec.failureReason
                });
              } else {
                emptyReason = 'No signature records found';
              }
            } else if (ep.name === 'provenance') {
              const records = data.attestations || data.provenanceRecords || [];
              count = records.length;
              if (count > 0) {
                const rec = records[0];
                setProvenanceData({
                  verificationStatus: rec.status || rec.verification_status || rec.verificationStatus,
                  predicateType: rec.predicate_type || rec.predicateType || rec.attestation_type || rec.attestationType,
                  predicateVersion: rec.predicate_version || rec.predicateVersion || rec.slsa_level || rec.slsaLevel,
                  builderIdentity: rec.builder_identity || rec.builderIdentity || rec.builder_id || rec.builderId,
                  sourceRepository: rec.source_repository || rec.sourceRepository,
                  sourceCommit: rec.source_commit || rec.sourceCommit,
                  buildType: rec.build_type || rec.buildType,
                  startedOn: rec.started_on || rec.startedOn,
                  finishedOn: rec.finished_on || rec.finishedOn,
                  freshnessStatus: rec.freshness_status || rec.freshnessStatus,
                  replayStatus: rec.replay_status || rec.replayStatus,
                  envelopeSignatureStatus: rec.envelope_signature_status || rec.envelopeSignatureStatus,
                  bindingStatus: rec.binding_status || rec.bindingStatus,
                  policyVersion: rec.policy_version || rec.policyVersion,
                  reasonCodes: rec.reason_codes || rec.reasonCodes
                });
              } else {
                emptyReason = 'No provenance records found';
              }
            } else if (ep.name === 'vex') {
              const records = data.vexStatements || [];
              count = records.length;
              if (count > 0) {
                setVexData(records.map(rec => ({
                  vulnerabilityId: rec.vulnerability_id || rec.vulnerabilityId,
                  originalCvssScore: rec.original_cvss_score !== undefined ? rec.original_cvss_score : rec.original_cvss !== undefined ? rec.original_cvss : rec.originalCvssScore,
                  originalSeverity: rec.original_severity || rec.originalSeverity,
                  componentIdentity: rec.component_identity || rec.componentIdentity || rec.component_identifiers || rec.componentIdentifiers,
                  packageOrRelease: rec.package_or_release || rec.packageOrRelease || rec.release_identifiers || rec.releaseIdentifiers,
                  vexStatus: rec.applicability_status || rec.applicabilityStatus || rec.vex_status || rec.vexStatus,
                  justification: rec.justification,
                  applicabilityDisposition: rec.applicability_disposition || rec.applicabilityDisposition,
                  policyBlockingStatus: rec.policy_blocking_status || rec.policyBlockingStatus || rec.policy_impact || rec.policyImpact,
                  productMatch: rec.product_match !== undefined ? rec.product_match : rec.productMatch,
                  releaseMatch: rec.release_match !== undefined ? rec.release_match : rec.releaseMatch,
                  digestManifestMatch: rec.digest_manifest_match !== undefined ? rec.digest_manifest_match : rec.digestManifestMatch,
                  componentMatch: rec.component_match !== undefined ? rec.component_match : rec.componentMatch,
                  vulnerabilityIdMatch: rec.vulnerability_id_match !== undefined ? rec.vulnerability_id_match : rec.vulnerabilityIdMatch,
                  reasonCodes: rec.reason_codes || rec.reasonCodes
                })));
              } else {
                emptyReason = 'No VEX statements found';
              }
            } else if (ep.name === 'contextAssertions') {
              const records = data.assertions || [];
              const active = records.filter(r => r.status === 'ACTIVE');
              count = active.length;
              if (count > 0) {
                const rec = active[0];
                setContextAssertionData({
                  status: rec.status,
                  environment: rec.environment,
                  assertor: rec.asserted_by,
                  role: rec.assertor_role,
                  signerFingerprint: rec.public_key_fingerprint,
                  assertionTime: rec.asserted_at,
                  expiry: rec.valid_until,
                  releaseBinding: rec.digest_manifest_digest,
                  verificationStatus: rec.verification_status,
                  assuranceState: rec.assurance_state,
                  ruleIds: rec.rule_ids || [],
                  reasonCodes: rec.reason_codes || []
                });
              } else {
                emptyReason = 'No active context assertions found';
              }
            } else if (ep.name === 'exceptions') {
              if (data.policyExceptions && data.policyExceptions.length > 0) {
                count = data.policyExceptions.length;
                setExceptionsData(data.policyExceptions);
              } else {
                emptyReason = 'No policy exceptions requested or active';
              }
            } else if (ep.name === 'trustDecision') {
              count = 1;
              if (data.latestDecision) {
                setTrustDecisionData(data.latestDecision);
              }
            }
          } catch (err) {
            parseError = err.message;
          }
        } else {
          status = res.reason.response ? res.reason.response.status : 'Network Error';
          emptyReason = res.reason.message;
        }

        logs.push({
          endpoint: ep.url,
          status,
          count,
          parseError,
          emptyReason
        });
      });

      setDiagnostics(logs);

      // Check if document fetch failed (critical)
      if (results[0].status === 'rejected') {
        setError(results[0].reason.response?.data?.error || 'Failed to load SBOM document');
      }

    } catch (err) {
      setError(err.message || 'An unexpected error occurred');
    } finally {
      setLoading(false);
    }
  }, [reset]);

  return {
    loading,
    error,
    documentData,
    signatureData,
    provenanceData,
    vexData,
    contextAssertionData,
    exceptionsData,
    trustDecisionData,
    diagnostics,
    fetchEvidence,
    reset
  };
}
