import axios from 'axios';

const _rawApiUrl = (process.env.REACT_APP_API_BASE_URL || 'http://localhost:3000/api').trim();
const API_BASE_URL = _rawApiUrl.endsWith('/') ? _rawApiUrl.slice(0, -1) : _rawApiUrl;

function normalizeError(err) {
  const status = err.response?.status;
  const data = err.response?.data || {};
  return {
    status: status || 500,
    message: data.error || data.message || err.message || 'An unknown API error occurred',
    correlationId: data.correlationId || null
  };
}

export async function submitProvenance({ sbomId, provenancePayload, principal, role }) {
  try {
    const response = await axios.post(
      `${API_BASE_URL}/v1/sbom/${encodeURIComponent(sbomId)}/provenance`,
      provenancePayload,
      {
        headers: {
          'Content-Type': 'application/json',
          'x-user-id': principal,
          'x-user-role': role
        }
      }
    );
    return response.data;
  } catch (err) {
    throw normalizeError(err);
  }
}

export async function reevaluateSbom({ sbomId, principal, role, correlationId }) {
  try {
    const headers = {
      'x-user-id': principal,
      'x-user-role': role
    };
    if (correlationId) {
      headers['x-correlation-id'] = correlationId;
    }
    
    // Does not send caller-selected result metadata like status or decisionId
    const response = await axios.post(
      `${API_BASE_URL}/v1/sbom/${encodeURIComponent(sbomId)}/reevaluate`,
      { triggerType: 'PROVENANCE_CHANGED' },
      { headers }
    );
    return response.data;
  } catch (err) {
    throw normalizeError(err);
  }
}

export async function getDecisionHistory({ sbomId, principal, role }) {
  try {
    const response = await axios.get(
      `${API_BASE_URL}/v1/sbom/${encodeURIComponent(sbomId)}/trust-decision`,
      {
        headers: {
          'x-user-id': principal,
          'x-user-role': role
        }
      }
    );
    return response.data;
  } catch (err) {
    throw normalizeError(err);
  }
}
