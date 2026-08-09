const { ENUM_ENVIRONMENT, ENUM_INTERNET_EXPOSURE } = require('./contextRiskConstants');

function normalizeEnvironment(val) {
  if (!val) return { originalValue: val, canonicalValue: null, normalized: false, reason: 'Missing' };
  const str = String(val).toUpperCase();
  if (ENUM_ENVIRONMENT.includes(str)) return { originalValue: val, canonicalValue: str, normalized: false, reason: 'Canonical' };
  
  const map = {
    'DEV': 'DEVELOPMENT',
    'PROD': 'PRODUCTION',
    'PROD_CRITICAL': 'PRODUCTION'
  };
  
  if (map[str]) {
    return { originalValue: val, canonicalValue: map[str], normalized: true, reason: `Mapped legacy alias ${str}` };
  }
  
  return { originalValue: val, canonicalValue: null, normalized: false, reason: 'Unsupported alias' };
}

function normalizeExposure(val) {
  if (!val) return { originalValue: val, canonicalValue: null, normalized: false, reason: 'Missing' };
  const str = String(val).toUpperCase();
  if (ENUM_INTERNET_EXPOSURE.includes(str)) return { originalValue: val, canonicalValue: str, normalized: false, reason: 'Canonical' };
  
  const map = {
    'INTERNET': 'PUBLIC'
  };
  
  if (map[str]) {
    return { originalValue: val, canonicalValue: map[str], normalized: true, reason: `Mapped legacy alias ${str}` };
  }
  
  return { originalValue: val, canonicalValue: null, normalized: false, reason: 'Unsupported alias' };
}

module.exports = {
  normalizeEnvironment,
  normalizeExposure
};
