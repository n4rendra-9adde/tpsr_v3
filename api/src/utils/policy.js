'use strict';

var fs = require('fs');
var path = require('path');

var bannedPackagesPath = path.join(__dirname, '../config/banned_packages.json');
var bannedPackages = {};

try {
  if (fs.existsSync(bannedPackagesPath)) {
    bannedPackages = JSON.parse(fs.readFileSync(bannedPackagesPath, 'utf8'));
  }
} catch (e) {
  console.error('[TPSR] Failed to load banned packages registry:', e.message);
}

// Simple semver comparator
// returns 1 if v1 > v2
// returns -1 if v1 < v2
// returns 0 if v1 == v2
function compareVersions(v1, v2) {
  var parts1 = v1.split('.').map(Number);
  var parts2 = v2.split('.').map(Number);
  
  var maxLen = Math.max(parts1.length, parts2.length);
  for (var i = 0; i < maxLen; i++) {
    var p1 = parts1[i] || 0;
    var p2 = parts2[i] || 0;
    if (p1 > p2) return 1;
    if (p1 < p2) return -1;
  }
  return 0;
}

/**
 * Evaluates the SBOM document against automated security policies.
 * @param {Object} sbomJson - The parsed SBOM JSON payload
 * @returns {Object} result - { policy_status: 'PASS'|'FAIL', reason: string, violations: string[], evaluation_mode: string }
 */
function evaluateSBOM(sbomJson) {
  var violations = [];

  if (!sbomJson || typeof sbomJson !== 'object') {
    return {
      policy_status: 'PASS',
      reason: 'No parsable JSON payload provided',
      violations: [],
      evaluation_mode: 'UNKNOWN'
    };
  }

  // 1. Check if vulnerability metadata exists (CycloneDX style)
  var hasVulns = sbomJson.vulnerabilities && Array.isArray(sbomJson.vulnerabilities) && sbomJson.vulnerabilities.length > 0;
  var hasUsableVulnData = false;

  if (hasVulns) {
    // RULE TYPE 1 — Embedded Vulnerability Validation
    for (var v = 0; v < sbomJson.vulnerabilities.length; v++) {
      var vuln = sbomJson.vulnerabilities[v];
      var vulnId = vuln.id || 'Unknown-Vuln';

      if (vuln.ratings && Array.isArray(vuln.ratings)) {
        for (var r = 0; r < vuln.ratings.length; r++) {
          var rating = vuln.ratings[r];

          // Check CVSS Score
          if (rating && rating.score !== undefined && rating.score !== null) {
            hasUsableVulnData = true;
            var numericScore = parseFloat(rating.score);
            if (!isNaN(numericScore) && numericScore >= 8.0) {
              violations.push('Vulnerability ' + vulnId + ' has CVSS score >= 8.0 (' + numericScore + ')');
            }
          }

          // Check Severity
          if (rating && typeof rating.severity === 'string') {
            hasUsableVulnData = true;
            if (rating.severity.trim().toLowerCase() === 'critical') {
              violations.push('Vulnerability ' + vulnId + ' has CRITICAL severity');
            }
          }
        }
      }
    }

    // Only return if we actually found usable vulnerability ratings. 
    // Otherwise, fall through to Rule Type 2.
    if (hasUsableVulnData) {
      if (violations.length > 0) {
        return {
          policy_status: 'FAIL',
          reason: 'Embedded vulnerability validation failed',
          violations: violations,
          evaluation_mode: 'EMBEDDED_VULNERABILITY'
        };
      }

      return {
        policy_status: 'PASS',
        reason: 'No critical embedded vulnerabilities found',
        violations: [],
        evaluation_mode: 'EMBEDDED_VULNERABILITY'
      };
    }
  }

  // RULE TYPE 2 — Internal Security Policy Registry
  // Extract components (CycloneDX style)
  if (sbomJson.components && Array.isArray(sbomJson.components)) {
    for (var c = 0; c < sbomJson.components.length; c++) {
      var comp = sbomJson.components[c];
      var name = comp.name;
      var version = comp.version;

      if (name && version && bannedPackages[name]) {
        var rules = bannedPackages[name];

        // Check blocked versions
        if (rules.blocked_versions && Array.isArray(rules.blocked_versions)) {
          if (rules.blocked_versions.indexOf(version) !== -1) {
            violations.push('Component ' + name + ' is explicitly blocked at version ' + version);
          }
        }

        // Check minimum safe version
        if (rules.minimum_safe_version) {
          if (compareVersions(version, rules.minimum_safe_version) === -1) {
            violations.push('Component ' + name + ' version ' + version + ' is below minimum safe version ' + rules.minimum_safe_version);
          }
        }
      }
    }
  }

  if (violations.length > 0) {
    return {
      policy_status: 'FAIL',
      reason: 'Internal package policy validation failed',
      violations: violations,
      evaluation_mode: 'INTERNAL_PACKAGE_POLICY'
    };
  }

  return {
    policy_status: 'PASS',
    reason: 'Internal package policy passed (no blocked packages found)',
    violations: [],
    evaluation_mode: 'INTERNAL_PACKAGE_POLICY'
  };
}

module.exports = {
  evaluateSBOM: evaluateSBOM,
  compareVersions: compareVersions
};
