'use strict';

/**
 * CVSS-Only Assessment
 * 
 * Rules:
 * 1. Missing vulnerability information: NOT_EVALUATED
 * 2. Highest original CVSS >= threshold: REJECT
 * 3. Highest original CVSS < threshold: ACCEPT
 */
function evaluate(input, threshold = 8.0) {
  if (!input || input.vulnerabilities === undefined) {
    return { outcome: 'NOT_EVALUATED', decision: 'NOT_EVALUATED' };
  }
  
  if (input.vulnerabilities.length === 0) {
    return { outcome: 'PERMIT', decision: 'ACCEPT' };
  }

  let highestCvss = 0;
  for (const vuln of input.vulnerabilities) {
    if (vuln.originalCvss !== undefined && vuln.originalCvss > highestCvss) {
      highestCvss = vuln.originalCvss;
    }
  }

  if (highestCvss >= threshold) {
    return { outcome: 'BLOCK', decision: 'REJECT' };
  } else {
    return { outcome: 'PERMIT', decision: 'ACCEPT' };
  }
}

module.exports = { evaluate };
