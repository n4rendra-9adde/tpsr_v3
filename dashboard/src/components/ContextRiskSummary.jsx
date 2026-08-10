import React from 'react';

const ContextRiskSummary = ({ contextRisk, originalVulnerabilities = [], isSimulation = false }) => {
  if (isSimulation) {
    return (
      <div className="bg-yellow-50 border-l-4 border-yellow-400 p-4 mb-4">
        <h3 className="text-yellow-800 font-bold">SIMULATION ONLY</h3>
        <p className="text-yellow-700">This context risk output is a simulation and not an authoritative context result.</p>
      </div>
    );
  }

  if (!contextRisk) {
    return (
      <div className="bg-gray-50 border border-gray-200 p-4 rounded mb-4">
        <h3 className="font-bold text-gray-700">CONTEXT RISK NOT AVAILABLE FOR THIS HISTORICAL DECISION</h3>
      </div>
    );
  }

  const {
    contextAssuranceState,
    contextAssertionId,
    contextModelVersion,
    contextEvaluatedAt,
    environment,
    internetExposure,
    assetCriticality,
    privilegeLevel,
    dataSensitivity,
    runtimeExecution,
    componentPresence,
    exploitability,
    exploitabilityBasis,
    vexApplicability,
    exceptionStatus,
    exceptionId,
    contextualRisk,
    policyBlockingStatus,
    reviewRequired,
    exceptionRequired,
    triggeredContextRuleIds,
    evaluatedContextRuleIds,
    contextReasonCodes,
    conflictResults
  } = contextRisk;

  return (
    <div className="context-risk-summary border border-blue-200 rounded p-4 mb-4 shadow-sm">
      <h2 className="text-xl font-bold mb-4 text-blue-800 border-b pb-2">AUTHENTICATED CONTEXT RESULT</h2>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-6 mb-6">
        <section className="bg-gray-50 p-3 rounded">
          <h3 className="font-bold text-gray-700 border-b pb-1 mb-2">A. Authenticated Context</h3>
          <ul className="text-sm space-y-1">
            <li><strong>Assurance State:</strong> <span className={`px-2 py-0.5 rounded text-xs font-bold ${contextAssuranceState === 'VERIFIED_TRUSTED' ? 'bg-green-100 text-green-800' : contextAssuranceState === 'CONFLICTING' ? 'bg-orange-100 text-orange-800' : contextAssuranceState === 'MISSING' ? 'bg-red-100 text-red-800' : 'bg-gray-200'}`}>{contextAssuranceState || 'MISSING'}</span></li>
            <li><strong>Assertion ID:</strong> {contextAssertionId}</li>
            <li><strong>Model Version:</strong> {contextModelVersion}</li>
            <li><strong>Evaluated At:</strong> {contextEvaluatedAt}</li>
          </ul>
        </section>

        <section className="bg-gray-50 p-3 rounded">
          <h3 className="font-bold text-gray-700 border-b pb-1 mb-2">B. Deployment Context</h3>
          <ul className="text-sm space-y-1">
            <li><strong>Environment:</strong> {environment}</li>
            <li><strong>Internet Exposure:</strong> {internetExposure}</li>
            <li><strong>Asset Criticality:</strong> {assetCriticality}</li>
            <li><strong>Privilege Level:</strong> {privilegeLevel}</li>
            <li><strong>Data Sensitivity:</strong> {dataSensitivity}</li>
            <li><strong>Runtime Execution:</strong> {runtimeExecution}</li>
            <li><strong>Component Presence:</strong> {componentPresence}</li>
          </ul>
        </section>
      </div>

      <section className="mb-6 bg-gray-50 p-3 rounded">
        <h3 className="font-bold text-gray-700 border-b pb-1 mb-2">C. Vulnerability Interpretation</h3>
        {originalVulnerabilities.length > 0 ? (
          <table className="min-w-full bg-white text-sm text-left">
            <thead>
              <tr className="bg-gray-100">
                <th className="py-2 px-3 border-b">Vuln ID</th>
                <th className="py-2 px-3 border-b">Original CVSS</th>
                <th className="py-2 px-3 border-b">Original Severity</th>
                <th className="py-2 px-3 border-b">VEX Applicability</th>
                <th className="py-2 px-3 border-b">Derived Exploitability</th>
                <th className="py-2 px-3 border-b">Exploitability Basis</th>
              </tr>
            </thead>
            <tbody>
              {originalVulnerabilities.map((v, i) => (
                <tr key={i} className="border-b">
                  <td className="py-1 px-3">{v.vulnerabilityId}</td>
                  <td className="py-1 px-3">{v.originalCvss ?? 'N/A'}</td>
                  <td className="py-1 px-3">{v.originalSeverity}</td>
                  <td className="py-1 px-3">{vexApplicability}</td>
                  <td className="py-1 px-3 font-semibold">{exploitability}</td>
                  <td className="py-1 px-3 text-xs">{exploitabilityBasis}</td>
                </tr>
              ))}
            </tbody>
          </table>
        ) : (
          <p className="text-sm text-gray-500 italic">No vulnerabilities present.</p>
        )}
      </section>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-6 mb-6">
        <section className="bg-gray-50 p-3 rounded">
          <h3 className="font-bold text-gray-700 border-b pb-1 mb-2">D. Policy Result</h3>
          <ul className="text-sm space-y-1">
            <li><strong>Contextual Risk:</strong> {contextualRisk}</li>
            <li><strong>Policy-Blocking Status:</strong> <span className={`px-2 py-0.5 rounded text-xs font-bold ${policyBlockingStatus === 'BLOCKING' ? 'bg-red-100 text-red-800' : policyBlockingStatus === 'REVIEW_REQUIRED' ? 'bg-orange-100 text-orange-800' : 'bg-green-100 text-green-800'}`}>{policyBlockingStatus}</span></li>
            <li><strong>Review Required:</strong> {reviewRequired ? 'Yes' : 'No'}</li>
            <li><strong>Exception Required:</strong> {exceptionRequired ? 'Yes' : 'No'}</li>
            <li><strong>Exception Status:</strong> {exceptionStatus}</li>
            <li><strong>Exception ID:</strong> {exceptionId}</li>
          </ul>
        </section>

        <section className="bg-gray-50 p-3 rounded overflow-hidden">
          <h3 className="font-bold text-gray-700 border-b pb-1 mb-2">E. Explanation and Traceability</h3>
          <div className="text-sm space-y-2 h-32 overflow-y-auto">
            <div><strong>Triggered Rules:</strong> {triggeredContextRuleIds?.length ? triggeredContextRuleIds.join(', ') : 'None'}</div>
            <div><strong>Evaluated Rules:</strong> {evaluatedContextRuleIds?.length ? evaluatedContextRuleIds.join(', ') : 'None'}</div>
            <div><strong>Reason Codes:</strong> {contextReasonCodes?.length ? contextReasonCodes.join(', ') : 'None'}</div>
            {conflictResults && (
               <div className="bg-orange-50 text-orange-800 p-2 rounded mt-2 border border-orange-200">
                 <strong>Conflicts detected:</strong>
                 <pre className="text-xs mt-1 whitespace-pre-wrap">{JSON.stringify(conflictResults, null, 2)}</pre>
               </div>
            )}
          </div>
        </section>
      </div>
    </div>
  );
};

export default ContextRiskSummary;
