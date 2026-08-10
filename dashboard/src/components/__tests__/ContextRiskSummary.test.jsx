import React from 'react';
import { render, screen } from '@testing-library/react';
import ContextRiskSummary from '../ContextRiskSummary';

describe('ContextRiskSummary', () => {
  const mockContextRisk = {
    contextAssuranceState: 'VERIFIED_TRUSTED',
    contextAssertionId: 'ctx-123',
    contextModelVersion: '0.1',
    contextEvaluatedAt: '2023-01-01T00:00:00Z',
    environment: 'PRODUCTION',
    internetExposure: 'PUBLIC',
    assetCriticality: 'HIGH',
    privilegeLevel: 'LOW',
    dataSensitivity: 'HIGH',
    runtimeExecution: 'EXECUTED',
    componentPresence: 'PRESENT',
    exploitability: 'EXPLOITABLE',
    exploitabilityBasis: 'Trusted AFFECTED VEX with executed component',
    vexApplicability: 'AFFECTED',
    exceptionStatus: 'ACTIVE',
    exceptionId: 'exc-123',
    contextualRisk: 'CRITICAL',
    policyBlockingStatus: 'BLOCKING',
    reviewRequired: false,
    exceptionRequired: true,
    triggeredContextRuleIds: ['CAECTD-R017'],
    evaluatedContextRuleIds: ['CAECTD-R001', 'CAECTD-R017'],
    contextReasonCodes: ['CTX-003'],
    conflictResults: null
  };

  const mockOriginalVulnerabilities = [
    {
      vulnerabilityId: 'CVE-2023-1234',
      originalCvss: 9.8,
      originalSeverity: 'CRITICAL'
    }
  ];

  it('renders trusted context result all authoritative sections', () => {
    render(
      <ContextRiskSummary 
        contextRisk={mockContextRisk} 
        originalVulnerabilities={mockOriginalVulnerabilities} 
        isSimulation={false} 
      />
    );
    
    expect(screen.getByText('AUTHENTICATED CONTEXT RESULT')).toBeInTheDocument();
    expect(screen.getByText('ctx-123')).toBeInTheDocument();
    expect(screen.getByText('VERIFIED_TRUSTED')).toBeInTheDocument();
    expect(screen.getByText('CVE-2023-1234')).toBeInTheDocument();
    expect(screen.getByText('9.8')).toBeInTheDocument();
    expect(screen.getAllByText('CRITICAL').length).toBeGreaterThan(0);
    expect(screen.getByText('AFFECTED')).toBeInTheDocument();
    expect(screen.getByText('EXPLOITABLE')).toBeInTheDocument();
    expect(screen.getByText('BLOCKING')).toBeInTheDocument();
    expect(screen.getByText('CAECTD-R017')).toBeInTheDocument();
  });

  it('renders MISSING and REVIEW_REQUIRED for missing context', () => {
    const missingRisk = { ...mockContextRisk, contextAssuranceState: 'MISSING', policyBlockingStatus: 'REVIEW_REQUIRED' };
    render(<ContextRiskSummary contextRisk={missingRisk} isSimulation={false} />);
    
    expect(screen.getAllByText('MISSING').length).toBeGreaterThan(0);
    expect(screen.getByText('REVIEW_REQUIRED')).toBeInTheDocument();
  });

  it('renders CONFLICTING and conflict warning', () => {
    const conflictingRisk = { ...mockContextRisk, contextAssuranceState: 'CONFLICTING', conflictResults: { error: 'Mismatch' } };
    render(<ContextRiskSummary contextRisk={conflictingRisk} isSimulation={false} />);
    
    expect(screen.getByText('CONFLICTING')).toBeInTheDocument();
    expect(screen.getByText('Conflicts detected:')).toBeInTheDocument();
  });

  it('renders NOT_AFFECTED VEX distinct from original', () => {
    const notAffectedRisk = { ...mockContextRisk, policyBlockingStatus: 'NON_BLOCKING', vexApplicability: 'NOT_AFFECTED', exploitability: 'NOT_EXPLOITABLE' };
    render(<ContextRiskSummary contextRisk={notAffectedRisk} originalVulnerabilities={mockOriginalVulnerabilities} isSimulation={false} />);
    
    expect(screen.getByText('9.8')).toBeInTheDocument();
    expect(screen.getAllByText('CRITICAL').length).toBeGreaterThan(0);
    expect(screen.getByText('NOT_AFFECTED')).toBeInTheDocument();
    expect(screen.getByText('NOT_EXPLOITABLE')).toBeInTheDocument();
    expect(screen.getByText('NON_BLOCKING')).toBeInTheDocument();
  });

  it('renders active exception ID', () => {
    render(<ContextRiskSummary contextRisk={mockContextRisk} isSimulation={false} />);
    expect(screen.getByText('exc-123')).toBeInTheDocument();
  });

  it('displays historical unavailability message', () => {
    render(<ContextRiskSummary contextRisk={null} isSimulation={false} />);
    expect(screen.getByText('CONTEXT RISK NOT AVAILABLE FOR THIS HISTORICAL DECISION')).toBeInTheDocument();
  });

  it('renders simulation warning', () => {
    render(<ContextRiskSummary contextRisk={mockContextRisk} isSimulation={true} />);
    expect(screen.getByText('SIMULATION ONLY')).toBeInTheDocument();
  });

  it('handles empty arrays without crashing', () => {
    const emptyRisk = { ...mockContextRisk, triggeredContextRuleIds: [], evaluatedContextRuleIds: [], contextReasonCodes: [] };
    render(<ContextRiskSummary contextRisk={emptyRisk} originalVulnerabilities={[]} isSimulation={false} />);
    expect(screen.getAllByText('None').length).toBeGreaterThan(0);
    expect(screen.getByText('No vulnerabilities present.')).toBeInTheDocument();
  });
});
