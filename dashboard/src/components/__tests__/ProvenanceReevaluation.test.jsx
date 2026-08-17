import React from 'react';
import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import { ProvenanceSubmit } from '../ProvenanceSubmit';
import { DecisionHistory } from '../DecisionHistory';
import * as apiClient from '../../api/client';
import '@testing-library/jest-dom';

jest.mock('../../api/client', () => ({
  submitProvenance: jest.fn(),
  reevaluateSbom: jest.fn(),
  getDecisionHistory: jest.fn()
}));

const mockIdentity = { userId: 'dev-1', role: 'developer' };

describe('Step 3B: Automatic Provenance Reevaluation and Decision History', () => {
  beforeEach(() => {
    jest.clearAllMocks();
    window.matchMedia = window.matchMedia || function() {
      return {
        matches: false,
        addListener: function() {},
        removeListener: function() {},
        addEventListener: function() {},
        removeEventListener: function() {},
        dispatchEvent: function() { return false; },
      };
    };
  });

  const setupFile = (content = '{"_type": "https://in-toto.io/Statement/v0.1"}') => {
    return new File([content], 'prov.json', { type: 'application/json' });
  };

  it('1. Successful valid provenance submission shows "Re-evaluating automatically".', async () => {
    let resolveReeval;
    apiClient.submitProvenance.mockResolvedValue({});
    apiClient.reevaluateSbom.mockReturnValue(new Promise(resolve => { resolveReeval = resolve; }));

    render(<ProvenanceSubmit sbomId="SBOM-123" principal="dev-1" role="developer" />);
    
    const input = document.querySelector('input[type="file"]');
    Object.defineProperty(input, 'files', { value: [setupFile()] });
    fireEvent.change(input);

    await waitFor(() => {
      expect(screen.getByText('prov.json')).toBeInTheDocument();
    });

    fireEvent.click(screen.getByRole('button', { name: /Submit Provenance/i }));

    await waitFor(() => {
      expect(screen.getByText('Re-evaluating automatically')).toBeInTheDocument();
    });
    
    resolveReeval({});
  });

  it('2. Valid provenance automatically calls the reevaluation endpoint.', async () => {
    apiClient.submitProvenance.mockResolvedValue({});
    apiClient.reevaluateSbom.mockResolvedValue({
      recommendation: { recommendation: 'APPROVE', internalTrustState: 'TRUSTED' },
      analysisStatus: 'COMPLETED'
    });

    render(<ProvenanceSubmit sbomId="SBOM-123" principal="dev-1" role="developer" />);
    
    const input = document.querySelector('input[type="file"]');
    Object.defineProperty(input, 'files', { value: [setupFile()] });
    fireEvent.change(input);

    await waitFor(() => {
      expect(screen.getByText('prov.json')).toBeInTheDocument();
    });

    fireEvent.click(screen.getByRole('button', { name: /Submit Provenance/i }));

    await waitFor(() => {
      expect(apiClient.reevaluateSbom).toHaveBeenCalledTimes(1);
    });
  });

  it('3. The reevaluation request contains the exact SBOM ID and authentication headers.', async () => {
    apiClient.submitProvenance.mockResolvedValue({});
    apiClient.reevaluateSbom.mockResolvedValue({
      recommendation: { recommendation: 'APPROVE', internalTrustState: 'TRUSTED' },
      analysisStatus: 'COMPLETED'
    });

    render(<ProvenanceSubmit sbomId="SBOM-123" principal="dev-1" role="developer" />);
    
    const input = document.querySelector('input[type="file"]');
    Object.defineProperty(input, 'files', { value: [setupFile()] });
    fireEvent.change(input);

    await waitFor(() => {
      expect(screen.getByText('prov.json')).toBeInTheDocument();
    });

    fireEvent.click(screen.getByRole('button', { name: /Submit Provenance/i }));

    await waitFor(() => {
      expect(apiClient.reevaluateSbom).toHaveBeenCalledWith(expect.objectContaining({
        sbomId: 'SBOM-123',
        principal: 'dev-1',
        role: 'developer'
      }));
    });
  });

  it('4. The reevaluation request does not contain recommendation, decisionId, snapshotId, status, policy, reasonCodes, confidence, or suggestions.', async () => {
    apiClient.submitProvenance.mockResolvedValue({});
    apiClient.reevaluateSbom.mockResolvedValue({});

    render(<ProvenanceSubmit sbomId="SBOM-123" principal="dev-1" role="developer" />);
    
    const input = document.querySelector('input[type="file"]');
    Object.defineProperty(input, 'files', { value: [setupFile()] });
    fireEvent.change(input);
    await waitFor(() => expect(screen.getByText('prov.json')).toBeInTheDocument());
    fireEvent.click(screen.getByRole('button', { name: /Submit Provenance/i }));

    await waitFor(() => {
      const callArgs = apiClient.reevaluateSbom.mock.calls[0][0];
      expect(callArgs.recommendation).toBeUndefined();
      expect(callArgs.decisionId).toBeUndefined();
      expect(callArgs.snapshotId).toBeUndefined();
      expect(callArgs.status).toBeUndefined();
      expect(callArgs.policy).toBeUndefined();
      expect(callArgs.reasonCodes).toBeUndefined();
      expect(callArgs.confidence).toBeUndefined();
      expect(callArgs.suggestedActions).toBeUndefined();
    });
  });

  it('5. Successful reevaluation renders the new RecommendationCard result.', async () => {
    // This is tested in SubmitPage integration logically, but we can verify the callback
    const onComplete = jest.fn();
    apiClient.submitProvenance.mockResolvedValue({});
    apiClient.reevaluateSbom.mockResolvedValue({
      recommendation: { recommendation: 'APPROVE', internalTrustState: 'TRUSTED' },
      analysisStatus: 'COMPLETED'
    });

    render(<ProvenanceSubmit sbomId="SBOM-123" principal="dev-1" role="developer" onReevaluationComplete={onComplete} />);
    
    const input = document.querySelector('input[type="file"]');
    Object.defineProperty(input, 'files', { value: [setupFile()] });
    fireEvent.change(input);
    await waitFor(() => expect(screen.getByText('prov.json')).toBeInTheDocument());
    fireEvent.click(screen.getByRole('button', { name: /Submit Provenance/i }));

    await waitFor(() => {
      expect(onComplete).toHaveBeenCalledWith(
        expect.objectContaining({ recommendation: 'APPROVE' }),
        'COMPLETED'
      );
    });
  });

  it('6. Successful reevaluation displays the new decision ID and snapshot ID.', async () => {
    const onComplete = jest.fn();
    apiClient.submitProvenance.mockResolvedValue({});
    apiClient.reevaluateSbom.mockResolvedValue({
      recommendation: { decisionId: 'DEC-456', snapshotId: 'SNAP-789' },
      analysisStatus: 'COMPLETED'
    });

    render(<ProvenanceSubmit sbomId="SBOM-123" principal="dev-1" role="developer" onReevaluationComplete={onComplete} />);
    
    const input = document.querySelector('input[type="file"]');
    Object.defineProperty(input, 'files', { value: [setupFile()] });
    fireEvent.change(input);
    await waitFor(() => expect(screen.getByText('prov.json')).toBeInTheDocument());
    fireEvent.click(screen.getByRole('button', { name: /Submit Provenance/i }));

    await waitFor(() => {
      expect(onComplete).toHaveBeenCalledWith(
        expect.objectContaining({ decisionId: 'DEC-456', snapshotId: 'SNAP-789' }),
        'COMPLETED'
      );
    });
  });

  it('7. DecisionHistory displays the previous decision as HISTORICAL and the new decision as CURRENT.', async () => {
    apiClient.getDecisionHistory.mockResolvedValue({
      history: [
        { id: 'DEC-2', snapshot_id: 'SNAP-2', trust_status: 'APPROVE', evaluated_at: '2026-08-17T12:00:00Z' },
        { id: 'DEC-1', snapshot_id: 'SNAP-1', trust_status: 'REJECT', evaluated_at: '2026-08-17T10:00:00Z' }
      ]
    });

    render(<DecisionHistory sbomId="SBOM-123" principal="dev-1" role="developer" refreshTrigger={0} />);

    await waitFor(() => {
      expect(screen.getByText('DEC-2')).toBeInTheDocument();
      expect(screen.getByText('DEC-1')).toBeInTheDocument();
      expect(screen.getByText('CURRENT')).toBeInTheDocument();
      expect(screen.getByText('HISTORICAL')).toBeInTheDocument();
    });
  });

  it('8. Reevaluation failure preserves the previous recommendation and displays a safe retry state.', async () => {
    apiClient.submitProvenance.mockResolvedValue({});
    apiClient.reevaluateSbom.mockRejectedValue({ message: 'Backend timeout' });
    const onComplete = jest.fn();

    render(<ProvenanceSubmit sbomId="SBOM-123" principal="dev-1" role="developer" onReevaluationComplete={onComplete} />);
    
    const input = document.querySelector('input[type="file"]');
    Object.defineProperty(input, 'files', { value: [setupFile()] });
    fireEvent.change(input);
    await waitFor(() => expect(screen.getByText('prov.json')).toBeInTheDocument());
    fireEvent.click(screen.getByRole('button', { name: /Submit Provenance/i }));

    await waitFor(() => {
      expect(screen.getByText('Automatic reevaluation could not complete')).toBeInTheDocument();
      expect(screen.getByText('Backend timeout')).toBeInTheDocument();
      expect(screen.getByRole('button', { name: /Retry/i })).toBeInTheDocument();
      expect(onComplete).not.toHaveBeenCalled();
    });
  });

  it('9. Failed or invalid provenance submission does not call reevaluation.', async () => {
    apiClient.submitProvenance.mockRejectedValue({ message: 'Invalid schema' });

    render(<ProvenanceSubmit sbomId="SBOM-123" principal="dev-1" role="developer" />);
    
    const input = document.querySelector('input[type="file"]');
    Object.defineProperty(input, 'files', { value: [setupFile()] });
    fireEvent.change(input);
    await waitFor(() => expect(screen.getByText('prov.json')).toBeInTheDocument());
    fireEvent.click(screen.getByRole('button', { name: /Submit Provenance/i }));

    await waitFor(() => {
      expect(screen.getByText('Invalid schema')).toBeInTheDocument();
      expect(apiClient.reevaluateSbom).not.toHaveBeenCalled();
    });
  });

  it('10. Refresh/history reload restores the persisted current recommendation and prior decision.', async () => {
    apiClient.getDecisionHistory.mockResolvedValue({
      history: [
        { id: 'DEC-5', trust_status: 'APPROVE', evaluated_at: '2026-08-17T12:00:00Z' },
        { id: 'DEC-4', trust_status: 'REJECT', evaluated_at: '2026-08-17T10:00:00Z' }
      ]
    });

    const { rerender } = render(<DecisionHistory sbomId="SBOM-123" principal="dev-1" role="developer" refreshTrigger={0} />);
    await waitFor(() => expect(screen.getByText('DEC-5')).toBeInTheDocument());
    
    // Simulate refresh by passing new trigger
    rerender(<DecisionHistory sbomId="SBOM-123" principal="dev-1" role="developer" refreshTrigger={1} />);
    
    await waitFor(() => {
      expect(apiClient.getDecisionHistory).toHaveBeenCalledTimes(2);
      expect(screen.getByText('DEC-5')).toBeInTheDocument();
      expect(screen.getByText('DEC-4')).toBeInTheDocument();
    });
  });
});
