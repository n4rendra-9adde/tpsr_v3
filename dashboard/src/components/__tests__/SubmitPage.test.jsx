import React from 'react';
import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import SubmitPage from '../SubmitPage';
import axios from 'axios';
import '@testing-library/jest-dom';

jest.mock('axios');

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

const mockIdentity = { userId: 'dev-1', role: 'developer' };

describe('SubmitPage Automatic Recommendation (Step 3A)', () => {
  beforeEach(() => {
    jest.clearAllMocks();
  });

  const setupFile = () => {
    const file = new File(['{"serialNumber": "SBOM-123"}'], 'sbom.json', { type: 'application/json' });
    return file;
  };

  it('1. Upload pending state displays "Uploading and analyzing SBOM" and disables duplicate submission.', async () => {
    // We mock a long-running promise to test pending state
    let resolvePost;
    const pendingPromise = new Promise((resolve) => { resolvePost = resolve; });
    axios.post.mockReturnValue(pendingPromise);
    
    render(<SubmitPage selectedIdentity={mockIdentity} />);
    
    const file = setupFile();
    const input = document.querySelector('input[type="file"]');
    Object.defineProperty(input, 'files', { value: [file] });
    fireEvent.change(input);

    await waitFor(() => {
      expect(screen.getByPlaceholderText('Enter SBOM ID')).toHaveValue('SBOM-123');
    });

    const submitBtn = screen.getByRole('button', { name: /Submit SBOM|Uploading and analyzing SBOM/i });
    fireEvent.click(submitBtn);

    expect(screen.getByRole('button', { name: /Uploading and analyzing SBOM/i })).toBeInTheDocument();
    expect(screen.getByRole('button', { name: /Uploading and analyzing SBOM/i })).toBeDisabled();
    
    // Resolve promise to clean up
    resolvePost({ data: { submissionStatus: 'ACCEPTED' } });
  });

  it('2. Successful submission renders RecommendationCard from the submission response without sending a separate Evaluate/compliance request.', async () => {
    axios.post.mockResolvedValue({
      data: {
        submissionStatus: 'ACCEPTED',
        analysisStatus: 'COMPLETED',
        recommendation: {
          recommendation: 'APPROVE',
          internalTrustState: 'TRUSTED'
        }
      }
    });

    render(<SubmitPage selectedIdentity={mockIdentity} />);
    
    const file = setupFile();
    const input = document.querySelector('input[type="file"]');
    Object.defineProperty(input, 'files', { value: [file] });
    fireEvent.change(input);

    await waitFor(() => {
      expect(screen.getByPlaceholderText('Enter SBOM ID')).toHaveValue('SBOM-123');
    });

    fireEvent.click(screen.getByRole('button', { name: /Submit SBOM/i }));

    await waitFor(() => {
      expect(screen.getByText('APPROVE')).toBeInTheDocument();
      expect(screen.getByText('TRUSTED')).toBeInTheDocument();
    });

    expect(axios.post).toHaveBeenCalledTimes(1);
    expect(axios.post).toHaveBeenCalledWith(
      expect.stringContaining('/submit'),
      expect.any(Object),
      expect.any(Object)
    );
  });

  it('3. REJECT renders the primary Rule ID, primary reason code, blocking finding, and server-provided suggestion.', async () => {
    axios.post.mockResolvedValue({
      data: {
        submissionStatus: 'ACCEPTED',
        analysisStatus: 'COMPLETED',
        recommendation: {
          recommendation: 'REJECT',
          internalTrustState: 'UNTRUSTED',
          primaryRuleId: 'RULE-INT-1',
          primaryReasonCode: 'INT-001',
          blockingFindings: ['Hash mismatch'],
          suggestedActions: [
            { message: 'Regenerate the artifact and SBOM.', requiredRole: 'developer', requiredEvidenceType: 'ARTIFACT' }
          ]
        }
      }
    });

    render(<SubmitPage selectedIdentity={mockIdentity} />);
    
    const file = setupFile();
    const input = document.querySelector('input[type="file"]');
    Object.defineProperty(input, 'files', { value: [file] });
    fireEvent.change(input);

    await waitFor(() => {
      expect(screen.getByPlaceholderText('Enter SBOM ID')).toHaveValue('SBOM-123');
    });

    fireEvent.click(screen.getByRole('button', { name: /Submit SBOM/i }));

    await waitFor(() => {
      expect(screen.getByText('REJECT')).toBeInTheDocument();
      expect(screen.getByText('RULE-INT-1')).toBeInTheDocument();
      expect(screen.getByText('INT-001')).toBeInTheDocument();
      expect(screen.getByText('Hash mismatch')).toBeInTheDocument();
      expect(screen.getByText('Regenerate the artifact and SBOM.')).toBeInTheDocument();
    });
  });

  it('4. REJECT does not render a generic Approve button.', async () => {
    axios.post.mockResolvedValue({
      data: {
        submissionStatus: 'ACCEPTED',
        analysisStatus: 'COMPLETED',
        recommendation: {
          recommendation: 'REJECT',
          internalTrustState: 'UNTRUSTED'
        }
      }
    });

    render(<SubmitPage selectedIdentity={mockIdentity} />);
    
    const file = setupFile();
    const input = document.querySelector('input[type="file"]');
    Object.defineProperty(input, 'files', { value: [file] });
    fireEvent.change(input);

    await waitFor(() => {
      expect(screen.getByPlaceholderText('Enter SBOM ID')).toHaveValue('SBOM-123');
    });

    fireEvent.click(screen.getByRole('button', { name: /Submit SBOM/i }));

    await waitFor(() => {
      expect(screen.getByText('REJECT')).toBeInTheDocument();
    });

    const approveButtons = screen.queryAllByRole('button', { name: /Approve/i });
    expect(approveButtons.length).toBe(0);
  });

  it('5. MANUAL_REVIEW_REQUIRED renders an explicit security-review-required state.', async () => {
    axios.post.mockResolvedValue({
      data: {
        submissionStatus: 'ACCEPTED',
        analysisStatus: 'COMPLETED',
        recommendation: {
          recommendation: 'MANUAL_REVIEW_REQUIRED',
          internalTrustState: 'REVIEW_REQUIRED'
        }
      }
    });

    render(<SubmitPage selectedIdentity={mockIdentity} />);
    
    const file = setupFile();
    const input = document.querySelector('input[type="file"]');
    Object.defineProperty(input, 'files', { value: [file] });
    fireEvent.change(input);

    await waitFor(() => {
      expect(screen.getByPlaceholderText('Enter SBOM ID')).toHaveValue('SBOM-123');
    });

    fireEvent.click(screen.getByRole('button', { name: /Submit SBOM/i }));

    await waitFor(() => {
      expect(screen.getByText('MANUAL_REVIEW_REQUIRED')).toBeInTheDocument();
      expect(screen.getByText('A manual security review is required before this artifact can be approved.')).toBeInTheDocument();
    });
  });

  it('6. ANALYSIS_INCOMPLETE renders a safe incomplete state and does not use approval styling.', async () => {
    axios.post.mockResolvedValue({
      data: {
        submissionStatus: 'ACCEPTED',
        analysisStatus: 'INCOMPLETE',
        recommendation: {
          correlationId: 'corr-999'
        }
      }
    });

    render(<SubmitPage selectedIdentity={mockIdentity} />);
    
    const file = setupFile();
    const input = document.querySelector('input[type="file"]');
    Object.defineProperty(input, 'files', { value: [file] });
    fireEvent.change(input);

    await waitFor(() => {
      expect(screen.getByPlaceholderText('Enter SBOM ID')).toHaveValue('SBOM-123');
    });

    fireEvent.click(screen.getByRole('button', { name: /Submit SBOM/i }));

    await waitFor(() => {
      expect(screen.getByText('Analysis Incomplete')).toBeInTheDocument();
      expect(screen.getByText('corr-999')).toBeInTheDocument();
    });

    expect(screen.queryByText('APPROVE')).not.toBeInTheDocument();
  });
});
