import "@testing-library/jest-dom";
import React from 'react';
import { render, screen } from '@testing-library/react';
import { SignatureEvidenceCard, ProvenanceEvidenceCard, VexApplicabilityTable } from '../index';

describe('Evidence Components', () => {

  describe('SignatureEvidenceCard', () => {
    it('renders empty state when signatureData is null', () => {
      render(<SignatureEvidenceCard signatureData={null} />);
      expect(screen.getByText('Signature evidence unavailable')).toBeInTheDocument();
    });

    it('renders populated state with offline-keyed mode correctly', () => {
      const mockData = {
        verificationStatus: 'VERIFIED',
        verificationMode: 'offline-keyed',
        signatureType: 'x509',
        targetDigest: 'sha256:abc1234',
        signerIdentity: 'spiffe://example.org/builder',
        reasonCodes: 'SIG-001'
      };
      
      render(<SignatureEvidenceCard signatureData={mockData} />);
      expect(screen.getByText('Transparency log not checked in offline-keyed mode')).toBeInTheDocument();
      expect(screen.getByText('spiffe://example.org/builder')).toBeInTheDocument();
      expect(screen.getByText('SIG-001')).toBeInTheDocument();
      // Should show VERIFIED
      const tags = screen.getAllByText('VERIFIED');
      expect(tags.length).toBeGreaterThan(0);
    });
  });

  describe('ProvenanceEvidenceCard', () => {
    it('renders empty state when provenanceData is null', () => {
      render(<ProvenanceEvidenceCard provenanceData={null} />);
      expect(screen.getByText('Provenance evidence unavailable')).toBeInTheDocument();
    });

    it('renders populated state without certification label', () => {
      const mockData = {
        verificationStatus: 'VERIFIED',
        predicateType: 'https://slsa.dev/provenance/v1',
        builderIdentity: 'https://github.com/actions/runner',
        freshnessStatus: 'PASS',
        bindingStatus: 'PASS'
      };
      
      render(<ProvenanceEvidenceCard provenanceData={mockData} />);
      // Should find builder
      expect(screen.getByText('https://github.com/actions/runner')).toBeInTheDocument();
      expect(screen.getByText('https://slsa.dev/provenance/v1')).toBeInTheDocument();
    });
  });

  describe('VexApplicabilityTable', () => {
    it('renders empty state when vulnerabilities is empty', () => {
      render(<VexApplicabilityTable vulnerabilities={[]} />);
      expect(screen.getByText('No vulnerabilities found')).toBeInTheDocument();
    });

    it('renders vulnerabilities with componentIdentity and packageOrRelease mapping', () => {
      const mockData = [
        {
          vulnerabilityId: 'CVE-2023-1234',
          originalCvssScore: 9.8,
          originalSeverity: 'CRITICAL',
          componentIdentity: 'pkg:npm/express',
          packageOrRelease: 'express@4.17.1',
          vexStatus: 'NOT_AFFECTED'
        }
      ];
      
      render(<VexApplicabilityTable vulnerabilities={mockData} />);
      expect(screen.getByText('CVE-2023-1234')).toBeInTheDocument();
      expect(screen.getByText('9.8')).toBeInTheDocument();
      expect(screen.getByText('CRITICAL')).toBeInTheDocument();
      expect(screen.getByText('pkg:npm/express')).toBeInTheDocument();
      expect(screen.getByText('express@4.17.1')).toBeInTheDocument();
      expect(screen.getByText('NOT_AFFECTED')).toBeInTheDocument();
    });
  });

});
