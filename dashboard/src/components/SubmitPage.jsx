import React, { useState } from 'react';
import { Card, Space, Typography, Upload, Button, Alert, message, Select } from 'antd';
import axios from 'axios';
import { RecommendationCard } from './RecommendationCard';
import { ProvenanceSubmit } from './ProvenanceSubmit';
import { DecisionHistory } from './DecisionHistory';

const { Title, Text } = Typography;
const _rawApiUrl = (process.env.REACT_APP_API_BASE_URL || 'http://localhost:3000/api').trim();
const API_BASE_URL = _rawApiUrl.endsWith('/') ? _rawApiUrl.slice(0, -1) : _rawApiUrl;

export default function SubmitPage({ selectedIdentity }) {
  const [sbomID, setSbomId] = useState('');
  const [sbomContent, setSbomContent] = useState('');
  const [selectedFile, setSelectedFile] = useState(null);
  const [fileReading, setFileReading] = useState(false);
  const [errorMsg, setErrorMsg] = useState('');
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState(null);
  const [refreshTrigger, setRefreshTrigger] = useState(0);

  const handleBeforeUpload = (file) => {
    setErrorMsg('');
    setSelectedFile(null);
    setSbomContent('');
    setResult(null);

    const allowedExtensions = ['.json', '.xml', '.spdx', '.cdx', '.txt'];
    const ext = file.name.slice((Math.max(0, file.name.lastIndexOf(".")) || Infinity)).toLowerCase();
    
    if (!allowedExtensions.includes(ext)) {
      setErrorMsg(`Invalid file type. Allowed: ${allowedExtensions.join(', ')}`);
      return false;
    }

    if (file.size === 0) {
      setErrorMsg('Selected SBOM file is empty.');
      return false;
    }

    setFileReading(true);
    const reader = new FileReader();
    reader.onload = (e) => {
      const content = e.target.result;
      if (!content || content.trim() === '') {
        setErrorMsg('Selected SBOM file is empty or could not be read as text.');
        setFileReading(false);
        return;
      }
      setSbomContent(content);
      setSelectedFile(file);
      setFileReading(false);
      
      // Attempt to automatically extract SBOM ID if present
      try {
        const json = JSON.parse(content);
        if (json.serialNumber) {
          setSbomId(json.serialNumber);
        } else if (json.metadata && json.metadata.component && json.metadata.component['bom-ref']) {
          setSbomId(json.metadata.component['bom-ref']);
        }
      } catch (e) {
        // ignore
      }
    };
    reader.onerror = () => {
      setErrorMsg('Failed to read selected SBOM file.');
      setFileReading(false);
    };
    reader.readAsText(file);
    return false;
  };

  const handleRemoveFile = () => {
    setSelectedFile(null);
    setSbomContent('');
    setErrorMsg('');
    setResult(null);
    setSbomId('');
    setRefreshTrigger(t => t + 1);
  };

  const handleSubmit = async () => {
    setErrorMsg('');
    setResult(null);

    const idTrimmed = sbomID.trim();
    const contentTrimmed = sbomContent.trim();

    if (!idTrimmed) {
      setErrorMsg('SBOM ID is required.');
      return;
    }
    if (!contentTrimmed) {
      setErrorMsg('Please select an SBOM file.');
      return;
    }

    setLoading(true);
    try {
      // 1. Submit directly
      const response = await axios.post(
        `${API_BASE_URL}/submit`,
        { 
          sbomID: idTrimmed, 
          sbom: contentTrimmed,
          buildID: 'auto-build-1',
          softwareName: 'auto-software',
          softwareVersion: '1.0.0',
          format: 'SPDX',
          offChainRef: 'https://example.com/sbom',
          signatures: ['dummy-signature']
        },
        { headers: { 'x-user-id': selectedIdentity.userId, 'x-user-role': selectedIdentity.role } }
      );
      
      const resData = response.data;
      
      if (resData.submissionStatus === 'ACCEPTED' || resData.submissionStatus === 'UPDATED') {
        setResult(resData);
        setRefreshTrigger(t => t + 1);
      } else {
        setErrorMsg('Submission failed.');
      }
    } catch (err) {
      setErrorMsg(err.response?.data?.error || err.response?.data?.message || err.message || 'Submission failed');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '24px', maxWidth: '800px' }}>
      <div>
        <Title level={2} style={{ margin: 0 }}>Submit SBOM</Title>
        <Text type="secondary">Upload and register an SBOM into the TPSR ledger. Analysis is automatic.</Text>
      </div>

      <Card>
        <Space direction="vertical" style={{ width: '100%' }} size="large">
          {errorMsg && <Alert message={errorMsg} type="error" showIcon />}
          
          <div>
            <div style={{ marginBottom: 8 }}><Text strong>SBOM ID (Auto-extracted or Manual)</Text></div>
            <input 
              type="text"
              placeholder="Enter SBOM ID" 
              value={sbomID} 
              onChange={(e) => setSbomId(e.target.value)} 
              className="ant-input"
            />
          </div>

          <div>
            <div style={{ marginBottom: 8 }}><Text strong>SBOM File</Text></div>
            <Upload
              beforeUpload={handleBeforeUpload}
              showUploadList={false}
              accept=".json,.xml,.spdx,.cdx,.txt"
              maxCount={1}
            >
              <Button disabled={fileReading || loading}>
                {fileReading ? 'Reading file...' : (selectedFile ? 'Replace Local SBOM File' : 'Select Local SBOM File')}
              </Button>
            </Upload>
            {selectedFile && (
              <Alert 
                style={{ marginTop: 8 }}
                type="info"
                message={<Text strong>{selectedFile.name}</Text>}
                description={`Size: ${(selectedFile.size / 1024).toFixed(2)} KB`}
                showIcon
                action={
                  <Button size="small" danger onClick={handleRemoveFile} disabled={loading}>
                    Remove
                  </Button>
                }
              />
            )}
          </div>

          <Button 
            type="primary" 
            onClick={handleSubmit} 
            loading={loading}
            disabled={!sbomID.trim() || !sbomContent || fileReading || loading}
          >
            {loading ? 'Uploading and analyzing SBOM' : 'Submit SBOM'}
          </Button>
        </Space>
      </Card>

      {result && result.recommendation && (
        <RecommendationCard recommendation={result.recommendation} analysisStatus={result.analysisStatus} />
      )}
      
      {result && !result.recommendation && result.analysisStatus === 'INCOMPLETE' && (
        <RecommendationCard analysisStatus="INCOMPLETE" />
      )}

      {result && (
        <ProvenanceSubmit 
          sbomId={result.sbomId || sbomID} 
          principal={selectedIdentity.userId} 
          role={selectedIdentity.role} 
          onReevaluationComplete={(newRecommendation, newStatus) => {
            setResult(prev => ({
              ...prev,
              recommendation: newRecommendation,
              analysisStatus: newStatus
            }));
            setRefreshTrigger(t => t + 1);
          }}
        />
      )}

      {result && (
        <DecisionHistory 
          sbomId={result.sbomId || sbomID} 
          principal={selectedIdentity.userId} 
          role={selectedIdentity.role} 
          refreshTrigger={refreshTrigger}
        />
      )}
    </div>
  );
}
