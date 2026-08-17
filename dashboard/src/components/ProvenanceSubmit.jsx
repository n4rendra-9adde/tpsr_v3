import React, { useState } from 'react';
import { Card, Space, Typography, Upload, Button, Alert } from 'antd';
import { submitProvenance, reevaluateSbom } from '../api/client';

const { Text } = Typography;

export function ProvenanceSubmit({ sbomId, principal, role, onReevaluationComplete }) {
  const [selectedFile, setSelectedFile] = useState(null);
  const [fileContent, setFileContent] = useState('');
  const [fileReading, setFileReading] = useState(false);
  const [errorMsg, setErrorMsg] = useState('');
  const [loading, setLoading] = useState(false);
  const [reevaluating, setReevaluating] = useState(false);
  const [reevalError, setReevalError] = useState('');

  const handleBeforeUpload = (file) => {
    setErrorMsg('');
    setReevalError('');
    setSelectedFile(null);
    setFileContent('');

    if (file.size === 0) {
      setErrorMsg('Selected provenance file is empty.');
      return false;
    }

    setFileReading(true);
    const reader = new FileReader();
    reader.onload = (e) => {
      const content = e.target.result;
      if (!content || content.trim() === '') {
        setErrorMsg('Selected file could not be read as text.');
        setFileReading(false);
        return;
      }
      setFileContent(content);
      setSelectedFile(file);
      setFileReading(false);
    };
    reader.onerror = () => {
      setErrorMsg('Failed to read selected file.');
      setFileReading(false);
    };
    reader.readAsText(file);
    return false;
  };

  const handleRemoveFile = () => {
    setSelectedFile(null);
    setFileContent('');
    setErrorMsg('');
    setReevalError('');
  };

  const handleSubmit = async () => {
    setErrorMsg('');
    setReevalError('');
    
    if (!fileContent.trim()) {
      setErrorMsg('Please select a valid provenance file.');
      return;
    }

    let parsedPayload;
    try {
      parsedPayload = JSON.parse(fileContent);
    } catch (e) {
      setErrorMsg('Provenance must be a valid JSON file.');
      return;
    }

    setLoading(true);
    try {
      // 1. Submit Provenance
      // If the parsed payload already has an envelope property, send it as is, otherwise wrap it
      const payloadToSend = parsedPayload.envelope ? parsedPayload : { envelope: parsedPayload };
      await submitProvenance({ sbomId, provenancePayload: payloadToSend, principal, role });
      
      // 2. Clear upload selection
      setSelectedFile(null);
      setFileContent('');
      
      // 3. Trigger automatic reevaluation
      await handleReevaluate();
    } catch (err) {
      setErrorMsg(err.message || 'Provenance submission failed');
      setLoading(false);
    }
  };

  const handleReevaluate = async () => {
    setReevaluating(true);
    setReevalError('');
    try {
      const data = await reevaluateSbom({ sbomId, principal, role });
      if (onReevaluationComplete) {
        onReevaluationComplete(data.recommendation, data.analysisStatus);
      }
    } catch (err) {
      setReevalError(err.message || 'Automatic reevaluation could not complete');
    } finally {
      setReevaluating(false);
      setLoading(false);
    }
  };

  if (!sbomId) return null;

  return (
    <Card title="Submit Provenance" size="small" style={{ marginTop: 24, borderColor: '#91caff' }}>
      <Space direction="vertical" style={{ width: '100%' }}>
        {reevaluating && (
          <Alert type="info" showIcon message="Re-evaluating automatically" banner />
        )}
        {errorMsg && <Alert message={errorMsg} type="error" showIcon />}
        {reevalError && (
          <Alert
            message="Automatic reevaluation could not complete"
            description={reevalError}
            type="error"
            showIcon
            action={<Button size="small" onClick={handleReevaluate}>Retry</Button>}
          />
        )}
        
        <Text>Upload SLSA Provenance for this SBOM to trigger an automatic reevaluation.</Text>
        
        <Upload
          beforeUpload={handleBeforeUpload}
          showUploadList={false}
          accept=".json"
          maxCount={1}
        >
          <Button disabled={fileReading || loading || reevaluating}>
            {fileReading ? 'Reading file...' : (selectedFile ? 'Replace Provenance File' : 'Select Provenance JSON')}
          </Button>
        </Upload>

        {selectedFile && (
          <Alert 
            style={{ marginTop: 8 }}
            type="info"
            message={<Text strong>{selectedFile.name}</Text>}
            showIcon
            action={
              <Button size="small" danger onClick={handleRemoveFile} disabled={loading || reevaluating}>
                Remove
              </Button>
            }
          />
        )}

        <Button 
          type="primary" 
          onClick={handleSubmit} 
          loading={loading && !reevaluating}
          disabled={!fileContent || loading || reevaluating}
        >
          Submit Provenance
        </Button>
      </Space>
    </Card>
  );
}
