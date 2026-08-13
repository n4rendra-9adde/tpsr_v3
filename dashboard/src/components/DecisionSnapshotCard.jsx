import React, { useState } from 'react';
import { Card, Descriptions, Tag, Typography, Button, message, Space } from 'antd';
import axios from 'axios';

const { Text } = Typography;
const API_BASE_URL = process.env.REACT_APP_API_URL || 'http://localhost:3000/api';

export function DecisionSnapshotCard({ decisionData, sbomId, identity }) {
  const [replayLoading, setReplayLoading] = useState(false);
  const [replayResult, setReplayResult] = useState(null);

  if (!decisionData || !decisionData.snapshotHash) {
    return null;
  }

  const handleReplay = async () => {
    setReplayLoading(true);
    setReplayResult(null);
    try {
      const headers = { 
        'x-user-id': identity.userId, 
        'x-user-role': identity.role 
      };
      const response = await axios.post(`${API_BASE_URL}/v1/sbom/${encodeURIComponent(sbomId)}/replay`, {}, { headers });
      setReplayResult(response.data);
      message.success('Replay verification completed');
    } catch (err) {
      const msg = err.response?.data?.error || err.message;
      message.error(`Replay failed: ${msg}`);
      setReplayResult({ divergenceStatus: 'FAILED', divergenceReason: msg });
    } finally {
      setReplayLoading(false);
    }
  };

  return (
    <Card 
      title="Immutable Decision Snapshot (Point 13)" 
      size="small" 
      style={{ marginBottom: 16, borderColor: '#d9d9d9', backgroundColor: '#fafafa' }}
      extra={
        <Button size="small" type="primary" onClick={handleReplay} loading={replayLoading}>
          Verify Replay
        </Button>
      }
    >
      <Descriptions column={1} bordered size="small">
        <Descriptions.Item label="Policy Generation">
          <Text strong>{decisionData.generation || 'UNKNOWN'}</Text>
        </Descriptions.Item>
        <Descriptions.Item label="Snapshot Hash (SHA-256)">
          <Text code style={{ wordBreak: 'break-all' }}>{decisionData.snapshotHash}</Text>
        </Descriptions.Item>
        <Descriptions.Item label="Evaluated At">
          <Text>{new Date(decisionData.evaluatedAt).toLocaleString()}</Text>
        </Descriptions.Item>
        <Descriptions.Item label="Decision">
          <Tag color={decisionData.trustStatus === 'TRUSTED' ? 'green' : 'red'}>
            {decisionData.trustStatus}
          </Tag>
        </Descriptions.Item>
        
        {replayResult && (
          <Descriptions.Item label="Replay Verification Result">
            <Space direction="vertical">
              <Tag color={replayResult.divergenceStatus === 'EXACT_MATCH' ? 'success' : 'error'}>
                {replayResult.divergenceStatus}
              </Tag>
              {replayResult.divergenceReason && (
                <Text type="danger">{replayResult.divergenceReason}</Text>
              )}
            </Space>
          </Descriptions.Item>
        )}
      </Descriptions>
    </Card>
  );
}
