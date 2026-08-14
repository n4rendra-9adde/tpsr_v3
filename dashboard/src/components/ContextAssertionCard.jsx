import React from 'react';
import { Card, Descriptions, Tag, Typography, Tooltip } from 'antd';
import { getReasonDescription } from '../utils/reasonCodeMap';

const { Text } = Typography;

export function ContextAssertionCard({ contextData }) {
  if (!contextData) {
    return (
      <Card title="Authenticated Context Assertion" size="small" style={{ marginBottom: 16 }}>
        <Text type="secondary">No active context assertion found.</Text>
      </Card>
    );
  }

  return (
    <Card title={<><Text strong>AUTHENTICATED CONTEXT ASSERTION</Text></>} size="small" style={{ marginBottom: 16, borderColor: '#91caff', backgroundColor: '#e6f4ff' }}>
      <Descriptions column={2} bordered size="small">
        <Descriptions.Item label="Status">
          <Tag color={contextData.status === 'ACTIVE' ? 'green' : 'red'}>{contextData.status}</Tag>
        </Descriptions.Item>
        <Descriptions.Item label="Environment">
          <Text strong>{contextData.environment}</Text>
        </Descriptions.Item>
        <Descriptions.Item label="Assertor">
          <Text>{contextData.assertor}</Text>
        </Descriptions.Item>
        <Descriptions.Item label="Role">
          <Text>{contextData.role}</Text>
        </Descriptions.Item>
        <Descriptions.Item label="Signer Fingerprint" span={2}>
          <Text code>{contextData.signerFingerprint}</Text>
        </Descriptions.Item>
        <Descriptions.Item label="Assertion Time">
          <Text>{new Date(contextData.assertionTime).toLocaleString()}</Text>
        </Descriptions.Item>
        <Descriptions.Item label="Expiry">
          <Text>{new Date(contextData.expiry).toLocaleString()}</Text>
        </Descriptions.Item>
        <Descriptions.Item label="Release Binding" span={2}>
          <Text code>{contextData.releaseBinding}</Text>
        </Descriptions.Item>
        <Descriptions.Item label="Verification Status">
          <Tag color={contextData.verificationStatus === 'VERIFIED' ? 'success' : 'error'}>{contextData.verificationStatus}</Tag>
        </Descriptions.Item>
        <Descriptions.Item label="Assurance State">
          <Text strong>{contextData.assuranceState}</Text>
        </Descriptions.Item>
        <Descriptions.Item label="Rule IDs">
          {contextData.ruleIds && contextData.ruleIds.length > 0 ? contextData.ruleIds.join(', ') : 'None'}
        </Descriptions.Item>
        <Descriptions.Item label="Reason Codes">
          {contextData.reasonCodes && contextData.reasonCodes.length > 0 ? (
            <Tooltip title={getReasonDescription(contextData.reasonCodes)}>
              <Text strong style={{ cursor: 'help' }}>{contextData.reasonCodes.join(', ')}</Text>
            </Tooltip>
          ) : 'None'}
        </Descriptions.Item>
      </Descriptions>
    </Card>
  );
}
