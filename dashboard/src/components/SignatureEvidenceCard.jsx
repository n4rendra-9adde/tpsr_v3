import React from 'react';
import { Card, Descriptions, Tag, Alert, Typography, Tooltip } from 'antd';
import { getReasonDescription } from '../utils/reasonCodeMap';

const { Text } = Typography;

export function SignatureEvidenceCard({ signatureData }) {
  if (!signatureData) {
    return (
      <Card title="Signature Verification" size="small" style={{ marginBottom: 16 }}>
        <Alert type="warning" showIcon message="Signature evidence unavailable" />
      </Card>
    );
  }

  const {
    verificationStatus,
    verificationMode,
    signatureType,
    targetType,
    targetDigest,
    signerIdentity,
    publicKeyFingerprint,
    transparencyLogVerified,
    verifiedAt,
    reasonCodes,
    failureReason
  } = signatureData;

  const isVerified = verificationStatus === 'VERIFIED';

  return (
    <Card title="Signature Verification" size="small" style={{ marginBottom: 16 }}>
      {isVerified ? (
        <Alert type="success" showIcon message="Real Cosign signature verified and trusted" style={{ marginBottom: 16 }} />
      ) : (
        failureReason && <Alert type="error" showIcon message={failureReason} style={{ marginBottom: 16 }} />
      )}
      {verificationMode === 'offline-keyed' && (
        <Alert type="info" showIcon message="Transparency log not checked in offline-keyed mode" style={{ marginBottom: 16 }} />
      )}
      <Descriptions column={2} bordered size="small">
        <Descriptions.Item label="Verification Status">
          <Tag color={isVerified ? 'green' : 'red'}>{verificationStatus || 'FAILED'}</Tag>
        </Descriptions.Item>
        <Descriptions.Item label="Verification Mode">{verificationMode || 'Not available'}</Descriptions.Item>
        <Descriptions.Item label="Signature Type">{signatureType || 'Not available'}</Descriptions.Item>
        <Descriptions.Item label="Target Type">{targetType || 'Not available'}</Descriptions.Item>
        <Descriptions.Item label="Target Digest">
          {targetDigest ? <Text code>{targetDigest}</Text> : 'Not available'}
        </Descriptions.Item>
        <Descriptions.Item label="Signer Identity">{signerIdentity || 'Not available'}</Descriptions.Item>
        <Descriptions.Item label="Public-key fingerprint">
          {publicKeyFingerprint ? <Text code>{publicKeyFingerprint}</Text> : 'Not available'}
        </Descriptions.Item>
        <Descriptions.Item label="Transparency-log Verification">
          {transparencyLogVerified === true ? 'Yes' : transparencyLogVerified === false ? 'false' : 'Not available'}
        </Descriptions.Item>
        <Descriptions.Item label="Verified Timestamp">
          {verifiedAt ? new Date(verifiedAt).toLocaleString() : 'Not available'}
        </Descriptions.Item>
        <Descriptions.Item label="Reason Codes">
          {reasonCodes ? (
            <Tooltip title={getReasonDescription(reasonCodes)}>
              <Text strong style={{ cursor: 'help' }}>{getReasonDescription(reasonCodes)}</Text>
            </Tooltip>
          ) : 'Not available'}
        </Descriptions.Item>
      </Descriptions>
    </Card>
  );
}
