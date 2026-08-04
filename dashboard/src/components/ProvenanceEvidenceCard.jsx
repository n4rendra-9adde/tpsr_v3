import React from 'react';
import { Card, Descriptions, Tag, Alert, Typography } from 'antd';

const { Text } = Typography;

export function ProvenanceEvidenceCard({ provenanceData }) {
  if (!provenanceData) {
    return (
      <Card title="SLSA-compatible provenance verification" size="small" style={{ marginBottom: 16 }}>
        <Alert type="warning" showIcon message="Provenance evidence unavailable" />
      </Card>
    );
  }

  const {
    verificationStatus,
    predicateType,
    predicateVersion,
    builderIdentity,
    sourceRepository,
    sourceCommit,
    buildType,
    startedOn,
    finishedOn,
    freshnessStatus,
    replayStatus,
    envelopeSignatureStatus,
    bindingStatus,
    policyVersion,
    reasonCodes
  } = provenanceData;

  const isVerified = verificationStatus === 'VERIFIED';

  return (
    <Card title="SLSA-compatible provenance verification" size="small" style={{ marginBottom: 16 }}>
      <Descriptions column={2} bordered size="small">
        <Descriptions.Item label="Verification Status">
          <Tag color={isVerified ? 'green' : 'red'}>{verificationStatus || 'FAILED'}</Tag>
        </Descriptions.Item>
        <Descriptions.Item label="Predicate Type & Version">
          {predicateType ? `${predicateType} ${predicateVersion || ''}` : (predicateVersion || 'Not available')}
        </Descriptions.Item>
        <Descriptions.Item label="Builder Identity">{builderIdentity || 'Not available'}</Descriptions.Item>
        <Descriptions.Item label="Source Repository">{sourceRepository || 'Not available'}</Descriptions.Item>
        <Descriptions.Item label="Source Commit">
          {sourceCommit ? <Text code>{sourceCommit}</Text> : 'Not available'}
        </Descriptions.Item>
        <Descriptions.Item label="Build Type">{buildType || 'Not available'}</Descriptions.Item>
        <Descriptions.Item label="Started Timestamp">
          {startedOn ? new Date(startedOn).toLocaleString() : 'Not available'}
        </Descriptions.Item>
        <Descriptions.Item label="Finished Timestamp">
          {finishedOn ? new Date(finishedOn).toLocaleString() : 'Not available'}
        </Descriptions.Item>
        <Descriptions.Item label="Freshness Status">
          {freshnessStatus ? <Tag color={freshnessStatus === 'PASS' ? 'green' : 'red'}>{freshnessStatus}</Tag> : 'Not available'}
        </Descriptions.Item>
        <Descriptions.Item label="Replay Status">
          {replayStatus ? <Tag color={replayStatus === 'PASS' ? 'green' : 'red'}>{replayStatus}</Tag> : 'Not available'}
        </Descriptions.Item>
        <Descriptions.Item label="Envelope-signature Status">
          {envelopeSignatureStatus ? <Tag color={envelopeSignatureStatus === 'PASS' ? 'green' : 'red'}>{envelopeSignatureStatus}</Tag> : 'Not available'}
        </Descriptions.Item>
        <Descriptions.Item label="Digest-manifest Binding Status">
          {bindingStatus ? <Tag color={bindingStatus === 'PASS' ? 'green' : 'red'}>{bindingStatus}</Tag> : 'Not available'}
        </Descriptions.Item>
        <Descriptions.Item label="Policy Version">{policyVersion || 'Not available'}</Descriptions.Item>
        <Descriptions.Item label="Reason Codes">
          {reasonCodes ? <Text strong>{reasonCodes}</Text> : 'Not available'}
        </Descriptions.Item>
      </Descriptions>
    </Card>
  );
}
