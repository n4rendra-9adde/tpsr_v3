import React from 'react';
import { Card, Tag, Typography, Alert, Space, List, Divider } from 'antd';

const { Text, Title } = Typography;

export function RecommendationCard({ recommendation, analysisStatus }) {
  if (analysisStatus === 'INCOMPLETE' || !recommendation) {
    return (
      <Card title="Analysis Incomplete" size="small" style={{ borderColor: '#d9d9d9' }}>
        <Alert
          type="error"
          showIcon
          message="SBOM Analysis Incomplete"
          description={
            <Space direction="vertical">
              <Text>The evaluation could not be completed successfully.</Text>
              {recommendation?.correlationId && (
                <Text>Correlation ID: <Text code>{recommendation.correlationId}</Text></Text>
              )}
            </Space>
          }
        />
      </Card>
    );
  }

  const {
    recommendation: recState,
    internalTrustState,
    primaryRuleId,
    primaryReasonCode,
    blockingFindings = [],
    reviewFindings = [],
    evidenceCompleteness,
    policyGeneration,
    decisionId,
    snapshotId,
    evaluatedAt,
    correlationId,
    suggestedActions = [],
    humanReviewRequired,
    exceptionPermitted,
    conditions = []
  } = recommendation;

  let color = 'default';
  let titleStr = recState;
  
  if (recState === 'APPROVE') color = 'green';
  else if (recState === 'APPROVE_WITH_CONDITIONS') color = 'orange'; // Amber is typically orange/gold in Antd
  else if (recState === 'MANUAL_REVIEW_REQUIRED') color = 'orange';
  else if (recState === 'REJECT') color = 'red';
  else if (recState === 'ANALYSIS_INCOMPLETE') color = 'red'; // neutral or red-neutral

  const isReject = recState === 'REJECT';
  const isReview = recState === 'MANUAL_REVIEW_REQUIRED';

  return (
    <Card 
      title={<Space><Tag color={color}>{titleStr}</Tag> <Text type="secondary">{internalTrustState}</Text></Space>} 
      size="small"
      style={{ borderColor: color === 'default' ? '#d9d9d9' : undefined }}
    >
      <Space direction="vertical" style={{ width: '100%' }}>
        
        {isReview && (
          <Alert type="warning" showIcon message="A manual security review is required before this artifact can be approved." />
        )}
        
        <Space size="large" wrap>
          {primaryRuleId && (
            <div><Text type="secondary">Primary Rule ID:</Text> <Text strong>{primaryRuleId}</Text></div>
          )}
          {primaryReasonCode && (
            <div><Text type="secondary">Reason Code:</Text> <Text strong>{primaryReasonCode}</Text></div>
          )}
          {evidenceCompleteness && (
            <div><Text type="secondary">Completeness:</Text> <Text strong>{typeof evidenceCompleteness === 'object' ? (evidenceCompleteness.complete ? 'Complete' : 'Incomplete') : evidenceCompleteness}</Text></div>
          )}
          {policyGeneration && (
            <div><Text type="secondary">Policy Gen:</Text> <Text code>{policyGeneration}</Text></div>
          )}
        </Space>

        <Space size="large" wrap>
          {decisionId && (
            <div><Text type="secondary">Decision ID:</Text> <Text code copyable>{decisionId}</Text></div>
          )}
          {snapshotId && (
            <div><Text type="secondary">Snapshot ID:</Text> <Text code copyable>{snapshotId}</Text></div>
          )}
          {correlationId && (
            <div><Text type="secondary">Correlation ID:</Text> <Text code copyable>{correlationId}</Text></div>
          )}
          {evaluatedAt && (
            <div><Text type="secondary">Evaluated At:</Text> <Text>{new Date(evaluatedAt).toLocaleString()}</Text></div>
          )}
        </Space>

        {blockingFindings.length > 0 && (
          <>
            <Divider style={{ margin: '12px 0' }} />
            <Text strong type="danger">Blocking Findings</Text>
            <ul>
              {blockingFindings.map((finding, idx) => (
                <li key={idx}>
                  <Text type="danger">{finding}</Text>
                </li>
              ))}
            </ul>
            {!exceptionPermitted && (
              <Alert type="error" message="This control cannot be overridden through a standard exception." banner />
            )}
          </>
        )}

        {reviewFindings.length > 0 && (
          <>
            <Divider style={{ margin: '12px 0' }} />
            <Text strong type="warning">Review Findings</Text>
            <ul>
              {reviewFindings.map((finding, idx) => (
                <li key={idx}>
                  <Text type="warning">{finding}</Text>
                </li>
              ))}
            </ul>
          </>
        )}

        {suggestedActions.length > 0 && (
          <>
            <Divider style={{ margin: '12px 0' }} />
            <Text strong>Suggested Actions</Text>
            <List
              size="small"
              dataSource={suggestedActions}
              renderItem={(action) => (
                <List.Item>
                  <Space direction="vertical">
                    <Text strong>{action.message}</Text>
                    <Space>
                      <Tag>{action.requiredRole}</Tag>
                      <Tag color="blue">{action.requiredEvidenceType}</Tag>
                      {!action.exceptionable && <Tag color="red">Non-exceptionable</Tag>}
                    </Space>
                  </Space>
                </List.Item>
              )}
            />
          </>
        )}
      </Space>
    </Card>
  );
}
