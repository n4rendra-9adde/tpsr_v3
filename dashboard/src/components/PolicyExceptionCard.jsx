import React from 'react';
import { Card, Tag, Descriptions, Badge, Typography, Space } from 'antd';
import { SafetyCertificateOutlined, WarningOutlined, ClockCircleOutlined, ExclamationCircleOutlined } from '@ant-design/icons';

const { Title, Text } = Typography;

const statusColors = {
  ACTIVE: 'success',
  REQUESTED: 'processing',
  APPROVED: 'processing',
  EXPIRED: 'error',
  REVOKED: 'error',
  REJECTED: 'error',
  INVALID: 'default',
  SUPERSEDED: 'default',
  OUT_OF_SCOPE: 'default'
};

const PolicyExceptionCard = ({ exceptionData }) => {
  if (!exceptionData) {
    return (
      <Card title="Governed Policy Exception" size="small" style={{ marginBottom: 16 }}>
        <Text type="secondary">No exception data provided.</Text>
      </Card>
    );
  }

  const {
    id, status, policy_rule_id, reason_code, vulnerability_ids, component_identifiers,
    requested_by, owned_by, approved_by, requested_at, approved_at, valid_from, valid_until,
    justification, business_need, remediation_plan, compensating_controls, residual_risk,
    assurance_state, revocation_reason
  } = exceptionData;

  const isActiveMitigation = status === 'ACTIVE' && assurance_state === 'VERIFIED_TRUSTED';
  
  const renderRemainingValidity = () => {
    if (!valid_until) return 'N/A';
    const now = new Date();
    const until = new Date(valid_until);
    if (until < now) return <Text type="danger">Expired</Text>;
    
    const diffHours = Math.floor((until - now) / (1000 * 60 * 60));
    const diffDays = Math.floor(diffHours / 24);
    
    if (diffDays > 0) return `${diffDays} days left`;
    return `${diffHours} hours left`;
  };

  return (
    <Card 
      title={
        <Space>
          <SafetyCertificateOutlined style={{ color: isActiveMitigation ? '#52c41a' : '#8c8c8c' }} />
          <span>GOVERNED POLICY EXCEPTION</span>
          <Badge status={statusColors[status] || 'default'} text={status} />
        </Space>
      } 
      size="small" 
      style={{ marginBottom: 16, borderLeft: isActiveMitigation ? '4px solid #52c41a' : '4px solid #d9d9d9' }}
    >
      <Descriptions size="small" column={{ xxl: 3, xl: 3, lg: 2, md: 1, sm: 1, xs: 1 }} bordered>
        <Descriptions.Item label="Exception ID"><Text code>{id}</Text></Descriptions.Item>
        <Descriptions.Item label="Status">
          <Tag color={statusColors[status] || 'default'}>{status}</Tag>
        </Descriptions.Item>
        <Descriptions.Item label="Assurance State">
          <Text strong type={isActiveMitigation ? 'success' : 'danger'}>{assurance_state || 'NOT_EVALUATED'}</Text>
        </Descriptions.Item>
        
        <Descriptions.Item label="Policy Rule ID">{policy_rule_id}</Descriptions.Item>
        <Descriptions.Item label="Reason Code">{reason_code}</Descriptions.Item>
        <Descriptions.Item label="Residual Risk">
          <Tag color={residual_risk === 'CRITICAL' ? 'red' : residual_risk === 'HIGH' ? 'volcano' : residual_risk === 'MEDIUM' ? 'orange' : 'green'}>
            {residual_risk}
          </Tag>
        </Descriptions.Item>
        
        <Descriptions.Item label="Requested By">{requested_by}</Descriptions.Item>
        <Descriptions.Item label="Owner">{owned_by}</Descriptions.Item>
        <Descriptions.Item label="Approved By">{approved_by || 'N/A'}</Descriptions.Item>
        
        <Descriptions.Item label="Valid From">{valid_from ? new Date(valid_from).toLocaleString() : 'N/A'}</Descriptions.Item>
        <Descriptions.Item label="Valid Until">{valid_until ? new Date(valid_until).toLocaleString() : 'N/A'}</Descriptions.Item>
        <Descriptions.Item label="Remaining Validity">{renderRemainingValidity()}</Descriptions.Item>
      </Descriptions>
      
      <div style={{ marginTop: 16 }}>
        <Descriptions size="small" column={1} layout="vertical" bordered>
          <Descriptions.Item label="Vulnerability IDs">
            {vulnerability_ids && vulnerability_ids.length > 0 ? vulnerability_ids.join(', ') : 'None'}
          </Descriptions.Item>
          <Descriptions.Item label="Component Scope">
            {component_identifiers && component_identifiers.length > 0 ? component_identifiers.join(', ') : 'None'}
          </Descriptions.Item>
          <Descriptions.Item label="Justification">{justification}</Descriptions.Item>
          {business_need && <Descriptions.Item label="Business Need">{business_need}</Descriptions.Item>}
          {remediation_plan && <Descriptions.Item label="Remediation Plan">{remediation_plan}</Descriptions.Item>}
          {compensating_controls && Array.isArray(compensating_controls) && compensating_controls.length > 0 && (
            <Descriptions.Item label="Compensating Controls">
              {compensating_controls.map((c, i) => <div key={i}>- {c}</div>)}
            </Descriptions.Item>
          )}
          {status === 'REVOKED' && (
             <Descriptions.Item label="Revocation Reason">
                <Text type="danger">{revocation_reason}</Text>
             </Descriptions.Item>
          )}
        </Descriptions>
      </div>
      
      {!isActiveMitigation && (
        <div style={{ marginTop: 16 }}>
           <Text type="secondary" italic>
             <ExclamationCircleOutlined style={{ marginRight: 8 }} />
             This exception is {status} and is NOT acting as active mitigation.
           </Text>
        </div>
      )}
    </Card>
  );
};

export default PolicyExceptionCard;
