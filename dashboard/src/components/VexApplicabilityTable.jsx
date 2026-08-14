import React from 'react';
import { Table, Tag, Alert, Tooltip } from 'antd';
import { getReasonDescription } from '../utils/reasonCodeMap';

export function VexApplicabilityTable({ vulnerabilities }) {
  if (!vulnerabilities || vulnerabilities.length === 0) {
    return <Alert type="info" showIcon message="No vulnerabilities found" />;
  }

  const columns = [
    { title: 'Vulnerability ID', dataIndex: 'vulnerabilityId', key: 'vulnerabilityId' },
    { title: 'Original CVSS', dataIndex: 'originalCvssScore', key: 'originalCvssScore', render: (t) => t || '-' },
    { title: 'Original Severity', dataIndex: 'originalSeverity', key: 'originalSeverity', render: (t) => t || '-' },
    { title: 'Component', dataIndex: 'componentIdentity', key: 'componentIdentity', render: (t) => t || '-' },
    { title: 'Package / Release', dataIndex: 'packageOrRelease', key: 'packageOrRelease', render: (t) => t || '-' },
    { 
      title: 'VEX Status', 
      dataIndex: 'vexStatus', 
      key: 'vexStatus',
      render: (t) => t ? <Tag>{t}</Tag> : <Tag>VEX_NOT_AVAILABLE</Tag>
    },
    { title: 'Justification', dataIndex: 'justification', key: 'justification', render: (t) => t || '-' },
    { 
      title: 'Applicability', 
      dataIndex: 'applicabilityDisposition', 
      key: 'applicabilityDisposition',
      render: (t) => {
        let color = 'default';
        if (t === 'APPLICABLE') color = 'red';
        if (t === 'NOT_AFFECTED' || t === 'FIXED_FOR_RELEASE') color = 'green';
        if (t === 'UNDER_INVESTIGATION') color = 'orange';
        if (t === 'VEX_INVALID') color = 'error';
        return <Tag color={color}>{t || 'VEX_NOT_AVAILABLE'}</Tag>;
      }
    },
    { 
      title: 'Policy Blocking', 
      dataIndex: 'policyBlockingStatus', 
      key: 'policyBlockingStatus',
      render: (t) => {
        let color = 'default';
        if (t === 'BLOCKING') color = 'red';
        if (t === 'NON_BLOCKING') color = 'green';
        if (t === 'REVIEW_REQUIRED') color = 'orange';
        return <Tag color={color}>{t || '-'}</Tag>;
      }
    },
    { title: 'Product Match', dataIndex: 'productMatch', key: 'productMatch', render: (t) => t ? 'Yes' : '-' },
    { title: 'Release Match', dataIndex: 'releaseMatch', key: 'releaseMatch', render: (t) => t ? 'Yes' : '-' },
    { title: 'Manifest Match', dataIndex: 'digestManifestMatch', key: 'digestManifestMatch', render: (t) => t ? 'Yes' : '-' },
    { title: 'Component Match', dataIndex: 'componentMatch', key: 'componentMatch', render: (t) => t ? 'Yes' : '-' },
    { title: 'Vuln-ID Match', dataIndex: 'vulnerabilityIdMatch', key: 'vulnerabilityIdMatch', render: (t) => t ? 'Yes' : '-' },
    { 
      title: 'Reason Codes', 
      dataIndex: 'reasonCodes', 
      key: 'reasonCodes', 
      render: (t) => t ? (
        <Tooltip title={getReasonDescription(t)}>
          <span style={{ cursor: 'help', fontWeight: 'bold' }}>{getReasonDescription(t)}</span>
        </Tooltip>
      ) : '-' 
    }
  ];

  return (
    <Table 
      columns={columns}
      dataSource={vulnerabilities}
      rowKey={(record, idx) => (record.vulnerabilityId || 'unk') + idx}
      pagination={false}
      size="small"
      scroll={{ x: 1200 }}
    />
  );
}
