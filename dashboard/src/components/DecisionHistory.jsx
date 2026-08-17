import React, { useEffect, useState } from 'react';
import { Card, Table, Tag, Typography, Alert, Button, Space, Spin } from 'antd';
import { getDecisionHistory } from '../api/client';

const { Text } = Typography;

export function DecisionHistory({ sbomId, principal, role, refreshTrigger }) {
  const [history, setHistory] = useState([]);
  const [loading, setLoading] = useState(false);
  const [errorMsg, setErrorMsg] = useState(null);

  const fetchHistory = async () => {
    if (!sbomId) return;
    setLoading(true);
    setErrorMsg(null);
    try {
      const data = await getDecisionHistory({ sbomId, principal, role });
      const historyList = data.history || [];
      // Sort newest first based on evaluatedAt or timestamp
      const sorted = [...historyList].sort((a, b) => {
        const timeA = new Date(a.evaluated_at || a.timestamp || 0).getTime();
        const timeB = new Date(b.evaluated_at || b.timestamp || 0).getTime();
        return timeB - timeA;
      });
      setHistory(sorted);
    } catch (err) {
      setErrorMsg(err.message || 'Failed to load decision history');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchHistory();
  }, [sbomId, principal, role, refreshTrigger]);

  const columns = [
    {
      title: 'Status',
      key: 'status',
      render: (_, record, index) => {
        if (index === 0) {
          return <Tag color="blue">CURRENT</Tag>;
        }
        return <Tag>HISTORICAL</Tag>;
      }
    },
    {
      title: 'Decision ID',
      dataIndex: 'id',
      key: 'id',
      render: (t) => <Text code>{t || '-'}</Text>
    },
    {
      title: 'Snapshot ID',
      dataIndex: 'snapshot_id',
      key: 'snapshot_id',
      render: (t) => <Text code>{t || '-'}</Text>
    },
    {
      title: 'Recommendation',
      dataIndex: 'trust_status',
      key: 'trust_status',
      render: (t) => {
        // Map backend trust status to recommendation if needed, or use directly if it is the recommendation
        let color = 'default';
        if (t === 'TRUSTED' || t === 'APPROVE') color = 'green';
        else if (t === 'CONDITIONALLY_ACCEPTED' || t === 'APPROVE_WITH_CONDITIONS') color = 'orange';
        else if (t === 'REVIEW_REQUIRED' || t === 'MANUAL_REVIEW_REQUIRED') color = 'orange';
        else if (t === 'UNTRUSTED' || t === 'REJECTED' || t === 'REJECT') color = 'red';
        return <Tag color={color}>{t}</Tag>;
      }
    },
    {
      title: 'Reason',
      key: 'reason',
      render: (_, record) => (
        <Space direction="vertical" size="small">
          {record.reason_code && <Text strong>{record.reason_code}</Text>}
          {record.reason_description && <Text type="secondary" style={{ fontSize: '12px' }}>{record.reason_description}</Text>}
        </Space>
      )
    },
    {
      title: 'Evaluated At',
      dataIndex: 'evaluated_at',
      key: 'evaluated_at',
      render: (t) => t ? new Date(t).toLocaleString() : '-'
    }
  ];

  if (!sbomId) return null;

  return (
    <Card title="Decision History" size="small" style={{ marginTop: 24 }}>
      {errorMsg && (
        <Alert
          type="error"
          showIcon
          message={errorMsg}
          action={<Button size="small" onClick={fetchHistory}>Retry</Button>}
          style={{ marginBottom: 16 }}
        />
      )}
      
      {loading && history.length === 0 ? (
        <div style={{ textAlign: 'center', padding: '20px' }}><Spin /></div>
      ) : (
        <Table
          dataSource={history}
          columns={columns}
          rowKey={(record) => record.id || record.timestamp || Math.random()}
          pagination={false}
          size="small"
          locale={{ emptyText: 'No decision history available' }}
        />
      )}
    </Card>
  );
}
