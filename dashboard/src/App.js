import React, { useState, useMemo, useEffect } from 'react';
import { Layout, Menu, Typography, Card, Row, Col, Table, Tag, Input, Select, Space, Button, Alert, Descriptions, Modal, message } from 'antd';
import { Link, Navigate, Route, Routes, useLocation } from 'react-router-dom';
import axios from 'axios';

const { Header, Content, Sider } = Layout;
const { Title, Text } = Typography;
const { TextArea } = Input;

// Centralized environment normalization
const _rawApiUrl = (process.env.REACT_APP_API_BASE_URL || 'http://localhost:3000/api').trim();
const API_BASE_URL = _rawApiUrl.endsWith('/') ? _rawApiUrl.slice(0, -1) : _rawApiUrl;

const USER_ID = (process.env.REACT_APP_USER_ID || '').trim() || 'dashboard-user';
const SBOMS_ROLE = (process.env.REACT_APP_SBOMS_ROLE || '').trim() || 'security';
const VERIFY_ROLE = (process.env.REACT_APP_VERIFY_ROLE || '').trim() || 'auditor';
const HISTORY_ROLE = (process.env.REACT_APP_HISTORY_ROLE || '').trim() || 'auditor';
const COMPLIANCE_ROLE = (process.env.REACT_APP_COMPLIANCE_ROLE || '').trim() || 'admin';

const DEMO_IDENTITIES = [
  { label: 'Developer', userId: 'developer-user', role: 'developer' },
  { label: 'Security', userId: 'security-user', role: 'security' },
  { label: 'Auditor', userId: 'auditor-user', role: 'auditor' },
  { label: 'Admin', userId: 'admin-user', role: 'admin' },
];

// Detect if any defaults are still active
const _usingDefaults =
  USER_ID === 'dashboard-user' ||
  SBOMS_ROLE === 'security' ||
  VERIFY_ROLE === 'auditor' ||
  HISTORY_ROLE === 'auditor' ||
  COMPLIANCE_ROLE === 'admin';

function SBOMListPage({ selectedIdentity }) {
  const [searchText, setSearchText] = useState('');
  const [statusFilter, setStatusFilter] = useState('All');
  const [loading, setLoading] = useState(false);
  const [errorMsg, setErrorMsg] = useState('');
  const [sboms, setSboms] = useState([]);
  const [modalVisible, setModalVisible] = useState(false);
  const [selectedSbomId, setSelectedSbomId] = useState(null);
  const [selectedSbomJson, setSelectedSbomJson] = useState('');
  const [actionLoading, setActionLoading] = useState(null);

  useEffect(() => {
    fetchSboms();
  }, [selectedIdentity]);

  const fetchSboms = async () => {
    setLoading(true);
    setErrorMsg('');
    try {
      const response = await axios.get(`${API_BASE_URL}/sboms`, {
        headers: { 'x-user-id': selectedIdentity.userId, 'x-user-role': selectedIdentity.role }
      });
      const rawSboms = response.data.sboms || [];
      const normalizedSboms = rawSboms.map(item => ({
        ...item,
        sbomID: item.sbomID ?? item.sbom_id,
        softwareName: item.softwareName ?? item.software_name,
        softwareVersion: item.softwareVersion ?? item.software_version,
        buildID: item.buildID ?? item.build_id ?? item.build_number,
        submitterID: item.submitterID ?? item.submitter_id,
        timestamp: item.timestamp ?? item.created_at,
        requestedBy: item.requestedBy ?? item.requested_by,
        jobName: item.jobName ?? item.job_name
      }));
      setSboms(normalizedSboms);
    } catch (err) {
      const msg = err.response?.data?.error || err.response?.data?.message || err.message || 'Failed to load SBOM list';
      setErrorMsg(msg);
    } finally {
      setLoading(false);
    }
  };

  const filteredData = useMemo(() => {
    return sboms.filter((item) => {
      const matchStatus = statusFilter === 'All' || item.status === statusFilter;
      const searchTrimmed = searchText.trim().toLowerCase();
      const matchSearch = searchTrimmed === '' || 
        (item.sbomID && item.sbomID.toLowerCase().includes(searchTrimmed)) ||
        (item.softwareName && item.softwareName.toLowerCase().includes(searchTrimmed));
      return matchStatus && matchSearch;
    });
  }, [searchText, statusFilter, sboms]);

  const fetchDocument = async (sbomID) => {
    const response = await axios.get(`${API_BASE_URL}/sboms/${encodeURIComponent(sbomID)}/document`, {
      headers: { 'x-user-id': selectedIdentity.userId, 'x-user-role': selectedIdentity.role }
    });
    return response.data;
  };

  const handleView = async (record) => {
    try {
      setActionLoading(`${record.sbomID}-view`);
      const data = await fetchDocument(record.sbomID);
      setSelectedSbomId(record.sbomID);
      setSelectedSbomJson(JSON.stringify(data.sbom, null, 2));
      setModalVisible(true);
    } catch (err) {
      message.error(err.response?.data?.error || err.response?.data?.message || err.message || 'Failed to fetch SBOM document');
    } finally {
      setActionLoading(null);
    }
  };

  const handleCopy = async (record) => {
    try {
      setActionLoading(`${record.sbomID}-copy`);
      const data = await fetchDocument(record.sbomID);
      const jsonText = JSON.stringify(data.sbom, null, 2);
      await navigator.clipboard.writeText(jsonText);
      message.success('SBOM JSON copied to clipboard');
    } catch (err) {
      message.error(err.response?.data?.error || err.response?.data?.message || err.message || 'Failed to copy SBOM document');
    } finally {
      setActionLoading(null);
    }
  };

  const handleDownload = async (record) => {
    try {
      setActionLoading(`${record.sbomID}-download`);
      const response = await axios.get(`${API_BASE_URL}/sboms/${encodeURIComponent(record.sbomID)}/document?download=true`, {
        headers: { 'x-user-id': selectedIdentity.userId, 'x-user-role': selectedIdentity.role },
        responseType: 'blob'
      });
      
      let filename = `${record.sbomID}.json`;
      const disposition = response.headers['content-disposition'];
      if (disposition && disposition.indexOf('filename=') !== -1) {
        const filenameRegex = /filename[^;=\n]*=((['"]).*?\2|[^;\n]*)/;
        const matches = filenameRegex.exec(disposition);
        if (matches != null && matches[1]) { 
          filename = matches[1].replace(/['"]/g, '');
        }
      }

      const url = window.URL.createObjectURL(new Blob([response.data]));
      const link = document.createElement('a');
      link.href = url;
      link.setAttribute('download', filename);
      document.body.appendChild(link);
      link.click();
      link.parentNode.removeChild(link);
      window.URL.revokeObjectURL(url);
    } catch (err) {
      message.error('Failed to download SBOM document');
    } finally {
      setActionLoading(null);
    }
  };

  const handleApprove = (record) => {
    Modal.confirm({
      title: 'Approve SBOM?',
      content: 'This will change the SBOM lifecycle status from PENDING to APPROVED.',
      onOk: async () => {
        try {
          setActionLoading(`${record.sbomID}-approve`);
          await axios.post(`${API_BASE_URL}/approve`, { sbomID: record.sbomID }, {
            headers: {
              'Content-Type': 'application/json',
              'x-user-id': selectedIdentity.userId,
              'x-user-role': selectedIdentity.role
            }
          });
          message.success('SBOM approved successfully');
          await fetchSboms();
        } catch (err) {
          const msg = err.response?.data?.error || err.response?.data?.message || err.message || 'Failed to approve SBOM';
          message.error(msg);
        } finally {
          setActionLoading(null);
        }
      }
    });
  };

  const handleActivate = (record) => {
    Modal.confirm({
      title: 'Activate SBOM?',
      content: 'This will change the SBOM lifecycle status from APPROVED to ACTIVE.',
      onOk: async () => {
        try {
          setActionLoading(`${record.sbomID}-activate`);
          await axios.post(`${API_BASE_URL}/activate`, { sbomID: record.sbomID }, {
            headers: {
              'Content-Type': 'application/json',
              'x-user-id': selectedIdentity.userId,
              'x-user-role': selectedIdentity.role
            }
          });
          message.success('SBOM activated successfully');
          await fetchSboms();
        } catch (err) {
          const msg = err.response?.data?.error || err.response?.data?.message || err.message || 'Failed to activate SBOM';
          message.error(msg);
        } finally {
          setActionLoading(null);
        }
      }
    });
  };

  const handleSupersede = (record) => {
    Modal.confirm({
      title: 'Supersede SBOM?',
      content: 'This will change the SBOM lifecycle status to SUPERSEDED.',
      onOk: async () => {
        try {
          setActionLoading(`${record.sbomID}-supersede`);
          await axios.post(`${API_BASE_URL}/supersede`, { sbomID: record.sbomID }, {
            headers: {
              'Content-Type': 'application/json',
              'x-user-id': selectedIdentity.userId,
              'x-user-role': selectedIdentity.role
            }
          });
          message.success('SBOM superseded successfully');
          await fetchSboms();
        } catch (err) {
          const msg = err.response?.data?.error || err.response?.data?.message || err.message || 'Failed to supersede SBOM';
          message.error(msg);
        } finally {
          setActionLoading(null);
        }
      }
    });
  };

  const total = sboms.length;
  const approved = sboms.filter((i) => i.status === 'APPROVED').length;
  const active = sboms.filter((i) => i.status === 'ACTIVE').length;
  const superseded = sboms.filter((i) => i.status === 'SUPERSEDED').length;

  const columns = [
    { title: 'SBOM ID', dataIndex: 'sbomID', key: 'sbomID' },
    { title: 'Software Name', dataIndex: 'softwareName', key: 'softwareName' },
    { title: 'Version', dataIndex: 'softwareVersion', key: 'softwareVersion' },
    { title: 'Format', dataIndex: 'format', key: 'format' },
    {
      title: 'Status',
      dataIndex: 'status',
      key: 'status',
      render: (status) => {
        let color = 'default';
        if (status === 'PENDING') color = 'gold';
        if (status === 'APPROVED') color = 'blue';
        if (status === 'ACTIVE') color = 'green';
        if (status === 'SUPERSEDED') color = 'red';
        return <Tag color={color}>{status}</Tag>;
      },
    },
    { title: 'Build ID', dataIndex: 'buildID', key: 'buildID' },
    { title: 'Requested By', dataIndex: 'requestedBy', key: 'requestedBy', render: (text) => text || '-' },
    { title: 'Job Name', dataIndex: 'jobName', key: 'jobName', render: (text) => text || '-' },
    { title: 'Submitter', dataIndex: 'submitterID', key: 'submitterID', render: (text) => text || '-' },
    { title: 'Timestamp', dataIndex: 'timestamp', key: 'timestamp' },
    {
      title: 'Actions',
      key: 'actions',
      render: (_, record) => (
        <Space size="small">
          <Button size="small" loading={actionLoading === `${record.sbomID}-view`} onClick={() => handleView(record)}>View</Button>
          <Button size="small" loading={actionLoading === `${record.sbomID}-copy`} onClick={() => handleCopy(record)}>Copy</Button>
          <Button size="small" loading={actionLoading === `${record.sbomID}-download`} onClick={() => handleDownload(record)}>Download</Button>
          {(selectedIdentity.role === 'security' || selectedIdentity.role === 'admin') && (
            <>
              {record.status === 'PENDING' && (
                <Button size="small" type="primary" loading={actionLoading === `${record.sbomID}-approve`} onClick={() => handleApprove(record)}>Approve</Button>
              )}
              {record.status === 'APPROVED' && (
                <>
                  <Button size="small" type="primary" loading={actionLoading === `${record.sbomID}-activate`} onClick={() => handleActivate(record)}>Activate</Button>
                  <Button size="small" danger loading={actionLoading === `${record.sbomID}-supersede`} onClick={() => handleSupersede(record)}>Supersede</Button>
                </>
              )}
              {record.status === 'ACTIVE' && (
                <Button size="small" danger loading={actionLoading === `${record.sbomID}-supersede`} onClick={() => handleSupersede(record)}>Supersede</Button>
              )}
            </>
          )}
        </Space>
      ),
    },
  ];

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '24px' }}>
      <div>
        <Title level={2} style={{ margin: 0 }}>SBOM Registry</Title>
        <Text type="secondary">This page shows registered SBOM records in the TPSR dashboard.</Text>
      </div>

      {errorMsg && <Alert message={errorMsg} type="error" showIcon />}

      <Row gutter={16}>
        <Col span={6}>
          <Card size="small" loading={loading}>
            <Typography.Title level={4} style={{ margin: 0 }}>{total}</Typography.Title>
            <Typography.Text type="secondary">Total SBOMs</Typography.Text>
          </Card>
        </Col>
        <Col span={6}>
          <Card size="small" loading={loading}>
            <Typography.Title level={4} style={{ margin: 0 }}>{approved}</Typography.Title>
            <Typography.Text type="secondary">Approved</Typography.Text>
          </Card>
        </Col>
        <Col span={6}>
          <Card size="small" loading={loading}>
            <Typography.Title level={4} style={{ margin: 0 }}>{active}</Typography.Title>
            <Typography.Text type="secondary">Active</Typography.Text>
          </Card>
        </Col>
        <Col span={6}>
          <Card size="small" loading={loading}>
            <Typography.Title level={4} style={{ margin: 0 }}>{superseded}</Typography.Title>
            <Typography.Text type="secondary">Superseded</Typography.Text>
          </Card>
        </Col>
      </Row>

      <Card>
        <Space style={{ marginBottom: 16 }}>
          <Input
            placeholder="Search SBOM ID or Name..."
            value={searchText}
            onChange={(e) => setSearchText(e.target.value)}
            style={{ width: 250 }}
            disabled={loading}
          />
          <Select
            value={statusFilter}
            onChange={setStatusFilter}
            style={{ width: 150 }}
            disabled={loading}
            options={[
              { value: 'All', label: 'All' },
              { value: 'PENDING', label: 'PENDING' },
              { value: 'APPROVED', label: 'APPROVED' },
              { value: 'ACTIVE', label: 'ACTIVE' },
              { value: 'SUPERSEDED', label: 'SUPERSEDED' },
            ]}
          />
          <Button onClick={fetchSboms} loading={loading}>Refresh</Button>
        </Space>
        <Table
          columns={columns}
          dataSource={filteredData}
          rowKey="sbomID"
          pagination={{ pageSize: 10 }}
          loading={loading}
        />
      </Card>

      <Modal
        title={`SBOM JSON - ${selectedSbomId}`}
        open={modalVisible}
        onCancel={() => setModalVisible(false)}
        footer={[
          <Button key="close" onClick={() => setModalVisible(false)}>Close</Button>
        ]}
        width={800}
      >
        <Input.TextArea
          value={selectedSbomJson}
          rows={20}
          readOnly
          style={{ fontFamily: 'monospace' }}
        />
      </Modal>
    </div>
  );
}

function VerifyPage({ selectedIdentity }) {
  const [sbomID, setSbomId] = useState('');
  const [sbomContent, setSbomContent] = useState('');
  const [errorMsg, setErrorMsg] = useState('');
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState(null);

  const handleVerify = async () => {
    setErrorMsg('');
    setResult(null);

    const idTrimmed = sbomID.trim();
    const contentTrimmed = sbomContent.trim();

    if (!idTrimmed || !contentTrimmed) {
      setErrorMsg('SBOM ID and SBOM Content are required');
      return;
    }

    setLoading(true);
    try {
      const response = await axios.post(
        `${API_BASE_URL}/verify`,
        { sbomID: idTrimmed, sbom: contentTrimmed },
        { headers: { 'x-user-id': selectedIdentity.userId, 'x-user-role': selectedIdentity.role } }
      );
      setResult(response.data.verification);
    } catch (err) {
      const msg = err.response?.data?.error || err.response?.data?.message || err.message || 'Verification failed';
      setErrorMsg(msg);
    } finally {
      setLoading(false);
    }
  };

  const getLedgerStatusColor = (status) => {
    if (status === 'PENDING') return 'gold';
    if (status === 'APPROVED') return 'blue';
    if (status === 'ACTIVE') return 'green';
    if (status === 'SUPERSEDED') return 'red';
    return 'default';
  };

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '24px', maxWidth: '800px' }}>
      <div>
        <Title level={2} style={{ margin: 0 }}>Verify SBOM Integrity</Title>
        <Text type="secondary">This page allows users to verify whether an SBOM matches the ledger record.</Text>
      </div>

      <Card>
        <Space direction="vertical" style={{ width: '100%' }} size="large">
          {errorMsg && <Alert message={errorMsg} type="error" showIcon />}
          
          <div>
            <div style={{ marginBottom: 8 }}><Text strong>SBOM ID</Text></div>
            <Input 
              placeholder="Enter SBOM ID" 
              value={sbomID} 
              onChange={(e) => setSbomId(e.target.value)} 
            />
          </div>

          <div>
            <div style={{ marginBottom: 8 }}><Text strong>SBOM Content</Text></div>
            <TextArea 
              rows={8} 
              placeholder="Paste raw SBOM JSON/XML content here" 
              value={sbomContent} 
              onChange={(e) => setSbomContent(e.target.value)} 
            />
          </div>

          <Button type="primary" onClick={handleVerify} loading={loading}>
            Verify Integrity
          </Button>
        </Space>
      </Card>

      {result && (
        <Card title="Verification Result" size="small">
          <Descriptions column={1} bordered size="small">
            <Descriptions.Item label="Status">
              <Tag color={result.match ? 'green' : 'red'}>{result.match ? 'VERIFIED' : 'FAILED'}</Tag>
            </Descriptions.Item>
            <Descriptions.Item label="SBOM ID">
              <Text>{result.sbomID}</Text>
            </Descriptions.Item>
            <Descriptions.Item label="Submitted Hash">
              <Text code>{result.submittedHash}</Text>
            </Descriptions.Item>
            <Descriptions.Item label="Stored Hash">
              <Text code>{result.storedHash}</Text>
            </Descriptions.Item>
            <Descriptions.Item label="Match">
              <Text strong>{result.match ? 'Yes' : 'No'}</Text>
            </Descriptions.Item>
            <Descriptions.Item label="Ledger Status">
              <Tag color={getLedgerStatusColor(result.status)}>{result.status}</Tag>
            </Descriptions.Item>
          </Descriptions>
        </Card>
      )}
    </div>
  );
}

function HistoryPage({ selectedIdentity }) {
  const [sbomID, setSbomId] = useState('');
  const [loading, setLoading] = useState(false);
  const [errorMsg, setErrorMsg] = useState('');
  const [history, setHistory] = useState([]);

  const handleLoad = async () => {
    setErrorMsg('');
    setHistory([]);

    const idTrimmed = sbomID.trim();
    if (!idTrimmed) {
      setErrorMsg('SBOM ID is required');
      return;
    }

    setLoading(true);
    try {
      const response = await axios.get(
        `${API_BASE_URL}/history/${encodeURIComponent(idTrimmed)}`,
        { headers: { 'x-user-id': selectedIdentity.userId, 'x-user-role': selectedIdentity.role } }
      );
      setHistory(response.data.history || []);
    } catch (err) {
      const msg = err.response?.data?.error || err.response?.data?.message || err.message || 'Failed to load history';
      setErrorMsg(msg);
    } finally {
      setLoading(false);
    }
  };

  const totalEvents = history.length;
  const deleteEvents = history.filter(i => i.isDelete).length;
  const activeStatusEvents = history.filter(i => i.record?.status === 'ACTIVE').length;
  let latestTransaction = '-';
  if (history.length > 0) {
    let latestEntry = history[0];
    for (let i = 1; i < history.length; i++) {
      if ((history[i].timestamp || 0) > (latestEntry.timestamp || 0)) {
        latestEntry = history[i];
      }
    }
    latestTransaction = latestEntry.txID || '-';
  }

  const columns = [
    { title: 'Transaction ID', dataIndex: 'txID', key: 'txID' },
    { title: 'Timestamp', dataIndex: 'timestamp', key: 'timestamp' },
    { 
      title: 'Deleted', 
      dataIndex: 'isDelete', 
      key: 'isDelete',
      render: (isDel) => (isDel ? 'Yes' : 'No')
    },
    { 
      title: 'Status', 
      key: 'status',
      render: (_, item) => {
        const s = item.record?.status;
        if (!s) return '-';
        let color = 'default';
        if (s === 'PENDING') color = 'gold';
        if (s === 'APPROVED') color = 'blue';
        if (s === 'ACTIVE') color = 'green';
        if (s === 'SUPERSEDED') color = 'red';
        return <Tag color={color}>{s}</Tag>;
      }
    },
    { 
      title: 'Submitter', 
      key: 'submitterID',
      render: (_, item) => item.record?.submitterID || '-'
    },
    { 
      title: 'Build ID', 
      key: 'buildID',
      render: (_, item) => item.record?.buildID || '-'
    },
  ];

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '24px' }}>
      <div>
        <Title level={2} style={{ margin: 0 }}>SBOM History</Title>
        <Text type="secondary">This page displays the lifecycle and ledger history of SBOM records.</Text>
      </div>

      <Card size="small" style={{ backgroundColor: '#e6f4ff', borderColor: '#91caff' }}>
        <Text strong style={{ color: '#0958d9' }}>Note:</Text>
        <Text style={{ marginLeft: 8 }}>This page now uses the real backend history API.</Text>
      </Card>

      <Card>
        <Space direction="vertical" style={{ width: '100%' }} size="large">
          {errorMsg && <Alert message={errorMsg} type="error" showIcon />}
          
          <div>
            <div style={{ marginBottom: 8 }}><Text strong>SBOM ID</Text></div>
            <Space>
              <Input 
                placeholder="Enter SBOM ID" 
                value={sbomID} 
                onChange={(e) => setSbomId(e.target.value)} 
                style={{ width: 300 }}
              />
              <Button type="primary" onClick={handleLoad} loading={loading}>
                Load History
              </Button>
            </Space>
          </div>
        </Space>
      </Card>

      {history.length > 0 && (
        <>
          <Row gutter={16}>
            <Col span={6}>
              <Card size="small">
                <Typography.Title level={4} style={{ margin: 0 }}>{totalEvents}</Typography.Title>
                <Typography.Text type="secondary">Total Events</Typography.Text>
              </Card>
            </Col>
            <Col span={6}>
              <Card size="small">
                <Typography.Title level={4} style={{ margin: 0 }}>{activeStatusEvents}</Typography.Title>
                <Typography.Text type="secondary">Active Status Events</Typography.Text>
              </Card>
            </Col>
            <Col span={6}>
              <Card size="small">
                <Typography.Title level={4} style={{ margin: 0 }}>{deleteEvents}</Typography.Title>
                <Typography.Text type="secondary">Delete Events</Typography.Text>
              </Card>
            </Col>
            <Col span={6}>
              <Card size="small">
                <Typography.Title level={5} style={{ margin: 0, wordBreak: 'break-all' }}>{latestTransaction}</Typography.Title>
                <Typography.Text type="secondary">Latest Transaction</Typography.Text>
              </Card>
            </Col>
          </Row>

          <Card>
            <Table 
              columns={columns} 
              dataSource={history} 
              rowKey={(item, index) => item.txID || index} 
              pagination={{ pageSize: 10 }}
            />
          </Card>
        </>
      )}
    </div>
  );
}

function CompliancePage({ selectedIdentity }) {
  const [sbomID, setSbomId] = useState('');
  const [sbomContent, setSbomContent] = useState('');
  const [errorMsg, setErrorMsg] = useState('');
  const [loading, setLoading] = useState(false);
  const [report, setReport] = useState(null);

  const handleGenerate = async () => {
    setErrorMsg('');
    setReport(null);

    const idTrimmed = sbomID.trim();
    const contentTrimmed = sbomContent.trim();

    if (!idTrimmed || !contentTrimmed) {
      setErrorMsg('SBOM ID and SBOM Content are required');
      return;
    }

    setLoading(true);
    try {
      const response = await axios.post(
        `${API_BASE_URL}/compliance-report`,
        { sbomID: idTrimmed, sbom: contentTrimmed },
        { headers: { 'x-user-id': selectedIdentity.userId, 'x-user-role': selectedIdentity.role } }
      );
      setReport(response.data.report);
    } catch (err) {
      const msg = err.response?.data?.error || err.response?.data?.message || err.message || 'Compliance report generation failed';
      setErrorMsg(msg);
    } finally {
      setLoading(false);
    }
  };

  const getLedgerStatusColor = (status) => {
    if (status === 'PENDING') return 'gold';
    if (status === 'APPROVED') return 'blue';
    if (status === 'ACTIVE') return 'green';
    if (status === 'SUPERSEDED') return 'red';
    return 'default';
  };

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '24px', maxWidth: '800px' }}>
      <div>
        <Title level={2} style={{ margin: 0 }}>Compliance Report</Title>
        <Text type="secondary">This page evaluates whether an SBOM satisfies ledger integrity and lifecycle compliance conditions.</Text>
      </div>

      <Card>
        <Space direction="vertical" style={{ width: '100%' }} size="large">
          {errorMsg && <Alert message={errorMsg} type="error" showIcon />}
          
          <div>
            <div style={{ marginBottom: 8 }}><Text strong>SBOM ID</Text></div>
            <Input 
              placeholder="Enter SBOM ID" 
              value={sbomID} 
              onChange={(e) => setSbomId(e.target.value)} 
            />
          </div>

          <div>
            <div style={{ marginBottom: 8 }}><Text strong>SBOM Content</Text></div>
            <TextArea 
              rows={8} 
              placeholder="Paste raw SBOM JSON/XML content here" 
              value={sbomContent} 
              onChange={(e) => setSbomContent(e.target.value)} 
            />
          </div>

          <Button type="primary" onClick={handleGenerate} loading={loading}>
            Generate Compliance Report
          </Button>
        </Space>
      </Card>

      {report && (
        <Card title="Compliance Report Result" size="small">
          <Alert 
            style={{ marginBottom: 16 }}
            type={report.compliant ? 'success' : 'warning'}
            message={report.compliant ? 'SBOM is compliant with the current ledger state.' : 'SBOM is not compliant with the current ledger state.'}
            showIcon 
          />
          <Descriptions column={1} bordered size="small">
            <Descriptions.Item label="Compliance Status">
              <Tag color={report.compliant ? 'green' : 'red'}>
                {report.compliant ? 'COMPLIANT' : 'NON-COMPLIANT'}
              </Tag>
            </Descriptions.Item>
            <Descriptions.Item label="SBOM ID">
              <Text>{report.sbomID}</Text>
            </Descriptions.Item>
            <Descriptions.Item label="Computed Hash">
              <Text code>{report.computedHash}</Text>
            </Descriptions.Item>
            <Descriptions.Item label="Stored Hash">
              <Text code>{report.storedHash}</Text>
            </Descriptions.Item>
            <Descriptions.Item label="Integrity Match">
              <Text strong>{report.integrityMatch ? 'Yes' : 'No'}</Text>
            </Descriptions.Item>
            <Descriptions.Item label="Ledger Status">
              <Tag color={getLedgerStatusColor(report.ledgerStatus)}>{report.ledgerStatus}</Tag>
            </Descriptions.Item>
            <Descriptions.Item label="History Count">
              <Text>{report.historyCount}</Text>
            </Descriptions.Item>
            <Descriptions.Item label="Latest Transaction">
              <Text>{report.latestTxID || '-'}</Text>
            </Descriptions.Item>
            <Descriptions.Item label="Latest Timestamp">
              <Text>{report.latestTimestamp || '-'}</Text>
            </Descriptions.Item>
            <Descriptions.Item label="Latest Is Deleted">
              <Text>{report.latestIsDelete ? 'Yes' : 'No'}</Text>
            </Descriptions.Item>
          </Descriptions>
        </Card>
      )}
    </div>
  );
}

function App() {
  const location = useLocation();
  const [configWarningDismissed, setConfigWarningDismissed] = useState(false);
  const [selectedIdentity, setSelectedIdentity] = useState(DEMO_IDENTITIES[1]); // Default to Security

  const menuItems = [
    {
      key: '/sboms',
      label: <Link to="/sboms">SBOMs</Link>,
    },
    {
      key: '/verify',
      label: <Link to="/verify">Verify</Link>,
    },
    {
      key: '/history',
      label: <Link to="/history">History</Link>,
    },
    {
      key: '/compliance',
      label: <Link to="/compliance">Compliance</Link>,
    },
  ];

  return (
    <Layout style={{ minHeight: '100vh' }}>
      <Sider width={200} theme="dark">
        <div style={{ padding: '16px', textAlign: 'center' }}>
          <Title level={4} style={{ color: 'white', margin: 0 }}>TPSR</Title>
        </div>
        <Menu
          theme="dark"
          mode="inline"
          selectedKeys={[location.pathname]}
          items={menuItems}
        />
      </Sider>
      <Layout>
        <Header style={{ background: '#fff', padding: '0 24px', display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
          <Title level={3} style={{ margin: 0 }}>TPSR Dashboard</Title>
          <Space>
            <Text type="secondary" style={{ fontSize: '12px', marginRight: '16px' }}>
              Prototype demo identity only. Production IAM/SSO is not implemented.
            </Text>
            <Text strong>Demo Identity:</Text>
            <Select
              value={selectedIdentity.userId}
              onChange={(value) => {
                const id = DEMO_IDENTITIES.find(i => i.userId === value);
                if (id) setSelectedIdentity(id);
              }}
              style={{ width: 150 }}
              options={DEMO_IDENTITIES.map(id => ({ label: id.label, value: id.userId }))}
            />
          </Space>
        </Header>
        <Content style={{ padding: '24px', margin: 0, minHeight: 280 }}>
          {_usingDefaults && !configWarningDismissed && (
            <Alert
              style={{ marginBottom: 24 }}
              type="warning"
              showIcon
              closable
              onClose={() => setConfigWarningDismissed(true)}
              message="Dashboard is running with default integration identity/role settings. Configure .env values before production deployment."
            />
          )}
          <Routes>
            <Route path="/" element={<Navigate to="/sboms" replace />} />
            <Route path="/sboms" element={<SBOMListPage selectedIdentity={selectedIdentity} />} />
            <Route path="/verify" element={<VerifyPage selectedIdentity={selectedIdentity} />} />
            <Route path="/history" element={<HistoryPage selectedIdentity={selectedIdentity} />} />
            <Route path="/compliance" element={<CompliancePage selectedIdentity={selectedIdentity} />} />
          </Routes>
        </Content>
      </Layout>
    </Layout>
  );
}

export default App;
