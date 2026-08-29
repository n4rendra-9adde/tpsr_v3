import React, { useState, useMemo, useEffect } from 'react';
import { Layout, Menu, Typography, Card, Row, Col, Table, Tag, Input, Select, Space, Button, Alert, Descriptions, Modal, message, Upload, Tooltip, ConfigProvider } from 'antd';
import { Link, Navigate, Route, Routes, useLocation } from 'react-router-dom';
import { useSbomEvidence } from './hooks/useSbomEvidence';
import { EvidenceApiDiagnostics } from './components';
import SubmitPage from './components/SubmitPage';
import axios from 'axios';
import { 
  TrustDecisionBadge, 
  AnchorStatusBadge, 
  SignatureEvidenceCard, 
  ContextAssertionCard,
  PolicyExceptionCard,
  ProvenanceEvidenceCard, 
  ContextRiskSummary,
  VexApplicabilityTable, 
  ReasonCodeList, 
  SimulationNotice,
  DecisionSnapshotCard 
} from './components';


// Bypass Ngrok free tier browser warning
axios.defaults.headers.common['ngrok-skip-browser-warning'] = '69420';

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

/** Abbreviate a long Fabric X.509 identity string for display in tables. */
function abbrevLedgerId(id) {
  if (!id || typeof id !== 'string') return '-';
  if (id.length <= 24) return id;
  return id.slice(0, 20) + '...';
}

/** Format a Unix epoch timestamp (seconds) to a human-readable string. */
function fmtUnix(ts) {
  if (!ts) return '-';
  return new Date(ts * 1000).toLocaleString();
}

/** Format an ISO date string or return '-'. */
function fmtISO(iso) {
  if (!iso) return '-';
  try { return new Date(iso).toLocaleString(); } catch (_) { return iso; }
}

function SBOMListPage({ selectedIdentity }) {
  const [searchText, setSearchText] = useState('');
  const [statusFilter, setStatusFilter] = useState('All');
  const [loading, setLoading] = useState(false);
  const [errorMsg, setErrorMsg] = useState('');
  const [sboms, setSboms] = useState([]);
  const [modalVisible, setModalVisible] = useState(false);
  const [selectedSbomId, setSelectedSbomId] = useState(null);
  const [selectedSbomJson, setSelectedSbomJson] = useState('');
  const [selectedRecord, setSelectedRecord] = useState(null);
  const [actionLoading, setActionLoading] = useState(null);
  const [currentPage, setCurrentPage] = useState(1);
  const [pageSize, setPageSize] = useState(10);

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
        fabricTxId: item.fabricTxId ?? item.fabric_tx_id,
        sbomHash: item.sbomHash ?? item.sbom_hash,
        offChainRef: item.offChainRef ?? item.off_chain_ref,
        createdAt: item.createdAt ?? item.created_at,
        timestamp: item.timestamp ?? item.created_at,
        requestedBy: item.requestedBy ?? item.requested_by,
        jobName: item.jobName ?? item.job_name,
        policyStatus: item.policyStatus ?? item.policy_status,
        policyReason: item.policyReason ?? item.policy_reason,
        policyViolations: item.policyViolations ?? item.policy_violations,
        trustStatus: item.trustStatus || 'UNEVALUATED',
        trustReasonCode: item.trustReasonCode || 'GOV-002',
        trustReasonDescription: item.trustReasonDescription || 'v3 trust evaluation not yet executed'
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
      setSelectedRecord(record);
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
      content: 'This will change the SBOM lifecycle status from COMPLIANT to APPROVED.',
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
          const errData = err.response?.data;
          const msg = errData?.error 
                      ? (errData.details ? `${errData.error} - ${errData.details}` : errData.error)
                      : (err.message || 'Failed to approve SBOM');
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

  const handleReviewPending = (record) => {
    Modal.confirm({
      title: 'Mark Review Pending?',
      content: 'This will move the SBOM to the REVIEW_PENDING state for security evaluation.',
      onOk: async () => {
        try {
          setActionLoading(`${record.sbomID}-review`);
          await axios.post(`${API_BASE_URL}/review-pending`, { sbomID: record.sbomID }, {
            headers: {
              'Content-Type': 'application/json',
              'x-user-id': selectedIdentity.userId,
              'x-user-role': selectedIdentity.role
            }
          });
          message.success('SBOM marked as review pending');
          await fetchSboms();
        } catch (err) {
          const msg = err.response?.data?.error || err.response?.data?.message || err.message || 'Failed to update SBOM';
          message.error(msg);
        } finally {
          setActionLoading(null);
        }
      }
    });
  };

  const handleSecurityReviewed = (record) => {
    Modal.confirm({
      title: 'Mark Security Reviewed?',
      content: 'This will confirm security review is complete and automatically evaluate compliance. This may automatically advance to COMPLIANT or REJECTED.',
      onOk: async () => {
        try {
          setActionLoading(`${record.sbomID}-security`);
          await axios.post(`${API_BASE_URL}/security-reviewed`, { sbomID: record.sbomID }, {
            headers: {
              'Content-Type': 'application/json',
              'x-user-id': selectedIdentity.userId,
              'x-user-role': selectedIdentity.role
            }
          });
          message.success('SBOM security review processed');
          await fetchSboms();
        } catch (err) {
          const errData = err.response?.data;
          const msg = errData?.error 
                      ? (errData.details ? `${errData.error} - ${errData.details}` : errData.error)
                      : (err.message || 'Failed to process security review');
          message.error(msg);
        } finally {
          setActionLoading(null);
        }
      }
    });
  };

  const handleReject = (record) => {
    let rejectReason = '';
    Modal.confirm({
      title: 'Reject SBOM?',
      content: (
        <div>
          <p>This will reject the SBOM and mark it as REJECTED.</p>
          <Input.TextArea
            placeholder="Optional reason for rejection"
            onChange={e => rejectReason = e.target.value}
            rows={3}
          />
        </div>
      ),
      onOk: async () => {
        try {
          setActionLoading(`${record.sbomID}-reject`);
          await axios.post(`${API_BASE_URL}/reject`, { sbomID: record.sbomID, reason: rejectReason }, {
            headers: {
              'Content-Type': 'application/json',
              'x-user-id': selectedIdentity.userId,
              'x-user-role': selectedIdentity.role
            }
          });
          message.success('SBOM rejected successfully');
          await fetchSboms();
        } catch (err) {
          const msg = err.response?.data?.error || err.response?.data?.message || err.message || 'Failed to reject SBOM';
          message.error(msg);
        } finally {
          setActionLoading(null);
        }
      }
    });
  };

  const computeSecuritySuggestions = (record) => {
    let sbomJson = {};
    try {
      sbomJson = typeof record.sbom_json === 'string' ? JSON.parse(record.sbom_json) : (record.sbom_json || {});
    } catch (_) {}

    const components = sbomJson.components || [];
    const compCount = components.length;

    const licenses = new Set();
    components.forEach(c => {
      if (c.licenses && Array.isArray(c.licenses)) {
        c.licenses.forEach(l => {
          if (l.license && l.license.id) licenses.add(l.license.id);
          else if (l.license && l.license.name) licenses.add(l.license.name);
          else if (typeof l === 'string') licenses.add(l);
        });
      }
    });

    const allVulns = [];
    if (Array.isArray(record.vulnerabilities)) {
      allVulns.push(...record.vulnerabilities);
    }
    if (Array.isArray(sbomJson.vulnerabilities)) {
      allVulns.push(...sbomJson.vulnerabilities);
    }
    components.forEach(c => {
      if (c.vulnerabilities && Array.isArray(c.vulnerabilities)) {
        allVulns.push(...c.vulnerabilities);
      }
    });

    let vulnCount = allVulns.length;
    let criticalCount = 0;
    let highCount = 0;

    allVulns.forEach(v => {
      const sev = (v.severity || v.originalSeverity || '').toUpperCase();
      if (sev === 'CRITICAL') criticalCount++;
      else if (sev === 'HIGH') highCount++;
    });

    const isPolicyFail = record.policy_status === 'FAIL' || record.policyStatus === 'FAIL';
    const violations = record.policy_violations || record.policyViolations || [];

    let suggestedDecision = 'MARK TRUSTED';
    let decisionReason = 'SBOM passes structural integrity, policy compliance, and zero critical vulnerabilities.';
    let decisionBadgeColor = '#52c41a';

    if (isPolicyFail || criticalCount > 0) {
      suggestedDecision = 'REQUIRE POLICY EXCEPTION';
      if (isPolicyFail && violations.length > 0) {
        decisionReason = `Policy Failure: ${violations.slice(0, 2).join(' | ')}`;
      } else {
        decisionReason = `${criticalCount} Critical & ${highCount} High vulnerability finding(s) detected. Governed policy exception required before approval.`;
      }
      decisionBadgeColor = '#ff4d4f';
    } else if (highCount > 0 || vulnCount > 0) {
      suggestedDecision = 'CONDITIONAL APPROVAL';
      decisionReason = `${vulnCount} vulnerability finding(s) present (${highCount} High). Restrict exposure to NONE.`;
      decisionBadgeColor = '#fa8c16';
    }

    const tips = [
      `📦 Dependency Profile: ${compCount > 0 ? `${compCount} components cataloged` : 'Clean payload'}.`,
      `📜 License Profile: ${licenses.size > 0 ? Array.from(licenses).slice(0, 3).join(', ') : 'Permissive licenses'}.`,
      `⚠️ Security Findings: ${vulnCount > 0 ? `${vulnCount} vulnerabilities detected (${criticalCount} Critical, ${highCount} High)` : 'No CVE findings'}.`,
      isPolicyFail ? `🚨 Policy Violations: ${violations.length} policy rule(s) violated.` : `🔐 Ledger Anchor: Hyperledger Fabric Tx verified.`
    ];

    return {
      suggestedDecision,
      decisionReason,
      decisionBadgeColor,
      compCount,
      vulnCount,
      tips
    };
  };

  const handleContextAssertion = (record) => {
    let env = 'PRODUCTION';
    let exp = 'NONE';
    let crit = 'LOW';
    let just = 'Verified security deployment context';
    let source = 'SECURITY_AUDIT_DASHBOARD';

    const aiAnalysis = computeSecuritySuggestions(record);

    Modal.confirm({
      title: `Complete Context Review for ${record.sbomID}`,
      width: 580,
      content: (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '14px', marginTop: '16px' }}>
          <div style={{
            background: 'linear-gradient(135deg, #e6f7ff 0%, #f0f5ff 100%)',
            border: '1px solid #91caff',
            borderRadius: '8px',
            padding: '12px 16px'
          }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '6px' }}>
              <span style={{ fontWeight: 700, color: '#1677ff', fontSize: '13px' }}>🛡️ CAECTD Security Review & Decision Recommendation</span>
              <span style={{
                backgroundColor: aiAnalysis.decisionBadgeColor,
                color: '#fff',
                fontWeight: 700,
                fontSize: '11px',
                padding: '2px 8px',
                borderRadius: '10px'
              }}>{aiAnalysis.suggestedDecision}</span>
            </div>
            <p style={{ margin: '0 0 8px 0', fontSize: '12px', color: '#262626', fontWeight: 500 }}>
              {aiAnalysis.decisionReason}
            </p>
            <div style={{ display: 'flex', flexDirection: 'column', gap: '4px', borderTop: '1px dashed #adc6ff', paddingTop: '8px' }}>
              {aiAnalysis.tips.map((tip, idx) => (
                <div key={idx} style={{ fontSize: '11px', color: '#434343' }}>{tip}</div>
              ))}
            </div>
          </div>

          <p style={{ color: '#595959', margin: 0, fontSize: '13px' }}>
            Declare the deployment context assertion below to complete review and establish <strong>TRUSTED</strong> state:
          </p>
          <div>
            <label style={{ fontWeight: 600, display: 'block', marginBottom: '4px' }}>Deployment Environment</label>
            <Select defaultValue="PRODUCTION" style={{ width: '100%' }} onChange={val => env = val}>
              <Select.Option value="PRODUCTION">PRODUCTION</Select.Option>
              <Select.Option value="STAGING">STAGING</Select.Option>
              <Select.Option value="DEVELOPMENT">DEVELOPMENT</Select.Option>
            </Select>
          </div>
          <div>
            <label style={{ fontWeight: 600, display: 'block', marginBottom: '4px' }}>Internet Exposure</label>
            <Select defaultValue="NONE" style={{ width: '100%' }} onChange={val => exp = val}>
              <Select.Option value="NONE">NONE (Internal Service / Non-Exposed)</Select.Option>
              <Select.Option value="INDIRECT">INDIRECT (Behind Reverse Proxy / WAF)</Select.Option>
              <Select.Option value="DIRECT">DIRECT (Publicly Internet Exposed)</Select.Option>
            </Select>
          </div>
          <div>
            <label style={{ fontWeight: 600, display: 'block', marginBottom: '4px' }}>Asset Criticality</label>
            <Select defaultValue="LOW" style={{ width: '100%' }} onChange={val => crit = val}>
              <Select.Option value="LOW">LOW</Select.Option>
              <Select.Option value="MEDIUM">MEDIUM</Select.Option>
              <Select.Option value="HIGH">HIGH</Select.Option>
              <Select.Option value="CRITICAL">CRITICAL</Select.Option>
            </Select>
          </div>
          <div>
            <label style={{ fontWeight: 600, display: 'block', marginBottom: '4px' }}>Review Justification</label>
            <Input.TextArea
              defaultValue="Verified security deployment context"
              onChange={e => just = e.target.value}
              rows={2}
            />
          </div>
        </div>
      ),
      okText: 'Submit & Mark Trusted',
      onOk: async () => {
        try {
          setActionLoading(`${record.sbomID}-context`);
          await axios.post(`${API_BASE_URL}/v1/sbom/${record.sbomID}/context/assertions`, {
            assertion: {
              environment: env,
              internetExposure: exp,
              assetCriticality: crit,
              privilegeLevel: 'UNPRIVILEGED',
              dataSensitivity: 'PUBLIC',
              runtimeExecution: 'EXECUTED',
              componentPresence: 'PRESENT',
              justification: just || 'Security review completed via dashboard',
              evidenceSource: source
            }
          }, {
            headers: {
              'Content-Type': 'application/json',
              'x-user-id': selectedIdentity.userId,
              'x-user-role': selectedIdentity.role
            }
          });
          message.success('Context review recorded! Trust decision updated to TRUSTED.');
          await fetchSboms();
        } catch (err) {
          const msg = err.response?.data?.error || err.message || 'Failed to submit context review';
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
      title: 'Policy Status',
      dataIndex: 'policyStatus',
      key: 'policyStatus',
      render: (status) => {
        if (!status) return <Tag>UNKNOWN</Tag>;
        return <Tag color={status === 'PASS' ? 'success' : 'error'}>{status}</Tag>;
      }
    },
    {
      title: 'Trust Decision',
      dataIndex: 'trustStatus',
      key: 'trustStatus',
      render: (status, record) => <TrustDecisionBadge status={status} reasonCode={record.trustReasonCode} reasonDesc={record.trustReasonDescription} />
    },
    {
      title: 'Status',
      dataIndex: 'status',
      key: 'status',
      render: (status) => <AnchorStatusBadge status={status} />,
    },
    { title: 'Build ID', dataIndex: 'buildID', key: 'buildID' },
    { title: 'Recorded By', dataIndex: 'requestedBy', key: 'requestedBy', render: (text) => text || '-' },
    { title: 'Job Name', dataIndex: 'jobName', key: 'jobName', render: (text) => text || '-' },
    {
      title: 'Anchored',
      key: 'anchored',
      render: (_, record) => record.fabricTxId
        ? <Tooltip title={`Fabric Tx: ${record.fabricTxId}`}><Tag color="geekblue">Anchored</Tag></Tooltip>
        : <Tag>Pending</Tag>
    },
    { title: 'Anchored At', dataIndex: 'createdAt', key: 'createdAt', render: (t) => fmtISO(t) },
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
              {record.trustStatus === 'REVIEW_REQUIRED' && (
                <Button size="small" style={{ backgroundColor: '#fa8c16', color: '#fff', borderColor: '#fa8c16' }} loading={actionLoading === `${record.sbomID}-context`} onClick={() => handleContextAssertion(record)}>Make Trusted</Button>
              )}
              {record.status === 'REGISTERED' && (
                <Button size="small" type="dashed" loading={actionLoading === `${record.sbomID}-review`} onClick={() => handleReviewPending(record)}>Review Pending</Button>
              )}
              {record.status === 'REVIEW_PENDING' && (
                <Button size="small" type="primary" loading={actionLoading === `${record.sbomID}-security`} onClick={() => handleSecurityReviewed(record)}>Security Reviewed</Button>
              )}
              {record.status === 'COMPLIANT' && (selectedIdentity.role === 'auditor' || selectedIdentity.role === 'admin') && (
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
          {record.status === 'COMPLIANT' && selectedIdentity.role === 'auditor' && selectedIdentity.role !== 'admin' && (
            <Button size="small" type="primary" loading={actionLoading === `${record.sbomID}-approve`} onClick={() => handleApprove(record)}>Approve</Button>
          )}
          {(selectedIdentity.role === 'security' || selectedIdentity.role === 'auditor' || selectedIdentity.role === 'admin') && 
           ['REGISTERED', 'REVIEW_PENDING', 'SECURITY_REVIEWED', 'COMPLIANT', 'APPROVED', 'ACTIVE'].includes(record.status) && (
            <Button size="small" danger loading={actionLoading === `${record.sbomID}-reject`} onClick={() => handleReject(record)}>Reject</Button>
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
              { value: 'REGISTERED', label: 'REGISTERED' },
              { value: 'REVIEW_PENDING', label: 'REVIEW_PENDING' },
              { value: 'SECURITY_REVIEWED', label: 'SECURITY_REVIEWED' },
              { value: 'COMPLIANT', label: 'COMPLIANT' },
              { value: 'APPROVED', label: 'APPROVED' },
              { value: 'ACTIVE', label: 'ACTIVE' },
              { value: 'SUPERSEDED', label: 'SUPERSEDED' },
              { value: 'REJECTED', label: 'REJECTED' },
            ]}
          />
          <Button onClick={fetchSboms} loading={loading}>Refresh</Button>
        </Space>
        <Table
          columns={columns}
          dataSource={filteredData}
          rowKey="sbomID"
          pagination={{ 
            current: currentPage,
            pageSize: pageSize,
            showSizeChanger: true, 
            pageSizeOptions: ['10', '20', '50', '100', '200'],
            onChange: (page, size) => {
              setCurrentPage(page);
              setPageSize(size);
            },
            onShowSizeChange: (current, size) => {
              setCurrentPage(1);
              setPageSize(size);
            }
          }}
          loading={loading}
        />
      </Card>

      <Modal
        title={`SBOM Document - ${selectedSbomId}`}
        open={modalVisible}
        onCancel={() => setModalVisible(false)}
        footer={[
          <Button key="close" onClick={() => setModalVisible(false)}>Close</Button>
        ]}
        width={860}
      >
        {selectedRecord && (
          <>
            <Card
              title="Ledger Anchor Evidence"
              size="small"
              style={{ marginBottom: 16, borderColor: '#91caff', backgroundColor: '#e6f4ff' }}
            >
              <Descriptions column={1} bordered size="small">
                <Descriptions.Item label="Recorded By">
                  <Text strong>{selectedRecord.requestedBy || '-'}</Text>
                </Descriptions.Item>
                <Descriptions.Item label="Ledger Identity">
                  <Tooltip title={selectedRecord.submitterID || 'N/A'}>
                    <Text code style={{ cursor: 'help' }}>{abbrevLedgerId(selectedRecord.submitterID)}</Text>
                  </Tooltip>
                </Descriptions.Item>
                <Descriptions.Item label="Anchored Hash">
                  <Text code style={{ wordBreak: 'break-all' }}>{selectedRecord.sbomHash || '-'}</Text>
                </Descriptions.Item>
                <Descriptions.Item label="Fabric Transaction ID">
                  <Text code style={{ wordBreak: 'break-all' }}>{selectedRecord.fabricTxId || '-'}</Text>
                </Descriptions.Item>
                <Descriptions.Item label="Anchored At">
                  {fmtISO(selectedRecord.createdAt)}
                </Descriptions.Item>
                <Descriptions.Item label="Lifecycle State">
                  <AnchorStatusBadge status={selectedRecord.status} />
                </Descriptions.Item>
                <Descriptions.Item label="Off-chain SBOM Reference">
                  {selectedRecord.offChainRef || '-'}
                </Descriptions.Item>
                <Descriptions.Item label="Fabric Channel">
                  {selectedRecord.fabric_channel || 'tpsrchannel'}
                </Descriptions.Item>
                <Descriptions.Item label="Policy Status">
                  <Space>
                    {selectedRecord.policyStatus
                      ? <Tag color={selectedRecord.policyStatus === 'PASS' ? 'success' : 'error'}>{selectedRecord.policyStatus}</Tag>
                      : <Tag>UNKNOWN</Tag>}
                    {selectedRecord.policyVersion && (
                      <Tag color="purple">v{selectedRecord.policyVersion}</Tag>
                    )}
                  </Space>
                </Descriptions.Item>
                {selectedRecord.policyReason && (
                  <Descriptions.Item label="Policy Reason">{selectedRecord.policyReason}</Descriptions.Item>
                )}
                {selectedRecord.policyViolations && selectedRecord.policyViolations.length > 0 && (
                  <Descriptions.Item label="Policy Violations">
                    <ul>{selectedRecord.policyViolations.map((v, i) => <li key={i}><Text type="danger">{v}</Text></li>)}</ul>
                  </Descriptions.Item>
                )}
                <Descriptions.Item label="Trust Decision Status">
                  <TrustDecisionBadge status={selectedRecord.trustStatus} reasonCode={selectedRecord.trustReasonCode} reasonDesc={selectedRecord.trustReasonDescription} />
                </Descriptions.Item>
                {selectedRecord.trustReasonCode && (
                  <Descriptions.Item label="Trust Reason">
                    <Text strong>{selectedRecord.trustReasonCode}</Text>: {selectedRecord.trustReasonDescription}
                  </Descriptions.Item>
                )}
              </Descriptions>
              {selectedRecord.trustStatus === 'REVIEW_REQUIRED' && (
                <Alert
                  style={{ marginTop: 12 }}
                  type="warning"
                  showIcon
                  message="Context Review Required (CTX-005)"
                  description={
                    <div style={{ marginTop: 8 }}>
                      <p style={{ margin: 0, marginBottom: 8 }}>
                        This SBOM has valid cryptographic provenance & signatures, but requires deployment context verification to satisfy governance rule CAECTD-R024.
                      </p>
                      <Button
                        type="primary"
                        style={{ backgroundColor: '#fa8c16', borderColor: '#fa8c16' }}
                        onClick={() => {
                          setModalVisible(false);
                          handleContextAssertion(selectedRecord);
                        }}
                      >
                        Complete Context Review & Make Trusted
                      </Button>
                    </div>
                  }
                />
              )}
            </Card>
            <Text strong>Raw SBOM JSON Payload:</Text>
            <Input.TextArea
              value={selectedSbomJson}
              rows={14}
              readOnly
              style={{ fontFamily: 'monospace', marginTop: 8 }}
            />
          </>
        )}
        {!selectedRecord && (
          <Input.TextArea
            value={selectedSbomJson}
            rows={16}
            readOnly
            style={{ fontFamily: 'monospace', marginTop: 8 }}
          />
        )}
      </Modal>
    </div>
  );
}

function VerifyPage({ selectedIdentity }) {
  const [sbomID, setSbomId] = useState('');
  const [sbomContent, setSbomContent] = useState('');
  const [selectedFile, setSelectedFile] = useState(null);
  const [fileReading, setFileReading] = useState(false);
  const [errorMsg, setErrorMsg] = useState('');
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState(null);
  const [perfMetrics, setPerfMetrics] = useState(null);

  const {
    loading: evidenceLoading,
    error: evidenceError,
    documentData: anchorDoc,
    signatureData,
    provenanceData,
    vexData,
    contextAssertionData,
    exceptionsData,
    trustDecisionData,
    diagnostics,
    fetchEvidence,
    reset: resetEvidence
  } = useSbomEvidence();

  const handleBeforeUpload = (file) => {
    setErrorMsg('');
    setSelectedFile(null);
    setSbomContent('');

    const allowedExtensions = ['.json', '.xml', '.spdx', '.cdx', '.txt'];
    const ext = file.name.slice((Math.max(0, file.name.lastIndexOf(".")) || Infinity)).toLowerCase();
    
    if (!allowedExtensions.includes(ext)) {
      setErrorMsg(`Invalid file type. Allowed: ${allowedExtensions.join(', ')}`);
      return false;
    }

    if (file.size === 0) {
      setErrorMsg('Selected SBOM file is empty.');
      return false;
    }

    setFileReading(true);
    const reader = new FileReader();
    reader.onload = (e) => {
      const content = e.target.result;
      if (!content || content.trim() === '') {
        setErrorMsg('Selected SBOM file is empty or could not be read as text.');
        setFileReading(false);
        return;
      }
      setSbomContent(content);
      setSelectedFile(file);
      setFileReading(false);
    };
    reader.onerror = () => {
      setErrorMsg('Failed to read selected SBOM file.');
      setFileReading(false);
    };
    reader.readAsText(file);
    return false;
  };

  const handleRemoveFile = () => {
    setSelectedFile(null);
    setSbomContent('');
    setErrorMsg('');
    setResult(null);
    setPerfMetrics(null);
    resetEvidence();
  };

  const handleVerify = async () => {
    setErrorMsg('');
    setResult(null);
    resetEvidence();

    const idTrimmed = sbomID.trim();
    const contentTrimmed = sbomContent.trim();

    if (!idTrimmed) {
      setErrorMsg('SBOM ID is required.');
      return;
    }
    if (!contentTrimmed) {
      setErrorMsg('Please select an SBOM file.');
      return;
    }

    setLoading(true);
    try {
      const verifyPromise = axios.post(
        `${API_BASE_URL}/verify`,
        { sbomID: idTrimmed, sbom: contentTrimmed },
        { headers: { 'x-user-id': selectedIdentity.userId, 'x-user-role': selectedIdentity.role } }
      );
      
      const evidencePromise = fetchEvidence(idTrimmed, selectedIdentity);

      const [verifyResp] = await Promise.allSettled([verifyPromise, evidencePromise]);

      if (verifyResp.status === 'fulfilled') {
        setResult(verifyResp.value.data.verification);
        if (verifyResp.value.data.performanceMetrics) {
          setPerfMetrics(verifyResp.value.data.performanceMetrics);
        }
      } else {
        const err = verifyResp.reason;
        setErrorMsg(err.response?.data?.error || err.response?.data?.message || err.message || 'Verification failed');
      }
    } finally {
      setLoading(false);
    }
  };

  const getLedgerStatusColor = (status) => {
    if (status === 'REGISTERED') return 'default';
    if (status === 'REVIEW_PENDING') return 'orange';
    if (status === 'SECURITY_REVIEWED') return 'cyan';
    if (status === 'COMPLIANT') return 'geekblue';
    if (status === 'APPROVED') return 'blue';
    if (status === 'ACTIVE') return 'green';
    if (status === 'SUPERSEDED') return 'red';
    if (status === 'REJECTED') return 'red';
    return 'default';
  };

  // Authoritative four-state trust-decision color helper (TPSR v3 enum remediation)
  const getTrustColor = (ts) => {
    if (ts === 'TRUSTED')               return 'green';
    if (ts === 'CONDITIONALLY_ACCEPTED') return 'blue';
    if (ts === 'REVIEW_REQUIRED')        return 'orange';
    if (ts === 'REJECTED')               return 'red';
    if (ts === 'UNTRUSTED')              return 'red'; // legacy read-compatibility
    return 'default';
  };
  const getTrustLabel = (ts) => ts === 'UNTRUSTED' ? 'REJECTED (legacy)' : (ts || 'UNEVALUATED');


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
            <div style={{ marginBottom: 8 }}><Text strong>SBOM File</Text></div>
            <Upload
              beforeUpload={handleBeforeUpload}
              showUploadList={false}
              accept=".json,.xml,.spdx,.cdx,.txt"
              maxCount={1}
            >
              <Button disabled={fileReading}>
                {fileReading ? 'Reading file...' : (selectedFile ? 'Replace Local SBOM File' : 'Select Local SBOM File')}
              </Button>
            </Upload>
            {selectedFile && (
              <Alert 
                style={{ marginTop: 8 }}
                type="info"
                message={<Text strong>{selectedFile.name}</Text>}
                description={`Size: ${(selectedFile.size / 1024).toFixed(2)} KB | Status: Loaded`}
                showIcon
                action={
                  <Button size="small" danger onClick={handleRemoveFile}>
                    Remove
                  </Button>
                }
              />
            )}
          </div>

          <Button 
            type="primary" 
            onClick={handleVerify} 
            loading={loading}
            disabled={!sbomID.trim() || !sbomContent || fileReading}
          >
            Verify Integrity
          </Button>
        </Space>
      </Card>

      <EvidenceApiDiagnostics diagnostics={diagnostics} />
      {evidenceError && <Alert type="error" showIcon message={evidenceError} style={{marginBottom: 16}} />}
      {result && (
        <Card title="Verification Result" size="small">
          {anchorDoc && (
            <>
              <Alert
                message={<Text strong>Trust Governance Status: {getTrustLabel(anchorDoc.trustStatus)}</Text>}
                description={`Reason Code ${anchorDoc.trustReasonCode}: ${anchorDoc.trustReasonDescription}`}
                type={anchorDoc.trustStatus === 'TRUSTED' ? 'success' : (anchorDoc.trustStatus === 'REJECTED' || anchorDoc.trustStatus === 'UNTRUSTED') ? 'error' : 'warning'}
                showIcon
                style={{ marginBottom: 16 }}
              />
              <Row gutter={16} style={{ marginBottom: 16 }}>
                <Col span={6}>
                  <Card size="small">
                    <Typography.Text type="secondary">Integrity Match</Typography.Text>
                    <Typography.Title level={5} style={{ margin: 0, color: result.match ? '#52c41a' : '#ff4d4f' }}>
                      {result.match ? 'MATCH ✓' : 'MISMATCH ✗'}
                    </Typography.Title>
                  </Card>
                </Col>
                <Col span={6}>
                  <Card size="small">
                    <Typography.Text type="secondary">Lifecycle State</Typography.Text>
                    <Typography.Title level={5} style={{ margin: 0 }}>
                      <AnchorStatusBadge status={result.status} />
                    </Typography.Title>
                  </Card>
                </Col>
                <Col span={6}>
                  <Card size="small">
                    <Typography.Text type="secondary">Trust Decision</Typography.Text>
                    <Typography.Title level={5} style={{ margin: 0 }}>
                      <TrustDecisionBadge status={anchorDoc.trustStatus} reasonCode={anchorDoc.trustReasonCode} reasonDesc={anchorDoc.trustReasonDescription} />
                    </Typography.Title>
                  </Card>
                </Col>
                <Col span={6}>
                  <Card size="small">
                    <Typography.Text type="secondary">Policy Status</Typography.Text>
                    <Typography.Title level={5} style={{ margin: 0 }}>
                      <Space>
                        <Tag color={anchorDoc.policyStatus === 'PASS' ? 'success' : 'error'}>{anchorDoc.policyStatus || 'UNKNOWN'}</Tag>
                        {anchorDoc.policyVersion && <Tag color="purple">v{anchorDoc.policyVersion}</Tag>}
                      </Space>
                    </Typography.Title>
                  </Card>
                </Col>
              </Row>
            </>
          )}

          
          <SignatureEvidenceCard signatureData={signatureData} />
          <ProvenanceEvidenceCard provenanceData={provenanceData} />
          <ContextAssertionCard contextData={contextAssertionData} />
          {exceptionsData && exceptionsData.length > 0 && exceptionsData.map((exc) => (
             <PolicyExceptionCard key={exc.id} exceptionData={exc} />
          ))}
          
          <ContextRiskSummary 
            contextRisk={trustDecisionData?.contextRisk}
            originalVulnerabilities={trustDecisionData?.originalVulnerabilities || []}
            isSimulation={false}
          />

          <DecisionSnapshotCard 
            decisionData={trustDecisionData} 
            sbomId={result.sbomID} 
            identity={selectedIdentity} 
          />

          {anchorDoc && (
            <Card
              title="Ledger Anchor Proof"
              size="small"
              style={{ marginBottom: 16, borderColor: '#91caff', backgroundColor: '#e6f4ff' }}
            >
              <Descriptions column={1} bordered size="small">
                <Descriptions.Item label="Anchored Hash">
                  <Text code style={{ wordBreak: 'break-all' }}>{anchorDoc.sbomHash || result.storedHash || '-'}</Text>
                </Descriptions.Item>
                <Descriptions.Item label="Submitted / Computed Hash">
                  <Text code style={{ wordBreak: 'break-all' }}>{result.submittedHash || '-'}</Text>
                </Descriptions.Item>
                <Descriptions.Item label="Hash Match">
                  <Tag color={result.match ? 'green' : 'red'}>{result.match ? 'MATCH ✓' : 'MISMATCH ✗'}</Tag>
                </Descriptions.Item>
                <Descriptions.Item label="Fabric Transaction ID">
                  <Text code style={{ wordBreak: 'break-all' }}>{anchorDoc.fabricTxID || '-'}</Text>
                </Descriptions.Item>
                <Descriptions.Item label="Anchored At">
                  {fmtISO(anchorDoc.anchoredAt)}
                </Descriptions.Item>
                <Descriptions.Item label="Recorded By">
                  <Text strong>{anchorDoc.recordedBy || '-'}</Text>
                </Descriptions.Item>
                <Descriptions.Item label="Ledger Identity">
                  <Tooltip title={anchorDoc.submitterID || 'N/A'}>
                    <Text code style={{ cursor: 'help' }}>{abbrevLedgerId(anchorDoc.submitterID)}</Text>
                  </Tooltip>
                </Descriptions.Item>
                <Descriptions.Item label="Lifecycle State">
                  <AnchorStatusBadge status={result.status} />
                </Descriptions.Item>
                <Descriptions.Item label="Trust Status">
                  <TrustDecisionBadge status={anchorDoc.trustStatus} reasonCode={anchorDoc.trustReasonCode} reasonDesc={anchorDoc.trustReasonDescription} />
                </Descriptions.Item>
              </Descriptions>
            </Card>
          )}

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

          {perfMetrics && (
            <Card
              title="Performance Metrics"
              size="small"
              style={{ marginTop: 16, borderColor: '#d9d9d9', backgroundColor: '#fafafa' }}
            >
              <Descriptions column={2} bordered size="small">
                {Object.entries(perfMetrics).map(([key, value]) => (
                  <Descriptions.Item key={key} label={key.replace(/([A-Z])/g, ' $1').replace(/^./, str => str.toUpperCase())}>
                    {value !== null ? `${value} ms` : 'N/A'}
                  </Descriptions.Item>
                ))}
              </Descriptions>
            </Card>
          )}

          {result.match === false && (
            <div style={{ marginTop: 24 }}>
              <Title level={4}>Integrity Failure Analysis</Title>

              {result.integrityFailureReason && (
                <Alert
                  style={{ marginBottom: 16 }}
                  type="error"
                  showIcon
                  message="Why Integrity Failed"
                  description={result.integrityFailureReason}
                />
              )}

              {result.tamperDetected && (
                <div style={{ marginBottom: 16 }}>
                  <Text strong>Primary Tamper Classification: </Text>
                  <Tag color="volcano">{result.tamperType}</Tag>
                </div>
              )}

              {result.tamperReport && result.tamperReport.summary && (
                <Alert message={result.tamperReport.summary} type="warning" showIcon style={{ marginBottom: 16 }} />
              )}

              {result.affectedComponents && result.affectedComponents.length > 0 && (
                <>
                  <Text strong style={{ display: 'block', marginBottom: 8 }}>Changed Components</Text>
                  <Table
                    dataSource={result.affectedComponents}
                    rowKey={(record, idx) => record.component + idx}
                    pagination={false}
                    size="small"
                    bordered
                    style={{ marginBottom: 16 }}
                    columns={[
                      { title: 'Component', dataIndex: 'component', key: 'component' },
                      { title: 'Original Version', dataIndex: 'originalVersion', key: 'originalVersion', render: t => t || '-' },
                      { title: 'Modified Version', dataIndex: 'modifiedVersion', key: 'modifiedVersion', render: t => t || '-' },
                      {
                        title: 'Change',
                        dataIndex: 'status',
                        key: 'status',
                        render: status => {
                          let color = 'default';
                          if (status === 'Added') color = 'red';
                          if (status === 'Removed') color = 'volcano';
                          if (status === 'Modified') color = 'orange';
                          return <Tag color={color}>{status}</Tag>;
                        }
                      }
                    ]}
                  />
                </>
              )}

              {result.changedFields && result.changedFields.length > 0 && (
                <>
                  <Text strong style={{ display: 'block', marginBottom: 8 }}>Changed Metadata Fields</Text>
                  <Table
                    dataSource={result.changedFields}
                    rowKey={(record, idx) => record.fieldPath + idx}
                    pagination={false}
                    size="small"
                    bordered
                    style={{ marginBottom: 16 }}
                    columns={[
                      { title: 'Field Path', dataIndex: 'fieldPath', key: 'fieldPath' },
                      { title: 'Original Value', dataIndex: 'originalValue', key: 'originalValue', render: t => t !== null ? t : '-' },
                      { title: 'Modified Value', dataIndex: 'modifiedValue', key: 'modifiedValue', render: t => t !== null ? t : '-' },
                      { title: 'Change Type', dataIndex: 'changeType', key: 'changeType', render: t => <Tag color="orange">{t}</Tag> }
                    ]}
                  />
                </>
              )}

              {result.submittedPolicySnapshot && (
                <Card title="Submitted SBOM Policy Evaluation" size="small" style={{ backgroundColor: '#fffbe6', borderColor: '#ffe58f' }}>
                  <Descriptions column={1} size="small" bordered>
                    <Descriptions.Item label="Policy Status">
                      <Tag color={result.submittedPolicySnapshot.policyStatus === 'PASS' ? 'success' : 'error'}>
                        {result.submittedPolicySnapshot.policyStatus}
                      </Tag>
                    </Descriptions.Item>
                    <Descriptions.Item label="Reason">
                      {result.submittedPolicySnapshot.policyReason}
                    </Descriptions.Item>
                    {result.submittedPolicySnapshot.policyTamperNote && (
                      <Descriptions.Item label="Tamper + Policy Link">
                        <Text type="danger">{result.submittedPolicySnapshot.policyTamperNote}</Text>
                      </Descriptions.Item>
                    )}
                    {result.submittedPolicySnapshot.policyViolations && result.submittedPolicySnapshot.policyViolations.length > 0 && (
                      <Descriptions.Item label="Violations">
                        <ul>
                          {result.submittedPolicySnapshot.policyViolations.map((v, idx) => (
                            <li key={idx}><Text type="danger">{v}</Text></li>
                          ))}
                        </ul>
                      </Descriptions.Item>
                    )}
                  </Descriptions>
                </Card>
              )}
            </div>
          )}
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
    {
      title: 'Fabric Tx ID',
      dataIndex: 'txID',
      key: 'txID',
      render: (txID) => txID
        ? <Tooltip title={txID}><Text code style={{ cursor: 'help' }}>{txID.slice(0, 16) + '...'}</Text></Tooltip>
        : '-'
    },
    {
      title: 'Anchored At',
      dataIndex: 'timestamp',
      key: 'timestamp',
      render: (ts) => fmtUnix(ts)
    },
    {
      title: 'Deleted',
      dataIndex: 'isDelete',
      key: 'isDelete',
      render: (isDel) => isDel ? <Tag color="red">Yes</Tag> : <Tag color="green">No</Tag>
    },
    {
      title: 'Lifecycle State',
      key: 'status',
      render: (_, item) => <AnchorStatusBadge status={item.record?.status} />
    },
    {
      title: 'Ledger Identity',
      key: 'submitterID',
      render: (_, item) => {
        const full = item.record?.submitterID || '';
        if (!full) return '-';
        return <Tooltip title={full}><Text code style={{ cursor: 'help' }}>{abbrevLedgerId(full)}</Text></Tooltip>;
      }
    },
    {
      title: 'Build ID',
      key: 'buildID',
      render: (_, item) => item.record?.buildID || '-'
    },
    {
      title: 'Trust Decision',
      key: 'trustStatus',
      render: (_, item) => <TrustDecisionBadge status={item.record?.trustStatus || item.record?.trust_status} reasonCode={item.record?.trustReasonCode} reasonDesc={item.record?.trustReasonDescription} />
    },
    {
      title: 'Outbox Anchor Status',
      key: 'outboxStatus',
      render: (_, item) => {
        const os = item.record?.outboxStatus || item.record?.outbox_status || (item.txID ? 'COMPLETED' : 'PENDING');
        let color = 'default';
        if (os === 'COMPLETED') color = 'geekblue';
        if (os === 'FAILED') color = 'red';
        if (os === 'PROCESSING') color = 'blue';
        return <Tag color={color}>{os}</Tag>;
      }
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
              pagination={{ defaultPageSize: 10, showSizeChanger: true, pageSizeOptions: ['10', '20', '50', '100', '200'] }}
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
  const [selectedFile, setSelectedFile] = useState(null);
  const [fileReading, setFileReading] = useState(false);
  const [errorMsg, setErrorMsg] = useState('');
  const [loading, setLoading] = useState(false);
  const [report, setReport] = useState(null);
  const [perfMetrics, setPerfMetrics] = useState(null);
  const [simEnv, setSimEnv] = useState('PROD');
  const [simExposure, setSimExposure] = useState('INTERNAL');
  const [simVex, setSimVex] = useState('NONE');
  const [simResult, setSimResult] = useState(null);
  const [simLoading, setSimLoading] = useState(false);

  const {
    loading: evidenceLoading,
    error: evidenceError,
    documentData: anchorDoc,
    vexData,
    contextAssertionData,
    exceptionsData,
    trustDecisionData,
    diagnostics,
    fetchEvidence,
    reset: resetEvidence
  } = useSbomEvidence();

  const handleBeforeUpload = (file) => {
    setErrorMsg('');
    setSelectedFile(null);
    setSbomContent('');

    const allowedExtensions = ['.json', '.xml', '.spdx', '.cdx', '.txt'];
    const ext = file.name.slice((Math.max(0, file.name.lastIndexOf(".")) || Infinity)).toLowerCase();
    
    if (!allowedExtensions.includes(ext)) {
      setErrorMsg(`Invalid file type. Allowed: ${allowedExtensions.join(', ')}`);
      return false;
    }

    if (file.size === 0) {
      setErrorMsg('Selected SBOM file is empty.');
      return false;
    }

    setFileReading(true);
    const reader = new FileReader();
    reader.onload = (e) => {
      const content = e.target.result;
      if (!content || content.trim() === '') {
        setErrorMsg('Selected SBOM file is empty or could not be read as text.');
        setFileReading(false);
        return;
      }
      setSbomContent(content);
      setSelectedFile(file);
      setFileReading(false);
    };
    reader.onerror = () => {
      setErrorMsg('Failed to read selected SBOM file.');
      setFileReading(false);
    };
    reader.readAsText(file);
    return false;
  };

  const handleRemoveFile = () => {
    setSelectedFile(null);
    setSbomContent('');
    setErrorMsg('');
    setReport(null);
    setPerfMetrics(null);
    resetEvidence();
  };

  const handleGenerate = async () => {
    setErrorMsg('');
    setReport(null);
    resetEvidence();

    const idTrimmed = sbomID.trim();
    const contentTrimmed = sbomContent.trim();

    if (!idTrimmed) {
      setErrorMsg('SBOM ID is required.');
      return;
    }
    if (!contentTrimmed) {
      setErrorMsg('Please select an SBOM file.');
      return;
    }

    setLoading(true);
    try {
      const reportPromise = axios.post(
        `${API_BASE_URL}/compliance-report`,
        { sbomID: idTrimmed, sbom: contentTrimmed },
        { headers: { 'x-user-id': selectedIdentity.userId, 'x-user-role': selectedIdentity.role } }
      );
      const evidencePromise = fetchEvidence(idTrimmed, selectedIdentity);

      const [reportResp] = await Promise.allSettled([reportPromise, evidencePromise]);

      if (reportResp.status === 'fulfilled') {
        setReport(reportResp.value.data.report);
        if (reportResp.value.data.performanceMetrics) {
          setPerfMetrics(reportResp.value.data.performanceMetrics);
        }
      } else {
        const err = reportResp.reason;
        setErrorMsg(err.response?.data?.error || err.response?.data?.message || err.message || 'Compliance report generation failed');
      }
    } finally {
      setLoading(false);
    }
  };

  const handleSimulate = async () => {
    setSimLoading(true);
    setSimResult(null);
    try {
      let simulatedStatus = 'TRUSTED';
      let simulatedReasonCode = 'GOV-001';
      let simulatedReasonDesc = 'All provenance, signature, VEX, and deployment context checks passed.';
      
      if (simEnv === 'PROD_CRITICAL' && simExposure === 'PUBLIC' && simVex !== 'RESOLVED') {
        simulatedStatus = 'REJECTED';
        simulatedReasonCode = 'CTX-003';
        simulatedReasonDesc = 'Critical deployment environment prohibits public network exposure without approved VEX resolution.';
      } else if (simVex === 'AFFECTED') {
        simulatedStatus = 'REJECTED';
        simulatedReasonCode = 'VEX-002';
        simulatedReasonDesc = 'Active VEX statement indicates vulnerability affects deployment target.';
      } else if (simVex === 'RESOLVED') {
        simulatedStatus = 'CONDITIONALLY_ACCEPTED';
        simulatedReasonCode = 'EXC-001';
        simulatedReasonDesc = 'Policy exception or VEX statement mitigates underlying risk score. Trust is conditionally accepted.';
      }

      setSimResult({
        status: simulatedStatus,
        reasonCode: simulatedReasonCode,
        reasonDescription: simulatedReasonDesc,
        simulatedAt: new Date().toISOString()
      });
    } finally {
      setSimLoading(false);
    }
  };

  const getLedgerStatusColor = (status) => {
    if (status === 'REGISTERED') return 'default';
    if (status === 'REVIEW_PENDING') return 'orange';
    if (status === 'SECURITY_REVIEWED') return 'cyan';
    if (status === 'COMPLIANT') return 'geekblue';
    if (status === 'APPROVED') return 'blue';
    if (status === 'ACTIVE') return 'green';
    if (status === 'SUPERSEDED') return 'red';
    if (status === 'REJECTED') return 'red';
    return 'default';
  };

  // Authoritative four-state trust-decision color helper (TPSR v3 enum remediation)
  const getTrustColor = (ts) => {
    if (ts === 'TRUSTED')               return 'green';
    if (ts === 'CONDITIONALLY_ACCEPTED') return 'blue';
    if (ts === 'REVIEW_REQUIRED')        return 'orange';
    if (ts === 'REJECTED')               return 'red';
    if (ts === 'UNTRUSTED')              return 'red'; // legacy read-compatibility
    return 'default';
  };
  const getTrustLabel = (ts) => ts === 'UNTRUSTED' ? 'REJECTED (legacy)' : (ts || 'UNEVALUATED');


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
            <div style={{ marginBottom: 8 }}><Text strong>SBOM File</Text></div>
            <Upload
              beforeUpload={handleBeforeUpload}
              showUploadList={false}
              accept=".json,.xml,.spdx,.cdx,.txt"
              maxCount={1}
            >
              <Button disabled={fileReading}>
                {fileReading ? 'Reading file...' : (selectedFile ? 'Replace Local SBOM File' : 'Select Local SBOM File')}
              </Button>
            </Upload>
            {selectedFile && (
              <Alert 
                style={{ marginTop: 8 }}
                type="info"
                message={<Text strong>{selectedFile.name}</Text>}
                description={`Size: ${(selectedFile.size / 1024).toFixed(2)} KB | Status: Loaded`}
                showIcon
                action={
                  <Button size="small" danger onClick={handleRemoveFile}>
                    Remove
                  </Button>
                }
              />
            )}
          </div>

          <Button 
            type="primary" 
            onClick={handleGenerate} 
            loading={loading}
            disabled={!sbomID.trim() || !sbomContent || fileReading}
          >
            Generate Compliance Report
          </Button>
        </Space>
      </Card>

      <EvidenceApiDiagnostics diagnostics={diagnostics} />
      {evidenceError && <Alert type="error" showIcon message={evidenceError} style={{marginBottom: 16}} />}
      {report && (
        <Card title="Compliance Report Result" size="small">
          {anchorDoc && (
            <>
              <Alert
                message={<Text strong>Trust Governance Status: {getTrustLabel(anchorDoc.trustStatus)}</Text>}
                description={`Reason Code ${anchorDoc.trustReasonCode}: ${anchorDoc.trustReasonDescription}`}
                type={anchorDoc.trustStatus === 'TRUSTED' ? 'success' : (anchorDoc.trustStatus === 'REJECTED' || anchorDoc.trustStatus === 'UNTRUSTED') ? 'error' : 'warning'}
                showIcon
                style={{ marginBottom: 16 }}
              />
              <Row gutter={16} style={{ marginBottom: 16 }}>
                <Col span={6}>
                  <Card size="small">
                    <Typography.Text type="secondary">Integrity Match</Typography.Text>
                    <Typography.Title level={5} style={{ margin: 0, color: report.integrityMatch ? '#52c41a' : '#ff4d4f' }}>
                      {report.integrityMatch ? 'MATCH ✓' : 'MISMATCH ✗'}
                    </Typography.Title>
                  </Card>
                </Col>
                <Col span={6}>
                  <Card size="small">
                    <Typography.Text type="secondary">Lifecycle State</Typography.Text>
                    <Typography.Title level={5} style={{ margin: 0 }}>
                      <AnchorStatusBadge status={report.lifecycleState} />
                    </Typography.Title>
                  </Card>
                </Col>
                <Col span={6}>
                  <Card size="small">
                    <Typography.Text type="secondary">Trust Decision</Typography.Text>
                    <Typography.Title level={5} style={{ margin: 0 }}>
                      <TrustDecisionBadge status={anchorDoc.trustStatus} reasonCode={anchorDoc.trustReasonCode} reasonDesc={anchorDoc.trustReasonDescription} />
                    </Typography.Title>
                  </Card>
                </Col>
                <Col span={6}>
                  <Card size="small">
                    <Typography.Text type="secondary">Policy Status</Typography.Text>
                    <Typography.Title level={5} style={{ margin: 0 }}>
                      <Tag color={report.policyStatus === 'PASS' ? 'success' : 'error'}>{report.policyStatus || 'UNKNOWN'}</Tag>
                    </Typography.Title>
                  </Card>
                </Col>
              </Row>
              <Card title="What-If Trust & Policy Simulator" size="small" style={{ marginBottom: 16, backgroundColor: '#f6ffed', borderColor: '#b7eb8f' }}>
                <SimulationNotice />
                <Space direction="vertical" style={{ width: '100%' }}>
                  <Text type="secondary">Test how changing deployment context or VEX overlays affects TPSR v3 trust evaluation for this SBOM:</Text>
                  <Space wrap>
                    <div>
                      <Text strong style={{ marginRight: 8 }}>Environment:</Text>
                      <Select value={simEnv} onChange={setSimEnv} style={{ width: 150 }} options={[
                        { value: 'DEV', label: 'DEV' },
                        { value: 'STAGING', label: 'STAGING' },
                        { value: 'PROD', label: 'PROD' },
                        { value: 'PROD_CRITICAL', label: 'PROD_CRITICAL' }
                      ]} />
                    </div>
                    <div>
                      <Text strong style={{ marginRight: 8 }}>Network Exposure:</Text>
                      <Select value={simExposure} onChange={setSimExposure} style={{ width: 140 }} options={[
                        { value: 'INTERNAL', label: 'INTERNAL' },
                        { value: 'PUBLIC', label: 'PUBLIC' }
                      ]} />
                    </div>
                    <div>
                      <Text strong style={{ marginRight: 8 }}>Simulate VEX:</Text>
                      <Select value={simVex} onChange={setSimVex} style={{ width: 160 }} options={[
                        { value: 'NONE', label: 'None (Default)' },
                        { value: 'RESOLVED', label: 'Apply RESOLVED' },
                        { value: 'AFFECTED', label: 'Apply AFFECTED' }
                      ]} />
                    </div>
                    <Button type="primary" onClick={handleSimulate} loading={simLoading}>Simulate Decision</Button>
                  </Space>
                  {simResult && (
                    <Alert
                      style={{ marginTop: 12 }}
                      type={simResult.status === 'TRUSTED' ? 'success' : 'error'}
                      message={`Simulated Outcome: ${simResult.status} (${simResult.reasonCode})`}
                      description={simResult.reasonDescription}
                      showIcon
                    />
                  )}
                </Space>
              </Card>
            </>
          )}

          {anchorDoc && (
            <Card
              title="Anchor & Governance Evidence"
              size="small"
              style={{ marginBottom: 16, borderColor: '#91caff', backgroundColor: '#e6f4ff' }}
            >
              <Descriptions column={1} bordered size="small">
                <Descriptions.Item label="Recorded By">
                  <Text strong>{anchorDoc.recordedBy || '-'}</Text>
                </Descriptions.Item>
                <Descriptions.Item label="Ledger Identity">
                  <Tooltip title={anchorDoc.submitterID || 'N/A'}>
                    <Text code style={{ cursor: 'help' }}>{abbrevLedgerId(anchorDoc.submitterID)}</Text>
                  </Tooltip>
                </Descriptions.Item>
                <Descriptions.Item label="Anchored Hash">
                  <Text code style={{ wordBreak: 'break-all' }}>{anchorDoc.sbomHash || report.storedHash || '-'}</Text>
                </Descriptions.Item>
                <Descriptions.Item label="Submitted Hash">
                  <Text code style={{ wordBreak: 'break-all' }}>{report.computedHash || '-'}</Text>
                </Descriptions.Item>
                <Descriptions.Item label="Hash Match">
                  <Tag color={report.integrityMatch ? 'green' : 'red'}>{report.integrityMatch ? 'MATCH ✓' : 'MISMATCH ✗'}</Tag>
                </Descriptions.Item>
                <Descriptions.Item label="Fabric Transaction ID">
                  <Text code style={{ wordBreak: 'break-all' }}>{anchorDoc.fabricTxID || '-'}</Text>
                </Descriptions.Item>
                <Descriptions.Item label="Anchored At">
                  {fmtISO(anchorDoc.anchoredAt)}
                </Descriptions.Item>
                <Descriptions.Item label="Lifecycle State">
                  <AnchorStatusBadge status={report.lifecycleState} />
                </Descriptions.Item>
                <Descriptions.Item label="Off-chain SBOM Reference">
                  {anchorDoc.offChainRef || '-'}
                </Descriptions.Item>
              </Descriptions>
            </Card>
          )}

          {exceptionsData && exceptionsData.length > 0 && exceptionsData.map((exc) => (
             <PolicyExceptionCard key={exc.id} exceptionData={exc} />
          ))}

          {perfMetrics && (
            <Card
              title="Performance Metrics"
              size="small"
              style={{ marginTop: 16, borderColor: '#d9d9d9', backgroundColor: '#fafafa' }}
            >
              <Descriptions column={2} bordered size="small">
                {Object.entries(perfMetrics).map(([key, value]) => (
                  <Descriptions.Item key={key} label={key.replace(/([A-Z])/g, ' $1').replace(/^./, str => str.toUpperCase())}>
                    {value !== null ? `${value} ms` : 'N/A'}
                  </Descriptions.Item>
                ))}
              </Descriptions>
            </Card>
          )}

          {!report.compliant && report.nonComplianceReasons && report.nonComplianceReasons.length > 0 && (
            <Card
              title="Non-Compliance Reasons"
              size="small"
              style={{ marginBottom: 16, borderColor: '#ff4d4f', backgroundColor: '#fff2f0' }}
            >
              <Space direction="vertical" style={{ width: '100%' }}>
                {report.nonComplianceReasons.map((reason, idx) => (
                  <Tag color="error" key={idx} style={{ marginBottom: 4 }}>{reason}</Tag>
                ))}

                {report.integrityFailureReason && (
                  <Alert
                    type="error"
                    showIcon
                    message="Integrity Failure"
                    description={report.integrityFailureReason}
                    style={{ marginTop: 8 }}
                  />
                )}

                {report.tamperSummary && (
                  <Alert
                    type="warning"
                    showIcon
                    message="Tampering Summary"
                    description={report.tamperSummary}
                    style={{ marginTop: 8 }}
                  />
                )}

                {report.policyFailureReason && (
                  <Alert
                    type="warning"
                    showIcon
                    message="Policy Failure"
                    description={report.policyFailureReason}
                    style={{ marginTop: 8 }}
                  />
                )}

                {report.lifecycleFailureReason && (
                  <Alert
                    type="warning"
                    showIcon
                    message="Lifecycle State Not Eligible"
                    description={report.lifecycleFailureReason}
                    style={{ marginTop: 8 }}
                  />
                )}
              </Space>
            </Card>
          )}

          {report.affectedComponents && report.affectedComponents.length > 0 && (
            <>
              <Text strong style={{ display: 'block', marginBottom: 8 }}>Changed Components</Text>
              <Table
                dataSource={report.affectedComponents}
                rowKey={(record, idx) => record.component + idx}
                pagination={false}
                size="small"
                bordered
                style={{ marginBottom: 16 }}
                columns={[
                  { title: 'Component', dataIndex: 'component', key: 'component' },
                  { title: 'Original Version', dataIndex: 'originalVersion', key: 'originalVersion', render: t => t || '-' },
                  { title: 'Modified Version', dataIndex: 'modifiedVersion', key: 'modifiedVersion', render: t => t || '-' },
                  {
                    title: 'Change',
                    dataIndex: 'status',
                    key: 'status',
                    render: status => {
                      let color = 'default';
                      if (status === 'Added') color = 'red';
                      if (status === 'Removed') color = 'volcano';
                      if (status === 'Modified') color = 'orange';
                      return <Tag color={color}>{status}</Tag>;
                    }
                  }
                ]}
              />
            </>
          )}

          {report.changedFields && report.changedFields.length > 0 && (
            <>
              <Text strong style={{ display: 'block', marginBottom: 8 }}>Changed Metadata Fields</Text>
              <Table
                dataSource={report.changedFields}
                rowKey={(record, idx) => record.fieldPath + idx}
                pagination={false}
                size="small"
                bordered
                style={{ marginBottom: 16 }}
                columns={[
                  { title: 'Field Path', dataIndex: 'fieldPath', key: 'fieldPath' },
                  { title: 'Original Value', dataIndex: 'originalValue', key: 'originalValue', render: t => t !== null ? t : '-' },
                  { title: 'Modified Value', dataIndex: 'modifiedValue', key: 'modifiedValue', render: t => t !== null ? t : '-' },
                  { title: 'Change Type', dataIndex: 'changeType', key: 'changeType', render: t => <Tag color="orange">{t}</Tag> }
                ]}
              />
            </>
          )}

          
          <Card title="VEX Applicability Analysis" size="small" style={{ marginBottom: 16 }}>
            <VexApplicabilityTable vulnerabilities={vexData || report.vulnerabilities || []} />
          </Card>
          <Descriptions column={1} bordered size="small">
            <Descriptions.Item label="Compliance Status">
              <Tag color={report.compliant ? 'green' : 'red'}>
                {report.compliant ? 'COMPLIANT' : 'NON-COMPLIANT'}
              </Tag>
            </Descriptions.Item>
            <Descriptions.Item label="SBOM ID">
              <Text>{report.sbomID}</Text>
            </Descriptions.Item>
            <Descriptions.Item label="Lifecycle State">
              <Tag color={getLedgerStatusColor(report.lifecycleState)}>{report.lifecycleState || 'UNKNOWN'}</Tag>
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
              <AnchorStatusBadge status={report.ledgerStatus} />
            </Descriptions.Item>
            <Descriptions.Item label="Policy Governance Status">
              {report.policyStatus === 'PASS' ? (
                <Tag color="success">PASS</Tag>
              ) : (
                <Tag color="error">FAIL: {report.policyReason || 'Unknown policy failure'}</Tag>
              )}
            </Descriptions.Item>
            {report.policyViolations && report.policyViolations.length > 0 && (
              <Descriptions.Item label="Policy Violations">
                <ul>{report.policyViolations.map((v, i) => <li key={i}><Text type="danger">{v}</Text></li>)}</ul>
              </Descriptions.Item>
            )}
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
      key: '/submit',
      label: <Link to="/submit">Submit</Link>,
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
    <ConfigProvider
      theme={{
        token: {
          colorPrimary: '#1677ff',
          borderRadius: 4,
          fontFamily: "'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif"
        }
      }}
    >
      <Alert 
        message={<><strong style={{ letterSpacing: '0.5px' }}>LOW-ASSURANCE DEVELOPMENT SESSION</strong> - Production administration and cryptographic identities may be simulated or restricted.</>} 
        type="warning" 
        banner 
        showIcon 
        style={{ position: 'sticky', top: 0, zIndex: 1000, textAlign: 'center', background: '#fffbe6', borderBottom: '1px solid #ffe58f' }} 
      />
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
            <Route path="/submit" element={<SubmitPage selectedIdentity={selectedIdentity} />} />
            <Route path="/verify" element={<VerifyPage selectedIdentity={selectedIdentity} />} />
            <Route path="/history" element={<HistoryPage selectedIdentity={selectedIdentity} />} />
            <Route path="/compliance" element={<CompliancePage selectedIdentity={selectedIdentity} />} />
          </Routes>
        </Content>
      </Layout>
      </Layout>
    </ConfigProvider>
  );
}

export default App;
