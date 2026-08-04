import re
import os

app_path = '/home/ng/Documents/tpsr_v2/dashboard/src/App.js'

with open(app_path, 'r') as f:
    content = f.read()

# Add imports
content = content.replace(
    "import { Link, Navigate, Route, Routes, useLocation } from 'react-router-dom';",
    "import { Link, Navigate, Route, Routes, useLocation } from 'react-router-dom';\nimport { useSbomEvidence } from './hooks/useSbomEvidence';\nimport { EvidenceApiDiagnostics } from './components';"
)

# Modify VerifyPage
verify_page_regex = r'function VerifyPage\(\{ selectedIdentity \}\) \{.*?\n\s*const getLedgerStatusColor'
def repl_verify(m):
    orig = m.group(0)
    # Replace state declarations
    new_state = """function VerifyPage({ selectedIdentity }) {
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
    diagnostics,
    fetchEvidence,
    reset: resetEvidence
  } = useSbomEvidence();"""
    
    s1 = re.sub(r'function VerifyPage\(\{ selectedIdentity \}\) \{.*?(?=const handleBeforeUpload =)', new_state + '\n\n  ', orig, flags=re.DOTALL)
    
    # Replace handleRemoveFile
    new_remove = """const handleRemoveFile = () => {
    setSelectedFile(null);
    setSbomContent('');
    setErrorMsg('');
    setResult(null);
    setPerfMetrics(null);
    resetEvidence();
  };"""
    s1 = re.sub(r'const handleRemoveFile = \(\) => \{.*?setProvenanceData\(null\);\n  \};', new_remove, s1, flags=re.DOTALL)
    
    # Replace handleVerify
    new_verify = """const handleVerify = async () => {
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
  };"""
    s1 = re.sub(r'const handleVerify = async \(\) => \{.*?finally \{\n      setLoading\(false\);\n    \}\n  \};', new_verify, s1, flags=re.DOTALL)
    
    return s1

content = re.sub(verify_page_regex, repl_verify, content, flags=re.DOTALL)

# Modify CompliancePage
compliance_page_regex = r'function CompliancePage\(\{ selectedIdentity \}\) \{.*?\n\s*const handleSimulate = async'
def repl_compliance(m):
    orig = m.group(0)
    new_state = """function CompliancePage({ selectedIdentity }) {
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
    diagnostics,
    fetchEvidence,
    reset: resetEvidence
  } = useSbomEvidence();"""
    s1 = re.sub(r'function CompliancePage\(\{ selectedIdentity \}\) \{.*?(?=const handleBeforeUpload =)', new_state + '\n\n  ', orig, flags=re.DOTALL)
    
    new_remove = """const handleRemoveFile = () => {
    setSelectedFile(null);
    setSbomContent('');
    setErrorMsg('');
    setReport(null);
    setPerfMetrics(null);
    resetEvidence();
  };"""
    s1 = re.sub(r'const handleRemoveFile = \(\) => \{.*?setProvenanceData\(null\);\n  \};', new_remove, s1, flags=re.DOTALL)
    
    new_generate = """const handleGenerate = async () => {
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
  };"""
    s1 = re.sub(r'const handleGenerate = async \(\) => \{.*?finally \{\n      setLoading\(false\);\n    \}\n  \};', new_generate, s1, flags=re.DOTALL)
    return s1

content = re.sub(compliance_page_regex, repl_compliance, content, flags=re.DOTALL)

# Add EvidenceApiDiagnostics render logic
content = content.replace('{result && (', '<EvidenceApiDiagnostics diagnostics={diagnostics} />\n      {evidenceError && <Alert type="error" showIcon message={evidenceError} style={{marginBottom: 16}} />}\n      {result && (')
content = content.replace('{report && (', '<EvidenceApiDiagnostics diagnostics={diagnostics} />\n      {evidenceError && <Alert type="error" showIcon message={evidenceError} style={{marginBottom: 16}} />}\n      {report && (')

# Also, update VexApplicabilityTable in CompliancePage to use vexData
content = content.replace(
    '<VexApplicabilityTable vulnerabilities={report.vulnerabilities || []} />',
    '<VexApplicabilityTable vulnerabilities={vexData || report.vulnerabilities || []} />'
)

with open(app_path, 'w') as f:
    f.write(content)
