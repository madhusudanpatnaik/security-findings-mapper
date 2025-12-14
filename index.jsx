// Combined entry point for Forge app
// Exports both the UI render function and the resolver handler

import React, { useState, useEffect, useCallback } from 'react';
import ForgeReconciler, {
  Box,
  Heading,
  Text,
  Button,
  ButtonGroup,
  Stack,
  Inline,
  Badge,
  SectionMessage,
  Lozenge,
  Textfield,
  Checkbox,
  Spinner,
  Tag,
  xcss
} from '@forge/react';
import { invoke } from '@forge/bridge';
import Resolver from '@forge/resolver';
import api, { route } from '@forge/api';
import { parseSecurityFindings } from './src/parser';

// ============================================
// RESOLVER (Backend)
// ============================================

const resolver = new Resolver();

resolver.define('getProjectContext', async (req) => {
  const { context } = req;
  return {
    projectId: context.extension?.project?.id,
    projectKey: context.extension?.project?.key,
    issueKey: context.extension?.issue?.key,
  };
});

resolver.define('parseFindings', async (req) => {
  const { content, format, fileName } = req.payload;
  
  try {
    const findings = parseSecurityFindings(content, format);
    return {
      success: true,
      findings,
      fileName,
      totalCount: findings.length,
      summary: {
        critical: findings.filter(f => f.severity === 'CRITICAL').length,
        high: findings.filter(f => f.severity === 'HIGH').length,
        medium: findings.filter(f => f.severity === 'MEDIUM').length,
        low: findings.filter(f => f.severity === 'LOW').length,
        info: findings.filter(f => f.severity === 'INFO').length,
      }
    };
  } catch (error) {
    return {
      success: false,
      error: error.message,
      findings: []
    };
  }
});

resolver.define('createIssues', async (req) => {
  const { findings, projectKey, issueType = 'Bug' } = req.payload;
  
  const results = {
    created: [],
    failed: [],
    total: findings.length
  };

  const priorityMap = {
    'CRITICAL': 'Highest',
    'HIGH': 'High',
    'MEDIUM': 'Medium',
    'LOW': 'Low',
    'INFO': 'Lowest'
  };

  const dueDaysMap = {
    'CRITICAL': 3,
    'HIGH': 7,
    'MEDIUM': 14,
    'LOW': 30,
    'INFO': 90
  };

  for (const finding of findings) {
    try {
      const dueDate = new Date();
      dueDate.setDate(dueDate.getDate() + (dueDaysMap[finding.severity] || 30));

      const labels = ['security-finding', finding.severity.toLowerCase()];
      if (finding.cweId) labels.push(`cwe-${finding.cweId}`);
      if (finding.owaspCategory) labels.push(`owasp-${finding.owaspCategory.toLowerCase()}`);

      const issueData = {
        fields: {
          project: { key: projectKey },
          issuetype: { name: issueType },
          summary: `[${finding.severity}] ${finding.title}`.substring(0, 255),
          description: {
            version: 1,
            type: 'doc',
            content: [
              {
                type: 'paragraph',
                content: [
                  { type: 'text', text: `Severity: ${finding.severity}`, marks: [{ type: 'strong' }] },
                  { type: 'text', text: finding.cvssScore ? ` | CVSS: ${finding.cvssScore}` : '' },
                  { type: 'text', text: finding.cweId ? ` | CWE-${finding.cweId}` : '' }
                ]
              },
              {
                type: 'paragraph',
                content: [{ type: 'text', text: finding.description || 'No description provided.' }]
              },
              ...(finding.location ? [{
                type: 'paragraph',
                content: [
                  { type: 'text', text: 'Location: ', marks: [{ type: 'strong' }] },
                  { type: 'text', text: finding.location }
                ]
              }] : []),
              ...(finding.remediation ? [{
                type: 'paragraph',
                content: [
                  { type: 'text', text: 'Remediation: ', marks: [{ type: 'strong' }] },
                  { type: 'text', text: finding.remediation }
                ]
              }] : [])
            ]
          },
          labels: labels.slice(0, 10),
          priority: { name: priorityMap[finding.severity] || 'Medium' },
          duedate: dueDate.toISOString().split('T')[0]
        }
      };
      
      const response = await api.asUser().requestJira(
        route`/rest/api/3/issue`,
        {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(issueData),
        }
      );

      if (response.ok) {
        const data = await response.json();
        results.created.push({
          key: data.key,
          id: data.id,
          title: finding.title,
          severity: finding.severity
        });
      } else {
        const errorData = await response.json();
        results.failed.push({
          title: finding.title,
          error: errorData.errors || errorData.errorMessages || 'Unknown error'
        });
      }
    } catch (error) {
      results.failed.push({
        title: finding.title,
        error: error.message
      });
    }
  }

  return results;
});

export const handler = resolver.getDefinitions();

// ============================================
// UI COMPONENTS (Frontend)
// ============================================

const containerStyles = xcss({
  padding: 'space.300',
  backgroundColor: 'elevation.surface',
  borderRadius: 'border.radius.200',
  marginBottom: 'space.200',
});

const statsCardStyles = xcss({
  padding: 'space.200',
  backgroundColor: 'elevation.surface.raised',
  borderRadius: 'border.radius.100',
  minWidth: '80px',
});

const findingCardStyles = xcss({
  padding: 'space.150',
  backgroundColor: 'elevation.surface.sunken',
  borderRadius: 'border.radius.100',
  marginBottom: 'space.100',
});

const SEVERITY_LOZENGE = {
  CRITICAL: 'removed',
  HIGH: 'removed',
  MEDIUM: 'moved',
  LOW: 'new',
  INFO: 'default',
};

function App() {
  const [step, setStep] = useState('upload');
  const [content, setContent] = useState('');
  const [findings, setFindings] = useState([]);
  const [summary, setSummary] = useState(null);
  const [selectedFindings, setSelectedFindings] = useState(new Set());
  const [projectKey, setProjectKey] = useState('');
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState(null);
  const [creationResults, setCreationResults] = useState(null);

  useEffect(() => {
    async function init() {
      try {
        const ctx = await invoke('getProjectContext');
        if (ctx.projectKey) {
          setProjectKey(ctx.projectKey);
        }
      } catch (e) {
        console.error('Init error:', e);
      }
    }
    init();
  }, []);

  const handleParse = useCallback(async () => {
    if (!content.trim()) {
      setError('Please paste security findings content');
      return;
    }
    setIsLoading(true);
    setError(null);
    try {
      const result = await invoke('parseFindings', {
        content: content,
        format: 'auto',
        fileName: 'pasted-content'
      });
      if (result.success && result.findings.length > 0) {
        setFindings(result.findings);
        setSummary(result.summary);
        setSelectedFindings(new Set(result.findings.map(f => f.id)));
        setStep('preview');
      } else if (result.findings.length === 0) {
        setError('No findings detected. Try a different format.');
      } else {
        setError(result.error || 'Failed to parse findings');
      }
    } catch (e) {
      setError(`Parse error: ${e.message}`);
    } finally {
      setIsLoading(false);
    }
  }, [content]);

  const toggleFinding = useCallback((id) => {
    setSelectedFindings(prev => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  }, []);

  const toggleAll = useCallback(() => {
    if (selectedFindings.size === findings.length) {
      setSelectedFindings(new Set());
    } else {
      setSelectedFindings(new Set(findings.map(f => f.id)));
    }
  }, [findings, selectedFindings]);

  const handleCreateIssues = useCallback(async () => {
    const selected = findings.filter(f => selectedFindings.has(f.id));
    if (selected.length === 0) {
      setError('Please select at least one finding');
      return;
    }
    if (!projectKey.trim()) {
      setError('Please enter a project key');
      return;
    }
    setStep('creating');
    setError(null);
    try {
      const result = await invoke('createIssues', {
        findings: selected,
        projectKey: projectKey.toUpperCase(),
        issueType: 'Bug'
      });
      setCreationResults(result);
      setStep('done');
    } catch (e) {
      setError(`Creation error: ${e.message}`);
      setStep('preview');
    }
  }, [findings, selectedFindings, projectKey]);

  const handleReset = useCallback(() => {
    setStep('upload');
    setContent('');
    setFindings([]);
    setSummary(null);
    setSelectedFindings(new Set());
    setCreationResults(null);
    setError(null);
  }, []);

  // UPLOAD STEP
  if (step === 'upload') {
    return (
      <Box padding="space.200">
        <Stack space="space.200">
          <Box xcss={containerStyles}>
            <Stack space="space.150">
              <Heading as="h2">🔒 Security Findings Mapper</Heading>
              <Text>Paste security findings (SARIF, JSON, CSV, or text) to create Jira issues automatically.</Text>
            </Stack>
          </Box>
          {error && <SectionMessage appearance="error" title="Error"><Text>{error}</Text></SectionMessage>}
          <Box xcss={containerStyles}>
            <Stack space="space.200">
              <Heading as="h3">📋 Paste Security Report</Heading>
              <Textfield
                name="content"
                value={content}
                onChange={(e) => { setContent(e.target.value); setError(null); }}
                placeholder="Paste SARIF, JSON, CSV, or plain text findings here..."
                isMultiline
                minimumRows={10}
              />
              <Inline space="space.100">
                <Button appearance="primary" onClick={handleParse} isDisabled={isLoading || !content.trim()}>
                  {isLoading ? 'Parsing...' : '🔍 Parse Findings'}
                </Button>
                <Button appearance="subtle" onClick={() => setContent('')} isDisabled={!content}>Clear</Button>
              </Inline>
            </Stack>
          </Box>
          <Box xcss={containerStyles}>
            <Inline space="space.050" shouldWrap>
              <Badge>SARIF</Badge><Badge>Snyk</Badge><Badge>Semgrep</Badge><Badge>Trivy</Badge><Badge>CSV</Badge><Badge>Text</Badge>
            </Inline>
          </Box>
        </Stack>
      </Box>
    );
  }

  // PREVIEW STEP
  if (step === 'preview') {
    return (
      <Box padding="space.200">
        <Stack space="space.200">
          <Box xcss={containerStyles}>
            <Inline spread="space-between" alignBlock="center">
              <Heading as="h2">📊 Parsed Findings</Heading>
              <Button appearance="subtle" onClick={handleReset}>← Back</Button>
            </Inline>
          </Box>
          {error && <SectionMessage appearance="error" title="Error"><Text>{error}</Text></SectionMessage>}
          {summary && (
            <Inline space="space.100" shouldWrap>
              <Box xcss={statsCardStyles}><Stack alignInline="center"><Text>{findings.length}</Text><Text>Total</Text></Stack></Box>
              <Box xcss={statsCardStyles}><Stack alignInline="center"><Lozenge appearance="removed">{summary.critical}</Lozenge><Text>Critical</Text></Stack></Box>
              <Box xcss={statsCardStyles}><Stack alignInline="center"><Lozenge appearance="removed">{summary.high}</Lozenge><Text>High</Text></Stack></Box>
              <Box xcss={statsCardStyles}><Stack alignInline="center"><Lozenge appearance="moved">{summary.medium}</Lozenge><Text>Medium</Text></Stack></Box>
              <Box xcss={statsCardStyles}><Stack alignInline="center"><Lozenge appearance="new">{summary.low}</Lozenge><Text>Low</Text></Stack></Box>
            </Inline>
          )}
          <Box xcss={containerStyles}>
            <Inline space="space.200" alignBlock="center">
              <Text>Project:</Text>
              <Textfield name="projectKey" value={projectKey} onChange={(e) => setProjectKey(e.target.value)} placeholder="SEC" width="small" />
              <Button appearance="subtle" onClick={toggleAll}>{selectedFindings.size === findings.length ? 'Deselect All' : 'Select All'}</Button>
            </Inline>
          </Box>
          <Box xcss={containerStyles}>
            <Stack space="space.100">
              <Heading as="h4">📋 Findings ({selectedFindings.size} selected)</Heading>
              {findings.map((finding) => (
                <Box key={finding.id} xcss={findingCardStyles}>
                  <Inline space="space.100" alignBlock="center">
                    <Checkbox isChecked={selectedFindings.has(finding.id)} onChange={() => toggleFinding(finding.id)} label="" />
                    <Lozenge appearance={SEVERITY_LOZENGE[finding.severity] || 'default'}>{finding.severity}</Lozenge>
                    <Text>{finding.title.substring(0, 50)}{finding.title.length > 50 ? '...' : ''}</Text>
                    {finding.cvssScore && <Badge>{finding.cvssScore.toFixed(1)}</Badge>}
                    {finding.cweId && <Tag text={`CWE-${finding.cweId}`} />}
                  </Inline>
                </Box>
              ))}
            </Stack>
          </Box>
          <Inline space="space.100">
            <Button appearance="primary" onClick={handleCreateIssues} isDisabled={selectedFindings.size === 0 || !projectKey.trim()}>
              🚀 Create {selectedFindings.size} Issues
            </Button>
            <Button appearance="subtle" onClick={handleReset}>Cancel</Button>
          </Inline>
        </Stack>
      </Box>
    );
  }

  // CREATING STEP
  if (step === 'creating') {
    return (
      <Box padding="space.200">
        <Box xcss={containerStyles}>
          <Stack space="space.200" alignInline="center">
            <Spinner size="large" />
            <Heading as="h2">Creating Jira Issues...</Heading>
            <Text>Please wait...</Text>
          </Stack>
        </Box>
      </Box>
    );
  }

  // DONE STEP
  return (
    <Box padding="space.200">
      <Stack space="space.200">
        <SectionMessage appearance={creationResults?.failed?.length > 0 ? 'warning' : 'success'} title={creationResults?.failed?.length > 0 ? 'Completed with Errors' : '✅ All Issues Created!'}>
          <Text>Created {creationResults?.created?.length || 0} issues{creationResults?.failed?.length > 0 && ` (${creationResults.failed.length} failed)`}</Text>
        </SectionMessage>
        {creationResults?.created?.length > 0 && (
          <Box xcss={containerStyles}>
            <Stack space="space.100">
              <Heading as="h4">✅ Created Issues</Heading>
              {creationResults.created.map((issue) => (
                <Box key={issue.key} xcss={findingCardStyles}>
                  <Inline space="space.100" alignBlock="center">
                    <Badge appearance="primary">{issue.key}</Badge>
                    <Lozenge appearance={SEVERITY_LOZENGE[issue.severity] || 'default'}>{issue.severity}</Lozenge>
                    <Text>{issue.title.substring(0, 40)}</Text>
                  </Inline>
                </Box>
              ))}
            </Stack>
          </Box>
        )}
        <Button appearance="primary" onClick={handleReset}>📋 Import More</Button>
      </Stack>
    </Box>
  );
}

export const render = ForgeReconciler.render(
  <React.StrictMode>
    <App />
  </React.StrictMode>
);

