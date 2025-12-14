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

// Styles
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
  // State
  const [step, setStep] = useState('upload');
  const [content, setContent] = useState('');
  const [findings, setFindings] = useState([]);
  const [summary, setSummary] = useState(null);
  const [selectedFindings, setSelectedFindings] = useState(new Set());
  const [projectKey, setProjectKey] = useState('');
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState(null);
  const [creationResults, setCreationResults] = useState(null);

  // Initialize - get project context
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

  // Parse findings
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
        setError('No findings detected. Try a different format or check your input.');
      } else {
        setError(result.error || 'Failed to parse findings');
      }
    } catch (e) {
      setError(`Parse error: ${e.message}`);
    } finally {
      setIsLoading(false);
    }
  }, [content]);

  // Toggle finding selection
  const toggleFinding = useCallback((id) => {
    setSelectedFindings(prev => {
      const next = new Set(prev);
      if (next.has(id)) {
        next.delete(id);
      } else {
        next.add(id);
      }
      return next;
    });
  }, []);

  // Select/deselect all
  const toggleAll = useCallback(() => {
    if (selectedFindings.size === findings.length) {
      setSelectedFindings(new Set());
    } else {
      setSelectedFindings(new Set(findings.map(f => f.id)));
    }
  }, [findings, selectedFindings]);

  // Create Jira issues
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

  // Reset
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
  const renderUploadStep = () => (
    <Stack space="space.200">
      <Box xcss={containerStyles}>
        <Stack space="space.150">
          <Heading as="h2">🔒 Security Findings Mapper</Heading>
          <Text>
            Paste security audit findings (SARIF, JSON, CSV, or plain text) to automatically create Jira issues with severity, CVSS scores, and CWE IDs.
          </Text>
        </Stack>
      </Box>

      {error && (
        <SectionMessage appearance="error" title="Error">
          <Text>{error}</Text>
        </SectionMessage>
      )}

      <Box xcss={containerStyles}>
        <Stack space="space.200">
          <Heading as="h3">📋 Paste Security Report</Heading>
          
          <Textfield
            name="content"
            value={content}
            onChange={(e) => { setContent(e.target.value); setError(null); }}
            placeholder="Paste your security findings here (SARIF JSON, Snyk JSON, Semgrep, CSV, or plain text)..."
            isMultiline
            minimumRows={10}
          />

          <Inline space="space.100">
            <Button
              appearance="primary"
              onClick={handleParse}
              isDisabled={isLoading || !content.trim()}
            >
              {isLoading ? 'Parsing...' : '🔍 Parse Findings'}
            </Button>
            
            <Button
              appearance="subtle"
              onClick={() => setContent('')}
              isDisabled={!content}
            >
              Clear
            </Button>
          </Inline>
        </Stack>
      </Box>

      <Box xcss={containerStyles}>
        <Stack space="space.100">
          <Text>Supported formats:</Text>
          <Inline space="space.050" shouldWrap>
            <Badge>SARIF</Badge>
            <Badge>Snyk</Badge>
            <Badge>Semgrep</Badge>
            <Badge>Trivy</Badge>
            <Badge>JSON</Badge>
            <Badge>CSV</Badge>
            <Badge>Plain Text</Badge>
          </Inline>
        </Stack>
      </Box>
    </Stack>
  );

  // PREVIEW STEP
  const renderPreviewStep = () => (
    <Stack space="space.200">
      <Box xcss={containerStyles}>
        <Inline spread="space-between" alignBlock="center">
          <Heading as="h2">📊 Parsed Findings</Heading>
          <Button appearance="subtle" onClick={handleReset}>← Back</Button>
        </Inline>
      </Box>

      {error && (
        <SectionMessage appearance="error" title="Error">
          <Text>{error}</Text>
        </SectionMessage>
      )}

      {/* Summary */}
      {summary && (
        <Inline space="space.100" shouldWrap>
          <Box xcss={statsCardStyles}>
            <Stack space="space.050" alignInline="center">
              <Text>{findings.length}</Text>
              <Text>Total</Text>
            </Stack>
          </Box>
          <Box xcss={statsCardStyles}>
            <Stack space="space.050" alignInline="center">
              <Lozenge appearance="removed">{summary.critical}</Lozenge>
              <Text>Critical</Text>
            </Stack>
          </Box>
          <Box xcss={statsCardStyles}>
            <Stack space="space.050" alignInline="center">
              <Lozenge appearance="removed">{summary.high}</Lozenge>
              <Text>High</Text>
            </Stack>
          </Box>
          <Box xcss={statsCardStyles}>
            <Stack space="space.050" alignInline="center">
              <Lozenge appearance="moved">{summary.medium}</Lozenge>
              <Text>Medium</Text>
            </Stack>
          </Box>
          <Box xcss={statsCardStyles}>
            <Stack space="space.050" alignInline="center">
              <Lozenge appearance="new">{summary.low}</Lozenge>
              <Text>Low</Text>
            </Stack>
          </Box>
        </Inline>
      )}

      {/* Project Key Input */}
      <Box xcss={containerStyles}>
        <Inline space="space.200" alignBlock="center">
          <Text>Project Key:</Text>
          <Textfield
            name="projectKey"
            value={projectKey}
            onChange={(e) => setProjectKey(e.target.value)}
            placeholder="e.g., SEC"
            width="small"
          />
          <Button appearance="subtle" onClick={toggleAll}>
            {selectedFindings.size === findings.length ? 'Deselect All' : 'Select All'}
          </Button>
        </Inline>
      </Box>

      {/* Findings List */}
      <Box xcss={containerStyles}>
        <Stack space="space.100">
          <Heading as="h4">📋 Findings ({selectedFindings.size} selected)</Heading>
          
          {findings.map((finding) => (
            <Box key={finding.id} xcss={findingCardStyles}>
              <Inline space="space.100" alignBlock="center">
                <Checkbox
                  isChecked={selectedFindings.has(finding.id)}
                  onChange={() => toggleFinding(finding.id)}
                  label=""
                />
                <Lozenge appearance={SEVERITY_LOZENGE[finding.severity] || 'default'}>
                  {finding.severity}
                </Lozenge>
                <Text>{finding.title.substring(0, 50)}{finding.title.length > 50 ? '...' : ''}</Text>
                {finding.cvssScore && <Badge>{finding.cvssScore.toFixed(1)}</Badge>}
                {finding.cweId && <Tag text={`CWE-${finding.cweId}`} />}
              </Inline>
            </Box>
          ))}
        </Stack>
      </Box>

      {/* Action Buttons */}
      <Inline space="space.100">
        <Button
          appearance="primary"
          onClick={handleCreateIssues}
          isDisabled={selectedFindings.size === 0 || !projectKey.trim()}
        >
          🚀 Create {selectedFindings.size} Issues
        </Button>
        <Button appearance="subtle" onClick={handleReset}>Cancel</Button>
      </Inline>
    </Stack>
  );

  // CREATING STEP
  const renderCreatingStep = () => (
    <Box xcss={containerStyles}>
      <Stack space="space.200" alignInline="center">
        <Spinner size="large" />
        <Heading as="h2">Creating Jira Issues...</Heading>
        <Text>Please wait while we create {selectedFindings.size} issues</Text>
      </Stack>
    </Box>
  );

  // DONE STEP
  const renderDoneStep = () => (
    <Stack space="space.200">
      <SectionMessage 
        appearance={creationResults?.failed?.length > 0 ? 'warning' : 'success'}
        title={creationResults?.failed?.length > 0 
          ? 'Completed with Errors' 
          : '✅ All Issues Created!'}
      >
        <Text>
          Created {creationResults?.created?.length || 0} issues
          {creationResults?.failed?.length > 0 && 
            ` (${creationResults.failed.length} failed)`}
        </Text>
      </SectionMessage>

      {/* Created Issues */}
      {creationResults?.created?.length > 0 && (
        <Box xcss={containerStyles}>
          <Stack space="space.100">
            <Heading as="h4">✅ Created Issues</Heading>
            {creationResults.created.map((issue) => (
              <Box key={issue.key} xcss={findingCardStyles}>
                <Inline space="space.100" alignBlock="center">
                  <Badge appearance="primary">{issue.key}</Badge>
                  <Lozenge appearance={SEVERITY_LOZENGE[issue.severity] || 'default'}>
                    {issue.severity}
                  </Lozenge>
                  <Text>{issue.title.substring(0, 40)}</Text>
                </Inline>
              </Box>
            ))}
          </Stack>
        </Box>
      )}

      {/* Failed Issues */}
      {creationResults?.failed?.length > 0 && (
        <Box xcss={containerStyles}>
          <Stack space="space.100">
            <Heading as="h4">❌ Failed</Heading>
            {creationResults.failed.map((item, idx) => (
              <SectionMessage key={idx} appearance="error">
                <Text>{item.title}: {JSON.stringify(item.error)}</Text>
              </SectionMessage>
            ))}
          </Stack>
        </Box>
      )}

      <Button appearance="primary" onClick={handleReset}>
        📋 Import More Findings
      </Button>
    </Stack>
  );

  return (
    <Box padding="space.200">
      {step === 'upload' && renderUploadStep()}
      {step === 'preview' && renderPreviewStep()}
      {step === 'creating' && renderCreatingStep()}
      {step === 'done' && renderDoneStep()}
    </Box>
  );
}

export const render = ForgeReconciler.render(
  <React.StrictMode>
    <App />
  </React.StrictMode>
);
