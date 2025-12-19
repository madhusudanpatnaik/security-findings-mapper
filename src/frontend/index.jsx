import React, { useState, useEffect } from 'react';
import ForgeReconciler, { 
  Box, Text, Button, Stack, Inline, TextArea, Textfield, xcss, 
  Heading, Badge, ProgressBar, SectionMessage, Lozenge, Strong, Select,
  Checkbox, Toggle, Tabs, TabList, Tab, TabPanel, Link
} from '@forge/react';
import { invoke } from '@forge/bridge';

const UI_BUILD = '2025-12-18.1';

// ============================================================================
// STYLES
// ============================================================================
const pageContainerStyle = xcss({
  padding: 'space.400',
});

const shellStyle = xcss({
  padding: 'space.400',
  minHeight: '400px',
  maxWidth: '1100px',
  margin: '0 auto',
});

const headerStyle = xcss({
  padding: 'space.300',
  backgroundColor: 'color.background.discovery.bold',
  borderRadius: 'border.radius.300',
  marginBottom: 'space.200',
});

const cardStyle = xcss({
  padding: 'space.300',
  backgroundColor: 'elevation.surface.overlay',
  borderRadius: 'border.radius.200',
  borderWidth: 'border.width',
  borderStyle: 'solid',
  borderColor: 'color.border',
});

const findingCardStyle = xcss({
  padding: 'space.150',
  backgroundColor: 'color.background.neutral.subtle',
  borderRadius: 'border.radius.100',
  borderLeftWidth: 'border.width.indicator',
  borderLeftStyle: 'solid',
  borderLeftColor: 'color.border',
});

const selectedCardStyle = xcss({
  padding: 'space.150',
  backgroundColor: 'color.background.selected',
  borderRadius: 'border.radius.100',
  borderLeftWidth: 'border.width.indicator',
  borderLeftStyle: 'solid',
  borderLeftColor: 'color.border.selected',
});

const statsBoxStyle = xcss({
  padding: 'space.200',
  backgroundColor: 'elevation.surface.sunken',
  borderRadius: 'border.radius.100',
  textAlign: 'center',
  minWidth: '110px',
});

const filterSeverityColStyle = xcss({
  width: '220px',
});

const filterSearchColStyle = xcss({
  display: 'block',
  flexGrow: 1,
  minWidth: '260px',
});

const ruleCardStyle = xcss({
  padding: 'space.200',
  backgroundColor: 'color.background.neutral.subtle',
  borderRadius: 'border.radius.100',
  borderWidth: 'border.width',
  borderStyle: 'solid',
  borderColor: 'color.border',
});

// Severity helpers
const getSeverityAppearance = (severity) => ({
  'CRITICAL': 'removed',
  'HIGH': 'removed', 
  'MEDIUM': 'moved',
  'LOW': 'new',
  'INFO': 'default'
}[severity] || 'default');

// ============================================================================
// SLA DEFAULTS (in days)
// ============================================================================
const DEFAULT_SLA = {
  CRITICAL: 1,
  HIGH: 7,
  MEDIUM: 30,
  LOW: 90,
  INFO: 180
};

// ============================================================================
// MAIN APP
// ============================================================================
function App() {
  // Core state
  const [step, setStep] = useState('upload');
  const [content, setContent] = useState('');
  const [findings, setFindings] = useState([]);
  const [selectedFindings, setSelectedFindings] = useState(new Set());
  const [summary, setSummary] = useState({});
  const [projectKey, setProjectKey] = useState('');
  const [users, setUsers] = useState([]);
  const [isLoading, setIsLoading] = useState(false);
  const [progress, setProgress] = useState(0);
  const [message, setMessage] = useState('');
  const [messageType, setMessageType] = useState('info');
  const [results, setResults] = useState(null);
  
  // Advanced settings
  const [enableSLA, setEnableSLA] = useState(true);
  const [slaSettings, setSlaSettings] = useState(DEFAULT_SLA);
  const [enableAutoAssign, setEnableAutoAssign] = useState(false);
  const [assignmentRules, setAssignmentRules] = useState({
    CRITICAL: null,
    HIGH: null,
    MEDIUM: null,
    LOW: null,
    INFO: null
  });
  const [defaultAssignee, setDefaultAssignee] = useState(null);
  
  // Filtering
  const [severityFilter, setSeverityFilter] = useState('ALL');
  const [searchTerm, setSearchTerm] = useState('');

  // Initialize
  useEffect(() => {
    invoke('getProjectContext').then(ctx => {
      if (ctx?.projectKey) {
        setProjectKey(ctx.projectKey);
        invoke('getAssignableUsers', { projectKey: ctx.projectKey }).then(res => {
          if (res.success && res.users?.length > 0) {
            setUsers(res.users);
          }
        }).catch(() => {});
      }
    }).catch(() => {});
  }, []);

  const fetchUsers = async (pk) => {
    if (pk && pk.length >= 2) {
      const res = await invoke('getAssignableUsers', { projectKey: pk.toUpperCase() });
      if (res.success && res.users?.length > 0) {
        setUsers(res.users);
      }
    }
  };

  const showMessage = (msg, type = 'info') => {
    setMessage(msg);
    setMessageType(type);
  };

  // Filter findings
  const filteredFindings = findings.filter(f => {
    if (severityFilter !== 'ALL' && f.severity !== severityFilter) return false;
    if (searchTerm && !f.title.toLowerCase().includes(searchTerm.toLowerCase())) return false;
    return true;
  });

  // Selection helpers
  const toggleFinding = (index) => {
    const newSelected = new Set(selectedFindings);
    if (newSelected.has(index)) {
      newSelected.delete(index);
    } else {
      newSelected.add(index);
    }
    setSelectedFindings(newSelected);
  };

  const selectAll = () => {
    const indices = filteredFindings.map((_, i) => findings.indexOf(filteredFindings[i]));
    setSelectedFindings(new Set(indices));
  };

  const selectNone = () => setSelectedFindings(new Set());

  const selectBySeverity = (sev) => {
    const indices = findings
      .map((f, i) => f.severity === sev ? i : -1)
      .filter(i => i >= 0);
    setSelectedFindings(new Set(indices));
  };

  // Parse findings
  const handleParse = async () => {
    if (!content.trim()) { 
      showMessage('Please paste your security scan results first', 'warning'); 
      return; 
    }
    setIsLoading(true);
    setProgress(0.3);
    showMessage('');
    
    try {
      setProgress(0.6);
      const result = await invoke('parseFindings', { content, format: 'auto' });
      setProgress(1);
      
      if (result.success && result.findings.length > 0) {
        setFindings(result.findings);
        setSummary(result.summary || {});
        // Select all by default
        setSelectedFindings(new Set(result.findings.map((_, i) => i)));
        setStep('preview');
        showMessage(`Parsed ${result.findings.length} security findings`, 'success');
      } else { 
        showMessage(result.error || 'No findings detected. Check format.', 'warning'); 
      }
    } catch (e) { 
      showMessage('Parse error: ' + e.message, 'error'); 
    }
    setIsLoading(false);
    setProgress(0);
  };

  // Create issues
  const handleCreate = async () => {
    if (!projectKey.trim()) { 
      showMessage('Enter your Jira project key', 'warning'); 
      return; 
    }
    
    const selectedList = findings.filter((_, i) => selectedFindings.has(i));
    if (selectedList.length === 0) {
      showMessage('Select at least one finding', 'warning');
      return;
    }

    setIsLoading(true);
    setProgress(0.1);
    showMessage('Creating Jira issues...');
    
    try {
      // Build findings with assignment rules and SLA
      const enrichedFindings = selectedList.map(f => ({
        ...f,
        assigneeId: enableAutoAssign 
          ? (assignmentRules[f.severity]?.value || defaultAssignee?.value || null)
          : (defaultAssignee?.value || null),
        dueDate: enableSLA ? calculateDueDate(f.severity) : null
      }));

      const result = await invoke('createIssues', { 
        findings: enrichedFindings, 
        projectKey: projectKey.toUpperCase(),
        enableSLA,
        slaSettings
      });
      
      setProgress(1);
      setResults(result);
      setStep('done');
      
      const created = result.created?.length || 0;
      const updated = result.updated?.length || 0;
      if (created > 0 || updated > 0) {
        showMessage(`Created ${created}, updated ${updated} issues`, 'success');
      } else if (result.failed?.length > 0) {
        showMessage('Issues failed. Check errors.', 'error');
      }
    } catch (e) { 
      showMessage('Error: ' + e.message, 'error'); 
    }
    setIsLoading(false);
    setProgress(0);
  };

  const calculateDueDate = (severity) => {
    const days = slaSettings[severity] || 30;
    const date = new Date();
    date.setDate(date.getDate() + days);
    return date.toISOString().split('T')[0];
  };

  const reset = () => { 
    setStep('upload'); 
    setContent(''); 
    setFindings([]); 
    setSelectedFindings(new Set());
    setSummary({});
    setResults(null); 
    setMessage(''); 
    setProgress(0);
  };

  // =========================================================================
  // STEP 1: UPLOAD
  // =========================================================================
  if (step === 'upload') {
    return (
      <Box xcss={pageContainerStyle}>
        <Box xcss={shellStyle}>
          <Stack space="space.300">
            {/* Header */}
            <Box xcss={headerStyle}>
              <Stack space="space.100">
                <Inline alignBlock="center" space="space.100">
                  <Text color="color.text.inverse">🛡️</Text>
                  <Heading as="h2">
                    <Text color="color.text.inverse" weight="bold">Security Findings Mapper</Text>
                  </Heading>
                  <Badge appearance="primary">Advanced</Badge>
                </Inline>
                <Text color="color.text.inverse" size="small">
                  Import • Deduplicate • Auto-assign • Track SLA
                </Text>
                <Text color="color.text.inverse" size="small">
                  Build: {UI_BUILD}
                </Text>
              </Stack>
            </Box>

            {/* Progress */}
            <Inline space="space.200" alignBlock="center" spread="space-between">
              <Inline space="space.050" alignBlock="center">
                <Badge appearance="primary">1</Badge>
                <Text weight="bold">Upload</Text>
              </Inline>
              <Text color="color.text.subtlest">→</Text>
              <Inline space="space.050" alignBlock="center">
                <Badge>2</Badge>
                <Text color="color.text.subtlest">Configure</Text>
              </Inline>
              <Text color="color.text.subtlest">→</Text>
              <Inline space="space.050" alignBlock="center">
                <Badge>3</Badge>
                <Text color="color.text.subtlest">Results</Text>
              </Inline>
            </Inline>

            {message && (
              <SectionMessage appearance={messageType === 'error' ? 'error' : messageType === 'warning' ? 'warning' : messageType === 'success' ? 'success' : 'information'}>
                <Text>{message}</Text>
              </SectionMessage>
            )}

            {/* Input */}
            <Box xcss={cardStyle}>
              <Stack space="space.200">
                <Inline alignBlock="center" spread="space-between">
                  <Text weight="bold">Paste Security Scan Results</Text>
                  <Text size="small" color="color.text.subtlest">
                    SARIF • Snyk • Semgrep • Trivy • Burp • CSV • Text
                  </Text>
                </Inline>
                <TextArea 
                  name="input" 
                  value={content} 
                  onChange={(e) => setContent(e.target.value)} 
                  placeholder="Paste your security scan output here..."
                  minimumRows={10}
                />
                
                {isLoading && <ProgressBar value={progress} />}
                
                <Inline space="space.100">
                  <Button 
                    appearance="primary" 
                    onClick={handleParse} 
                    isDisabled={isLoading || !content.trim()}
                  >
                    {isLoading ? '⏳ Parsing...' : '🔍 Parse Findings'}
                  </Button>
                  <Button appearance="subtle" onClick={() => setContent('')}>Clear</Button>
                </Inline>
              </Stack>
            </Box>
          </Stack>
        </Box>
      </Box>
    );
  }

  // =========================================================================
  // STEP 2: PREVIEW & CONFIGURE
  // =========================================================================
  if (step === 'preview') {
    const userOptions = [
      { label: '— None —', value: '' },
      ...users.map(u => ({ label: u.displayName, value: u.accountId }))
    ];

    return (
      <Box xcss={pageContainerStyle}>
        <Box xcss={shellStyle}>
          <Stack space="space.250">
            {/* Header */}
            <Box xcss={headerStyle}>
              <Inline alignBlock="center" spread="space-between">
                <Inline alignBlock="center" space="space.100">
                  <Text color="color.text.inverse">🛡️</Text>
                  <Heading as="h3">
                    <Text color="color.text.inverse" weight="bold">Configure & Review</Text>
                  </Heading>
                </Inline>
                <Badge appearance="added">{findings.length} findings</Badge>
              </Inline>
              <Text color="color.text.inverse" size="small">Build: {UI_BUILD}</Text>
            </Box>

            {/* Progress */}
            <Inline space="space.200" alignBlock="center" spread="space-between">
              <Inline space="space.050" alignBlock="center">
                <Badge appearance="added">✓</Badge>
                <Text color="color.text.subtlest">Upload</Text>
              </Inline>
              <Text color="color.text.subtlest">→</Text>
              <Inline space="space.050" alignBlock="center">
                <Badge appearance="primary">2</Badge>
                <Text weight="bold">Configure</Text>
              </Inline>
              <Text color="color.text.subtlest">→</Text>
              <Inline space="space.050" alignBlock="center">
                <Badge>3</Badge>
                <Text color="color.text.subtlest">Results</Text>
              </Inline>
            </Inline>

            {/* Summary Stats */}
            <Box xcss={cardStyle}>
              <Inline space="space.150" rowSpace="space.150" alignBlock="center" shouldWrap>
                <Box xcss={statsBoxStyle}>
                  <Stack space="space.050" alignInline="center">
                    <Heading as="h3">{selectedFindings.size}</Heading>
                    <Text size="small">Selected</Text>
                  </Stack>
                </Box>
                {Object.entries(summary).filter(([, v]) => v > 0).map(([sev, count]) => {
                  const normalized = sev.toUpperCase();
                  return (
                    <Box xcss={statsBoxStyle} key={sev}>
                      <Stack space="space.050" alignInline="center">
                        <Heading as="h3">{count}</Heading>
                        <Lozenge appearance={getSeverityAppearance(normalized)}>
                          {normalized}
                        </Lozenge>
                      </Stack>
                    </Box>
                  );
                })}
              </Inline>
            </Box>

            {/* Tabs: Findings | Settings */}
            <Tabs id="config-tabs">
              <TabList>
                <Tab>📋 Findings ({selectedFindings.size}/{findings.length})</Tab>
                <Tab>👤 Assignment</Tab>
                <Tab>⏰ SLA</Tab>
              </TabList>

              {/* TAB: Findings */}
              <TabPanel>
                <Stack space="space.300">
                  {/* Filters Card */}
                  <Box xcss={cardStyle}>
                    <Stack space="space.200">
                      {/* Header Row */}
                      <Inline spread="space-between" alignBlock="center" shouldWrap rowSpace="space.150">
                        <Text weight="bold">🔍 Filter & Select</Text>
                        {/* Keep buttons together; let the whole group wrap to next row if needed */}
                        <Inline space="space.100" alignBlock="center">
                          <Button appearance="primary" spacing="compact" onClick={selectAll}>
                            ✓ Select All
                          </Button>
                          <Button appearance="subtle" spacing="compact" onClick={selectNone}>
                            Clear
                          </Button>
                        </Inline>
                      </Inline>
                      
                      {/* Filter Controls Row */}
                      <Box xcss={ruleCardStyle}>
                        <Inline space="space.200" rowSpace="space.150" alignBlock="start" shouldWrap>
                          <Box xcss={filterSeverityColStyle}>
                            <Stack space="space.050">
                              <Text size="small" weight="bold">Severity</Text>
                              <Select
                                name="severity-filter"
                                value={{ label: severityFilter, value: severityFilter }}
                                options={[
                                  { label: '🔘 ALL', value: 'ALL' },
                                  { label: '🔴 CRITICAL', value: 'CRITICAL' },
                                  { label: '🟠 HIGH', value: 'HIGH' },
                                  { label: '🟡 MEDIUM', value: 'MEDIUM' },
                                  { label: '🟢 LOW', value: 'LOW' },
                                  { label: '🔵 INFO', value: 'INFO' },
                                ]}
                                onChange={(opt) => setSeverityFilter(opt.value)}
                                spacing="compact"
                              />
                            </Stack>
                          </Box>
                          <Box xcss={filterSearchColStyle}>
                            <Stack space="space.050">
                              <Text size="small" weight="bold">Search</Text>
                              <Textfield
                                name="search"
                                value={searchTerm}
                                onChange={(e) => setSearchTerm(e.target.value)}
                                placeholder="Search titles..."
                                width="100%"
                              />
                            </Stack>
                          </Box>
                        </Inline>
                      </Box>
                      
                      {/* Quick Select Buttons */}
                      <Inline space="space.100" alignBlock="center" shouldWrap>
                        <Text size="small" color="color.text.subtlest">Quick select by severity:</Text>
                        <Button 
                          appearance="danger" 
                          spacing="compact"
                          onClick={() => selectBySeverity('CRITICAL')}
                        >
                          Critical
                        </Button>
                        <Button 
                          appearance="warning" 
                          spacing="compact"
                          onClick={() => selectBySeverity('HIGH')}
                        >
                          High
                        </Button>
                        <Button 
                          appearance="subtle" 
                          spacing="compact"
                          onClick={() => selectBySeverity('MEDIUM')}
                        >
                          Medium
                        </Button>
                        <Button 
                          appearance="subtle" 
                          spacing="compact"
                          onClick={() => selectBySeverity('LOW')}
                        >
                          Low
                        </Button>
                      </Inline>
                    </Stack>
                  </Box>

                  {/* Findings List */}
                  <Box xcss={cardStyle}>
                    <Stack space="space.150">
                      <Inline spread="space-between" alignBlock="center">
                        <Text weight="bold">📋 Findings</Text>
                        <Badge appearance="primary">{filteredFindings.length} shown</Badge>
                      </Inline>
                      
                      <Stack space="space.100">
                        {filteredFindings.slice(0, 15).map((f) => {
                          const realIndex = findings.indexOf(f);
                          const isSelected = selectedFindings.has(realIndex);
                          return (
                            <Box 
                              key={realIndex} 
                              xcss={isSelected ? selectedCardStyle : findingCardStyle}
                              onClick={() => toggleFinding(realIndex)}
                              style={{ cursor: 'pointer' }}
                            >
                              <Inline space="space.150" rowSpace="space.100" alignBlock="center" spread="space-between" shouldWrap>
                                <Inline space="space.150" alignBlock="center">
                                  <Checkbox 
                                    isChecked={isSelected}
                                    onChange={() => toggleFinding(realIndex)}
                                  />
                                  <Lozenge appearance={getSeverityAppearance(f.severity)}>
                                    {f.severity}
                                  </Lozenge>
                                  <Stack space="space.0">
                                    <Text size="small" weight={isSelected ? 'bold' : 'regular'}>
                                      {f.title?.substring(0, 55)}{f.title?.length > 55 ? '...' : ''}
                                    </Text>
                                    {f.filePath && (
                                      <Text size="small" color="color.text.subtlest">
                                        📁 {f.filePath?.substring(0, 40)}
                                      </Text>
                                    )}
                                  </Stack>
                                </Inline>
                                <Inline space="space.100" alignBlock="center">
                                  {f.cweId && (
                                    <Lozenge appearance="default">CWE-{f.cweId}</Lozenge>
                                  )}
                                </Inline>
                              </Inline>
                            </Box>
                          );
                        })}
                        {filteredFindings.length > 15 && (
                          <Box xcss={statsBoxStyle}>
                            <Text size="small" color="color.text.subtlest">
                              + {filteredFindings.length - 15} more findings (scroll or filter to see more)
                            </Text>
                          </Box>
                        )}
                        {filteredFindings.length === 0 && (
                          <Box xcss={statsBoxStyle}>
                            <Text color="color.text.subtlest">No findings match your filter criteria</Text>
                          </Box>
                        )}
                      </Stack>
                    </Stack>
                  </Box>
                </Stack>
              </TabPanel>

              {/* TAB: Assignment Rules */}
              <TabPanel>
                <Box xcss={cardStyle}>
                  <Stack space="space.200">
                    <Inline alignBlock="center" spread="space-between" shouldWrap>
                      <Stack space="space.050">
                        <Text weight="bold">Auto-Assignment by Severity</Text>
                        <Text size="small" color="color.text.subtlest">Assign different team members based on severity</Text>
                      </Stack>
                      <Toggle 
                        id="auto-assign" 
                        isChecked={enableAutoAssign} 
                        onChange={() => setEnableAutoAssign(!enableAutoAssign)} 
                      />
                    </Inline>

                    {enableAutoAssign && (
                      <Stack space="space.150">
                        {['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'].map(sev => (
                          <Box xcss={ruleCardStyle} key={sev}>
                            <Inline alignBlock="center" spread="space-between" shouldWrap>
                              <Inline space="space.100" alignBlock="center">
                                <Lozenge appearance={getSeverityAppearance(sev)}>{sev}</Lozenge>
                                <Text size="small">→ Assign to:</Text>
                              </Inline>
                              <Select
                                name={`assign-${sev}`}
                                value={assignmentRules[sev]}
                                options={userOptions}
                                onChange={(opt) => setAssignmentRules({...assignmentRules, [sev]: opt})}
                                placeholder="Select..."
                                spacing="compact"
                              />
                            </Inline>
                          </Box>
                        ))}
                      </Stack>
                    )}

                    <Stack space="space.100">
                      <Text weight="bold">Default Assignee</Text>
                      <Text size="small" color="color.text.subtlest">Used when no severity rule matches or auto-assign is off</Text>
                      <Select
                        name="default-assignee"
                        value={defaultAssignee}
                        options={userOptions}
                        onChange={setDefaultAssignee}
                        placeholder="Select default assignee..."
                        isClearable
                      />
                    </Stack>
                  </Stack>
                </Box>
              </TabPanel>

              {/* TAB: SLA Settings */}
              <TabPanel>
                <Box xcss={cardStyle}>
                  <Stack space="space.200">
                    <Inline alignBlock="center" spread="space-between" shouldWrap>
                      <Stack space="space.050">
                        <Text weight="bold">SLA Due Dates</Text>
                        <Text size="small" color="color.text.subtlest">Set due dates based on severity (days from now)</Text>
                      </Stack>
                      <Toggle 
                        id="enable-sla" 
                        isChecked={enableSLA} 
                        onChange={() => setEnableSLA(!enableSLA)} 
                      />
                    </Inline>

                    {enableSLA && (
                      <Stack space="space.150">
                        {[
                          { sev: 'CRITICAL', desc: 'Must fix immediately' },
                          { sev: 'HIGH', desc: 'Fix within a week' },
                          { sev: 'MEDIUM', desc: 'Fix within a month' },
                          { sev: 'LOW', desc: 'Fix when possible' },
                          { sev: 'INFO', desc: 'Informational only' }
                        ].map(({ sev, desc }) => (
                          <Box xcss={ruleCardStyle} key={sev}>
                            <Inline alignBlock="center" spread="space-between" shouldWrap>
                              <Inline space="space.100" alignBlock="center">
                                <Lozenge appearance={getSeverityAppearance(sev)}>{sev}</Lozenge>
                                <Text size="small" color="color.text.subtlest">{desc}</Text>
                              </Inline>
                              <Inline space="space.050" alignBlock="center">
                                <Textfield
                                  name={`sla-${sev}`}
                                  type="number"
                                  value={String(slaSettings[sev])}
                                  onChange={(e) => setSlaSettings({...slaSettings, [sev]: parseInt(e.target.value) || 1})}
                                  width="xsmall"
                                />
                                <Text size="small">days</Text>
                              </Inline>
                            </Inline>
                          </Box>
                        ))}
                      </Stack>
                    )}
                  </Stack>
                </Box>
              </TabPanel>
            </Tabs>

            {/* Project Key & Actions */}
            <Box xcss={cardStyle}>
              <Stack space="space.200">
                <Inline spread="space-between" alignBlock="center" shouldWrap>
                  <Inline space="space.150" alignBlock="center">
                    <Text weight="bold">🎯 Target Project:</Text>
                    <Textfield 
                      name="pk" 
                      value={projectKey} 
                      onChange={(e) => {
                        setProjectKey(e.target.value);
                        fetchUsers(e.target.value);
                      }} 
                      placeholder="Enter project key (e.g., PROJ)" 
                      width="medium"
                    />
                  </Inline>
                  <Inline space="space.100">
                    <Button appearance="subtle" onClick={reset}>← Back</Button>
                    <Button 
                      appearance="primary" 
                      onClick={handleCreate} 
                      isDisabled={isLoading || !projectKey.trim() || selectedFindings.size === 0}
                    >
                      {isLoading ? '⏳ Creating...' : `🚀 Create ${selectedFindings.size} Issues`}
                    </Button>
                  </Inline>
                </Inline>
                
                {isLoading && <ProgressBar value={progress} />}
                
                {message && (
                  <SectionMessage appearance={messageType === 'error' ? 'error' : messageType === 'success' ? 'success' : 'information'}>
                    <Text>{message}</Text>
                  </SectionMessage>
                )}
              </Stack>
            </Box>
          </Stack>
        </Box>
      </Box>
    );
  }

  // =========================================================================
  // STEP 3: RESULTS
  // =========================================================================
  return (
    <Box xcss={pageContainerStyle}>
      <Box xcss={shellStyle}>
        <Stack space="space.250">
          {/* Header */}
          <Box xcss={headerStyle}>
            <Inline alignBlock="center" space="space.100">
              <Text color="color.text.inverse">🛡️</Text>
              <Heading as="h2">
                <Text color="color.text.inverse" weight="bold">Results</Text>
              </Heading>
            </Inline>
            <Text color="color.text.inverse" size="small">Build: {UI_BUILD}</Text>
          </Box>

          {/* Progress */}
          <Inline space="space.200" alignBlock="center" spread="space-between">
            <Inline space="space.050" alignBlock="center">
              <Badge appearance="added">✓</Badge>
              <Text color="color.text.subtlest">Upload</Text>
            </Inline>
            <Text color="color.text.subtlest">→</Text>
            <Inline space="space.050" alignBlock="center">
              <Badge appearance="added">✓</Badge>
              <Text color="color.text.subtlest">Configure</Text>
            </Inline>
            <Text color="color.text.subtlest">→</Text>
            <Inline space="space.050" alignBlock="center">
              <Badge appearance="primary">3</Badge>
              <Text weight="bold">Results</Text>
            </Inline>
          </Inline>

          {/* Summary Message */}
          {(results?.created?.length > 0 || results?.updated?.length > 0) ? (
            <SectionMessage appearance="success">
              <Text>
                <Strong>🎉 Success!</Strong> Created {results.created?.length || 0} new issues
                {results.updated?.length > 0 && `, updated ${results.updated.length} existing`}
              </Text>
            </SectionMessage>
          ) : (
            <SectionMessage appearance="error">
              <Text>Issues could not be created. Check errors below.</Text>
            </SectionMessage>
          )}

          {/* Stats */}
          <Inline space="space.150" rowSpace="space.150" shouldWrap>
            <Box xcss={statsBoxStyle}>
              <Stack space="space.050" alignInline="center">
                <Text weight="bold" color="color.text.success">{results?.created?.length || 0}</Text>
                <Text size="small">Created</Text>
              </Stack>
            </Box>
            <Box xcss={statsBoxStyle}>
              <Stack space="space.050" alignInline="center">
                <Text weight="bold" color="color.text.information">{results?.updated?.length || 0}</Text>
                <Text size="small">Updated</Text>
              </Stack>
            </Box>
            <Box xcss={statsBoxStyle}>
              <Stack space="space.050" alignInline="center">
                <Text weight="bold" color="color.text.danger">{results?.failed?.length || 0}</Text>
                <Text size="small">Failed</Text>
              </Stack>
            </Box>
          </Inline>

          {/* Created Issues */}
          {results?.created?.length > 0 && (
            <Box xcss={cardStyle}>
              <Stack space="space.150">
                <Inline spread="space-between" alignBlock="center">
                  <Text weight="bold">✅ Created Issues</Text>
                  <Badge appearance="primary">{results.created.length} issues</Badge>
                </Inline>
                {results.created.slice(0, 12).map((issue, i) => (
                  <Box key={i} xcss={findingCardStyle}>
                    <Inline space="space.150" alignBlock="center" spread="space-between">
                      <Inline space="space.150" alignBlock="center">
                        <Link href={`/browse/${issue.key}`} openNewTab>
                          <Lozenge appearance="success">{issue.key}</Lozenge>
                        </Link>
                        <Text size="small">{issue.title?.substring(0, 45)}</Text>
                      </Inline>
                      <Lozenge appearance={getSeverityAppearance(issue.severity)}>{issue.severity}</Lozenge>
                    </Inline>
                  </Box>
                ))}
                {results.created.length > 12 && (
                  <Text size="small" color="color.text.subtlest">+ {results.created.length - 12} more</Text>
                )}
              </Stack>
            </Box>
          )}

          {/* Updated Issues */}
          {results?.updated?.length > 0 && (
            <Box xcss={cardStyle}>
              <Stack space="space.150">
                <Text weight="bold">🔄 Updated (Deduplicated)</Text>
                {results.updated.slice(0, 8).map((issue, i) => (
                  <Box key={i} xcss={findingCardStyle}>
                    <Inline space="space.100" alignBlock="center">
                      <Lozenge appearance="inprogress">{issue.key}</Lozenge>
                      <Text size="small">{issue.title?.substring(0, 50)}</Text>
                    </Inline>
                  </Box>
                ))}
              </Stack>
            </Box>
          )}

          {/* Failed */}
          {results?.failed?.length > 0 && (
            <Box xcss={cardStyle}>
              <Stack space="space.150">
                <Text weight="bold" color="color.text.danger">❌ Failed</Text>
                {results.failed.slice(0, 5).map((fail, i) => (
                  <Box key={i} xcss={findingCardStyle}>
                    <Stack space="space.050">
                      <Text size="small" weight="bold">{fail.title?.substring(0, 50)}</Text>
                      <Text size="small" color="color.text.danger">
                        {typeof fail.error === 'string' ? fail.error : JSON.stringify(fail.error).substring(0, 80)}
                      </Text>
                    </Stack>
                  </Box>
                ))}
              </Stack>
            </Box>
          )}

          {/* Actions */}
          <Inline spread="space-between">
            <Text size="small" color="color.text.subtlest">
              Project: {results?.projectKey} • Type: {results?.debug?.usingType || 'Unknown'}
            </Text>
            <Button appearance="primary" onClick={reset}>📥 Import More</Button>
          </Inline>
        </Stack>
      </Box>
    </Box>
  );
}

ForgeReconciler.render(
  <React.StrictMode>
    <App />
  </React.StrictMode>
);
