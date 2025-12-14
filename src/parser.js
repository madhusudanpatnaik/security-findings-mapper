/**
 * Security Findings Parser
 * Supports: SARIF, JSON, CSV, Plain Text formats
 * 
 * Based on patterns from n0s1 and common security scanner outputs
 */

// Regex patterns for extracting security metadata
const PATTERNS = {
  // CVSS Score: "CVSS: 9.8", "CVSS 3.1: 9.8", "cvss_score: 9.8"
  cvss: /(?:cvss(?:[-_\s]?(?:v?3(?:\.1)?|v?2))?[-_:\s]+)([\d.]+)/i,
  
  // CWE ID: "CWE-89", "CWE: 89", "cwe_id: 89"
  cwe: /cwe[-_:\s]*(\d+)/i,
  
  // Severity: "Severity: CRITICAL", "[HIGH]", "severity: high"
  severity: /(?:severity[-_:\s]*|^\s*\[)(critical|high|medium|moderate|low|info|informational|warning)/im,
  
  // OWASP: "OWASP A03:2021", "A01-Injection", "owasp_category: A01"
  owasp: /(?:owasp[-_\s]*)?(a\d{2})(?:[-:\s]?(?:20\d{2})?)?/i,
  
  // CVE ID: "CVE-2021-44228", "cve_id: CVE-2021-44228"
  cve: /cve[-_:\s]*((?:\d{4})[-_](?:\d{4,}))/i,
  
  // File path / Location
  location: /(?:file|path|location|uri|affected)[-_:\s]*['"]*([^\s'"]+\.[a-zA-Z]{1,5}(?::\d+)?)/i,
  
  // URL pattern
  url: /(https?:\/\/[^\s<>"{}|\\^`\[\]]+)/i
};

// Severity normalization map
const SEVERITY_MAP = {
  'critical': 'CRITICAL',
  'high': 'HIGH',
  'medium': 'MEDIUM',
  'moderate': 'MEDIUM',
  'low': 'LOW',
  'info': 'INFO',
  'informational': 'INFO',
  'warning': 'MEDIUM',
  'error': 'HIGH',
  'note': 'INFO'
};

/**
 * Main parser function - auto-detects format and parses
 */
export function parseSecurityFindings(content, format = 'auto') {
  if (!content || typeof content !== 'string') {
    throw new Error('Invalid content: expected non-empty string');
  }

  const trimmedContent = content.trim();
  
  // Auto-detect format if not specified
  if (format === 'auto') {
    format = detectFormat(trimmedContent);
  }

  switch (format.toLowerCase()) {
    case 'sarif':
      return parseSARIF(trimmedContent);
    case 'json':
      return parseJSON(trimmedContent);
    case 'csv':
      return parseCSV(trimmedContent);
    case 'text':
    case 'txt':
    case 'plaintext':
      return parsePlainText(trimmedContent);
    case 'snyk':
      return parseSnykJSON(trimmedContent);
    case 'semgrep':
      return parseSemgrepJSON(trimmedContent);
    case 'trivy':
      return parseTrivyJSON(trimmedContent);
    case 'burp':
      return parseBurpXML(trimmedContent);
    default:
      // Try JSON first, then text
      try {
        const parsed = JSON.parse(trimmedContent);
        if (parsed.$schema?.includes('sarif') || parsed.runs) {
          return parseSARIF(trimmedContent);
        }
        return parseJSON(trimmedContent);
      } catch {
        return parsePlainText(trimmedContent);
      }
  }
}

/**
 * Auto-detect content format
 */
function detectFormat(content) {
  const trimmed = content.trim();
  
  // Check for JSON/SARIF
  if (trimmed.startsWith('{') || trimmed.startsWith('[')) {
    try {
      const parsed = JSON.parse(trimmed);
      if (parsed.$schema?.includes('sarif') || parsed.runs) {
        return 'sarif';
      }
      if (parsed.vulnerabilities && parsed.packageManager) {
        return 'snyk';
      }
      if (parsed.results && parsed.results[0]?.check_id) {
        return 'semgrep';
      }
      if (parsed.Results || parsed.Vulnerabilities) {
        return 'trivy';
      }
      return 'json';
    } catch {
      return 'text';
    }
  }
  
  // Check for XML (Burp, etc.)
  if (trimmed.startsWith('<?xml') || trimmed.startsWith('<issues')) {
    return 'burp';
  }
  
  // Check for CSV (has header row with commas)
  const firstLine = trimmed.split('\n')[0];
  if (firstLine.includes(',') && 
      (firstLine.toLowerCase().includes('severity') || 
       firstLine.toLowerCase().includes('vulnerability') ||
       firstLine.toLowerCase().includes('finding'))) {
    return 'csv';
  }
  
  return 'text';
}

/**
 * Parse SARIF format (Static Analysis Results Interchange Format)
 * Used by: GitHub CodeQL, Semgrep, many SAST tools
 */
function parseSARIF(content) {
  const data = JSON.parse(content);
  const findings = [];
  
  const runs = data.runs || [];
  
  for (const run of runs) {
    const tool = run.tool?.driver?.name || 'Unknown Tool';
    const rules = run.tool?.driver?.rules || [];
    const rulesMap = {};
    
    // Build rules lookup
    for (const rule of rules) {
      rulesMap[rule.id] = rule;
    }
    
    const results = run.results || [];
    
    for (const result of results) {
      const ruleId = result.ruleId || 'unknown';
      const rule = rulesMap[ruleId] || {};
      
      // Get location
      const location = result.locations?.[0]?.physicalLocation;
      const filePath = location?.artifactLocation?.uri || '';
      const startLine = location?.region?.startLine || '';
      const locationStr = startLine ? `${filePath}:${startLine}` : filePath;
      
      // Get severity
      let severity = result.level || rule.defaultConfiguration?.level || 'warning';
      severity = SEVERITY_MAP[severity.toLowerCase()] || 'MEDIUM';
      
      // Extract CWE if present
      const cweMatch = (rule.id + ' ' + (rule.shortDescription?.text || '')).match(PATTERNS.cwe);
      const cweId = cweMatch ? cweMatch[1] : null;
      
      // Build finding
      findings.push({
        id: `sarif-${findings.length + 1}`,
        title: rule.shortDescription?.text || result.message?.text || ruleId,
        description: rule.fullDescription?.text || result.message?.text || '',
        severity: severity,
        cvssScore: extractCVSS(rule.properties || {}),
        cweId: cweId,
        cveId: extractCVE(result.message?.text || ''),
        owaspCategory: extractOWASP(rule.properties?.tags || []),
        affectedComponent: locationStr,
        location: locationStr,
        evidence: result.message?.text || '',
        remediation: rule.help?.text || rule.helpUri || '',
        references: rule.helpUri ? [rule.helpUri] : [],
        tool: tool,
        ruleId: ruleId,
        raw: result
      });
    }
  }
  
  return findings;
}

/**
 * Parse generic JSON array of findings
 */
function parseJSON(content) {
  const data = JSON.parse(content);
  const findings = [];
  
  // Handle both array and object with array property
  let items = data;
  if (!Array.isArray(data)) {
    // Look for common array properties
    items = data.findings || data.vulnerabilities || data.issues || 
            data.results || data.items || data.data || [];
  }
  
  if (!Array.isArray(items)) {
    items = [items];
  }
  
  for (const item of items) {
    const finding = normalizeJSONFinding(item, findings.length + 1);
    if (finding) {
      findings.push(finding);
    }
  }
  
  return findings;
}

/**
 * Normalize a JSON finding object to our standard format
 */
function normalizeJSONFinding(item, index) {
  if (!item || typeof item !== 'object') return null;
  
  // Extract title (try multiple common field names)
  const title = item.title || item.name || item.vulnerability || 
                item.finding || item.summary || item.rule_name ||
                item.check_name || item.message || `Finding ${index}`;
  
  // Extract severity
  let severity = item.severity || item.level || item.risk || 
                 item.criticality || item.priority || 'MEDIUM';
  if (typeof severity === 'number') {
    // Convert numeric severity (CVSS-like)
    if (severity >= 9) severity = 'CRITICAL';
    else if (severity >= 7) severity = 'HIGH';
    else if (severity >= 4) severity = 'MEDIUM';
    else if (severity >= 0.1) severity = 'LOW';
    else severity = 'INFO';
  } else {
    severity = SEVERITY_MAP[String(severity).toLowerCase()] || 'MEDIUM';
  }
  
  // Extract description
  const description = item.description || item.details || item.body ||
                      item.message || item.finding_description || '';
  
  // Extract CVSS
  let cvssScore = item.cvss || item.cvss_score || item.cvssScore ||
                  item.cvss_v3 || item.cvss3_score || null;
  if (typeof cvssScore === 'object') {
    cvssScore = cvssScore.score || cvssScore.baseScore || null;
  }
  
  // Extract CWE
  let cweId = item.cwe || item.cwe_id || item.cweId || null;
  if (typeof cweId === 'string') {
    const match = cweId.match(/\d+/);
    cweId = match ? match[0] : null;
  }
  if (Array.isArray(cweId)) {
    cweId = cweId[0];
    if (typeof cweId === 'object') cweId = cweId.id || cweId.cwe_id;
    if (typeof cweId === 'string') {
      const match = cweId.match(/\d+/);
      cweId = match ? match[0] : null;
    }
  }
  
  // Extract CVE
  let cveId = item.cve || item.cve_id || item.cveId || null;
  if (Array.isArray(cveId)) cveId = cveId[0];
  
  // Extract location
  const location = item.location || item.file || item.path || 
                   item.uri || item.url || item.affected_file ||
                   item.component || item.package || '';
  
  // Extract OWASP category
  let owaspCategory = item.owasp || item.owasp_category || null;
  if (Array.isArray(item.tags)) {
    owaspCategory = extractOWASP(item.tags);
  }
  
  return {
    id: `json-${index}`,
    title: String(title).substring(0, 200),
    description: String(description),
    severity: severity,
    cvssScore: cvssScore ? parseFloat(cvssScore) : null,
    cweId: cweId,
    cveId: cveId,
    owaspCategory: owaspCategory,
    affectedComponent: String(location),
    location: String(location),
    evidence: item.evidence || item.proof || item.snippet || '',
    remediation: item.remediation || item.fix || item.recommendation || 
                 item.solution || item.mitigation || '',
    references: extractReferences(item),
    tool: item.tool || item.scanner || item.source || 'Unknown',
    ruleId: item.rule_id || item.check_id || item.plugin_id || null,
    raw: item
  };
}

/**
 * Parse Snyk JSON format
 */
function parseSnykJSON(content) {
  const data = JSON.parse(content);
  const findings = [];
  
  const vulnerabilities = data.vulnerabilities || [];
  
  for (const vuln of vulnerabilities) {
    findings.push({
      id: `snyk-${findings.length + 1}`,
      title: vuln.title || vuln.name,
      description: vuln.description || '',
      severity: SEVERITY_MAP[vuln.severity?.toLowerCase()] || 'MEDIUM',
      cvssScore: vuln.cvssScore || vuln.CVSSv3 || null,
      cweId: vuln.identifiers?.CWE?.[0]?.replace('CWE-', '') || null,
      cveId: vuln.identifiers?.CVE?.[0] || null,
      owaspCategory: null,
      affectedComponent: `${vuln.packageName}@${vuln.version}`,
      location: vuln.from?.join(' → ') || '',
      evidence: '',
      remediation: vuln.fixedIn ? `Upgrade to version ${vuln.fixedIn.join(' or ')}` : '',
      references: vuln.references?.map(r => r.url) || [],
      tool: 'Snyk',
      ruleId: vuln.id,
      raw: vuln
    });
  }
  
  return findings;
}

/**
 * Parse Semgrep JSON format
 */
function parseSemgrepJSON(content) {
  const data = JSON.parse(content);
  const findings = [];
  
  const results = data.results || [];
  
  for (const result of results) {
    const severity = result.extra?.severity || result.extra?.metadata?.severity || 'WARNING';
    
    findings.push({
      id: `semgrep-${findings.length + 1}`,
      title: result.check_id || 'Unknown Rule',
      description: result.extra?.message || '',
      severity: SEVERITY_MAP[severity.toLowerCase()] || 'MEDIUM',
      cvssScore: null,
      cweId: result.extra?.metadata?.cwe?.[0]?.replace('CWE-', '') || null,
      cveId: null,
      owaspCategory: result.extra?.metadata?.owasp?.[0] || null,
      affectedComponent: `${result.path}:${result.start?.line || ''}`,
      location: result.path,
      evidence: result.extra?.lines || '',
      remediation: result.extra?.fix || result.extra?.metadata?.fix || '',
      references: result.extra?.metadata?.references || [],
      tool: 'Semgrep',
      ruleId: result.check_id,
      raw: result
    });
  }
  
  return findings;
}

/**
 * Parse Trivy JSON format
 */
function parseTrivyJSON(content) {
  const data = JSON.parse(content);
  const findings = [];
  
  const results = data.Results || [];
  
  for (const result of results) {
    const vulnerabilities = result.Vulnerabilities || [];
    
    for (const vuln of vulnerabilities) {
      findings.push({
        id: `trivy-${findings.length + 1}`,
        title: `${vuln.VulnerabilityID}: ${vuln.Title || vuln.PkgName}`,
        description: vuln.Description || '',
        severity: SEVERITY_MAP[vuln.Severity?.toLowerCase()] || 'MEDIUM',
        cvssScore: vuln.CVSS?.nvd?.V3Score || vuln.CVSS?.redhat?.V3Score || null,
        cweId: vuln.CweIDs?.[0]?.replace('CWE-', '') || null,
        cveId: vuln.VulnerabilityID?.startsWith('CVE') ? vuln.VulnerabilityID : null,
        owaspCategory: null,
        affectedComponent: `${vuln.PkgName}@${vuln.InstalledVersion}`,
        location: result.Target || '',
        evidence: '',
        remediation: vuln.FixedVersion ? `Upgrade to ${vuln.FixedVersion}` : '',
        references: vuln.References || [],
        tool: 'Trivy',
        ruleId: vuln.VulnerabilityID,
        raw: vuln
      });
    }
  }
  
  return findings;
}

/**
 * Parse Burp Suite XML format
 */
function parseBurpXML(content) {
  const findings = [];
  
  // Simple XML parsing for Burp format
  const issueRegex = /<issue>([\s\S]*?)<\/issue>/gi;
  let match;
  
  while ((match = issueRegex.exec(content)) !== null) {
    const issueXml = match[1];
    
    const getName = (tag) => {
      const m = issueXml.match(new RegExp(`<${tag}>([\\s\\S]*?)<\\/${tag}>`, 'i'));
      return m ? m[1].replace(/<!\[CDATA\[([\s\S]*?)\]\]>/g, '$1').trim() : '';
    };
    
    const severityMap = {
      'high': 'HIGH',
      'medium': 'MEDIUM',
      'low': 'LOW',
      'information': 'INFO',
      'info': 'INFO'
    };
    
    findings.push({
      id: `burp-${findings.length + 1}`,
      title: getName('name') || 'Unknown Issue',
      description: getName('issueDetail') || getName('issueBackground') || '',
      severity: severityMap[getName('severity').toLowerCase()] || 'MEDIUM',
      cvssScore: null,
      cweId: null,
      cveId: null,
      owaspCategory: null,
      affectedComponent: getName('path') || getName('location'),
      location: getName('host') + getName('path'),
      evidence: getName('request') || getName('response') || '',
      remediation: getName('remediationBackground') || getName('remediationDetail') || '',
      references: [],
      tool: 'Burp Suite',
      ruleId: getName('type'),
      raw: issueXml
    });
  }
  
  return findings;
}

/**
 * Parse CSV format
 */
function parseCSV(content) {
  const lines = content.split('\n').filter(l => l.trim());
  if (lines.length < 2) return [];
  
  // Parse header
  const header = parseCSVLine(lines[0]).map(h => h.toLowerCase().trim());
  const findings = [];
  
  // Map common header names
  const headerMap = {
    title: header.findIndex(h => ['title', 'name', 'vulnerability', 'finding', 'issue'].includes(h)),
    severity: header.findIndex(h => ['severity', 'risk', 'level', 'priority'].includes(h)),
    description: header.findIndex(h => ['description', 'details', 'summary'].includes(h)),
    cvss: header.findIndex(h => ['cvss', 'cvss_score', 'score'].includes(h)),
    cwe: header.findIndex(h => ['cwe', 'cwe_id'].includes(h)),
    cve: header.findIndex(h => ['cve', 'cve_id'].includes(h)),
    location: header.findIndex(h => ['location', 'file', 'path', 'url', 'component'].includes(h)),
    remediation: header.findIndex(h => ['remediation', 'fix', 'recommendation', 'solution'].includes(h)),
  };
  
  // Parse data rows
  for (let i = 1; i < lines.length; i++) {
    const values = parseCSVLine(lines[i]);
    if (values.length === 0) continue;
    
    const getValue = (key) => {
      const idx = headerMap[key];
      return idx >= 0 && idx < values.length ? values[idx].trim() : '';
    };
    
    const title = getValue('title') || `Finding ${i}`;
    let severity = getValue('severity') || 'MEDIUM';
    severity = SEVERITY_MAP[severity.toLowerCase()] || 'MEDIUM';
    
    findings.push({
      id: `csv-${i}`,
      title: title,
      description: getValue('description'),
      severity: severity,
      cvssScore: parseFloat(getValue('cvss')) || null,
      cweId: getValue('cwe').replace(/\D/g, '') || null,
      cveId: getValue('cve') || null,
      owaspCategory: null,
      affectedComponent: getValue('location'),
      location: getValue('location'),
      evidence: '',
      remediation: getValue('remediation'),
      references: [],
      tool: 'CSV Import',
      ruleId: null,
      raw: values
    });
  }
  
  return findings;
}

/**
 * Parse a CSV line handling quoted values
 */
function parseCSVLine(line) {
  const values = [];
  let current = '';
  let inQuotes = false;
  
  for (let i = 0; i < line.length; i++) {
    const char = line[i];
    
    if (char === '"') {
      if (inQuotes && line[i + 1] === '"') {
        current += '"';
        i++;
      } else {
        inQuotes = !inQuotes;
      }
    } else if (char === ',' && !inQuotes) {
      values.push(current);
      current = '';
    } else {
      current += char;
    }
  }
  values.push(current);
  
  return values;
}

/**
 * Parse plain text findings (most flexible, uses regex)
 */
function parsePlainText(content) {
  const findings = [];
  
  // Split by common finding delimiters
  const findingDelimiters = [
    /(?:^|\n)(?:#{1,3}\s*)?(?:finding|vulnerability|issue|bug)\s*[:#]?\s*\d*/gi,
    /(?:^|\n)[-=]{3,}/g,
    /(?:^|\n)\d+\.\s+/g,
    /(?:^|\n)\[(?:CRITICAL|HIGH|MEDIUM|LOW|INFO)\]/gi
  ];
  
  // Try to split into sections
  let sections = [content];
  for (const delimiter of findingDelimiters) {
    const newSections = [];
    for (const section of sections) {
      const parts = section.split(delimiter).filter(p => p.trim().length > 50);
      if (parts.length > 1) {
        newSections.push(...parts);
      } else {
        newSections.push(section);
      }
    }
    if (newSections.length > sections.length) {
      sections = newSections;
      break;
    }
  }
  
  // If no sections found, try paragraph-based splitting
  if (sections.length === 1) {
    sections = content.split(/\n\s*\n/).filter(p => p.trim().length > 30);
  }
  
  // Parse each section as a finding
  for (const section of sections) {
    const finding = parseTextSection(section, findings.length + 1);
    if (finding && finding.title && finding.title !== `Finding ${findings.length + 1}`) {
      findings.push(finding);
    }
  }
  
  // If we got nothing, treat whole content as single finding
  if (findings.length === 0) {
    const finding = parseTextSection(content, 1);
    if (finding) {
      findings.push(finding);
    }
  }
  
  return findings;
}

/**
 * Parse a text section into a finding
 */
function parseTextSection(text, index) {
  const lines = text.split('\n').filter(l => l.trim());
  if (lines.length === 0) return null;
  
  // Extract title (first significant line or line with vulnerability keywords)
  let title = lines[0].replace(/^[\s#*-]+/, '').trim();
  
  // Look for better title candidates
  for (const line of lines.slice(0, 5)) {
    if (/(?:title|name|vulnerability|finding)[\s:]+(.+)/i.test(line)) {
      title = RegExp.$1.trim();
      break;
    }
  }
  
  // Extract severity
  let severity = 'MEDIUM';
  const severityMatch = text.match(PATTERNS.severity);
  if (severityMatch) {
    severity = SEVERITY_MAP[severityMatch[1].toLowerCase()] || 'MEDIUM';
  }
  
  // Extract CVSS
  let cvssScore = null;
  const cvssMatch = text.match(PATTERNS.cvss);
  if (cvssMatch) {
    cvssScore = parseFloat(cvssMatch[1]);
  }
  
  // Extract CWE
  let cweId = null;
  const cweMatch = text.match(PATTERNS.cwe);
  if (cweMatch) {
    cweId = cweMatch[1];
  }
  
  // Extract CVE
  let cveId = null;
  const cveMatch = text.match(PATTERNS.cve);
  if (cveMatch) {
    cveId = `CVE-${cveMatch[1]}`;
  }
  
  // Extract OWASP
  let owaspCategory = null;
  const owaspMatch = text.match(PATTERNS.owasp);
  if (owaspMatch) {
    owaspCategory = owaspMatch[1].toUpperCase();
  }
  
  // Extract location
  let location = '';
  const locationMatch = text.match(PATTERNS.location);
  if (locationMatch) {
    location = locationMatch[1];
  }
  
  // Extract description (content between title and remediation)
  const descriptionLines = [];
  let inDescription = true;
  for (const line of lines.slice(1)) {
    if (/(?:remediation|fix|recommendation|solution|mitigation)/i.test(line)) {
      inDescription = false;
    }
    if (inDescription) {
      descriptionLines.push(line);
    }
  }
  const description = descriptionLines.join('\n').trim();
  
  // Extract remediation
  let remediation = '';
  const remediationMatch = text.match(/(?:remediation|fix|recommendation|solution|mitigation)[:\s]+(.+?)(?:\n\n|$)/is);
  if (remediationMatch) {
    remediation = remediationMatch[1].trim();
  }
  
  // Extract references (URLs)
  const references = [];
  const urlMatches = text.matchAll(new RegExp(PATTERNS.url.source, 'gi'));
  for (const match of urlMatches) {
    if (!references.includes(match[1])) {
      references.push(match[1]);
    }
  }
  
  return {
    id: `text-${index}`,
    title: title.substring(0, 200),
    description: description,
    severity: severity,
    cvssScore: cvssScore,
    cweId: cweId,
    cveId: cveId,
    owaspCategory: owaspCategory,
    affectedComponent: location,
    location: location,
    evidence: '',
    remediation: remediation,
    references: references,
    tool: 'Manual Import',
    ruleId: null,
    raw: text
  };
}

// Helper functions

function extractCVSS(properties) {
  if (properties['security-severity']) {
    return parseFloat(properties['security-severity']);
  }
  if (properties.cvss) {
    return parseFloat(properties.cvss);
  }
  return null;
}

function extractCVE(text) {
  const match = text.match(PATTERNS.cve);
  return match ? `CVE-${match[1]}` : null;
}

function extractOWASP(tags) {
  if (!Array.isArray(tags)) return null;
  
  for (const tag of tags) {
    const match = String(tag).match(PATTERNS.owasp);
    if (match) {
      return match[1].toUpperCase();
    }
  }
  return null;
}

function extractReferences(item) {
  const refs = [];
  
  if (item.references) {
    if (Array.isArray(item.references)) {
      for (const ref of item.references) {
        if (typeof ref === 'string') refs.push(ref);
        else if (ref.url) refs.push(ref.url);
      }
    } else if (typeof item.references === 'string') {
      refs.push(item.references);
    }
  }
  
  if (item.url) refs.push(item.url);
  if (item.link) refs.push(item.link);
  if (item.helpUri) refs.push(item.helpUri);
  
  return [...new Set(refs)];
}

