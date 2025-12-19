/**
 * Security Findings Parser
 * Supports: SARIF, JSON, CSV, Plain Text formats
 * 
 * Based on patterns from n0s1 and common security scanner outputs
 */

import crypto from 'crypto';

/**
 * Generate a fingerprint hash for a finding to enable deduplication.
 * Combines: ruleId, file path, line number, scanner, and severity
 */
function generateFingerprint(ruleId, location, scanner, severity) {
  const normalized = [
    (ruleId || '').toLowerCase().trim(),
    (location || '').toLowerCase().trim(),
    (scanner || '').toLowerCase().trim(),
    (severity || '').toUpperCase().trim()
  ].join('|');
  
  return crypto.createHash('sha256').update(normalized).digest('hex');
}

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
  url: /(https?:\/\/[^^\s<>"{}|\\^`[\]]+)/i
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
  
  console.log('[PARSER] Format detected/specified:', format);

  switch (format.toLowerCase()) {
    case 'sarif':
      console.log('[PARSER] Using SARIF parser');
      return parseSARIF(trimmedContent);
    case 'json':
      console.log('[PARSER] Using generic JSON parser');
      return parseJSON(trimmedContent);
    case 'csv':
      console.log('[PARSER] Using CSV parser');
      return parseCSV(trimmedContent);
    case 'text':
    case 'txt':
    case 'plaintext':
      console.log('[PARSER] Using plaintext parser');
      return parsePlainText(trimmedContent);
    case 'snyk':
      console.log('[PARSER] Using Snyk parser');
      return parseSnykJSON(trimmedContent);
    case 'semgrep':
      console.log('[PARSER] Using Semgrep parser');
      return parseSemgrepJSON(trimmedContent);
    case 'trivy':
      console.log('[PARSER] Using Trivy parser');
      return parseTrivyJSON(trimmedContent);
    case 'burp':
      console.log('[PARSER] Using Burp parser');
      return parseBurpXML(trimmedContent);
    default:
      console.log('[PARSER] Using default fallback');
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
        console.log('[DEBUG] Detected format: sarif');
        return 'sarif';
      }
      if (parsed.vulnerabilities && parsed.packageManager) {
        console.log('[DEBUG] Detected format: snyk');
        return 'snyk';
      }
      if (parsed.results && parsed.results[0]?.check_id) {
        console.log('[DEBUG] Detected format: semgrep');
        return 'semgrep';
      }
      if (parsed.Results || parsed.Vulnerabilities) {
        console.log('[DEBUG] Detected format: trivy');
        return 'trivy';
      }
      console.log('[DEBUG] Detected format: json (generic)');
      return 'json';
    } catch {
      console.log('[DEBUG] Detected format: text (JSON parse failed)');
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
      
      // Generate fingerprint for deduplication
      const fingerprint = generateFingerprint(ruleId, locationStr, tool, severity);
      
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
        fingerprint: fingerprint,
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
  
  // Generate fingerprint for deduplication
  const fingerprint = generateFingerprint(
    item.rule_id || item.check_id || item.plugin_id || title,
    location,
    item.tool || item.scanner || item.source || 'Unknown',
    severity
  );
  
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
    fingerprint: fingerprint,
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
    const severity = SEVERITY_MAP[vuln.severity?.toLowerCase()] || 'MEDIUM';
    const location = `${vuln.packageName}@${vuln.version}`;
    const fingerprint = generateFingerprint(vuln.id, location, 'Snyk', severity);
    
    findings.push({
      id: `snyk-${findings.length + 1}`,
      title: vuln.title || vuln.name,
      description: vuln.description || '',
      severity: severity,
      cvssScore: vuln.cvssScore || vuln.CVSSv3 || null,
      cweId: vuln.identifiers?.CWE?.[0]?.replace('CWE-', '') || null,
      cveId: vuln.identifiers?.CVE?.[0] || null,
      owaspCategory: null,
      affectedComponent: location,
      location: vuln.from?.join(' → ') || '',
      evidence: vuln.evidence || vuln.exploit || vuln.exploitMaturity || '',
      remediation: vuln.fixedIn ? `Upgrade to version ${vuln.fixedIn.join(' or ')}` : '',
      references: vuln.references?.map(r => r.url) || [],
      tool: 'Snyk',
      ruleId: vuln.id,
      fingerprint: fingerprint,
      raw: vuln
    });
  }
  
  return findings;
}

/**
 * Parse Semgrep JSON format
 */
function parseSemgrepJSON(content) {
  console.log('[DEBUG] parseSemgrepJSON called');
  const data = JSON.parse(content);
  const findings = [];
  
  const results = data.results || [];
  console.log('[DEBUG] Semgrep results count:', results.length);
  
  for (const result of results) {
    const severity = result.extra?.severity || result.extra?.metadata?.severity || 'WARNING';
    const normSeverity = SEVERITY_MAP[severity.toLowerCase()] || 'MEDIUM';
    const location = `${result.path}:${result.start?.line || ''}`;
    const fingerprint = generateFingerprint(result.check_id, location, 'Semgrep', normSeverity);
    
    // Create a human-readable title from check_id
    // e.g., "javascript.express.security.audit.xss.mustache.var-in-href" -> "XSS: Variable in href (Mustache)"
    const checkId = result.check_id || 'Unknown Rule';
    const titleFromMessage = result.extra?.message?.split('.')[0] || '';
    const readableTitle = formatSemgrepTitle(checkId, titleFromMessage);
    console.log('[DEBUG] Semgrep finding: checkId=', checkId, 'title=', readableTitle);
    
    findings.push({
      id: `semgrep-${findings.length + 1}`,
      title: readableTitle,
      description: result.extra?.message || '',
      severity: normSeverity,
      cvssScore: null,
      cweId: extractCWEFromArray(result.extra?.metadata?.cwe),
      cveId: null,
      owaspCategory: result.extra?.metadata?.owasp?.[0] || null,
      affectedComponent: location,
      location: result.path,
      evidence: result.extra?.lines || '',
      remediation: result.extra?.fix || result.extra?.metadata?.fix || '',
      references: result.extra?.metadata?.references || [],
      tool: 'Semgrep',
      ruleId: checkId,
      fingerprint: fingerprint,
      raw: result
    });
  }
  
  return findings;
}

/**
 * Format Semgrep check_id into a readable title
 */
function formatSemgrepTitle(checkId) {
  // Extract meaningful parts from the check_id
  // e.g., "javascript.express.security.audit.xss.mustache.var-in-href"
  const parts = checkId.split('.');
  
  // Find the security-relevant parts (after 'security' or 'audit')
  const securityIndex = parts.findIndex(p => p === 'security' || p === 'audit');
  const relevantParts = securityIndex >= 0 ? parts.slice(securityIndex + 1) : parts.slice(-3);
  
  // Format each part: replace hyphens, capitalize
  const formatted = relevantParts
    .filter(p => p !== 'audit' && p !== 'security')
    .map(p => {
      // Handle common abbreviations
      const abbrevMap = {
        'xss': 'XSS',
        'sqli': 'SQL Injection',
        'csrf': 'CSRF',
        'ssrf': 'SSRF',
        'rce': 'RCE',
        'jwt': 'JWT',
        'xxe': 'XXE',
        'idor': 'IDOR',
        'lfi': 'LFI',
        'rfi': 'RFI'
      };
      if (abbrevMap[p.toLowerCase()]) {
        return abbrevMap[p.toLowerCase()];
      }
      // Replace hyphens and capitalize words
      return p.split('-')
        .map(w => w.charAt(0).toUpperCase() + w.slice(1))
        .join(' ');
    })
    .join(': ');
  
  return formatted || checkId;
}

/**
 * Extract CWE ID from Semgrep's CWE array format
 */
function extractCWEFromArray(cweArray) {
  if (!cweArray || !Array.isArray(cweArray) || cweArray.length === 0) {
    return null;
  }
  const cwe = cweArray[0];
  if (typeof cwe === 'string') {
    const match = cwe.match(/CWE-?(\d+)/i);
    return match ? match[1] : null;
  }
  return null;
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
      const severity = SEVERITY_MAP[vuln.Severity?.toLowerCase()] || 'MEDIUM';
      const location = result.Target || '';
      const fingerprint = generateFingerprint(vuln.VulnerabilityID, location, 'Trivy', severity);
      
      findings.push({
        id: `trivy-${findings.length + 1}`,
        title: `${vuln.VulnerabilityID}: ${vuln.Title || vuln.PkgName}`,
        description: vuln.Description || '',
        severity: severity,
        cvssScore: vuln.CVSS?.nvd?.V3Score || vuln.CVSS?.redhat?.V3Score || null,
        cweId: vuln.CweIDs?.[0]?.replace('CWE-', '') || null,
        cveId: vuln.VulnerabilityID?.startsWith('CVE') ? vuln.VulnerabilityID : null,
        owaspCategory: null,
        affectedComponent: `${vuln.PkgName}@${vuln.InstalledVersion}`,
        location: location,
        evidence: vuln.PrimaryURL || vuln.Description || '',
        remediation: vuln.FixedVersion ? `Upgrade to ${vuln.FixedVersion}` : '',
        references: vuln.References || [],
        tool: 'Trivy',
        ruleId: vuln.VulnerabilityID,
        fingerprint: fingerprint,
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
    
    const severity = severityMap[getName('severity').toLowerCase()] || 'MEDIUM';
    const location = getName('host') + getName('path');
    const fingerprint = generateFingerprint(getName('type'), location, 'Burp Suite', severity);
    
    findings.push({
      id: `burp-${findings.length + 1}`,
      title: getName('name') || 'Unknown Issue',
      description: getName('issueDetail') || getName('issueBackground') || '',
      severity: severity,
      cvssScore: null,
      cweId: null,
      cveId: null,
      owaspCategory: null,
      affectedComponent: getName('path') || getName('location'),
      location: location,
      evidence: getName('request') || getName('response') || '',
      remediation: getName('remediationBackground') || getName('remediationDetail') || '',
      references: [],
      tool: 'Burp Suite',
      ruleId: getName('type'),
      fingerprint: fingerprint,
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
    evidence: header.findIndex(h => ['evidence', 'proof', 'snippet', 'details'].includes(h)),
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
    const location = getValue('location');
    const fingerprint = generateFingerprint(title, location, 'CSV Import', severity);
    
    findings.push({
      id: `csv-${i}`,
      title: title,
      description: getValue('description'),
      severity: severity,
      cvssScore: parseFloat(getValue('cvss')) || null,
      cweId: getValue('cwe').replace(/\D/g, '') || null,
      cveId: getValue('cve') || null,
      owaspCategory: null,
      affectedComponent: location,
      location: location,
      evidence: getValue('evidence'),
      remediation: getValue('remediation'),
      references: [],
      tool: 'CSV Import',
      ruleId: null,
      fingerprint: fingerprint,
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
  
  // ONLY use Method 1 for structured reports with "Finding #N: Title" pattern
  // This is the most reliable method for security reports
  const findingPattern = /Finding\s*#?(\d+)\s*:\s*([^\n]+)/gi;
  const findingMatches = [...content.matchAll(findingPattern)];
  
  if (findingMatches.length > 0) {
    for (let i = 0; i < findingMatches.length; i++) {
      const match = findingMatches[i];
      const findingNum = match[1];
      const title = match[2].trim();
      
      // STRICT validation: title must be meaningful
      if (!title || 
          title.length < 5 || 
          /^[-=\s*#]+$/.test(title) ||
          /^[\d.]+$/.test(title)) {
        continue;
      }
      
      // Extract block from this finding to the next (or end)
      const startIndex = match.index;
      const nextMatch = findingMatches[i + 1];
      const endIndex = nextMatch ? nextMatch.index : content.length;
      const block = content.slice(startIndex, endIndex);
      
      // Build finding directly here instead of calling parseStructuredFinding
      // to ensure we use the exact title we validated
      const finding = buildFindingFromBlock(findingNum, title, block);
      if (finding) {
        findings.push(finding);
      }
    }
    
    // Return early - don't fall through to other methods
    return findings;
  }
  
  // Fallback for non-structured reports (no "Finding #N:" pattern found)
  // Only parse if content looks like security findings
  if (!/vulnerability|security issue|injection|xss|csrf|cwe-/i.test(content)) {
    return findings;
  }
  
  // Try paragraph-based parsing as last resort
  const paragraphs = content.split(/\n\s*\n/).filter(p => p.trim().length > 100);
  for (const para of paragraphs) {
    if (/vulnerability|injection|xss|csrf|exposure|bypass/i.test(para)) {
      const finding = parseTextSection(para, findings.length + 1);
      if (finding && finding.title && 
          finding.title.length >= 8 &&
          !/^[-=\s*#]+$/.test(finding.title) &&
          !/^(SECURITY|END OF|Application|Date|Report)/i.test(finding.title)) {
        findings.push(finding);
      }
    }
  }
  
  return findings;
}

/**
 * Build a finding from a validated block
 */
function buildFindingFromBlock(findingNum, title, block) {
  // Title is already validated by caller
  if (!title || title.length < 5) return null;
  
  // Extract fields using labeled patterns
  const extractField = (pattern) => {
    const match = block.match(pattern);
    return match ? match[1].trim() : '';
  };
  
  // Severity
  let severity = 'MEDIUM';
  const severityMatch = block.match(/Severity:\s*(CRITICAL|HIGH|MEDIUM|LOW|INFO)/i);
  if (severityMatch) {
    severity = SEVERITY_MAP[severityMatch[1].toLowerCase()] || 'MEDIUM';
  }
  
  // CVSS
  let cvssScore = null;
  const cvssMatch = block.match(/CVSS:\s*([\d.]+)/i);
  if (cvssMatch) {
    cvssScore = parseFloat(cvssMatch[1]);
  }
  
  // CWE
  let cweId = null;
  const cweMatch = block.match(/CWE-?(\d+)/i);
  if (cweMatch) {
    cweId = cweMatch[1];
  }
  
  // OWASP
  let owaspCategory = null;
  const owaspMatch = block.match(/OWASP:\s*(A\d{2}:\d{4})/i);
  if (owaspMatch) {
    owaspCategory = owaspMatch[1].toUpperCase();
  }
  
  // Description (between "Description:" and next field)
  let description = '';
  const descMatch = block.match(/Description:\s*([\s\S]*?)(?=\n(?:Affected|Evidence|Remediation|References|$))/i);
  if (descMatch) {
    description = descMatch[1].trim();
  }
  
  // Affected Component / Location
  let location = '';
  const locationMatch = block.match(/Affected\s*Component:\s*([\s\S]*?)(?=\n(?:Evidence|Remediation|References|Description|$))/i);
  if (locationMatch) {
    location = locationMatch[1].trim().split('\n')[0];
  }
  
  // Evidence
  let evidence = '';
  const evidenceMatch = block.match(/Evidence:\s*([\s\S]*?)(?=\n(?:Remediation|References|$))/i);
  if (evidenceMatch) {
    evidence = evidenceMatch[1].trim();
  }
  
  // Remediation
  let remediation = '';
  const remMatch = block.match(/Remediation:\s*([\s\S]*?)(?=\n(?:References|$)|\n[=]{10,})/i);
  if (remMatch) {
    remediation = remMatch[1].trim();
  }
  
  // References (URLs)
  const references = [];
  const urlMatches = block.matchAll(/https?:\/\/[^\s<>"']+/gi);
  for (const match of urlMatches) {
    if (!references.includes(match[0])) {
      references.push(match[0]);
    }
  }
  
  return {
    id: `text-${findingNum}`,
    title: title.substring(0, 200),
    description: description,
    severity: severity,
    cvssScore: cvssScore,
    cweId: cweId,
    cveId: extractField(/CVE-(\d{4}-\d+)/i) ? `CVE-${extractField(/CVE-(\d{4}-\d+)/i)}` : null,
    owaspCategory: owaspCategory,
    affectedComponent: location,
    location: location,
    evidence: evidence,
    remediation: remediation,
    references: references,
    tool: 'Manual Import',
    ruleId: cweId ? `CWE-${cweId}` : null,
    fingerprint: generateFingerprint(title, location, 'Manual Import', severity),
    raw: block
  };
}

/**
 * Parse a text section into a finding
 */
function parseTextSection(text, index) {
  const lines = text.split('\n').filter(l => l.trim() && !/^[=-]{3,}$/.test(l.trim()));
  if (lines.length === 0) return null;
  
  // Skip sections that are just headers/metadata
  if (/^(security (scan )?report|application:|date:|generated by|end of report)/i.test(text.trim())) {
    return null;
  }
  
  // Extract title (first significant line or line with vulnerability keywords)
  let title = '';
  
  // Look for explicit title/name patterns first
  for (const line of lines.slice(0, 8)) {
    if (/(?:title|name|vulnerability|finding)[\s:]+(.+)/i.test(line)) {
      title = RegExp.$1.trim();
      break;
    }
  }
  
  // If no explicit title found, use first substantial line that's not just severity/metadata
  if (!title) {
    for (const line of lines) {
      const cleanLine = line.replace(/^[\s#*-]+/, '').trim();
      // Skip lines that are just severity, metadata, or decorative
      if (cleanLine.length > 5 && 
          !/^(CRITICAL|HIGH|MEDIUM|LOW|INFO|SEVERITY|CVSS|CWE|DATE|APPLICATION)/i.test(cleanLine) &&
          !/^[=\-\s*]+$/.test(cleanLine) &&
          !/^\d+\.\d+$/.test(cleanLine)) {
        title = cleanLine;
        break;
      }
    }
  }
  
  // If still no title, this isn't a valid finding
  if (!title || title.length < 4) {
    return null;
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
    fingerprint: generateFingerprint(title, location, 'Manual Import', severity),
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

