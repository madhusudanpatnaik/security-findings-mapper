import Resolver from '@forge/resolver';
import api, { route } from '@forge/api';
import { parseSecurityFindings } from './parser.js';

const resolver = new Resolver();

// ============================================================================
// GET PROJECT CONTEXT
// ============================================================================
resolver.define('getProjectContext', async (req) => {
  return {
    projectId: req.context?.extension?.project?.id,
    projectKey: req.context?.extension?.project?.key,
  };
});

// ============================================================================
// GET ASSIGNABLE USERS
// ============================================================================
resolver.define('getAssignableUsers', async (req) => {
  const { projectKey } = req.payload;
  if (!projectKey || typeof projectKey !== 'string') {
    return { success: false, users: [], error: 'projectKey is required' };
  }
  try {
    const response = await api.asUser().requestJira(
      route`/rest/api/3/user/assignable/search?project=${projectKey}&maxResults=50`
    );
    if (response.ok) {
      const users = await response.json();
      return {
        success: true,
        users: users.map(u => ({
          accountId: u.accountId,
          displayName: u.displayName,
          avatarUrl: u.avatarUrls?.['24x24'] || ''
        }))
      };
    }
    return { success: false, users: [], error: `HTTP ${response.status}` };
  } catch (e) {
    return { success: false, users: [], error: e.message };
  }
});

// ============================================================================
// ATTACH FILE TO ISSUE
// ============================================================================
resolver.define('attachFile', async (req) => {
  const { issueKey, fileName, fileContent, mimeType } = req.payload;

  if (!issueKey || typeof issueKey !== 'string') {
    return { success: false, error: 'issueKey is required' };
  }
  if (!fileName || typeof fileName !== 'string') {
    return { success: false, error: 'fileName is required' };
  }
  if (!fileContent || typeof fileContent !== 'string') {
    return { success: false, error: 'fileContent (base64) is required' };
  }
  
  try {
    // Decode base64 content to binary
    const binaryContent = Buffer.from(fileContent, 'base64');
    
    // Create multipart form data boundary
    const boundary = '----FormBoundary' + Date.now().toString(16);
    
    // Build multipart body
    const bodyParts = [
      `--${boundary}`,
      `Content-Disposition: form-data; name="file"; filename="${fileName}"`,
      `Content-Type: ${mimeType || 'application/pdf'}`,
      '',
      ''
    ];
    
    const headerBuffer = Buffer.from(bodyParts.join('\r\n'), 'utf-8');
    const footerBuffer = Buffer.from(`\r\n--${boundary}--\r\n`, 'utf-8');
    
    // Combine buffers
    const bodyBuffer = Buffer.concat([headerBuffer, binaryContent, footerBuffer]);
    
    const response = await api.asUser().requestJira(
      route`/rest/api/3/issue/${issueKey}/attachments`,
      {
        method: 'POST',
        headers: {
          'X-Atlassian-Token': 'no-check',
          'Content-Type': `multipart/form-data; boundary=${boundary}`
        },
        body: bodyBuffer
      }
    );

    if (response.ok) {
      const data = await response.json();
      return { 
        success: true, 
        attachments: data,
        message: `Attached ${fileName} to ${issueKey}`
      };
    } else {
      const errText = await response.text();
      return { 
        success: false, 
        error: `HTTP ${response.status}: ${errText}`
      };
    }
  } catch (e) {
    return { success: false, error: e.message };
  }
});

// ============================================================================
// PARSE FINDINGS
// ============================================================================
resolver.define('parseFindings', async (req) => {
  const { content, format } = req.payload;
  try {
    const findings = parseSecurityFindings(content, format);
    return {
      success: true,
      findings,
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
    return { success: false, error: error.message, findings: [] };
  }
});

// ============================================================================
// CREATE ISSUES (ADVANCED)
// ============================================================================
resolver.define('createIssues', async (req) => {
  const { findings, projectKey } = req.payload;
  const results = { 
    created: [], 
    updated: [], 
    failed: [], 
    total: findings.length, 
    projectKey, 
    debug: { searches: [] } 
  };
  
  // Get available issue types for this project
  let issueTypeId = null;
  let hasDueDate = false;
  
  try {
    const metaResp = await api.asUser().requestJira(
      route`/rest/api/3/issue/createmeta?projectKeys=${projectKey}&expand=projects.issuetypes.fields`
    );
    if (metaResp.ok) {
      const meta = await metaResp.json();
      const project = meta.projects?.[0];
      results.debug.projectName = project?.name;
      results.debug.issueTypes = project?.issuetypes?.map(it => `${it.name}(${it.id})`);
      
      // Find a suitable issue type - prefer Bug > Story > Task
      const types = project?.issuetypes || [];
      const bug = types.find(t => t.name.toLowerCase() === 'bug');
      const story = types.find(t => t.name.toLowerCase() === 'story');
      const task = types.find(t => t.name.toLowerCase() === 'task');
      const nonSubtask = types.find(t => !t.subtask);
      const chosen = bug || story || task || nonSubtask || types[0];
      
      if (chosen) {
        issueTypeId = chosen.id;
        results.debug.usingType = `${chosen.name} (${chosen.id})`;
        // Check if duedate field is available
        hasDueDate = chosen.fields?.duedate !== undefined;
      }
    } else {
      results.debug.metaError = `HTTP ${metaResp.status}`;
    }
  } catch (e) {
    results.debug.metaError = e.message;
  }

  if (!issueTypeId) {
    results.failed = findings.map(f => ({ title: f.title, error: 'Could not determine issue type' }));
    return results;
  }

  // Process each finding
  for (const f of findings) {
    try {
      // Try to find existing issue with matching fingerprint
      let existingIssue = null;
      const fingerprintLabel = f.fingerprint ? `finding-${f.fingerprint.slice(0, 20)}` : null;
      
      if (f.fingerprint) {
        existingIssue = await findExistingIssue(projectKey, f, fingerprintLabel, results);
      }

      if (existingIssue) {
        // Update existing issue with new evidence/comment
        await updateExistingIssue(existingIssue, f, results);
      } else {
        // Create new issue
        await createNewIssue(f, projectKey, issueTypeId, fingerprintLabel, hasDueDate, results);
      }
    } catch (e) {
      results.failed.push({ title: f.title, error: e.message });
    }
  }
  
  return results;
});

// ============================================================================
// FIND EXISTING ISSUE (DEDUPLICATION)
// ============================================================================
async function findExistingIssue(projectKey, f, fingerprintLabel, results) {
  if (!f.fingerprint) return null;

  // Build JQL to search for existing issues
  const clauses = [];
  
  // Search by fingerprint label (primary method)
  if (fingerprintLabel) {
    clauses.push(`labels = "${fingerprintLabel}"`);
  }
  
  // Search by full fingerprint in description
  clauses.push(`description ~ "${f.fingerprint}"`);
  
  // Fallback: match by similar summary (CWE + title pattern)
  const summaryPattern = `[${f.severity}] ${f.title}`.substring(0, 50).replace(/["[\]]/g, '');
  clauses.push(`summary ~ "${summaryPattern}"`);

  const jql = `project = "${projectKey}" AND (${clauses.join(' OR ')}) ORDER BY created DESC`;

  try {
    const searchResp = await api.asUser().requestJira(route`/rest/api/3/search`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ 
        jql, 
        maxResults: 5, 
        fields: ['summary', 'labels', 'description'] 
      })
    });
    
    if (searchResp.ok) {
      const data = await searchResp.json();
      results?.debug?.searches?.push({ 
        title: f.title.substring(0, 30), 
        fingerprint: f.fingerprint?.substring(0, 20), 
        hits: data.issues?.length || 0 
      });
      
      // Find best match - prioritize fingerprint label match
      if (data.issues && data.issues.length > 0) {
        // Check for exact fingerprint label match first
        for (const issue of data.issues) {
          const labels = issue.fields?.labels || [];
          if (fingerprintLabel && labels.includes(fingerprintLabel)) {
            return issue;
          }
        }
        // Otherwise return first match
        return data.issues[0];
      }
    }
  } catch (e) {
    results?.debug?.searches?.push({ 
      title: f.title.substring(0, 30), 
      error: e.message 
    });
  }
  return null;
}

// ============================================================================
// CREATE NEW ISSUE
// ============================================================================
async function createNewIssue(f, projectKey, issueTypeId, fingerprintLabel, hasDueDate, results) {
  const issueData = {
    fields: {
      project: { key: projectKey },
      issuetype: { id: issueTypeId },
      summary: `[${f.severity}] ${f.title}`.substring(0, 255),
      labels: [fingerprintLabel, `severity-${f.severity.toLowerCase()}`].filter(Boolean),
      description: buildDescription(f)
    }
  };

  // Add assignee if provided (from frontend enrichment)
  if (f.assigneeId) {
    issueData.fields.assignee = { accountId: f.assigneeId };
  }

  // Add due date if enabled and field exists
  if (f.dueDate && hasDueDate) {
    issueData.fields.duedate = f.dueDate;
  }

  // Add priority based on severity (if available)
  // Note: Priority mapping varies by Jira configuration

  const response = await api.asUser().requestJira(route`/rest/api/3/issue`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(issueData)
  });

  if (response.ok) {
    const data = await response.json();
    results.created.push({ 
      key: data.key, 
      id: data.id, 
      title: f.title, 
      severity: f.severity,
      dueDate: f.dueDate,
      status: 'created'
    });
  } else {
    const errText = await response.text();
    let errDetails;
    try { errDetails = JSON.parse(errText); } catch { errDetails = errText; }
    results.failed.push({ 
      title: f.title, 
      error: errDetails?.errors || errDetails?.errorMessages || errDetails || `HTTP ${response.status}` 
    });
  }
}

// ============================================================================
// UPDATE EXISTING ISSUE (DEDUPLICATION)
// ============================================================================
async function updateExistingIssue(existingIssue, f, results) {
  const issueKey = existingIssue.key;
  
  try {
    // Add comment with updated finding information
    const comment = {
      body: {
        version: 1,
        type: 'doc',
        content: [
          { 
            type: 'heading', 
            attrs: { level: 3 }, 
            content: [{ type: 'text', text: '🔄 Updated Finding Report' }] 
          },
          { 
            type: 'paragraph', 
            content: [{ type: 'text', text: `Scan Date: ${new Date().toISOString().split('T')[0]}` }] 
          },
          { 
            type: 'paragraph', 
            content: [{ type: 'text', text: `Scanner: ${f.tool || 'Unknown'}` }] 
          },
          { 
            type: 'paragraph', 
            content: [{ type: 'text', text: `Severity: ${f.severity}` }] 
          },
          ...(f.cvssScore ? [{ 
            type: 'paragraph', 
            content: [{ type: 'text', text: `CVSS: ${f.cvssScore}` }] 
          }] : []),
          ...(f.evidence ? [{ 
            type: 'paragraph', 
            content: [{ type: 'text', text: `Evidence:\n${f.evidence.substring(0, 500)}` }] 
          }] : []),
          { 
            type: 'paragraph', 
            content: [{ 
              type: 'text', 
              text: 'ℹ️ This finding was detected again in the latest scan. The issue already exists in this project.',
              marks: [{ type: 'em' }]
            }] 
          }
        ]
      }
    };

    const commentResp = await api.asUser().requestJira(
      route`/rest/api/3/issue/${issueKey}/comment`,
      {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(comment)
      }
    );

    if (commentResp.ok) {
      results.updated.push({
        key: issueKey,
        title: f.title,
        severity: f.severity,
        status: 'updated'
      });
    } else {
      results.failed.push({
        title: f.title,
        error: `Failed to add comment to ${issueKey}: HTTP ${commentResp.status}`
      });
    }
  } catch (e) {
    results.failed.push({
      title: f.title,
      error: `Error updating ${issueKey}: ${e.message}`
    });
  }
}

// ============================================================================
// BUILD DESCRIPTION DOCUMENT
// ============================================================================
function buildDescription(f) {
  const content = [
    // Title/Summary
    { 
      type: 'heading', 
      attrs: { level: 2 }, 
      content: [{ type: 'text', text: '🔒 Security Finding' }] 
    },
    
    // Description
    { 
      type: 'paragraph', 
      content: [{ type: 'text', text: f.description || 'Security vulnerability detected.' }] 
    },
    
    // Metadata table
    { 
      type: 'heading', 
      attrs: { level: 3 }, 
      content: [{ type: 'text', text: '📋 Details' }] 
    },
    { 
      type: 'paragraph', 
      content: [{ type: 'text', text: `Severity: ${f.severity}`, marks: [{ type: 'strong' }] }] 
    },
  ];

  // Add optional fields
  if (f.cvssScore) {
    content.push({ 
      type: 'paragraph', 
      content: [{ type: 'text', text: `CVSS Score: ${f.cvssScore}` }] 
    });
  }
  
  if (f.cweId) {
    content.push({ 
      type: 'paragraph', 
      content: [{ type: 'text', text: `CWE: CWE-${f.cweId}` }] 
    });
  }
  
  if (f.cveId) {
    content.push({ 
      type: 'paragraph', 
      content: [{ type: 'text', text: `CVE: ${f.cveId}` }] 
    });
  }
  
  if (f.owaspCategory) {
    content.push({ 
      type: 'paragraph', 
      content: [{ type: 'text', text: `OWASP: ${f.owaspCategory}` }] 
    });
  }
  
  if (f.affectedComponent || f.location) {
    content.push({ 
      type: 'heading', 
      attrs: { level: 3 }, 
      content: [{ type: 'text', text: '📍 Location' }] 
    });
    content.push({ 
      type: 'paragraph', 
      content: [{ type: 'text', text: f.affectedComponent || f.location }] 
    });
  }
  
  if (f.evidence) {
    content.push({ 
      type: 'heading', 
      attrs: { level: 3 }, 
      content: [{ type: 'text', text: '🔍 Evidence' }] 
    });
    content.push({ 
      type: 'codeBlock', 
      attrs: { language: 'text' },
      content: [{ type: 'text', text: f.evidence.substring(0, 2000) }] 
    });
  }
  
  if (f.remediation) {
    content.push({ 
      type: 'heading', 
      attrs: { level: 3 }, 
      content: [{ type: 'text', text: '🛠️ Remediation' }] 
    });
    content.push({ 
      type: 'paragraph', 
      content: [{ type: 'text', text: f.remediation }] 
    });
  }
  
  if (f.references && f.references.length > 0) {
    content.push({ 
      type: 'heading', 
      attrs: { level: 3 }, 
      content: [{ type: 'text', text: '📚 References' }] 
    });
    content.push({ 
      type: 'bulletList', 
      content: f.references.slice(0, 5).map(ref => ({
        type: 'listItem',
        content: [{
          type: 'paragraph',
          content: [{ type: 'text', text: ref }]
        }]
      }))
    });
  }
  
  // Fingerprint (for deduplication tracking)
  if (f.fingerprint) {
    content.push({ 
      type: 'paragraph', 
      content: [{ 
        type: 'text', 
        text: `\n---\nFingerprint: ${f.fingerprint}`,
        marks: [{ type: 'code' }]
      }] 
    });
  }

  return {
    version: 1,
    type: 'doc',
    content
  };
}

export const handler = resolver.getDefinitions();
