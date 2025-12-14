# 🔒 Security Findings Mapper

> **Codegeist 2025** | Apps for Software Teams | Built on Forge

**One-click import of security audit findings into Jira.**

Parse SARIF, Snyk, Semgrep, Trivy, or plain text → auto-create Jira issues with severity, CVSS, CWE, labels, and due dates.

---

## 🎯 The Problem

Security audits produce 50+ findings in reports. Teams manually copy each into Jira:

- **6-8 hours wasted** per audit
- **Inconsistent data** - missing severity, wrong labels
- **Delayed sprints** waiting for ticket creation

## 💡 The Solution

**Paste → Parse → Create. Done in 30 seconds.**

1. Paste your security report (SARIF, JSON, CSV, or text)
2. Review parsed findings with auto-detected metadata
3. Click "Create Issues" - all Jira tickets created instantly

**Time saved: 6-8 hours → 30 seconds**

---

## ✨ Features

- **Auto-detect format** - SARIF, Snyk, Semgrep, Trivy, CSV, plain text
- **Extract metadata** - Severity, CVSS score, CWE ID, CVE, OWASP category
- **Rich Jira issues** - Structured descriptions, labels, priorities, due dates
- **Bulk import** - Select which findings to import

### Created Issues Include:

```
Summary: [CRITICAL] SQL Injection in /api/login
Labels: security-finding, critical, cwe-89, owasp-a03
Priority: Highest
Due Date: +3 days (auto-calculated from severity)
Description: Full finding details + remediation steps
```

---

## 🚀 Quick Start

```bash
cd security-findings-mapper

# Install dependencies
npm install

# Login to Forge
forge login

# Register (first time only)
forge register

# Deploy
forge deploy

# Install on your Jira site
forge install
```

---

## 📁 Project Structure

```
security-findings-mapper/
├── manifest.yml           # Forge configuration
├── package.json           # Dependencies
├── src/
│   ├── index.js           # Backend (Jira API)
│   ├── parser.js          # Multi-format parser
│   └── frontend/
│       └── index.jsx      # React UI
└── samples/               # Test files
    ├── sarif-example.json
    ├── snyk-example.json
    └── ...
```

---

## 🎬 Demo (2 minutes)

**0:00-0:15** - "Security audits waste 6 hours copying findings to Jira"

**0:15-0:45** - Paste SARIF JSON, click Parse

**0:45-1:15** - Show parsed findings with severity badges, CVSS scores

**1:15-1:45** - Click Create, show issues appearing in Jira

**1:45-2:00** - "30 seconds. Done."

---

## 📊 Supported Formats

| Format | Source |
|--------|--------|
| SARIF | GitHub CodeQL, Semgrep, SAST tools |
| Snyk JSON | Snyk vulnerability reports |
| Semgrep JSON | Semgrep SAST output |
| Trivy JSON | Trivy container scans |
| CSV | Any scanner export |
| Plain Text | Manual audit reports |

---

## 🏆 Submission Info

- **Category**: Apps for Software Teams
- **Bonus**: Runs on Atlassian eligible
- **Built with**: Forge, React, Jira REST API

---

## 📄 License

MIT

---

Built for **Codegeist 2025: Atlassian Williams Racing Edition** 🏎️
