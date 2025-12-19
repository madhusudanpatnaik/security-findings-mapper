# 🛡️ Security Findings Mapper

![Security Findings Mapper Banner](images/banner.png)

> **Transform security scan chaos into actionable Jira issues in seconds**

[![Built on Forge](https://img.shields.io/badge/Built%20on-Atlassian%20Forge-0052CC?logo=atlassian)](https://developer.atlassian.com/platform/forge/)
[![Codegeist 2025](https://img.shields.io/badge/Codegeist-2025-FF5630)](https://codegeist.devpost.com/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

---

## 📋 Project Summary

| | |
|---|---|
| **Project Name** | Security Findings Mapper |
| **Elevator Pitch** | Paste any security scan → instantly create Jira issues with severity, SLA, and auto-assignment |

---

## 🎯 The Problem

Security audits produce 50–200+ findings in various formats. Teams manually copy each into Jira:

- ⏱️ **6–8 hours wasted** per audit transcribing findings
- 🔀 **Inconsistent data** — missing severity, wrong labels, no CWE/CVE
- 🐢 **Delayed sprints** waiting for security tickets
- 📉 **No SLA tracking** — critical vulnerabilities sit unfixed

## 💡 The Solution

**Paste → Preview → Create. Done in 30 seconds.**

1. 📥 **Upload** — Paste security scan output (SARIF, Snyk, Semgrep, Trivy, Burp, CSV, or plain text)
2. ⚙️ **Configure** — Filter findings, auto-assign by severity, set SLA due dates
3. 🚀 **Create** — Bulk-create deduplicated Jira issues with full metadata

**Result: 6–8 hours → 30 seconds. Zero copy-paste errors.**

---

## ✨ Key Features

| Feature | Description |
|---------|-------------|
| 🔍 **Multi-format parser** | Auto-detects SARIF, Snyk, Semgrep, Trivy, Burp XML, CSV, plain text |
| 📊 **Rich metadata** | Severity, CVSS, CWE/CVE, file location, evidence snippets, remediation |
| 🔄 **Deduplication** | Fingerprint-based matching prevents duplicate issues |
| 👤 **Auto-assignment** | Assign different team members per severity level |
| ⏰ **SLA due dates** | Configure days-to-fix per severity (Critical=1d, High=7d, etc.) |
| 🎨 **Modern UI** | Guided 3-step flow with filtering, quick-select, and progress tracking |

### Example Created Issue

```
Summary: [HIGH] SQL Injection in /api/login
Labels: security-finding, CWE-89, HIGH
Description:
  • Severity: HIGH (CVSS 8.1)
  • CWE: CWE-89 (SQL Injection)
  • Location: src/db/queries.js:45
  • Evidence: SELECT * FROM users WHERE id = ${userId}
  • Remediation: Use parameterized queries
Due Date: 7 days from import (configurable)
```

---

## 🚀 Quick Start

```bash
# Clone and install
cd security-findings-mapper
npm install

# Login to Forge CLI
forge login

# Deploy to production
forge deploy -e production

# Install on your Jira site
forge install -e production
```

Then open any Jira project → **Apps** → **Security Findings Mapper**

---

## 📁 Project Structure

```
security-findings-mapper/
├── manifest.yml              # Forge app manifest
├── package.json              # Dependencies
├── .eslintrc.cjs             # Linting config
├── src/
│   ├── parser.js             # Multi-format security findings parser
│   ├── resolver.js           # Backend resolvers (Jira REST API)
│   └── frontend/
│       └── index.jsx         # React UI (UI Kit 2)
└── samples/                  # Test files for all supported formats
    ├── sarif-example.json
    ├── snyk-example.json
    ├── semgrep-example.json
    ├── trivy-example.json
    ├── csv-example.csv
    └── plain-text-example.txt
```

---

## 🎬 How It Works

```
┌─────────────┐     ┌─────────────┐     ┌─────────────┐
│   UPLOAD    │ ──▶ │  CONFIGURE  │ ──▶ │   RESULTS   │
│             │     │             │     │             │
│ Paste scan  │     │ Filter,     │     │ Created: 12 │
│ output      │     │ assign,     │     │ Updated: 3  │
│             │     │ set SLA     │     │ Failed: 0   │
└─────────────┘     └─────────────┘     └─────────────┘
```

1. **Upload** — Paste security scan JSON/CSV/text
2. **Configure** — Select findings, set assignees per severity, configure SLA
3. **Results** — View created/deduplicated issues with direct links

---

## 📊 Supported Formats

| Format | Source | Example |
|--------|--------|---------|
| **SARIF** | GitHub CodeQL, Semgrep, most SAST tools | `sarif-example.json` |
| **Snyk JSON** | Snyk CLI / Web exports | `snyk-example.json` |
| **Semgrep JSON** | Semgrep SAST output | `semgrep-example.json` |
| **Trivy JSON** | Trivy container/image scans | `trivy-example.json` |
| **Burp XML** | Burp Suite scan exports | — |
| **CSV** | Any scanner with CSV export | `csv-example.csv` |
| **Plain Text** | Manual audit reports, bullet lists | `plain-text-example.txt` |

---

## 🔧 Technical Details

| | |
|---|---|
| **Platform** | Atlassian Forge |
| **UI Framework** | UI Kit 2 (`@forge/react`) |
| **Runtime** | Node.js 22.x |
| **API** | Jira REST API v3 |

### Permissions

| Scope | Purpose |
|-------|---------|
| `read:jira-work` | Read project info |
| `write:jira-work` | Create/update issues |
| `read:jira-user` | Load assignable users |
| `manage:jira-project` | Access project settings |

---

## 🏆 Codegeist 2025

| | |
|---|---|
| **Category** | Apps for Software Teams |
| **Submission** | Codegeist 2025: Atlassian Williams Racing Edition 🏎️ |
| **Built with** | Forge, React, Jira REST API |

---

## 📄 License

MIT — free to use, modify, and distribute.

---

**Built for Codegeist 2025** 🏁
