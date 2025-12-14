# 🚀 Setup Guide - Security Findings Mapper

Complete step-by-step instructions to deploy and run the Security Findings Mapper for Codegeist 2025.

---

## Prerequisites

### 1. Install Node.js 18+

```bash
# Check your Node version
node --version  # Should be v18.x or higher

# If not installed, download from https://nodejs.org/
# Or use nvm:
nvm install 18
nvm use 18
```

### 2. Install Atlassian Forge CLI

```bash
npm install -g @forge/cli

# Verify installation
forge --version
```

### 3. Create Atlassian Developer Account

1. Go to https://developer.atlassian.com/
2. Sign up or sign in
3. Create a new cloud developer instance (free)
   - This gives you Jira + Confluence sandbox

---

## Deployment Steps

### Step 1: Clone and Setup

```bash
cd security-findings-mapper

# Install dependencies
npm install
```

### Step 2: Login to Forge

```bash
forge login
```

This will:
1. Open your browser
2. Ask you to authorize the Forge CLI
3. Generate an API token

### Step 3: Register the App

If this is the first deploy, you need to register the app:

```bash
forge register
```

This creates a unique app ID in your manifest.yml.

### Step 4: Deploy to Development

```bash
forge deploy -e development
```

Expected output:
```
Deploying your app to the development environment.
Deployed to development.
```

### Step 5: Install on Your Jira Instance

```bash
forge install -e development
```

Select your development site when prompted.

### Step 6: Test the App

1. Open your Jira instance
2. Go to any project
3. You should see "Security Findings Mapper" in:
   - Project sidebar (Project Page)
   - Issue panel (when viewing an issue)

---

## Development Mode (Hot Reload)

For development with live updates:

```bash
forge tunnel
```

This creates a tunnel so your local code runs instead of the deployed version.

---

## Production Deployment

### Step 1: Deploy to Production

```bash
forge deploy -e production
```

### Step 2: Enable App Sharing

1. Go to https://developer.atlassian.com/console/myapps/
2. Select "security-findings-mapper"
3. Click "Distribution" in the left menu
4. Under "Distribution controls", click "Edit"
5. Select "Sharing" option
6. Fill in app details:
   - App name: Security Findings Mapper
   - Short description: Parse security audit reports and auto-create Jira issues
   - App icon: (optional)
7. Click "Save changes"
8. Select which Atlassian apps to support (Jira)
9. Copy the installation link

### Step 3: Share Installation Link

The installation link format:
```
https://developer.atlassian.com/console/install/<your-app-id>
```

Share this with judges and testers.

---

## Troubleshooting

### "Permission denied" errors

Make sure your manifest.yml has these scopes:
```yaml
permissions:
  scopes:
    - read:jira-work
    - write:jira-work
    - read:jira-user
    - manage:jira-project
```

After adding scopes, redeploy:
```bash
forge deploy
```

### "Module not found" errors

```bash
# Clear and reinstall
rm -rf node_modules
npm install
forge deploy
```

### App not appearing in Jira

1. Check installation: `forge install --upgrade`
2. Hard refresh Jira (Cmd+Shift+R / Ctrl+Shift+F5)
3. Check browser console for errors

### Tunnel not connecting

```bash
# Kill existing tunnel
pkill -f "forge tunnel"

# Restart
forge tunnel
```

---

## Submission Checklist

### Required for Codegeist 2025

- [ ] App deployed to production environment
- [ ] Sharing enabled with installation link
- [ ] Demo video recorded (under 5 minutes)
- [ ] Video uploaded to YouTube/Vimeo (public)
- [ ] Category selected: "Apps for Software Teams"
- [ ] Bonus prizes indicated (if applicable)
- [ ] App ID copied from Developer Console
- [ ] Devpost submission form completed

### Demo Video Tips

1. **Start strong** - Show the problem (manual ticket creation pain)
2. **Quick demo** - Paste report → parse → create issues
3. **Highlight features** - Multi-format support, CVSS/CWE extraction
4. **Show results** - Created Jira issues with rich metadata
5. **End with impact** - "6 hours → 30 seconds"

### Getting Your App ID

1. Go to https://developer.atlassian.com/console/myapps/
2. Click on your app
3. App ID is in the URL: `https://developer.atlassian.com/console/myapps/<APP_ID>/`

---

## Bonus Prize Eligibility

### "Runs on Atlassian" Bonus ($2,000)

Your app qualifies if it:
- ✅ Built on Forge
- ✅ Uses Atlassian product APIs
- ✅ Ready for Marketplace listing

To verify:
1. Go to Developer Console → your app → Distribution
2. Ensure "Sharing" is enabled
3. Verify all scopes are properly declared

### Submission Note for Runs on Atlassian

Add this to your Devpost submission:
> "This app meets Runs on Atlassian requirements: built on Forge, uses Jira REST API for issue creation, and is ready for Marketplace distribution with sharing enabled."

---

## Quick Commands Reference

```bash
# Deploy
forge deploy                    # Deploy to development
forge deploy -e production      # Deploy to production

# Install
forge install                   # Install on site
forge install --upgrade         # Upgrade installation

# Development
forge tunnel                    # Live development mode
forge logs                      # View app logs

# Info
forge whoami                    # Check logged in account
forge settings                  # View current settings
```

---

## Support

- Forge Documentation: https://developer.atlassian.com/platform/forge/
- Atlassian Developer Community: https://community.developer.atlassian.com/
- Codegeist 2025 FAQ: https://codegeist.devpost.com/

---

Good luck with your submission! 🏆

