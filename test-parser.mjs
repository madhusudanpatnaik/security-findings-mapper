/**
 * Test script to validate the parser works correctly
 * Run with: node test-parser.mjs
 */

import { readFileSync } from 'fs';
import { parseSecurityFindings } from './src/parser.js';

console.log('🔍 Testing Security Findings Parser\n');
console.log('='.repeat(60));

const testFiles = [
  { file: 'samples/sarif-example.json', format: 'sarif' },
  { file: 'samples/snyk-example.json', format: 'snyk' },
  { file: 'samples/semgrep-example.json', format: 'semgrep' },
  { file: 'samples/trivy-example.json', format: 'trivy' },
  { file: 'samples/csv-example.csv', format: 'csv' },
  { file: 'samples/plain-text-example.txt', format: 'text' },
];

let totalTests = 0;
let passedTests = 0;
let failedTests = 0;

for (const test of testFiles) {
  totalTests++;
  console.log(`\n📄 Testing: ${test.file}`);
  console.log('-'.repeat(40));
  
  try {
    const content = readFileSync(test.file, 'utf-8');
    const findings = parseSecurityFindings(content, test.format);
    
    if (findings.length === 0) {
      console.log('⚠️  WARNING: No findings parsed!');
      failedTests++;
    } else {
      console.log(`✅ PASSED: Parsed ${findings.length} findings`);
      passedTests++;
      
      // Show summary
      const summary = {
        critical: findings.filter(f => f.severity === 'CRITICAL').length,
        high: findings.filter(f => f.severity === 'HIGH').length,
        medium: findings.filter(f => f.severity === 'MEDIUM').length,
        low: findings.filter(f => f.severity === 'LOW').length,
        info: findings.filter(f => f.severity === 'INFO').length,
      };
      console.log(`   Severity: C:${summary.critical} H:${summary.high} M:${summary.medium} L:${summary.low} I:${summary.info}`);
      
      // Show first finding as sample
      const first = findings[0];
      console.log(`   Sample finding:`);
      console.log(`     Title: ${first.title?.substring(0, 50)}...`);
      console.log(`     Severity: ${first.severity}`);
      console.log(`     CVSS: ${first.cvssScore || 'N/A'}`);
      console.log(`     CWE: ${first.cweId ? 'CWE-' + first.cweId : 'N/A'}`);
      console.log(`     Location: ${first.location?.substring(0, 40) || 'N/A'}`);
    }
  } catch (error) {
    console.log(`❌ FAILED: ${error.message}`);
    failedTests++;
  }
}

// Test auto-detect
console.log('\n' + '='.repeat(60));
console.log('\n🔄 Testing Auto-Detection');
console.log('-'.repeat(40));

try {
  const sarifContent = readFileSync('samples/sarif-example.json', 'utf-8');
  const findings = parseSecurityFindings(sarifContent, 'auto');
  if (findings.length > 0) {
    console.log(`✅ Auto-detect SARIF: ${findings.length} findings`);
    passedTests++;
  } else {
    console.log('⚠️  Auto-detect SARIF: No findings');
    failedTests++;
  }
  totalTests++;
} catch (error) {
  console.log(`❌ Auto-detect SARIF failed: ${error.message}`);
  failedTests++;
  totalTests++;
}

// Final summary
console.log('\n' + '='.repeat(60));
console.log('\n📊 FINAL RESULTS');
console.log(`   Total: ${totalTests}`);
console.log(`   Passed: ${passedTests}`);
console.log(`   Failed: ${failedTests}`);
console.log(`   Success Rate: ${((passedTests / totalTests) * 100).toFixed(1)}%`);

if (failedTests > 0) {
  console.log('\n❌ SOME TESTS FAILED - FIX BEFORE DEPLOYMENT');
  process.exit(1);
} else {
  console.log('\n✅ ALL TESTS PASSED - READY FOR DEPLOYMENT');
  process.exit(0);
}

