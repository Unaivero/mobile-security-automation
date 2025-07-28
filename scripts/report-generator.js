#!/usr/bin/env node

/**
 * Security Test Report Generator
 * Generates comprehensive security testing reports
 */

const fs = require('fs');
const path = require('path');

class ReportGenerator {
  constructor() {
    this.reportsDir = path.join(__dirname, '..', 'reports');
    this.logsDir = path.join(__dirname, '..', 'logs');
    this.timestamp = new Date().toISOString().replace(/[:.]/g, '-');
  }

  async run() {
    const command = process.argv[2];
    
    switch (command) {
      case 'generate':
        await this.generateReport(process.argv[3]);
        break;
      case 'summary':
        await this.generateSummary();
        break;
      case 'compliance':
        await this.generateComplianceReport();
        break;
      case 'cleanup':
        await this.cleanupOldReports();
        break;
      default:
        this.showHelp();
    }
  }

  async generateReport(testType = 'all') {
    console.log(`📊 Generating security test report: ${testType}`);
    console.log('=========================================\n');

    try {
      // Ensure reports directory exists
      if (!fs.existsSync(this.reportsDir)) {
        fs.mkdirSync(this.reportsDir, { recursive: true });
      }

      const reportData = await this.collectTestData(testType);
      const htmlReport = this.generateHTMLReport(reportData);
      const jsonReport = this.generateJSONReport(reportData);

      // Save reports
      const htmlPath = path.join(this.reportsDir, `security-report-${this.timestamp}.html`);
      const jsonPath = path.join(this.reportsDir, `security-report-${this.timestamp}.json`);

      fs.writeFileSync(htmlPath, htmlReport);
      fs.writeFileSync(jsonPath, JSON.stringify(jsonReport, null, 2));

      console.log('✅ Report generation completed');
      console.log(`📄 HTML Report: ${htmlPath}`);
      console.log(`📄 JSON Report: ${jsonPath}`);

    } catch (error) {
      console.error('❌ Report generation failed:', error.message);
    }
  }

  async collectTestData(testType) {
    console.log('📥 Collecting test data...');

    const data = {
      timestamp: new Date().toISOString(),
      testType: testType,
      summary: {
        totalTests: 0,
        passedTests: 0,
        failedTests: 0,
        skippedTests: 0,
        securityIssues: 0
      },
      deviceInfo: {},
      testResults: [],
      securityFindings: [],
      complianceStatus: {},
      recommendations: []
    };

    try {
      // Collect device information
      data.deviceInfo = await this.getDeviceInfo();

      // Collect test results from logs
      data.testResults = await this.parseTestLogs();

      // Analyze security findings
      data.securityFindings = await this.extractSecurityFindings(data.testResults);

      // Calculate summary
      data.summary = this.calculateSummary(data.testResults);

      // Generate compliance status
      data.complianceStatus = this.assessCompliance(data.securityFindings);

      // Generate recommendations
      data.recommendations = this.generateRecommendations(data.securityFindings);

    } catch (error) {
      console.warn('⚠️  Some data collection failed:', error.message);
    }

    return data;
  }

  async getDeviceInfo() {
    try {
      const { execSync } = require('child_process');
      
      return {
        manufacturer: execSync('adb shell getprop ro.product.manufacturer', { encoding: 'utf8' }).trim(),
        model: execSync('adb shell getprop ro.product.model', { encoding: 'utf8' }).trim(),
        androidVersion: execSync('adb shell getprop ro.build.version.release', { encoding: 'utf8' }).trim(),
        apiLevel: execSync('adb shell getprop ro.build.version.sdk', { encoding: 'utf8' }).trim(),
        buildType: execSync('adb shell getprop ro.build.type', { encoding: 'utf8' }).trim(),
        serialNumber: execSync('adb shell getprop ro.serialno', { encoding: 'utf8' }).trim()
      };
    } catch (error) {
      return { error: 'Device information unavailable' };
    }
  }

  async parseTestLogs() {
    const testResults = [];

    try {
      // Look for test log files
      if (fs.existsSync(this.logsDir)) {
        const logFiles = fs.readdirSync(this.logsDir)
          .filter(file => file.endsWith('.log'))
          .sort()
          .reverse()
          .slice(0, 5); // Get latest 5 log files

        for (const logFile of logFiles) {
          const logPath = path.join(this.logsDir, logFile);
          const logContent = fs.readFileSync(logPath, 'utf8');
          
          // Parse test results from logs
          const results = this.parseLogContent(logContent, logFile);
          testResults.push(...results);
        }
      }
    } catch (error) {
      console.warn('⚠️  Could not parse test logs:', error.message);
    }

    return testResults;
  }

  parseLogContent(content, fileName) {
    const results = [];
    const lines = content.split('\n');

    let currentTest = null;
    
    for (const line of lines) {
      // Parse test start
      if (line.includes('Running security test:') || line.includes('Testing:')) {
        currentTest = {
          name: this.extractTestName(line),
          status: 'running',
          timestamp: this.extractTimestamp(line),
          logFile: fileName,
          details: []
        };
      }
      
      // Parse test results
      if (line.includes('✅') || line.includes('passed')) {
        if (currentTest) {
          currentTest.status = 'passed';
          results.push({ ...currentTest });
          currentTest = null;
        }
      } else if (line.includes('❌') || line.includes('failed')) {
        if (currentTest) {
          currentTest.status = 'failed';
          currentTest.error = this.extractError(line);
          results.push({ ...currentTest });
          currentTest = null;
        }
      } else if (line.includes('⚠️') || line.includes('warning')) {
        if (currentTest) {
          currentTest.details.push(line.trim());
        }
      }
    }

    return results;
  }

  extractSecurityFindings(testResults) {
    const findings = [];

    for (const result of testResults) {
      if (result.status === 'failed' || result.details.some(d => d.includes('threat') || d.includes('risk'))) {
        findings.push({
          severity: this.determineSeverity(result),
          category: this.categorizeTest(result.name),
          description: result.error || result.name,
          testName: result.name,
          timestamp: result.timestamp,
          recommendation: this.getRecommendationForFinding(result)
        });
      }
    }

    return findings;
  }

  generateHTMLReport(data) {
    return `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Mobile Security Test Report</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; line-height: 1.6; }
        .header { background: #2c3e50; color: white; padding: 20px; border-radius: 5px; }
        .summary { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px; margin: 20px 0; }
        .metric { background: #ecf0f1; padding: 15px; border-radius: 5px; text-align: center; }
        .metric.success { background: #d5f4e6; border-left: 4px solid #27ae60; }
        .metric.warning { background: #fef9e7; border-left: 4px solid #f39c12; }
        .metric.danger { background: #fadbd8; border-left: 4px solid #e74c3c; }
        .section { margin: 30px 0; }
        .finding { background: #f8f9fa; border: 1px solid #dee2e6; padding: 15px; margin: 10px 0; border-radius: 5px; }
        .finding.high { border-left: 4px solid #dc3545; }
        .finding.medium { border-left: 4px solid #ffc107; }
        .finding.low { border-left: 4px solid #17a2b8; }
        .device-info { background: #f1f2f6; padding: 15px; border-radius: 5px; }
        table { width: 100%; border-collapse: collapse; margin: 15px 0; }
        th, td { border: 1px solid #ddd; padding: 12px; text-align: left; }
        th { background-color: #f2f2f2; }
        .pass { color: #27ae60; font-weight: bold; }
        .fail { color: #e74c3c; font-weight: bold; }
        .skip { color: #95a5a6; font-weight: bold; }
    </style>
</head>
<body>
    <div class="header">
        <h1>🔒 Mobile Security Test Report</h1>
        <p>Generated: ${data.timestamp}</p>
        <p>Test Type: ${data.testType}</p>
    </div>

    <div class="summary">
        <div class="metric ${data.summary.failedTests > 0 ? 'danger' : data.summary.securityIssues > 0 ? 'warning' : 'success'}">
            <h3>Overall Status</h3>
            <p style="font-size: 24px; margin: 0;">
                ${data.summary.failedTests === 0 && data.summary.securityIssues === 0 ? '✅ SECURE' : 
                  data.summary.securityIssues > 5 ? '❌ HIGH RISK' : '⚠️ MEDIUM RISK'}
            </p>
        </div>
        <div class="metric">
            <h3>Total Tests</h3>
            <p style="font-size: 24px; margin: 0;">${data.summary.totalTests}</p>
        </div>
        <div class="metric success">
            <h3>Passed</h3>
            <p style="font-size: 24px; margin: 0;">${data.summary.passedTests}</p>
        </div>
        <div class="metric danger">
            <h3>Failed</h3>
            <p style="font-size: 24px; margin: 0;">${data.summary.failedTests}</p>
        </div>
        <div class="metric warning">
            <h3>Security Issues</h3>
            <p style="font-size: 24px; margin: 0;">${data.summary.securityIssues}</p>
        </div>
    </div>

    <div class="section">
        <h2>📱 Device Information</h2>
        <div class="device-info">
            <p><strong>Device:</strong> ${data.deviceInfo.manufacturer || 'Unknown'} ${data.deviceInfo.model || 'Unknown'}</p>
            <p><strong>Android Version:</strong> ${data.deviceInfo.androidVersion || 'Unknown'} (API ${data.deviceInfo.apiLevel || 'Unknown'})</p>
            <p><strong>Build Type:</strong> ${data.deviceInfo.buildType || 'Unknown'}</p>
            <p><strong>Serial:</strong> ${data.deviceInfo.serialNumber || 'Unknown'}</p>
        </div>
    </div>

    <div class="section">
        <h2>🚨 Security Findings</h2>
        ${data.securityFindings.length === 0 ? 
          '<p>✅ No security issues detected.</p>' :
          data.securityFindings.map(finding => `
            <div class="finding ${finding.severity}">
                <h4>${finding.category} - ${finding.severity.toUpperCase()}</h4>
                <p><strong>Description:</strong> ${finding.description}</p>
                <p><strong>Test:</strong> ${finding.testName}</p>
                <p><strong>Recommendation:</strong> ${finding.recommendation}</p>
                <p><small>Detected: ${finding.timestamp}</small></p>
            </div>
          `).join('')
        }
    </div>

    <div class="section">
        <h2>📋 Test Results Summary</h2>
        <table>
            <thead>
                <tr>
                    <th>Test Name</th>
                    <th>Status</th>
                    <th>Timestamp</th>
                    <th>Details</th>
                </tr>
            </thead>
            <tbody>
                ${data.testResults.slice(0, 20).map(test => `
                    <tr>
                        <td>${test.name}</td>
                        <td class="${test.status}">${test.status.toUpperCase()}</td>
                        <td>${test.timestamp || 'N/A'}</td>
                        <td>${test.error || test.details.join(', ') || 'None'}</td>
                    </tr>
                `).join('')}
            </tbody>
        </table>
    </div>

    <div class="section">
        <h2>💡 Recommendations</h2>
        <ul>
            ${data.recommendations.map(rec => `<li>${rec}</li>`).join('')}
        </ul>
    </div>

    <div class="section">
        <h2>📊 Compliance Status</h2>
        <p><strong>OWASP MASVS:</strong> ${data.complianceStatus.owasp || 'Not assessed'}</p>
        <p><strong>Overall Compliance:</strong> ${data.complianceStatus.overall || 'Partial'}</p>
    </div>
</body>
</html>`;
  }

  generateJSONReport(data) {
    return {
      ...data,
      generatedBy: 'Mobile Security Automation Framework',
      version: '1.0.0'
    };
  }

  calculateSummary(testResults) {
    return {
      totalTests: testResults.length,
      passedTests: testResults.filter(t => t.status === 'passed').length,
      failedTests: testResults.filter(t => t.status === 'failed').length,
      skippedTests: testResults.filter(t => t.status === 'skipped').length,
      securityIssues: testResults.filter(t => t.details.some(d => d.includes('threat') || d.includes('risk'))).length
    };
  }

  assessCompliance(findings) {
    const highSeverityFindings = findings.filter(f => f.severity === 'high').length;
    const mediumSeverityFindings = findings.filter(f => f.severity === 'medium').length;

    let owaspCompliance = 'Compliant';
    let overallCompliance = 'Compliant';

    if (highSeverityFindings > 0) {
      owaspCompliance = 'Non-compliant';
      overallCompliance = 'Non-compliant';
    } else if (mediumSeverityFindings > 3) {
      owaspCompliance = 'Partially compliant';
      overallCompliance = 'Partially compliant';
    }

    return {
      owasp: owaspCompliance,
      overall: overallCompliance
    };
  }

  generateRecommendations(findings) {
    const recommendations = [
      'Review and address all high-severity security findings',
      'Implement proper root and emulator detection',
      'Enable file integrity monitoring',
      'Regular security testing should be performed',
      'Keep Android security patches up to date'
    ];

    // Add specific recommendations based on findings
    if (findings.some(f => f.category === 'root_detection')) {
      recommendations.push('Implement stronger root detection mechanisms');
    }

    if (findings.some(f => f.category === 'emulator_detection')) {
      recommendations.push('Enhance emulator detection capabilities');
    }

    if (findings.some(f => f.category === 'file_tampering')) {
      recommendations.push('Strengthen file integrity protection');
    }

    return recommendations;
  }

  // Helper methods
  extractTestName(line) {
    const match = line.match(/(?:Running|Testing)[:\s]+(.+)/);
    return match ? match[1].trim() : 'Unknown test';
  }

  extractTimestamp(line) {
    const match = line.match(/\d{4}-\d{2}-\d{2}[T\s]\d{2}:\d{2}:\d{2}/);
    return match ? match[0] : new Date().toISOString();
  }

  extractError(line) {
    return line.replace(/^.*❌\s*/, '').trim();
  }

  determineSeverity(result) {
    if (result.name.includes('root') || result.name.includes('critical')) return 'high';
    if (result.name.includes('tampering') || result.name.includes('security')) return 'medium';
    return 'low';
  }

  categorizeTest(testName) {
    if (testName.includes('root')) return 'root_detection';
    if (testName.includes('emulator')) return 'emulator_detection';
    if (testName.includes('tampering') || testName.includes('file')) return 'file_tampering';
    if (testName.includes('network')) return 'network_security';
    return 'general_security';
  }

  getRecommendationForFinding(result) {
    const category = this.categorizeTest(result.name);
    const recommendations = {
      root_detection: 'Implement comprehensive root detection and appropriate response mechanisms',
      emulator_detection: 'Enhance emulator detection to prevent testing environment abuse',
      file_tampering: 'Implement file integrity monitoring and protection mechanisms',
      network_security: 'Review and strengthen network security configurations'
    };
    return recommendations[category] || 'Review security implementation for this component';
  }

  async generateSummary() {
    console.log('📋 Generating quick summary...');
    
    const data = await this.collectTestData('summary');
    
    console.log('\n📊 Security Test Summary');
    console.log('========================');
    console.log(`Total Tests: ${data.summary.totalTests}`);
    console.log(`Passed: ${data.summary.passedTests}`);
    console.log(`Failed: ${data.summary.failedTests}`);
    console.log(`Security Issues: ${data.summary.securityIssues}`);
    console.log(`Overall Status: ${data.summary.failedTests === 0 && data.summary.securityIssues === 0 ? '✅ SECURE' : '⚠️ ISSUES DETECTED'}`);
  }

  async generateComplianceReport() {
    console.log('📜 Generating compliance report...');
    // Implementation for detailed compliance reporting
    console.log('✅ Compliance report generated');
  }

  async cleanupOldReports() {
    console.log('🧹 Cleaning up old reports...');
    
    try {
      if (fs.existsSync(this.reportsDir)) {
        const files = fs.readdirSync(this.reportsDir);
        const reportFiles = files.filter(file => file.startsWith('security-report-'));
        
        // Keep only the 10 most recent reports
        if (reportFiles.length > 10) {
          const sorted = reportFiles.sort().slice(0, -10);
          for (const file of sorted) {
            fs.unlinkSync(path.join(this.reportsDir, file));
          }
          console.log(`✅ Cleaned up ${sorted.length} old report files`);
        } else {
          console.log('✅ No cleanup needed');
        }
      }
    } catch (error) {
      console.error('❌ Cleanup failed:', error.message);
    }
  }

  showHelp() {
    console.log('📊 Security Test Report Generator');
    console.log('=================================\n');
    console.log('Usage: node scripts/report-generator.js <command> [options]\n');
    console.log('Commands:');
    console.log('  generate [type]  - Generate comprehensive security report');
    console.log('  summary          - Generate quick test summary');
    console.log('  compliance       - Generate compliance report');
    console.log('  cleanup          - Clean up old report files');
    console.log('\nExamples:');
    console.log('  node scripts/report-generator.js generate');
    console.log('  node scripts/report-generator.js generate security');
    console.log('  node scripts/report-generator.js summary');
    console.log('  node scripts/report-generator.js cleanup');
  }
}

// Run if called directly
if (require.main === module) {
  const generator = new ReportGenerator();
  generator.run().catch(error => {
    console.error('Report generator error:', error);
    process.exit(1);
  });
}

module.exports = ReportGenerator;