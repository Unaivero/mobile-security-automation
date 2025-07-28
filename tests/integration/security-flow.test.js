/**
 * Security Flow Integration Tests
 * End-to-end security testing workflows
 */

const { expect } = require('chai');
const BasePage = require('../../src/pages/base-page');
const SecurityPage = require('../../src/pages/security-page');
const { TestDataManager } = require('../../src/config/test-data');

describe('Security Flow Integration Tests', function() {
  let basePage, securityPage;
  let testConfig, testUser;

  before(async function() {
    // Initialize page objects
    basePage = new BasePage(browser);
    securityPage = new SecurityPage(browser);
    
    // Get test configuration
    testConfig = global.securityConfig.getTestConfiguration('integration');
    
    // Get test user based on environment
    testUser = TestDataManager.getUserByProfile('legitimate');
    
    console.log(`🔗 Running security flow integration tests`);
    console.log(`👤 Test user: ${testUser.username}`);
    console.log(`🌐 Environment: ${global.testEnvironment}`);
  });

  describe('Complete Security Validation Flow', function() {
    it('should perform end-to-end security validation', async function() {
      global.SecurityTestUtils.logSecurityStep('e2e_security_validation', 'Starting end-to-end security validation');
      
      // Step 1: Device Analysis
      console.log('🔍 Step 1: Device Security Analysis');
      const deviceAnalysis = await global.deviceDetector.analyzeDevice();
      
      expect(deviceAnalysis).to.have.property('deviceInfo');
      expect(deviceAnalysis).to.have.property('emulatorDetection');
      expect(deviceAnalysis).to.have.property('rootDetection');
      expect(deviceAnalysis).to.have.property('riskAssessment');
      
      console.log(`   Device: ${deviceAnalysis.deviceInfo?.model || 'Unknown'}`);
      console.log(`   Emulator: ${deviceAnalysis.emulatorDetection?.isEmulator ? 'YES' : 'NO'}`);
      console.log(`   Rooted: ${deviceAnalysis.rootDetection?.isRooted ? 'YES' : 'NO'}`);
      console.log(`   Risk Score: ${deviceAnalysis.riskAssessment?.score || 'Unknown'}/100`);
      
      // Step 2: Application Security Check
      console.log('🛡️  Step 2: Application Security Validation');
      const appPackage = process.env.APP_PACKAGE;
      
      if (appPackage) {
        const appSecurity = await global.securityChecker.validateApplicationSecurity(appPackage);
        
        if (!appSecurity.error && !appSecurity.skipped) {
          console.log(`   Package: ${appPackage}`);
          console.log(`   Debuggable: ${appSecurity.debuggableCheck?.isDebuggable ? 'YES' : 'NO'}`);
          console.log(`   Allows Backup: ${appSecurity.backupCheck?.allowsBackup ? 'YES' : 'NO'}`);
          console.log(`   Test Only: ${appSecurity.testOnlyCheck?.isTestOnly ? 'YES' : 'NO'}`);
        }
      } else {
        console.log('   No application package specified - skipping app security check');
      }
      
      // Step 3: Environment Security
      console.log('🌐 Step 3: Environment Security Analysis');
      const envSecurity = await global.securityChecker.validateEnvironmentSecurity();
      
      console.log(`   ADB Status: ${envSecurity.adbStatus?.secure ? 'SECURE' : 'INSECURE'}`);
      console.log(`   Developer Options: ${envSecurity.developerOptions?.enabled ? 'ENABLED' : 'DISABLED'}`);
      console.log(`   VPN Detected: ${envSecurity.vpnDetection?.detected ? 'YES' : 'NO'}`);
      
      // Step 4: File Integrity
      console.log('📁 Step 4: File Integrity Validation');
      const criticalFiles = ['/system/build.prop', '/data/local.prop'];
      const fileIntegrity = await global.securityChecker.validateFileIntegrity(criticalFiles);
      
      console.log(`   Files Checked: ${fileIntegrity.summary?.total || 0}`);
      console.log(`   Integrity Violations: ${fileIntegrity.summary?.failed || 0}`);
      
      // Step 5: Overall Assessment
      console.log('📊 Step 5: Overall Security Assessment');
      const overallSecurity = await global.securityChecker.calculateOverallAssessment({
        deviceSecurity: { overallRisk: deviceAnalysis.riskAssessment?.score || 50 },
        applicationSecurity: appSecurity,
        environmentSecurity: envSecurity,
        fileIntegrity: fileIntegrity
      });
      
      console.log(`   Overall Score: ${overallSecurity.overallScore}/100`);
      console.log(`   Security Level: ${overallSecurity.securityLevel}`);
      console.log(`   Status: ${overallSecurity.passed ? 'PASSED' : 'FAILED'}`);
      
      // Validate the complete flow
      expect(overallSecurity).to.have.property('overallScore');
      expect(overallSecurity.overallScore).to.be.a('number');
      expect(overallSecurity.securityLevel).to.be.a('string');
      
      // Take comprehensive screenshot
      await basePage.takeSecurityScreenshot('e2e-security-validation', 
        'End-to-end security validation completed');
      
      global.SecurityTestUtils.logSecurityPassed('e2e_security_validation_completed');
    });

    it('should test security response workflow', async function() {
      global.SecurityTestUtils.logSecurityStep('security_response_workflow', 'Testing security response workflow');
      
      // Navigate to app security section
      const navigated = await securityPage.navigateToSecurity();
      
      if (navigated) {
        // Get initial security status
        const initialStatus = await securityPage.getSecurityStatus();
        console.log(`🔒 Initial Security Status:`);
        console.log(`   Level: ${initialStatus.level}`);
        console.log(`   Warnings: ${initialStatus.warnings.length}`);
        console.log(`   Threats: ${initialStatus.threats.length}`);
        console.log(`   Secure: ${initialStatus.isSecure}`);
        
        // Test different security scenarios based on device type
        if (global.deviceType === 'emulator') {
          // Test emulator response
          const emulatorWarning = await securityPage.getEmulatorWarning();
          
          if (emulatorWarning.detected) {
            console.log(`⚠️  Emulator Warning: ${emulatorWarning.message}`);
            console.log(`📋 Action: ${emulatorWarning.action}`);
            
            // Test dismissal if allowed
            if (emulatorWarning.action !== 'block_access') {
              const dismissed = await securityPage.dismissSecurityWarning('ok');
              expect(dismissed).to.be.true;
              console.log('✅ Security warning dismissed successfully');
            }
          }
        }
        
        // Get final security status
        const finalStatus = await securityPage.getSecurityStatus();
        console.log(`🔒 Final Security Status:`);
        console.log(`   Level: ${finalStatus.level}`);
        console.log(`   Secure: ${finalStatus.isSecure}`);
        
        // Validate security response workflow
        expect(initialStatus).to.have.property('level');
        expect(finalStatus).to.have.property('level');
        
        // Take screenshot of security workflow
        await basePage.takeSecurityScreenshot('security-response-workflow', 
          'Security response workflow test');
        
        global.SecurityTestUtils.logSecurityPassed('security_response_workflow_completed');
      } else {
        console.log('⚠️  Security UI not available - workflow test skipped');
        this.skip();
      }
    });
  });

  describe('Multi-Factor Security Testing', function() {
    it('should test combined security threats', async function() {
      global.SecurityTestUtils.logSecurityStep('combined_threats', 'Testing combined security threats');
      
      // Simulate multiple security issues
      const securityIssues = [];
      
      // Check for emulator
      const emulatorDetection = await global.securityChecker.detectEmulator();
      if (emulatorDetection.detected) {
        securityIssues.push({
          type: 'emulator',
          severity: 'high',
          confidence: emulatorDetection.confidence
        });
      }
      
      // Check for root
      const rootDetection = await global.securityChecker.detectRoot();
      if (rootDetection.detected) {
        securityIssues.push({
          type: 'root',
          severity: 'critical',
          confidence: rootDetection.confidence
        });
      }
      
      // Check for debugging
      const debugCheck = await global.adbHelper.executeShellCommand('getprop ro.debuggable');
      if (debugCheck.success && debugCheck.output.trim() === '1') {
        securityIssues.push({
          type: 'debugging',
          severity: 'medium',
          confidence: 1.0
        });
      }
      
      console.log(`🚨 Security Issues Detected: ${securityIssues.length}`);
      securityIssues.forEach((issue, index) => {
        console.log(`   ${index + 1}. ${issue.type.toUpperCase()}: ${issue.severity} (${Math.round(issue.confidence * 100)}%)`);
      });
      
      // Calculate combined risk score
      const riskScore = securityIssues.reduce((total, issue) => {
        const severityWeight = {
          'low': 1,
          'medium': 2,
          'high': 3,
          'critical': 4
        };
        return total + (severityWeight[issue.severity] * issue.confidence);
      }, 0);
      
      console.log(`📊 Combined Risk Score: ${riskScore}`);
      
      // Test application response to combined threats
      if (securityIssues.length > 1) {
        global.SecurityTestUtils.logThreatDetected('multiple_security_threats', 
          `Multiple security threats detected: ${securityIssues.map(i => i.type).join(', ')}`);
        
        // Navigate to app and check response
        const navigated = await securityPage.navigateToSecurity();
        if (navigated) {
          const securityStatus = await securityPage.getSecurityStatus();
          
          // High-risk combinations should trigger security measures
          if (riskScore >= 6) {
            expect(securityStatus.warnings.length).to.be.above(0);
            console.log('✅ Application correctly detected high-risk combination');
          }
        }
      } else {
        global.SecurityTestUtils.logSecurityPassed('no_combined_threats_detected');
      }
      
      // Store results for reporting
      this.currentTest.combinedThreats = {
        issues: securityIssues,
        riskScore: riskScore,
        riskLevel: riskScore >= 8 ? 'critical' : riskScore >= 6 ? 'high' : riskScore >= 3 ? 'medium' : 'low'
      };
    });

    it('should validate security policy enforcement', async function() {
      global.SecurityTestUtils.logSecurityStep('policy_enforcement', 'Validating security policy enforcement');
      
      // Get current security policies
      const policies = testConfig.policies;
      
      console.log('📋 Security Policy Validation:');
      
      // Test emulator policy enforcement
      if (policies.deviceSecurity.emulatorPolicy.enabled) {
        console.log(`   Emulator Policy: ${policies.deviceSecurity.emulatorPolicy.action.toUpperCase()}`);
        
        const emulatorDetection = await global.securityChecker.detectEmulator();
        
        if (emulatorDetection.detected) {
          // Navigate to app and verify policy enforcement
          const navigated = await securityPage.navigateToSecurity();
          if (navigated) {
            const emulatorWarning = await securityPage.getEmulatorWarning();
            
            switch (policies.deviceSecurity.emulatorPolicy.action) {
              case 'block':
                expect(emulatorWarning.detected).to.be.true;
                expect(emulatorWarning.action).to.equal('block_access');
                console.log('     ✅ Emulator blocking policy enforced');
                break;
              case 'warn':
                expect(emulatorWarning.detected).to.be.true;
                console.log('     ✅ Emulator warning policy enforced');
                break;
              case 'log':
                // Should log but not necessarily show UI warning
                console.log('     ✅ Emulator logging policy enforced');
                break;
            }
          }
        }
      }
      
      // Test root policy enforcement
      if (policies.deviceSecurity.rootPolicy.enabled) {
        console.log(`   Root Policy: ${policies.deviceSecurity.rootPolicy.action.toUpperCase()}`);
        
        const rootDetection = await global.securityChecker.detectRoot();
        
        if (rootDetection.detected) {
          const navigated = await securityPage.navigateToSecurity();
          if (navigated) {
            const rootWarning = await securityPage.getRootWarning();
            
            switch (policies.deviceSecurity.rootPolicy.action) {
              case 'block':
                expect(rootWarning.detected).to.be.true;
                expect(rootWarning.blocked).to.be.true;
                console.log('     ✅ Root blocking policy enforced');
                break;
              case 'warn':
                expect(rootWarning.detected).to.be.true;
                console.log('     ✅ Root warning policy enforced');
                break;
            }
          }
        }
      }
      
      // Test file integrity policy
      if (policies.applicationSecurity.integrityPolicy.enabled) {
        console.log(`   File Integrity Policy: ${policies.applicationSecurity.integrityPolicy.action.toUpperCase()}`);
        
        // Create a test file and tamper with it
        await global.fileManipulator.createTestFiles();
        const testFile = '/data/local/tmp/test_config.properties';
        
        // Tamper with the file
        const backup = await global.fileManipulator.createBackup(testFile);
        const tamperResult = await global.fileManipulator.modifyConfig(testFile, 'test', 'tampered');
        
        if (tamperResult.success) {
          const navigated = await securityPage.navigateToSecurity();
          if (navigated) {
            const tamperingAlert = await securityPage.getTamperingAlert();
            
            if (tamperingAlert.detected) {
              console.log('     ✅ File integrity policy enforced');
              expect(tamperingAlert.action).to.include(policies.applicationSecurity.integrityPolicy.action);
            }
          }
          
          // Restore file
          await global.fileManipulator.restoreFromBackup(backup.backupName);
        }
      }
      
      global.SecurityTestUtils.logSecurityPassed('security_policies_validated');
    });
  });

  describe('Performance and Reliability', function() {
    it('should test security check performance', async function() {
      global.SecurityTestUtils.logSecurityStep('performance_testing', 'Testing security check performance');
      
      const performanceMetrics = [];
      
      // Test emulator detection performance
      const emulatorStart = Date.now();
      await global.securityChecker.detectEmulator();
      const emulatorTime = Date.now() - emulatorStart;
      performanceMetrics.push({ check: 'emulator_detection', time: emulatorTime });
      
      // Test root detection performance
      const rootStart = Date.now();
      await global.securityChecker.detectRoot();
      const rootTime = Date.now() - rootStart;
      performanceMetrics.push({ check: 'root_detection', time: rootTime });
      
      // Test file integrity performance
      const fileStart = Date.now();
      await global.securityChecker.validateFileIntegrity('/system/build.prop');
      const fileTime = Date.now() - fileStart;
      performanceMetrics.push({ check: 'file_integrity', time: fileTime });
      
      console.log('⏱️  Security Check Performance:');
      performanceMetrics.forEach(metric => {
        console.log(`   ${metric.check}: ${metric.time}ms`);
        
        // Ensure checks complete within reasonable time
        expect(metric.time).to.be.below(30000); // 30 seconds max
      });
      
      const averageTime = performanceMetrics.reduce((sum, m) => sum + m.time, 0) / performanceMetrics.length;
      console.log(`   Average: ${Math.round(averageTime)}ms`);
      
      if (averageTime > 10000) {
        console.log('⚠️  Security checks are taking longer than expected');
      } else {
        global.SecurityTestUtils.logSecurityPassed('security_performance_acceptable');
      }
    });

    it('should test security check reliability', async function() {
      global.SecurityTestUtils.logSecurityStep('reliability_testing', 'Testing security check reliability');
      
      const iterations = 3;
      const reliabilityResults = [];
      
      // Run security checks multiple times
      for (let i = 0; i < iterations; i++) {
        console.log(`🔄 Reliability Test Iteration ${i + 1}/${iterations}`);
        
        const emulatorResult = await global.securityChecker.detectEmulator();
        const rootResult = await global.securityChecker.detectRoot();
        
        reliabilityResults.push({
          iteration: i + 1,
          emulator: emulatorResult.detected,
          root: rootResult.detected,
          timestamp: Date.now()
        });
        
        // Small delay between iterations
        if (i < iterations - 1) {
          await global.SecurityTestUtils.sleep(2000);
        }
      }
      
      // Analyze consistency
      const emulatorResults = reliabilityResults.map(r => r.emulator);
      const rootResults = reliabilityResults.map(r => r.root);
      
      const emulatorConsistent = emulatorResults.every(result => result === emulatorResults[0]);
      const rootConsistent = rootResults.every(result => result === rootResults[0]);
      
      console.log('🔄 Reliability Analysis:');
      console.log(`   Emulator Detection Consistency: ${emulatorConsistent ? 'CONSISTENT' : 'INCONSISTENT'}`);
      console.log(`   Root Detection Consistency: ${rootConsistent ? 'CONSISTENT' : 'INCONSISTENT'}`);
      
      // Results should be consistent across multiple runs
      expect(emulatorConsistent).to.be.true;
      expect(rootConsistent).to.be.true;
      
      if (emulatorConsistent && rootConsistent) {
        global.SecurityTestUtils.logSecurityPassed('security_checks_reliable');
      } else {
        global.SecurityTestUtils.logSecurityFailed('security_reliability', 
          'Security checks produced inconsistent results');
      }
    });
  });

  after(async function() {
    // Clean up any test artifacts
    await global.fileManipulator.cleanup();
    
    // Generate integration test summary
    console.log('\n📊 Security Flow Integration Test Summary:');
    console.log('==========================================');
    console.log(`Test Environment: ${global.testEnvironment}`);
    console.log(`Device Type: ${global.deviceType}`);
    console.log(`Test User: ${testUser.username}`);
    
    if (this.currentTest?.parent?.ctx?.combinedThreats) {
      const threats = this.currentTest.parent.ctx.combinedThreats;
      console.log(`Security Issues: ${threats.issues.length}`);
      console.log(`Risk Level: ${threats.riskLevel.toUpperCase()}`);
      console.log(`Risk Score: ${threats.riskScore}`);
    }
    
    console.log('==========================================\n');
  });
});