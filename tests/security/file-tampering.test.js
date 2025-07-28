/**
 * File Tampering Detection Security Tests
 * Tests for detecting file system modifications and integrity violations
 */

const { expect } = require('chai');
const BasePage = require('../../src/pages/base-page');
const SecurityPage = require('../../src/pages/security-page');
const { TestDataManager } = require('../../src/config/test-data');
const path = require('path');

describe('File Tampering Detection Security Tests', function() {
  let basePage, securityPage;
  let testConfig, deviceInfo;
  let originalChecksums = new Map();

  before(async function() {
    // Initialize page objects
    basePage = new BasePage(browser);
    securityPage = new SecurityPage(browser);
    
    // Get test configuration
    testConfig = global.securityConfig.getTestConfiguration('file_tampering');
    
    // Get device information
    deviceInfo = await global.deviceDetector.analyzeDevice();
    
    // Initialize file manipulator
    await global.fileManipulator.initialize();
    
    console.log(`🔍 Running file tampering tests on: ${deviceInfo.deviceInfo?.model || 'Unknown Device'}`);
    console.log(`📁 File integrity monitoring: ${testConfig.policies.applicationSecurity.integrityPolicy.enabled ? 'ENABLED' : 'DISABLED'}`);
    console.log(`🛡️  Action on tampering: ${testConfig.policies.applicationSecurity.integrityPolicy.action}`);
  });

  describe('File Integrity Baseline', function() {
    it('should establish baseline checksums for critical files', async function() {
      global.SecurityTestUtils.logSecurityStep('baseline_establishment', 'Establishing file integrity baseline');
      
      // Create test files for tampering scenarios
      const testFilesResult = await global.fileManipulator.createTestFiles();
      expect(testFilesResult.success).to.be.true;
      
      const testFiles = testFilesResult.createdFiles;
      console.log(`📁 Created ${testFiles.length} test files for tampering detection`);
      
      // Calculate initial checksums
      for (const filePath of testFiles) {
        const result = await global.adbHelper.executeShellCommand(`sha256sum ${filePath}`);
        if (result.success) {
          const checksum = result.output.split(' ')[0];
          originalChecksums.set(filePath, checksum);
          console.log(`🔒 ${path.basename(filePath)}: ${checksum.substring(0, 16)}...`);
        }
      }
      
      expect(originalChecksums.size).to.equal(testFiles.length);
      global.SecurityTestUtils.logSecurityPassed('baseline_established');
      
      // Store baseline for later comparison
      this.currentTest.baseline = Array.from(originalChecksums.entries());
      
      // Take screenshot of initial state
      await basePage.takeSecurityScreenshot('file-integrity-baseline', 'File integrity baseline established');
    });

    it('should verify initial file integrity', async function() {
      global.SecurityTestUtils.logSecurityStep('initial_integrity_check', 'Verifying initial file integrity');
      
      let integrityViolations = 0;
      
      for (const [filePath, expectedChecksum] of originalChecksums) {
        const currentResult = await global.adbHelper.executeShellCommand(`sha256sum ${filePath}`);
        
        if (currentResult.success) {
          const currentChecksum = currentResult.output.split(' ')[0];
          
          if (currentChecksum !== expectedChecksum) {
            integrityViolations++;
            console.log(`⚠️  Integrity violation: ${filePath}`);
            console.log(`   Expected: ${expectedChecksum}`);
            console.log(`   Current:  ${currentChecksum}`);
          }
        } else {
          integrityViolations++;
          console.log(`❌ Cannot verify: ${filePath} (file missing or inaccessible)`);
        }
      }
      
      expect(integrityViolations).to.equal(0);
      global.SecurityTestUtils.logSecurityPassed('initial_integrity_verified');
    });
  });

  describe('Configuration File Tampering', function() {
    it('should detect configuration file modifications', async function() {
      global.SecurityTestUtils.logSecurityStep('config_tampering', 'Testing configuration file tampering detection');
      
      const configFile = '/data/local/tmp/test_config.properties';
      
      // Verify file exists in our baseline
      expect(originalChecksums.has(configFile)).to.be.true;
      
      // Create backup before modification
      const backup = await global.fileManipulator.createBackup(configFile, 'config_test_backup');
      expect(backup.success).to.be.true;
      
      // Modify configuration file
      const modifyResult = await global.fileManipulator.modifyConfig(
        configFile, 
        'debug.enabled', 
        'true', 
        'properties'
      );
      
      expect(modifyResult.success).to.be.true;
      console.log(`🔧 Modified ${configFile}: debug.enabled = true`);
      
      // Verify tampering detection
      const currentResult = await global.adbHelper.executeShellCommand(`sha256sum ${configFile}`);
      expect(currentResult.success).to.be.true;
      
      const currentChecksum = currentResult.output.split(' ')[0];
      const originalChecksum = originalChecksums.get(configFile);
      
      // Checksums should be different (indicating tampering)
      expect(currentChecksum).to.not.equal(originalChecksum);
      
      global.SecurityTestUtils.logThreatDetected('config_file_tampered', 
        `Configuration file modified: ${configFile}`);
      
      // Test app response to tampering if available
      const navigated = await securityPage.navigateToSecurity();
      if (navigated) {
        const tamperingAlert = await securityPage.getTamperingAlert();
        
        if (testConfig.policies.applicationSecurity.integrityPolicy.enabled) {
          // Should detect tampering
          if (tamperingAlert.detected) {
            expect(tamperingAlert.action).to.equal(testConfig.policies.applicationSecurity.integrityPolicy.action);
            global.SecurityTestUtils.logSecurityPassed('tampering_detected_and_handled');
          }
        }
      }
      
      // Restore original file
      const restoreResult = await global.fileManipulator.restoreFromBackup(backup.backupName);
      expect(restoreResult.success).to.be.true;
      
      // Take screenshot of tampering detection
      await basePage.takeSecurityScreenshot('config-tampering-detection', 'Configuration file tampering detection');
    });

    it('should detect JSON configuration tampering', async function() {
      global.SecurityTestUtils.logSecurityStep('json_tampering', 'Testing JSON configuration tampering');
      
      const jsonFile = '/data/local/tmp/test_data.json';
      
      // Create backup
      const backup = await global.fileManipulator.createBackup(jsonFile, 'json_test_backup');
      expect(backup.success).to.be.true;
      
      // Modify JSON configuration
      const modifyResult = await global.fileManipulator.modifyConfig(
        jsonFile,
        'security.enabled',
        false,
        'json'
      );
      
      expect(modifyResult.success).to.be.true;
      console.log(`🔧 Modified ${jsonFile}: security.enabled = false`);
      
      // Verify modification was detected
      const currentResult = await global.adbHelper.executeShellCommand(`sha256sum ${jsonFile}`);
      const currentChecksum = currentResult.output.split(' ')[0];
      const originalChecksum = originalChecksums.get(jsonFile);
      
      expect(currentChecksum).to.not.equal(originalChecksum);
      
      global.SecurityTestUtils.logThreatDetected('json_config_tampered', 
        `JSON configuration modified: security.enabled changed to false`);
      
      // Restore original file
      await global.fileManipulator.restoreFromBackup(backup.backupName);
    });
  });

  describe('Binary File Tampering', function() {
    it('should detect script file modifications', async function() {
      global.SecurityTestUtils.logSecurityStep('script_tampering', 'Testing script file tampering');
      
      const scriptFile = '/data/local/tmp/test_script.sh';
      
      // Create backup
      const backup = await global.fileManipulator.createBackup(scriptFile, 'script_test_backup');
      expect(backup.success).to.be.true;
      
      // Inject malicious code into script
      const tamperResult = await global.fileManipulator.tamperWithFile(
        scriptFile, 
        'inject_code', 
        { code: '\n# Malicious code injection\nrm -rf /data/local/tmp/*\n' }
      );
      
      expect(tamperResult.success).to.be.true;
      console.log(`🔧 Injected malicious code into ${scriptFile}`);
      
      // Verify tampering detection
      const currentResult = await global.adbHelper.executeShellCommand(`sha256sum ${scriptFile}`);
      const currentChecksum = currentResult.output.split(' ')[0];
      const originalChecksum = originalChecksums.get(scriptFile);
      
      expect(currentChecksum).to.not.equal(originalChecksum);
      
      global.SecurityTestUtils.logThreatDetected('script_file_tampered', 
        `Script file modified with potential malicious code: ${scriptFile}`);
      
      // Check if the injected code is present
      const contentCheck = await global.adbHelper.executeShellCommand(`cat ${scriptFile}`);
      expect(contentCheck.output).to.include('Malicious code injection');
      
      // Restore original file
      await global.fileManipulator.restoreFromBackup(backup.backupName);
    });

    it('should detect file corruption', async function() {
      global.SecurityTestUtils.logSecurityStep('file_corruption', 'Testing file corruption detection');
      
      const testFile = '/data/local/tmp/test_config.properties';
      
      // Create backup
      const backup = await global.fileManipulator.createBackup(testFile, 'corruption_test_backup');
      expect(backup.success).to.be.true;
      
      // Corrupt the file
      const corruptResult = await global.fileManipulator.tamperWithFile(
        testFile,
        'corrupt',
        { corruption: 'RANDOM_CORRUPTION_DATA_INJECTION' }
      );
      
      expect(corruptResult.success).to.be.true;
      console.log(`🔧 Corrupted file: ${testFile}`);
      
      // Verify corruption detection
      const currentResult = await global.adbHelper.executeShellCommand(`sha256sum ${testFile}`);
      const currentChecksum = currentResult.output.split(' ')[0];
      const originalChecksum = originalChecksums.get(testFile);
      
      expect(currentChecksum).to.not.equal(originalChecksum);
      
      global.SecurityTestUtils.logThreatDetected('file_corruption_detected', 
        `File corruption detected: ${testFile}`);
      
      // Restore original file
      await global.fileManipulator.restoreFromBackup(backup.backupName);
    });
  });

  describe('Permission Tampering', function() {
    it('should detect file permission modifications', async function() {
      global.SecurityTestUtils.logSecurityStep('permission_tampering', 'Testing file permission tampering');
      
      const testFile = '/data/local/tmp/test_script.sh';
      
      // Get original permissions
      const originalPerms = await global.adbHelper.executeShellCommand(`ls -la ${testFile}`);
      expect(originalPerms.success).to.be.true;
      
      console.log(`📋 Original permissions: ${originalPerms.output}`);
      
      // Create backup
      const backup = await global.fileManipulator.createBackup(testFile, 'permission_test_backup');
      expect(backup.success).to.be.true;
      
      // Modify file permissions to make it writable/executable by all
      const tamperResult = await global.fileManipulator.tamperWithFile(
        testFile,
        'modify_permissions',
        { permissions: '777' }
      );
      
      expect(tamperResult.success).to.be.true;
      console.log(`🔧 Modified permissions to 777 for ${testFile}`);
      
      // Verify permission change
      const newPerms = await global.adbHelper.executeShellCommand(`ls -la ${testFile}`);
      expect(newPerms.success).to.be.true;
      
      console.log(`📋 New permissions: ${newPerms.output}`);
      expect(newPerms.output).to.not.equal(originalPerms.output);
      
      // Check if file is now executable by others
      expect(newPerms.output).to.include('rwxrwxrwx');
      
      global.SecurityTestUtils.logThreatDetected('file_permissions_tampered', 
        `File permissions modified to dangerous level: ${testFile} now has 777 permissions`);
      
      // Restore original file and permissions
      await global.fileManipulator.restoreFromBackup(backup.backupName);
    });

    it('should detect timestamp manipulation', async function() {
      global.SecurityTestUtils.logSecurityStep('timestamp_tampering', 'Testing timestamp manipulation detection');
      
      const testFile = '/data/local/tmp/test_config.properties';
      
      // Get original timestamp
      const originalStat = await global.adbHelper.executeShellCommand(`stat ${testFile}`);
      expect(originalStat.success).to.be.true;
      
      console.log(`📅 Original timestamp info:\n${originalStat.output}`);
      
      // Create backup
      const backup = await global.fileManipulator.createBackup(testFile, 'timestamp_test_backup');
      expect(backup.success).to.be.true;
      
      // Modify timestamp
      const tamperResult = await global.fileManipulator.tamperWithFile(
        testFile,
        'modify_timestamp',
        { timestamp: '202001010000' } // January 1, 2020
      );
      
      expect(tamperResult.success).to.be.true;
      console.log(`🔧 Modified timestamp for ${testFile}`);
      
      // Verify timestamp change
      const newStat = await global.adbHelper.executeShellCommand(`stat ${testFile}`);
      expect(newStat.success).to.be.true;
      
      console.log(`📅 New timestamp info:\n${newStat.output}`);
      expect(newStat.output).to.not.equal(originalStat.output);
      
      global.SecurityTestUtils.logThreatDetected('timestamp_manipulation', 
        `File timestamp manipulated: ${testFile}`);
      
      // Restore original file
      await global.fileManipulator.restoreFromBackup(backup.backupName);
    });
  });

  describe('Real-time Monitoring', function() {
    it('should monitor files for real-time tampering detection', async function() {
      global.SecurityTestUtils.logSecurityStep('realtime_monitoring', 'Testing real-time file monitoring');
      
      const monitoredFiles = Array.from(originalChecksums.keys());
      
      // Start monitoring in background
      const monitoringPromise = global.fileManipulator.monitorFileIntegrity(monitoredFiles, 15000);
      
      // Wait a moment for monitoring to start
      await global.SecurityTestUtils.sleep(2000);
      
      // Perform tampering while monitoring is active
      const testFile = monitoredFiles[0];
      const backup = await global.fileManipulator.createBackup(testFile, 'realtime_test_backup');
      
      // Modify file during monitoring
      const modifyResult = await global.fileManipulator.modifyConfig(
        testFile,
        'realtime_test',
        'tampering_detected',
        'properties'
      );
      
      expect(modifyResult.success).to.be.true;
      console.log(`🔧 Modified ${testFile} during real-time monitoring`);
      
      // Wait for monitoring to complete
      const monitoringResult = await monitoringPromise;
      
      expect(monitoringResult.success).to.be.true;
      expect(monitoringResult.changes.length).to.be.above(0);
      
      const detectedChange = monitoringResult.changes.find(change => change.filePath === testFile);
      expect(detectedChange).to.exist;
      
      global.SecurityTestUtils.logThreatDetected('realtime_tampering_detected', 
        `Real-time tampering detected: ${detectedChange.filePath}`);
      
      console.log(`⚡ Real-time detection: ${monitoringResult.changes.length} changes detected`);
      
      // Restore file
      await global.fileManipulator.restoreFromBackup(backup.backupName);
      
      // Take screenshot of monitoring results
      await basePage.takeSecurityScreenshot('realtime-monitoring', 'Real-time file tampering detection');
    });

    it('should validate file integrity after tampering attempts', async function() {
      global.SecurityTestUtils.logSecurityStep('integrity_validation', 'Validating file integrity after tampering');
      
      let integrityViolations = [];
      
      // Check each file against original baseline
      for (const [filePath, expectedChecksum] of originalChecksums) {
        const validationResult = await global.securityChecker.validateFileIntegrity(filePath);
        
        if (validationResult.exists) {
          if (validationResult.tampered) {
            integrityViolations.push({
              file: filePath,
              expected: expectedChecksum,
              current: validationResult.currentChecksum
            });
          }
        } else {
          integrityViolations.push({
            file: filePath,
            issue: 'file_missing'
          });
        }
      }
      
      if (integrityViolations.length > 0) {
        console.log(`⚠️  Integrity violations found: ${integrityViolations.length}`);
        integrityViolations.forEach(violation => {
          console.log(`   ${violation.file}: ${violation.issue || 'checksum_mismatch'}`);
        });
        
        global.SecurityTestUtils.logThreatDetected('integrity_violations', 
          `${integrityViolations.length} file integrity violations detected`);
      } else {
        global.SecurityTestUtils.logSecurityPassed('file_integrity_validated');
      }
      
      // At this point, we expect files to be restored, so no violations should remain
      expect(integrityViolations.length).to.equal(0);
    });
  });

  describe('Tampering Response Testing', function() {
    it('should test application response to file tampering', async function() {
      global.SecurityTestUtils.logSecurityStep('app_tampering_response', 'Testing application response to tampering');
      
      // Navigate to security section
      const navigated = await securityPage.navigateToSecurity();
      
      if (navigated) {
        // Perform a quick tampering test
        const testFile = '/data/local/tmp/test_config.properties';
        const backup = await global.fileManipulator.createBackup(testFile, 'response_test_backup');
        
        // Modify file
        const modifyResult = await global.fileManipulator.modifyConfig(
          testFile,
          'security_test',
          'response_check',
          'properties'
        );
        
        if (modifyResult.success) {
          // Check app security response
          const tamperingAlert = await securityPage.getTamperingAlert();
          
          if (testConfig.policies.applicationSecurity.integrityPolicy.enabled) {
            if (tamperingAlert.detected) {
              console.log(`🛡️  App detected tampering: ${tamperingAlert.message}`);
              console.log(`⚡ Action taken: ${tamperingAlert.action}`);
              console.log(`📊 Severity: ${tamperingAlert.severity}`);
              
              // Verify appropriate action was taken
              const expectedAction = testConfig.policies.applicationSecurity.integrityPolicy.action;
              expect(tamperingAlert.action).to.include(expectedAction);
              
              global.SecurityTestUtils.logSecurityPassed('app_responded_to_tampering');
            } else {
              global.SecurityTestUtils.logSecurityFailed('app_tampering_response', 
                'Application failed to detect file tampering');
            }
          }
        }
        
        // Restore file
        await global.fileManipulator.restoreFromBackup(backup.backupName);
        
        // Take screenshot of app response
        await basePage.takeSecurityScreenshot('app-tampering-response', 
          'Application response to file tampering');
      } else {
        console.log('⚠️  App does not have security UI - testing detection logic only');
      }
    });
  });

  after(async function() {
    // Clean up test files and backups
    await global.fileManipulator.cleanup();
    
    // Generate test summary
    console.log('\n📊 File Tampering Detection Test Summary:');
    console.log('==========================================');
    console.log(`Device Type: ${global.deviceType}`);
    console.log(`Device Model: ${deviceInfo.deviceInfo?.model || 'Unknown'}`);
    console.log(`Files Monitored: ${originalChecksums.size}`);
    console.log(`Integrity Policy: ${testConfig.policies.applicationSecurity.integrityPolicy.enabled ? 'ENABLED' : 'DISABLED'}`);
    console.log(`Action on Tampering: ${testConfig.policies.applicationSecurity.integrityPolicy.action}`);
    console.log('==========================================\n');
  });
});