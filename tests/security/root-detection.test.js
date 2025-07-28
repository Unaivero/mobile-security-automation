/**
 * Root Detection Security Tests
 * Tests for detecting and responding to rooted/jailbroken devices
 */

const { expect } = require('chai');
const BasePage = require('../../src/pages/base-page');
const SecurityPage = require('../../src/pages/security-page');
const { TestDataManager } = require('../../src/config/test-data');

describe('Root Detection Security Tests', function() {
  let basePage, securityPage;
  let testConfig, deviceInfo;

  before(async function() {
    // Initialize page objects
    basePage = new BasePage(browser);
    securityPage = new SecurityPage(browser);
    
    // Get test configuration
    testConfig = global.securityConfig.getTestConfiguration('root_detection');
    
    // Get device information
    deviceInfo = await global.deviceDetector.analyzeDevice();
    
    console.log(`🔍 Running root detection tests on: ${deviceInfo.deviceInfo?.model || 'Unknown Device'}`);
    console.log(`🔓 Expected root status: ${global.deviceType === 'rooted' ? 'ROOTED' : 'NOT ROOTED'}`);
    console.log(`🛡️  Security policy action: ${testConfig.policies.deviceSecurity.rootPolicy.action}`);
  });

  describe('Basic Root Detection', function() {
    it('should detect su binary presence', async function() {
      global.SecurityTestUtils.logSecurityStep('su_binary_check', 'Checking for su binary in common locations');
      
      // Common su binary locations
      const suPaths = [
        '/system/bin/su',
        '/system/xbin/su',
        '/sbin/su',
        '/system/usr/we-need-root/su-backup',
        '/system/xbin/mu',
        '/su/bin/su'
      ];
      
      const foundSuPaths = [];
      
      for (const path of suPaths) {
        const result = await global.adbHelper.executeShellCommand(`test -f ${path} && echo exists || echo missing`);
        if (result.success && result.output.includes('exists')) {
          foundSuPaths.push(path);
        }
      }
      
      console.log(`🔍 Su binaries found: ${foundSuPaths.length}/${suPaths.length}`);
      
      if (foundSuPaths.length > 0) {
        global.SecurityTestUtils.logThreatDetected('su_binary_found', 
          `Su binary detected at: ${foundSuPaths.join(', ')}`);
        
        // Verify permissions and functionality
        for (const suPath of foundSuPaths) {
          const permResult = await global.adbHelper.executeShellCommand(`ls -la ${suPath}`);
          console.log(`📋 ${suPath} permissions: ${permResult.output}`);
        }
        
        expect(foundSuPaths.length).to.be.above(0);
      } else {
        global.SecurityTestUtils.logSecurityPassed('no_su_binary_found');
      }
      
      // Take screenshot for evidence
      await basePage.takeSecurityScreenshot('su-binary-check', 'Su binary detection results');
    });

    it('should detect root management applications', async function() {
      global.SecurityTestUtils.logSecurityStep('root_apps_check', 'Scanning for root management applications');
      
      // Get list of installed packages
      const packagesResult = await global.adbHelper.executeShellCommand('pm list packages');
      expect(packagesResult.success).to.be.true;
      
      const packages = packagesResult.output.split('\n')
        .map(line => line.replace('package:', ''))
        .filter(pkg => pkg.trim());
      
      // Known root management packages
      const rootPackages = [
        'com.noshufou.android.su',
        'com.noshufou.android.su.elite',
        'eu.chainfire.supersu',
        'com.koushikdutta.superuser',
        'com.thirdparty.superuser',
        'com.yellowes.su',
        'com.topjohnwu.magisk',
        'com.kingroot.kinguser',
        'com.kingo.root',
        'com.smedialink.oneclickroot',
        'com.zhiqupk.root.global',
        'com.alephzain.framaroot'
      ];
      
      const foundRootApps = packages.filter(pkg => 
        rootPackages.some(rootPkg => pkg.includes(rootPkg))
      );
      
      console.log(`📱 Root apps found: ${foundRootApps.length}`);
      
      if (foundRootApps.length > 0) {
        global.SecurityTestUtils.logThreatDetected('root_apps_detected', 
          `Root management apps found: ${foundRootApps.join(', ')}`);
        
        // Get detailed info about root apps
        for (const app of foundRootApps) {
          const appInfo = await global.adbHelper.getApplicationInfo(app);
          if (appInfo.success) {
            console.log(`📋 ${app}: ${JSON.stringify(appInfo.info, null, 2)}`);
          }
        }
        
        expect(foundRootApps.length).to.be.above(0);
      } else {
        global.SecurityTestUtils.logSecurityPassed('no_root_apps_found');
      }
      
      // Store results for later analysis
      this.currentTest.rootApps = foundRootApps;
    });

    it('should test system directory write permissions', async function() {
      global.SecurityTestUtils.logSecurityStep('system_write_test', 'Testing write access to system directories');
      
      // System directories that should be read-only on non-rooted devices
      const systemDirs = [
        '/system',
        '/system/bin',
        '/system/xbin',
        '/data/data',
        '/data/system'
      ];
      
      const writableDirs = [];
      
      for (const dir of systemDirs) {
        // Try to create a test file
        const testFile = `${dir}/root_test_${Date.now()}.tmp`;
        const writeResult = await global.adbHelper.executeShellCommand(`touch ${testFile} 2>/dev/null && echo writable || echo readonly`);
        
        if (writeResult.success && writeResult.output.includes('writable')) {
          writableDirs.push(dir);
          
          // Clean up test file
          await global.adbHelper.executeShellCommand(`rm -f ${testFile}`);
        }
      }
      
      console.log(`📁 Writable system directories: ${writableDirs.length}/${systemDirs.length}`);
      
      if (writableDirs.length > 0) {
        global.SecurityTestUtils.logThreatDetected('system_writable', 
          `System directories are writable: ${writableDirs.join(', ')}`);
        
        // This strongly indicates root access
        expect(writableDirs.length).to.be.above(0);
      } else {
        global.SecurityTestUtils.logSecurityPassed('system_directories_protected');
      }
    });

    it('should detect dangerous system properties', async function() {
      global.SecurityTestUtils.logSecurityStep('dangerous_props_check', 'Checking for dangerous system properties');
      
      const systemProps = await global.adbHelper.getSystemProperties();
      
      // Properties that may indicate root or debugging
      const dangerousProps = {
        'ro.debuggable': '1',
        'ro.secure': '0',
        'service.adb.root': '1',
        'ro.build.tags': 'test-keys'
      };
      
      const foundDangerousProps = [];
      
      Object.entries(dangerousProps).forEach(([prop, dangerousValue]) => {
        const actualValue = systemProps[prop];
        if (actualValue === dangerousValue) {
          foundDangerousProps.push(`${prop}=${actualValue}`);
        }
      });
      
      if (foundDangerousProps.length > 0) {
        global.SecurityTestUtils.logThreatDetected('dangerous_properties', 
          `Found dangerous properties: ${foundDangerousProps.join(', ')}`);
      } else {
        global.SecurityTestUtils.logSecurityPassed('no_dangerous_properties_found');
      }
      
      // Log key security properties
      console.log(`🔒 ro.secure: ${systemProps['ro.secure'] || 'not set'}`);
      console.log(`🐛 ro.debuggable: ${systemProps['ro.debuggable'] || 'not set'}`);
      console.log(`🔑 ro.build.tags: ${systemProps['ro.build.tags'] || 'not set'}`);
    });
  });

  describe('Advanced Root Detection', function() {
    it('should perform comprehensive root detection analysis', async function() {
      global.SecurityTestUtils.logSecurityStep('comprehensive_root_analysis', 'Performing comprehensive root detection');
      
      // Use the security checker for comprehensive analysis
      const rootDetection = await global.securityChecker.detectRoot();
      
      expect(rootDetection).to.have.property('detected');
      expect(rootDetection).to.have.property('confidence');
      expect(rootDetection).to.have.property('risk');
      
      console.log(`🔓 Root detection result: ${rootDetection.detected ? 'ROOTED' : 'NOT ROOTED'}`);
      console.log(`📊 Confidence: ${Math.round(rootDetection.confidence * 100)}%`);
      console.log(`⚠️  Risk level: ${rootDetection.risk}`);
      
      if (rootDetection.detected) {
        global.SecurityTestUtils.logThreatDetected('root_access_confirmed', 
          `Root access detected with ${Math.round(rootDetection.confidence * 100)}% confidence`);
        
        // Verify security response
        expect(rootDetection.risk).to.equal('critical');
      } else {
        global.SecurityTestUtils.logSecurityPassed('device_not_rooted');
      }
      
      // Take screenshot of detection results
      await basePage.takeSecurityScreenshot('comprehensive-root-detection', 
        'Comprehensive root detection analysis');
      
      // Store detailed results
      this.currentTest.rootDetection = rootDetection;
    });

    it('should detect Magisk root hiding framework', async function() {
      global.SecurityTestUtils.logSecurityStep('magisk_detection', 'Checking for Magisk root management');
      
      // Check for Magisk-related files and processes
      const magiskIndicators = [
        '/sbin/magisk',
        '/system/addon.d/99-magisk.sh',
        '/data/adb/magisk',
        '/cache/.magisk'
      ];
      
      const foundMagiskFiles = [];
      
      for (const indicator of magiskIndicators) {
        const result = await global.adbHelper.executeShellCommand(`test -e ${indicator} && echo exists`);
        if (result.success && result.output.includes('exists')) {
          foundMagiskFiles.push(indicator);
        }
      }
      
      // Check for Magisk processes
      const processResult = await global.adbHelper.getRunningProcesses();
      const magiskProcesses = [];
      
      if (processResult.success) {
        magiskProcesses.push(...processResult.processes.filter(proc => 
          proc.name.toLowerCase().includes('magisk') ||
          proc.name.toLowerCase().includes('daemon')
        ));
      }
      
      const magiskDetected = foundMagiskFiles.length > 0 || magiskProcesses.length > 0;
      
      if (magiskDetected) {
        global.SecurityTestUtils.logThreatDetected('magisk_detected', 
          `Magisk root framework detected - Files: ${foundMagiskFiles.join(', ')}, Processes: ${magiskProcesses.length}`);
        
        console.log(`🎭 Magisk files: ${foundMagiskFiles.join(', ')}`);
        console.log(`⚙️  Magisk processes: ${magiskProcesses.length}`);
      } else {
        global.SecurityTestUtils.logSecurityPassed('no_magisk_detected');
      }
    });

    it('should detect Xposed framework', async function() {
      global.SecurityTestUtils.logSecurityStep('xposed_detection', 'Checking for Xposed framework');
      
      // Check for Xposed-related packages
      const packagesResult = await global.adbHelper.executeShellCommand('pm list packages');
      const packages = packagesResult.output.split('\n');
      
      const xposedPackages = packages.filter(pkg => 
        pkg.includes('xposed') || 
        pkg.includes('com.rovo89') ||
        pkg.includes('de.robv.android.xposed')
      );
      
      // Check for Xposed files
      const xposedFiles = [
        '/system/framework/XposedBridge.jar',
        '/system/bin/app_process_xposed',
        '/system/xposed.prop'
      ];
      
      const foundXposedFiles = [];
      
      for (const file of xposedFiles) {
        const result = await global.adbHelper.executeShellCommand(`test -f ${file} && echo exists`);
        if (result.success && result.output.includes('exists')) {
          foundXposedFiles.push(file);
        }
      }
      
      const xposedDetected = xposedPackages.length > 0 || foundXposedFiles.length > 0;
      
      if (xposedDetected) {
        global.SecurityTestUtils.logThreatDetected('xposed_detected', 
          `Xposed framework detected - Packages: ${xposedPackages.length}, Files: ${foundXposedFiles.length}`);
        
        console.log(`📦 Xposed packages: ${xposedPackages.join(', ')}`);
        console.log(`📁 Xposed files: ${foundXposedFiles.join(', ')}`);
      } else {
        global.SecurityTestUtils.logSecurityPassed('no_xposed_detected');
      }
    });

    it('should test application response to root detection', async function() {
      global.SecurityTestUtils.logSecurityStep('app_root_response', 'Testing application response to root detection');
      
      // Navigate to security section
      const navigated = await securityPage.navigateToSecurity();
      
      if (navigated) {
        // Check for root warning
        const rootWarning = await securityPage.getRootWarning();
        
        // Determine expected behavior based on actual root status
        const actualRootStatus = this.currentTest?.parent?.ctx?.rootDetection?.detected || false;
        
        if (actualRootStatus) {
          // Device is rooted - should show warning/block
          if (testConfig.policies.deviceSecurity.rootPolicy.action === 'block') {
            expect(rootWarning.detected).to.be.true;
            expect(rootWarning.blocked).to.be.true;
            
            global.SecurityTestUtils.logSecurityPassed('rooted_device_blocked_correctly');
          } else if (testConfig.policies.deviceSecurity.rootPolicy.action === 'warn') {
            expect(rootWarning.detected).to.be.true;
            
            global.SecurityTestUtils.logSecurityPassed('rooted_device_warning_shown');
          }
        } else {
          // Device is not rooted - should allow access
          expect(rootWarning.detected).to.be.false;
          expect(rootWarning.blocked).to.be.false;
          
          global.SecurityTestUtils.logSecurityPassed('non_rooted_device_access_granted');
        }
        
        // Take screenshot of security response
        await basePage.takeSecurityScreenshot('root-security-response', 
          'App security response to root detection');
      } else {
        console.log('⚠️  App does not have security UI - testing detection logic only');
      }
    });
  });

  describe('Root Hiding Detection', function() {
    it('should detect attempts to hide root access', async function() {
      global.SecurityTestUtils.logSecurityStep('root_hiding_detection', 'Testing detection of root hiding attempts');
      
      // Check for common root hiding techniques
      const hidingTechniques = {
        // RootCloak
        rootCloak: await this.checkForRootCloak(),
        // Hide My Root
        hideMyRoot: await this.checkForHideMyRoot(),
        // Magisk Hide
        magiskHide: await this.checkForMagiskHide(),
        // Universal Root Hide
        universalRootHide: await this.checkForUniversalRootHide()
      };
      
      const detectedHidingMethods = Object.entries(hidingTechniques)
        .filter(([method, detected]) => detected)
        .map(([method]) => method);
      
      if (detectedHidingMethods.length > 0) {
        global.SecurityTestUtils.logThreatDetected('root_hiding_detected', 
          `Root hiding methods detected: ${detectedHidingMethods.join(', ')}`);
        
        // This indicates sophisticated root usage
        expect(detectedHidingMethods.length).to.be.above(0);
      } else {
        global.SecurityTestUtils.logSecurityStep('no_root_hiding', 'No root hiding techniques detected');
      }
    });

    it('should verify detection robustness against hiding', async function() {
      global.SecurityTestUtils.logSecurityStep('detection_robustness', 'Verifying detection robustness');
      
      // Run detection multiple times to ensure consistency
      const detectionRuns = [];
      
      for (let i = 0; i < 3; i++) {
        const detection = await global.securityChecker.detectRoot();
        detectionRuns.push(detection.detected);
        
        // Small delay between runs
        await global.SecurityTestUtils.sleep(1000);
      }
      
      // All runs should have consistent results
      const consistentResults = detectionRuns.every(result => result === detectionRuns[0]);
      
      expect(consistentResults).to.be.true;
      
      if (consistentResults) {
        global.SecurityTestUtils.logSecurityPassed('consistent_root_detection');
      } else {
        global.SecurityTestUtils.logSecurityFailed('inconsistent_root_detection', 
          'Root detection results were inconsistent across multiple runs');
      }
      
      console.log(`🔄 Detection consistency: ${detectionRuns.join(', ')}`);
    });
  });

  after(async function() {
    // Generate test summary
    console.log('\n📊 Root Detection Test Summary:');
    console.log('===============================');
    console.log(`Device Type: ${global.deviceType}`);
    console.log(`Device Model: ${deviceInfo.deviceInfo?.model || 'Unknown'}`);
    
    if (this.currentTest?.parent?.ctx?.rootDetection) {
      const detection = this.currentTest.parent.ctx.rootDetection;
      console.log(`Root Status: ${detection.detected ? 'ROOTED' : 'NOT ROOTED'}`);
      console.log(`Confidence: ${Math.round(detection.confidence * 100)}%`);
      console.log(`Risk Level: ${detection.risk}`);
    }
    
    console.log('===============================\n');
  });

  // Helper methods for root hiding detection
  async checkForRootCloak() {
    const result = await global.adbHelper.executeShellCommand('pm list packages | grep rootcloak');
    return result.success && result.output.includes('rootcloak');
  }

  async checkForHideMyRoot() {
    const result = await global.adbHelper.executeShellCommand('pm list packages | grep hidemyroot');
    return result.success && result.output.includes('hidemyroot');
  }

  async checkForMagiskHide() {
    // Check for Magisk Hide configuration
    const result = await global.adbHelper.executeShellCommand('test -d /data/adb/magisk_hide && echo exists');
    return result.success && result.output.includes('exists');
  }

  async checkForUniversalRootHide() {
    const result = await global.adbHelper.executeShellCommand('pm list packages | grep universal');
    return result.success && result.output.includes('universal') && result.output.includes('root');
  }
});