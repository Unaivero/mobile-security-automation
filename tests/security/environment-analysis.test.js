/**
 * Environment Analysis Security Tests
 * Comprehensive testing of the device environment for security threats
 */

const { expect } = require('chai');
const BasePage = require('../../src/pages/base-page');
const SecurityPage = require('../../src/pages/security-page');
const { TestDataManager } = require('../../src/config/test-data');

describe('Environment Analysis Security Tests', function() {
  let basePage, securityPage;
  let testConfig, deviceInfo, environmentAnalysis;

  before(async function() {
    // Initialize page objects
    basePage = new BasePage(browser);
    securityPage = new SecurityPage(browser);
    
    // Get test configuration
    testConfig = global.securityConfig.getTestConfiguration('environment_analysis');
    
    // Perform comprehensive device analysis
    deviceInfo = await global.deviceDetector.analyzeDevice();
    
    console.log(`🔍 Running environment analysis on: ${deviceInfo.deviceInfo?.model || 'Unknown Device'}`);
    console.log(`🌐 Environment: ${global.testEnvironment}`);
    console.log(`📊 Risk Score: ${deviceInfo.riskAssessment?.score || 'Unknown'}/100`);
  });

  describe('Comprehensive Device Profiling', function() {
    it('should perform complete device environment analysis', async function() {
      global.SecurityTestUtils.logSecurityStep('device_profiling', 'Performing comprehensive device analysis');
      
      // Perform comprehensive security validation
      environmentAnalysis = await global.securityChecker.validateSecurity({
        packageName: process.env.APP_PACKAGE,
        criticalFiles: [
          '/system/build.prop',
          '/system/bin/su',
          '/data/local.prop'
        ]
      });
      
      expect(environmentAnalysis).to.have.property('timestamp');
      expect(environmentAnalysis).to.have.property('deviceAnalysis');
      expect(environmentAnalysis).to.have.property('overallAssessment');
      
      const assessment = environmentAnalysis.overallAssessment;
      
      console.log(`🛡️  Overall Security Score: ${assessment.overallScore}/100`);
      console.log(`📊 Security Level: ${assessment.securityLevel}`);
      console.log(`⚠️  Risk Level: ${assessment.riskLevel}`);
      console.log(`✅ Assessment: ${assessment.passed ? 'PASSED' : 'FAILED'}`);
      
      // Log individual factor scores
      if (assessment.factors) {
        assessment.factors.forEach(factor => {
          console.log(`   ${factor.category}: ${Math.round(factor.score)}% (weight: ${factor.weight})`);
        });
      }
      
      // Take comprehensive screenshot
      await basePage.takeSecurityScreenshot('environment-analysis', 
        'Comprehensive environment security analysis');
      
      // Store analysis for later tests
      this.currentTest.parent.environmentAnalysis = environmentAnalysis;
    });

    it('should analyze device hardware characteristics', async function() {
      global.SecurityTestUtils.logSecurityStep('hardware_analysis', 'Analyzing device hardware characteristics');
      
      // Get detailed device information
      const deviceAnalysis = environmentAnalysis.deviceAnalysis || await global.deviceDetector.analyzeDevice();
      
      expect(deviceAnalysis).to.have.property('deviceInfo');
      
      const hardwareInfo = {
        manufacturer: deviceAnalysis.deviceInfo.manufacturer,
        model: deviceAnalysis.deviceInfo.model,
        hardware: deviceAnalysis.deviceInfo.hardware,
        cpuAbi: deviceAnalysis.deviceInfo.cpuAbi,
        memory: deviceAnalysis.deviceInfo.memoryInfo,
        storage: deviceAnalysis.deviceInfo.storageInfo
      };
      
      console.log('🔧 Hardware Analysis:');
      Object.entries(hardwareInfo).forEach(([key, value]) => {
        if (value) {
          console.log(`   ${key}: ${typeof value === 'object' ? JSON.stringify(value) : value}`);
        }
      });
      
      // Check for suspicious hardware characteristics
      const suspiciousHardware = [];
      
      if (hardwareInfo.hardware?.includes('goldfish')) {
        suspiciousHardware.push('emulator_hardware');
      }
      
      if (hardwareInfo.model?.toLowerCase().includes('sdk')) {
        suspiciousHardware.push('sdk_model');
      }
      
      if (suspiciousHardware.length > 0) {
        global.SecurityTestUtils.logThreatDetected('suspicious_hardware', 
          `Suspicious hardware characteristics: ${suspiciousHardware.join(', ')}`);
      } else {
        global.SecurityTestUtils.logSecurityPassed('hardware_analysis_clean');
      }
      
      // Store hardware analysis
      this.currentTest.hardwareAnalysis = hardwareInfo;
    });

    it('should analyze software environment', async function() {
      global.SecurityTestUtils.logSecurityStep('software_analysis', 'Analyzing software environment');
      
      // Get system properties and analyze
      const systemProps = await global.adbHelper.getSystemProperties();
      
      const softwareInfo = {
        androidVersion: systemProps['ro.build.version.release'],
        apiLevel: systemProps['ro.build.version.sdk'],
        buildType: systemProps['ro.build.type'],
        buildTags: systemProps['ro.build.tags'],
        buildUser: systemProps['ro.build.user'],
        buildHost: systemProps['ro.build.host'],
        securityPatch: systemProps['ro.build.version.security_patch'],
        bootloader: systemProps['ro.bootloader'],
        kernel: deviceInfo.deviceInfo?.kernelVersion
      };
      
      console.log('💾 Software Environment:');
      Object.entries(softwareInfo).forEach(([key, value]) => {
        if (value) {
          console.log(`   ${key}: ${value}`);
        }
      });
      
      // Analyze for security concerns
      const securityConcerns = [];
      
      // Check build tags
      if (softwareInfo.buildTags === 'test-keys') {
        securityConcerns.push('test_build');
      }
      
      // Check build user
      if (softwareInfo.buildUser && softwareInfo.buildUser !== 'android-build') {
        securityConcerns.push('non_standard_build_user');
      }
      
      // Check API level (warn if too old)
      const apiLevel = parseInt(softwareInfo.apiLevel);
      if (apiLevel < 23) { // Android 6.0
        securityConcerns.push('outdated_android_version');
      }
      
      if (securityConcerns.length > 0) {
        global.SecurityTestUtils.logThreatDetected('software_security_concerns', 
          `Software security concerns: ${securityConcerns.join(', ')}`);
      } else {
        global.SecurityTestUtils.logSecurityPassed('software_environment_secure');
      }
      
      // Store software analysis
      this.currentTest.softwareAnalysis = softwareInfo;
    });
  });

  describe('Network Environment Analysis', function() {
    it('should analyze network configuration', async function() {
      global.SecurityTestUtils.logSecurityStep('network_analysis', 'Analyzing network environment');
      
      // Get network interface information
      const networkResult = await global.adbHelper.executeShellCommand('ip addr show');
      const networkInterfaces = networkResult.success ? networkResult.output : '';
      
      // Get DNS configuration
      const dnsResult = await global.adbHelper.executeShellCommand('getprop | grep dns');
      const dnsConfig = dnsResult.success ? dnsResult.output : '';
      
      // Get network operator information
      const operatorResult = await global.adbHelper.executeShellCommand('getprop | grep operator');
      const operatorInfo = operatorResult.success ? operatorResult.output : '';
      
      console.log('🌐 Network Environment Analysis:');
      console.log(`   Interfaces: ${networkInterfaces.split('\n').length} detected`);
      console.log(`   DNS Config: ${dnsConfig.split('\n').length} entries`);
      console.log(`   Operator: ${operatorInfo.includes('operator') ? 'Detected' : 'Unknown'}`);
      
      // Check for suspicious network indicators
      const networkThreats = [];
      
      // Check for tun interfaces (VPN indicators)
      if (networkInterfaces.includes('tun') || networkInterfaces.includes('ppp')) {
        networkThreats.push('vpn_interface_detected');
      }
      
      // Check for proxy indicators in network config
      const proxyCheck = await global.adbHelper.executeShellCommand('getprop | grep proxy');
      if (proxyCheck.success && proxyCheck.output.trim()) {
        networkThreats.push('proxy_configuration_detected');
      }
      
      if (networkThreats.length > 0) {
        global.SecurityTestUtils.logThreatDetected('network_threats', 
          `Network threats detected: ${networkThreats.join(', ')}`);
      } else {
        global.SecurityTestUtils.logSecurityPassed('network_environment_clean');
      }
      
      // Store network analysis
      this.currentTest.networkAnalysis = {
        interfaces: networkInterfaces,
        dns: dnsConfig,
        operator: operatorInfo,
        threats: networkThreats
      };
    });

    it('should detect proxy and VPN usage', async function() {
      global.SecurityTestUtils.logSecurityStep('proxy_vpn_detection', 'Detecting proxy and VPN usage');
      
      // Check HTTP proxy settings
      const httpProxy = await global.adbHelper.executeShellCommand('getprop http.proxyHost');
      const httpProxyPort = await global.adbHelper.executeShellCommand('getprop http.proxyPort');
      
      // Check HTTPS proxy settings  
      const httpsProxy = await global.adbHelper.executeShellCommand('getprop https.proxyHost');
      const httpsProxyPort = await global.adbHelper.executeShellCommand('getprop https.proxyPort');
      
      const proxyConfig = {
        httpProxy: httpProxy.success ? httpProxy.output.trim() : '',
        httpProxyPort: httpProxyPort.success ? httpProxyPort.output.trim() : '',
        httpsProxy: httpsProxy.success ? httpsProxy.output.trim() : '',
        httpsProxyPort: httpsProxyPort.success ? httpsProxyPort.output.trim() : ''
      };
      
      const proxyDetected = Object.values(proxyConfig).some(value => value && value !== '');
      
      if (proxyDetected) {
        console.log('🕸️  Proxy Configuration Detected:');
        Object.entries(proxyConfig).forEach(([key, value]) => {
          if (value) console.log(`   ${key}: ${value}`);
        });
        
        global.SecurityTestUtils.logThreatDetected('proxy_detected', 
          `Proxy configuration detected: ${JSON.stringify(proxyConfig)}`);
      } else {
        global.SecurityTestUtils.logSecurityPassed('no_proxy_detected');
      }
      
      // Check for VPN indicators
      const vpnCheck = await global.adbHelper.executeShellCommand('ps | grep vpn');
      const vpnProcesses = vpnCheck.success ? vpnCheck.output.split('\n').filter(line => line.includes('vpn')) : [];
      
      if (vpnProcesses.length > 0) {
        console.log(`🔒 VPN Processes Detected: ${vpnProcesses.length}`);
        vpnProcesses.forEach(process => console.log(`   ${process.trim()}`));
        
        global.SecurityTestUtils.logThreatDetected('vpn_detected', 
          `VPN processes detected: ${vpnProcesses.length}`);
      } else {
        global.SecurityTestUtils.logSecurityPassed('no_vpn_detected');
      }
    });
  });

  describe('Application Environment Analysis', function() {
    it('should analyze installed applications for security risks', async function() {
      global.SecurityTestUtils.logSecurityStep('app_analysis', 'Analyzing installed applications');
      
      // Get list of installed packages
      const packagesResult = await global.adbHelper.executeShellCommand('pm list packages');
      expect(packagesResult.success).to.be.true;
      
      const packages = packagesResult.output.split('\n')
        .map(line => line.replace('package:', ''))
        .filter(pkg => pkg.trim());
      
      console.log(`📱 Total packages installed: ${packages.length}`);
      
      // Categorize applications
      const appCategories = {
        rootingApps: [],
        securityApps: [],
        hackingTools: [],
        vpnApps: [],
        debuggingApps: [],
        suspiciousApps: []
      };
      
      // Known security-relevant package patterns
      const patterns = {
        rootingApps: ['supersu', 'superuser', 'kingroot', 'magisk', 'chainfire'],
        securityApps: ['antivirus', 'security', 'malware', 'firewall'],
        hackingTools: ['frida', 'xposed', 'substrate', 'gameguardian', 'cheat'],
        vpnApps: ['vpn', 'tunnel', 'proxy'],
        debuggingApps: ['adb', 'debug', 'developer', 'logcat', 'monitor'],
        suspiciousApps: ['fake', 'clone', 'hacker', 'crack']
      };
      
      // Categorize packages
      packages.forEach(pkg => {
        Object.entries(patterns).forEach(([category, keywords]) => {
          if (keywords.some(keyword => pkg.toLowerCase().includes(keyword))) {
            appCategories[category].push(pkg);
          }
        });
      });
      
      // Report findings
      console.log('📊 Application Security Analysis:');
      Object.entries(appCategories).forEach(([category, apps]) => {
        if (apps.length > 0) {
          console.log(`   ${category}: ${apps.length} found`);
          apps.slice(0, 3).forEach(app => console.log(`     - ${app}`));
          if (apps.length > 3) console.log(`     ... and ${apps.length - 3} more`);
        }
      });
      
      // Generate security alerts
      const riskApps = [...appCategories.rootingApps, ...appCategories.hackingTools, ...appCategories.suspiciousApps];
      
      if (riskApps.length > 0) {
        global.SecurityTestUtils.logThreatDetected('risky_apps_detected', 
          `${riskApps.length} potentially risky applications detected`);
      } else {
        global.SecurityTestUtils.logSecurityPassed('no_risky_apps_detected');
      }
      
      // Store app analysis
      this.currentTest.appAnalysis = {
        totalPackages: packages.length,
        categories: appCategories,
        riskScore: riskApps.length / packages.length
      };
    });

    it('should analyze development and debugging tools', async function() {
      global.SecurityTestUtils.logSecurityStep('dev_tools_analysis', 'Analyzing development and debugging tools');
      
      // Check ADB status
      const adbStatus = await global.adbHelper.executeShellCommand('getprop ro.adb.secure');
      const adbSecure = adbStatus.success ? adbStatus.output.trim() : '1';
      
      // Check developer options
      const devOptions = await global.adbHelper.executeShellCommand('getprop ro.debuggable');
      const debuggable = devOptions.success ? devOptions.output.trim() : '0';
      
      // Check USB debugging
      const usbDebug = await global.adbHelper.executeShellCommand('getprop persist.service.adb.enable');
      const usbDebugging = usbDebug.success ? usbDebug.output.trim() : '0';
      
      const devConfig = {
        adbSecure: adbSecure === '1',
        debuggable: debuggable === '1',
        usbDebugging: usbDebugging === '1'
      };
      
      console.log('🛠️  Development Configuration:');
      console.log(`   ADB Secure: ${devConfig.adbSecure}`);
      console.log(`   Debuggable: ${devConfig.debuggable}`);
      console.log(`   USB Debugging: ${devConfig.usbDebugging}`);
      
      // Assess development risk
      const devRisks = [];
      
      if (!devConfig.adbSecure) {
        devRisks.push('adb_not_secure');
      }
      
      if (devConfig.debuggable && global.testEnvironment === 'production') {
        devRisks.push('debugging_enabled_in_production');
      }
      
      if (devConfig.usbDebugging) {
        devRisks.push('usb_debugging_enabled');
      }
      
      if (devRisks.length > 0) {
        global.SecurityTestUtils.logThreatDetected('development_risks', 
          `Development-related risks: ${devRisks.join(', ')}`);
      } else {
        global.SecurityTestUtils.logSecurityPassed('development_configuration_secure');
      }
      
      // Store dev analysis
      this.currentTest.devAnalysis = {
        configuration: devConfig,
        risks: devRisks,
        riskLevel: devRisks.length > 2 ? 'high' : devRisks.length > 0 ? 'medium' : 'low'
      };
    });
  });

  describe('Security Feature Analysis', function() {
    it('should analyze device security features', async function() {
      global.SecurityTestUtils.logSecurityStep('security_features', 'Analyzing device security features');
      
      const securityFeatures = {};
      
      // Check SELinux status
      const selinuxResult = await global.adbHelper.executeShellCommand('getenforce');
      securityFeatures.selinux = selinuxResult.success ? selinuxResult.output.trim() : 'Unknown';
      
      // Check encryption status
      const encryptionResult = await global.adbHelper.executeShellCommand('getprop ro.crypto.state');
      securityFeatures.encryption = encryptionResult.success ? encryptionResult.output.trim() : 'Unknown';
      
      // Check verified boot
      const verifiedBootResult = await global.adbHelper.executeShellCommand('getprop ro.boot.verifiedbootstate');
      securityFeatures.verifiedBoot = verifiedBootResult.success ? verifiedBootResult.output.trim() : 'Unknown';
      
      // Check security patch level
      const patchResult = await global.adbHelper.executeShellCommand('getprop ro.build.version.security_patch');
      securityFeatures.securityPatch = patchResult.success ? patchResult.output.trim() : 'Unknown';
      
      console.log('🔒 Security Features Analysis:');
      Object.entries(securityFeatures).forEach(([feature, status]) => {
        console.log(`   ${feature}: ${status}`);
      });
      
      // Evaluate security posture
      const securityScore = this.calculateSecurityScore(securityFeatures);
      console.log(`📊 Device Security Score: ${securityScore}/100`);
      
      if (securityScore < 70) {
        global.SecurityTestUtils.logThreatDetected('weak_security_features', 
          `Device security features are insufficient (score: ${securityScore}/100)`);
      } else {
        global.SecurityTestUtils.logSecurityPassed('security_features_adequate');
      }
      
      // Store security features analysis
      this.currentTest.securityFeatures = {
        features: securityFeatures,
        score: securityScore,
        assessment: securityScore >= 70 ? 'adequate' : 'insufficient'
      };
    });

    it('should generate comprehensive threat assessment', async function() {
      global.SecurityTestUtils.logSecurityStep('threat_assessment', 'Generating comprehensive threat assessment');
      
      // Compile all analysis results
      const threatAssessment = {
        deviceProfile: this.currentTest.parent.environmentAnalysis?.deviceAnalysis || deviceInfo,
        hardwareThreats: this.extractThreats(this.currentTest.hardwareAnalysis),
        softwareThreats: this.extractThreats(this.currentTest.softwareAnalysis),
        networkThreats: this.currentTest.networkAnalysis?.threats || [],
        applicationThreats: this.calculateAppThreats(this.currentTest.appAnalysis),
        developmentThreats: this.currentTest.devAnalysis?.risks || [],
        securityDeficits: this.calculateSecurityDeficits(this.currentTest.securityFeatures),
        overallRisk: 'calculating...'
      };
      
      // Calculate overall risk score
      const riskFactors = [
        threatAssessment.hardwareThreats.length * 10,
        threatAssessment.softwareThreats.length * 8,
        threatAssessment.networkThreats.length * 12,
        threatAssessment.applicationThreats * 15,
        threatAssessment.developmentThreats.length * 6,
        threatAssessment.securityDeficits * 20
      ];
      
      const totalRisk = riskFactors.reduce((sum, risk) => sum + risk, 0);
      threatAssessment.overallRisk = Math.min(100, totalRisk);
      
      console.log('🚨 Comprehensive Threat Assessment:');
      console.log(`   Hardware Threats: ${threatAssessment.hardwareThreats.length}`);
      console.log(`   Software Threats: ${threatAssessment.softwareThreats.length}`);
      console.log(`   Network Threats: ${threatAssessment.networkThreats.length}`);
      console.log(`   Application Risk: ${threatAssessment.applicationThreats}`);
      console.log(`   Development Risks: ${threatAssessment.developmentThreats.length}`);
      console.log(`   Security Deficits: ${threatAssessment.securityDeficits}`);
      console.log(`   Overall Risk Score: ${threatAssessment.overallRisk}/100`);
      
      // Generate final assessment
      const riskLevel = this.getRiskLevel(threatAssessment.overallRisk);
      console.log(`🎯 Risk Level: ${riskLevel.toUpperCase()}`);
      
      if (riskLevel === 'high' || riskLevel === 'critical') {
        global.SecurityTestUtils.logThreatDetected('high_risk_environment', 
          `Environment poses high security risk (score: ${threatAssessment.overallRisk}/100)`);
      } else {
        global.SecurityTestUtils.logSecurityPassed('acceptable_risk_environment');
      }
      
      // Take final screenshot
      await basePage.takeSecurityScreenshot('threat-assessment', 
        'Comprehensive threat assessment results');
      
      // Store final assessment
      this.currentTest.threatAssessment = threatAssessment;
    });
  });

  after(async function() {
    // Generate comprehensive test summary
    console.log('\n📊 Environment Analysis Test Summary:');
    console.log('=====================================');
    console.log(`Device: ${deviceInfo.deviceInfo?.manufacturer} ${deviceInfo.deviceInfo?.model}`);
    console.log(`Android: ${deviceInfo.deviceInfo?.androidVersion} (API ${deviceInfo.deviceInfo?.apiLevel})`);
    console.log(`Environment: ${global.testEnvironment}`);
    
    if (environmentAnalysis?.overallAssessment) {
      const assessment = environmentAnalysis.overallAssessment;
      console.log(`Security Score: ${assessment.overallScore}/100`);
      console.log(`Security Level: ${assessment.securityLevel}`);
      console.log(`Risk Level: ${assessment.riskLevel}`);
      console.log(`Overall: ${assessment.passed ? 'PASSED' : 'FAILED'}`);
    }
    
    console.log('=====================================\n');
  });

  // Helper methods
  calculateSecurityScore(features) {
    let score = 100;
    
    if (features.selinux !== 'Enforcing') score -= 20;
    if (features.encryption !== 'encrypted') score -= 25;
    if (features.verifiedBoot !== 'green') score -= 15;
    if (!features.securityPatch || features.securityPatch === 'Unknown') score -= 10;
    
    return Math.max(0, score);
  }

  extractThreats(analysis) {
    // Extract threat indicators from analysis object
    if (!analysis) return [];
    
    const threats = [];
    Object.entries(analysis).forEach(([key, value]) => {
      if (typeof value === 'string' && (
        value.includes('suspicious') || 
        value.includes('threat') || 
        value.includes('risk')
      )) {
        threats.push(key);
      }
    });
    
    return threats;
  }

  calculateAppThreats(appAnalysis) {
    if (!appAnalysis) return 0;
    
    const riskWeight = {
      rootingApps: 3,
      hackingTools: 2,
      suspiciousApps: 2,
      debuggingApps: 1
    };
    
    let totalThreat = 0;
    Object.entries(appAnalysis.categories).forEach(([category, apps]) => {
      const weight = riskWeight[category] || 0;
      totalThreat += apps.length * weight;
    });
    
    return totalThreat;
  }

  calculateSecurityDeficits(securityFeatures) {
    if (!securityFeatures) return 5;
    
    return Math.max(0, (100 - securityFeatures.score) / 10);
  }

  getRiskLevel(score) {
    if (score >= 80) return 'critical';
    if (score >= 60) return 'high';
    if (score >= 40) return 'medium';
    if (score >= 20) return 'low';
    return 'minimal';
  }
});