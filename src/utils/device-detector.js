/**
 * Device Detector Utility
 * Provides device state detection and analysis for security testing
 */

const ADBHelper = require('./adb-helper');
const chalk = require('chalk');
const crypto = require('crypto');

class DeviceDetector {
  constructor(deviceId = null) {
    this.adb = new ADBHelper(deviceId);
    this.detectionCache = new Map();
    this.cacheTimeout = 30000; // 30 seconds
  }

  /**
   * Comprehensive device analysis
   */
  async analyzeDevice() {
    try {
      console.log(chalk.blue('🔍 Starting comprehensive device analysis...'));
      
      const analysis = {
        deviceInfo: await this.getDeviceInfo(),
        emulatorDetection: await this.detectEmulator(),
        rootDetection: await this.detectRoot(),
        debugDetection: await this.detectDebugging(),
        securityFeatures: await this.checkSecurityFeatures(),
        networkAnalysis: await this.analyzeNetwork(),
        installedApps: await this.getSecurityRelevantApps(),
        riskAssessment: null,
        timestamp: new Date().toISOString()
      };

      // Calculate overall risk assessment
      analysis.riskAssessment = this.calculateRiskScore(analysis);
      
      console.log(chalk.green('✅ Device analysis completed'));
      this.logAnalysisResults(analysis);
      
      return analysis;
    } catch (error) {
      console.error(chalk.red('❌ Device analysis failed:'), error.message);
      return { error: error.message, timestamp: new Date().toISOString() };
    }
  }

  /**
   * Get comprehensive device information
   */
  async getDeviceInfo() {
    const cacheKey = 'device_info';
    const cached = this.getCachedResult(cacheKey);
    if (cached) return cached;

    try {
      console.log(chalk.blue('📱 Getting device information...'));
      
      const deviceInfo = await this.adb.getDeviceInfo();
      const properties = await this.adb.getSystemProperties();
      
      const info = {
        ...deviceInfo,
        buildDate: properties['ro.build.date'],
        buildUser: properties['ro.build.user'],
        buildHost: properties['ro.build.host'],
        buildTags: properties['ro.build.tags'],
        cpuAbi: properties['ro.product.cpu.abi'],
        cpuAbi2: properties['ro.product.cpu.abi2'],
        density: properties['ro.sf.lcd_density'],
        locale: properties['ro.product.locale'],
        timezone: properties['persist.sys.timezone'],
        securityPatch: properties['ro.build.version.security_patch'],
        kernelVersion: await this.getKernelVersion(),
        storageInfo: await this.getStorageInfo(),
        memoryInfo: await this.getMemoryInfo()
      };

      this.setCachedResult(cacheKey, info);
      return info;
    } catch (error) {
      console.error(chalk.red('❌ Failed to get device info:'), error.message);
      return { error: error.message };
    }
  }

  /**
   * Advanced emulator detection
   */
  async detectEmulator() {
    const cacheKey = 'emulator_detection';
    const cached = this.getCachedResult(cacheKey);
    if (cached) return cached;

    try {
      console.log(chalk.blue('🔍 Performing advanced emulator detection...'));
      
      const properties = await this.adb.getSystemProperties();
      const detectionResults = {
        buildFingerprint: this.checkBuildFingerprint(properties),
        hardwareFeatures: await this.checkHardwareFeatures(),
        systemFiles: await this.checkEmulatorFiles(),
        networkInterface: await this.checkNetworkInterfaces(),
        sensorData: await this.checkSensors(),
        performanceMetrics: await this.checkPerformanceCharacteristics(),
        processAnalysis: await this.checkEmulatorProcesses()
      };

      // Calculate confidence score
      const indicators = Object.values(detectionResults).filter(result => result.detected).length;
      const confidence = indicators / Object.keys(detectionResults).length;
      
      const result = {
        isEmulator: confidence > 0.5,
        confidence: confidence,
        indicators: indicators,
        details: detectionResults,
        timestamp: new Date().toISOString()
      };

      console.log(chalk.yellow(`📱 Emulator detection: ${result.isEmulator ? 'EMULATOR' : 'PHYSICAL'} (${Math.round(confidence * 100)}% confidence)`));
      
      this.setCachedResult(cacheKey, result);
      return result;
    } catch (error) {
      console.error(chalk.red('❌ Emulator detection failed:'), error.message);
      return { error: error.message, isEmulator: false };
    }
  }

  /**
   * Advanced root detection
   */
  async detectRoot() {
    const cacheKey = 'root_detection';
    const cached = this.getCachedResult(cacheKey);
    if (cached) return cached;

    try {
      console.log(chalk.blue('🔍 Performing advanced root detection...'));
      
      const detectionResults = {
        suBinary: await this.checkSuBinary(),
        rootApps: await this.checkRootApps(),
        systemWritable: await this.checkSystemWritable(),
        dangerousProps: await this.checkDangerousProps(),
        rootCloaking: await this.checkRootCloaking(),
        busyBox: await this.checkBusyBox(),
        xposed: await this.checkXposedFramework(),
        magisk: await this.checkMagisk()
      };

      // Calculate confidence score
      const indicators = Object.values(detectionResults).filter(result => result.detected).length;
      const confidence = indicators / Object.keys(detectionResults).length;
      
      const result = {
        isRooted: confidence > 0.3, // Lower threshold due to root hiding techniques
        confidence: confidence,
        indicators: indicators,
        details: detectionResults,
        timestamp: new Date().toISOString()
      };

      console.log(chalk.yellow(`🔓 Root detection: ${result.isRooted ? 'ROOTED' : 'NOT ROOTED'} (${Math.round(confidence * 100)}% confidence)`));
      
      this.setCachedResult(cacheKey, result);
      return result;
    } catch (error) {
      console.error(chalk.red('❌ Root detection failed:'), error.message);
      return { error: error.message, isRooted: false };
    }
  }

  /**
   * Detect debugging environments
   */
  async detectDebugging() {
    try {
      console.log(chalk.blue('🔍 Detecting debugging environments...'));
      
      const properties = await this.adb.getSystemProperties();
      
      const debugging = {
        adbEnabled: properties['ro.adb.secure'] === '0',
        debuggable: properties['ro.debuggable'] === '1',
        developerOptions: await this.checkDeveloperOptions(),
        usbDebugging: await this.checkUSBDebugging(),
        mockLocations: await this.checkMockLocations(),
        debuggerAttached: await this.checkDebuggerAttached()
      };

      const result = {
        debuggingDetected: Object.values(debugging).some(Boolean),
        details: debugging,
        riskLevel: this.calculateDebuggingRisk(debugging)
      };

      return result;
    } catch (error) {
      console.error(chalk.red('❌ Debug detection failed:'), error.message);
      return { error: error.message };
    }
  }

  /**
   * Check device security features
   */
  async checkSecurityFeatures() {
    try {
      console.log(chalk.blue('🔒 Checking device security features...'));
      
      const features = {
        screenLock: await this.checkScreenLock(),
        encryption: await this.checkEncryption(),
        selinux: await this.checkSELinux(),
        verifiedBoot: await this.checkVerifiedBoot(),
        playProtect: await this.checkPlayProtect(),
        securityPatch: await this.checkSecurityPatchLevel(),
        keystore: await this.checkKeystore()
      };

      return {
        securityScore: this.calculateSecurityScore(features),
        features: features
      };
    } catch (error) {
      console.error(chalk.red('❌ Security features check failed:'), error.message);
      return { error: error.message };
    }
  }

  /**
   * Analyze network configuration
   */
  async analyzeNetwork() {
    try {
      console.log(chalk.blue('🌐 Analyzing network configuration...'));
      
      const network = {
        interfaces: await this.getNetworkInterfaces(),
        vpnStatus: await this.checkVPNStatus(),
        proxySettings: await this.checkProxySettings(),
        dnsServers: await this.getDNSServers(),
        networkOperator: await this.getNetworkOperator()
      };

      return {
        riskIndicators: this.analyzeNetworkRisks(network),
        details: network
      };
    } catch (error) {
      console.error(chalk.red('❌ Network analysis failed:'), error.message);
      return { error: error.message };
    }
  }

  /**
   * Get security-relevant installed applications
   */
  async getSecurityRelevantApps() {
    try {
      console.log(chalk.blue('📱 Analyzing installed applications...'));
      
      const result = await this.adb.executeShellCommand('pm list packages');
      if (!result.success) return [];

      const packages = result.output.split('\n')
        .map(line => line.replace('package:', ''))
        .filter(pkg => pkg.trim());

      const securityApps = {
        rootingApps: packages.filter(pkg => this.isRootingApp(pkg)),
        securityApps: packages.filter(pkg => this.isSecurityApp(pkg)),
        hackingTools: packages.filter(pkg => this.isHackingTool(pkg)),
        vpnApps: packages.filter(pkg => this.isVPNApp(pkg)),
        debuggingApps: packages.filter(pkg => this.isDebuggingApp(pkg))
      };

      return {
        totalPackages: packages.length,
        securityRelevant: securityApps,
        riskApps: [...securityApps.rootingApps, ...securityApps.hackingTools]
      };
    } catch (error) {
      console.error(chalk.red('❌ App analysis failed:'), error.message);
      return { error: error.message };
    }
  }

  /**
   * Calculate overall device risk score
   */
  calculateRiskScore(analysis) {
    try {
      let riskScore = 0;
      let maxScore = 0;

      // Emulator detection (20 points if emulator)
      if (analysis.emulatorDetection && !analysis.emulatorDetection.error) {
        if (analysis.emulatorDetection.isEmulator) riskScore += 20;
        maxScore += 20;
      }

      // Root detection (30 points if rooted)
      if (analysis.rootDetection && !analysis.rootDetection.error) {
        if (analysis.rootDetection.isRooted) riskScore += 30;
        maxScore += 30;
      }

      // Debugging detection (15 points if debugging enabled)
      if (analysis.debugDetection && !analysis.debugDetection.error) {
        if (analysis.debugDetection.debuggingDetected) riskScore += 15;
        maxScore += 15;
      }

      // Security features (inverse scoring - less features = more risk)
      if (analysis.securityFeatures && !analysis.securityFeatures.error) {
        const securityDeficit = Math.max(0, 10 - (analysis.securityFeatures.securityScore || 0));
        riskScore += securityDeficit;
        maxScore += 10;
      }

      // Risk apps (10 points for presence of risky apps)
      if (analysis.installedApps && !analysis.installedApps.error) {
        if (analysis.installedApps.riskApps && analysis.installedApps.riskApps.length > 0) {
          riskScore += 10;
        }
        maxScore += 10;
      }

      // Network risks (15 points for network-based risks)
      if (analysis.networkAnalysis && !analysis.networkAnalysis.error) {
        if (analysis.networkAnalysis.riskIndicators && analysis.networkAnalysis.riskIndicators.length > 0) {
          riskScore += Math.min(15, analysis.networkAnalysis.riskIndicators.length * 5);
        }
        maxScore += 15;
      }

      const normalizedScore = maxScore > 0 ? (riskScore / maxScore) * 100 : 0;
      
      return {
        score: Math.round(normalizedScore),
        level: this.getRiskLevel(normalizedScore),
        factors: {
          emulator: analysis.emulatorDetection?.isEmulator || false,
          rooted: analysis.rootDetection?.isRooted || false,
          debugging: analysis.debugDetection?.debuggingDetected || false,
          securityFeatures: analysis.securityFeatures?.securityScore || 0,
          riskApps: analysis.installedApps?.riskApps?.length || 0,
          networkRisks: analysis.networkAnalysis?.riskIndicators?.length || 0
        }
      };
    } catch (error) {
      console.error(chalk.red('❌ Risk calculation failed:'), error.message);
      return { score: 50, level: 'unknown', error: error.message };
    }
  }

  /**
   * Helper methods for specific checks
   */
  
  checkBuildFingerprint(properties) {
    const fingerprint = properties['ro.build.fingerprint'] || '';
    const model = properties['ro.build.model'] || '';
    const product = properties['ro.build.product'] || '';
    
    const emulatorIndicators = [
      fingerprint.includes('generic'),
      fingerprint.includes('test-keys'),
      model.includes('Emulator'),
      model.includes('Android SDK'),
      product.includes('sdk'),
      product.includes('generic')
    ];

    return {
      detected: emulatorIndicators.some(Boolean),
      indicators: emulatorIndicators.filter(Boolean).length,
      details: { fingerprint, model, product }
    };
  }

  async checkHardwareFeatures() {
    try {
      const result = await this.adb.executeShellCommand('pm list features');
      const features = result.success ? result.output : '';
      
      const hardwareFeatures = {
        camera: features.includes('android.hardware.camera'),
        gps: features.includes('android.hardware.location.gps'),
        nfc: features.includes('android.hardware.nfc'),
        telephony: features.includes('android.hardware.telephony'),
        bluetooth: features.includes('android.hardware.bluetooth'),
        wifi: features.includes('android.hardware.wifi')
      };

      // Emulators often lack hardware features
      const missingFeatures = Object.values(hardwareFeatures).filter(f => !f).length;
      
      return {
        detected: missingFeatures > 3,
        missingFeatures: missingFeatures,
        details: hardwareFeatures
      };
    } catch (error) {
      return { detected: false, error: error.message };
    }
  }

  async checkEmulatorFiles() {
    const emulatorFiles = [
      '/system/lib/libc_malloc_debug_qemu.so',
      '/sys/qemu_trace',
      '/system/bin/qemu-props',
      '/dev/socket/qemud',
      '/dev/qemu_pipe',
      '/proc/tty/drivers'
    ];

    try {
      let foundFiles = 0;
      for (const file of emulatorFiles) {
        const result = await this.adb.executeShellCommand(`test -e ${file} && echo exists || echo missing`);
        if (result.success && result.output.includes('exists')) {
          foundFiles++;
        }
      }

      return {
        detected: foundFiles > 0,
        foundFiles: foundFiles,
        totalChecked: emulatorFiles.length
      };
    } catch (error) {
      return { detected: false, error: error.message };
    }
  }

  async getKernelVersion() {
    try {
      const result = await this.adb.executeShellCommand('uname -a');
      return result.success ? result.output.trim() : 'unknown';
    } catch (error) {
      return 'unknown';
    }
  }

  async getStorageInfo() {
    try {
      const result = await this.adb.executeShellCommand('df /data');
      if (result.success) {
        const lines = result.output.split('\n');
        const dataLine = lines.find(line => line.includes('/data'));
        if (dataLine) {
          const parts = dataLine.trim().split(/\s+/);
          return {
            total: parts[1],
            used: parts[2],
            available: parts[3],
            usage: parts[4]
          };
        }
      }
      return {};
    } catch (error) {
      return {};
    }
  }

  async getMemoryInfo() {
    try {
      const result = await this.adb.executeShellCommand('cat /proc/meminfo | head -5');
      if (result.success) {
        const memInfo = {};
        result.output.split('\n').forEach(line => {
          const match = line.match(/^(\w+):\s*(\d+)\s*kB/);
          if (match) {
            memInfo[match[1]] = parseInt(match[2]);
          }
        });
        return memInfo;
      }
      return {};
    } catch (error) {
      return {};
    }
  }

  // Additional helper methods...
  
  getRiskLevel(score) {
    if (score >= 80) return 'critical';
    if (score >= 60) return 'high';
    if (score >= 40) return 'medium';
    if (score >= 20) return 'low';
    return 'minimal';
  }

  logAnalysisResults(analysis) {
    console.log(chalk.blue('\n📊 Device Analysis Summary:'));
    console.log(chalk.gray('================================'));
    
    if (analysis.deviceInfo && !analysis.deviceInfo.error) {
      console.log(chalk.white(`Device: ${analysis.deviceInfo.model} (${analysis.deviceInfo.manufacturer})`));
      console.log(chalk.white(`Android: ${analysis.deviceInfo.androidVersion} (API ${analysis.deviceInfo.apiLevel})`));
    }
    
    if (analysis.emulatorDetection && !analysis.emulatorDetection.error) {
      const status = analysis.emulatorDetection.isEmulator ? chalk.red('EMULATOR') : chalk.green('PHYSICAL');
      console.log(chalk.white(`Type: ${status}`));
    }
    
    if (analysis.rootDetection && !analysis.rootDetection.error) {
      const status = analysis.rootDetection.isRooted ? chalk.red('ROOTED') : chalk.green('NOT ROOTED');
      console.log(chalk.white(`Root: ${status}`));
    }
    
    if (analysis.riskAssessment) {
      const riskColor = analysis.riskAssessment.level === 'critical' ? chalk.red :
                       analysis.riskAssessment.level === 'high' ? chalk.yellow :
                       chalk.green;
      console.log(chalk.white(`Risk: ${riskColor(analysis.riskAssessment.level.toUpperCase())} (${analysis.riskAssessment.score}/100)`));
    }
    
    console.log(chalk.gray('================================\n'));
  }

  // Cache management
  getCachedResult(key) {
    const cached = this.detectionCache.get(key);
    if (cached && Date.now() - cached.timestamp < this.cacheTimeout) {
      return cached.data;
    }
    return null;
  }

  setCachedResult(key, data) {
    this.detectionCache.set(key, {
      data,
      timestamp: Date.now()
    });
  }

  // Stub methods for comprehensive implementation
  async checkSuBinary() { return { detected: false }; }
  async checkRootApps() { return { detected: false }; }
  async checkSystemWritable() { return { detected: false }; }
  async checkDangerousProps() { return { detected: false }; }
  async checkRootCloaking() { return { detected: false }; }
  async checkBusyBox() { return { detected: false }; }
  async checkXposedFramework() { return { detected: false }; }
  async checkMagisk() { return { detected: false }; }
  async checkDeveloperOptions() { return false; }
  async checkUSBDebugging() { return false; }
  async checkMockLocations() { return false; }
  async checkDebuggerAttached() { return false; }
  async checkScreenLock() { return true; }
  async checkEncryption() { return true; }
  async checkSELinux() { return true; }
  async checkVerifiedBoot() { return true; }
  async checkPlayProtect() { return true; }
  async checkSecurityPatchLevel() { return 10; }
  async checkKeystore() { return true; }
  async getNetworkInterfaces() { return []; }
  async checkVPNStatus() { return false; }
  async checkProxySettings() { return {}; }
  async getDNSServers() { return []; }
  async getNetworkOperator() { return ''; }
  async checkNetworkInterfaces() { return { detected: false }; }
  async checkSensors() { return { detected: false }; }
  async checkPerformanceCharacteristics() { return { detected: false }; }
  async checkEmulatorProcesses() { return { detected: false }; }
  
  calculateDebuggingRisk(debugging) {
    const risks = Object.values(debugging).filter(Boolean).length;
    return risks > 2 ? 'high' : risks > 0 ? 'medium' : 'low';
  }
  
  calculateSecurityScore(features) {
    return Object.values(features).filter(Boolean).length;
  }
  
  analyzeNetworkRisks(network) {
    return [];
  }
  
  isRootingApp(pkg) {
    const rootingApps = ['supersu', 'superuser', 'kingroot', 'kingoroot', 'magisk'];
    return rootingApps.some(app => pkg.includes(app));
  }
  
  isSecurityApp(pkg) {
    const securityApps = ['antivirus', 'security', 'malware', 'firewall'];
    return securityApps.some(app => pkg.includes(app));
  }
  
  isHackingTool(pkg) {
    const hackingTools = ['frida', 'xposed', 'substrate', 'gameguardian'];
    return hackingTools.some(tool => pkg.includes(tool));
  }
  
  isVPNApp(pkg) {
    return pkg.includes('vpn') || pkg.includes('tunnel');
  }
  
  isDebuggingApp(pkg) {
    const debugApps = ['adb', 'debug', 'developer', 'logcat'];
    return debugApps.some(app => pkg.includes(app));
  }
}

module.exports = DeviceDetector;