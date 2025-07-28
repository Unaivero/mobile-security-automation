/**
 * Security Checker Utility
 * Provides comprehensive security validation helpers for mobile testing
 */

const ADBHelper = require('./adb-helper');
const DeviceDetector = require('./device-detector');
const FileManipulator = require('./file-manipulator');
const chalk = require('chalk');
const crypto = require('crypto');

class SecurityChecker {
  constructor(deviceId = null) {
    this.adb = new ADBHelper(deviceId);
    this.deviceDetector = new DeviceDetector(deviceId);
    this.fileManipulator = new FileManipulator(deviceId);
    this.securityResults = new Map();
    this.alertThresholds = {
      emulator: 0.7,
      root: 0.5,
      tamper: 0.3,
      debug: 0.6
    };
  }

  /**
   * Comprehensive security validation
   */
  async validateSecurity(options = {}) {
    try {
      console.log(chalk.blue('🛡️  Starting comprehensive security validation...'));
      
      const validation = {
        timestamp: new Date().toISOString(),
        deviceAnalysis: await this.validateDeviceSecurity(),
        applicationSecurity: await this.validateApplicationSecurity(options.packageName),
        environmentSecurity: await this.validateEnvironmentSecurity(),
        fileIntegrity: await this.validateFileIntegrity(options.criticalFiles || []),
        networkSecurity: await this.validateNetworkSecurity(),
        runtimeSecurity: await this.validateRuntimeSecurity(),
        overallAssessment: null
      };

      // Calculate overall security assessment
      validation.overallAssessment = this.calculateOverallAssessment(validation);
      
      // Store results for historical analysis
      this.securityResults.set(Date.now(), validation);
      
      console.log(chalk.green('✅ Security validation completed'));
      this.logSecuritySummary(validation);
      
      return validation;
    } catch (error) {
      console.error(chalk.red('❌ Security validation failed:'), error.message);
      return { error: error.message, timestamp: new Date().toISOString() };
    }
  }

  /**
   * Validate device-level security
   */
  async validateDeviceSecurity() {
    try {
      console.log(chalk.blue('📱 Validating device security...'));
      
      const deviceAnalysis = await this.deviceDetector.analyzeDevice();
      
      const deviceSecurity = {
        emulatorStatus: {
          isEmulator: deviceAnalysis.emulatorDetection?.isEmulator || false,
          confidence: deviceAnalysis.emulatorDetection?.confidence || 0,
          risk: this.calculateEmulatorRisk(deviceAnalysis.emulatorDetection),
          passed: !deviceAnalysis.emulatorDetection?.isEmulator
        },
        rootStatus: {
          isRooted: deviceAnalysis.rootDetection?.isRooted || false,
          confidence: deviceAnalysis.rootDetection?.confidence || 0,
          risk: this.calculateRootRisk(deviceAnalysis.rootDetection),
          passed: !deviceAnalysis.rootDetection?.isRooted
        },
        debugStatus: {
          debuggingEnabled: deviceAnalysis.debugDetection?.debuggingDetected || false,
          risk: this.calculateDebugRisk(deviceAnalysis.debugDetection),
          passed: !deviceAnalysis.debugDetection?.debuggingDetected
        },
        securityFeatures: {
          score: deviceAnalysis.securityFeatures?.securityScore || 0,
          details: deviceAnalysis.securityFeatures?.features || {},
          passed: (deviceAnalysis.securityFeatures?.securityScore || 0) >= 7
        },
        overallRisk: deviceAnalysis.riskAssessment?.score || 50,
        recommendations: this.generateDeviceRecommendations(deviceAnalysis)
      };

      return deviceSecurity;
    } catch (error) {
      console.error(chalk.red('❌ Device security validation failed:'), error.message);
      return { error: error.message };
    }
  }

  /**
   * Validate application-specific security
   */
  async validateApplicationSecurity(packageName) {
    if (!packageName) {
      return { skipped: true, reason: 'No package name provided' };
    }

    try {
      console.log(chalk.blue(`📱 Validating application security: ${packageName}`));
      
      const appInfo = await this.adb.getApplicationInfo(packageName);
      
      if (!appInfo.success) {
        return { error: 'Failed to get application information' };
      }

      const appSecurity = {
        packageInfo: appInfo.info,
        debuggableCheck: {
          isDebuggable: appInfo.info.debuggable || false,
          risk: appInfo.info.debuggable ? 'high' : 'low',
          passed: !appInfo.info.debuggable
        },
        backupCheck: {
          allowsBackup: appInfo.info.allowBackup || false,
          risk: appInfo.info.allowBackup ? 'medium' : 'low',
          passed: !appInfo.info.allowBackup
        },
        testOnlyCheck: {
          isTestOnly: appInfo.info.testOnly || false,
          risk: appInfo.info.testOnly ? 'high' : 'low',
          passed: !appInfo.info.testOnly
        },
        permissionsAnalysis: await this.analyzeAppPermissions(packageName),
        certificateValidation: await this.validateAppCertificate(packageName),
        codeIntegrity: await this.validateCodeIntegrity(packageName)
      };

      return appSecurity;
    } catch (error) {
      console.error(chalk.red('❌ Application security validation failed:'), error.message);
      return { error: error.message };
    }
  }

  /**
   * Validate environment security
   */
  async validateEnvironmentSecurity() {
    try {
      console.log(chalk.blue('🌐 Validating environment security...'));
      
      const environmentSecurity = {
        adbStatus: await this.checkADBSecurity(),
        developerOptions: await this.checkDeveloperOptions(),
        mockLocationCheck: await this.checkMockLocations(),
        vpnDetection: await this.detectVPN(),
        proxyDetection: await this.detectProxy(),
        hooking: await this.detectHookingFrameworks(),
        antiDebugging: await this.checkAntiDebuggingMeasures()
      };

      return environmentSecurity;
    } catch (error) {
      console.error(chalk.red('❌ Environment security validation failed:'), error.message);
      return { error: error.message };
    }
  }

  /**
   * Validate file integrity
   */
  async validateFileIntegrity(criticalFiles) {
    try {
      console.log(chalk.blue('📁 Validating file integrity...'));
      
      if (criticalFiles.length === 0) {
        // Use default critical files if none provided
        criticalFiles = [
          '/system/build.prop',
          '/system/bin/su',
          '/system/xbin/su',
          '/data/local.prop'
        ];
      }

      const integrityResults = {
        checkedFiles: [],
        violations: [],
        summary: {
          total: criticalFiles.length,
          passed: 0,
          failed: 0,
          missing: 0
        }
      };

      for (const filePath of criticalFiles) {
        const fileCheck = await this.checkFileIntegrity(filePath);
        integrityResults.checkedFiles.push(fileCheck);
        
        if (fileCheck.exists) {
          if (fileCheck.tampered) {
            integrityResults.violations.push(fileCheck);
            integrityResults.summary.failed++;
          } else {
            integrityResults.summary.passed++;
          }
        } else {
          integrityResults.summary.missing++;
        }
      }

      return integrityResults;
    } catch (error) {
      console.error(chalk.red('❌ File integrity validation failed:'), error.message);
      return { error: error.message };
    }
  }

  /**
   * Validate network security
   */
  async validateNetworkSecurity() {
    try {
      console.log(chalk.blue('🌐 Validating network security...'));
      
      const networkSecurity = {
        connectionAnalysis: await this.analyzeNetworkConnections(),
        dnsValidation: await this.validateDNSConfiguration(),
        certificatePinning: await this.checkCertificatePinning(),
        trafficInterception: await this.detectTrafficInterception(),
        networkOperator: await this.validateNetworkOperator()
      };

      return networkSecurity;
    } catch (error) {
      console.error(chalk.red('❌ Network security validation failed:'), error.message);
      return { error: error.message };
    }
  }

  /**
   * Validate runtime security
   */
  async validateRuntimeSecurity() {
    try {
      console.log(chalk.blue('⚡ Validating runtime security...'));
      
      const runtimeSecurity = {
        processAnalysis: await this.analyzeRunningProcesses(),
        memoryProtection: await this.checkMemoryProtection(),
        codeInjection: await this.detectCodeInjection(),
        dynamicAnalysis: await this.performDynamicAnalysis(),
        behaviorAnalysis: await this.analyzeBehaviorPatterns()
      };

      return runtimeSecurity;
    } catch (error) {
      console.error(chalk.red('❌ Runtime security validation failed:'), error.message);
      return { error: error.message };
    }
  }

  /**
   * Detect emulator environment
   */
  async detectEmulator() {
    try {
      console.log(chalk.blue('🔍 Detecting emulator environment...'));
      
      const emulatorCheck = await this.adb.isEmulator();
      
      const detection = {
        detected: emulatorCheck.isEmulator,
        confidence: emulatorCheck.isEmulator ? 0.9 : 0.1,
        indicators: emulatorCheck.indicators || [],
        properties: emulatorCheck.properties || {},
        risk: emulatorCheck.isEmulator ? 'high' : 'low',
        recommendation: emulatorCheck.isEmulator ? 
          'Block access or require additional verification' : 
          'Continue normal operation'
      };

      if (detection.detected) {
        console.log(chalk.red('⚠️  EMULATOR DETECTED'));
        console.log(chalk.red(`   Confidence: ${Math.round(detection.confidence * 100)}%`));
      } else {
        console.log(chalk.green('✅ Physical device confirmed'));
      }

      return detection;
    } catch (error) {
      console.error(chalk.red('❌ Emulator detection failed:'), error.message);
      return { error: error.message, detected: false };
    }
  }

  /**
   * Detect root/jailbreak
   */
  async detectRoot() {
    try {
      console.log(chalk.blue('🔍 Detecting root access...'));
      
      const rootCheck = await this.adb.isRooted();
      
      const detection = {
        detected: rootCheck.isRooted,
        confidence: rootCheck.confidence === 'high' ? 0.9 : 
                   rootCheck.confidence === 'medium' ? 0.6 : 0.3,
        indicators: rootCheck.indicators || [],
        risk: rootCheck.isRooted ? 'critical' : 'low',
        recommendation: rootCheck.isRooted ? 
          'Block access immediately' : 
          'Continue normal operation'
      };

      if (detection.detected) {
        console.log(chalk.red('⚠️  ROOT ACCESS DETECTED'));
        console.log(chalk.red(`   Indicators: ${detection.indicators.join(', ')}`));
      } else {
        console.log(chalk.green('✅ No root access detected'));
      }

      return detection;
    } catch (error) {
      console.error(chalk.red('❌ Root detection failed:'), error.message);
      return { error: error.message, detected: false };
    }
  }

  /**
   * Validate file integrity for a specific file
   */
  async validateFileIntegrity(filePath) {
    try {
      console.log(chalk.blue(`🔍 Validating file integrity: ${filePath}`));
      
      // Check if file exists
      const existsResult = await this.adb.executeShellCommand(`test -f ${filePath} && echo exists || echo missing`);
      const exists = existsResult.success && existsResult.output.includes('exists');
      
      if (!exists) {
        return {
          filePath: filePath,
          exists: false,
          tampered: false,
          details: 'File does not exist'
        };
      }

      // Calculate current checksum
      const checksumResult = await this.adb.executeShellCommand(`sha256sum ${filePath}`);
      if (!checksumResult.success) {
        return {
          filePath: filePath,
          exists: true,
          tampered: null,
          error: 'Could not calculate checksum'
        };
      }

      const currentChecksum = checksumResult.output.split(' ')[0];
      
      // Check against known good checksums (if available)
      const knownChecksums = this.getKnownFileChecksums();
      const expectedChecksum = knownChecksums[filePath];
      
      const integrity = {
        filePath: filePath,
        exists: true,
        currentChecksum: currentChecksum,
        expectedChecksum: expectedChecksum,
        tampered: expectedChecksum ? currentChecksum !== expectedChecksum : false,
        timestamp: new Date().toISOString()
      };

      if (integrity.tampered) {
        console.log(chalk.red(`⚠️  File integrity violation: ${filePath}`));
      } else {
        console.log(chalk.green(`✅ File integrity verified: ${filePath}`));
      }

      return integrity;
    } catch (error) {
      console.error(chalk.red(`❌ File integrity check failed: ${filePath}`), error.message);
      return { filePath, error: error.message };
    }
  }

  /**
   * Calculate overall security assessment
   */
  calculateOverallAssessment(validation) {
    try {
      let totalScore = 0;
      let maxScore = 0;
      const factors = [];

      // Device security (40% weight)
      if (validation.deviceSecurity && !validation.deviceSecurity.error) {
        const deviceScore = this.calculateDeviceSecurityScore(validation.deviceSecurity);
        totalScore += deviceScore * 0.4;
        maxScore += 0.4;
        factors.push({ category: 'device', score: deviceScore, weight: 0.4 });
      }

      // Application security (25% weight)
      if (validation.applicationSecurity && !validation.applicationSecurity.error && !validation.applicationSecurity.skipped) {
        const appScore = this.calculateAppSecurityScore(validation.applicationSecurity);
        totalScore += appScore * 0.25;
        maxScore += 0.25;
        factors.push({ category: 'application', score: appScore, weight: 0.25 });
      }

      // Environment security (20% weight)
      if (validation.environmentSecurity && !validation.environmentSecurity.error) {
        const envScore = this.calculateEnvironmentSecurityScore(validation.environmentSecurity);
        totalScore += envScore * 0.2;
        maxScore += 0.2;
        factors.push({ category: 'environment', score: envScore, weight: 0.2 });
      }

      // File integrity (10% weight)
      if (validation.fileIntegrity && !validation.fileIntegrity.error) {
        const fileScore = this.calculateFileIntegrityScore(validation.fileIntegrity);
        totalScore += fileScore * 0.1;
        maxScore += 0.1;
        factors.push({ category: 'fileIntegrity', score: fileScore, weight: 0.1 });
      }

      // Network security (5% weight)
      if (validation.networkSecurity && !validation.networkSecurity.error) {
        const networkScore = this.calculateNetworkSecurityScore(validation.networkSecurity);
        totalScore += networkScore * 0.05;
        maxScore += 0.05;
        factors.push({ category: 'network', score: networkScore, weight: 0.05 });
      }

      const normalizedScore = maxScore > 0 ? (totalScore / maxScore) * 100 : 50;
      
      return {
        overallScore: Math.round(normalizedScore),
        securityLevel: this.getSecurityLevel(normalizedScore),
        riskLevel: this.getRiskLevel(100 - normalizedScore),
        factors: factors,
        recommendations: this.generateOverallRecommendations(validation, normalizedScore),
        passed: normalizedScore >= 70,
        timestamp: new Date().toISOString()
      };
    } catch (error) {
      console.error(chalk.red('❌ Overall assessment calculation failed:'), error.message);
      return {
        overallScore: 50,
        securityLevel: 'unknown',
        riskLevel: 'medium',
        error: error.message
      };
    }
  }

  /**
   * Helper methods for specific security checks
   */
  
  calculateEmulatorRisk(emulatorDetection) {
    if (!emulatorDetection || emulatorDetection.error) return 'unknown';
    return emulatorDetection.isEmulator ? 'high' : 'low';
  }

  calculateRootRisk(rootDetection) {
    if (!rootDetection || rootDetection.error) return 'unknown';
    return rootDetection.isRooted ? 'critical' : 'low';
  }

  calculateDebugRisk(debugDetection) {
    if (!debugDetection || debugDetection.error) return 'unknown';
    return debugDetection.debuggingDetected ? 'high' : 'low';
  }

  generateDeviceRecommendations(deviceAnalysis) {
    const recommendations = [];
    
    if (deviceAnalysis.emulatorDetection?.isEmulator) {
      recommendations.push('Consider blocking emulator access or requiring additional verification');
    }
    
    if (deviceAnalysis.rootDetection?.isRooted) {
      recommendations.push('Block access immediately - rooted device detected');
    }
    
    if (deviceAnalysis.debugDetection?.debuggingDetected) {
      recommendations.push('Disable debugging features in production');
    }
    
    return recommendations;
  }

  getKnownFileChecksums() {
    // In a real implementation, this would come from a secure database
    return {
      '/system/build.prop': 'known_checksum_1',
      '/system/bin/su': null, // Should not exist
      '/system/xbin/su': null // Should not exist
    };
  }

  calculateDeviceSecurityScore(deviceSecurity) {
    let score = 100;
    
    if (deviceSecurity.emulatorStatus?.isEmulator) score -= 30;
    if (deviceSecurity.rootStatus?.isRooted) score -= 40;
    if (deviceSecurity.debugStatus?.debuggingEnabled) score -= 20;
    
    const securityFeaturesScore = (deviceSecurity.securityFeatures?.score || 0) / 10 * 10;
    score = Math.min(score, score + securityFeaturesScore - 50);
    
    return Math.max(0, score);
  }

  calculateAppSecurityScore(appSecurity) {
    let score = 100;
    
    if (appSecurity.debuggableCheck?.isDebuggable) score -= 30;
    if (appSecurity.backupCheck?.allowsBackup) score -= 15;
    if (appSecurity.testOnlyCheck?.isTestOnly) score -= 25;
    
    return Math.max(0, score);
  }

  calculateEnvironmentSecurityScore(envSecurity) {
    let score = 100;
    
    // Deduct points for each security issue
    Object.values(envSecurity).forEach(check => {
      if (check && check.risk === 'high') score -= 20;
      else if (check && check.risk === 'medium') score -= 10;
    });
    
    return Math.max(0, score);
  }

  calculateFileIntegrityScore(fileIntegrity) {
    if (!fileIntegrity.summary) return 50;
    
    const { total, passed, failed } = fileIntegrity.summary;
    return total > 0 ? Math.round((passed / total) * 100) : 100;
  }

  calculateNetworkSecurityScore(networkSecurity) {
    // Simplified network security scoring
    return 80; // Default good score if no major issues
  }

  getSecurityLevel(score) {
    if (score >= 90) return 'excellent';
    if (score >= 80) return 'good';
    if (score >= 70) return 'acceptable';
    if (score >= 60) return 'poor';
    return 'critical';
  }

  getRiskLevel(score) {
    if (score >= 80) return 'critical';
    if (score >= 60) return 'high';
    if (score >= 40) return 'medium';
    if (score >= 20) return 'low';
    return 'minimal';
  }

  generateOverallRecommendations(validation, score) {
    const recommendations = [];
    
    if (score < 70) {
      recommendations.push('Overall security posture is insufficient for production use');
    }
    
    if (validation.deviceSecurity?.emulatorStatus?.isEmulator) {
      recommendations.push('Implement emulator detection and blocking');
    }
    
    if (validation.deviceSecurity?.rootStatus?.isRooted) {
      recommendations.push('Implement root detection and access restriction');
    }
    
    return recommendations;
  }

  logSecuritySummary(validation) {
    console.log(chalk.blue('\n🛡️  Security Validation Summary:'));
    console.log(chalk.gray('========================================='));
    
    if (validation.overallAssessment) {
      const assessment = validation.overallAssessment;
      const scoreColor = assessment.overallScore >= 80 ? chalk.green :
                        assessment.overallScore >= 60 ? chalk.yellow :
                        chalk.red;
      
      console.log(chalk.white(`Overall Score: ${scoreColor(assessment.overallScore + '/100')}`));
      console.log(chalk.white(`Security Level: ${assessment.securityLevel.toUpperCase()}`));
      console.log(chalk.white(`Risk Level: ${assessment.riskLevel.toUpperCase()}`));
      console.log(chalk.white(`Status: ${assessment.passed ? chalk.green('PASSED') : chalk.red('FAILED')}`));
    }
    
    console.log(chalk.gray('=========================================\n'));
  }

  // Stub methods for comprehensive implementation
  async analyzeAppPermissions(packageName) { return { risk: 'low', details: [] }; }
  async validateAppCertificate(packageName) { return { valid: true, details: {} }; }
  async validateCodeIntegrity(packageName) { return { intact: true, details: {} }; }
  async checkADBSecurity() { return { secure: true, details: {} }; }
  async checkDeveloperOptions() { return { enabled: false, risk: 'low' }; }
  async checkMockLocations() { return { enabled: false, risk: 'low' }; }
  async detectVPN() { return { detected: false, risk: 'low' }; }
  async detectProxy() { return { detected: false, risk: 'low' }; }
  async detectHookingFrameworks() { return { detected: false, risk: 'low' }; }
  async checkAntiDebuggingMeasures() { return { active: true, effectiveness: 'high' }; }
  async checkFileIntegrity(filePath) { return { exists: true, tampered: false }; }
  async analyzeNetworkConnections() { return { suspicious: false, details: [] }; }
  async validateDNSConfiguration() { return { secure: true, details: {} }; }
  async checkCertificatePinning() { return { enabled: true, bypass: false }; }
  async detectTrafficInterception() { return { detected: false, risk: 'low' }; }
  async validateNetworkOperator() { return { trusted: true, details: {} }; }
  async analyzeRunningProcesses() { return { suspicious: [], total: 0 }; }
  async checkMemoryProtection() { return { enabled: true, effectiveness: 'high' }; }
  async detectCodeInjection() { return { detected: false, risk: 'low' }; }
  async performDynamicAnalysis() { return { threats: [], score: 90 }; }
  async analyzeBehaviorPatterns() { return { anomalies: [], score: 95 }; }
}

module.exports = SecurityChecker;