/**
 * Test Data Configuration
 * Centralized test data management for security testing scenarios
 */

const crypto = require('crypto');

// Security test users with different risk profiles
const testUsers = {
  legitimate: {
    username: 'legit_user_001',
    password: 'SecurePass123!',
    email: 'legitimate@testdomain.com',
    profile: {
      accountAge: 365,
      transactionHistory: 'clean',
      riskScore: 0.1,
      previousViolations: 0,
      verificationLevel: 'full'
    },
    deviceProfile: {
      expectedDeviceType: 'physical',
      expectedLocation: 'US',
      sessionPattern: 'regular'
    }
  },
  
  suspicious: {
    username: 'suspect_user_001',
    password: 'WeakPass1',
    email: 'suspicious@tempmail.com',
    profile: {
      accountAge: 7,
      transactionHistory: 'unusual_patterns',
      riskScore: 0.7,
      previousViolations: 2,
      verificationLevel: 'partial'
    },
    deviceProfile: {
      expectedDeviceType: 'emulator',
      expectedLocation: 'multiple',
      sessionPattern: 'irregular'
    }
  },
  
  highRisk: {
    username: 'highrisk_user_001',
    password: 'password123',
    email: 'highrisk@10minutemail.com',
    profile: {
      accountAge: 1,
      transactionHistory: 'flagged',
      riskScore: 0.9,
      previousViolations: 5,
      verificationLevel: 'none'
    },
    deviceProfile: {
      expectedDeviceType: 'rooted',
      expectedLocation: 'proxy',
      sessionPattern: 'automation'
    }
  }
};

// Security test scenarios
const securityScenarios = {
  emulatorDetection: {
    name: 'Emulator Detection Testing',
    description: 'Test app behavior on emulated vs physical devices',
    testCases: [
      {
        id: 'EMU_001',
        name: 'Basic emulator detection',
        deviceType: 'emulator',
        expectedBehavior: 'show_warning',
        user: testUsers.legitimate,
        assertions: [
          'emulator_warning_displayed',
          'access_restricted',
          'security_log_created'
        ]
      },
      {
        id: 'EMU_002',
        name: 'Physical device confirmation',
        deviceType: 'physical',
        expectedBehavior: 'normal_operation',
        user: testUsers.legitimate,
        assertions: [
          'no_emulator_warning',
          'full_access_granted',
          'normal_functionality'
        ]
      },
      {
        id: 'EMU_003',
        name: 'Emulator bypass attempt',
        deviceType: 'emulator',
        expectedBehavior: 'block_access',
        user: testUsers.highRisk,
        manipulations: ['hide_emulator_properties'],
        assertions: [
          'bypass_detection_failed',
          'access_blocked',
          'security_alert_triggered'
        ]
      }
    ]
  },
  
  rootDetection: {
    name: 'Root Detection Testing',
    description: 'Test app behavior on rooted vs non-rooted devices',
    testCases: [
      {
        id: 'ROOT_001',
        name: 'Basic root detection',
        deviceType: 'rooted',
        expectedBehavior: 'block_access',
        user: testUsers.legitimate,
        assertions: [
          'root_warning_displayed',
          'access_completely_blocked',
          'security_incident_logged'
        ]
      },
      {
        id: 'ROOT_002',
        name: 'Non-rooted device verification',
        deviceType: 'physical',
        expectedBehavior: 'normal_operation',
        user: testUsers.legitimate,
        assertions: [
          'no_root_warning',
          'full_functionality_available',
          'security_checks_passed'
        ]
      },
      {
        id: 'ROOT_003',
        name: 'Root hiding detection',
        deviceType: 'rooted',
        expectedBehavior: 'detect_hidden_root',
        user: testUsers.suspicious,
        manipulations: ['hide_root_indicators'],
        assertions: [
          'hidden_root_detected',
          'advanced_security_triggered',
          'access_denied_with_reason'
        ]
      }
    ]
  },
  
  fileTampering: {
    name: 'File Tampering Detection Testing',
    description: 'Test detection of file system modifications',
    testCases: [
      {
        id: 'FILE_001',
        name: 'Configuration file tampering',
        deviceType: 'physical',
        expectedBehavior: 'detect_tampering',
        user: testUsers.suspicious,
        manipulations: [
          {
            type: 'modify_config',
            file: '/data/data/com.app/shared_prefs/security.xml',
            changes: { 'debug_mode': 'true' }
          }
        ],
        assertions: [
          'tampering_detected',
          'security_warning_shown',
          'app_functionality_restricted'
        ]
      },
      {
        id: 'FILE_002',
        name: 'Binary file corruption',
        deviceType: 'physical',
        expectedBehavior: 'detect_corruption',
        user: testUsers.legitimate,
        manipulations: [
          {
            type: 'corrupt_binary',
            file: '/data/app/com.app/lib/libsecurity.so',
            method: 'random_bytes_injection'
          }
        ],
        assertions: [
          'corruption_detected',
          'integrity_check_failed',
          'app_refuses_to_start'
        ]
      }
    ]
  },
  
  networkSecurity: {
    name: 'Network Security Testing',
    description: 'Test network-related security measures',
    testCases: [
      {
        id: 'NET_001',
        name: 'Proxy detection',
        deviceType: 'physical',
        expectedBehavior: 'detect_proxy',
        user: testUsers.suspicious,
        networkConfig: {
          proxy: 'http://proxy.test:8080',
          ssl_proxy: 'https://proxy.test:8443'
        },
        assertions: [
          'proxy_detected',
          'warning_displayed',
          'enhanced_security_enabled'
        ]
      },
      {
        id: 'NET_002',
        name: 'Certificate pinning bypass',
        deviceType: 'physical',
        expectedBehavior: 'prevent_bypass',
        user: testUsers.highRisk,
        manipulations: [
          'install_custom_ca',
          'modify_network_config'
        ],
        assertions: [
          'bypass_attempt_blocked',
          'connection_refused',
          'security_violation_logged'
        ]
      }
    ]
  }
};

// Mock data for various testing scenarios
const mockData = {
  // Emulator properties for testing detection
  emulatorProperties: {
    suspicious: {
      'ro.build.fingerprint': 'generic/sdk_gphone_x86/generic_x86:11/RSR1.201211.001/6953398:user/release-keys',
      'ro.build.model': 'Android SDK built for x86',
      'ro.build.product': 'sdk_gphone_x86',
      'ro.hardware': 'goldfish',
      'ro.kernel.qemu': '1',
      'ro.product.device': 'generic_x86',
      'ro.serialno': 'emulator-5554'
    },
    physical: {
      'ro.build.fingerprint': 'google/redfin/redfin:13/TQ2A.230505.002/9891397:user/release-keys',
      'ro.build.model': 'Pixel 5',
      'ro.build.product': 'redfin',
      'ro.hardware': 'redfin',
      'ro.product.device': 'redfin',
      'ro.serialno': 'ABC123456789'
    }
  },
  
  // Root indicators for testing
  rootIndicators: {
    present: [
      '/system/bin/su',
      '/system/xbin/su',
      '/sbin/su',
      '/system/app/Superuser.apk',
      '/system/app/SuperSU.apk'
    ],
    processes: [
      'su',
      'superuser',
      'supersu',
      'daemonsu',
      'magiskd'
    ],
    packages: [
      'com.noshufou.android.su',
      'com.thirdparty.superuser',
      'eu.chainfire.supersu',
      'com.koushikdutta.superuser',
      'com.topjohnwu.magisk'
    ]
  },
  
  // Network configurations for testing
  networkConfigurations: {
    normal: {
      dns: ['8.8.8.8', '8.8.4.4'],
      proxy: null,
      vpn: false,
      operator: 'Test Network'
    },
    suspicious: {
      dns: ['1.1.1.1', '1.0.0.1'],
      proxy: 'http://suspicious-proxy.com:8080',
      vpn: true,
      operator: 'Unknown Network'
    },
    corporate: {
      dns: ['192.168.1.1'],
      proxy: 'http://corporate-proxy.internal:3128',
      vpn: false,
      operator: 'Corporate Network'
    }
  },
  
  // File integrity test data
  fileChecksums: {
    '/system/build.prop': 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
    '/system/bin/app_process': 'a665a45920422f9d417e4867efdc4fb8a04a1f3fff1fa07e998e86f7f7a27ae3',
    '/data/app/com.test.app/base.apk': 'b5d4045c3f466fa91fe2cc6abe79232a1a57cdf104f7a26e716e0a1e2789df78'
  },
  
  // Application packages for testing
  testApplications: {
    legitimate: {
      packageName: 'com.test.legitimate.app',
      versionName: '1.0.0',
      versionCode: 100,
      debuggable: false,
      testOnly: false,
      allowBackup: false,
      targetSdk: 33,
      minSdk: 21
    },
    debug: {
      packageName: 'com.test.debug.app',
      versionName: '1.0.0-debug',
      versionCode: 100,
      debuggable: true,
      testOnly: true,
      allowBackup: true,
      targetSdk: 33,
      minSdk: 21
    },
    suspicious: {
      packageName: 'com.suspicious.app',
      versionName: '0.1.0',
      versionCode: 1,
      debuggable: true,
      testOnly: false,
      allowBackup: true,
      targetSdk: 23,
      minSdk: 16
    }
  }
};

// Security thresholds and configurations
const securityThresholds = {
  riskScores: {
    low: 0.3,
    medium: 0.6,
    high: 0.8,
    critical: 0.9
  },
  
  emulatorDetection: {
    confidenceThreshold: 0.7,
    maxAllowedIndicators: 3,
    blockingEnabled: true
  },
  
  rootDetection: {
    confidenceThreshold: 0.5,
    maxAllowedIndicators: 1,
    blockingEnabled: true
  },
  
  fileIntegrity: {
    checksumMismatchTolerance: 0,
    criticalFiles: [
      '/system/build.prop',
      '/system/bin/app_process',
      '/data/app/*/base.apk'
    ],
    monitoringEnabled: true
  },
  
  networkSecurity: {
    allowProxies: false,
    allowVpns: false,
    requireCertificatePinning: true,
    maxRedirects: 3
  }
};

// Test environment configurations
const testEnvironments = {
  development: {
    apiEndpoint: 'https://dev-api.test.com',
    debugMode: true,
    loggingLevel: 'debug',
    securityLevel: 'relaxed',
    allowEmulators: true,
    allowRootedDevices: false
  },
  
  staging: {
    apiEndpoint: 'https://staging-api.test.com',
    debugMode: false,
    loggingLevel: 'info',
    securityLevel: 'standard',
    allowEmulators: true,
    allowRootedDevices: false
  },
  
  production: {
    apiEndpoint: 'https://api.test.com',
    debugMode: false,
    loggingLevel: 'error',
    securityLevel: 'strict',
    allowEmulators: false,
    allowRootedDevices: false
  }
};

/**
 * Utility functions for test data management
 */
class TestDataManager {
  /**
   * Get user data by risk profile
   */
  static getUserByProfile(profile) {
    return testUsers[profile] || testUsers.legitimate;
  }
  
  /**
   * Get security scenario by name
   */
  static getSecurityScenario(scenarioName) {
    return securityScenarios[scenarioName];
  }
  
  /**
   * Generate random test user
   */
  static generateRandomUser(profile = 'legitimate') {
    const baseUser = testUsers[profile];
    const timestamp = Date.now();
    
    return {
      ...baseUser,
      username: `${baseUser.username}_${timestamp}`,
      email: `test_${timestamp}@testdomain.com`,
      sessionId: this.generateSessionId(),
      createdAt: new Date().toISOString()
    };
  }
  
  /**
   * Generate session ID
   */
  static generateSessionId() {
    return crypto.randomBytes(16).toString('hex');
  }
  
  /**
   * Get mock data by category
   */
  static getMockData(category, type = null) {
    const categoryData = mockData[category];
    return type ? categoryData[type] : categoryData;
  }
  
  /**
   * Get security threshold
   */
  static getSecurityThreshold(category, metric) {
    const categoryThresholds = securityThresholds[category];
    return metric ? categoryThresholds[metric] : categoryThresholds;
  }
  
  /**
   * Get test environment configuration
   */
  static getEnvironmentConfig(environment = 'development') {
    return testEnvironments[environment] || testEnvironments.development;
  }
  
  /**
   * Validate test data structure
   */
  static validateTestData(data, schema) {
    // Simple validation - in production, use a library like Joi
    const requiredFields = schema.required || [];
    const missingFields = requiredFields.filter(field => !data[field]);
    
    if (missingFields.length > 0) {
      throw new Error(`Missing required fields: ${missingFields.join(', ')}`);
    }
    
    return true;
  }
  
  /**
   * Create test data backup
   */
  static createBackup() {
    return {
      timestamp: new Date().toISOString(),
      users: testUsers,
      scenarios: securityScenarios,
      mockData: mockData,
      thresholds: securityThresholds
    };
  }
  
  /**
   * Generate test report data
   */
  static generateReportData(testResults) {
    return {
      summary: {
        totalTests: testResults.length,
        passed: testResults.filter(r => r.status === 'passed').length,
        failed: testResults.filter(r => r.status === 'failed').length,
        skipped: testResults.filter(r => r.status === 'skipped').length
      },
      securityFindings: testResults.filter(r => r.securityIssue),
      recommendations: this.generateRecommendations(testResults),
      timestamp: new Date().toISOString()
    };
  }
  
  /**
   * Generate security recommendations based on test results
   */
  static generateRecommendations(testResults) {
    const recommendations = [];
    
    // Analyze emulator detection results
    const emulatorTests = testResults.filter(r => r.testType === 'emulator_detection');
    if (emulatorTests.some(t => t.status === 'failed')) {
      recommendations.push({
        category: 'emulator_detection',
        priority: 'high',
        message: 'Strengthen emulator detection mechanisms',
        action: 'Review and update emulator fingerprinting techniques'
      });
    }
    
    // Analyze root detection results
    const rootTests = testResults.filter(r => r.testType === 'root_detection');
    if (rootTests.some(t => t.status === 'failed')) {
      recommendations.push({
        category: 'root_detection',
        priority: 'critical',
        message: 'Improve root detection capabilities',
        action: 'Implement additional root detection methods'
      });
    }
    
    return recommendations;
  }
}

module.exports = {
  testUsers,
  securityScenarios,
  mockData,
  securityThresholds,
  testEnvironments,
  TestDataManager
};