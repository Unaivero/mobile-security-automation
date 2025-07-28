/**
 * WebDriverIO Configuration
 * Main configuration file for mobile security automation testing
 */

const { getCapabilities, getDeviceConfig } = require('./src/config/capabilities');
const { SecurityConfigManager } = require('./src/config/security-config');
const path = require('path');

// Environment configuration
const TEST_ENV = process.env.TEST_ENV || 'development';
const DEVICE_TYPE = process.env.DEVICE_TYPE || 'emulator';
const PARALLEL = process.env.PARALLEL ? parseInt(process.env.PARALLEL) : 1;
const DEBUG = process.env.DEBUG === 'true';

// Initialize security configuration
const securityConfig = new SecurityConfigManager(TEST_ENV);
const deviceConfig = getDeviceConfig(DEVICE_TYPE);

exports.config = {
  // Test runner configuration
  runner: 'local',
  
  // Appium server configuration  
  protocol: 'http',
  hostname: process.env.APPIUM_HOST || 'localhost',
  port: parseInt(process.env.APPIUM_PORT) || 4723,
  path: '/',
  
  // Test specifications
  specs: [
    './tests/security/**/*.test.js',
    './tests/integration/**/*.test.js'
  ],
  
  // Test suites
  suites: {
    security: [
      './tests/security/emulator-detection.test.js',
      './tests/security/root-detection.test.js',
      './tests/security/file-tampering.test.js',
      './tests/security/environment-analysis.test.js'
    ],
    integration: [
      './tests/integration/security-flow.test.js',
      './tests/integration/threat-response.test.js'
    ],
    emulator: [
      './tests/security/emulator-detection.test.js'
    ],
    root: [
      './tests/security/root-detection.test.js'
    ],
    tampering: [
      './tests/security/file-tampering.test.js'
    ],
    network: [
      './tests/security/network-security.test.js'
    ]
  },
  
  // Exclude patterns
  exclude: [
    './tests/fixtures/**',
    './tests/helpers/**',
    './tests/**/*.skip.js'
  ],
  
  // Device capabilities
  capabilities: [{
    ...getCapabilities(DEVICE_TYPE, {
      // Override with environment variables
      platformVersion: process.env.PLATFORM_VERSION,
      deviceName: process.env.DEVICE_NAME,
      appPackage: process.env.APP_PACKAGE,
      appActivity: process.env.APP_ACTIVITY,
      app: process.env.APP_PATH,
      udid: process.env.DEVICE_UDID
    })
  }],
  
  // Test execution settings
  logLevel: DEBUG ? 'debug' : 'info',
  logLevels: {
    webdriver: DEBUG ? 'debug' : 'silent',
    'appium:command': DEBUG ? 'info' : 'silent'
  },
  
  coloredLogs: true,
  screenshotPath: './reports/screenshots/',
  baseUrl: process.env.BASE_URL || 'http://localhost',
  
  // Timeouts
  waitforTimeout: deviceConfig.timeout,
  connectionRetryTimeout: 120000,
  connectionRetryCount: 3,
  
  // Test framework
  framework: 'mocha',
  mochaOpts: {
    ui: 'bdd',
    timeout: deviceConfig.timeout * 2,
    retries: deviceConfig.retries,
    bail: process.env.FAIL_FAST === 'true'
  },
  
  // Parallel execution
  maxInstances: PARALLEL,
  maxInstancesPerCapability: PARALLEL,
  
  // Services
  services: [
    ['appium', {
      logPath: './reports/logs/',
      command: 'appium',
      args: {
        // Appium server arguments
        address: 'localhost',
        port: 4723,
        relaxedSecurity: true,
        allowInsecure: ['adb_shell'],
        denyInsecure: [],
        log: './reports/logs/appium.log',
        logLevel: DEBUG ? 'debug' : 'info',
        logTimestamp: true,
        // Security-specific configurations
        defaultCapabilities: JSON.stringify({
          securityTesting: true,
          allowTestPackages: true
        })
      }
    }]
  ],
  
  // Reporters
  reporters: [
    'spec',
    ['allure', {
      outputDir: './reports/allure-results/',
      disableWebdriverStepsReporting: false,
      disableWebdriverScreenshotsReporting: false,
      useCucumberStepReporter: false
    }],
    ['junit', {
      outputDir: './reports/junit/',
      outputFileFormat: function(options) {
        return `security-test-results-${options.cid}.xml`;
      }
    }],
    ['json', {
      outputDir: './reports/json/',
      outputFileFormat: function(options) {
        return `security-test-results-${options.cid}.json`;
      }
    }],
    ['html-nice', {
      outputDir: './reports/html/',
      filename: 'security-test-report.html',
      reportTitle: 'Mobile Security Test Report',
      linkScreenshots: true,
      showInBrowser: false,
      collapseTests: false,
      useOnAfterCommandForScreenshot: true
    }]
  ],
  
  // Hooks
  onPrepare: function (config, capabilities) {
    console.log('🛡️  Mobile Security Testing Framework');
    console.log('=====================================');
    console.log(`Environment: ${TEST_ENV}`);
    console.log(`Device Type: ${DEVICE_TYPE}`);
    console.log(`Parallel Execution: ${PARALLEL}`);
    console.log(`Security Level: ${securityConfig.config.security_level}`);
    console.log('=====================================\n');
    
    // Validate security configuration
    try {
      securityConfig.validateConfiguration();
      console.log('✅ Security configuration validated\n');
    } catch (error) {
      console.error('❌ Security configuration validation failed:', error.message);
      process.exit(1);
    }
  },
  
  before: async function (capabilities, specs, browser) {
    // Set global test context
    global.testEnvironment = TEST_ENV;
    global.deviceType = DEVICE_TYPE;
    global.securityConfig = securityConfig;
    global.browser = browser;
    
    // Initialize security utilities
    const ADBHelper = require('./src/utils/adb-helper');
    const DeviceDetector = require('./src/utils/device-detector');
    const SecurityChecker = require('./src/utils/security-checker');
    const FileManipulator = require('./src/utils/file-manipulator');
    
    global.adbHelper = new ADBHelper();
    global.deviceDetector = new DeviceDetector();
    global.securityChecker = new SecurityChecker();
    global.fileManipulator = new FileManipulator();
    
    // Initialize file manipulator
    await global.fileManipulator.initialize();
    
    // Set browser timeouts
    await browser.setTimeout({
      'implicit': 10000,
      'pageLoad': 30000,
      'script': 30000
    });
    
    console.log('🔧 Test environment initialized');
  },
  
  beforeTest: async function (test, context) {
    console.log(`\n🧪 Starting test: ${test.title}`);
    
    // Create test-specific screenshot directory
    const testDir = path.join('./reports/screenshots', test.parent.replace(/\s+/g, '-'));
    await browser.executeScript('mobile: shell', {
      command: 'mkdir',
      args: ['-p', testDir]
    }).catch(() => {}); // Ignore errors
    
    // Log test start for security audit
    global.SecurityTestUtils?.logSecurityStep('test_start', test.title);
  },
  
  afterTest: async function (test, context, { error, result, duration, passed, retries }) {
    if (error) {
      console.log(`❌ Test failed: ${test.title}`);
      console.log(`   Error: ${error.message}`);
      
      // Take screenshot on failure
      try {
        const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
        const screenshotPath = `./reports/screenshots/failure-${test.title.replace(/\s+/g, '-')}-${timestamp}.png`;
        await browser.saveScreenshot(screenshotPath);
        console.log(`📸 Failure screenshot saved: ${screenshotPath}`);
      } catch (screenshotError) {
        console.error('Failed to take screenshot:', screenshotError.message);
      }
      
      // Log security test failure
      global.SecurityTestUtils?.logSecurityFailed(test.title, error.message);
    } else {
      console.log(`✅ Test passed: ${test.title} (${duration}ms)`);
      global.SecurityTestUtils?.logSecurityPassed(test.title);
    }
  },
  
  after: async function (result, capabilities, specs) {
    console.log('\n🧹 Cleaning up test environment...');
    
    try {
      // Cleanup file manipulator
      if (global.fileManipulator) {
        await global.fileManipulator.cleanup();
      }
      
      // Reset device state if needed
      if (DEVICE_TYPE === 'emulator' && process.env.RESET_AFTER_TESTS === 'true') {
        console.log('🔄 Resetting emulator state...');
        // Add emulator reset logic here
      }
      
      console.log('✅ Cleanup completed');
    } catch (error) {
      console.error('❌ Cleanup failed:', error.message);
    }
  },
  
  onComplete: function (exitCode, config, capabilities, results) {
    console.log('\n📊 Test Execution Summary:');
    console.log('==========================');
    
    const totalTests = results.counts.total || 0;
    const passedTests = results.counts.passed || 0;
    const failedTests = results.counts.failed || 0;
    const skippedTests = results.counts.skipped || 0;
    
    console.log(`Total Tests: ${totalTests}`);
    console.log(`Passed: ${passedTests}`);
    console.log(`Failed: ${failedTests}`);
    console.log(`Skipped: ${skippedTests}`);
    console.log(`Success Rate: ${totalTests > 0 ? Math.round((passedTests/totalTests) * 100) : 0}%`);
    console.log('==========================');
    
    // Security-specific reporting
    if (results.securityFindings && results.securityFindings.length > 0) {
      console.log('\n🚨 Security Findings:');
      results.securityFindings.forEach((finding, index) => {
        console.log(`${index + 1}. ${finding.severity}: ${finding.description}`);
      });
    }
    
    // Generate compliance report if enabled
    if (securityConfig.isFeatureEnabled('compliance.audit.enabled')) {
      console.log('\n📋 Generating compliance report...');
      // Add compliance report generation logic here
    }
    
    // Send alerts if critical failures
    if (failedTests > 0 && securityConfig.isFeatureEnabled('alerts.channels.email.enabled')) {
      console.log('\n📧 Sending failure alerts...');
      // Add alert sending logic here
    }
    
    console.log('\n🏁 Test execution completed');
    
    // Exit with appropriate code
    process.exit(exitCode);
  },
  
  // Error handling
  onError: function (error, context) {
    console.error('🚨 Test execution error:', error.message);
    
    // Log error for security audit
    global.SecurityTestUtils?.logSecurityFailed('test_execution', error.message);
  },
  
  // Custom security testing configuration
  securityTesting: {
    enabled: true,
    environment: TEST_ENV,
    deviceType: DEVICE_TYPE,
    policies: securityConfig.config.policies,
    evidenceCollection: securityConfig.config.testConfig.evidence,
    reporting: securityConfig.config.testConfig.reporting,
    
    // Test-specific overrides
    overrides: {
      emulator_detection: {
        timeout: 45000,
        retries: 2,
        evidence: ['screenshots', 'logs', 'device_info']
      },
      root_detection: {
        timeout: 60000,
        retries: 1,
        evidence: ['screenshots', 'logs', 'system_props']
      },
      file_tampering: {
        timeout: 90000,
        retries: 2,
        evidence: ['screenshots', 'logs', 'file_checksums']
      }
    }
  }
};