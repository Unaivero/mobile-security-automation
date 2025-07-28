/**
 * Device Capabilities Configuration
 * Defines capabilities for different devices and testing scenarios
 */

const path = require('path');

// Base capabilities for Android testing
const baseAndroidCapabilities = {
  platformName: 'Android',
  automationName: 'UiAutomator2',
  newCommandTimeout: 300,
  noReset: true,
  fullReset: false,
  autoGrantPermissions: true,
  ignoreHiddenApiPolicyError: true,
  disableWindowAnimation: true,
  // Security testing specific
  allowTestPackages: true,
  enforceAppInstall: false,
  skipUnlock: true,
  unlockType: 'pin',
  unlockKey: '1234'
};

// Physical device capabilities
const physicalDeviceCapabilities = {
  ...baseAndroidCapabilities,
  // Will be populated with actual device ID at runtime
  udid: process.env.DEVICE_UDID || 'auto-detect',
  systemPort: parseInt(process.env.SYSTEM_PORT) || 8200,
  // Enhanced security testing on physical devices
  gpsEnabled: true,
  isHeadless: false,
  // Real device specific settings
  skipDeviceInitialization: false,
  skipServerInstallation: false
};

// Emulator capabilities
const emulatorCapabilities = {
  ...baseAndroidCapabilities,
  avd: process.env.AVD_NAME || 'SecurityTest_API_30',
  avdLaunchTimeout: 180000,
  avdReadyTimeout: 180000,
  isHeadless: process.env.HEADLESS === 'true',
  // Emulator specific settings
  gpsEnabled: false,
  networkSpeed: 'full',
  // Wipe data for clean state
  avdArgs: '-wipe-data -no-snapshot-load',
  // Enhanced logging for security testing
  enablePerformanceLogging: true
};

// Security-focused capabilities
const securityTestCapabilities = {
  // Enable detailed logging
  logLevel: 'debug',
  enablePerformanceLogging: true,
  printPageSourceOnFindFailure: true,
  
  // Screenshot capabilities for evidence
  screenshotOnFailure: true,
  screenshotPath: './reports/screenshots/',
  
  // Network proxy for traffic analysis
  proxyType: process.env.PROXY_TYPE || 'manual',
  httpProxy: process.env.HTTP_PROXY,
  sslProxy: process.env.SSL_PROXY,
  
  // Additional security testing flags
  allowInvisibleElements: true,
  shouldUseSingletonTestManager: true,
  eventTimings: true,
  
  // Custom security testing capabilities
  securityTesting: {
    enableHookDetection: true,
    enableEmulatorDetection: true,
    enableRootDetection: true,
    enableFileIntegrityCheck: true,
    enableNetworkMonitoring: true
  }
};

// BrowserStack capabilities for cloud testing
const browserStackCapabilities = {
  ...baseAndroidCapabilities,
  // BrowserStack specific
  'bstack:options': {
    userName: process.env.BROWSERSTACK_USERNAME,
    accessKey: process.env.BROWSERSTACK_ACCESS_KEY,
    projectName: 'Mobile Security Automation',
    buildName: `Security Tests - ${new Date().toISOString().split('T')[0]}`,
    sessionName: 'Security Validation',
    debug: true,
    networkLogs: true,
    video: true,
    appiumLogs: true,
    deviceLogs: true,
    local: false,
    localIdentifier: process.env.BROWSERSTACK_LOCAL_IDENTIFIER
  },
  // Device selection
  'bstack:options.deviceName': process.env.BS_DEVICE || 'Google Pixel 7',
  'bstack:options.osVersion': process.env.BS_OS_VERSION || '13.0',
  
  // Security testing enhancements
  acceptSslCerts: true,
  acceptInsecureCerts: true
};

// Sauce Labs capabilities
const sauceLabsCapabilities = {
  ...baseAndroidCapabilities,
  // Sauce Labs specific
  'sauce:options': {
    username: process.env.SAUCE_USERNAME,
    accessKey: process.env.SAUCE_ACCESS_KEY,
    name: 'Mobile Security Tests',
    build: `security-${Date.now()}`,
    tags: ['security', 'mobile', 'automation'],
    recordVideo: true,
    recordScreenshots: true,
    extendedDebugging: true,
    capturePerformance: true
  }
};

/**
 * Get capabilities based on device type and environment
 */
function getCapabilities(deviceType = 'emulator', options = {}) {
  let capabilities = {};
  
  switch (deviceType.toLowerCase()) {
    case 'physical':
    case 'real':
      capabilities = { ...physicalDeviceCapabilities };
      break;
      
    case 'emulator':
    case 'simulator':
      capabilities = { ...emulatorCapabilities };
      break;
      
    case 'browserstack':
    case 'bs':
      capabilities = { ...browserStackCapabilities };
      break;
      
    case 'saucelabs':
    case 'sauce':
      capabilities = { ...sauceLabsCapabilities };
      break;
      
    default:
      console.warn(`Unknown device type: ${deviceType}, using emulator capabilities`);
      capabilities = { ...emulatorCapabilities };
  }
  
  // Merge security testing capabilities
  capabilities = { ...capabilities, ...securityTestCapabilities };
  
  // Apply environment-specific overrides
  if (process.env.PLATFORM_VERSION) {
    capabilities.platformVersion = process.env.PLATFORM_VERSION;
  }
  
  if (process.env.DEVICE_NAME) {
    capabilities.deviceName = process.env.DEVICE_NAME;
  }
  
  if (process.env.APP_PACKAGE) {
    capabilities.appPackage = process.env.APP_PACKAGE;
    capabilities.appActivity = process.env.APP_ACTIVITY || '.MainActivity';
  }
  
  if (process.env.APP_PATH) {
    capabilities.app = process.env.APP_PATH;
  }
  
  // Apply custom options
  capabilities = { ...capabilities, ...options };
  
  return capabilities;
}

/**
 * Get device-specific configuration
 */
function getDeviceConfig(deviceType) {
  const config = {
    emulator: {
      timeout: 60000,
      retries: 3,
      parallel: 2,
      setupScript: 'setup-emulator.sh',
      teardownScript: 'cleanup-emulator.sh'
    },
    physical: {
      timeout: 30000,
      retries: 2,
      parallel: 1,
      setupScript: 'setup-physical.sh',
      teardownScript: 'cleanup-physical.sh'
    },
    browserstack: {
      timeout: 120000,
      retries: 3,
      parallel: 5,
      setupScript: null,
      teardownScript: null
    },
    saucelabs: {
      timeout: 120000,
      retries: 3,
      parallel: 4,
      setupScript: null,
      teardownScript: null
    }
  };
  
  return config[deviceType.toLowerCase()] || config.emulator;
}

/**
 * Validate capabilities
 */
function validateCapabilities(capabilities) {
  const required = ['platformName', 'automationName'];
  const missing = required.filter(field => !capabilities[field]);
  
  if (missing.length > 0) {
    throw new Error(`Missing required capabilities: ${missing.join(', ')}`);
  }
  
  // Security-specific validations
  if (capabilities.securityTesting) {
    console.log('🛡️  Security testing capabilities enabled');
  }
  
  return true;
}

/**
 * Security-specific capabilities for different test types
 */
const securityTestTypes = {
  emulatorDetection: {
    description: 'Emulator detection testing',
    requiredCapabilities: {
      enableEmulatorDetection: true,
      allowEmulatorTesting: true
    },
    recommendations: [
      'Test on both physical devices and emulators',
      'Verify app behavior differs appropriately'
    ]
  },
  
  rootDetection: {
    description: 'Root/Jailbreak detection testing',
    requiredCapabilities: {
      enableRootDetection: true,
      allowRootedTesting: true
    },
    recommendations: [
      'Test on rooted and non-rooted devices',
      'Verify security measures activate correctly'
    ]
  },
  
  fileIntegrity: {
    description: 'File tampering detection testing',
    requiredCapabilities: {
      enableFileIntegrityCheck: true,
      allowFileModification: true
    },
    recommendations: [
      'Monitor critical application files',
      'Test tampering detection mechanisms'
    ]
  },
  
  networkSecurity: {
    description: 'Network security testing',
    requiredCapabilities: {
      enableNetworkMonitoring: true,
      proxyType: 'manual',
      acceptSslCerts: true
    },
    recommendations: [
      'Use proxy for traffic analysis',
      'Test certificate pinning bypass'
    ]
  }
};

/**
 * Get security test capabilities
 */
function getSecurityTestCapabilities(testType) {
  const baseConfig = securityTestTypes[testType];
  if (!baseConfig) {
    throw new Error(`Unknown security test type: ${testType}`);
  }
  
  return {
    ...baseAndroidCapabilities,
    ...securityTestCapabilities,
    ...baseConfig.requiredCapabilities,
    testType: testType,
    testDescription: baseConfig.description
  };
}

/**
 * Performance testing capabilities
 */
const performanceCapabilities = {
  ...securityTestCapabilities,
  enablePerformanceLogging: true,
  recordVideo: true,
  recordScreenshots: true,
  capturePerformance: true,
  logTypes: ['logcat', 'bugreport', 'server'],
  // Performance monitoring
  performanceMonitoring: {
    cpu: true,
    memory: true,
    network: true,
    battery: true,
    fps: true
  }
};

module.exports = {
  baseAndroidCapabilities,
  physicalDeviceCapabilities,
  emulatorCapabilities,
  securityTestCapabilities,
  browserStackCapabilities,
  sauceLabsCapabilities,
  performanceCapabilities,
  securityTestTypes,
  getCapabilities,
  getDeviceConfig,
  validateCapabilities,
  getSecurityTestCapabilities
};