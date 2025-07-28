module.exports = {
  testEnvironment: 'node',
  testMatch: [
    '**/tests/**/*.test.js'
  ],
  collectCoverage: true,
  coverageDirectory: 'reports/coverage',
  coverageReporters: [
    'html',
    'text',
    'lcov'
  ],
  setupFilesAfterEnv: [
    '<rootDir>/jest.setup.js'
  ],
  testTimeout: 60000,
  verbose: true,
  reporters: [
    'default',
    [
      'jest-html-reporters',
      {
        publicPath: './reports',
        filename: 'security-test-report.html',
        pageTitle: 'Mobile Security Test Report',
        logoImgPath: undefined,
        hideIcon: false,
        expand: true,
        testCommand: 'npm run test:security'
      }
    ]
  ],
  // Global test variables
  globals: {
    'DEVICE_TYPE': process.env.DEVICE_TYPE || 'emulator',
    'APPIUM_PORT': process.env.APPIUM_PORT || 4723,
    'PLATFORM_VERSION': process.env.PLATFORM_VERSION || '13.0',
    'DEVICE_NAME': process.env.DEVICE_NAME || 'Android Emulator',
    'APP_PACKAGE': process.env.APP_PACKAGE || 'com.security.testapp',
    'TEST_TIMEOUT': 60000,
    'SECURITY_TIMEOUT': 30000
  },
  // Transform configuration for ES6 modules
  transform: {
    '^.+\\.js$': 'babel-jest'
  },
  // Module path mapping
  moduleNameMapping: {
    '^@/(.*)$': '<rootDir>/src/$1',
    '^@tests/(.*)$': '<rootDir>/tests/$1',
    '^@utils/(.*)$': '<rootDir>/src/utils/$1',
    '^@pages/(.*)$': '<rootDir>/src/pages/$1',
    '^@config/(.*)$': '<rootDir>/src/config/$1'
  },
  // Test environment setup
  testEnvironmentOptions: {
    url: 'http://localhost'
  },
  // Coverage settings
  collectCoverageFrom: [
    'src/**/*.js',
    '!src/config/**',
    '!**/node_modules/**'
  ],
  coverageThreshold: {
    global: {
      branches: 70,
      functions: 70,
      lines: 70,
      statements: 70
    }
  }
};
