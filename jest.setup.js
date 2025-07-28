/**
 * Jest Setup File
 * Global test configuration and utilities
 */

const chalk = require('chalk');
const moment = require('moment');

// Global test setup
beforeAll(async () => {
  console.log(chalk.blue('\n🛡️  Mobile Security Testing Framework'));
  console.log(chalk.gray(`Started at: ${moment().format('YYYY-MM-DD HH:mm:ss')}`));
  console.log(chalk.gray('=====================================\n'));
});

afterAll(async () => {
  console.log(chalk.gray('\n====================================='));
  console.log(chalk.blue('🏁 Security testing completed'));
  console.log(chalk.gray(`Finished at: ${moment().format('YYYY-MM-DD HH:mm:ss')}\n`));
});

// Global test utilities
global.SecurityTestUtils = {
  /**
   * Log security test step
   */
  logSecurityStep: (step, description) => {
    console.log(chalk.yellow(`🔍 ${step}: ${description}`));
  },

  /**
   * Log security threat detected
   */
  logThreatDetected: (threat, details) => {
    console.log(chalk.red(`⚠️  THREAT DETECTED: ${threat}`));
    if (details) {
      console.log(chalk.red(`   Details: ${details}`));
    }
  },

  /**
   * Log security validation passed
   */
  logSecurityPassed: (validation) => {
    console.log(chalk.green(`✅ Security validation passed: ${validation}`));
  },

  /**
   * Log security validation failed
   */
  logSecurityFailed: (validation, reason) => {
    console.log(chalk.red(`❌ Security validation failed: ${validation}`));
    if (reason) {
      console.log(chalk.red(`   Reason: ${reason}`));
    }
  },

  /**
   * Generate test timestamp
   */
  getTimestamp: () => moment().format('YYYY-MM-DD_HH-mm-ss'),

  /**
   * Sleep utility for async operations
   */
  sleep: (ms) => new Promise(resolve => setTimeout(resolve, ms))
};

// Global error handling
process.on('unhandledRejection', (reason, promise) => {
  console.error(chalk.red('Unhandled Rejection at:', promise, 'reason:', reason));
});

process.on('uncaughtException', (error) => {
  console.error(chalk.red('Uncaught Exception:', error));
  process.exit(1);
});
