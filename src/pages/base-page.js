/**
 * Base Page Object Model Class
 * Provides common functionality for all page objects with security-focused methods
 */

const { remote } = require('webdriverio');
const chalk = require('chalk');

class BasePage {
  constructor(driver = null) {
    this.driver = driver;
    this.timeout = 30000;
    this.securityTimeout = 15000;
  }

  /**
   * Initialize WebDriver connection for mobile testing
   */
  async initializeDriver(capabilities = {}) {
    try {
      console.log(chalk.blue('🔧 Initializing mobile driver...'));
      
      const defaultCapabilities = {
        platformName: 'Android',
        platformVersion: global.PLATFORM_VERSION || '13.0',
        deviceName: global.DEVICE_NAME || 'Android Emulator',
        automationName: 'UiAutomator2',
        appPackage: global.APP_PACKAGE || 'com.security.testapp',
        appActivity: '.MainActivity',
        noReset: true,
        fullReset: false,
        // Security testing specific capabilities
        autoGrantPermissions: true,
        ignoreHiddenApiPolicyError: true,
        disableWindowAnimation: true,
        // Enable shell commands for security testing
        allowTestPackages: true,
        enforceAppInstall: false
      };

      this.driver = await remote({
        protocol: 'http',
        hostname: 'localhost',
        port: global.APPIUM_PORT || 4723,
        path: '/',
        capabilities: { ...defaultCapabilities, ...capabilities }
      });

      console.log(chalk.green('✅ Mobile driver initialized successfully'));
      return this.driver;
    } catch (error) {
      console.error(chalk.red('❌ Failed to initialize mobile driver:'), error.message);
      throw error;
    }
  }

  /**
   * Find element with security-aware timeout
   */
  async findElement(selector, timeout = this.timeout) {
    try {
      console.log(chalk.gray(`🔍 Finding element: ${selector}`));
      
      const element = await this.driver.$(selector);
      await element.waitForDisplayed({ timeout });
      
      console.log(chalk.green(`✅ Element found: ${selector}`));
      return element;
    } catch (error) {
      console.error(chalk.red(`❌ Element not found: ${selector}`), error.message);
      throw error;
    }
  }

  /**
   * Find multiple elements with security validation
   */
  async findElements(selector, timeout = this.timeout) {
    try {
      console.log(chalk.gray(`🔍 Finding elements: ${selector}`));
      
      const elements = await this.driver.$$(selector);
      
      if (elements.length === 0) {
        throw new Error(`No elements found for selector: ${selector}`);
      }
      
      console.log(chalk.green(`✅ Found ${elements.length} elements: ${selector}`));
      return elements;
    } catch (error) {
      console.error(chalk.red(`❌ Elements not found: ${selector}`), error.message);
      throw error;
    }
  }

  /**
   * Tap element with security validation
   */
  async tapElement(selector, timeout = this.timeout) {
    try {
      const element = await this.findElement(selector, timeout);
      await element.click();
      
      console.log(chalk.green(`✅ Tapped element: ${selector}`));
      await this.waitForStability();
      
      return true;
    } catch (error) {
      console.error(chalk.red(`❌ Failed to tap element: ${selector}`), error.message);
      return false;
    }
  }

  /**
   * Enter text with security considerations
   */
  async enterText(selector, text, clearFirst = true, timeout = this.timeout) {
    try {
      const element = await this.findElement(selector, timeout);
      
      if (clearFirst) {
        await element.clearValue();
      }
      
      await element.setValue(text);
      
      console.log(chalk.green(`✅ Entered text in: ${selector}`));
      return true;
    } catch (error) {
      console.error(chalk.red(`❌ Failed to enter text in: ${selector}`), error.message);
      return false;
    }
  }

  /**
   * Get element text with security validation
   */
  async getElementText(selector, timeout = this.timeout) {
    try {
      const element = await this.findElement(selector, timeout);
      const text = await element.getText();
      
      console.log(chalk.green(`✅ Got text from ${selector}: "${text}"`));
      return text;
    } catch (error) {
      console.error(chalk.red(`❌ Failed to get text from: ${selector}`), error.message);
      return null;
    }
  }

  /**
   * Check if element exists (security-aware)
   */
  async isElementPresent(selector, timeout = 5000) {
    try {
      const element = await this.driver.$(selector);
      await element.waitForDisplayed({ timeout });
      return true;
    } catch (error) {
      return false;
    }
  }

  /**
   * Wait for app stability after actions
   */
  async waitForStability(timeout = 2000) {
    await this.driver.pause(timeout);
  }

  /**
   * Take screenshot for security test evidence
   */
  async takeSecurityScreenshot(testName, description = '') {
    try {
      const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
      const filename = `security-${testName}-${timestamp}.png`;
      
      await this.driver.saveScreenshot(`./reports/screenshots/${filename}`);
      
      console.log(chalk.blue(`📸 Security screenshot saved: ${filename}`));
      if (description) {
        console.log(chalk.gray(`   Description: ${description}`));
      }
      
      return filename;
    } catch (error) {
      console.error(chalk.red('❌ Failed to take screenshot:'), error.message);
      return null;
    }
  }

  /**
   * Log security event for audit trail
   */
  logSecurityEvent(event, details = {}) {
    const timestamp = new Date().toISOString();
    const logEntry = {
      timestamp,
      event,
      details,
      deviceInfo: this.getDeviceInfo()
    };
    
    console.log(chalk.yellow(`🔒 SECURITY EVENT: ${event}`));
    console.log(chalk.gray(`   Timestamp: ${timestamp}`));
    if (Object.keys(details).length > 0) {
      console.log(chalk.gray(`   Details: ${JSON.stringify(details, null, 2)}`));
    }
  }

  /**
   * Get basic device information for security context
   */
  async getDeviceInfo() {
    try {
      const capabilities = await this.driver.getCapabilities();
      return {
        platformName: capabilities.platformName,
        platformVersion: capabilities.platformVersion,
        deviceName: capabilities.deviceName,
        udid: capabilities.udid,
        systemPort: capabilities.systemPort
      };
    } catch (error) {
      console.error(chalk.red('❌ Failed to get device info:'), error.message);
      return {};
    }
  }

  /**
   * Validate app is in secure state
   */
  async validateSecureState(expectedState = 'secure') {
    try {
      // Check for security warnings or indicators
      const securityWarnings = await this.checkForSecurityWarnings();
      const appState = await this.getAppSecurityState();
      
      const isSecure = securityWarnings.length === 0 && appState === expectedState;
      
      if (isSecure) {
        console.log(chalk.green('✅ App is in secure state'));
      } else {
        console.log(chalk.red('⚠️  App security state validation failed'));
        console.log(chalk.red(`   Expected: ${expectedState}, Got: ${appState}`));
        console.log(chalk.red(`   Warnings: ${securityWarnings.join(', ')}`));
      }
      
      return {
        isSecure,
        state: appState,
        warnings: securityWarnings
      };
    } catch (error) {
      console.error(chalk.red('❌ Failed to validate secure state:'), error.message);
      return {
        isSecure: false,
        state: 'unknown',
        warnings: ['validation_failed']
      };
    }
  }

  /**
   * Check for security warnings in the app UI
   */
  async checkForSecurityWarnings() {
    const warnings = [];
    
    try {
      // Common security warning selectors
      const warningSelectors = [
        '//*[contains(@text, "Security Warning")]',
        '//*[contains(@text, "Device Compromised")]',
        '//*[contains(@text, "Root Detected")]',
        '//*[contains(@text, "Emulator Detected")]',
        '//*[contains(@text, "Tampered")]',
        '//*[contains(@text, "Unsafe Environment")]',
        '//*[contains(@resource-id, "security_warning")]',
        '//*[contains(@resource-id, "threat_alert")]'
      ];

      for (const selector of warningSelectors) {
        if (await this.isElementPresent(selector, 2000)) {
          const warningText = await this.getElementText(selector);
          warnings.push(warningText);
        }
      }
      
      return warnings;
    } catch (error) {
      console.error(chalk.red('❌ Failed to check security warnings:'), error.message);
      return ['warning_check_failed'];
    }
  }

  /**
   * Get current app security state
   */
  async getAppSecurityState() {
    try {
      // Check if app is in a blocked/restricted state
      if (await this.isElementPresent('//*[contains(@text, "Access Blocked")]', 2000)) {
        return 'blocked';
      }
      
      // Check if app is showing warnings
      if (await this.isElementPresent('//*[contains(@text, "Warning")]', 2000)) {
        return 'warning';
      }
      
      // Check if app is in normal operation
      if (await this.isElementPresent('//*[contains(@resource-id, "main_content")]', 2000)) {
        return 'secure';
      }
      
      return 'unknown';
    } catch (error) {
      console.error(chalk.red('❌ Failed to get app security state:'), error.message);
      return 'error';
    }
  }

  /**
   * Clean up driver and resources
   */
  async cleanup() {
    try {
      if (this.driver) {
        await this.driver.deleteSession();
        console.log(chalk.green('✅ Driver session cleaned up'));
      }
    } catch (error) {
      console.error(chalk.red('❌ Failed to cleanup driver:'), error.message);
    }
  }
}

module.exports = BasePage;
