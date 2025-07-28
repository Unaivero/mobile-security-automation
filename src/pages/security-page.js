/**
 * Security Page Object Model
 * Handles security-specific UI interactions and validations
 */

const BasePage = require('./base-page');
const chalk = require('chalk');

class SecurityPage extends BasePage {
  constructor(driver) {
    super(driver);
    
    // Security-specific selectors
    this.selectors = {
      // Security status indicators
      securityStatus: '//*[@resource-id="security_status"]',
      securityIndicator: '//*[@resource-id="security_indicator"]',
      
      // Warning dialogs and messages
      securityWarningDialog: '//*[@resource-id="security_warning_dialog"]',
      emulatorWarning: '//*[contains(@text, "Emulator detected")]',
      rootWarning: '//*[contains(@text, "Root detected")]',
      tamperingWarning: '//*[contains(@text, "File tampering detected")]',
      
      // Security action buttons
      securityOkButton: '//*[@resource-id="security_ok_btn"]',
      securityExitButton: '//*[@resource-id="security_exit_btn"]',
      securityRetryButton: '//*[@resource-id="security_retry_btn"]',
      
      // Security settings
      securitySettings: '//*[@resource-id="security_settings"]',
      debugModeToggle: '//*[@resource-id="debug_mode_toggle"]',
      securityLevelSelector: '//*[@resource-id="security_level"]',
      
      // Security logs and reports
      securityLog: '//*[@resource-id="security_log"]',
      threatReport: '//*[@resource-id="threat_report"]',
      
      // App state indicators
      appBlocked: '//*[contains(@text, "Access Blocked")]',
      appSecure: '//*[contains(@text, "Secure Environment")]',
      appWarning: '//*[contains(@text, "Security Warning")]'
    };
  }

  /**
   * Navigate to security section
   */
  async navigateToSecurity() {
    try {
      console.log(chalk.blue('🔒 Navigating to security section...'));
      
      // Try multiple navigation paths
      const navigationSelectors = [
        '//*[@text="Security"]',
        '//*[@content-desc="Security"]',
        '//*[@resource-id="nav_security"]',
        '//*[@resource-id="menu_security"]'
      ];
      
      for (const selector of navigationSelectors) {
        if (await this.isElementPresent(selector, 3000)) {
          await this.tapElement(selector);
          await this.waitForStability();
          break;
        }
      }
      
      // Verify we're in security section
      const isInSecurity = await this.isElementPresent(this.selectors.securityStatus, 5000);
      
      if (isInSecurity) {
        console.log(chalk.green('✅ Successfully navigated to security section'));
        await this.takeSecurityScreenshot('security-navigation', 'Security section loaded');
        return true;
      } else {
        console.log(chalk.yellow('⚠️  Security section not found, app may not have security UI'));
        return false;
      }
    } catch (error) {
      console.error(chalk.red('❌ Failed to navigate to security section:'), error.message);
      return false;
    }
  }

  /**
   * Get security status from the app
   */
  async getSecurityStatus() {
    try {
      console.log(chalk.blue('🔍 Getting app security status...'));
      
      const status = {
        level: 'unknown',
        warnings: [],
        threats: [],
        isSecure: false,
        timestamp: new Date().toISOString()
      };
      
      // Check security indicator
      if (await this.isElementPresent(this.selectors.securityIndicator, 3000)) {
        const indicatorText = await this.getElementText(this.selectors.securityIndicator);
        status.level = this.parseSecurityLevel(indicatorText);
      }
      
      // Check for active warnings
      status.warnings = await this.getActiveWarnings();
      
      // Check for detected threats
      status.threats = await this.getDetectedThreats();
      
      // Determine overall security state
      status.isSecure = status.warnings.length === 0 && status.threats.length === 0;
      
      console.log(chalk.green('✅ Security status retrieved:'));
      console.log(chalk.gray(`   Level: ${status.level}`));
      console.log(chalk.gray(`   Warnings: ${status.warnings.length}`));
      console.log(chalk.gray(`   Threats: ${status.threats.length}`));
      console.log(chalk.gray(`   Is Secure: ${status.isSecure}`));
      
      this.logSecurityEvent('security_status_check', status);
      
      return status;
    } catch (error) {
      console.error(chalk.red('❌ Failed to get security status:'), error.message);
      return {
        level: 'error',
        warnings: ['status_check_failed'],
        threats: [],
        isSecure: false,
        error: error.message
      };
    }
  }

  /**
   * Check for emulator detection warning
   */
  async getEmulatorWarning() {
    try {
      console.log(chalk.blue('🔍 Checking for emulator detection warning...'));
      
      // Check for emulator warning dialog
      if (await this.isElementPresent(this.selectors.emulatorWarning, 5000)) {
        const warningText = await this.getElementText(this.selectors.emulatorWarning);
        
        console.log(chalk.red('⚠️  Emulator warning detected!'));
        console.log(chalk.red(`   Message: ${warningText}`));
        
        await this.takeSecurityScreenshot('emulator-warning', 'Emulator detection warning displayed');
        
        this.logSecurityEvent('emulator_detection_warning', {
          message: warningText,
          detected: true
        });
        
        return {
          detected: true,
          message: warningText,
          action: await this.getWarningAction(),
          timestamp: new Date().toISOString()
        };
      }
      
      console.log(chalk.green('✅ No emulator warning detected'));
      return {
        detected: false,
        message: null,
        action: null
      };
    } catch (error) {
      console.error(chalk.red('❌ Failed to check emulator warning:'), error.message);
      return {
        detected: false,
        error: error.message
      };
    }
  }

  /**
   * Check for root detection warning
   */
  async getRootWarning() {
    try {
      console.log(chalk.blue('🔍 Checking for root detection warning...'));
      
      // Check for root warning dialog
      if (await this.isElementPresent(this.selectors.rootWarning, 5000)) {
        const warningText = await this.getElementText(this.selectors.rootWarning);
        
        console.log(chalk.red('⚠️  Root detection warning found!'));
        console.log(chalk.red(`   Message: ${warningText}`));
        
        await this.takeSecurityScreenshot('root-warning', 'Root detection warning displayed');
        
        const warningAction = await this.getWarningAction();
        
        this.logSecurityEvent('root_detection_warning', {
          message: warningText,
          action: warningAction,
          detected: true
        });
        
        return {
          detected: true,
          message: warningText,
          action: warningAction,
          blocked: warningAction === 'block_access',
          timestamp: new Date().toISOString()
        };
      }
      
      console.log(chalk.green('✅ No root warning detected'));
      return {
        detected: false,
        message: null,
        action: null,
        blocked: false
      };
    } catch (error) {
      console.error(chalk.red('❌ Failed to check root warning:'), error.message);
      return {
        detected: false,
        error: error.message,
        blocked: false
      };
    }
  }

  /**
   * Check for file tampering detection alert
   */
  async getTamperingAlert() {
    try {
      console.log(chalk.blue('🔍 Checking for file tampering alert...'));
      
      // Check for tampering warning
      if (await this.isElementPresent(this.selectors.tamperingWarning, 5000)) {
        const alertText = await this.getElementText(this.selectors.tamperingWarning);
        
        console.log(chalk.red('⚠️  File tampering alert detected!'));
        console.log(chalk.red(`   Message: ${alertText}`));
        
        await this.takeSecurityScreenshot('tampering-alert', 'File tampering detection alert');
        
        const alertAction = await this.getWarningAction();
        
        this.logSecurityEvent('file_tampering_alert', {
          message: alertText,
          action: alertAction,
          detected: true
        });
        
        return {
          detected: true,
          message: alertText,
          action: alertAction,
          severity: this.parseTamperingSeverity(alertText),
          timestamp: new Date().toISOString()
        };
      }
      
      console.log(chalk.green('✅ No file tampering alert detected'));
      return {
        detected: false,
        message: null,
        action: null,
        severity: 'none'
      };
    } catch (error) {
      console.error(chalk.red('❌ Failed to check tampering alert:'), error.message);
      return {
        detected: false,
        error: error.message,
        severity: 'unknown'
      };
    }
  }

  /**
   * Get list of active security warnings
   */
  async getActiveWarnings() {
    const warnings = [];
    
    try {
      // Check for various warning types
      const warningChecks = [
        { selector: this.selectors.emulatorWarning, type: 'emulator' },
        { selector: this.selectors.rootWarning, type: 'root' },
        { selector: this.selectors.tamperingWarning, type: 'tampering' },
        { selector: this.selectors.appWarning, type: 'general' }
      ];
      
      for (const check of warningChecks) {
        if (await this.isElementPresent(check.selector, 2000)) {
          const warningText = await this.getElementText(check.selector);
          warnings.push({
            type: check.type,
            message: warningText,
            selector: check.selector
          });
        }
      }
      
      return warnings;
    } catch (error) {
      console.error(chalk.red('❌ Failed to get active warnings:'), error.message);
      return [];
    }
  }

  /**
   * Get list of detected security threats
   */
  async getDetectedThreats() {
    const threats = [];
    
    try {
      // Check threat report section if available
      if (await this.isElementPresent(this.selectors.threatReport, 3000)) {
        const reportText = await this.getElementText(this.selectors.threatReport);
        threats.push(...this.parseThreatReport(reportText));
      }
      
      // Check security log for threat entries
      if (await this.isElementPresent(this.selectors.securityLog, 3000)) {
        const logText = await this.getElementText(this.selectors.securityLog);
        threats.push(...this.parseSecurityLog(logText));
      }
      
      return threats;
    } catch (error) {
      console.error(chalk.red('❌ Failed to get detected threats:'), error.message);
      return [];
    }
  }

  /**
   * Dismiss security warning dialog
   */
  async dismissSecurityWarning(action = 'ok') {
    try {
      console.log(chalk.blue(`🔒 Dismissing security warning with action: ${action}`));
      
      const actionSelector = action === 'ok' ? this.selectors.securityOkButton : 
                           action === 'exit' ? this.selectors.securityExitButton :
                           this.selectors.securityRetryButton;
      
      if (await this.isElementPresent(actionSelector, 5000)) {
        await this.tapElement(actionSelector);
        await this.waitForStability();
        
        console.log(chalk.green('✅ Security warning dismissed'));
        return true;
      }
      
      console.log(chalk.yellow('⚠️  Security warning action button not found'));
      return false;
    } catch (error) {
      console.error(chalk.red('❌ Failed to dismiss security warning:'), error.message);
      return false;
    }
  }

  /**
   * Parse security level from indicator text
   */
  parseSecurityLevel(text) {
    if (!text) return 'unknown';
    
    const lowerText = text.toLowerCase();
    
    if (lowerText.includes('high') || lowerText.includes('secure')) return 'high';
    if (lowerText.includes('medium') || lowerText.includes('warning')) return 'medium';
    if (lowerText.includes('low') || lowerText.includes('danger')) return 'low';
    if (lowerText.includes('blocked') || lowerText.includes('critical')) return 'blocked';
    
    return 'unknown';
  }

  /**
   * Get warning action type
   */
  async getWarningAction() {
    try {
      // Check if app is blocked
      if (await this.isElementPresent(this.selectors.appBlocked, 2000)) {
        return 'block_access';
      }
      
      // Check if there's an exit button (forced exit)
      if (await this.isElementPresent(this.selectors.securityExitButton, 2000)) {
        return 'force_exit';
      }
      
      // Check if there's a retry button (warning with retry)
      if (await this.isElementPresent(this.selectors.securityRetryButton, 2000)) {
        return 'warning_retry';
      }
      
      // Default warning action
      return 'warning_continue';
    } catch (error) {
      console.error(chalk.red('❌ Failed to get warning action:'), error.message);
      return 'unknown';
    }
  }

  /**
   * Parse tampering severity from alert text
   */
  parseTamperingSeverity(text) {
    if (!text) return 'unknown';
    
    const lowerText = text.toLowerCase();
    
    if (lowerText.includes('critical') || lowerText.includes('severe')) return 'critical';
    if (lowerText.includes('high') || lowerText.includes('major')) return 'high';
    if (lowerText.includes('medium') || lowerText.includes('moderate')) return 'medium';
    if (lowerText.includes('low') || lowerText.includes('minor')) return 'low';
    
    return 'medium'; // Default severity
  }

  /**
   * Parse threat report text into threat objects
   */
  parseThreatReport(reportText) {
    const threats = [];
    
    try {
      // Split report by lines and parse each threat entry
      const lines = reportText.split('\n');
      
      for (const line of lines) {
        if (line.trim() && (line.includes('detected') || line.includes('found'))) {
          threats.push({
            type: this.extractThreatType(line),
            description: line.trim(),
            severity: this.extractThreatSeverity(line)
          });
        }
      }
    } catch (error) {
      console.error(chalk.red('❌ Failed to parse threat report:'), error.message);
    }
    
    return threats;
  }

  /**
   * Parse security log for threat entries
   */
  parseSecurityLog(logText) {
    const threats = [];
    
    try {
      // Look for threat-related log entries
      const threatKeywords = ['threat', 'attack', 'malicious', 'suspicious', 'violation'];
      const lines = logText.split('\n');
      
      for (const line of lines) {
        const lowerLine = line.toLowerCase();
        if (threatKeywords.some(keyword => lowerLine.includes(keyword))) {
          threats.push({
            type: 'log_entry',
            description: line.trim(),
            severity: 'medium',
            source: 'security_log'
          });
        }
      }
    } catch (error) {
      console.error(chalk.red('❌ Failed to parse security log:'), error.message);
    }
    
    return threats;
  }

  /**
   * Extract threat type from text
   */
  extractThreatType(text) {
    const lowerText = text.toLowerCase();
    
    if (lowerText.includes('root')) return 'root_detection';
    if (lowerText.includes('emulator')) return 'emulator_detection';
    if (lowerText.includes('tamper')) return 'file_tampering';
    if (lowerText.includes('debug')) return 'debug_detection';
    if (lowerText.includes('hook')) return 'code_injection';
    
    return 'unknown_threat';
  }

  /**
   * Extract threat severity from text
   */
  extractThreatSeverity(text) {
    const lowerText = text.toLowerCase();
    
    if (lowerText.includes('critical') || lowerText.includes('high')) return 'high';
    if (lowerText.includes('medium') || lowerText.includes('moderate')) return 'medium';
    if (lowerText.includes('low') || lowerText.includes('minor')) return 'low';
    
    return 'medium';
  }
}

module.exports = SecurityPage;
