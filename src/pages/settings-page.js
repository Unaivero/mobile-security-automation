/**
 * Settings Page Object Model
 * Handles app settings and configuration for security testing
 */

const BasePage = require('./base-page');
const chalk = require('chalk');

class SettingsPage extends BasePage {
  constructor(driver) {
    super(driver);
    
    // Settings-specific selectors
    this.selectors = {
      // Navigation
      settingsButton: '//*[@text="Settings"]',
      securitySettings: '//*[@text="Security Settings"]',
      debugSettings: '//*[@text="Debug Settings"]',
      
      // Security configuration
      debugModeToggle: '//*[@resource-id="debug_mode_toggle"]',
      debugModeSwitch: '//*[@class="android.widget.Switch"][@resource-id="debug_mode_switch"]',
      debugModeCheckbox: '//*[@class="android.widget.CheckBox"][@resource-id="debug_mode_checkbox"]',
      
      // Security level settings
      securityLevelSpinner: '//*[@resource-id="security_level_spinner"]',
      securityLevelHigh: '//*[@text="High Security"]',
      securityLevelMedium: '//*[@text="Medium Security"]',
      securityLevelLow: '//*[@text="Low Security"]',
      
      // File integrity settings
      fileIntegrityToggle: '//*[@resource-id="file_integrity_toggle"]',
      checksumValidation: '//*[@resource-id="checksum_validation"]',
      
      // Developer options
      developerOptionsTitle: '//*[@text="Developer Options"]',
      allowDebugging: '//*[@text="Allow USB Debugging"]',
      mockLocations: '//*[@text="Allow Mock Locations"]',
      
      // Save/Apply buttons
      saveButton: '//*[@resource-id="save_button"]',
      applyButton: '//*[@resource-id="apply_button"]',
      resetButton: '//*[@resource-id="reset_button"]',
      
      // Status indicators
      settingsStatus: '//*[@resource-id="settings_status"]',
      configurationSaved: '//*[contains(@text, "Configuration saved")]'
    };
  }

  /**
   * Navigate to settings section
   */
  async navigateToSettings() {
    try {
      console.log(chalk.blue('⚙️  Navigating to settings...'));
      
      // Try multiple navigation paths
      const navigationSelectors = [
        this.selectors.settingsButton,
        '//*[@content-desc="Settings"]',
        '//*[@resource-id="nav_settings"]',
        '//*[@resource-id="menu_settings"]'
      ];
      
      for (const selector of navigationSelectors) {
        if (await this.isElementPresent(selector, 3000)) {
          await this.tapElement(selector);
          await this.waitForStability();
          break;
        }
      }
      
      // Verify we're in settings
      const isInSettings = await this.isElementPresent(this.selectors.settingsStatus, 5000) ||
                          await this.isElementPresent('//*[contains(@text, "Settings")]', 5000);
      
      if (isInSettings) {
        console.log(chalk.green('✅ Successfully navigated to settings'));
        await this.takeSecurityScreenshot('settings-navigation', 'Settings page loaded');
        return true;
      } else {
        console.log(chalk.yellow('⚠️  Settings page not found'));
        return false;
      }
    } catch (error) {
      console.error(chalk.red('❌ Failed to navigate to settings:'), error.message);
      return false;
    }
  }

  /**
   * Navigate to security settings subsection
   */
  async navigateToSecuritySettings() {
    try {
      console.log(chalk.blue('🔒 Navigating to security settings...'));
      
      if (await this.isElementPresent(this.selectors.securitySettings, 5000)) {
        await this.tapElement(this.selectors.securitySettings);
        await this.waitForStability();
        
        console.log(chalk.green('✅ Navigated to security settings'));
        await this.takeSecurityScreenshot('security-settings', 'Security settings page');
        return true;
      }
      
      console.log(chalk.yellow('⚠️  Security settings not found'));
      return false;
    } catch (error) {
      console.error(chalk.red('❌ Failed to navigate to security settings:'), error.message);
      return false;
    }
  }

  /**
   * Get current debug mode status
   */
  async getDebugModeStatus() {
    try {
      console.log(chalk.blue('🔍 Checking debug mode status...'));
      
      let isEnabled = false;
      let toggleType = 'unknown';
      
      // Check for switch toggle
      if (await this.isElementPresent(this.selectors.debugModeSwitch, 3000)) {
        const switchElement = await this.findElement(this.selectors.debugModeSwitch);
        const isChecked = await switchElement.getAttribute('checked');
        isEnabled = isChecked === 'true';
        toggleType = 'switch';
      }
      // Check for checkbox toggle
      else if (await this.isElementPresent(this.selectors.debugModeCheckbox, 3000)) {
        const checkboxElement = await this.findElement(this.selectors.debugModeCheckbox);
        const isChecked = await checkboxElement.getAttribute('checked');
        isEnabled = isChecked === 'true';
        toggleType = 'checkbox';
      }
      // Check for generic toggle
      else if (await this.isElementPresent(this.selectors.debugModeToggle, 3000)) {
        const toggleElement = await this.findElement(this.selectors.debugModeToggle);
        const toggleState = await toggleElement.getAttribute('checked') || 
                           await toggleElement.getAttribute('selected') || 
                           await toggleElement.getText();
        isEnabled = toggleState === 'true' || toggleState.toLowerCase().includes('enabled');
        toggleType = 'generic';
      }
      
      console.log(chalk.green(`✅ Debug mode status: ${isEnabled ? 'ENABLED' : 'DISABLED'}`));
      console.log(chalk.gray(`   Toggle type: ${toggleType}`));
      
      this.logSecurityEvent('debug_mode_status_check', {
        enabled: isEnabled,
        toggleType: toggleType
      });
      
      return {
        enabled: isEnabled,
        toggleType: toggleType,
        timestamp: new Date().toISOString()
      };
    } catch (error) {
      console.error(chalk.red('❌ Failed to get debug mode status:'), error.message);
      return {
        enabled: false,
        toggleType: 'unknown',
        error: error.message
      };
    }
  }

  /**
   * Toggle debug mode on/off
   */
  async toggleDebugMode(enable = true) {
    try {
      console.log(chalk.blue(`🔧 ${enable ? 'Enabling' : 'Disabling'} debug mode...`));
      
      const currentStatus = await this.getDebugModeStatus();
      
      // If already in desired state, no action needed
      if (currentStatus.enabled === enable) {
        console.log(chalk.green(`✅ Debug mode already ${enable ? 'enabled' : 'disabled'}`));
        return true;
      }
      
      // Find and toggle the appropriate control
      let toggleSelector = null;
      
      if (currentStatus.toggleType === 'switch') {
        toggleSelector = this.selectors.debugModeSwitch;
      } else if (currentStatus.toggleType === 'checkbox') {
        toggleSelector = this.selectors.debugModeCheckbox;
      } else {
        toggleSelector = this.selectors.debugModeToggle;
      }
      
      if (toggleSelector && await this.isElementPresent(toggleSelector, 5000)) {
        await this.tapElement(toggleSelector);
        await this.waitForStability();
        
        // Verify the change
        const newStatus = await this.getDebugModeStatus();
        
        if (newStatus.enabled === enable) {
          console.log(chalk.green(`✅ Debug mode successfully ${enable ? 'enabled' : 'disabled'}`));
          
          this.logSecurityEvent('debug_mode_toggled', {
            previousState: currentStatus.enabled,
            newState: newStatus.enabled,
            action: enable ? 'enable' : 'disable'
          });
          
          await this.takeSecurityScreenshot('debug-mode-toggled', 
            `Debug mode ${enable ? 'enabled' : 'disabled'}`);
          
          return true;
        } else {
          console.log(chalk.red('❌ Debug mode toggle failed - state not changed'));
          return false;
        }
      } else {
        console.log(chalk.red('❌ Debug mode toggle control not found'));
        return false;
      }
    } catch (error) {
      console.error(chalk.red('❌ Failed to toggle debug mode:'), error.message);
      return false;
    }
  }

  /**
   * Set security level
   */
  async setSecurityLevel(level = 'high') {
    try {
      console.log(chalk.blue(`🔒 Setting security level to: ${level}`));
      
      // Map level to selector
      const levelSelectors = {
        'high': this.selectors.securityLevelHigh,
        'medium': this.selectors.securityLevelMedium,
        'low': this.selectors.securityLevelLow
      };
      
      // Open security level spinner
      if (await this.isElementPresent(this.selectors.securityLevelSpinner, 5000)) {
        await this.tapElement(this.selectors.securityLevelSpinner);
        await this.waitForStability();
        
        // Select the desired level
        const targetSelector = levelSelectors[level.toLowerCase()];
        if (targetSelector && await this.isElementPresent(targetSelector, 5000)) {
          await this.tapElement(targetSelector);
          await this.waitForStability();
          
          console.log(chalk.green(`✅ Security level set to: ${level}`));
          
          this.logSecurityEvent('security_level_changed', {
            newLevel: level
          });
          
          await this.takeSecurityScreenshot('security-level-set', `Security level: ${level}`);
          return true;
        } else {
          console.log(chalk.red(`❌ Security level option not found: ${level}`));
          return false;
        }
      } else {
        console.log(chalk.red('❌ Security level spinner not found'));
        return false;
      }
    } catch (error) {
      console.error(chalk.red('❌ Failed to set security level:'), error.message);
      return false;
    }
  }

  /**
   * Toggle file integrity checking
   */
  async toggleFileIntegrity(enable = true) {
    try {
      console.log(chalk.blue(`🔧 ${enable ? 'Enabling' : 'Disabling'} file integrity checking...`));
      
      if (await this.isElementPresent(this.selectors.fileIntegrityToggle, 5000)) {
        const currentState = await this.getToggleState(this.selectors.fileIntegrityToggle);
        
        if (currentState !== enable) {
          await this.tapElement(this.selectors.fileIntegrityToggle);
          await this.waitForStability();
          
          const newState = await this.getToggleState(this.selectors.fileIntegrityToggle);
          
          if (newState === enable) {
            console.log(chalk.green(`✅ File integrity checking ${enable ? 'enabled' : 'disabled'}`));
            
            this.logSecurityEvent('file_integrity_toggled', {
              previousState: currentState,
              newState: newState,
              action: enable ? 'enable' : 'disable'
            });
            
            return true;
          }
        } else {
          console.log(chalk.green(`✅ File integrity checking already ${enable ? 'enabled' : 'disabled'}`));
          return true;
        }
      }
      
      console.log(chalk.red('❌ File integrity toggle not found'));
      return false;
    } catch (error) {
      console.error(chalk.red('❌ Failed to toggle file integrity:'), error.message);
      return false;
    }
  }

  /**
   * Save current settings configuration
   */
  async saveSettings() {
    try {
      console.log(chalk.blue('💾 Saving settings configuration...'));
      
      // Try different save button selectors
      const saveSelectors = [
        this.selectors.saveButton,
        this.selectors.applyButton,
        '//*[@text="Save"]',
        '//*[@text="Apply"]',
        '//*[@content-desc="Save"]'
      ];
      
      for (const selector of saveSelectors) {
        if (await this.isElementPresent(selector, 3000)) {
          await this.tapElement(selector);
          await this.waitForStability();
          
          // Check for confirmation message
          if (await this.isElementPresent(this.selectors.configurationSaved, 5000)) {
            console.log(chalk.green('✅ Settings saved successfully'));
            
            this.logSecurityEvent('settings_saved', {
              timestamp: new Date().toISOString()
            });
            
            await this.takeSecurityScreenshot('settings-saved', 'Settings configuration saved');
            return true;
          }
          
          break;
        }
      }
      
      console.log(chalk.yellow('⚠️  Save confirmation not detected, but save action attempted'));
      return true;
    } catch (error) {
      console.error(chalk.red('❌ Failed to save settings:'), error.message);
      return false;
    }
  }

  /**
   * Reset settings to default
   */
  async resetSettings() {
    try {
      console.log(chalk.blue('🔄 Resetting settings to default...'));
      
      if (await this.isElementPresent(this.selectors.resetButton, 5000)) {
        await this.tapElement(this.selectors.resetButton);
        await this.waitForStability();
        
        // Handle confirmation dialog if present
        const confirmSelectors = [
          '//*[@text="Confirm"]',
          '//*[@text="OK"]',
          '//*[@text="Reset"]',
          '//*[@resource-id="confirm_reset"]'
        ];
        
        for (const selector of confirmSelectors) {
          if (await this.isElementPresent(selector, 3000)) {
            await this.tapElement(selector);
            await this.waitForStability();
            break;
          }
        }
        
        console.log(chalk.green('✅ Settings reset to default'));
        
        this.logSecurityEvent('settings_reset', {
          timestamp: new Date().toISOString()
        });
        
        await this.takeSecurityScreenshot('settings-reset', 'Settings reset to default');
        return true;
      }
      
      console.log(chalk.red('❌ Reset button not found'));
      return false;
    } catch (error) {
      console.error(chalk.red('❌ Failed to reset settings:'), error.message);
      return false;
    }
  }

  /**
   * Get current settings configuration
   */
  async getCurrentConfiguration() {
    try {
      console.log(chalk.blue('📋 Getting current settings configuration...'));
      
      const config = {
        debugMode: await this.getDebugModeStatus(),
        fileIntegrity: await this.getToggleState(this.selectors.fileIntegrityToggle),
        checksumValidation: await this.getToggleState(this.selectors.checksumValidation),
        timestamp: new Date().toISOString()
      };
      
      // Try to get security level
      try {
        config.securityLevel = await this.getCurrentSecurityLevel();
      } catch (error) {
        config.securityLevel = 'unknown';
      }
      
      console.log(chalk.green('✅ Current configuration retrieved:'));
      console.log(chalk.gray(`   Debug Mode: ${config.debugMode.enabled}`));
      console.log(chalk.gray(`   Security Level: ${config.securityLevel}`));
      console.log(chalk.gray(`   File Integrity: ${config.fileIntegrity}`));
      console.log(chalk.gray(`   Checksum Validation: ${config.checksumValidation}`));
      
      this.logSecurityEvent('configuration_retrieved', config);
      
      return config;
    } catch (error) {
      console.error(chalk.red('❌ Failed to get current configuration:'), error.message);
      return {
        error: error.message,
        timestamp: new Date().toISOString()
      };
    }
  }

  /**
   * Apply security configuration for testing
   */
  async applySecurityTestConfiguration(config = {}) {
    try {
      console.log(chalk.blue('🔧 Applying security test configuration...'));
      
      const defaultConfig = {
        debugMode: false,
        securityLevel: 'high',
        fileIntegrity: true,
        checksumValidation: true
      };
      
      const testConfig = { ...defaultConfig, ...config };
      
      // Navigate to security settings if not already there
      await this.navigateToSecuritySettings();
      
      // Apply each configuration setting
      let success = true;
      
      // Set debug mode
      if (!(await this.toggleDebugMode(testConfig.debugMode))) {
        success = false;
      }
      
      // Set security level
      if (!(await this.setSecurityLevel(testConfig.securityLevel))) {
        success = false;
      }
      
      // Set file integrity
      if (!(await this.toggleFileIntegrity(testConfig.fileIntegrity))) {
        success = false;
      }
      
      // Save configuration
      if (!(await this.saveSettings())) {
        success = false;
      }
      
      if (success) {
        console.log(chalk.green('✅ Security test configuration applied successfully'));
        
        this.logSecurityEvent('test_configuration_applied', {
          configuration: testConfig,
          success: true
        });
        
        await this.takeSecurityScreenshot('test-config-applied', 
          'Security test configuration applied');
      } else {
        console.log(chalk.red('❌ Failed to apply complete security test configuration'));
      }
      
      return success;
    } catch (error) {
      console.error(chalk.red('❌ Failed to apply security test configuration:'), error.message);
      return false;
    }
  }

  /**
   * Get toggle state (helper method)
   */
  async getToggleState(selector) {
    try {
      if (await this.isElementPresent(selector, 3000)) {
        const element = await this.findElement(selector);
        const state = await element.getAttribute('checked') || 
                     await element.getAttribute('selected') || 
                     'false';
        return state === 'true';
      }
      return false;
    } catch (error) {
      return false;
    }
  }

  /**
   * Get current security level
   */
  async getCurrentSecurityLevel() {
    try {
      // Try to find selected security level
      const levels = ['high', 'medium', 'low'];
      
      for (const level of levels) {
        const selector = this.selectors[`securityLevel${level.charAt(0).toUpperCase() + level.slice(1)}`];
        if (await this.isElementPresent(selector, 2000)) {
          const element = await this.findElement(selector);
          const isSelected = await element.getAttribute('selected') === 'true' ||
                           await element.getAttribute('checked') === 'true';
          
          if (isSelected) {
            return level;
          }
        }
      }
      
      return 'unknown';
    } catch (error) {
      return 'unknown';
    }
  }
}

module.exports = SettingsPage;
