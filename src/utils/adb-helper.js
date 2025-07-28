/**
 * ADB Helper Utility
 * Provides Android Debug Bridge command utilities for security testing
 */

const { execSync, spawn } = require('child_process');
const chalk = require('chalk');
const fs = require('fs-extra');
const path = require('path');

class ADBHelper {
  constructor(deviceId = null) {
    this.deviceId = deviceId;
    this.adbPath = this.findADBPath();
    this.timeout = 30000;
  }

  /**
   * Find ADB executable path
   */
  findADBPath() {
    try {
      // Try common locations
      const commonPaths = [
        '/usr/local/bin/adb',
        '/opt/android-sdk/platform-tools/adb',
        process.env.ANDROID_HOME ? path.join(process.env.ANDROID_HOME, 'platform-tools', 'adb') : null,
        'adb' // Global PATH
      ].filter(Boolean);

      for (const adbPath of commonPaths) {
        try {
          execSync(`${adbPath} version`, { stdio: 'ignore' });
          console.log(chalk.green(`✅ Found ADB at: ${adbPath}`));
          return adbPath;
        } catch (error) {
          continue;
        }
      }

      throw new Error('ADB not found in common locations');
    } catch (error) {
      console.error(chalk.red('❌ ADB not found. Please install Android SDK platform-tools'));
      throw error;
    }
  }

  /**
   * Get connected devices
   */
  async getConnectedDevices() {
    try {
      const output = execSync(`${this.adbPath} devices`, { encoding: 'utf8' });
      const lines = output.split('\n').filter(line => line.trim() && !line.includes('List of devices'));
      
      const devices = lines.map(line => {
        const [deviceId, status] = line.trim().split('\t');
        return { deviceId, status };
      }).filter(device => device.status === 'device');

      console.log(chalk.blue(`📱 Found ${devices.length} connected device(s)`));
      return devices;
    } catch (error) {
      console.error(chalk.red('❌ Failed to get connected devices:'), error.message);
      return [];
    }
  }

  /**
   * Execute ADB command
   */
  async executeCommand(command, options = {}) {
    try {
      const deviceFlag = this.deviceId ? `-s ${this.deviceId}` : '';
      const fullCommand = `${this.adbPath} ${deviceFlag} ${command}`;
      
      console.log(chalk.gray(`🔧 Executing: ${fullCommand}`));
      
      const output = execSync(fullCommand, {
        encoding: 'utf8',
        timeout: options.timeout || this.timeout,
        ...options
      });

      console.log(chalk.green(`✅ Command executed successfully`));
      return { success: true, output: output.trim() };
    } catch (error) {
      console.error(chalk.red(`❌ ADB command failed: ${command}`), error.message);
      return { success: false, error: error.message, output: error.stdout || '' };
    }
  }

  /**
   * Execute shell command on device
   */
  async executeShellCommand(command, options = {}) {
    return await this.executeCommand(`shell "${command}"`, options);
  }

  /**
   * Get device system properties
   */
  async getSystemProperties() {
    try {
      console.log(chalk.blue('🔍 Getting device system properties...'));
      
      const result = await this.executeShellCommand('getprop');
      if (!result.success) {
        throw new Error('Failed to get system properties');
      }

      const properties = {};
      const lines = result.output.split('\n');
      
      for (const line of lines) {
        const match = line.match(/\[(.*?)\]: \[(.*?)\]/);
        if (match) {
          properties[match[1]] = match[2];
        }
      }

      console.log(chalk.green(`✅ Retrieved ${Object.keys(properties).length} system properties`));
      return properties;
    } catch (error) {
      console.error(chalk.red('❌ Failed to get system properties:'), error.message);
      return {};
    }
  }

  /**
   * Check if device is an emulator
   */
  async isEmulator() {
    try {
      console.log(chalk.blue('🔍 Checking if device is an emulator...'));
      
      const properties = await this.getSystemProperties();
      
      // Check emulator-specific properties
      const emulatorIndicators = [
        properties['ro.build.fingerprint']?.includes('generic'),
        properties['ro.build.model']?.includes('Emulator'),
        properties['ro.build.product']?.includes('sdk'),
        properties['ro.hardware']?.includes('goldfish'),
        properties['ro.hardware']?.includes('ranchu'),
        properties['ro.kernel.qemu'] === '1',
        properties['ro.product.device']?.includes('generic'),
        properties['ro.product.model']?.includes('Emulator')
      ];

      const isEmulator = emulatorIndicators.some(indicator => indicator === true);
      
      console.log(chalk.yellow(`📱 Device is ${isEmulator ? 'an emulator' : 'a physical device'}`));
      
      return {
        isEmulator,
        indicators: emulatorIndicators.filter(Boolean),
        properties: {
          fingerprint: properties['ro.build.fingerprint'],
          model: properties['ro.build.model'],
          product: properties['ro.build.product'],
          hardware: properties['ro.hardware'],
          device: properties['ro.product.device']
        }
      };
    } catch (error) {
      console.error(chalk.red('❌ Failed to check emulator status:'), error.message);
      return { isEmulator: false, error: error.message };
    }
  }

  /**
   * Check if device is rooted
   */
  async isRooted() {
    try {
      console.log(chalk.blue('🔍 Checking if device is rooted...'));
      
      const rootIndicators = [];
      
      // Check for su binary
      const suCheck = await this.executeShellCommand('which su');
      if (suCheck.success && suCheck.output.includes('/su')) {
        rootIndicators.push('su_binary_found');
      }

      // Check for Superuser app
      const superuserCheck = await this.executeShellCommand('pm list packages | grep superuser');
      if (superuserCheck.success && superuserCheck.output.trim()) {
        rootIndicators.push('superuser_app_found');
      }

      // Check for busybox
      const busyboxCheck = await this.executeShellCommand('which busybox');
      if (busyboxCheck.success && busyboxCheck.output.includes('/busybox')) {
        rootIndicators.push('busybox_found');
      }

      // Check writable system directories
      const writableCheck = await this.executeShellCommand('test -w /system && echo "writable" || echo "readonly"');
      if (writableCheck.success && writableCheck.output.includes('writable')) {
        rootIndicators.push('system_writable');
      }

      // Check for root management apps
      const rootApps = ['com.noshufou.android.su', 'com.thirdparty.superuser', 'eu.chainfire.supersu'];
      for (const app of rootApps) {
        const appCheck = await this.executeShellCommand(`pm list packages ${app}`);
        if (appCheck.success && appCheck.output.includes(app)) {
          rootIndicators.push(`root_app_${app}`);
        }
      }

      const isRooted = rootIndicators.length > 0;
      
      console.log(chalk.yellow(`🔓 Device is ${isRooted ? 'rooted' : 'not rooted'}`));
      if (isRooted) {
        console.log(chalk.yellow(`   Root indicators: ${rootIndicators.join(', ')}`));
      }
      
      return {
        isRooted,
        indicators: rootIndicators,
        confidence: rootIndicators.length > 2 ? 'high' : rootIndicators.length > 0 ? 'medium' : 'low'
      };
    } catch (error) {
      console.error(chalk.red('❌ Failed to check root status:'), error.message);
      return { isRooted: false, error: error.message };
    }
  }

  /**
   * Simulate root access for testing
   */
  async simulateRootAccess() {
    try {
      console.log(chalk.blue('🔧 Simulating root access for testing...'));
      
      // Create a temporary su script
      const tempSuScript = '/data/local/tmp/test_su';
      const suContent = '#!/system/bin/sh\necho "root access simulated"\nexit 0';
      
      // Push the script to device
      await this.pushFile(Buffer.from(suContent), tempSuScript);
      await this.executeShellCommand(`chmod 755 ${tempSuScript}`);
      
      // Add to PATH temporarily
      await this.executeShellCommand(`export PATH=${path.dirname(tempSuScript)}:$PATH`);
      
      console.log(chalk.green('✅ Root access simulation setup complete'));
      
      return {
        success: true,
        simulatedSuPath: tempSuScript,
        cleanup: async () => {
          await this.executeShellCommand(`rm -f ${tempSuScript}`);
        }
      };
    } catch (error) {
      console.error(chalk.red('❌ Failed to simulate root access:'), error.message);
      return { success: false, error: error.message };
    }
  }

  /**
   * Get device information
   */
  async getDeviceInfo() {
    try {
      console.log(chalk.blue('📱 Getting device information...'));
      
      const properties = await this.getSystemProperties();
      const emulatorCheck = await this.isEmulator();
      const rootCheck = await this.isRooted();
      
      const deviceInfo = {
        manufacturer: properties['ro.product.manufacturer'],
        model: properties['ro.product.model'],
        device: properties['ro.product.device'],
        androidVersion: properties['ro.build.version.release'],
        apiLevel: properties['ro.build.version.sdk'],
        buildFingerprint: properties['ro.build.fingerprint'],
        serialNumber: properties['ro.serialno'],
        hardware: properties['ro.hardware'],
        isEmulator: emulatorCheck.isEmulator,
        isRooted: rootCheck.isRooted,
        securityPatch: properties['ro.build.version.security_patch'],
        bootloader: properties['ro.bootloader'],
        timestamp: new Date().toISOString()
      };

      console.log(chalk.green('✅ Device information retrieved'));
      console.log(chalk.gray(`   Model: ${deviceInfo.model}`));
      console.log(chalk.gray(`   Android: ${deviceInfo.androidVersion} (API ${deviceInfo.apiLevel})`));
      console.log(chalk.gray(`   Emulator: ${deviceInfo.isEmulator}`));
      console.log(chalk.gray(`   Rooted: ${deviceInfo.isRooted}`));
      
      return deviceInfo;
    } catch (error) {
      console.error(chalk.red('❌ Failed to get device info:'), error.message);
      return { error: error.message };
    }
  }

  /**
   * Push file to device
   */
  async pushFile(localPath, remotePath) {
    try {
      console.log(chalk.blue(`📤 Pushing file to device: ${remotePath}`));
      
      // If localPath is a buffer, write to temp file first
      if (Buffer.isBuffer(localPath)) {
        const tempFile = path.join(__dirname, '../../tmp', `temp_${Date.now()}.tmp`);
        await fs.ensureDir(path.dirname(tempFile));
        await fs.writeFile(tempFile, localPath);
        localPath = tempFile;
      }
      
      const result = await this.executeCommand(`push "${localPath}" "${remotePath}"`);
      
      if (result.success) {
        console.log(chalk.green(`✅ File pushed successfully`));
      }
      
      return result;
    } catch (error) {
      console.error(chalk.red('❌ Failed to push file:'), error.message);
      return { success: false, error: error.message };
    }
  }

  /**
   * Pull file from device
   */
  async pullFile(remotePath, localPath) {
    try {
      console.log(chalk.blue(`📥 Pulling file from device: ${remotePath}`));
      
      const result = await this.executeCommand(`pull "${remotePath}" "${localPath}"`);
      
      if (result.success) {
        console.log(chalk.green(`✅ File pulled successfully`));
      }
      
      return result;
    } catch (error) {
      console.error(chalk.red('❌ Failed to pull file:'), error.message);
      return { success: false, error: error.message };
    }
  }

  /**
   * Install APK
   */
  async installAPK(apkPath, options = {}) {
    try {
      console.log(chalk.blue(`📲 Installing APK: ${path.basename(apkPath)}`));
      
      const flags = [];
      if (options.replace) flags.push('-r');
      if (options.test) flags.push('-t');
      if (options.downgrade) flags.push('-d');
      
      const result = await this.executeCommand(`install ${flags.join(' ')} "${apkPath}"`);
      
      if (result.success) {
        console.log(chalk.green(`✅ APK installed successfully`));
      }
      
      return result;
    } catch (error) {
      console.error(chalk.red('❌ Failed to install APK:'), error.message);
      return { success: false, error: error.message };
    }
  }

  /**
   * Start application
   */
  async startApplication(packageName, activityName = '.MainActivity') {
    try {
      console.log(chalk.blue(`🚀 Starting application: ${packageName}`));
      
      const result = await this.executeShellCommand(
        `am start -n ${packageName}/${activityName}`
      );
      
      if (result.success) {
        console.log(chalk.green(`✅ Application started successfully`));
      }
      
      return result;
    } catch (error) {
      console.error(chalk.red('❌ Failed to start application:'), error.message);
      return { success: false, error: error.message };
    }
  }

  /**
   * Stop application
   */
  async stopApplication(packageName) {
    try {
      console.log(chalk.blue(`🛑 Stopping application: ${packageName}`));
      
      const result = await this.executeShellCommand(`am force-stop ${packageName}`);
      
      if (result.success) {
        console.log(chalk.green(`✅ Application stopped successfully`));
      }
      
      return result;
    } catch (error) {
      console.error(chalk.red('❌ Failed to stop application:'), error.message);
      return { success: false, error: error.message };
    }
  }

  /**
   * Get application info
   */
  async getApplicationInfo(packageName) {
    try {
      console.log(chalk.blue(`📋 Getting application info: ${packageName}`));
      
      const result = await this.executeShellCommand(`dumpsys package ${packageName}`);
      
      if (result.success) {
        console.log(chalk.green(`✅ Application info retrieved`));
        
        // Parse key information from dumpsys output
        const info = {
          packageName,
          versionName: this.extractValue(result.output, 'versionName'),
          versionCode: this.extractValue(result.output, 'versionCode'),
          targetSdkVersion: this.extractValue(result.output, 'targetSdk'),
          minSdkVersion: this.extractValue(result.output, 'minSdk'),
          debuggable: result.output.includes('DEBUGGABLE'),
          testOnly: result.output.includes('TEST_ONLY'),
          allowBackup: result.output.includes('allowBackup=true')
        };
        
        return { success: true, info };
      }
      
      return result;
    } catch (error) {
      console.error(chalk.red('❌ Failed to get application info:'), error.message);
      return { success: false, error: error.message };
    }
  }

  /**
   * Extract value from dumpsys output
   */
  extractValue(text, key) {
    const regex = new RegExp(`${key}=([^\\s]+)`);
    const match = text.match(regex);
    return match ? match[1] : null;
  }

  /**
   * Take screenshot
   */
  async takeScreenshot(localPath) {
    try {
      console.log(chalk.blue(`📸 Taking screenshot...`));
      
      const remotePath = '/sdcard/screenshot.png';
      
      // Take screenshot on device
      const screenshotResult = await this.executeShellCommand(`screencap -p ${remotePath}`);
      if (!screenshotResult.success) {
        throw new Error('Failed to take screenshot on device');
      }
      
      // Pull screenshot to local path
      const pullResult = await this.pullFile(remotePath, localPath);
      
      // Clean up remote screenshot
      await this.executeShellCommand(`rm -f ${remotePath}`);
      
      if (pullResult.success) {
        console.log(chalk.green(`✅ Screenshot saved: ${localPath}`));
      }
      
      return pullResult;
    } catch (error) {
      console.error(chalk.red('❌ Failed to take screenshot:'), error.message);
      return { success: false, error: error.message };
    }
  }

  /**
   * Get running processes
   */
  async getRunningProcesses() {
    try {
      console.log(chalk.blue('🔍 Getting running processes...'));
      
      const result = await this.executeShellCommand('ps');
      
      if (result.success) {
        const processes = result.output.split('\n')
          .slice(1) // Skip header
          .filter(line => line.trim())
          .map(line => {
            const parts = line.trim().split(/\s+/);
            return {
              pid: parts[1],
              ppid: parts[2],
              name: parts[parts.length - 1],
              user: parts[0]
            };
          });
        
        console.log(chalk.green(`✅ Found ${processes.length} running processes`));
        return { success: true, processes };
      }
      
      return result;
    } catch (error) {
      console.error(chalk.red('❌ Failed to get running processes:'), error.message);
      return { success: false, error: error.message };
    }
  }

  /**
   * Monitor logcat for security events
   */
  async monitorLogcat(filters = [], duration = 30000) {
    return new Promise((resolve) => {
      console.log(chalk.blue(`📊 Monitoring logcat for ${duration}ms...`));
      
      const deviceFlag = this.deviceId ? ['-s', this.deviceId] : [];
      const logcatProcess = spawn(this.adbPath, [...deviceFlag, 'logcat', '-v', 'time']);
      
      const logs = [];
      
      logcatProcess.stdout.on('data', (data) => {
        const logLine = data.toString();
        
        // Apply filters if provided
        if (filters.length === 0 || filters.some(filter => logLine.includes(filter))) {
          logs.push({
            timestamp: new Date().toISOString(),
            content: logLine.trim()
          });
        }
      });
      
      logcatProcess.stderr.on('data', (data) => {
        console.error(chalk.red('Logcat error:'), data.toString());
      });
      
      // Stop monitoring after duration
      setTimeout(() => {
        logcatProcess.kill();
        console.log(chalk.green(`✅ Logcat monitoring completed. Captured ${logs.length} log entries`));
        resolve({ success: true, logs });
      }, duration);
      
      logcatProcess.on('error', (error) => {
        console.error(chalk.red('❌ Logcat monitoring failed:'), error.message);
        resolve({ success: false, error: error.message });
      });
    });
  }
}

module.exports = ADBHelper;