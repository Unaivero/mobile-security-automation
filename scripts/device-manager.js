#!/usr/bin/env node

/**
 * Device Management Script
 * Manages Android devices and emulators for security testing
 */

const { execSync, spawn } = require('child_process');
const fs = require('fs');
const path = require('path');

class DeviceManager {
  constructor() {
    this.connectedDevices = [];
    this.runningEmulators = [];
  }

  async run() {
    const command = process.argv[2];
    
    switch (command) {
      case 'list':
        await this.listDevices();
        break;
      case 'connect':
        await this.connectDevice(process.argv[3]);
        break;
      case 'start-emulator':
        await this.startEmulator(process.argv[3]);
        break;
      case 'setup-device':
        await this.setupDevice(process.argv[3]);
        break;
      case 'security-check':
        await this.performSecurityCheck(process.argv[3]);
        break;
      default:
        this.showHelp();
    }
  }

  async listDevices() {
    console.log('📱 Connected Devices and Emulators');
    console.log('==================================\n');

    try {
      // List ADB devices
      const adbOutput = execSync('adb devices -l', { encoding: 'utf8' });
      const deviceLines = adbOutput.split('\n')
        .filter(line => line.includes('device'))
        .filter(line => !line.startsWith('List of devices'));

      if (deviceLines.length === 0) {
        console.log('❌ No devices connected');
        console.log('\nTo connect a device:');
        console.log('• Enable USB Debugging on your Android device');
        console.log('• Connect via USB or Wi-Fi');
        console.log('• Run: node scripts/device-manager.js connect <device-id>');
        return;
      }

      deviceLines.forEach((line, index) => {
        const parts = line.trim().split(/\s+/);
        const deviceId = parts[0];
        const status = parts[1];
        const details = parts.slice(2).join(' ');

        console.log(`${index + 1}. Device ID: ${deviceId}`);
        console.log(`   Status: ${status}`);
        if (details) console.log(`   Details: ${details}`);
        
        // Get additional device info
        try {
          const manufacturer = execSync(`adb -s ${deviceId} shell getprop ro.product.manufacturer`, { encoding: 'utf8' }).trim();
          const model = execSync(`adb -s ${deviceId} shell getprop ro.product.model`, { encoding: 'utf8' }).trim();
          const android = execSync(`adb -s ${deviceId} shell getprop ro.build.version.release`, { encoding: 'utf8' }).trim();
          
          console.log(`   Device: ${manufacturer} ${model}`);
          console.log(`   Android: ${android}`);
        } catch (error) {
          console.log('   Info: Unable to retrieve device details');
        }
        console.log();
      });

      // List available emulators
      try {
        const emulatorOutput = execSync('emulator -list-avds', { encoding: 'utf8' });
        const emulators = emulatorOutput.trim().split('\n').filter(line => line.trim());
        
        if (emulators.length > 0) {
          console.log('💻 Available Emulators:');
          emulators.forEach((emulator, index) => {
            console.log(`${index + 1}. ${emulator}`);
          });
          console.log();
        }
      } catch (error) {
        console.log('💻 Emulator command not available\n');
      }

    } catch (error) {
      console.error('❌ Error listing devices:', error.message);
    }
  }

  async connectDevice(deviceId) {
    if (!deviceId) {
      console.error('❌ Please specify a device ID');
      console.log('Usage: node scripts/device-manager.js connect <device-id>');
      return;
    }

    console.log(`📱 Connecting to device: ${deviceId}`);

    try {
      // Check if device is already connected
      const devices = execSync('adb devices', { encoding: 'utf8' });
      if (devices.includes(deviceId)) {
        console.log('✅ Device is already connected');
      } else {
        // Try to connect
        execSync(`adb connect ${deviceId}`, { encoding: 'utf8' });
        console.log('✅ Device connected successfully');
      }

      // Verify connection
      await this.verifyDeviceConnection(deviceId);

    } catch (error) {
      console.error('❌ Failed to connect device:', error.message);
    }
  }

  async startEmulator(emulatorName) {
    if (!emulatorName) {
      console.error('❌ Please specify an emulator name');
      console.log('Usage: node scripts/device-manager.js start-emulator <emulator-name>');
      return;
    }

    console.log(`💻 Starting emulator: ${emulatorName}`);

    try {
      // Start emulator in background
      const emulatorProcess = spawn('emulator', ['-avd', emulatorName], {
        stdio: 'pipe',
        detached: true
      });

      emulatorProcess.unref();

      console.log('🚀 Emulator is starting...');
      console.log('⏳ This may take a few minutes');

      // Wait for emulator to boot
      await this.waitForEmulator();

    } catch (error) {
      console.error('❌ Failed to start emulator:', error.message);
    }
  }

  async setupDevice(deviceId) {
    console.log(`⚙️  Setting up device for security testing: ${deviceId || 'default'}`);

    try {
      const adbCommand = deviceId ? `adb -s ${deviceId}` : 'adb';

      // Install required permissions
      console.log('📋 Installing required test files...');
      
      // Create test directory
      execSync(`${adbCommand} shell mkdir -p /data/local/tmp/security_test`, { stdio: 'pipe' });
      
      // Push test configuration files
      const testDataPath = path.join(__dirname, '..', 'tests', 'fixtures', 'security-test-data.json');
      if (fs.existsSync(testDataPath)) {
        execSync(`${adbCommand} push "${testDataPath}" /data/local/tmp/security_test/`, { stdio: 'pipe' });
        console.log('✅ Test data files installed');
      }

      // Verify device permissions
      console.log('🔒 Checking device permissions...');
      const permissions = [
        'android.permission.READ_EXTERNAL_STORAGE',
        'android.permission.WRITE_EXTERNAL_STORAGE'
      ];

      // Create a simple test to verify ADB access
      const testResult = execSync(`${adbCommand} shell echo "test"`, { encoding: 'utf8' });
      if (testResult.trim() === 'test') {
        console.log('✅ ADB shell access verified');
      }

      console.log('✅ Device setup completed');

    } catch (error) {
      console.error('❌ Device setup failed:', error.message);
    }
  }

  async performSecurityCheck(deviceId) {
    console.log(`🔒 Performing security check: ${deviceId || 'default device'}`);

    try {
      const adbCommand = deviceId ? `adb -s ${deviceId}` : 'adb';

      console.log('🔍 Checking device security status...');

      // Check if device is rooted
      const suCheck = execSync(`${adbCommand} shell which su 2>/dev/null || echo "not found"`, { encoding: 'utf8' });
      const isRooted = !suCheck.includes('not found');

      // Check if developer options are enabled
      const devOptions = execSync(`${adbCommand} shell getprop ro.debuggable`, { encoding: 'utf8' }).trim();
      const isDevelopment = devOptions === '1';

      // Check emulator indicators
      const buildModel = execSync(`${adbCommand} shell getprop ro.product.model`, { encoding: 'utf8' }).trim();
      const isEmulator = buildModel.toLowerCase().includes('sdk') || buildModel.toLowerCase().includes('emulator');

      // Display results
      console.log('\n📊 Security Analysis Results:');
      console.log('============================');
      console.log(`Root Access: ${isRooted ? '❌ DETECTED' : '✅ NOT DETECTED'}`);
      console.log(`Development Mode: ${isDevelopment ? '⚠️  ENABLED' : '✅ DISABLED'}`);
      console.log(`Emulator: ${isEmulator ? '⚠️  DETECTED' : '✅ PHYSICAL DEVICE'}`);

      // Risk assessment
      let riskLevel = 'LOW';
      if (isRooted) riskLevel = 'HIGH';
      else if (isDevelopment || isEmulator) riskLevel = 'MEDIUM';

      console.log(`\n🎯 Overall Risk Level: ${riskLevel}`);

      if (riskLevel === 'HIGH') {
        console.log('\n⚠️  Recommendations:');
        console.log('• This device has elevated security risks');
        console.log('• Use for security testing purposes only');
        console.log('• Enable additional security monitoring');
      }

    } catch (error) {
      console.error('❌ Security check failed:', error.message);
    }
  }

  async verifyDeviceConnection(deviceId) {
    console.log('🔍 Verifying device connection...');

    try {
      const adbCommand = deviceId ? `adb -s ${deviceId}` : 'adb';
      
      // Get device info
      const manufacturer = execSync(`${adbCommand} shell getprop ro.product.manufacturer`, { encoding: 'utf8' }).trim();
      const model = execSync(`${adbCommand} shell getprop ro.product.model`, { encoding: 'utf8' }).trim();
      const android = execSync(`${adbCommand} shell getprop ro.build.version.release`, { encoding: 'utf8' }).trim();
      
      console.log('✅ Device connection verified');
      console.log(`📱 Device: ${manufacturer} ${model}`);
      console.log(`🤖 Android: ${android}`);

    } catch (error) {
      console.error('❌ Device verification failed:', error.message);
    }
  }

  async waitForEmulator() {
    return new Promise((resolve, reject) => {
      const checkEmulator = () => {
        try {
          const devices = execSync('adb devices', { encoding: 'utf8' });
          if (devices.includes('emulator-') && devices.includes('device')) {
            console.log('✅ Emulator is ready');
            resolve();
          } else {
            setTimeout(checkEmulator, 5000);
          }
        } catch (error) {
          reject(error);
        }
      };

      checkEmulator();
    });
  }

  showHelp() {
    console.log('📱 Mobile Security Device Manager');
    console.log('================================\n');
    console.log('Usage: node scripts/device-manager.js <command> [options]\n');
    console.log('Commands:');
    console.log('  list                    - List all connected devices and available emulators');
    console.log('  connect <device-id>     - Connect to a specific device');
    console.log('  start-emulator <name>   - Start an Android emulator');
    console.log('  setup-device [device]   - Setup device for security testing');
    console.log('  security-check [device] - Perform security analysis on device');
    console.log('\nExamples:');
    console.log('  node scripts/device-manager.js list');
    console.log('  node scripts/device-manager.js connect 192.168.1.100:5555');
    console.log('  node scripts/device-manager.js start-emulator Pixel_4_API_30');
    console.log('  node scripts/device-manager.js setup-device emulator-5554');
    console.log('  node scripts/device-manager.js security-check');
  }
}

// Run if called directly
if (require.main === module) {
  const manager = new DeviceManager();
  manager.run().catch(error => {
    console.error('Device manager error:', error);
    process.exit(1);
  });
}

module.exports = DeviceManager;