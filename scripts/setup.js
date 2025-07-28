#!/usr/bin/env node

/**
 * Setup Script for Mobile Security Automation Framework
 * Initializes the testing environment and validates dependencies
 */

const fs = require('fs');
const path = require('path');
const { execSync } = require('child_process');

class SetupManager {
  constructor() {
    this.rootDir = path.resolve(__dirname, '..');
    this.errors = [];
    this.warnings = [];
  }

  async run() {
    console.log('🚀 Mobile Security Automation Framework Setup');
    console.log('==============================================\n');

    try {
      await this.checkNodeVersion();
      await this.validateDependencies();
      await this.checkADBConnection();
      await this.validateDirectoryStructure();
      await this.createConfigFiles();
      await this.runInitialTests();
      
      this.showResults();
    } catch (error) {
      console.error('❌ Setup failed:', error.message);
      process.exit(1);
    }
  }

  async checkNodeVersion() {
    console.log('📋 Checking Node.js version...');
    
    const nodeVersion = process.version;
    const majorVersion = parseInt(nodeVersion.slice(1).split('.')[0]);
    
    if (majorVersion < 14) {
      this.errors.push(`Node.js version ${nodeVersion} is too old. Please upgrade to Node.js 14 or higher.`);
    } else {
      console.log(`✅ Node.js ${nodeVersion} is compatible\n`);
    }
  }

  async validateDependencies() {
    console.log('📦 Validating dependencies...');
    
    const packageJsonPath = path.join(this.rootDir, 'package.json');
    
    if (!fs.existsSync(packageJsonPath)) {
      this.errors.push('package.json not found. Run "npm init" first.');
      return;
    }

    try {
      execSync('npm list --depth=0', { cwd: this.rootDir, stdio: 'pipe' });
      console.log('✅ All npm dependencies are installed\n');
    } catch (error) {
      this.warnings.push('Some npm dependencies may be missing. Run "npm install".');
    }
  }

  async checkADBConnection() {
    console.log('📱 Checking ADB connection...');
    
    try {
      const devices = execSync('adb devices', { encoding: 'utf8' });
      const deviceLines = devices.split('\n').filter(line => line.includes('\tdevice'));
      
      if (deviceLines.length === 0) {
        this.warnings.push('No ADB devices connected. Connect a device or start an emulator.');
      } else {
        console.log(`✅ Found ${deviceLines.length} connected device(s):`);
        deviceLines.forEach(line => {
          console.log(`   ${line.split('\t')[0]}`);
        });
        console.log();
      }
    } catch (error) {
      this.errors.push('ADB not found in PATH. Please install Android SDK Platform Tools.');
    }
  }

  async validateDirectoryStructure() {
    console.log('📁 Validating directory structure...');
    
    const requiredDirs = [
      'src/utils',
      'src/config',
      'src/pages',
      'tests/security',
      'tests/integration',
      'tests/fixtures',
      'scripts',
      'reports',
      'logs'
    ];

    let missingDirs = 0;
    
    for (const dir of requiredDirs) {
      const fullPath = path.join(this.rootDir, dir);
      if (!fs.existsSync(fullPath)) {
        fs.mkdirSync(fullPath, { recursive: true });
        missingDirs++;
      }
    }

    if (missingDirs > 0) {
      console.log(`✅ Created ${missingDirs} missing directories`);
    } else {
      console.log('✅ Directory structure is complete');
    }
    console.log();
  }

  async createConfigFiles() {
    console.log('⚙️  Creating configuration files...');
    
    const configFiles = [
      {
        path: '.env.example',
        content: `# Mobile Security Automation Environment Variables
APP_PACKAGE=com.example.app
TEST_ENVIRONMENT=development
ADB_TIMEOUT=30000
SECURITY_LEVEL=standard
DEVICE_WAIT_TIMEOUT=60000
SCREENSHOT_DIR=./reports/screenshots
LOG_LEVEL=info
`
      },
      {
        path: '.gitignore',
        content: `# Dependencies
node_modules/
npm-debug.log*

# Test results
reports/
logs/
screenshots/

# Environment variables
.env

# IDE files
.vscode/
.idea/

# System files
.DS_Store
Thumbs.db

# Temporary files
*.tmp
*.temp
`
      },
      {
        path: 'scripts/test-runner.sh',
        content: `#!/bin/bash

# Mobile Security Test Runner
echo "🧪 Starting Mobile Security Tests"
echo "================================="

# Check if device is connected
if ! adb devices | grep -q "device$"; then
    echo "❌ No device connected. Please connect a device or start an emulator."
    exit 1
fi

# Set environment
export NODE_ENV=test
export TEST_ENVIRONMENT=\${TEST_ENVIRONMENT:-development}

# Run security tests
echo "🔒 Running security tests..."
npm run test:security

# Run integration tests
echo "🔗 Running integration tests..."
npm run test:integration

echo "✅ Test run completed"
`
      }
    ];

    for (const file of configFiles) {
      const fullPath = path.join(this.rootDir, file.path);
      if (!fs.existsSync(fullPath)) {
        fs.writeFileSync(fullPath, file.content);
        
        // Make shell scripts executable
        if (file.path.endsWith('.sh')) {
          try {
            execSync(`chmod +x "${fullPath}"`);
          } catch (error) {
            // Ignore permission errors on Windows
          }
        }
      }
    }

    console.log('✅ Configuration files created\n');
  }

  async runInitialTests() {
    console.log('🧪 Running initial validation tests...');
    
    try {
      // Test ADB helper
      const adbHelperPath = path.join(this.rootDir, 'src/utils/adb-helper.js');
      if (fs.existsSync(adbHelperPath)) {
        console.log('✅ ADB Helper module found');
      } else {
        this.errors.push('ADB Helper module not found');
      }

      // Test device detector
      const deviceDetectorPath = path.join(this.rootDir, 'src/utils/device-detector.js');
      if (fs.existsSync(deviceDetectorPath)) {
        console.log('✅ Device Detector module found');
      } else {
        this.errors.push('Device Detector module not found');
      }

      // Test security checker
      const securityCheckerPath = path.join(this.rootDir, 'src/utils/security-checker.js');
      if (fs.existsSync(securityCheckerPath)) {
        console.log('✅ Security Checker module found');
      } else {
        this.errors.push('Security Checker module not found');
      }

      console.log();
    } catch (error) {
      this.warnings.push('Could not validate all modules');
    }
  }

  showResults() {
    console.log('📊 Setup Summary');
    console.log('================');
    
    if (this.errors.length === 0) {
      console.log('✅ Setup completed successfully!\n');
      
      console.log('🚀 Next steps:');
      console.log('1. Copy .env.example to .env and configure your settings');
      console.log('2. Connect an Android device or start an emulator');
      console.log('3. Run: npm run test:security');
      console.log('4. Run: npm run test:integration');
      console.log();
      
      if (this.warnings.length > 0) {
        console.log('⚠️  Warnings:');
        this.warnings.forEach(warning => console.log(`   ${warning}`));
        console.log();
      }
    } else {
      console.log('❌ Setup encountered errors:\n');
      this.errors.forEach(error => console.log(`   ${error}`));
      console.log();
      
      if (this.warnings.length > 0) {
        console.log('⚠️  Warnings:');
        this.warnings.forEach(warning => console.log(`   ${warning}`));
        console.log();
      }
      
      process.exit(1);
    }
  }
}

// Run setup if called directly
if (require.main === module) {
  const setup = new SetupManager();
  setup.run().catch(error => {
    console.error('Setup failed:', error);
    process.exit(1);
  });
}

module.exports = SetupManager;