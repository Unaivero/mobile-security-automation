/**
 * File Manipulator Utility
 * Provides file tampering utilities for security testing
 */

const ADBHelper = require('./adb-helper');
const chalk = require('chalk');
const crypto = require('crypto');
const fs = require('fs-extra');
const path = require('path');

class FileManipulator {
  constructor(deviceId = null) {
    this.adb = new ADBHelper(deviceId);
    this.backupDir = path.join(__dirname, '../../tmp/backups');
    this.checksums = new Map();
    this.monitoredFiles = new Set();
  }

  /**
   * Initialize file manipulation environment
   */
  async initialize() {
    try {
      console.log(chalk.blue('🔧 Initializing file manipulation environment...'));
      
      // Ensure backup directory exists
      await fs.ensureDir(this.backupDir);
      
      // Set up monitoring directories on device
      await this.setupMonitoringDirectories();
      
      console.log(chalk.green('✅ File manipulation environment initialized'));
      return true;
    } catch (error) {
      console.error(chalk.red('❌ Failed to initialize file manipulator:'), error.message);
      return false;
    }
  }

  /**
   * Create backup of critical files
   */
  async createBackup(remotePath, backupName = null) {
    try {
      const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
      const fileName = backupName || `${path.basename(remotePath)}_${timestamp}`;
      const localBackupPath = path.join(this.backupDir, fileName);
      
      console.log(chalk.blue(`💾 Creating backup of: ${remotePath}`));
      
      // Pull file from device
      const result = await this.adb.pullFile(remotePath, localBackupPath);
      
      if (result.success) {
        // Calculate checksum for integrity verification
        const content = await fs.readFile(localBackupPath);
        const checksum = crypto.createHash('sha256').update(content).digest('hex');
        
        this.checksums.set(fileName, {
          originalPath: remotePath,
          localPath: localBackupPath,
          checksum: checksum,
          timestamp: new Date().toISOString()
        });
        
        console.log(chalk.green(`✅ Backup created: ${fileName}`));
        console.log(chalk.gray(`   Checksum: ${checksum.substring(0, 16)}...`));
        
        return {
          success: true,
          backupName: fileName,
          localPath: localBackupPath,
          checksum: checksum
        };
      }
      
      return result;
    } catch (error) {
      console.error(chalk.red('❌ Failed to create backup:'), error.message);
      return { success: false, error: error.message };
    }
  }

  /**
   * Restore file from backup
   */
  async restoreFromBackup(backupName) {
    try {
      console.log(chalk.blue(`🔄 Restoring from backup: ${backupName}`));
      
      const backupInfo = this.checksums.get(backupName);
      if (!backupInfo) {
        throw new Error(`Backup not found: ${backupName}`);
      }
      
      // Verify backup integrity
      const content = await fs.readFile(backupInfo.localPath);
      const currentChecksum = crypto.createHash('sha256').update(content).digest('hex');
      
      if (currentChecksum !== backupInfo.checksum) {
        throw new Error('Backup file integrity check failed');
      }
      
      // Restore file to device
      const result = await this.adb.pushFile(backupInfo.localPath, backupInfo.originalPath);
      
      if (result.success) {
        console.log(chalk.green(`✅ File restored successfully`));
      }
      
      return result;
    } catch (error) {
      console.error(chalk.red('❌ Failed to restore backup:'), error.message);
      return { success: false, error: error.message };
    }
  }

  /**
   * Modify configuration file
   */
  async modifyConfig(configPath, key, value, configFormat = 'properties') {
    try {
      console.log(chalk.blue(`🔧 Modifying config: ${configPath}`));
      console.log(chalk.gray(`   Setting ${key} = ${value}`));
      
      // Create backup first
      const backup = await this.createBackup(configPath, `config_backup_${Date.now()}`);
      if (!backup.success) {
        throw new Error('Failed to create backup before modification');
      }
      
      // Pull current config
      const tempLocalPath = path.join(__dirname, '../../tmp', `temp_config_${Date.now()}`);
      const pullResult = await this.adb.pullFile(configPath, tempLocalPath);
      
      if (!pullResult.success) {
        throw new Error('Failed to pull config file');
      }
      
      // Modify config based on format
      let modifiedContent;
      const originalContent = await fs.readFile(tempLocalPath, 'utf8');
      
      switch (configFormat) {
        case 'properties':
          modifiedContent = this.modifyPropertiesFile(originalContent, key, value);
          break;
        case 'json':
          modifiedContent = this.modifyJSONFile(originalContent, key, value);
          break;
        case 'xml':
          modifiedContent = this.modifyXMLFile(originalContent, key, value);
          break;
        default:
          throw new Error(`Unsupported config format: ${configFormat}`);
      }
      
      // Write modified content
      await fs.writeFile(tempLocalPath, modifiedContent);
      
      // Push modified file back
      const pushResult = await this.adb.pushFile(tempLocalPath, configPath);
      
      // Clean up temp file
      await fs.remove(tempLocalPath);
      
      if (pushResult.success) {
        console.log(chalk.green(`✅ Configuration modified successfully`));
        
        // Add to monitored files for integrity checking
        this.monitoredFiles.add(configPath);
        
        return {
          success: true,
          backupName: backup.backupName,
          originalValue: this.extractOriginalValue(originalContent, key, configFormat),
          newValue: value
        };
      }
      
      return pushResult;
    } catch (error) {
      console.error(chalk.red('❌ Failed to modify config:'), error.message);
      return { success: false, error: error.message };
    }
  }

  /**
   * Tamper with application files
   */
  async tamperWithFile(filePath, tamperType, options = {}) {
    try {
      console.log(chalk.blue(`🔧 Tampering with file: ${filePath}`));
      console.log(chalk.gray(`   Tamper type: ${tamperType}`));
      
      // Create backup
      const backup = await this.createBackup(filePath, `tamper_backup_${Date.now()}`);
      if (!backup.success) {
        throw new Error('Failed to create backup before tampering');
      }
      
      let tamperResult;
      
      switch (tamperType) {
        case 'corrupt':
          tamperResult = await this.corruptFile(filePath, options);
          break;
        case 'modify_permissions':
          tamperResult = await this.modifyFilePermissions(filePath, options.permissions || '777');
          break;
        case 'inject_code':
          tamperResult = await this.injectCode(filePath, options.code || '// Injected code');
          break;
        case 'replace_content':
          tamperResult = await this.replaceFileContent(filePath, options.newContent || 'TAMPERED');
          break;
        case 'modify_timestamp':
          tamperResult = await this.modifyTimestamp(filePath, options.timestamp);
          break;
        case 'add_malicious_payload':
          tamperResult = await this.addMaliciousPayload(filePath, options.payload);
          break;
        default:
          throw new Error(`Unknown tamper type: ${tamperType}`);
      }
      
      if (tamperResult.success) {
        console.log(chalk.red(`⚠️  File tampered successfully: ${tamperType}`));
        this.monitoredFiles.add(filePath);
        
        return {
          success: true,
          tamperType: tamperType,
          backupName: backup.backupName,
          details: tamperResult.details
        };
      }
      
      return tamperResult;
    } catch (error) {
      console.error(chalk.red('❌ File tampering failed:'), error.message);
      return { success: false, error: error.message };
    }
  }

  /**
   * Monitor file integrity
   */
  async monitorFileIntegrity(filePaths, duration = 30000) {
    try {
      console.log(chalk.blue(`🔍 Starting file integrity monitoring for ${duration}ms...`));
      
      const initialChecksums = new Map();
      
      // Calculate initial checksums
      for (const filePath of filePaths) {
        const checksum = await this.calculateRemoteFileChecksum(filePath);
        if (checksum) {
          initialChecksums.set(filePath, checksum);
          this.monitoredFiles.add(filePath);
        }
      }
      
      console.log(chalk.green(`✅ Monitoring ${initialChecksums.size} files for changes...`));
      
      // Monitor for changes
      const changes = [];
      const monitorInterval = setInterval(async () => {
        for (const [filePath, originalChecksum] of initialChecksums) {
          const currentChecksum = await this.calculateRemoteFileChecksum(filePath);
          
          if (currentChecksum && currentChecksum !== originalChecksum) {
            changes.push({
              filePath: filePath,
              originalChecksum: originalChecksum,
              currentChecksum: currentChecksum,
              timestamp: new Date().toISOString(),
              changeType: 'content_modified'
            });
            
            console.log(chalk.red(`⚠️  File integrity violation detected: ${filePath}`));
            
            // Update the checksum to avoid duplicate notifications
            initialChecksums.set(filePath, currentChecksum);
          }
        }
      }, 5000); // Check every 5 seconds
      
      // Stop monitoring after duration
      setTimeout(() => {
        clearInterval(monitorInterval);
        console.log(chalk.green(`✅ File integrity monitoring completed`));
        console.log(chalk.yellow(`   Changes detected: ${changes.length}`));
      }, duration);
      
      return {
        success: true,
        monitoredFiles: Array.from(initialChecksums.keys()),
        changes: changes
      };
    } catch (error) {
      console.error(chalk.red('❌ File integrity monitoring failed:'), error.message);
      return { success: false, error: error.message };
    }
  }

  /**
   * Create test files for tampering scenarios
   */
  async createTestFiles() {
    try {
      console.log(chalk.blue('📝 Creating test files for tampering scenarios...'));
      
      const testFiles = [
        {
          path: '/data/local/tmp/test_config.properties',
          content: 'debug.enabled=false\nsecurity.level=high\nlogging.enabled=true\n'
        },
        {
          path: '/data/local/tmp/test_data.json',
          content: JSON.stringify({
            security: { enabled: true, level: 'high' },
            features: { debug: false, test: false }
          }, null, 2)
        },
        {
          path: '/data/local/tmp/test_script.sh',
          content: '#!/bin/sh\necho "Test script execution"\nexit 0\n'
        }
      ];
      
      const createdFiles = [];
      
      for (const testFile of testFiles) {
        // Create local temp file
        const tempPath = path.join(__dirname, '../../tmp', path.basename(testFile.path));
        await fs.writeFile(tempPath, testFile.content);
        
        // Push to device
        const result = await this.adb.pushFile(tempPath, testFile.path);
        
        if (result.success) {
          // Set appropriate permissions
          await this.adb.executeShellCommand(`chmod 644 ${testFile.path}`);
          createdFiles.push(testFile.path);
          
          console.log(chalk.green(`✅ Test file created: ${testFile.path}`));
        }
        
        // Clean up local temp file
        await fs.remove(tempPath);
      }
      
      return { success: true, createdFiles: createdFiles };
    } catch (error) {
      console.error(chalk.red('❌ Failed to create test files:'), error.message);
      return { success: false, error: error.message };
    }
  }

  /**
   * Clean up test files and backups
   */
  async cleanup() {
    try {
      console.log(chalk.blue('🧹 Cleaning up test files and backups...'));
      
      // Remove test files from device
      const testFilePatterns = [
        '/data/local/tmp/test_*',
        '/data/local/tmp/tamper_*',
        '/data/local/tmp/temp_*'
      ];
      
      for (const pattern of testFilePatterns) {
        await this.adb.executeShellCommand(`rm -f ${pattern}`);
      }
      
      // Clean up local backup directory
      const backupFiles = await fs.readdir(this.backupDir);
      for (const file of backupFiles) {
        await fs.remove(path.join(this.backupDir, file));
      }
      
      // Clear internal state
      this.checksums.clear();
      this.monitoredFiles.clear();
      
      console.log(chalk.green('✅ Cleanup completed'));
      return { success: true };
    } catch (error) {
      console.error(chalk.red('❌ Cleanup failed:'), error.message);
      return { success: false, error: error.message };
    }
  }

  /**
   * Helper methods for file manipulation
   */
  
  async setupMonitoringDirectories() {
    const monitorDirs = ['/data/local/tmp', '/sdcard/test'];
    
    for (const dir of monitorDirs) {
      await this.adb.executeShellCommand(`mkdir -p ${dir}`);
    }
  }

  modifyPropertiesFile(content, key, value) {
    const lines = content.split('\n');
    let keyFound = false;
    
    const modifiedLines = lines.map(line => {
      if (line.trim().startsWith(key + '=')) {
        keyFound = true;
        return `${key}=${value}`;
      }
      return line;
    });
    
    // Add key if not found
    if (!keyFound) {
      modifiedLines.push(`${key}=${value}`);
    }
    
    return modifiedLines.join('\n');
  }

  modifyJSONFile(content, key, value) {
    try {
      const json = JSON.parse(content);
      this.setNestedValue(json, key, value);
      return JSON.stringify(json, null, 2);
    } catch (error) {
      throw new Error(`Invalid JSON content: ${error.message}`);
    }
  }

  modifyXMLFile(content, key, value) {
    // Simple XML modification - in a real implementation, use a proper XML parser
    const regex = new RegExp(`(<${key}[^>]*>)[^<]*(</`, key + '>)');
    if (regex.test(content)) {
      return content.replace(regex, `$1${value}$2`);
    } else {
      // Add new element before closing root tag
      return content.replace('</root>', `  <${key}>${value}</${key}>\n</root>`);
    }
  }

  setNestedValue(obj, path, value) {
    const keys = path.split('.');
    let current = obj;
    
    for (let i = 0; i < keys.length - 1; i++) {
      const key = keys[i];
      if (!(key in current)) {
        current[key] = {};
      }
      current = current[key];
    }
    
    current[keys[keys.length - 1]] = value;
  }

  extractOriginalValue(content, key, format) {
    switch (format) {
      case 'properties':
        const match = content.match(new RegExp(`^${key}=(.*)$`, 'm'));
        return match ? match[1] : null;
      case 'json':
        try {
          const json = JSON.parse(content);
          return this.getNestedValue(json, key);
        } catch (error) {
          return null;
        }
      default:
        return null;
    }
  }

  getNestedValue(obj, path) {
    return path.split('.').reduce((current, key) => current && current[key], obj);
  }

  async calculateRemoteFileChecksum(filePath) {
    try {
      const result = await this.adb.executeShellCommand(`sha256sum ${filePath}`);
      if (result.success) {
        const checksum = result.output.split(' ')[0];
        return checksum;
      }
      return null;
    } catch (error) {
      return null;
    }
  }

  async corruptFile(filePath, options) {
    try {
      // Simple corruption: add random bytes
      const corruption = options.corruption || 'CORRUPTED_DATA_INJECTION';
      const result = await this.adb.executeShellCommand(`echo "${corruption}" >> ${filePath}`);
      
      return {
        success: result.success,
        details: { corruptionType: 'append', data: corruption }
      };
    } catch (error) {
      return { success: false, error: error.message };
    }
  }

  async modifyFilePermissions(filePath, permissions) {
    try {
      const result = await this.adb.executeShellCommand(`chmod ${permissions} ${filePath}`);
      
      return {
        success: result.success,
        details: { newPermissions: permissions }
      };
    } catch (error) {
      return { success: false, error: error.message };
    }
  }

  async injectCode(filePath, code) {
    try {
      const result = await this.adb.executeShellCommand(`echo "${code}" >> ${filePath}`);
      
      return {
        success: result.success,
        details: { injectedCode: code }
      };
    } catch (error) {
      return { success: false, error: error.message };
    }
  }

  async replaceFileContent(filePath, newContent) {
    try {
      const result = await this.adb.executeShellCommand(`echo "${newContent}" > ${filePath}`);
      
      return {
        success: result.success,
        details: { newContent: newContent }
      };
    } catch (error) {
      return { success: false, error: error.message };
    }
  }

  async modifyTimestamp(filePath, timestamp) {
    try {
      const touchTime = timestamp || '202301010000'; // Format: YYYYMMDDhhmm
      const result = await this.adb.executeShellCommand(`touch -t ${touchTime} ${filePath}`);
      
      return {
        success: result.success,
        details: { newTimestamp: touchTime }
      };
    } catch (error) {
      return { success: false, error: error.message };
    }
  }

  async addMaliciousPayload(filePath, payload) {
    try {
      const maliciousCode = payload || 'eval(base64_decode("bWFsaWNpb3VzX2NvZGU="))'; // "malicious_code" in base64
      const result = await this.adb.executeShellCommand(`echo "${maliciousCode}" >> ${filePath}`);
      
      return {
        success: result.success,
        details: { payload: maliciousCode }
      };
    } catch (error) {
      return { success: false, error: error.message };
    }
  }
}

module.exports = FileManipulator;