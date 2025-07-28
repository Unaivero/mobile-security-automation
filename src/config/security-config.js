/**
 * Security Configuration
 * Central configuration for security testing parameters and policies
 */

const path = require('path');
const crypto = require('crypto');

// Security policy configurations
const securityPolicies = {
  // Device security policies
  deviceSecurity: {
    emulatorPolicy: {
      enabled: true,
      action: 'block', // 'block', 'warn', 'log'
      confidence_threshold: 0.7,
      bypass_allowed: false,
      whitelist: [], // Device IDs that are allowed
      blacklist: [], // Device IDs that are always blocked
      detection_methods: [
        'build_fingerprint',
        'hardware_features',
        'system_files',
        'performance_characteristics',
        'sensor_data'
      ]
    },
    
    rootPolicy: {
      enabled: true,
      action: 'block', // 'block', 'warn', 'log'
      confidence_threshold: 0.5,
      bypass_allowed: false,
      detection_methods: [
        'su_binary',
        'root_apps',
        'system_writable',
        'dangerous_props',
        'busybox',
        'xposed_framework'
      ],
      advanced_detection: {
        magisk_detection: true,
        root_cloaking_detection: true,
        substrate_detection: true
      }
    },
    
    debugPolicy: {
      enabled: true,
      action: 'warn', // 'block', 'warn', 'log'
      allowed_in_dev: true,
      allowed_in_staging: false,
      allowed_in_production: false,
      detection_methods: [
        'adb_enabled',
        'debuggable_flag',
        'developer_options',
        'usb_debugging',
        'mock_locations'
      ]
    }
  },
  
  // Application security policies
  applicationSecurity: {
    integrityPolicy: {
      enabled: true,
      action: 'block',
      checksum_validation: true,
      signature_validation: true,
      code_injection_detection: true,
      hooking_detection: true,
      monitored_files: [
        'classes.dex',
        'AndroidManifest.xml',
        'resources.arsc',
        'lib/*/lib*.so'
      ]
    },
    
    runtimePolicy: {
      enabled: true,
      anti_debugging: true,
      anti_hooking: true,
      ssl_pinning: true,
      obfuscation_check: true,
      dynamic_analysis_detection: true
    }
  },
  
  // Network security policies
  networkSecurity: {
    trafficPolicy: {
      enabled: true,
      ssl_pinning: true,
      certificate_validation: true,
      proxy_detection: true,
      vpn_detection: true,
      mitm_detection: true,
      allowed_domains: [],
      blocked_domains: [],
      require_https: true
    },
    
    proxyPolicy: {
      enabled: true,
      action: 'warn',
      whitelist: [
        '127.0.0.1',
        'localhost'
      ],
      blacklist: [
        'proxy.suspicious.com',
        'mitm.attacker.net'
      ],
      corporate_proxies_allowed: true
    }
  }
};

// Security test configurations
const securityTestConfig = {
  // Test execution settings
  execution: {
    timeout: 60000,
    retries: 3,
    parallel_execution: false,
    fail_fast: false,
    evidence_collection: true,
    screenshots_on_failure: true,
    detailed_logging: true
  },
  
  // Evidence collection settings
  evidence: {
    screenshots: {
      enabled: true,
      format: 'png',
      quality: 'high',
      path: './reports/screenshots/'
    },
    
    logs: {
      enabled: true,
      level: 'debug',
      path: './reports/logs/',
      retention_days: 30,
      formats: ['logcat', 'appium', 'test']
    },
    
    videos: {
      enabled: false, // Enable for critical tests only
      format: 'mp4',
      quality: 'medium',
      path: './reports/videos/'
    },
    
    network_traces: {
      enabled: true,
      capture_ssl: false, // Only in test environments
      path: './reports/network/'
    }
  },
  
  // Reporting settings
  reporting: {
    formats: ['html', 'json', 'xml'],
    include_evidence: true,
    security_summary: true,
    risk_assessment: true,
    recommendations: true,
    compliance_mapping: true
  }
};

// Security alert configurations
const securityAlerts = {
  // Alert levels and thresholds
  levels: {
    info: {
      threshold: 0.2,
      action: 'log',
      notification: false
    },
    warning: {
      threshold: 0.5,
      action: 'log_and_report',
      notification: true
    },
    critical: {
      threshold: 0.8,
      action: 'block_and_alert',
      notification: true,
      escalation: true
    }
  },
  
  // Alert channels
  channels: {
    email: {
      enabled: process.env.ALERT_EMAIL_ENABLED === 'true',
      recipients: (process.env.ALERT_EMAIL_RECIPIENTS || '').split(','),
      smtp_config: {
        host: process.env.SMTP_HOST,
        port: process.env.SMTP_PORT || 587,
        secure: process.env.SMTP_SECURE === 'true',
        auth: {
          user: process.env.SMTP_USER,
          pass: process.env.SMTP_PASS
        }
      }
    },
    
    webhook: {
      enabled: process.env.ALERT_WEBHOOK_ENABLED === 'true',
      url: process.env.ALERT_WEBHOOK_URL,
      timeout: 5000,
      retry_attempts: 3
    },
    
    slack: {
      enabled: process.env.SLACK_ALERTS_ENABLED === 'true',
      webhook_url: process.env.SLACK_WEBHOOK_URL,
      channel: process.env.SLACK_CHANNEL || '#security-alerts',
      username: 'Security Bot'
    }
  }
};

// Compliance and regulatory configurations
const complianceConfig = {
  // Standards compliance
  standards: {
    owasp_masvs: {
      enabled: true,
      version: '2.0',
      categories: [
        'MASVS-STORAGE',
        'MASVS-CRYPTO',
        'MASVS-AUTH',
        'MASVS-NETWORK',
        'MASVS-PLATFORM',
        'MASVS-CODE',
        'MASVS-RESILIENCE'
      ]
    },
    
    pci_dss: {
      enabled: false,
      version: '4.0',
      requirements: [
        '4.1', // Use strong cryptography
        '6.5', // Address common vulnerabilities
        '11.3' // Implement penetration testing
      ]
    },
    
    gdpr: {
      enabled: true,
      data_protection: true,
      consent_tracking: true,
      breach_notification: true
    }
  },
  
  // Audit requirements
  audit: {
    enabled: true,
    log_all_activities: true,
    retention_period: '7 years',
    tamper_protection: true,
    digital_signatures: true
  }
};

// Environment-specific configurations
const environmentConfigs = {
  development: {
    security_level: 'relaxed',
    debug_mode: true,
    detailed_logging: true,
    allow_test_certificates: true,
    bypass_ssl_pinning: true,
    mock_security_checks: false,
    policies: {
      ...securityPolicies,
      deviceSecurity: {
        ...securityPolicies.deviceSecurity,
        emulatorPolicy: {
          ...securityPolicies.deviceSecurity.emulatorPolicy,
          action: 'warn'
        },
        debugPolicy: {
          ...securityPolicies.deviceSecurity.debugPolicy,
          allowed_in_dev: true
        }
      }
    }
  },
  
  staging: {
    security_level: 'standard',
    debug_mode: false,
    detailed_logging: true,
    allow_test_certificates: true,
    bypass_ssl_pinning: false,
    mock_security_checks: false,
    policies: securityPolicies
  },
  
  production: {
    security_level: 'strict',
    debug_mode: false,
    detailed_logging: false,
    allow_test_certificates: false,
    bypass_ssl_pinning: false,
    mock_security_checks: false,
    policies: {
      ...securityPolicies,
      deviceSecurity: {
        ...securityPolicies.deviceSecurity,
        debugPolicy: {
          ...securityPolicies.deviceSecurity.debugPolicy,
          action: 'block',
          allowed_in_production: false
        }
      }
    }
  }
};

// Threat intelligence configurations
const threatIntelligence = {
  // Known threats database
  knownThreats: {
    malicious_packages: [
      'com.malware.fake',
      'com.suspicious.app',
      'com.hacker.tool'
    ],
    
    malicious_signatures: [
      'deadbeef12345678',
      'cafebabe87654321'
    ],
    
    malicious_certificates: [
      'CN=Fake Certificate Authority',
      'CN=Suspicious Signer'
    ],
    
    malicious_domains: [
      'malicious-api.com',
      'phishing-site.org',
      'fake-update.net'
    ]
  },
  
  // Reputation services
  reputation: {
    enabled: true,
    cache_duration: 3600, // 1 hour
    services: [
      {
        name: 'VirusTotal',
        enabled: process.env.VT_API_KEY ? true : false,
        api_key: process.env.VT_API_KEY,
        rate_limit: 4 // requests per minute
      }
    ]
  }
};

/**
 * Security Configuration Manager
 */
class SecurityConfigManager {
  constructor(environment = 'development') {
    this.environment = environment;
    this.config = this.loadEnvironmentConfig(environment);
  }
  
  /**
   * Load configuration for specific environment
   */
  loadEnvironmentConfig(environment) {
    const envConfig = environmentConfigs[environment];
    if (!envConfig) {
      throw new Error(`Unknown environment: ${environment}`);
    }
    
    return {
      ...envConfig,
      testConfig: securityTestConfig,
      alerts: securityAlerts,
      compliance: complianceConfig,
      threatIntel: threatIntelligence,
      environment: environment,
      loadedAt: new Date().toISOString()
    };
  }
  
  /**
   * Get security policy
   */
  getSecurityPolicy(category, policy = null) {
    const policies = this.config.policies;
    const categoryPolicies = policies[category];
    
    if (!categoryPolicies) {
      throw new Error(`Unknown security category: ${category}`);
    }
    
    return policy ? categoryPolicies[policy] : categoryPolicies;
  }
  
  /**
   * Update security policy
   */
  updateSecurityPolicy(category, policy, updates) {
    if (!this.config.policies[category] || !this.config.policies[category][policy]) {
      throw new Error(`Invalid policy path: ${category}.${policy}`);
    }
    
    this.config.policies[category][policy] = {
      ...this.config.policies[category][policy],
      ...updates,
      updatedAt: new Date().toISOString()
    };
  }
  
  /**
   * Validate security configuration
   */
  validateConfiguration() {
    const errors = [];
    
    // Validate required settings
    if (!this.config.policies) {
      errors.push('Security policies not defined');
    }
    
    // Validate alert configuration
    if (this.config.alerts.channels.email.enabled) {
      if (!this.config.alerts.channels.email.recipients.length) {
        errors.push('Email alerts enabled but no recipients configured');
      }
    }
    
    // Validate compliance settings
    if (this.config.compliance.standards.owasp_masvs.enabled) {
      if (!this.config.compliance.standards.owasp_masvs.categories.length) {
        errors.push('OWASP MASVS enabled but no categories specified');
      }
    }
    
    if (errors.length > 0) {
      throw new Error(`Configuration validation failed: ${errors.join(', ')}`);
    }
    
    return true;
  }
  
  /**
   * Generate configuration hash for integrity checking
   */
  generateConfigHash() {
    const configString = JSON.stringify(this.config, null, 0);
    return crypto.createHash('sha256').update(configString).digest('hex');
  }
  
  /**
   * Export configuration for backup
   */
  exportConfiguration() {
    return {
      ...this.config,
      exportedAt: new Date().toISOString(),
      hash: this.generateConfigHash()
    };
  }
  
  /**
   * Get test-specific configuration
   */
  getTestConfiguration(testType) {
    const baseConfig = {
      ...this.config.testConfig,
      policies: this.config.policies,
      environment: this.environment
    };
    
    // Apply test-specific overrides
    switch (testType) {
      case 'emulator_detection':
        return {
          ...baseConfig,
          focus: 'emulator',
          policies: {
            deviceSecurity: {
              emulatorPolicy: this.config.policies.deviceSecurity.emulatorPolicy
            }
          }
        };
        
      case 'root_detection':
        return {
          ...baseConfig,
          focus: 'root',
          policies: {
            deviceSecurity: {
              rootPolicy: this.config.policies.deviceSecurity.rootPolicy
            }
          }
        };
        
      case 'file_tampering':
        return {
          ...baseConfig,
          focus: 'integrity',
          policies: {
            applicationSecurity: {
              integrityPolicy: this.config.policies.applicationSecurity.integrityPolicy
            }
          }
        };
        
      default:
        return baseConfig;
    }
  }
  
  /**
   * Check if feature is enabled
   */
  isFeatureEnabled(feature) {
    const featurePath = feature.split('.');
    let current = this.config;
    
    for (const segment of featurePath) {
      if (current[segment] === undefined) {
        return false;
      }
      current = current[segment];
    }
    
    return current === true;
  }
  
  /**
   * Get security threshold
   */
  getThreshold(category, metric) {
    const policy = this.getSecurityPolicy(category);
    return policy[metric] || policy.confidence_threshold || 0.5;
  }
}

module.exports = {
  securityPolicies,
  securityTestConfig,
  securityAlerts,
  complianceConfig,
  environmentConfigs,
  threatIntelligence,
  SecurityConfigManager
};