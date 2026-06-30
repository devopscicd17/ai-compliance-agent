'use strict';
/**
 * cloudtrail-scanner.js  +  kms-scanner.js (combined)
 */

const {
  DescribeTrailsCommand,
  GetTrailStatusCommand,
  GetEventSelectorsCommand,
} = require('@aws-sdk/client-cloudtrail');

const {
  ListKeysCommand,
  DescribeKeyCommand,
  GetKeyRotationStatusCommand,
  ListAliasesCommand,
} = require('@aws-sdk/client-kms');

// ─── CloudTrail Scanner ────────────────────────────────────────────────────

class CloudTrailScanner {
  constructor(clients, accountId, region) {
    this.ct = clients.ct;
    this.accountId = accountId;
    this.region = region;
  }

  async scan() {
    const findings = [];
    console.log('  → Scanning CloudTrail configuration...');

    let trails = [];
    try {
      const r = await this.ct.send(new DescribeTrailsCommand({ includeShadowTrails: false }));
      trails = r.trailList || [];
    } catch (e) {
      console.warn('  ⚠ Cannot describe CloudTrail trails:', e.message);
      return [];
    }

    if (trails.length === 0) {
      findings.push(this._finding({
        id: `CT-001-${this.accountId}`,
        resource: `arn:aws:cloudtrail:${this.region}:${this.accountId}:trail/`,
        resourceName: 'CloudTrail',
        short: 'No CloudTrail trails configured',
        description: 'No CloudTrail trails are configured in this region/account. All AWS API calls are unlogged. This is a critical audit gap.',
        severity: 'CRITICAL',
        controls: [
          { framework: 'CIS', id: 'CIS-3.1', title: 'Ensure CloudTrail is enabled in all regions' },
          { framework: 'NIST', id: 'NIST-AU-2', title: 'Event Logging' },
          { framework: 'FEDRAMP', id: 'FEDRAMP-AU-2', title: 'Event Logging' },
          { framework: 'PCI', id: 'PCI-10.1', title: 'Implement audit trails to link all access to system components' },
        ],
        remediation: {
          manual: [
            `aws cloudtrail create-trail --name management-trail --s3-bucket-name <AUDIT-BUCKET> --is-multi-region-trail --enable-log-file-validation`,
            `aws cloudtrail start-logging --name management-trail`,
          ],
          automated: false, risk: 'HIGH',
        },
        current: { trails: 0 },
        expected: { multiRegion: true, logFileValidation: true },
      }));
      return findings;
    }

    for (const trail of trails) {
      const resource = trail.TrailARN;
      const name = trail.Name;

      // Multi-region check
      if (!trail.IsMultiRegionTrail) {
        findings.push(this._finding({
          id: `CT-002-${name}`,
          resource, resourceName: name,
          short: `Trail "${name}" is not multi-region`,
          description: `CloudTrail trail "${name}" only captures events in one region. API calls in other regions are not logged.`,
          severity: 'HIGH',
          controls: [
            { framework: 'CIS', id: 'CIS-3.1', title: 'Ensure CloudTrail is enabled in all regions' },
            { framework: 'NIST', id: 'NIST-AU-12', title: 'Audit Record Generation' },
            { framework: 'FEDRAMP', id: 'FEDRAMP-AU-12', title: 'Audit Record Generation' },
          ],
          remediation: {
            manual: [`aws cloudtrail update-trail --name ${name} --is-multi-region-trail`],
            automated: true, risk: 'LOW',
          },
          current: { multiRegion: false },
          expected: { multiRegion: true },
        }));
      }

      // Log file validation
      if (!trail.LogFileValidationEnabled) {
        findings.push(this._finding({
          id: `CT-003-${name}`,
          resource, resourceName: name,
          short: `Trail "${name}" has log file validation disabled`,
          description: `Log file validation for "${name}" is off. Without it, tampering with log files cannot be detected.`,
          severity: 'MEDIUM',
          controls: [
            { framework: 'CIS', id: 'CIS-3.2', title: 'Ensure CloudTrail log file validation is enabled' },
            { framework: 'NIST', id: 'NIST-AU-9', title: 'Protection of Audit Information' },
            { framework: 'FEDRAMP', id: 'FEDRAMP-AU-9', title: 'Protection of Audit Information' },
          ],
          remediation: {
            manual: [`aws cloudtrail update-trail --name ${name} --enable-log-file-validation`],
            automated: true, risk: 'LOW',
          },
          current: { logFileValidation: false },
          expected: { logFileValidation: true },
        }));
      }

      // CloudWatch integration
      if (!trail.CloudWatchLogsLogGroupArn) {
        findings.push(this._finding({
          id: `CT-004-${name}`,
          resource, resourceName: name,
          short: `Trail "${name}" not integrated with CloudWatch Logs`,
          description: `CloudTrail trail "${name}" does not send logs to CloudWatch Logs. Real-time alerting on suspicious API calls is not possible.`,
          severity: 'MEDIUM',
          controls: [
            { framework: 'CIS', id: 'CIS-3.4', title: 'Ensure CloudTrail trails are integrated with CloudWatch Logs' },
            { framework: 'NIST', id: 'NIST-SI-4', title: 'Information System Monitoring' },
          ],
          remediation: {
            manual: [
              `# Create log group:`,
              `aws logs create-log-group --log-group-name /aws/cloudtrail/${name}`,
              `# Update trail:`,
              `aws cloudtrail update-trail --name ${name} --cloud-watch-logs-log-group-arn arn:aws:logs:${this.region}:${this.accountId}:log-group:/aws/cloudtrail/${name} --cloud-watch-logs-role-arn <ROLE_ARN>`,
            ],
            automated: false, risk: 'LOW',
          },
          current: { cloudWatchLogs: false },
          expected: { cloudWatchLogs: true },
        }));
      }

      // Check if logging is active
      try {
        const status = await this.ct.send(new GetTrailStatusCommand({ Name: trail.TrailARN }));
        if (!status.IsLogging) {
          findings.push(this._finding({
            id: `CT-005-${name}`,
            resource, resourceName: name,
            short: `Trail "${name}" is not actively logging`,
            description: `CloudTrail trail "${name}" exists but logging is currently stopped.`,
            severity: 'CRITICAL',
            controls: [
              { framework: 'CIS', id: 'CIS-3.1', title: 'Ensure CloudTrail is enabled in all regions' },
              { framework: 'NIST', id: 'NIST-AU-12', title: 'Audit Record Generation' },
            ],
            remediation: {
              manual: [`aws cloudtrail start-logging --name ${name}`],
              automated: true, risk: 'LOW',
            },
            current: { logging: false },
            expected: { logging: true },
          }));
        }
      } catch (e) { /* ignore */ }
    }

    return findings;
  }

  _finding(f) {
    return { ...f, service: 'CloudTrail', status: 'OPEN', timestamp: new Date().toISOString(), accountId: this.accountId };
  }
}

// ─── KMS Scanner ──────────────────────────────────────────────────────────

class KMSScanner {
  constructor(clients, accountId, region) {
    this.kms = clients.kms;
    this.accountId = accountId;
    this.region = region;
  }

  async scan() {
    const findings = [];
    console.log('  → Scanning KMS key rotation...');

    let keys = [];
    try {
      const r = await this.kms.send(new ListKeysCommand({}));
      keys = r.Keys || [];
    } catch (e) {
      console.warn('  ⚠ Cannot list KMS keys:', e.message);
      return [];
    }

    const aliases = await this._getAliases();

    for (const key of keys) {
      try {
        const meta = await this.kms.send(new DescribeKeyCommand({ KeyId: key.KeyId }));
        const km = meta.KeyMetadata;
        if (km.KeyManager === 'AWS' || km.KeyState !== 'Enabled') continue; // Skip AWS-managed keys

        let rotationEnabled = false;
        try {
          const rr = await this.kms.send(new GetKeyRotationStatusCommand({ KeyId: key.KeyId }));
          rotationEnabled = rr.KeyRotationEnabled;
        } catch (e) {
          if (e.name === 'UnsupportedOperationException') continue;
        }

        if (!rotationEnabled) {
          const alias = aliases.get(key.KeyId) || key.KeyId;
          findings.push({
            id: `KMS-001-${key.KeyId}`,
            resource: `arn:aws:kms:${this.region}:${this.accountId}:key/${key.KeyId}`,
            resourceName: alias,
            short: `KMS key "${alias}" has automatic rotation disabled`,
            description: `Customer-managed KMS key "${alias}" does not have annual automatic key rotation enabled. FedRAMP SC-12 and NIST SC-12 require cryptographic key rotation.`,
            severity: 'MEDIUM',
            service: 'KMS',
            status: 'OPEN',
            accountId: this.accountId,
            timestamp: new Date().toISOString(),
            controls: [
              { framework: 'CIS', id: 'CIS-3.7', title: 'Ensure rotation for customer-created CMKs is enabled' },
              { framework: 'NIST', id: 'NIST-SC-12', title: 'Cryptographic Key Establishment and Management' },
              { framework: 'FEDRAMP', id: 'FEDRAMP-SC-12', title: 'Cryptographic Key Establishment and Management' },
            ],
            remediation: {
              manual: [`aws kms enable-key-rotation --key-id ${key.KeyId}`],
              automated: true, risk: 'LOW',
            },
            current: { rotation: false },
            expected: { rotation: true },
          });
        }
      } catch (e) { /* skip */ }
    }

    return findings;
  }

  async _getAliases() {
    const map = new Map();
    try {
      const r = await this.kms.send(new ListAliasesCommand({}));
      for (const a of r.Aliases || []) {
        if (a.TargetKeyId) map.set(a.TargetKeyId, a.AliasName);
      }
    } catch (e) { /* ignore */ }
    return map;
  }
}

module.exports = { CloudTrailScanner, KMSScanner };
