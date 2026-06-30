'use strict';
/**
 * rds-scanner.js
 * Evaluates RDS instances against FedRAMP SC-28, NIST SC-28, CIS 2.3.x
 */

const {
  DescribeDBInstancesCommand,
  DescribeDBSnapshotsCommand,
} = require('@aws-sdk/client-rds');

class RDSScanner {
  constructor(clients, accountId, region) {
    this.rds = clients.rds;
    this.accountId = accountId;
    this.region = region;
  }

  async scan() {
    const findings = [];
    console.log('  → Scanning RDS instances...');

    let instances = [];
    try {
      const r = await this.rds.send(new DescribeDBInstancesCommand({}));
      instances = r.DBInstances || [];
    } catch (e) {
      console.warn('  ⚠ Cannot list RDS instances:', e.message);
      return [];
    }

    console.log(`  → Checking ${instances.length} RDS instances`);

    for (const db of instances) {
      const resource = db.DBInstanceArn;
      const name = db.DBInstanceIdentifier;

      if (!db.StorageEncrypted) {
        findings.push(this._finding({
          id: `RDS-001-${name}`,
          resource, resourceName: name,
          short: `RDS instance "${name}" has encryption at rest disabled`,
          description: `RDS instance "${name}" (${db.Engine} ${db.EngineVersion}) does not have storage encryption enabled. FedRAMP Moderate and NIST SC-28 require encryption of data at rest.`,
          severity: 'HIGH',
          controls: [
            { framework: 'CIS', id: 'CIS-2.3.1', title: 'Ensure that encryption-at-rest is enabled for RDS Instances' },
            { framework: 'NIST', id: 'NIST-SC-28', title: 'Protection of Information at Rest' },
            { framework: 'FEDRAMP', id: 'FEDRAMP-SC-28', title: 'Protection of Information at Rest' },
            { framework: 'PCI', id: 'PCI-3.4', title: 'Render PAN unreadable anywhere stored' },
          ],
          remediation: {
            manual: [
              `# RDS encryption can only be enabled at creation — migrate to new encrypted instance:`,
              `# 1. Take a snapshot:`,
              `aws rds create-db-snapshot --db-instance-identifier ${name} --db-snapshot-identifier ${name}-for-migration`,
              `# 2. Copy snapshot with encryption:`,
              `aws rds copy-db-snapshot --source-db-snapshot-identifier ${name}-for-migration --target-db-snapshot-identifier ${name}-encrypted --kms-key-id alias/aws/rds`,
              `# 3. Restore from encrypted snapshot (creates new instance)`,
              `# 4. Update connection strings and delete old instance`,
            ],
            automated: false, risk: 'HIGH',
          },
          current: { encrypted: false, engine: db.Engine, version: db.EngineVersion },
          expected: { encrypted: true },
        }));
      }

      if (db.PubliclyAccessible) {
        findings.push(this._finding({
          id: `RDS-002-${name}`,
          resource, resourceName: name,
          short: `RDS instance "${name}" is publicly accessible`,
          description: `RDS instance "${name}" has PubliclyAccessible=true. The database endpoint is resolvable via public DNS and may be reachable from the internet.`,
          severity: 'CRITICAL',
          controls: [
            { framework: 'CIS', id: 'CIS-2.3.2', title: 'Ensure that public access is not given to RDS Instance' },
            { framework: 'NIST', id: 'NIST-SC-7', title: 'Boundary Protection' },
            { framework: 'FEDRAMP', id: 'FEDRAMP-SC-7', title: 'Boundary Protection' },
            { framework: 'PCI', id: 'PCI-1.3', title: 'Prohibit direct public access to cardholder data environment' },
          ],
          remediation: {
            manual: [
              `aws rds modify-db-instance --db-instance-identifier ${name} --no-publicly-accessible --apply-immediately`,
            ],
            automated: true, risk: 'LOW',
          },
          current: { publiclyAccessible: true },
          expected: { publiclyAccessible: false },
        }));
      }

      if (!db.MultiAZ) {
        findings.push(this._finding({
          id: `RDS-003-${name}`,
          resource, resourceName: name,
          short: `RDS instance "${name}" is not Multi-AZ`,
          description: `RDS instance "${name}" has Multi-AZ disabled. Single-AZ databases are vulnerable to availability zone failures.`,
          severity: 'LOW',
          controls: [
            { framework: 'NIST', id: 'NIST-CP-10', title: 'Information System Recovery and Reconstitution' },
            { framework: 'FEDRAMP', id: 'FEDRAMP-CP-10', title: 'Information System Recovery and Reconstitution' },
          ],
          remediation: {
            manual: [
              `aws rds modify-db-instance --db-instance-identifier ${name} --multi-az --apply-immediately`,
            ],
            automated: true, risk: 'MEDIUM',
          },
          current: { multiAZ: false },
          expected: { multiAZ: true },
        }));
      }

      if (!db.DeletionProtection) {
        findings.push(this._finding({
          id: `RDS-004-${name}`,
          resource, resourceName: name,
          short: `RDS instance "${name}" has deletion protection disabled`,
          description: `RDS instance "${name}" can be accidentally or maliciously deleted. Enable deletion protection.`,
          severity: 'MEDIUM',
          controls: [
            { framework: 'NIST', id: 'NIST-CP-9', title: 'Information System Backup' },
          ],
          remediation: {
            manual: [`aws rds modify-db-instance --db-instance-identifier ${name} --deletion-protection --apply-immediately`],
            automated: true, risk: 'LOW',
          },
          current: { deletionProtection: false },
          expected: { deletionProtection: true },
        }));
      }

      // Auto minor version upgrade check
      if (!db.AutoMinorVersionUpgrade) {
        findings.push(this._finding({
          id: `RDS-005-${name}`,
          resource, resourceName: name,
          short: `RDS instance "${name}" has auto minor version upgrade disabled`,
          description: `RDS instance "${name}" will not automatically apply minor engine version upgrades, which often include security patches.`,
          severity: 'LOW',
          controls: [
            { framework: 'NIST', id: 'NIST-SI-2', title: 'Flaw Remediation' },
            { framework: 'CIS', id: 'CIS-2.3.3', title: 'Ensure minor version upgrades are automatically applied' },
          ],
          remediation: {
            manual: [`aws rds modify-db-instance --db-instance-identifier ${name} --auto-minor-version-upgrade --apply-immediately`],
            automated: true, risk: 'LOW',
          },
          current: { autoMinorVersionUpgrade: false },
          expected: { autoMinorVersionUpgrade: true },
        }));
      }
    }

    return findings;
  }

  _finding(f) {
    return { ...f, service: 'RDS', status: 'OPEN', timestamp: new Date().toISOString(), accountId: this.accountId };
  }
}

module.exports = RDSScanner;
