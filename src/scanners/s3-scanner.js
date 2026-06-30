'use strict';
/**
 * s3-scanner.js
 * Evaluates S3 buckets against:
 *   CIS AWS Foundations 2.x
 *   FedRAMP Moderate SC-28, AC-3, AU-2
 *   NIST 800-53 SC-28, AC-3, AU-12
 *   PCI DSS 3.4, 10.x
 */

const {
  ListBucketsCommand,
  GetBucketAclCommand,
  GetBucketPolicyCommand,
  GetBucketEncryptionCommand,
  GetBucketLoggingCommand,
  GetBucketVersioningCommand,
  GetPublicAccessBlockCommand,
  GetBucketLocationCommand,
  GetBucketPolicyStatusCommand,
} = require('@aws-sdk/client-s3');

const { paginate } = require('../aws/client');

class S3Scanner {
  constructor(clients, accountId, region) {
    this.s3 = clients.s3;
    this.accountId = accountId;
    this.region = region;
  }

  async scan() {
    const findings = [];
    console.log('  → Listing S3 buckets...');

    let buckets = [];
    try {
      const resp = await this.s3.send(new ListBucketsCommand({}));
      buckets = resp.Buckets || [];
    } catch (e) {
      if (e.name === 'AccessDeniedException') {
        console.warn('  ⚠ No S3 ListBuckets permission — skipping S3 scan');
        return [];
      }
      throw e;
    }

    console.log(`  → Scanning ${buckets.length} S3 buckets`);

    for (const bucket of buckets) {
      const name = bucket.Name;
      const bFindings = await this._scanBucket(name);
      findings.push(...bFindings);
    }

    return findings;
  }

  async _scanBucket(name) {
    const findings = [];
    const resource = `arn:aws:s3:::${name}`;

    // ── Check public access block ──────────────────────────────────────────
    let pab = null;
    try {
      const r = await this.s3.send(new GetPublicAccessBlockCommand({ Bucket: name }));
      pab = r.PublicAccessBlockConfiguration;
    } catch (e) { /* not set */ }

    const pabFullyEnabled = pab &&
      pab.BlockPublicAcls && pab.IgnorePublicAcls &&
      pab.BlockPublicPolicy && pab.RestrictPublicBuckets;

    if (!pabFullyEnabled) {
      findings.push(this._finding({
        id: `S3-001-${name}`,
        resource,
        resourceName: name,
        short: 'S3 Block Public Access not fully enabled',
        description: `Bucket "${name}" does not have all four Block Public Access settings enabled. This may expose objects to public internet access.`,
        severity: 'HIGH',
        controls: [
          { framework: 'CIS', id: 'CIS-2.1.5', title: 'Ensure that S3 Buckets are configured with Block public access' },
          { framework: 'NIST', id: 'NIST-AC-3', title: 'Access Enforcement' },
          { framework: 'FEDRAMP', id: 'FEDRAMP-AC-3', title: 'Access Enforcement' },
        ],
        remediation: {
          manual: [
            'aws s3api put-public-access-block --bucket ' + name + ' --public-access-block-configuration "BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true"',
          ],
          automated: true,
          risk: 'LOW',
        },
        current: pab,
        expected: { BlockPublicAcls: true, IgnorePublicAcls: true, BlockPublicPolicy: true, RestrictPublicBuckets: true },
      }));
    }

    // ── Check encryption ───────────────────────────────────────────────────
    let encrypted = false;
    let encryptionType = null;
    try {
      const r = await this.s3.send(new GetBucketEncryptionCommand({ Bucket: name }));
      const rules = r.ServerSideEncryptionConfiguration?.Rules || [];
      encrypted = rules.length > 0;
      encryptionType = rules[0]?.ApplyServerSideEncryptionByDefault?.SSEAlgorithm;
    } catch (e) {
      if (e.name === 'ServerSideEncryptionConfigurationNotFoundError') encrypted = false;
    }

    if (!encrypted) {
      findings.push(this._finding({
        id: `S3-002-${name}`,
        resource,
        resourceName: name,
        short: 'S3 server-side encryption not enabled',
        description: `Bucket "${name}" has no default server-side encryption. Data at rest is unencrypted.`,
        severity: 'HIGH',
        controls: [
          { framework: 'CIS', id: 'CIS-2.1.1', title: 'Ensure all S3 buckets employ encryption-at-rest' },
          { framework: 'NIST', id: 'NIST-SC-28', title: 'Protection of Information at Rest' },
          { framework: 'FEDRAMP', id: 'FEDRAMP-SC-28', title: 'Protection of Information at Rest' },
          { framework: 'PCI', id: 'PCI-3.4', title: 'Render PAN unreadable anywhere it is stored' },
        ],
        remediation: {
          manual: [
            `aws s3api put-bucket-encryption --bucket ${name} --server-side-encryption-configuration '{"Rules":[{"ApplyServerSideEncryptionByDefault":{"SSEAlgorithm":"aws:kms"},"BucketKeyEnabled":true}]}'`,
          ],
          automated: true,
          risk: 'LOW',
        },
        current: { encrypted: false },
        expected: { encrypted: true, algorithm: 'aws:kms' },
      }));
    } else if (encryptionType === 'AES256') {
      findings.push(this._finding({
        id: `S3-002b-${name}`,
        resource,
        resourceName: name,
        short: 'S3 uses SSE-S3 instead of SSE-KMS',
        description: `Bucket "${name}" uses SSE-S3 (AES256). FedRAMP Moderate requires SSE-KMS for key management auditability.`,
        severity: 'MEDIUM',
        controls: [
          { framework: 'FEDRAMP', id: 'FEDRAMP-SC-12', title: 'Cryptographic Key Management' },
          { framework: 'NIST', id: 'NIST-SC-12', title: 'Cryptographic Key Establishment and Management' },
        ],
        remediation: {
          manual: [
            `aws s3api put-bucket-encryption --bucket ${name} --server-side-encryption-configuration '{"Rules":[{"ApplyServerSideEncryptionByDefault":{"SSEAlgorithm":"aws:kms"},"BucketKeyEnabled":true}]}'`,
          ],
          automated: true,
          risk: 'LOW',
        },
        current: { algorithm: 'AES256' },
        expected: { algorithm: 'aws:kms' },
      }));
    }

    // ── Check access logging ───────────────────────────────────────────────
    let loggingEnabled = false;
    try {
      const r = await this.s3.send(new GetBucketLoggingCommand({ Bucket: name }));
      loggingEnabled = !!(r.LoggingEnabled?.TargetBucket);
    } catch (e) { /* ignore */ }

    if (!loggingEnabled) {
      findings.push(this._finding({
        id: `S3-003-${name}`,
        resource,
        resourceName: name,
        short: 'S3 access logging disabled',
        description: `Bucket "${name}" does not have server access logging enabled. No audit trail exists for object-level API calls.`,
        severity: 'MEDIUM',
        controls: [
          { framework: 'CIS', id: 'CIS-2.1.2', title: 'Ensure S3 Bucket Policy is set to deny HTTP requests' },
          { framework: 'NIST', id: 'NIST-AU-12', title: 'Audit Record Generation' },
          { framework: 'FEDRAMP', id: 'FEDRAMP-AU-2', title: 'Event Logging' },
          { framework: 'PCI', id: 'PCI-10.2', title: 'Implement automated audit trails' },
        ],
        remediation: {
          manual: [
            `aws s3api put-bucket-logging --bucket ${name} --bucket-logging-status '{"LoggingEnabled":{"TargetBucket":"<YOUR-AUDIT-BUCKET>","TargetPrefix":"${name}/"}}'`,
          ],
          automated: false,
          risk: 'LOW',
        },
        current: { logging: false },
        expected: { logging: true },
      }));
    }

    // ── Check versioning ───────────────────────────────────────────────────
    let versioningEnabled = false;
    try {
      const r = await this.s3.send(new GetBucketVersioningCommand({ Bucket: name }));
      versioningEnabled = r.Status === 'Enabled';
    } catch (e) { /* ignore */ }

    if (!versioningEnabled) {
      findings.push(this._finding({
        id: `S3-004-${name}`,
        resource,
        resourceName: name,
        short: 'S3 versioning not enabled',
        description: `Bucket "${name}" does not have versioning enabled. Object deletion or overwrites are not recoverable.`,
        severity: 'LOW',
        controls: [
          { framework: 'CIS', id: 'CIS-2.1.3', title: 'Ensure MFA Delete is enabled on S3 buckets' },
          { framework: 'NIST', id: 'NIST-CP-9', title: 'Information System Backup' },
        ],
        remediation: {
          manual: [`aws s3api put-bucket-versioning --bucket ${name} --versioning-configuration Status=Enabled`],
          automated: true,
          risk: 'LOW',
        },
        current: { versioning: 'Disabled' },
        expected: { versioning: 'Enabled' },
      }));
    }

    // ── Check bucket policy for public access ──────────────────────────────
    try {
      const r = await this.s3.send(new GetBucketPolicyStatusCommand({ Bucket: name }));
      if (r.PolicyStatus?.IsPublic) {
        findings.push(this._finding({
          id: `S3-005-${name}`,
          resource,
          resourceName: name,
          short: 'S3 bucket policy grants public access',
          description: `Bucket "${name}" has a bucket policy that grants public access. This is a critical data exposure risk.`,
          severity: 'CRITICAL',
          controls: [
            { framework: 'CIS', id: 'CIS-2.1.5', title: 'Ensure that S3 Buckets are configured with Block public access' },
            { framework: 'NIST', id: 'NIST-AC-3', title: 'Access Enforcement' },
            { framework: 'FEDRAMP', id: 'FEDRAMP-AC-3', title: 'Access Enforcement' },
            { framework: 'PCI', id: 'PCI-7.1', title: 'Limit access to system components' },
          ],
          remediation: {
            manual: [
              `# Review and tighten the bucket policy:`,
              `aws s3api get-bucket-policy --bucket ${name}`,
              `# Then apply restrictive policy or remove public grants`,
              `aws s3api put-public-access-block --bucket ${name} --public-access-block-configuration "BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true"`,
            ],
            automated: false,
            risk: 'HIGH',
          },
          current: { publicPolicy: true },
          expected: { publicPolicy: false },
        }));
      }
    } catch (e) { /* no policy or access denied */ }

    return findings;
  }

  _finding(f) {
    return {
      ...f,
      service: 'S3',
      status: 'OPEN',
      timestamp: new Date().toISOString(),
      accountId: this.accountId,
    };
  }
}

module.exports = S3Scanner;
