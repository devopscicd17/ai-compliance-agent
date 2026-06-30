'use strict';
/**
 * remediator.js
 * Executes safe, automated remediation for LOW-risk findings.
 * In DRY_RUN mode, logs the action without calling AWS mutating APIs.
 */

const { S3Client, PutPublicAccessBlockCommand, PutBucketEncryptionCommand, PutBucketVersioningCommand } = require('@aws-sdk/client-s3');
const { EC2Client, ModifyInstanceMetadataOptionsCommand, RevokeSecurityGroupIngressCommand } = require('@aws-sdk/client-ec2');
const { KMSClient, EnableKeyRotationCommand } = require('@aws-sdk/client-kms');
const { CloudTrailClient, UpdateTrailCommand, StartLoggingCommand } = require('@aws-sdk/client-cloudtrail');
const { RDSClient, ModifyDBInstanceCommand } = require('@aws-sdk/client-rds');
const { IAMClient, UpdateAccountPasswordPolicyCommand } = require('@aws-sdk/client-iam');
const { baseConfig } = require('../aws/client');

class Remediator {
  constructor() {
    this.log = [];
  }

  async remediate(finding, apply = false) {
    const action = `[${apply ? 'APPLY' : 'DRY-RUN'}] ${finding.id}: ${finding.short}`;
    console.log(`  ${apply ? '🔧' : '🔍'} ${action}`);

    if (!apply) {
      this.log.push({ ...finding, remediatedAt: new Date().toISOString(), mode: 'DRY_RUN' });
      return { success: true, mode: 'DRY_RUN' };
    }

    try {
      const handler = this._getHandler(finding.id);
      if (handler) {
        await handler(finding);
        this.log.push({ ...finding, remediatedAt: new Date().toISOString(), mode: 'ACTIVE', status: 'FIXED' });
        return { success: true, mode: 'ACTIVE' };
      }
      console.warn(`  ⚠ No automated handler for ${finding.id} — requires manual action`);
      return { success: false, reason: 'no_handler' };
    } catch (e) {
      console.error(`  ✗ Remediation failed for ${finding.id}:`, e.message);
      return { success: false, error: e.message };
    }
  }

  _getHandler(id) {
    const region = process.env.AWS_REGION || 'us-east-1';

    if (id.startsWith('S3-001-')) {
      return async (f) => {
        const s3 = new S3Client(baseConfig(region));
        const bucket = f.resourceName;
        await s3.send(new PutPublicAccessBlockCommand({
          Bucket: bucket,
          PublicAccessBlockConfiguration: { BlockPublicAcls: true, IgnorePublicAcls: true, BlockPublicPolicy: true, RestrictPublicBuckets: true },
        }));
      };
    }
    if (id.startsWith('S3-002-')) {
      return async (f) => {
        const s3 = new S3Client(baseConfig(region));
        await s3.send(new PutBucketEncryptionCommand({
          Bucket: f.resourceName,
          ServerSideEncryptionConfiguration: { Rules: [{ ApplyServerSideEncryptionByDefault: { SSEAlgorithm: 'aws:kms' }, BucketKeyEnabled: true }] },
        }));
      };
    }
    if (id.startsWith('S3-004-')) {
      return async (f) => {
        const s3 = new S3Client(baseConfig(region));
        await s3.send(new PutBucketVersioningCommand({ Bucket: f.resourceName, VersioningConfiguration: { Status: 'Enabled' } }));
      };
    }
    if (id.startsWith('EC2-IMDS-')) {
      return async (f) => {
        const ec2 = new EC2Client(baseConfig(region));
        const instanceId = f.resource.split('/').pop();
        await ec2.send(new ModifyInstanceMetadataOptionsCommand({ InstanceId: instanceId, HttpTokens: 'required', HttpEndpoint: 'enabled' }));
      };
    }
    if (id.startsWith('KMS-001-')) {
      return async (f) => {
        const kms = new KMSClient(baseConfig(region));
        const keyId = f.resource.split('/').pop();
        await kms.send(new EnableKeyRotationCommand({ KeyId: keyId }));
      };
    }
    if (id.startsWith('CT-005-')) {
      return async (f) => {
        const ct = new CloudTrailClient(baseConfig(region));
        await ct.send(new StartLoggingCommand({ Name: f.resource }));
      };
    }
    if (id.startsWith('RDS-002-')) {
      return async (f) => {
        const rds = new RDSClient(baseConfig(region));
        await rds.send(new ModifyDBInstanceCommand({ DBInstanceIdentifier: f.resourceName, PubliclyAccessible: false, ApplyImmediately: true }));
      };
    }
    if (id.startsWith('IAM-002-') || id.startsWith('IAM-003-') || id.startsWith('IAM-004-')) {
      return async (f) => {
        const iam = new IAMClient(baseConfig(region));
        await iam.send(new UpdateAccountPasswordPolicyCommand({
          MinimumPasswordLength: 14, RequireSymbols: true, RequireNumbers: true,
          RequireUppercaseCharacters: true, RequireLowercaseCharacters: true,
          MaxPasswordAge: 90, PasswordReusePrevention: 24, AllowUsersToChangePassword: true,
        }));
      };
    }

    return null;
  }

  getLog() {
    return this.log;
  }
}

module.exports = Remediator;
