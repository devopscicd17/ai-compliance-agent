'use strict';
/**
 * aws-client.js
 * Central AWS SDK client factory with credential management,
 * cross-account role assumption, and retry logic.
 */

const { STSClient, AssumeRoleCommand, GetCallerIdentityCommand } = require('@aws-sdk/client-sts');
const { S3Client } = require('@aws-sdk/client-s3');
const { IAMClient } = require('@aws-sdk/client-iam');
const { EC2Client } = require('@aws-sdk/client-ec2');
const { RDSClient } = require('@aws-sdk/client-rds');
const { CloudTrailClient } = require('@aws-sdk/client-cloudtrail');
const { ConfigServiceClient } = require('@aws-sdk/client-config-service');
const { SecurityHubClient } = require('@aws-sdk/client-securityhub');
const { KMSClient } = require('@aws-sdk/client-kms');
const { CloudWatchClient } = require('@aws-sdk/client-cloudwatch');
const { LambdaClient } = require('@aws-sdk/client-lambda');
const { SNSClient } = require('@aws-sdk/client-sns');

const CLIENT_CACHE = new Map();

function baseConfig(region) {
  const cfg = { region: region || process.env.AWS_REGION || 'us-east-1' };
  if (process.env.AWS_ACCESS_KEY_ID && process.env.AWS_SECRET_ACCESS_KEY) {
    cfg.credentials = {
      accessKeyId: process.env.AWS_ACCESS_KEY_ID,
      secretAccessKey: process.env.AWS_SECRET_ACCESS_KEY,
      ...(process.env.AWS_SESSION_TOKEN && { sessionToken: process.env.AWS_SESSION_TOKEN }),
    };
  }
  return cfg;
}

async function assumeRoleCredentials(accountId, roleName, region) {
  const cacheKey = `${accountId}:${roleName}`;
  const cached = CLIENT_CACHE.get(cacheKey);
  if (cached && cached.expiry > Date.now() + 60_000) return cached.credentials;

  const sts = new STSClient(baseConfig(region));
  const roleArn = `arn:aws:iam::${accountId}:role/${roleName}`;
  const resp = await sts.send(new AssumeRoleCommand({
    RoleArn: roleArn,
    RoleSessionName: 'ComplianceAgentSession',
    DurationSeconds: 3600,
  }));

  const credentials = {
    accessKeyId: resp.Credentials.AccessKeyId,
    secretAccessKey: resp.Credentials.SecretAccessKey,
    sessionToken: resp.Credentials.SessionToken,
  };
  CLIENT_CACHE.set(cacheKey, { credentials, expiry: resp.Credentials.Expiration.getTime() });
  return credentials;
}

function makeClientConfig(region, credentials) {
  return {
    region: region || process.env.AWS_REGION || 'us-east-1',
    ...(credentials ? { credentials } : baseConfig(region)),
    maxAttempts: 3,
  };
}

function clientFactory(ClientClass, region, credentials) {
  return new ClientClass(makeClientConfig(region, credentials));
}

async function getClientsForAccount(accountId, region) {
  let credentials = null;
  if (accountId) {
    const roleName = process.env.AWS_ASSUME_ROLE_NAME || 'ComplianceAgentRole';
    credentials = await assumeRoleCredentials(accountId, roleName, region);
  }
  return {
    s3:       clientFactory(S3Client, region, credentials),
    iam:      clientFactory(IAMClient, region, credentials),
    ec2:      clientFactory(EC2Client, region, credentials),
    rds:      clientFactory(RDSClient, region, credentials),
    ct:       clientFactory(CloudTrailClient, region, credentials),
    config:   clientFactory(ConfigServiceClient, region, credentials),
    hub:      clientFactory(SecurityHubClient, region, credentials),
    kms:      clientFactory(KMSClient, region, credentials),
    cw:       clientFactory(CloudWatchClient, region, credentials),
    lambda:   clientFactory(LambdaClient, region, credentials),
    sns:      clientFactory(SNSClient, region, credentials),
    sts:      clientFactory(STSClient, region, credentials),
  };
}

async function getCurrentAccountId(region) {
  const sts = new STSClient(baseConfig(region));
  const resp = await sts.send(new GetCallerIdentityCommand({}));
  return { accountId: resp.Account, arn: resp.Arn, userId: resp.UserId };
}

// Paginate any AWS SDK command automatically
async function paginate(client, Command, params, resultKey) {
  const results = [];
  let nextToken;
  do {
    const resp = await client.send(new Command({ ...params, ...(nextToken && { NextToken: nextToken }) }));
    const items = resp[resultKey] || [];
    results.push(...items);
    nextToken = resp.NextToken || resp.Marker || resp.NextPageToken;
  } while (nextToken);
  return results;
}

module.exports = { getClientsForAccount, getCurrentAccountId, paginate, baseConfig };
