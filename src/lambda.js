'use strict';
/**
 * lambda.js
 * Entrypoint when deployed as an AWS Lambda function, triggered by
 * EventBridge Scheduler (e.g. every hour) for continuous monitoring
 * without needing a long-running container.
 *
 * Handler: src/lambda.handler
 */

require('dotenv').config();
const { ComplianceAgent } = require('./agent');

let cachedAgent; // reuse across warm invocations

exports.handler = async (event, context) => {
  console.log('Lambda invocation event:', JSON.stringify(event));

  if (!cachedAgent) cachedAgent = new ComplianceAgent();

  try {
    const report = await cachedAgent.runScan();
    return {
      statusCode: 200,
      body: JSON.stringify({
        accountId: report.accountId,
        totalFindings: report.findings.length,
        score: report.analysis.score,
        severityCounts: report.analysis.severityCounts,
        jsonReportPath: report.json,
        htmlReportPath: report.html,
      }),
    };
  } catch (e) {
    console.error('Lambda scan failed:', e);
    return { statusCode: 500, body: JSON.stringify({ error: e.message }) };
  }
};

// Separate handler if you want report-upload-to-S3 behavior baked in.
// Set REPORT_S3_BUCKET env var to auto-upload reports after each scan.
exports.handlerWithS3Upload = async (event, context) => {
  const result = await exports.handler(event, context);
  const bucket = process.env.REPORT_S3_BUCKET;
  if (bucket && result.statusCode === 200) {
    const { S3Client, PutObjectCommand } = require('@aws-sdk/client-s3');
    const fs = require('fs');
    const path = require('path');
    const s3 = new S3Client({});
    const body = JSON.parse(result.body);
    for (const [key, localPath] of [['json', body.jsonReportPath], ['html', body.htmlReportPath]]) {
      if (localPath && fs.existsSync(localPath)) {
        await s3.send(new PutObjectCommand({
          Bucket: bucket,
          Key: `compliance-reports/${path.basename(localPath)}`,
          Body: fs.readFileSync(localPath),
          ContentType: key === 'json' ? 'application/json' : 'text/html',
        }));
      }
    }
  }
  return result;
};
