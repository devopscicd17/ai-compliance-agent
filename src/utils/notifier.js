'use strict';
/**
 * notifier.js
 * Sends critical-finding alerts via SNS and/or Slack webhook.
 */

const { SNSClient, PublishCommand } = require('@aws-sdk/client-sns');
const { baseConfig } = require('../aws/client');
const https = require('https');
const { URL } = require('url');

class Notifier {
  constructor() {
    this.snsTopicArn = process.env.SNS_TOPIC_ARN;
    this.slackWebhook = process.env.SLACK_WEBHOOK_URL;
  }

  async notifyCritical(criticalCount, accountId, reportUrl) {
    const message = `🚨 AWS Compliance Alert\n\nAccount: ${accountId}\nCritical findings: ${criticalCount}\nReport: ${reportUrl}\n\nImmediate review recommended.`;

    await Promise.allSettled([
      this._sendSNS(message, accountId, criticalCount),
      this._sendSlack(message, accountId, criticalCount),
    ]);
  }

  async _sendSNS(message, accountId, criticalCount) {
    if (!this.snsTopicArn) return;
    try {
      const sns = new SNSClient(baseConfig());
      await sns.send(new PublishCommand({
        TopicArn: this.snsTopicArn,
        Subject: `[CRITICAL] AWS Compliance Alert — ${accountId}`,
        Message: message,
      }));
      console.log('  ✓ SNS notification sent');
    } catch (e) {
      console.warn('  ⚠ SNS notification failed:', e.message);
    }
  }

  async _sendSlack(message, accountId, criticalCount) {
    if (!this.slackWebhook) return;
    try {
      await this._postJson(this.slackWebhook, {
        text: message,
        blocks: [
          {
            type: 'section',
            text: { type: 'mrkdwn', text: `*🚨 AWS Compliance Alert*\n*Account:* ${accountId}\n*Critical findings:* ${criticalCount}` },
          },
        ],
      });
      console.log('  ✓ Slack notification sent');
    } catch (e) {
      console.warn('  ⚠ Slack notification failed:', e.message);
    }
  }

  _postJson(urlStr, body) {
    return new Promise((resolve, reject) => {
      const url = new URL(urlStr);
      const data = JSON.stringify(body);
      const req = https.request({
        hostname: url.hostname,
        path: url.pathname + url.search,
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(data) },
      }, (res) => {
        res.on('data', () => {});
        res.on('end', () => resolve(res.statusCode));
      });
      req.on('error', reject);
      req.write(data);
      req.end();
    });
  }
}

module.exports = Notifier;
