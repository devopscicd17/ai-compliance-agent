'use strict';
/**
 * agent.js
 * Main orchestrator for the Agentic AWS Compliance Agent.
 *
 * Modes:
 *   --mode=scan    Run one full scan, generate report, exit
 *   --mode=watch   Continuous monitoring loop (for containers/ECS/K8s)
 *   --mode=report  Regenerate report from last scan cache
 *   --mode=test    Dry-run against a single region with no AWS calls that mutate state
 *
 * Env vars are documented in .env.example
 */

require('dotenv').config();
const path = require('path');
const fs = require('fs');
const { Command } = require('commander');

const { getClientsForAccount, getCurrentAccountId } = require('./aws/client');
const S3Scanner = require('./scanners/s3-scanner');
const IAMScanner = require('./scanners/iam-scanner');
const EC2Scanner = require('./scanners/ec2-scanner');
const RDSScanner = require('./scanners/rds-scanner');
const { CloudTrailScanner, KMSScanner } = require('./scanners/cloudtrail-kms-scanner');
const AIRemediationEngine = require('./utils/ai-remediation');
const ReportGenerator = require('./reporters/report-generator');
const Remediator = require('./utils/remediator');
const Notifier = require('./utils/notifier');
const { startServer } = require('./server');

const FRAMEWORK_MAP = { FEDRAMP: 'FEDRAMP', CIS: 'CIS', NIST: 'NIST', PCI: 'PCI', CUSTOM: 'CUSTOM' };

class ComplianceAgent {
  constructor(opts = {}) {
    this.opts = opts;
    this.activeFrameworks = (process.env.ACTIVE_FRAMEWORKS || 'FEDRAMP,CIS,NIST')
      .split(',').map(f => f.trim().toUpperCase());
    this.targetAccounts = (process.env.AWS_TARGET_ACCOUNTS || '').split(',').map(s => s.trim()).filter(Boolean);
    this.region = process.env.AWS_REGION || 'us-east-1';
    this.ai = new AIRemediationEngine();
    this.reportGen = new ReportGenerator(process.env.REPORT_OUTPUT_DIR || './reports');
    this.remediator = new Remediator();
    this.notifier = new Notifier();
    this.lastFindings = [];
    this.lastReport = null;
  }

  async runScan() {
    const startedAt = Date.now();
    console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
    console.log('  AWS Agentic Compliance Scan — starting');
    console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');

    const accounts = this.targetAccounts.length ? this.targetAccounts : [null]; // null = current account
    let allFindings = [];
    let primaryAccountId = null;

    for (const accountId of accounts) {
      const identity = accountId
        ? { accountId }
        : await getCurrentAccountId(this.region);
      primaryAccountId = primaryAccountId || identity.accountId;

      console.log(`\n▶ Scanning account: ${identity.accountId}`);
      const clients = await getClientsForAccount(accountId, this.region);

      const scanners = [
        new S3Scanner(clients, identity.accountId, this.region),
        new IAMScanner(clients, identity.accountId, this.region),
        new EC2Scanner(clients, identity.accountId, this.region),
        new RDSScanner(clients, identity.accountId, this.region),
        new CloudTrailScanner(clients, identity.accountId, this.region),
        new KMSScanner(clients, identity.accountId, this.region),
      ];

      for (const scanner of scanners) {
        try {
          const findings = await scanner.scan();
          allFindings.push(...findings);
        } catch (e) {
          console.error(`  ✗ Scanner error [${scanner.constructor.name}]:`, e.message);
        }
      }
    }

    // Filter by active frameworks
    allFindings = allFindings.filter(f =>
      f.controls.some(c => this.activeFrameworks.includes(c.framework))
    );

    console.log(`\n✓ Scan complete: ${allFindings.length} findings across ${accounts.length} account(s) in ${Math.round((Date.now() - startedAt) / 1000)}s`);

    this.lastFindings = allFindings;

    // AI analysis
    console.log('\n▶ Running AI-powered risk analysis...');
    const aiAnalysis = await this.ai.analyzeAndPrioritize(allFindings);
    const execReport = await this.ai.generateExecutiveReport(allFindings, primaryAccountId, this.activeFrameworks);
    const merged = { ...aiAnalysis, ...execReport };

    // Generate reports
    console.log('\n▶ Generating reports...');
    const files = this.reportGen.generateAll(allFindings, merged, primaryAccountId, this.activeFrameworks);
    this.lastReport = { ...files, findings: allFindings, analysis: merged, accountId: primaryAccountId };
    console.log(`  ✓ JSON report: ${files.json}`);
    console.log(`  ✓ HTML report: ${files.html}`);

    // Notify
    if (merged.severityCounts?.CRITICAL > 0) {
      await this.notifier.notifyCritical(merged.severityCounts.CRITICAL, primaryAccountId, files.html);
    }

    // Auto-remediation
    const threshold = process.env.AUTO_REMEDIATE_THRESHOLD || 'CRITICAL';
    const mode = process.env.REMEDIATION_MODE || 'DRY_RUN';
    if (mode !== 'OFF') {
      console.log(`\n▶ Auto-remediation pass (mode=${mode}, threshold=${threshold})...`);
      const toFix = allFindings.filter(f =>
        f.remediation?.automated &&
        f.remediation?.risk === 'LOW' &&
        this._meetsThreshold(f.severity, threshold)
      );
      for (const f of toFix) {
        await this.remediator.remediate(f, mode === 'ACTIVE');
      }
      console.log(`  ✓ ${toFix.length} findings ${mode === 'ACTIVE' ? 'remediated' : 'would be remediated (dry-run)'}`);
    }

    console.log('\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
    console.log(`  Compliance Score: ${merged.score}/100`);
    console.log(`  Critical: ${merged.severityCounts.CRITICAL} | High: ${merged.severityCounts.HIGH} | Medium: ${merged.severityCounts.MEDIUM} | Low: ${merged.severityCounts.LOW}`);
    console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n');

    return this.lastReport;
  }

  _meetsThreshold(severity, threshold) {
    const order = { CRITICAL: 4, HIGH: 3, MEDIUM: 2, LOW: 1 };
    return order[severity] >= order[threshold];
  }

  async runWatch() {
    const intervalMin = parseInt(process.env.SCAN_INTERVAL_MINUTES || '60', 10);
    console.log(`👁  Watch mode active — scanning every ${intervalMin} minutes`);
    await this.runScan().catch(e => console.error('Scan error:', e));
    setInterval(() => {
      this.runScan().catch(e => console.error('Scan error:', e));
    }, intervalMin * 60 * 1000);

    // Also start the HTTP API/dashboard server so the agent is operable in a container
    if (process.env.ENABLE_HTTP_SERVER !== 'false') {
      startServer(this);
    }
  }
}

// ─── CLI entrypoint ─────────────────────────────────────────────────────────

async function main() {
  const program = new Command();
  program
    .option('--mode <mode>', 'scan | watch | report | test', 'scan')
    .option('--dry-run', 'do not apply any remediation', false)
    .parse(process.argv);

  const opts = program.opts();
  if (opts.dryRun) process.env.REMEDIATION_MODE = 'DRY_RUN';

  const agent = new ComplianceAgent(opts);

  switch (opts.mode) {
    case 'watch':
      await agent.runWatch();
      break;
    case 'report':
      if (!agent.lastFindings.length) {
        console.log('No cached findings — running a fresh scan first.');
      }
      await agent.runScan();
      break;
    case 'test':
      console.log('Test mode: validating AWS credentials and connectivity...');
      try {
        const id = await getCurrentAccountId(agent.region);
        console.log('✓ AWS credentials valid:', id);
      } catch (e) {
        console.error('✗ AWS credential check failed:', e.message);
        process.exit(1);
      }
      break;
    default:
      await agent.runScan();
      if (process.env.ENABLE_HTTP_SERVER === 'true') startServer(agent);
  }
}

if (require.main === module) {
  main().catch(e => {
    console.error('Fatal error:', e);
    process.exit(1);
  });
}

module.exports = { ComplianceAgent };
