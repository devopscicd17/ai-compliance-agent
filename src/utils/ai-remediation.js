'use strict';
/**
 * ai-remediation.js
 * Uses Claude (claude-sonnet-4-6) to:
 *   1. Analyze findings and prioritize by business risk
 *   2. Generate safe, production-ready remediation scripts
 *   3. Detect false positives
 *   4. Explain findings in plain English for executives
 */

const Anthropic = require('@anthropic-ai/sdk');

class AIRemediationEngine {
  constructor() {
    this.client = new Anthropic({ apiKey: process.env.ANTHROPIC_API_KEY });
    this.model = 'claude-sonnet-4-6';
  }

  async analyzeAndPrioritize(findings) {
    if (!findings.length) return { prioritized: [], executiveSummary: 'No findings to analyze.' };

    const input = findings.map(f => ({
      id: f.id,
      service: f.service,
      short: f.short,
      severity: f.severity,
      controls: f.controls.map(c => `${c.framework} ${c.id}`),
      resource: f.resourceName,
    }));

    const prompt = `You are an AWS security expert analyzing compliance findings for a cloud environment.

Here are the compliance findings (JSON):
${JSON.stringify(input, null, 2)}

Please respond with a JSON object (no markdown, no backticks) with exactly this structure:
{
  "prioritizedIds": ["finding_id_1", "finding_id_2"],
  "executiveSummary": "2-3 paragraph plain English summary for non-technical executives",
  "topRisks": [
    {"id": "finding_id", "businessImpact": "one sentence business impact description"}
  ],
  "quickWins": ["finding_id_1", "finding_id_2"],
  "complianceRisk": "overall compliance risk level: CRITICAL/HIGH/MEDIUM/LOW"
}

Prioritize by: business impact, exploitability, blast radius, and compliance requirement severity.
Quick wins = automated=true AND risk=LOW findings that can be fixed immediately.`;

    try {
      const msg = await this.client.messages.create({
        model: this.model,
        max_tokens: 2000,
        messages: [{ role: 'user', content: prompt }],
      });

      const text = msg.content[0].text.trim();
      const parsed = JSON.parse(text);
      return parsed;
    } catch (e) {
      console.warn('AI analysis failed:', e.message);
      return {
        prioritizedIds: findings.map(f => f.id),
        executiveSummary: `${findings.length} compliance findings were identified across your AWS environment. ${findings.filter(f => f.severity === 'CRITICAL').length} are critical severity and require immediate attention.`,
        topRisks: findings.filter(f => f.severity === 'CRITICAL').slice(0, 3).map(f => ({
          id: f.id,
          businessImpact: `Critical compliance violation on ${f.service} resource.`,
        })),
        quickWins: findings.filter(f => f.remediation?.automated && f.remediation?.risk === 'LOW').map(f => f.id),
        complianceRisk: findings.some(f => f.severity === 'CRITICAL') ? 'CRITICAL' : 'HIGH',
      };
    }
  }

  async generateRemediationScript(finding) {
    const prompt = `You are an AWS security engineer. Generate a safe, production-ready remediation for this compliance finding.

Finding:
- Resource: ${finding.resource}
- Issue: ${finding.short}
- Description: ${finding.description}
- Service: ${finding.service}
- Severity: ${finding.severity}
- Controls: ${finding.controls.map(c => `${c.framework} ${c.id}`).join(', ')}
- Current state: ${JSON.stringify(finding.current)}
- Expected state: ${JSON.stringify(finding.expected)}

Existing manual steps provided:
${(finding.remediation?.manual || []).join('\n')}

Respond with a JSON object (no markdown, no backticks):
{
  "shellScript": "complete bash script with safety checks, error handling, and --dry-run support",
  "terraformSnippet": "HCL terraform resource or data source if applicable, else null",
  "riskAssessment": "1-2 sentences on what could go wrong if applied",
  "preflightChecks": ["check1", "check2"],
  "rollbackProcedure": "how to undo this change",
  "estimatedDowntime": "none/seconds/minutes/requires maintenance window"
}`;

    try {
      const msg = await this.client.messages.create({
        model: this.model,
        max_tokens: 2000,
        messages: [{ role: 'user', content: prompt }],
      });

      const text = msg.content[0].text.trim();
      return JSON.parse(text);
    } catch (e) {
      return {
        shellScript: (finding.remediation?.manual || []).join('\n'),
        terraformSnippet: null,
        riskAssessment: 'Review manually before applying.',
        preflightChecks: ['Verify resource exists', 'Check for dependencies'],
        rollbackProcedure: 'Revert to previous configuration manually.',
        estimatedDowntime: 'Unknown',
      };
    }
  }

  async generateExecutiveReport(findings, accountId, frameworks) {
    const severityCounts = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 };
    const byService = {};
    const byFramework = {};

    for (const f of findings) {
      severityCounts[f.severity] = (severityCounts[f.severity] || 0) + 1;
      byService[f.service] = (byService[f.service] || 0) + 1;
      for (const c of f.controls) {
        byFramework[c.framework] = (byFramework[c.framework] || 0) + 1;
      }
    }

    const score = Math.max(0, Math.round(100 - (severityCounts.CRITICAL * 15 + severityCounts.HIGH * 8 + severityCounts.MEDIUM * 3 + severityCounts.LOW * 1)));

    const prompt = `You are a Chief Information Security Officer writing an executive compliance report for AWS account ${accountId}.

Scan data:
- Total findings: ${findings.length}
- Critical: ${severityCounts.CRITICAL}, High: ${severityCounts.HIGH}, Medium: ${severityCounts.MEDIUM}, Low: ${severityCounts.LOW}
- Compliance score: ${score}/100
- Active frameworks: ${frameworks.join(', ')}
- Services with findings: ${JSON.stringify(byService)}
- Frameworks with violations: ${JSON.stringify(byFramework)}

Top critical findings:
${findings.filter(f => f.severity === 'CRITICAL').slice(0, 5).map(f => `- ${f.short} (${f.service})`).join('\n')}

Write a professional executive summary in 3 paragraphs:
1. Overall risk posture and compliance score interpretation
2. Most significant risks and their business impact  
3. Recommended immediate actions and 30-60-90 day roadmap

Keep it factual, concise, and actionable for a C-suite audience. No markdown headers.`;

    try {
      const msg = await this.client.messages.create({
        model: this.model,
        max_tokens: 1000,
        messages: [{ role: 'user', content: prompt }],
      });
      return { text: msg.content[0].text.trim(), score, severityCounts, byService, byFramework };
    } catch (e) {
      return {
        text: `AWS account ${accountId} was scanned and ${findings.length} compliance findings were identified. The overall compliance score is ${score}/100. Immediate attention is required for ${severityCounts.CRITICAL} critical findings.`,
        score, severityCounts, byService, byFramework,
      };
    }
  }

  async detectFalsePositives(findings, context) {
    // Basic heuristic false-positive filtering — AI-assisted
    const prompt = `You are reviewing AWS compliance scan results for potential false positives.

Context about this environment: ${context || 'Production AWS account'}

Findings to review:
${JSON.stringify(findings.slice(0, 20).map(f => ({ id: f.id, short: f.short, service: f.service, resource: f.resourceName })), null, 2)}

Identify any findings that are likely false positives or acceptable exceptions based on common patterns.
Respond with JSON (no markdown): { "falsePositiveIds": ["id1"], "rationale": { "id1": "reason" } }
If none, return: { "falsePositiveIds": [], "rationale": {} }`;

    try {
      const msg = await this.client.messages.create({
        model: this.model,
        max_tokens: 800,
        messages: [{ role: 'user', content: prompt }],
      });
      return JSON.parse(msg.content[0].text.trim());
    } catch (e) {
      return { falsePositiveIds: [], rationale: {} };
    }
  }
}

module.exports = AIRemediationEngine;
