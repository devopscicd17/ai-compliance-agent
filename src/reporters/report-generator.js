'use strict';
/**
 * report-generator.js
 * Generates HTML, JSON, and PDF-ready compliance reports.
 */

const fs = require('fs');
const path = require('path');

const SEVERITY_COLOR = { CRITICAL: '#a32d2d', HIGH: '#993c1d', MEDIUM: '#854f0b', LOW: '#3b6d11' };
const SEVERITY_BG = { CRITICAL: '#fcebeb', HIGH: '#faece7', MEDIUM: '#faeeda', LOW: '#eaf3de' };
const STATUS_ICON = { OPEN: '⚠', FIXED: '✓', REMEDIATING: '⟳', SUPPRESSED: '—' };

class ReportGenerator {
  constructor(outputDir) {
    this.outputDir = outputDir || './reports';
    fs.mkdirSync(this.outputDir, { recursive: true });
  }

  generateAll(findings, aiAnalysis, accountId, frameworks, options = {}) {
    const ts = new Date().toISOString().replace(/[:.]/g, '-').slice(0, 19);
    const baseFile = path.join(this.outputDir, `compliance-report-${accountId}-${ts}`);

    const jsonFile = this._generateJSON(findings, aiAnalysis, accountId, frameworks, baseFile);
    const htmlFile = this._generateHTML(findings, aiAnalysis, accountId, frameworks, baseFile);

    return { json: jsonFile, html: htmlFile };
  }

  _generateJSON(findings, aiAnalysis, accountId, frameworks, baseFile) {
    const file = baseFile + '.json';
    const severityCounts = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 };
    findings.forEach(f => { severityCounts[f.severity] = (severityCounts[f.severity] || 0) + 1; });

    const report = {
      reportMetadata: {
        generatedAt: new Date().toISOString(),
        accountId,
        frameworks,
        totalFindings: findings.length,
        complianceScore: aiAnalysis?.score ?? 0,
        severitySummary: severityCounts,
      },
      executiveSummary: aiAnalysis?.text || '',
      aiAnalysis: {
        complianceRisk: aiAnalysis?.complianceRisk,
        topRisks: aiAnalysis?.topRisks || [],
        quickWins: aiAnalysis?.quickWins || [],
      },
      findings: findings.map(f => ({
        id: f.id,
        service: f.service,
        severity: f.severity,
        status: f.status,
        resourceName: f.resourceName,
        resource: f.resource,
        short: f.short,
        description: f.description,
        controls: f.controls,
        remediationSteps: f.remediation?.manual || [],
        automatedFixAvailable: f.remediation?.automated || false,
        remediationRisk: f.remediation?.risk || 'UNKNOWN',
        current: f.current,
        expected: f.expected,
        timestamp: f.timestamp,
        accountId: f.accountId,
      })),
    };

    fs.writeFileSync(file, JSON.stringify(report, null, 2));
    return file;
  }

  _generateHTML(findings, aiAnalysis, accountId, frameworks, baseFile) {
    const file = baseFile + '.html';
    const now = new Date();
    const score = aiAnalysis?.score ?? 0;
    const scoreColor = score >= 80 ? '#3b6d11' : score >= 60 ? '#ba7517' : '#a32d2d';
    const severityCounts = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 };
    findings.forEach(f => { severityCounts[f.severity] = (severityCounts[f.severity] || 0) + 1; });

    const byService = {};
    const byFramework = {};
    findings.forEach(f => {
      byService[f.service] = (byService[f.service] || 0) + 1;
      f.controls.forEach(c => { byFramework[c.framework] = (byFramework[c.framework] || 0) + 1; });
    });

    const findingsTableRows = findings.map(f => {
      const controls = f.controls.map(c => `<span class="tag">${c.framework} ${c.id}</span>`).join(' ');
      const steps = (f.remediation?.manual || []).map(s => `<li>${this._escHtml(s)}</li>`).join('');
      const auto = f.remediation?.automated
        ? `<span class="badge badge-ok">Auto-fix available</span>`
        : `<span class="badge badge-manual">Manual</span>`;

      return `
      <tr>
        <td><span class="sev-badge" style="background:${SEVERITY_BG[f.severity]};color:${SEVERITY_COLOR[f.severity]}">${f.severity}</span></td>
        <td class="resource">${this._escHtml(f.resourceName || '')}</td>
        <td>${this._escHtml(f.short)}</td>
        <td>${controls}</td>
        <td>${auto}</td>
        <td>
          <details>
            <summary style="cursor:pointer;font-size:12px;color:#185fa5">Steps ▸</summary>
            <ol style="font-size:12px;margin:6px 0 0 16px;line-height:1.6">${steps}</ol>
          </details>
        </td>
      </tr>`;
    }).join('');

    const serviceRows = Object.entries(byService).sort((a, b) => b[1] - a[1])
      .map(([s, n]) => `<tr><td>${s}</td><td>${n}</td><td style="width:150px"><div style="height:8px;background:#e24b4a;border-radius:4px;width:${Math.min(100, n * 8)}%"></div></td></tr>`).join('');

    const html = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>AWS Compliance Report — ${accountId}</title>
<style>
  *{box-sizing:border-box;margin:0;padding:0}
  body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;font-size:14px;color:#1a1a1a;background:#f7f6f3;line-height:1.6}
  .page{max-width:1100px;margin:0 auto;padding:32px 24px}
  .header{background:#0c447c;color:white;border-radius:12px;padding:32px 36px;margin-bottom:28px;display:flex;justify-content:space-between;align-items:flex-start}
  .header h1{font-size:24px;font-weight:600;margin-bottom:4px}
  .header .meta{font-size:13px;opacity:.75}
  .score-circle{width:80px;height:80px;border-radius:50%;background:white;display:flex;flex-direction:column;align-items:center;justify-content:center;flex-shrink:0}
  .score-num{font-size:24px;font-weight:700;color:${scoreColor}}
  .score-label{font-size:10px;color:#555;margin-top:-2px}
  .cards{display:grid;grid-template-columns:repeat(4,1fr);gap:14px;margin-bottom:28px}
  .card{background:white;border-radius:10px;padding:18px 20px;border:1px solid #e8e6e0}
  .card-label{font-size:12px;color:#666;margin-bottom:4px}
  .card-value{font-size:26px;font-weight:600}
  .section{background:white;border-radius:10px;border:1px solid #e8e6e0;padding:24px;margin-bottom:24px}
  .section h2{font-size:16px;font-weight:600;margin-bottom:16px;padding-bottom:10px;border-bottom:1px solid #f0ede8}
  .exec-summary{font-size:14px;line-height:1.8;color:#333}
  table{width:100%;border-collapse:collapse}
  th{text-align:left;font-size:12px;font-weight:600;color:#666;padding:8px 10px;border-bottom:2px solid #f0ede8}
  td{padding:10px 10px;border-bottom:1px solid #f5f3ef;vertical-align:top;font-size:13px}
  tr:hover td{background:#fdfcfb}
  .sev-badge{display:inline-block;padding:3px 9px;border-radius:20px;font-size:11px;font-weight:600}
  .resource{font-family:monospace;font-size:11px;color:#444;max-width:200px;word-break:break-all}
  .tag{display:inline-block;background:#f0ede8;color:#555;border-radius:4px;font-size:10px;padding:1px 5px;margin:1px;white-space:nowrap}
  .badge{display:inline-block;padding:2px 8px;border-radius:20px;font-size:10px;font-weight:500}
  .badge-ok{background:#eaf3de;color:#27500a}
  .badge-manual{background:#f0ede8;color:#666}
  .fw-pills{display:flex;gap:8px;flex-wrap:wrap;margin-bottom:16px}
  .fw-pill{background:#e6f1fb;color:#0c447c;border:1px solid #b5d4f4;border-radius:20px;padding:4px 14px;font-size:12px;font-weight:500}
  .footer{text-align:center;font-size:12px;color:#999;margin-top:32px;padding-top:16px;border-top:1px solid #e8e6e0}
  @media print{body{background:white}.header{-webkit-print-color-adjust:exact;print-color-adjust:exact}}
  @media(max-width:700px){.cards{grid-template-columns:repeat(2,1fr)}.header{flex-direction:column;gap:16px}}
</style>
</head>
<body>
<div class="page">

  <div class="header">
    <div>
      <h1>AWS Compliance Report</h1>
      <div class="meta">Account: ${accountId} &nbsp;|&nbsp; Generated: ${now.toLocaleString()} &nbsp;|&nbsp; Frameworks: ${frameworks.join(', ')}</div>
    </div>
    <div class="score-circle">
      <div class="score-num">${score}</div>
      <div class="score-label">/ 100</div>
    </div>
  </div>

  <div class="cards">
    <div class="card"><div class="card-label">Critical</div><div class="card-value" style="color:#a32d2d">${severityCounts.CRITICAL}</div></div>
    <div class="card"><div class="card-label">High</div><div class="card-value" style="color:#993c1d">${severityCounts.HIGH}</div></div>
    <div class="card"><div class="card-label">Medium</div><div class="card-value" style="color:#854f0b">${severityCounts.MEDIUM}</div></div>
    <div class="card"><div class="card-label">Low</div><div class="card-value" style="color:#3b6d11">${severityCounts.LOW}</div></div>
  </div>

  <div class="section">
    <h2>Active Frameworks</h2>
    <div class="fw-pills">
      ${frameworks.map(f => `<span class="fw-pill">${f}</span>`).join('')}
    </div>
    <table>
      <thead><tr><th>Framework</th><th>Violations</th></tr></thead>
      <tbody>
        ${Object.entries(byFramework).sort((a,b)=>b[1]-a[1]).map(([fw,n])=>`<tr><td>${fw}</td><td>${n}</td></tr>`).join('')}
      </tbody>
    </table>
  </div>

  <div class="section">
    <h2>Executive Summary</h2>
    <div class="exec-summary">${(aiAnalysis?.text || '').split('\n\n').map(p => `<p style="margin-bottom:12px">${this._escHtml(p)}</p>`).join('')}</div>
  </div>

  ${(aiAnalysis?.topRisks?.length) ? `
  <div class="section">
    <h2>Top Business Risks (AI Analysis)</h2>
    <ul style="list-style:none;display:flex;flex-direction:column;gap:10px">
      ${(aiAnalysis.topRisks || []).slice(0,5).map(r => {
        const f = findings.find(x => x.id === r.id);
        return f ? `<li style="display:flex;gap:12px;align-items:flex-start;padding:10px;background:#fafaf8;border-radius:8px;border:1px solid #f0ede8">
          <span class="sev-badge" style="background:${SEVERITY_BG[f.severity]};color:${SEVERITY_COLOR[f.severity]};flex-shrink:0">${f.severity}</span>
          <div><strong style="font-size:13px">${this._escHtml(f.short)}</strong><br><span style="font-size:12px;color:#555">${this._escHtml(r.businessImpact)}</span></div>
        </li>` : '';
      }).join('')}
    </ul>
  </div>` : ''}

  <div class="section">
    <h2>Findings by Service</h2>
    <table>
      <thead><tr><th>Service</th><th>Findings</th><th>Distribution</th></tr></thead>
      <tbody>${serviceRows}</tbody>
    </table>
  </div>

  <div class="section">
    <h2>All Findings (${findings.length})</h2>
    <table>
      <thead>
        <tr>
          <th>Severity</th>
          <th>Resource</th>
          <th>Finding</th>
          <th>Controls</th>
          <th>Fix</th>
          <th>Remediation</th>
        </tr>
      </thead>
      <tbody>${findingsTableRows}</tbody>
    </table>
  </div>

  <div class="footer">
    AWS Compliance Agent &nbsp;·&nbsp; Powered by Claude &nbsp;·&nbsp; ${now.toUTCString()}
  </div>

</div>
</body>
</html>`;

    fs.writeFileSync(file, html);
    return file;
  }

  _escHtml(s) {
    return String(s || '').replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
  }
}

module.exports = ReportGenerator;
