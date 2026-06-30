'use strict';
/**
 * server.js
 * Minimal dependency-free HTTP server exposing:
 *   GET  /healthz          - liveness/readiness probe (for ALB/K8s)
 *   GET  /                 - latest HTML report (or status page if none yet)
 *   GET  /api/findings     - latest findings as JSON
 *   GET  /api/score        - latest compliance score
 *   POST /api/scan         - trigger an on-demand scan
 *
 * No Express dependency needed — keeps the container image small.
 */

const http = require('http');
const fs = require('fs');
const url = require('url');

function startServer(agent) {
  const port = process.env.PORT || 8080;

  const server = http.createServer(async (req, res) => {
    const parsed = url.parse(req.url, true);

    try {
      if (parsed.pathname === '/healthz' && req.method === 'GET') {
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ status: 'ok', uptime: process.uptime(), lastScan: agent.lastReport?.findings ? new Date().toISOString() : null }));
        return;
      }

      if (parsed.pathname === '/api/findings' && req.method === 'GET') {
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify(agent.lastFindings || []));
        return;
      }

      if (parsed.pathname === '/api/score' && req.method === 'GET') {
        const a = agent.lastReport?.analysis;
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({
          score: a?.score ?? null,
          severityCounts: a?.severityCounts ?? null,
          complianceRisk: a?.complianceRisk ?? null,
        }));
        return;
      }

      if (parsed.pathname === '/api/scan' && req.method === 'POST') {
        res.writeHead(202, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ status: 'scan_started' }));
        agent.runScan().catch(e => console.error('Triggered scan failed:', e));
        return;
      }

      if (parsed.pathname === '/' && req.method === 'GET') {
        if (agent.lastReport?.html && fs.existsSync(agent.lastReport.html)) {
          res.writeHead(200, { 'Content-Type': 'text/html' });
          fs.createReadStream(agent.lastReport.html).pipe(res);
        } else {
          res.writeHead(200, { 'Content-Type': 'text/html' });
          res.end(`<html><body style="font-family:sans-serif;padding:40px;text-align:center">
            <h2>AWS Compliance Agent</h2>
            <p>No scan has completed yet. POST to /api/scan to trigger one, or wait for the scheduled scan.</p>
          </body></html>`);
        }
        return;
      }

      res.writeHead(404, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'not_found' }));
    } catch (e) {
      res.writeHead(500, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: e.message }));
    }
  });

  server.listen(port, () => {
    console.log(`🌐 HTTP server listening on :${port}  (/, /healthz, /api/findings, /api/score, /api/scan)`);
  });

  return server;
}

module.exports = { startServer };
