/**
 * AirLock Scanner — HTTP API Server
 * Exposes scan() as a REST endpoint for Cloud Run deployment.
 */

import { createServer } from 'http';
import { scan } from './agent-wrapper.js';

const PORT = process.env.PORT || 8080;

// In-memory request count for status
let requestCount = 0;
const startTime = Date.now();

// ── Middleware ──────────────────────────────────────────────

function jsonBody(req, res) {
  const ct = req.headers['content-type'] || '';
  if (!ct.includes('application/json')) {
    res.writeHead(415, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ error: 'Content-Type must be application/json' }));
    return null;
  }
  return '';
}

function authMiddleware(req, res) {
  const apiKey = process.env.AIRLOCK_API_KEY;
  if (!apiKey) return null; // No key configured — allow all

  const header = req.headers['authorization'] || '';
  const token = header.replace(/^Bearer\s+/i, '').trim();

  if (!token || token !== apiKey) {
    res.writeHead(401, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ error: 'Unauthorized — valid API key required' }));
    return false;
  }
  return null;
}

function corsMiddleware(res) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
}

// ── Routes ─────────────────────────────────────────────────

const routes = {
  'GET /health': healthHandler,
  'GET /status': statusHandler,
  'GET /': rootHandler,
  'POST /scan': scanHandler,
};

// ── Request Parser ─────────────────────────────────────────

function parseBody(req) {
  return new Promise((resolve, reject) => {
    let body = '';
    req.on('data', chunk => body += chunk);
    req.on('end', () => {
      try { resolve(body ? JSON.parse(body) : {}); }
      catch { reject(new Error('Invalid JSON')); }
    });
    req.on('error', reject);
  });
}

// ── Handlers ───────────────────────────────────────────────

function healthHandler(req, res, params, query) {
  res.writeHead(200, { 'Content-Type': 'application/json' });
  res.end(JSON.stringify({ status: 'ok', service: 'airlock-scanner' }));
}

function statusHandler(req, res, params, query) {
  res.writeHead(200, { 'Content-Type': 'application/json' });
  res.end(JSON.stringify({
    status: 'ok',
    uptime_seconds: Math.floor((Date.now() - startTime) / 1000),
    request_count: requestCount,
    version: '0.1.0'
  }));
}

function rootHandler(req, res, params, query) {
  res.writeHead(200, { 'Content-Type': 'application/json' });
  res.end(JSON.stringify({
    name: 'TheAgentDeck AirLock Scanner',
    version: '0.1.0',
    docs: 'POST /scan',
    health: 'GET /health'
  }));
}

async function scanHandler(req, res, params, query) {
  requestCount++;
  const authError = authMiddleware(req, res);
  if (authError !== null) return;

  let body;
  try {
    body = await parseBody(req);
  } catch (err) {
    res.writeHead(400, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ error: 'Invalid JSON body' }));
    return;
  }

  const { url, agent, mission, mode, memoryWrite } = body;

  if (!url) {
    res.writeHead(400, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ error: 'url is required' }));
    return;
  }

  // Input validation
  const parsedUrl = (() => {
    try { return new URL(url); }
    catch { return null; }
  })();
  if (!parsedUrl || !['http:', 'https:'].includes(parsedUrl.protocol)) {
    res.writeHead(400, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ error: 'url must be a valid http or https URL' }));
    return;
  }

  const startMs = Date.now();
  try {
    const result = await scan({
      url,
      agent: agent || 'api',
      mission: mission || 'api-scan',
      mode: mode || 'read',
      memoryWrite: memoryWrite !== undefined ? Boolean(memoryWrite) : false,
    });

    const elapsed = Date.now() - startMs;
    const packet = result.packet;

    res.writeHead(200, {
      'Content-Type': 'application/json',
      'X-AirLock-Version': '0.1.0',
      'X-Scan-Id': packet.scan_id,
      'X-Process-Ms': elapsed.toString(),
    });
    res.end(JSON.stringify({
      ok: true,
      packet,
      meta: {
        scan_id: packet.scan_id,
        page_risk: packet.page_risk,
        trust_level: packet.trust_level,
        process_ms: elapsed,
        packet_hash: packet.packet_hash,
      }
    }));
  } catch (err) {
    console.error(`Scan failed for ${url}:`, err.message);
    res.writeHead(500, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({
      ok: false,
      error: 'Scan failed',
      detail: err.message,
      url,
    }));
  }
}

// ── 404 Handler ───────────────────────────────────────────

function notFoundHandler(req, res) {
  res.writeHead(404, { 'Content-Type': 'application/json' });
  res.end(JSON.stringify({ error: 'Not found', path: req.url }));
}

// ── Router ─────────────────────────────────────────────────

function route(req, res) {
  corsMiddleware(res);
  if (req.method === 'OPTIONS') {
    res.writeHead(204);
    res.end();
    return;
  }

  const method = req.method;
  const pathname = req.url.split('?')[0];

  // Find matching route
  let handler = null;
  for (const [routeKey, h] of Object.entries(routes)) {
    const [m, path] = routeKey.split(' ');
    if (m !== method) continue;

    // Exact match
    if (path === pathname) { handler = h; break; }

    // Pattern match (e.g., /scan matches POST /scan)
    const pathParts = path.split('/').filter(Boolean);
    const urlParts = pathname.split('/').filter(Boolean);
    if (pathParts.length !== urlParts.length) continue;

    const matches = pathParts.every((part, i) =>
      part.startsWith(':') || part === urlParts[i]
    );
    if (matches) { handler = h; break; }
  }

  if (handler) {
    handler(req, res);
  } else {
    notFoundHandler(req, res);
  }
}

// ── Start ──────────────────────────────────────────────────

const server = createServer(route);

server.listen(PORT, () => {
  console.log(`TheAgentDeck AirLock Scanner running on port ${PORT}`);
  console.log(`Health: GET /health`);
  console.log(`Scan:   POST /scan with {"url": "https://..."}`);
  if (process.env.AIRLOCK_API_KEY) {
    console.log(`API key: REQUIRED (Bearer token)`);
  } else {
    console.log(`API key: NOT CONFIGURED — allowing all requests`);
  }
});