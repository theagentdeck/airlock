/**
 * AirLock Fetcher
 * Server-side fetch with publisher discovery, redirect chain logging,
 * robots.txt honoring, and signature verification fallback.
 */

import axios from 'axios';
import * as crypto from 'crypto';
import { readFileSync } from 'fs';
import { resolve, dirname } from 'path';
import { fileURLToPath } from 'url';

const __dirname = dirname(fileURLToPath(import.meta.url));

const AIRLOCK_UA = 'TheAgentDeck-AirLock/1.0 (+https://airlock.codes)';
const FETCH_TIMEOUT_MS = 15000;
const MAX_REDIRECTS = 5;

// ── SSRF Protection ─────────────────────────────────────────────────────────

/** Blocked IP ranges (SSRF protection) */
const SSRF_BLOCKED_RANGES = [
  { pattern: '127.0.0.0/8' },
  { pattern: '10.0.0.0/8' },
  { pattern: '172.16.0.0/12' },
  { pattern: '192.168.0.0/16' },
  { pattern: '169.254.0.0/16' },
  { pattern: '::1' },
  { pattern: 'fc00::/7' },
  { pattern: '0.0.0.0/8' },
];

/** Cloud metadata IP ranges */
const METADATA_IP_RANGES = ['169.254.169.254', 'metadata.google.internal'];

// Minimal DNS resolver — blocks internal hostnames, checks final resolved IPs
async function resolveAndValidateUrl(rawUrl) {
  const parsed = new URL(rawUrl);

  // Reject non-http schemes
  if (!['http:', 'https:'].includes(parsed.protocol)) {
    throw new Error(`AirLock: only http/https supported, got ${parsed.protocol}`);
  }

  const hostname = parsed.hostname;

  // Reject obviously internal hostnames
  if (METADATA_IP_RANGES.includes(hostname)) {
    throw new Error(`AirLock: blocked metadata endpoint ${hostname}`);
  }

  // Block numeric IP literals in blocked ranges
  const numericIp = /^\d+\.\d+\.\d+\.\d+$/.test(hostname);
  if (numericIp && isBlockedIP(hostname)) {
    throw new Error(`AirLock: blocked private/reserved IP ${hostname}`);
  }

  // For DNS names, do a lookup and validate all returned IPs
  if (!numericIp) {
    try {
      const { Resolver } = await import('dns');
      const resolver = new Resolver({ timeout: 3000 });
      const addresses = await resolver.resolve4(hostname).catch(() => []);
      for (const addr of addresses) {
        if (isBlockedIP(addr)) {
          throw new Error(`AirLock: DNS resolution of ${hostname} resolves to blocked IP ${addr}`);
        }
      }
    } catch (err) {
      // ENOTFOUND or other DNS failure — let axios try anyway, it will fail naturally
      if (err.message.startsWith('AirLock:')) throw err;
    }
  }

  return parsed.href;
}

function isBlockedIP(ip) {
  // Simple check — check octets against known private ranges
  const octets = ip.split('.').map(Number);
  if (octets.length !== 4) return false;

  const [a, b, c, d] = octets;

  // 127.x.x.x
  if (a === 127) return true;
  // 10.x.x.x
  if (a === 10) return true;
  // 172.16–31.x.x
  if (a === 172 && b >= 16 && b <= 31) return true;
  // 192.168.x.x
  if (a === 192 && b === 168) return true;
  // 169.254.x.x (link-local)
  if (a === 169 && b === 254) return true;
  // 0.x.x.x
  if (a === 0) return true;

  return false;
}

// ── Fetcher ─────────────────────────────────────────────────────────────────

/**
 * Fetch a URL, checking for publisher discovery metadata but always running
 * the normal scanner path unless the publisher packet is cryptographically verified.
 *
 * @param {string} url
 * @returns {Promise<{html: string, redirectChain: string[], finalUrl: string,
 *   packet_origin: 'scanner'|'publisher', publisherPacket: object|null,
 *   publisherVerified: boolean, discoveryMeta: object|null}>}
 */
export async function fetch(url) {
  // Validate URL before any network call (SSRF protection)
  await resolveAndValidateUrl(url);

  // Step 1: Check discovery metadata — recorded but never bypasses scanning
  const discoveryMeta = await checkPublisherDiscoveryMeta(url);
  // publisherVerified will only be true if Phase 4 signature verification passes
  // For now, always false (Phase 1/2) — discovery is logged but does NOT skip scanning

  // Step 2: Server-side fetch with redirect chain logging
  const redirectChain = [];
  let currentUrl = url;

  // Validate each hop (SSRF check on every redirect target)
  for (let i = 0; i < MAX_REDIRECTS; i++) {
    await resolveAndValidateUrl(currentUrl);

    // Honor robots.txt
    const robotsAllowed = await checkRobotsTxt(currentUrl);
    if (!robotsAllowed) {
      throw new Error(`AirLock: fetch blocked by robots.txt for ${currentUrl}`);
    }

    try {
      const response = await axios.get(currentUrl, {
        headers: {
          'User-Agent': AIRLOCK_UA,
          'Accept': 'text/html,application/xhtml+xml',
        },
        timeout: FETCH_TIMEOUT_MS,
        maxRedirects: 0,
        // Follow redirects manually so we can validate each hop
      });

      // Check for redirect
      const location = response.headers['location'];
      if (location && i < MAX_REDIRECTS - 1) {
        redirectChain.push(currentUrl);
        currentUrl = resolveUrl(currentUrl, location);
        continue;
      }

      // discoveryMeta is recorded but does NOT bypass the scan.
      // packet_origin remains 'scanner' unless a Phase 4 signature is verified.
      return {
        html: response.data,
        redirectChain,
        finalUrl: currentUrl,
        packet_origin: 'scanner', // NEVER 'publisher' unless signature is cryptographically verified
        publisherPacket: null,
        publisherVerified: false,
        discoveryMeta,
      };
    } catch (err) {
      if (err.code === 'ECONNREFUSED' || err.code === 'ENOTFOUND') {
        throw new Error(`AirLock: cannot reach ${currentUrl} — ${err.code}`);
      }
      if (err.response) {
        throw new Error(`AirLock: HTTP ${err.response.status} for ${currentUrl}`);
      }
      throw err;
    }
  }

  throw new Error(`AirLock: exceeded max redirects (${MAX_REDIRECTS}) for ${url}`);
}

/**
 * Check for publisher discovery metadata.
 * Discovery is recorded as context but NEVER bypasses the normal scanner path.
 * Only a cryptographically verified Phase 4 signature can set packet_origin='publisher'.
 *
 * @param {string} url
 * @returns {Promise<{packet: object|null, verified: boolean, source: string}|null>}
 */
async function checkPublisherDiscoveryMeta(url) {
  const parsed = new URL(url);
  const discoveryUrl = `${parsed.protocol}//${parsed.host}/.well-known/airlock.json`;

  try {
    const response = await axios.get(discoveryUrl, {
      headers: { 'User-Agent': AIRLOCK_UA },
      timeout: 5000,
      maxRedirects: 2,
    });

    if (!response.data || response.data.airlock_version !== '1.0') {
      return null;
    }

    // Discovery found — record it as UNVERIFIED metadata.
    // The normal scanner path runs next. The discovery meta is available
    // to the agent wrapper if it wants to include it as context.
    return {
      packet: response.data,
      verified: false, // Phase 4 will implement cryptographic verification
      source: 'discovery',
      url: discoveryUrl,
      discoveredAt: new Date().toISOString(),
    };
  } catch {
    return null;
  }
}

// ── Robots.txt ───────────────────────────────────────────────────────────────

const robotsCache = new Map();

async function checkRobotsTxt(url) {
  const parsed = new URL(url);
  const host = parsed.host;

  if (robotsCache.has(host)) {
    return checkAllow(robotsCache.get(host), parsed.pathname);
  }

  try {
    const robotsUrl = `${parsed.protocol}//${host}/robots.txt`;
    const response = await axios.get(robotsUrl, {
      headers: { 'User-Agent': AIRLOCK_UA },
      timeout: 3000,
    });

    const rules = parseRobotsTxt(response.data);
    robotsCache.set(host, rules);
    return checkAllow(rules, parsed.pathname);
  } catch {
    robotsCache.set(host, { allow: [/.*/], disallow: [] });
    return true;
  }
}

function parseRobotsTxt(body) {
  const allow = [];
  const disallow = [];
  let userAgent = null;

  for (const line of body.split('\n')) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith('#')) continue;

    const [key, ...valueParts] = trimmed.split(':');
    const keyLower = key.trim().toLowerCase();
    const value = valueParts.join(':').trim();

    if (keyLower === 'user-agent') {
      userAgent = value.toLowerCase();
    } else if (keyLower === 'allow' && (!userAgent || userAgent === '*')) {
      allow.push(globToRegex(value));
    } else if (keyLower === 'disallow' && (!userAgent || userAgent === '*')) {
      disallow.push(globToRegex(value));
    }
  }

  return { allow, disallow };
}

function checkAllow(rules, path) {
  for (const disallow of rules.disallow) {
    if (disallow.test(path)) {
      for (const allow of rules.allow) {
        if (allow.test(path)) return true;
      }
      return false;
    }
  }
  return true;
}

function globToRegex(glob) {
  const escaped = glob
    .replace(/[.+^${}()|[\]\\]/g, '\\$&')
    .replace(/\*/g, '.*')
    .replace(/\?/g, '.');
  return new RegExp('^' + escaped + '$');
}

function resolveUrl(base, relative) {
  try {
    return new URL(relative, base).href;
  } catch {
    return relative;
  }
}

export function computeHash(content) {
  return 'sha256:' + crypto.createHash('sha256').update(content, 'utf8').digest('hex');
}

export { AIRLOCK_UA, FETCH_TIMEOUT_MS, MAX_REDIRECTS };