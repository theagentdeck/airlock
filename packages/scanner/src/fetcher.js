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

/**
 * @param {string} url
 * @returns {Promise<{html: string, redirectChain: string[], finalUrl: string, packet_origin: 'scanner' | 'publisher', publisherPacket: object|null}>}
 */
export async function fetch(url) {
  // Step 1: Check if publisher is Airlock-ready
  const publisherResult = await checkPublisherDiscovery(url);
  if (publisherResult.packet) {
    return {
      html: null,
      redirectChain: [],
      finalUrl: url,
      packet_origin: 'publisher',
      publisherPacket: publisherResult.packet,
      publisherVerified: publisherResult.verified,
    };
  }

  // Step 2: Server-side fetch with redirect chain logging
  const redirectChain = [];
  let currentUrl = url;
  let html = null;

  for (let i = 0; i < MAX_REDIRECTS; i++) {
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
        maxRedirects: 0, // handle redirects manually
        validateStatus: (status) => status >= 200 && status < 400,
      });

      // Check for redirect
      const location = response.headers['location'];
      if (location && i < MAX_REDIRECTS - 1) {
        redirectChain.push(currentUrl);
        currentUrl = resolveUrl(currentUrl, location);
        continue;
      }

      html = response.data;
      break;
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

  if (!html) {
    throw new Error(`AirLock: exceeded max redirects (${MAX_REDIRECTS}) for ${url}`);
  }

  return {
    html,
    redirectChain,
    finalUrl: currentUrl,
    packet_origin: 'scanner',
    publisherPacket: null,
    publisherVerified: false,
  };
}

/**
 * Check if a publisher offers a signed AirLock packet via .well-known endpoint.
 * @param {string} url
 * @returns {Promise<{packet: object|null, verified: boolean}>}
 */
async function checkPublisherDiscovery(url) {
  const parsed = new URL(url);
  const discoveryUrl = `${parsed.protocol}//${parsed.host}/.well-known/airlock.json`;

  try {
    const response = await axios.get(discoveryUrl, {
      headers: { 'User-Agent': AIRLOCK_UA },
      timeout: 5000,
      maxRedirects: 2,
    });

    if (!response.data || response.data.airlock_version !== '1.0') {
      return { packet: null, verified: false };
    }

    // Try to fetch the publisher's feed/packet
    // For now, just return the discovery doc — the agent wrapper will handle feed subscription
    // Phase 4 will implement full subscription delivery
    return { packet: response.data, verified: false };
  } catch {
    // No discovery endpoint — fall through to scanner
    return { packet: null, verified: false };
  }
}

/**
 * Simple robots.txt check (user-agent: * only for now).
 * Cache per host to avoid repeated requests.
 */
const robotsCache = new Map();

async function checkRobotsTxt(url) {
  const parsed = new URL(url);
  const host = parsed.host;

  if (robotsCache.has(host)) {
    const rules = robotsCache.get(host);
    const path = parsed.pathname;
    return checkAllow(rules, path);
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
    // No robots.txt = allowed
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

/**
 * Compute SHA-256 hash of content for packet integrity.
 * @param {string} content
 * @returns {string}
 */
export function computeHash(content) {
  return 'sha256:' + crypto.createHash('sha256').update(content, 'utf8').digest('hex');
}

export { AIRLOCK_UA, FETCH_TIMEOUT_MS, MAX_REDIRECTS };