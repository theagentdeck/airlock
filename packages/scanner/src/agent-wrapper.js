/**
 * AirLock Agent Wrapper — Single entry point for all agent scans
 *
 * Usage:
 *   import { scan } from '@airlock/scanner';
 *   const result = await scan({ url, agent, mission, mode, memoryWrite });
 */

import { fetch as doFetch, computeHash } from './fetcher.js';
import { extract } from './extractor.js';
import { scanRisk } from './risk-scanner/pattern-layer.js';
import { scanRiskSemantic } from './risk-scanner/semantic-layer.js';
import { buildPacket } from './packet-builder.js';
import { logScan } from './logger.js';
import { v4 as uuidv4 } from 'uuid';
import YAML from 'js-yaml';
import { readFileSync } from 'fs';
import { resolve, dirname } from 'path';
import { fileURLToPath } from 'url';

const __dirname = dirname(fileURLToPath(import.meta.url));

// Load policies
const defaultPolicy = YAML.load(
  readFileSync(resolve(__dirname, '../policies/default.yaml'), 'utf8')
);
const loungePolicy = YAML.load(
  readFileSync(resolve(__dirname, '../policies/lounge.yaml'), 'utf8')
);

/**
 * Main scan entry point.
 * @param {object} params
 * @param {string} params.url — URL to scan
 * @param {string} params.agent — requesting agent name
 * @param {string} params.mission — mission context
 * @param {'read'|'inspect'|'interact'} [params.mode='read']
 * @param {boolean} [params.memoryWrite=false]
 * @param {'default'|'lounge'} [params.policy='lounge']
 * @returns {Promise<{packet: object, read_receipt?: object}>}
 */
export async function scan({ url, agent, mission, mode = 'read', memoryWrite = false, policy = 'lounge' }) {
  const policyConfig = policy === 'lounge' ? loungePolicy : defaultPolicy;
  const scanId = uuidv4();
  const startTime = Date.now();

  // ── Step 1: Fetch ──────────────────────────────────────────────────────────
  const fetchResult = await doFetch(url);

  // ── Step 2: Publisher packet (Phase 4) ─────────────────────────────────────
  // If publisher has a signed packet, verify + use it
  if (fetchResult.packet_origin === 'publisher' && fetchResult.publisherPacket) {
    // Phase 4: verify signature and transform publisher packet to AirLockPacket format
    const packet = await handlePublisherPacket(fetchResult, scanId, policyConfig);
    return { packet };
  }

  // ── Step 3: Extract ─────────────────────────────────────────────────────────
  const extracted = extract(fetchResult.html, fetchResult.finalUrl);

  // ── Step 4: Risk scan (pattern layer) ───────────────────────────────────────
  const patternRisks = scanRisk(extracted);

  // ── Step 5: Risk scan (semantic layer via Compyoot) ────────────────────────
  let semanticRisks = [];
  try {
    semanticRisks = await scanRiskSemantic(extracted.fullText);
  } catch (err) {
    console.warn('AirLock semantic scan unavailable:', err.message);
    // Non-fatal — pattern layer still fires
  }

  // ── Step 6: Combine suspicious content ──────────────────────────────────────
  const allSuspicious = [
    ...patternRisks.suspicious,
    ...semanticRisks.suspicious,
  ];

  // ── Step 7: Classify links ──────────────────────────────────────────────────
  const classifiedLinks = classifyLinks(extracted.links, policyConfig);

  // ── Step 8: Classify forms ──────────────────────────────────────────────────
  const classifiedForms = classifyForms(extracted.forms, policyConfig);

  // ── Step 9: Build packet ─────────────────────────────────────────────────────
  const packet = buildPacket({
    scanId,
    url: fetchResult.finalUrl,
    fetchedAt: new Date().toISOString(),
    packetOrigin: 'scanner',
    sourceType: inferSourceType(fetchResult.finalUrl, extracted),
    extracted,
    suspicious: allSuspicious,
    links: classifiedLinks,
    forms: classifiedForms,
    policy: policyConfig,
    memoryWrite,
  });

  // ── Step 10: Log ────────────────────────────────────────────────────────────
  try {
    await logScan({
      scan_id: packet.scan_id,
      requesting_agent: agent,
      mission,
      source_url: fetchResult.finalUrl,
      packet_origin: 'scanner',
      risk_level: patternRisks.riskLevel,
      page_risk: packet.page_risk,
      packet_hash: packet.packet_hash,
      blocked_sinks: packet.blocked_sinks,
      allowed_sinks: packet.allowed_sinks,
      timestamp: packet.fetched_at,
    });
  } catch (err) {
    console.error('AirLock: logging failed:', err.message);
    // Non-fatal — don't block the scan
  }

  const elapsed = Date.now() - startTime;
  console.log(`AirLock: scanned ${url} in ${elapsed}ms — risk=${packet.page_risk}, origin=scanner`);

  return { packet };
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

function classifyLinks(links, policy) {
  const classified = [];
  for (const link of links) {
    const url = link.href;
    let risk = 'low';
    let reason = '';
    let allowed = true;

    // Shortened URL detection
    if (isShortenedUrl(url)) {
      risk = 'high';
      reason = 'shortened URL / redirect chain unresolved';
      allowed = false;
    }
    // Suspicious TLD
    else if (isSuspiciousTld(url)) {
      risk = 'high';
      reason = 'suspicious TLD associated with spam/malware';
      allowed = false;
    }
    // Data URL
    else if (url.startsWith('data:')) {
      risk = 'medium';
      reason = 'data URL — potential exfiltration vector';
      allowed = false;
    }
    // External vs internal — check against source hostname or explicit allowed_host
    else {
      try {
        const parsed = new URL(url, 'https://text2list.app');
        const srcParsed = new URL(url);
        const sourceHost = srcParsed.hostname;
        if (parsed.hostname !== sourceHost && policy.allowed_host !== null) {
          risk = 'medium';
          reason = 'external link requires review';
          allowed = false;
        }
      } catch {
        // keep low risk
      }
    }

    classified.push({ url, anchor_text: link.text, risk, reason, allowed });
  }
  return classified;
}

function classifyForms(forms, policy) {
  const classified = [];
  for (const form of forms) {
    classified.push({
      description: `Form with fields: ${form.fields.join(', ')}`,
      fields: form.fields,
      inert: true,
      action: 'blocked', // v0.1: all forms blocked
    });
  }
  return classified;
}

function isShortenedUrl(url) {
  const shortDomains = [
    'bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'ow.ly', 'is.gd',
    'buff.ly', 'rebrand.ly', 'tiny.cc', 'shorturl.at', 'cutt.ly',
  ];
  try {
    const parsed = new URL(url);
    return shortDomains.some(d => parsed.hostname.endsWith(d));
  } catch {
    return false;
  }
}

function isSuspiciousTld(url) {
  try {
    const parsed = new URL(url);
    const tld = parsed.hostname.split('.').pop();
    return ['tk', 'ml', 'ga', 'cf', 'gq', 'xyz', 'top'].includes(tld);
  } catch {
    return false;
  }
}

function isExternalUrl(url, policy) {
  try {
    const parsed = new URL(url, 'https://text2list.app');
    return parsed.hostname !== policy.allowed_host;
  } catch {
    return true;
  }
}

function inferSourceType(url, extracted) {
  const host = new URL(url).hostname;
  const path = new URL(url).pathname;

  if (host.includes('forum') || host.includes('reddit') || host.includes('discourse')) {
    return 'public_forum';
  }
  if (host.includes('news') || host.includes('cnn') || host.includes('bbc')) {
    return 'news_site';
  }
  if (path.includes('/blog') || path.includes('/posts')) {
    return 'blog';
  }
  if (host.includes('amazon') || host.includes('ebay') || host.includes('shop')) {
    return 'ecommerce';
  }
  if (host.includes('twitter') || host.includes('x.com') || host.includes('facebook')) {
    return 'social_media';
  }
  if (path.includes('/docs') || host.includes('readme')) {
    return 'documentation';
  }
  return 'unknown';
}

async function handlePublisherPacket(fetchResult, scanId, policyConfig) {
  // Phase 4 placeholder — verify publisher signature, transform to AirLockPacket
  const publisherData = fetchResult.publisherPacket;

  return buildPacket({
    scanId,
    url: fetchResult.finalUrl,
    fetchedAt: new Date().toISOString(),
    packetOrigin: 'publisher',
    sourceType: 'publisher_attested',
    extracted: { title: publisherData.publisher_name || '', visible_text_summary: '', key_claims: [] },
    suspicious: [],
    links: [],
    forms: [],
    policy: policyConfig,
    memoryWrite: false,
    publisherSignature: 'PLACEHOLDER', // Phase 4: Ed25519 verify
    publisherVerified: false,          // Phase 4: cryptographic verify
  });
}

export { doFetch as fetchUrl }; // alias for internal use