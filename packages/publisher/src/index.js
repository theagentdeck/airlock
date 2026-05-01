/**
 * AirLock Publisher SDK — Phase 3
 * Generates signed AirLock packets from publisher content.
 *
 * v0.1: stub only — full SDK in Phase 3.
 * Target: publishers integrate in under 1 hour.
 */

import { createHmac, randomBytes } from 'crypto';
import { v4 as uuidv4 } from 'uuid';

/**
 * Create a new Airlock instance for a publisher.
 * @param {object} config
 * @param {string} config.publisher - e.g. 'example.com'
 * @param {string} config.signingKey - Ed25519 private key (base64)
 */
export class Airlock {
  constructor({ publisher, signingKey }) {
    this.publisher = publisher;
    this.signingKey = signingKey; // Phase 3: Ed25519 key
  }

  /**
   * Generate an AirLock packet from HTML content.
   * @param {object} params
   * @param {string} params.url
   * @param {string} params.content - raw HTML
   * @param {object} params.metadata - { author, published, tags, ... }
   */
  pack({ url, content, metadata = {} }) {
    // Phase 3: extract + build packet + sign
    const packet = {
      airlock_version: '1.0',
      packet_origin: 'publisher',
      url,
      fetched_at: new Date().toISOString(),
      source_type: 'publisher_attested',
      trust_level: 'high',
      page_risk: 'low',
      publisher_signature: 'PLACEHOLDER', // Phase 3: Ed25519 sign
      publisher_verified: true,
      extracted_content: {
        title: metadata.title || '',
        visible_text_summary: content.slice(0, 500),
        key_claims: [],
      },
      suspicious_content: [],
      links: [],
      forms: [],
      blocked_sinks: [],
      allowed_sinks: ['summarize', 'classify', 'quote_with_citation'],
      recommendation: 'Publisher-attested content. Trust level: high.',
      packet_hash: '', // Phase 3
      scan_id: uuidv4(),
    };

    return packet;
  }

  /**
   * Create an AirLock feed endpoint handler.
   * @param {object} params
   * @param {Function} params.getArticles - returns articles to include in feed
   */
  feed({ getArticles }) {
    // Phase 3: returns Express/Koa handler that serves packets
    return async (req, res) => {
      const articles = await getArticles();
      const packets = articles.map(a => this.pack({ url: a.url, content: a.html, metadata: a.meta }));
      res.json({ packets, airlock_version: '1.0', count: packets.length });
    };
  }
}

/**
 * Sign a packet with Ed25519.
 * @param {object} packet
 * @param {string} privateKey - base64 Ed25519 key
 */
export function signPacket(packet, privateKey) {
  // Phase 3
  const canonical = JSON.stringify(packet, Object.keys(packet).sort());
  // Phase 3: actual Ed25519 sign
  return Buffer.from(canonical).toString('base64');
}