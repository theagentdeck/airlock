/**
 * AirLock Discovery — Phase 4
 * .well-known/airlock.json parsing and subscription management.
 *
 * v0.1: stub only — publisher discovery in fetcher.js checks the endpoint,
 * but this package handles the full subscription + registry logic in Phase 4.
 */

import axios from 'axios';

const AIRLOCK_UA = 'TheAgentDeck-AirLock/1.0 (+https://airlock.codes)';

/**
 * Fetch and parse a publisher's discovery document.
 * @param {string} url - any URL on the publisher's domain
 * @returns {Promise<AirlockDiscoveryDocument|null>}
 */
export async function fetchDiscoveryDoc(url) {
  const parsed = new URL(url);
  const discoveryUrl = `${parsed.protocol}//${parsed.host}/.well-known/airlock.json`;

  try {
    const response = await axios.get(discoveryUrl, {
      headers: { 'User-Agent': AIRLOCK_UA },
      timeout: 5000,
    });

    if (!response.data || response.data.airlock_version !== '1.0') {
      return null;
    }

    return validateDiscoveryDoc(response.data);
  } catch {
    return null;
  }
}

/**
 * Validate and type-check a discovery document.
 * @param {object} doc
 * @returns {AirlockDiscoveryDocument}
 */
export function validateDiscoveryDoc(doc) {
  // Phase 4: full schema validation
  return {
    airlock_version: doc.airlock_version || '1.0',
    publisher: doc.publisher || '',
    publisher_name: doc.publisher_name || doc.publisher || '',
    trust_signals: doc.trust_signals || {
      verified_publisher: false,
      reputation_score: 0,
      verification_method: 'none',
    },
    feeds: doc.feeds || [],
    signing_key: doc.signing_key || { algorithm: 'ed25519', public_key: '', rotation_url: '' },
    instruction_authority: doc.instruction_authority || 'none',
    contact: doc.contact || '',
  };
}

/**
 * Subscribe to a publisher's feed (polling or webhook).
 * @param {object} feed
 * @param {'polling'|'webhook'} mode
 */
export async function subscribeToFeed(feed, mode) {
  // Phase 4: implement subscription delivery
  throw new Error('Phase 4 feature — not yet implemented');
}

/**
 * List all known Airlock publishers from the registry.
 * @param {object} options
 */
export async function listPublishers({ tier, verified, limit = 50 } = {}) {
  // Phase 4: query airlock.codes registry
  throw new Error('Phase 4 feature — registry not yet deployed');
}