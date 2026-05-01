/**
 * AirLock Verifier — Phase 4
 * Ed25519 signature verification for publisher-signed packets.
 *
 * v0.1: stub only — full implementation in Phase 4.
 */

import { createHmac, createVerify } from 'crypto';

/**
 * Verify a publisher's signed packet.
 * @param {object} packet
 * @param {string} packet.publisher_signature - Base64 Ed25519 signature
 * @param {string} packet.url
 * @param {object} publisherKey - { algorithm: 'ed25519', public_key: 'base64...' }
 * @returns {Promise<{valid: boolean, reason?: string}>}
 */
export async function verifyPacket(packet, publisherKey) {
  // Phase 4: implement Ed25519 verification
  // For now, always return false (no verification in Phase 1)
  return { valid: false, reason: 'Phase 4 feature — not yet implemented' };
}

/**
 * Verify that a publisher key is valid for a given domain.
 * @param {string} domain
 * @param {object} discoveryDoc - from .well-known/airlock.json
 */
export async function verifyPublisherKey(domain, discoveryDoc) {
  // Phase 4: check key ownership via TLS cert transparency or DNS challenge
  return { valid: false, reason: 'Phase 4 feature' };
}

/**
 * Check if a key has been rotated (revocation check).
 * @param {string} rotationUrl
 * @param {string} currentKeyId
 */
export async function checkKeyRotation(rotationUrl, currentKeyId) {
  // Phase 4: fetch rotation URL, compare key IDs
  return { rotated: false, newKeyId: currentKeyId };
}