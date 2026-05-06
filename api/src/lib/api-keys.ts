/**
 * AirLock API Key Utilities
 * Generate, hash, and validate per-subscriber API keys.
 * Raw key is returned ONCE on creation and never stored.
 */

import { createHash, randomBytes } from 'crypto';

/**
 * Generate a new AirLock API key.
 * Format: airlock_sk_live_<32 base36 chars>
 * Returns { raw, hash, prefix }
 */
export function generateApiKey(): { raw: string; hash: string; prefix: string } {
  const raw = 'airlock_sk_live_' + randomBytes(16).toString('base64url').slice(0, 32);
  const hash = sha256(raw);
  const prefix = raw.slice(0, 24); // airlock_sk_live_XXXX... for identification
  return { raw, hash, prefix };
}

/**
 * SHA-256 hash of a string.
 */
export function sha256(input: string): string {
  return createHash('sha256').update(input).digest('hex');
}

/**
 * Verify a raw API key against a stored hash.
 */
export function verifyApiKey(raw: string, hash: string): boolean {
  return sha256(raw) === hash;
}
