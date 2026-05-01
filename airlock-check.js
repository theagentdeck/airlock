/**
 * AirLock Pre-Flight Check
 * Lightweight scan before any agent action on external URLs.
 *
 * Usage:
 *   node airlock-check.js <url> [--mode read|post|inspect]
 *
 * Exit codes:
 *   0 = clean (low/medium risk, no critical findings)
 *   1 = blocked (high/critical risk OR critical finding)
 *   2 = error
 */

import { scan } from './packages/scanner/src/agent-wrapper.js';
import { readFileSync } from 'fs';

const args = process.argv.slice(2);
const url = args[0];
const mode = args.includes('--mode') ? args[args.indexOf('--mode') + 1] : 'read';

if (!url || url === '--help') {
  console.log('Usage: node airlock-check.js <url> [--mode read|post|inspect]');
  console.log('Modes: read (default) | post | inspect');
  process.exit(2);
}

try {
  const { packet } = await scan({
    url,
    agent: 'cleopatra',  // always Cleopatra for Reddit flows
    mission: `reddit-${mode}`,
    mode,
    memoryWrite: false,
    policy: 'lounge',
  });

  const criticals = packet.suspicious_content?.filter(f => f.severity === 'critical') || [];
  const highs = packet.suspicious_content?.filter(f => f.severity === 'high') || [];

  console.log(`\n🛡️  AirLock Pre-Flight: ${url}`);
  console.log(`    Risk: ${packet.page_risk}  |  Findings: ${packet.suspicious_content?.length || 0}`);
  if (packet.suspicious_content?.length > 0) {
    packet.suspicious_content.forEach(f => {
      console.log(`    [${f.severity.toUpperCase()}] ${f.type} — ${f.lane}`);
    });
  }

  if (packet.page_risk === 'critical' || packet.page_risk === 'high' || criticals.length > 0) {
    console.log('\n❌ BLOCKED — high/critical risk detected');
    process.exit(1);
  }

  if (highs.length > 0) {
    console.log('\n⚠️  CAUTION — high risk findings');
    process.exit(1);
  }

  console.log('\n✅ CLEAN — proceeding');
  process.exit(0);

} catch (err) {
  console.error('❌ AirLock error:', err.message);
  process.exit(2);
}
