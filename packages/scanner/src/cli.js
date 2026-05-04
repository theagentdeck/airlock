#!/usr/bin/env node
/**
 * AirLock CLI — supports both `airlock <url>` and `airlock scan <url>`
 */

import { scan } from './agent-wrapper.js';

const args = process.argv.slice(2);

// Strip the "scan" subcommand if user typed `airlock scan <url>`
const cmd = args[0];
const isScanSubcommand = cmd === 'scan' || cmd === 's';
const urlArgIndex = isScanSubcommand ? 1 : 0;
const url = args[urlArgIndex];

if (!url || url === '--help' || url === '-h' || args.includes('--help') || args.includes('-h')) {
  console.log(`
TheAgentDeck AirLock CLI

Usage:
  airlock <url>             Scan a URL and print the evidence packet
  airlock scan <url>       Same as above (subcommand form)
  airlock <url> --json     Output raw JSON
  airlock <url> --md       Output markdown summary

Example:
  airlock https://example.com/forum/thread
`);
  process.exit(0);
}

const format = args.includes('--json') ? 'json' : args.includes('--md') ? 'md' : 'summary';

try {
  const result = await scan({
    url,
    agent: 'cli',
    mission: 'manual-testing',
    mode: 'read',
    memoryWrite: false,
  });

  if (format === 'json') {
    console.log(JSON.stringify(result.packet, null, 2));
  } else if (format === 'md') {
    printMarkdown(result.packet);
  } else {
    printSummary(result.packet);
  }
} catch (err) {
  console.error('❌ AirLock scan failed:', err.message);
  process.exit(1);
}

function printSummary(packet) {
  console.log('\n🔒 TheAgentDeck AirLock — Evidence Packet\n');
  console.log(`  URL:       ${packet.url}`);
  console.log(`  Origin:    ${packet.packet_origin}`);
  console.log(`  Risk:      ${packet.page_risk}`);
  console.log(`  Trust:     ${packet.trust_level}`);
  console.log(`  Source:    ${packet.source_type}`);
  console.log(`  Policy:    ext_auth=${packet.agent_instruction_policy.external_content_has_authority}, memory_write=${packet.agent_instruction_policy.memory_write_allowed}\n`);

  if (packet.suspicious_content.length > 0) {
    console.log('  🚨 Suspicious Content:');
    for (const s of packet.suspicious_content) {
      console.log(`    [${s.severity.toUpperCase()}] ${s.type}: "${s.text.slice(0, 80)}${s.text.length > 80 ? '…' : ''}"`);
      console.log(`    → ${s.mitigation}`);
    }
    console.log('');
  } else {
    console.log('  ✅ No suspicious content detected\n');
  }

  console.log(`  📄 Title: ${packet.extracted_content.title || '(none)'}`);
  console.log(`  📝 Summary: ${packet.extracted_content.visible_text_summary.slice(0, 200)}${packet.extracted_content.visible_text_summary.length > 200 ? '…' : ''}\n`);

  if (packet.links.length > 0) {
    const riskyLinks = packet.links.filter(l => !l.allowed);
    if (riskyLinks.length > 0) {
      console.log(`  ⚠️  Risky Links (${riskyLinks.length}):`);
      for (const l of riskyLinks.slice(0, 5)) {
        console.log(`    ${l.reason}: ${l.url}`);
      }
      console.log('');
    }
  }

  console.log(`  🛡️  Allowed sinks:  ${packet.allowed_sinks.join(', ') || '(none)'}`);
  console.log(`  🚫 Blocked sinks:  ${packet.blocked_sinks.join(', ') || '(none)'}\n`);
  console.log(`  💡 ${packet.recommendation}\n`);
  console.log(`  Packet ID: ${packet.scan_id} | Hash: ${packet.packet_hash}\n`);
}

function printMarkdown(packet) {
  console.log(`# AirLock Evidence Packet\n`);
  console.log(`**URL:** ${packet.url}`);
  console.log(`**Origin:** ${packet.packet_origin}`);
  console.log(`**Risk:** ${packet.page_risk} | **Trust:** ${packet.trust_level}`);
  console.log(`**Source Type:** ${packet.source_type}`);
  console.log(`**Scanned:** ${packet.fetched_at}\n`);

  console.log(`## Instruction Policy`);
  console.log(`- External content has authority: ${packet.agent_instruction_policy.external_content_has_authority}`);
  console.log(`- Tool calls from page allowed: ${packet.agent_instruction_policy.tool_calls_allowed_from_page}`);
  console.log(`- Memory write allowed: ${packet.agent_instruction_policy.memory_write_allowed}`);
  console.log(`- Outbound links require review: ${packet.agent_instruction_policy.outbound_links_require_review}\n`);

  if (packet.suspicious_content.length > 0) {
    console.log(`## 🚨 Suspicious Content`);
    for (const s of packet.suspicious_content) {
      console.log(`### [${s.severity.toUpperCase()}] ${s.type}`);
      console.log(`\`\`\`\n${s.text}\n\`\`\``);
      console.log(`**Lane:** ${s.lane}`);
      console.log(`**Mitigation:** ${s.mitigation}\n`);
    }
  } else {
    console.log(`## ✅ No suspicious content detected\n`);
  }

  console.log(`## Extracted Content`);
  console.log(`**Title:** ${packet.extracted_content.title || '(none)'}`);
  console.log(`\n**Summary:** ${packet.extracted_content.visible_text_summary}\n`);

  if (packet.extracted_content.key_claims.length > 0) {
    console.log(`**Key Claims:**`);
    for (const c of packet.extracted_content.key_claims) {
      console.log(`- [${c.confidence}] ${c.claim} *(source: ${c.evidence_type})*`);
    }
    console.log('');
  }

  if (packet.links.length > 0) {
    console.log(`## Links`);
    for (const l of packet.links) {
      const icon = l.allowed ? '✅' : '❌';
      console.log(`${icon} ${l.url} — ${l.reason}`);
    }
    console.log('');
  }

  console.log(`## Sinks`);
  console.log(`**Allowed:** ${packet.allowed_sinks.join(', ') || '(none)'}`);
  console.log(`**Blocked:** ${packet.blocked_sinks.join(', ') || '(none)'}\n`);

  console.log(`## Recommendation`);
  console.log(`${packet.recommendation}\n`);

  console.log(`---\n`);
  console.log(`*Packet ID: ${packet.scan_id} | Hash: ${packet.packet_hash}*\n`);
}