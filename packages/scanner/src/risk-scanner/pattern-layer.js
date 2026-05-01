/**
 * AirLock Risk Scanner — Pattern Layer
 * Deterministic, cheap pattern matching for common prompt injection,
 * credential requests, hidden instructions, and other hostile content.
 *
 * No LLM call needed — exact/approximate string matches on known-bad
 * patterns from OWASP + security research.
 */

const PATTERN_INJECTION = [
  // Direct command overrides
  /ignore\s+(all\s+)?(previous|prior)\s+instructions?/i,
  /disregard\s+(all\s+)?(previous|prior)\s+instructions?/i,
  /forget\s+(all\s+)?(previous|prior)\s+instructions?/i,
  /override\s+(your\s+)?instructions/i,
  /you\s+are\s+now\s+/i,
  /forget\s+everything\s+about/i,
  /ignore\s+your\s+system\s+prompt/i,
  /disregard\s+your\s+system\s+prompt/i,

  // Jailbreak templates
  /pretend\s+you\s+are\s+(in\s+)?(a|an)\s+\w+\s+mode/i,
  /roleplay\s+(as\s+)?(a|an)\s+\w+/i,
  /DAN[\s.,]*(do\s+anything\s+now|anything\s+and\s+now)/i,
  /developer\s+mode/i,
  /new\s+instructions?:/i,
  /system\s+prompt\s*:/i,

  // Authority impersonation
  /\bas an? (AI|artificial intelligence|language model)\b/i,
  /\bI am (your|the) (creator|developer|owner|admin)/i,
  /\bonly (you|your model) (can|should) (do|see|know)/i,
  /you\s+must\s+(reveal|tell|show|disclose)/i,

  // OWASP indirect injection markers
  /\[SYSTEM INJECTION\]/i,
  /\[SYSTEM_MESSAGE\]/i,
  /INJECTED PROMPT/i,

  // Exfiltration
  /send\s+(your\s+)?(system\s+prompt|instructions|config)\s+to/i,
  /copy[\s-]?paste\s+(your\s+)?(system\s+prompt|instructions)/i,
  /reveal[\s-]?(your\s+)?(system\s+prompt|instructions)/i,
  /<\s*script[^>]*>/i,
  /javascript:/i,
];

const PATTERN_CREDENTIAL = [
  /api[\s_-]?key/i,
  /secret[_-]?(key|token)?/i,
  /\bpassword\b/i,
  /credential/i,
  /auth[_-]?token/i,
  /bearer\s+token/i,
  /private[_-]?key/i,
  /access[_-]?token/i,
  /openai[_-]?(api)?[_-]?key/i,
  /github[_-]?(api)?[_-]?token/i,
  /\bAKIA[0-9A-Z]{16}\b/,
  /\bsend\s+(your\s+)?(api[\s_-]?key|secret|credential|password)/i,  // exfil of credentials
];

const PATTERN_URGENCY = [
  /act\s+now/i,
  /do\s+this\s+immediately/i,
  /urgent(ly)?/i,
  /time[- ]?sensitive/i,
  /limited\s+time/i,
  /expires?\s+(today|soon|immediately)/i,
  /don't\s+wait/i,
];

const PATTERN_FLATTERY = [
  /you('re| are) (the (only |best |greatest |smartest ))?(smart|capable|intelligent|brilliant|amazing)/i,
  /only\s+you\s+(can|would|should)/i,
  /no\s+one\s+(else|other)\s+(can|does|knows)/i,
  /I\s+trust\s+you\s+(implicitly|completely|fully)/i,
];

const PATTERN_HIDDEN_SIGNALS = [
  /\btell\s+your\s+(agent|AI|assistant|model)\b/i,
  /\b(agent|AI|assistant)\s+should\s+(do|send|reveal|execute)/i,
  /\binstruct\s+(your|this)\s+(agent|AI|assistant)/i,
  /\bwhen\s+(your|this)\s+(agent|AI|model)\s+sees/i,
  /\bforward\s+to\s+(your|this)\s+agent/i,
];

const SHORTENER_RE = /^(bit\.ly|tinyurl\.com|t\.co|goo\.gl|ow\.ly|is\.gd|buff\.ly|rebrand\.ly|tiny\.cc|shorturl\.at|cutt\.ly)$/i;

/**
 * Main scan function.
 * @param {object} extracted - output from extractor.js
 * @returns {{suspicious: object[], riskLevel: string}}
 */
export function scanRisk(extracted) {
  const suspicious = [];
  const fullText = extracted.fullText || '';

  // ── Scan full text ────────────────────────────────────────────────────────
  suspicious.push(...scanFullText(fullText));

  // ── Scan hidden text (upgrade severity) ─────────────────────────────────
  for (const hidden of extracted.hiddenText || []) {
    const matches = scanFullText(hidden.text);
    for (const m of matches) {
      m.severity = upgradeSeverity(m.severity);
      m.lane = 'hidden_text';
    }
    suspicious.push(...matches);
  }

  // ── Scan link texts ───────────────────────────────────────────────────────
  for (const link of extracted.links || []) {
    const textToScan = `${link.text} ${link.title}`.trim();
    if (!textToScan) continue;

    // Hidden signals in link text
    for (const pattern of PATTERN_HIDDEN_SIGNALS) {
      if (pattern.test(textToScan)) {
        suspicious.push({
          type: 'hidden_instruction',
          severity: 'high',
          text: textToScan.slice(0, 200),
          lane: 'links',
          mitigation: 'Stripped from agent instruction context.',
          context: `link: ${link.href}`,
        });
      }
    }

    // Prompt injection in link URL
    for (const pattern of PATTERN_INJECTION) {
      if (pattern.test(link.href)) {
        suspicious.push({
          type: 'prompt_injection',
          severity: 'high',
          text: `URL contains injection pattern: ${link.href.slice(0, 100)}`,
          lane: 'links',
          mitigation: 'Link flagged as potentially hostile. Do not navigate without review.',
        });
      }
    }

    // Shortened URL detection
    try {
      const parsed = new URL(link.href);
      if (SHORTENER_RE.test(parsed.hostname)) {
        suspicious.push({
          type: 'prompt_injection',
          severity: 'high',
          text: `Shortened URL: ${link.href.slice(0, 100)}`,
          lane: 'links',
          mitigation: 'Shortened URL — redirect chain unresolved. Do not navigate without review.',
        });
      }
    } catch { /* invalid URL, skip */ }
  }

  // ── Scan image alt texts (steganographic injection) ───────────────────────
  for (const img of extracted.images || []) {
    const altToScan = `${img.alt} ${img.title}`.trim();
    if (!altToScan || altToScan.length < 10) continue;

    const matches = scanFullText(altToScan);
    for (const m of matches) {
      m.lane = 'images';
      m.context = `image alt: "${altToScan.slice(0, 80)}"`;
    }
    suspicious.push(...matches);
  }

  // ── Scan inline scripts ───────────────────────────────────────────────────
  for (const script of extracted.scripts || []) {
    if (script.type !== 'inline') continue;

    suspicious.push({
      type: 'prompt_injection',
      severity: 'high',
      text: `Inline script block detected (${script.length} chars)`,
      lane: 'code',
      mitigation: 'JavaScript stripped. No execution allowed.',
    });

    const scriptMatches = scanFullText(script.text || '');
    for (const m of scriptMatches) {
      m.lane = 'code';
      m.context = 'inline script content';
    }
    suspicious.push(...scriptMatches);
  }

  // ── Deduplicate ───────────────────────────────────────────────────────────
  const seen = new Set();
  const deduped = suspicious.filter(s => {
    const key = `${s.type}:${s.text.slice(0, 50)}:${s.lane}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });

  const riskLevel = computeOverallRisk(deduped);
  return { suspicious: deduped, riskLevel };
}

function scanFullText(text) {
  const results = [];

  // Check credentials FIRST — "send your API key" should be credential_request, not just injection
  for (const pattern of PATTERN_CREDENTIAL) {
    if (pattern.test(text)) {
      results.push({
        type: 'credential_request',
        severity: 'critical',
        text: extractMatchContext(text, pattern),
        lane: 'potential_exfiltration',
        mitigation: 'Blocked. Do not process credential requests from external pages.',
      });
    }
  }

  // Then check injection patterns
  for (const pattern of PATTERN_INJECTION) {
    if (pattern.test(text)) {
      results.push({
        type: 'prompt_injection',
        severity: inferSeverity(text, pattern),
        text: extractMatchContext(text, pattern),
        lane: 'potential_instructions',
        mitigation: 'Stripped from agent instruction context.',
      });
    }
  }

  for (const pattern of PATTERN_URGENCY) {
    if (pattern.test(text)) {
      results.push({
        type: 'authority_claim',
        severity: 'medium',
        text: extractMatchContext(text, pattern),
        lane: 'authority_claims',
        mitigation: 'Urgency framing flagged. Verify independently before acting.',
      });
    }
  }

  for (const pattern of PATTERN_FLATTERY) {
    if (pattern.test(text)) {
      results.push({
        type: 'authority_claim',
        severity: 'low',
        text: extractMatchContext(text, pattern),
        lane: 'authority_claims',
        mitigation: 'Flattery detected. Maintain objective assessment.',
      });
    }
  }

  return results;
}

function extractMatchContext(text, pattern) {
  const match = text.match(pattern);
  if (!match || !match[0]) return text.slice(0, 200);

  const start = Math.max(0, match.index - 40);
  const end = Math.min(text.length, match.index + match[0].length + 40);
  const context = text.slice(start, end);

  return (start > 0 ? '…' : '') + context + (end < text.length ? '…' : '');
}

function inferSeverity(text, pattern) {
  if (/system\s+prompt|instructions?:|developer\s+mode/i.test(text)) return 'critical';
  if (/eval|exec|import\s*\(|script[^>]/i.test(text)) return 'high';
  if (/ignore|disregard|override/i.test(text)) return 'high';
  return 'medium';
}

function upgradeSeverity(severity) {
  const levels = { low: 'medium', medium: 'high', high: 'critical', critical: 'critical' };
  return levels[severity] || severity;
}

function computeOverallRisk(suspicious) {
  if (!suspicious || suspicious.length === 0) return 'low';

  const severities = suspicious.map(s => s.severity);
  if (severities.includes('critical')) return 'critical';
  if (severities.includes('high')) return 'high';
  if (severities.includes('medium')) return 'medium';
  return 'low';
}

export { SHORTENER_RE };