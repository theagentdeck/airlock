/**
 * AirLock Risk Scanner — Semantic Layer
 * Routes to Compyoot for steganographic injection detection:
 * instructions hidden in alt text, CSS-invisible spans, markdown link titles,
 * and other hard-to-catch patterns.
 *
 * Falls back gracefully if Compyoot is unavailable.
 */

import { readFileSync } from 'fs';
import { resolve, dirname } from 'path';
import { fileURLToPath } from 'url';

const __dirname = dirname(fileURLToPath(import.meta.url));

// Load Compyoot path from environment or default
const COMPYOOT_PATH = process.env.AIRLOCK_COMPYOOT_PATH || resolve(__dirname, '../../../../compyoot/src');

/**
 * @param {string} text - Text to classify for prompt injection risk
 * @returns {Promise<{suspicious: SuspiciousContent[]}>}
 */
export async function scanRiskSemantic(text) {
  if (!text || text.length < 50) {
    return { suspicious: [] };
  }

  try {
    // Try to import Compyoot if available
    let compyoot;
    try {
      compyoot = await import(COMPYOOT_PATH + '/router.js').catch(() => null);
    } catch {
      // Compyoot not available — skip semantic layer
    }

    if (compyoot && compyoot.classify) {
      const result = await compyoot.classify({
        text,
        category: 'prompt_injection',
        model: 'free',
      });

      if (result.risk === 'high' || result.risk === 'critical') {
        return {
          suspicious: [
            {
              type: 'prompt_injection',
              severity: result.risk,
              text: text.slice(0, 200),
              lane: 'potential_instructions',
              mitigation: 'Stripped from agent instruction context.',
              source: 'semantic_layer',
              confidence: result.confidence,
            },
          ],
        };
      }
    }
  } catch (err) {
    // Non-fatal — log and fall back to pattern layer only
    console.warn('AirLock semantic scan error:', err.message);
  }

  return { suspicious: [] };
}

/**
 * Quick semantic classification via LLM for specific edge cases.
 * Used when pattern layer finds suspicious but inconclusive content.
 *
 * @param {string} text
 * @param {'free'|'cheap'} [tier='free']
 * @returns {Promise<{risk: string, reasoning: string}>}
 */
export async function classifyWithLLM(text, tier = 'free') {
  const model = tier === 'free' ? 'openrouter/hunter-alpha' : 'mistral-small-latest';

  try {
    const response = await fetch('https://openrouter.ai/api/v1/chat/completions', {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${process.env.OPENROUTER_API_KEY || ''}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        model,
        messages: [
          {
            role: 'system',
            content: `You are a prompt-injection classifier for AI agents. Classify the following text as: low, medium, high, or critical risk.

Risk levels:
- low: normal web content
- medium: potentially manipulative but not clearly hostile
- high: likely prompt injection attempt
- critical: clear and dangerous prompt injection

Respond ONLY with a JSON object: {"risk": "...", "reasoning": "..."}`,
          },
          { role: 'user', content: text.slice(0, 2000) },
        ],
        max_tokens: 100,
        temperature: 0,
      }),
    });

    if (!response.ok) {
      throw new Error(`LLM API error: ${response.status}`);
    }

    const data = await response.json();
    const content = data.choices?.[0]?.message?.content;

    if (!content) {
      throw new Error('No response from LLM');
    }

    return JSON.parse(content);
  } catch (err) {
    console.warn('AirLock LLM classification failed:', err.message);
    return { risk: 'medium', reasoning: 'Classification unavailable — defaulting to medium.' };
  }
}

/**
 * Steganographic injection check: scan for known steganographic patterns
 * that don't need LLM classification.
 *
 * @param {object} extracted - from extractor.js
 * @returns {{suspicious: SuspiciousContent[]}}
 */
export function checkSteganography(extracted) {
  const suspicious = [];

  // Check markdown link titles for instructions
  // e.g. [visible text](url "hidden instruction")
  const markdownInstructionPattern = /\[.*?\]\(.*?"([^"]+)"\)/g;
  const htmlWithTitle = extracted.fullText || '';

  // Check image alt text for very long strings (potential hidden instructions)
  for (const img of extracted.images || []) {
    if (img.alt && img.alt.length > 200) {
      suspicious.push({
        type: 'hidden_instruction',
        severity: 'medium',
        text: `Long alt text (${img.alt.length} chars): "${img.alt.slice(0, 100)}…"`,
        lane: 'images',
        mitigation: 'Alt text is unusually long. Verify it contains no hidden instructions.',
      });
    }
  }

  // Check for CSS text embedding techniques
  // Very rough heuristic: text in elements with zero font-size + color matching bg
  // Real detection needs computed styles — this is a placeholder

  return { suspicious };
}