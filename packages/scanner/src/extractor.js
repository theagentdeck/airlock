const ZERO_WIDTH_RE = /[\u200B\u200C\u200D\u2060\uFEFF]/g;

function decodeHtmlEntities(input = '') {
  return input
    .replace(/&nbsp;/gi, ' ')
    .replace(/&amp;/gi, '&')
    .replace(/&lt;/gi, '<')
    .replace(/&gt;/gi, '>')
    .replace(/&quot;/gi, '"')
    .replace(/&#39;/gi, "'")
    .replace(/&#x([0-9a-f]+);/gi, (_, hex) => String.fromCodePoint(parseInt(hex, 16)))
    .replace(/&#(\d+);/g, (_, dec) => String.fromCodePoint(parseInt(dec, 10)));
}

function stripTags(input = '') {
  return decodeHtmlEntities(input.replace(/<[^>]+>/g, ' '));
}

function normalizeWhitespace(input = '') {
  return input.replace(/\s+/g, ' ').trim();
}

function parseAttributes(raw = '') {
  const attrs = {};
  const attrRe = /([:\w-]+)(?:\s*=\s*("([^"]*)"|'([^']*)'|([^\s"'>]+)))?/g;
  let match;
  while ((match = attrRe.exec(raw))) {
    const [, key, , dq, sq, bare] = match;
    attrs[key.toLowerCase()] = decodeHtmlEntities(dq ?? sq ?? bare ?? '');
  }
  return attrs;
}

function extractTagMatches(html, tagName) {
  const re = new RegExp(`<${tagName}\\b([^>]*)>([\\s\\S]*?)<\\/${tagName}>`, 'gi');
  const out = [];
  let match;
  while ((match = re.exec(html))) {
    out.push({ attrs: parseAttributes(match[1]), innerHtml: match[2], raw: match[0], index: match.index });
  }
  return out;
}

function extractVoidTagMatches(html, tagName) {
  const re = new RegExp(`<${tagName}\\b([^>]*)\\/?>(?!<\\/${tagName}>)`, 'gi');
  const out = [];
  let match;
  while ((match = re.exec(html))) {
    out.push({ attrs: parseAttributes(match[1]), raw: match[0], index: match.index });
  }
  return out;
}

function findFirstTagInnerHtml(html, tagNames) {
  for (const tagName of tagNames) {
    const match = new RegExp(`<${tagName}\\b[^>]*>([\\s\\S]*?)<\\/${tagName}>`, 'i').exec(html);
    if (match) return match[1];
  }
  return '';
}

function isSameColor(a, b) {
  if (!a || !b) return false;
  const normalize = (value) => value.toLowerCase().replace(/\s+/g, '');
  return normalize(a) === normalize(b);
}

function parseStyle(style = '') {
  return style
    .split(';')
    .map((entry) => entry.trim())
    .filter(Boolean)
    .reduce((acc, entry) => {
      const idx = entry.indexOf(':');
      if (idx === -1) return acc;
      const key = entry.slice(0, idx).trim().toLowerCase();
      const value = entry.slice(idx + 1).trim();
      acc[key] = value;
      return acc;
    }, {});
}

function classifyHiddenReason(attrs = {}, innerText = '') {
  const reasons = [];
  const style = parseStyle(attrs.style || '');
  const text = normalizeWhitespace(innerText);

  if ('hidden' in attrs || attrs['aria-hidden'] === 'true') reasons.push('hidden-attribute');
  if (/display\s*:\s*none/i.test(attrs.style || '')) reasons.push('display-none');
  if (/visibility\s*:\s*hidden/i.test(attrs.style || '')) reasons.push('visibility-hidden');
  if (/opacity\s*:\s*0(?:\D|$)/i.test(attrs.style || '')) reasons.push('opacity-zero');
  if (/font-size\s*:\s*0(?:px|rem|em|%|\b)/i.test(attrs.style || '')) reasons.push('font-size-zero');
  if (/width\s*:\s*0(?:px|rem|em|%|\b)/i.test(attrs.style || '')) reasons.push('width-zero');
  if (/height\s*:\s*0(?:px|rem|em|%|\b)/i.test(attrs.style || '')) reasons.push('height-zero');
  if (style.color && (style['background-color'] || style.background) && isSameColor(style.color, style['background-color'] || style.background)) {
    reasons.push('color-matched');
  }
  if (ZERO_WIDTH_RE.test(text)) reasons.push('zero-width-characters');

  return reasons;
}

function removeComments(html = '') {
  return html.replace(/<!--[\s\S]*?-->/g, ' ');
}

function removeTagBlocks(html = '', tagNames = []) {
  return tagNames.reduce(
    (acc, tag) => acc.replace(new RegExp(`<${tag}\\b[\\s\\S]*?<\\/${tag}>`, 'gi'), ' '),
    html,
  );
}

function removeHiddenBlocks(html = '') {
  return html
    .replace(/<([a-z0-9:-]+)\b([^>]*(?:hidden|aria-hidden\s*=\s*["']?true|style\s*=\s*["'][^"']*(?:display\s*:\s*none|visibility\s*:\s*hidden|opacity\s*:\s*0|font-size\s*:\s*0|width\s*:\s*0|height\s*:\s*0)[^"']*["'])[^>]*)>[\s\S]*?<\/\1>/gi, ' ')
    .replace(/<([a-z0-9:-]+)\b([^>]*style\s*=\s*["'][^"']*(?:color\s*:\s*([^;"']+))[^"']*(?:background(?:-color)?\s*:\s*\3)[^"']*["'][^>]*)>[\s\S]*?<\/\1>/gi, ' ');
}

function extractVisibleText(html = '') {
  const scoped = findFirstTagInnerHtml(html, ['main', 'article']) || findFirstTagInnerHtml(html, ['body']) || html;
  const cleaned = removeHiddenBlocks(removeTagBlocks(removeComments(scoped), ['script', 'style', 'noscript', 'template']));
  return normalizeWhitespace(stripTags(cleaned));
}

function extractTitle(html = '') {
  const match = /<title[^>]*>([\s\S]*?)<\/title>/i.exec(html);
  return normalizeWhitespace(stripTags(match?.[1] || ''));
}

function extractCanonicalUrl(html = '', baseUrl = '') {
  const canonical = extractVoidTagMatches(html, 'link').find((item) => (item.attrs.rel || '').toLowerCase().split(/\s+/).includes('canonical'));
  return canonical?.attrs.href || baseUrl || null;
}

function extractMetaTags(html = '') {
  return extractVoidTagMatches(html, 'meta')
    .map(({ attrs }) => ({
      name: attrs.name || attrs.property || attrs['http-equiv'] || null,
      content: attrs.content || null,
      charset: attrs.charset || null,
    }))
    .filter((item) => item.name || item.content || item.charset);
}

function extractLinks(html = '') {
  return extractTagMatches(html, 'a').map(({ attrs, innerHtml }) => ({
    href: attrs.href || null,
    text: normalizeWhitespace(stripTags(innerHtml)),
    rel: attrs.rel || null,
    target: attrs.target || null,
  }));
}

function extractImages(html = '') {
  return extractVoidTagMatches(html, 'img').map(({ attrs }) => ({
    src: attrs.src || null,
    alt: normalizeWhitespace(attrs.alt || ''),
    title: normalizeWhitespace(attrs.title || ''),
  }));
}

function extractFormControls(innerHtml = '') {
  const controls = [];
  for (const input of extractVoidTagMatches(innerHtml, 'input')) {
    controls.push({
      tag: 'input',
      type: (input.attrs.type || 'text').toLowerCase(),
      name: input.attrs.name || null,
      placeholder: input.attrs.placeholder || null,
      value: input.attrs.value || null,
    });
  }
  for (const area of extractTagMatches(innerHtml, 'textarea')) {
    controls.push({
      tag: 'textarea',
      name: area.attrs.name || null,
      placeholder: area.attrs.placeholder || null,
      value: normalizeWhitespace(stripTags(area.innerHtml)),
    });
  }
  for (const select of extractTagMatches(innerHtml, 'select')) {
    controls.push({
      tag: 'select',
      name: select.attrs.name || null,
      options: extractTagMatches(select.innerHtml, 'option').map((option) => ({
        value: option.attrs.value || null,
        text: normalizeWhitespace(stripTags(option.innerHtml)),
      })),
    });
  }
  for (const button of extractTagMatches(innerHtml, 'button')) {
    controls.push({
      tag: 'button',
      type: (button.attrs.type || 'button').toLowerCase(),
      text: normalizeWhitespace(stripTags(button.innerHtml)),
      name: button.attrs.name || null,
    });
  }
  return controls;
}

function describeForm(form) {
  const controls = extractFormControls(form.innerHtml);
  const parts = controls.map((control) => {
    if (control.tag === 'input') return `${control.tag}:${control.type}${control.name ? `(${control.name})` : ''}`;
    if (control.tag === 'button') return `${control.tag}:${control.type}${control.text ? `(${control.text})` : ''}`;
    if (control.tag === 'select') return `${control.tag}${control.name ? `(${control.name})` : ''}`;
    return `${control.tag}${control.name ? `(${control.name})` : ''}`;
  });
  const method = (form.attrs.method || 'get').toUpperCase();
  return `${method} ${form.attrs.action || '[same-page]'} :: ${parts.join(', ') || 'no controls detected'}`;
}

function extractForms(html = '') {
  return extractTagMatches(html, 'form').map((form) => ({
    action: form.attrs.action || null,
    method: (form.attrs.method || 'get').toUpperCase(),
    description: describeForm(form),
    controls: extractFormControls(form.innerHtml),
    inert: true,
  }));
}

function extractHiddenText(html = '') {
  const findings = [];
  const hiddenPattern = /<([a-z0-9:-]+)\b([^>]*(?:hidden|aria-hidden\s*=\s*["']?true|style\s*=\s*["'][^"']*(?:display\s*:\s*none|visibility\s*:\s*hidden|opacity\s*:\s*0|font-size\s*:\s*0|width\s*:\s*0|height\s*:\s*0|color\s*:[^;"']+;?[^"']*background(?:-color)?\s*:[^;"']+)[^"']*["'])[^>]*)>([\s\S]*?)<\/\1>/gi;
  let match;
  while ((match = hiddenPattern.exec(html))) {
    const [, tagName, rawAttrs, innerHtml] = match;
    const attrs = parseAttributes(rawAttrs);
    const text = normalizeWhitespace(stripTags(innerHtml));
    if (!text) continue;
    const reasons = classifyHiddenReason(attrs, text);
    if (reasons.length) findings.push({ tag: tagName.toLowerCase(), text, reasons, attrs });
  }

  const zeroWidthMatches = [];
  let zw;
  const zeroWidthRe = /([^\n]{0,80}[\u200B\u200C\u200D\u2060\uFEFF][^\n]{0,80})/g;
  while ((zw = zeroWidthRe.exec(html))) {
    zeroWidthMatches.push(normalizeWhitespace(stripTags(zw[1])));
  }
  for (const text of zeroWidthMatches.filter(Boolean)) {
    findings.push({ tag: 'text-node', text, reasons: ['zero-width-characters'], attrs: {} });
  }

  return findings;
}

function extractComments(html = '') {
  const comments = [];
  const re = /<!--[\s\S]*?-->/g;
  let match;
  while ((match = re.exec(html))) {
    const text = normalizeWhitespace(match[0].slice(4, -3));
    if (text) comments.push(text);
  }
  return comments;
}

function extractPageArtifacts({ html = '', url = '' } = {}) {
  return {
    url,
    title: extractTitle(html),
    canonicalUrl: extractCanonicalUrl(html, url),
    visibleText: extractVisibleText(html),
    links: extractLinks(html),
    forms: extractForms(html),
    images: extractImages(html),
    metaTags: extractMetaTags(html),
    hiddenText: extractHiddenText(html),
    comments: extractComments(html),
  };
}

export { ZERO_WIDTH_RE, decodeHtmlEntities, normalizeWhitespace, parseAttributes, extractVisibleText, extractLinks, extractForms, extractImages, extractMetaTags, extractHiddenText, extractComments, extractPageArtifacts, extract };

/**
 * Main entry point — normalizes extractor output to the shape expected by risk-scanner and packet-builder.
 * @param {string} html - Raw HTML
 * @param {string} url - Source URL
 * @returns {ExtractedPage}
 */
function extract(html, url) {
  const artifacts = extractPageArtifacts({ html, url });

  // Build key_claims from first few substantive sentences
  const text = artifacts.visibleText || '';
  const sentences = text
    .split(/[.!?]+/)
    .map(s => normalizeWhitespace(s))
    .filter(s => s.length > 30 && s.length < 300);

  const key_claims = sentences.slice(0, 5).map(s => ({
    claim: s,
    confidence: 'low',
    evidence_type: 'unverifiable',
    source_hop: 'unknown → page → AirLock scan',
    provenance_chain: 'unverified → memory: blocked',
  }));

  return {
    title: artifacts.title || '',
    canonical: artifacts.canonicalUrl || url,
    meta: Object.fromEntries(
      (artifacts.metaTags || []).map(m => [m.name || m.property || 'unknown', m.content]).filter(([k]) => k !== 'unknown')
    ),
    fullText: artifacts.visibleText || '',
    visible_text_summary: artifacts.visibleText ? artifacts.visibleText.slice(0, 500) : '',
    links: (artifacts.links || []).map(l => {
      let href = l.href || '';
      // Resolve relative URLs against base
      if (href && !href.startsWith('http') && url) {
        try { href = new URL(href, url).href; } catch { /* keep as-is */ }
      }
      return { href, text: l.text || '', title: '' };
    }),
    forms: (artifacts.forms || []).map(f => ({ fields: (f.controls || []).map(c => `${c.tag}:${c.type || 'text'}(${c.name || ''})`).join(', ') })),
    images: (artifacts.images || []).map(i => ({ src: i.src || '', alt: i.alt || '', title: i.title || '' })),
    hiddenText: (artifacts.hiddenText || []).map(h => ({ text: h.text, reason: (h.reasons || []).join(', '), element: h.tag })),
    scripts: [],
    codeBlocks: [],
    key_claims,
  };
}

/** @typedef {ReturnType<typeof extractPageArtifacts>} ExtractedRaw */
