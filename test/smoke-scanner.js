import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { extractPageArtifacts } from '../packages/scanner/src/extractor.js';
import { scanPatternLayer } from '../packages/scanner/src/risk-scanner/pattern-layer.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const fixturesDir = path.join(__dirname, 'fixtures');
const files = fs.readdirSync(fixturesDir).filter((file) => file.endsWith('.html'));

for (const file of files) {
  const html = fs.readFileSync(path.join(fixturesDir, file), 'utf8');
  const extracted = extractPageArtifacts({ html, url: `file://${file}` });
  const risk = scanPatternLayer({ extracted, rawHtml: html });
  console.log(`\n=== ${file} ===`);
  console.log(JSON.stringify({
    title: extracted.title,
    visibleTextPreview: extracted.visibleText.slice(0, 160),
    hiddenTextCount: extracted.hiddenText.length,
    linkCount: extracted.links.length,
    formCount: extracted.forms.length,
    riskLevel: risk.riskLevel,
    findings: risk.findings.map((item) => ({ type: item.type, subtype: item.subtype, severity: item.severity })).slice(0, 8),
  }, null, 2));
}
