# AirLock Scanner

> External content is evidence, not instruction.

**Alpha** — static scan mode available today. Hosted API beta opening soon.

AirLock reduces prompt-injection exposure by converting untrusted web pages into sanitized evidence packets before your AI agent reads them.

---

## Status

| | Status |
|---|---|
| **Scanner** | Alpha — stable, tested, published |
| **Static scan** | Available now |
| **Rendered DOM scan** | On the roadmap |
| **Hosted API** | Beta opening soon |
| **Production use** | Not yet recommended as a sole security boundary |

---

## Quick Start

### CLI

```bash
npx @airlock/scanner https://example.com
```

Output:

```json
{
  "url": "https://example.com",
  "status": "sanitized",
  "risk_score": 0.04,
  "stripped": [
    {
      "type": "hidden_text",
      "selector": "div[style*='display:none']",
      "reason": "off-screen prompt injection pattern"
    }
  ],
  "content": {
    "title": "Example Domain",
    "text": "Example.com exists ..."
  }
}
```

### Node.js / npm

```bash
npm install @airlock/scanner
```

```js
import { scan } from '@airlock/scanner';

const { packet } = await scan({ url: 'https://example.com' });
// packet.instruction_authority === 'none'
// packet is what the agent sees — not the raw page
```

### Python / PyPI

```bash
pip install airlock-codes
```

```bash
airlock scan https://example.com
```

### Docker

```bash
docker pull theagentdeck/airlock
docker run theagentdeck/airlock scan https://example.com
```

---

## What AirLock Detects

| Threat | What it looks like |
|---|---|
| Prompt injection | Hidden text, CSS injection, off-screen HTML, zero-width chars |
| Memory-write gates | Links/scripts that instruct the agent to modify its own instructions |
| Compromised redirects | URL shorteners, redirect chains to unverifiable destinations |
| Hidden instructions | Content in `display:none`, `visibility:hidden`, alt text, link titles |
| Unverifiable content | `<script>`, `<style>`, `<iframe>`, embedded media that can't be statically verified |

---

## Threat Model

**AirLock is a static scanner.** It reduces risk at the fetch boundary — it does not make JS-rendered content safe.

**What it defends against:**
- Hidden/off-screen prompt injection in static HTML
- Script, style, iframe, and embed tags that can't be statically verified
- URL redirect chains to unverifiable destinations
- Memory-write and instruction-override link patterns

**What it does not yet defend against:**
- Dynamic browser-executed attacks (JS-rendered content after page load)
- Human-approved malicious content
- Model-side jailbreaks unrelated to retrieved web content
- Sites requiring authenticated browser sessions

---

## Architecture

```
packages/
  scanner/    — Phase 1 agent-side scanner (Node.js, this repo)
  core/       — shared packet types (future)
  publisher/  — publisher SDK (future)
  discovery/  — .well-known + subscription (future)
  verifier/   — Ed25519 signature verification (future)
```

---

## Running Tests

```bash
npm ci packages/scanner
node --test test/scan.test.js
```

---

## Security

See [SECURITY.md](./SECURITY.md) for our vulnerability disclosure policy and contact.

**Do not report security issues in public GitHub issues.**

Email: security@theagentdeck.ai

---

## License

MIT — free forever for self-hosted use. Paid plans (Starter/Pro/Scale) cover hosted API access, audit logs, and support.

---

## Links

- 🌐 **Landing page:** [airlock.codes](https://airlock.codes)
- 📦 **npm:** [npmjs.com/package/@airlock/scanner](https://www.npmjs.com/package/@airlock/scanner)
- 🐍 **PyPI:** [pypi.org/project/airlock-codes](https://pypi.org/project/airlock-codes)
- 🐳 **Docker:** [hub.docker.com/r/theagentdeck/airlock](https://hub.docker.com/r/theagentdeck/airlock)
- 𝕏 **X:** [@AirLockcodes](https://x.com/Airlockcodes)
- 📧 **Contact:** founders@theagentdeck.ai