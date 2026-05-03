#!/usr/bin/env python3
"""
AirLock CLI — `python -m airlock scan <url>`
"""

import sys
import json
from .core import scan_text_for_injections, build_packet, classify_url_risk


def main():
    args = sys.argv[1:]

    if not args or args[0] in ("--help", "-h", "help"):
        print("""
TheAgentDeck AirLock CLI

Usage:
  python -m airlock scan <url>      Scan a URL and print the evidence packet
  python -m airlock scan <url> --json   Output raw JSON

Example:
  python -m airlock scan https://example.com/forum/thread
""")
        sys.exit(0)

    subcommand = args[0]

    if subcommand == "scan":
        url = args[1] if len(args) > 1 else None
        if not url:
            print("Error: URL required")
            print("Usage: airlock scan <url> [--json]")
            sys.exit(1)

        is_json = "--json" in args

        from datetime import datetime, timezone
        from urllib.request import urlopen
        from urllib.error import URLError

        try:
            resp = urlopen(url, timeout=10)
            html = resp.read().decode("utf-8", errors="ignore")
        except URLError as e:
            print(f"Error fetching {url}: {e}")
            sys.exit(1)

        # Extract title
        title = ""
        if "<title" in html.lower():
            import re
            m = re.search(r"<title[^>]*>([^<]+)</title>", html, re.IGNORECASE)
            if m:
                title = m.group(1).strip()

        # Extract visible text
        import re
        text = re.sub(r"<[^>]+>", " ", html)
        text = re.sub(r"\s+", " ", text).strip()[:5000]

        # Scan for injections
        suspicious = scan_text_for_injections(text)

        # Check for hidden elements
        from .core import scan_hidden_elements
        hidden_findings = scan_hidden_elements(html)
        suspicious.extend(hidden_findings)

        # Classify links
        links = []
        link_pattern = re.compile(r'href=["\']([^"\']+)["\']', re.IGNORECASE)
        for match in link_pattern.finditer(html):
            url_link = match.group(1)
            if url_link.startswith("http"):
                risk_info = classify_url_risk(url_link)
                links.append({
                    "url": url_link,
                    "allowed": risk_info["allowed"],
                    "risk": risk_info["risk"],
                    "reason": risk_info["reason"],
                })

        now = datetime.now(timezone.utc).isoformat()

        packet = build_packet(
            url=url,
            fetched_at=now,
            packet_origin="scanner",
            source_type="public_page",
            extracted={"title": title, "text": text},
            suspicious=suspicious,
            links=links[:20],  # limit to 20
            forms=[],
            memory_write=False,
        )

        if is_json:
            print(json.dumps(packet, indent=2))
        else:
            print_summary(packet)


def print_summary(packet):
    print("\n🔒 TheAgentDeck AirLock — Evidence Packet\n")
    print(f"  URL:       {packet['url']}")
    print(f"  Origin:    {packet['packet_origin']}")
    print(f"  Risk:      {packet['page_risk']}")
    print(f"  Trust:     {packet['trust_level']}")
    print(f"  Source:    {packet['source_type']}")
    print(f"  Policy:    ext_auth={packet['agent_instruction_policy']['external_content_has_authority']}, memory_write={packet['agent_instruction_policy']['memory_write_allowed']}\n")

    if packet["suspicious_content"]:
        print("  🚨 Suspicious Content:")
        for s in packet["suspicious_content"]:
            text = s["text"]
            if len(text) > 80:
                text = text[:80] + "…"
            print(f"    [{s['severity'].upper()}] {s['type']}: \"{text}\"")
            print(f"    → {s['mitigation']}")
        print("")
    else:
        print("  ✅ No suspicious content detected\n")

    print(f"  📄 Title: {packet['extracted_content']['title'] or '(none)'}")
    summary = packet['extracted_content']['visible_text_summary']
    print(f"  📝 Summary: {summary[:200]}{'…' if len(summary) > 200 else ''}\n")

    if packet["links"]:
        risky = [l for l in packet["links"] if not l["allowed"]]
        if risky:
            print(f"  ⚠️  Risky Links ({len(risky)}):")
            for l in risky[:5]:
                print(f"    {l['reason']}: {l['url']}")
            print("")

    print(f"  🛡️  Allowed sinks:  {', '.join(packet['allowed_sinks']) or '(none)'}")
    print(f"  🚫 Blocked sinks:  {', '.join(packet['blocked_sinks']) or '(none)'}\n")
    print(f"  💡 {packet['recommendation']}\n")
    print(f"  Packet ID: {packet['scan_id']} | Hash: {packet['packet_hash'][:16]}…\n")


if __name__ == "__main__":
    main()