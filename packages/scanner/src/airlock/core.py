"""
AirLock Python Scanner
Source-to-sink firewall for agentic web browsing
"""

import re
import hashlib
import uuid
from datetime import datetime, timezone
from typing import Optional

ALLOWED_SINKS = [
    "summarize",
    "classify",
    "quote_with_citation",
    "add_to_temp_research_notes",
]

BLOCKED_SINKS = [
    "send_email",
    "post_to_social",
    "update_database",
    "update_listing",
    "create_memory",
    "run_code",
    "call_payment_api",
    "reveal_internal_context",
    "navigate_to_url",
    "fill_form",
    "submit_form",
]

INJECTION_PATTERNS = [
    (re.compile(r"ignore\s+all\s+previous\s+instructions", re.IGNORECASE), "prompt_injection", "high"),
    (re.compile(r"ignore\s+prior\s+(instructions?|rules?|directives?)", re.IGNORECASE), "prompt_injection", "high"),
    (re.compile(r"disregard\s+(your|all)\s+(instructions?|rules?)", re.IGNORECASE), "prompt_injection", "high"),
    (re.compile(r"(system|assistant)\s+prompt", re.IGNORECASE), "system_prompt_reference", "medium"),
    (re.compile(r"reveal|copy-paste.*system", re.IGNORECASE), "system_prompt_reference", "high"),
    (re.compile(r"send\s+(your|this)\s+(api\s*key|password|secret|token)", re.IGNORECASE), "credential_request", "critical"),
    (re.compile(r"you\s+(are|have\s+been).*(smart|intelligent|genius)", re.IGNORECASE), "flattery", "medium"),
    (re.compile(r"urgent(ly)?\s+now", re.IGNORECASE), "urgency", "medium"),
]

HIDDEN_ELEMENTS_PATTERNS = [
    re.compile(r"display\s*:\s*none", re.IGNORECASE),
    re.compile(r"visibility\s*:\s*hidden", re.IGNORECASE),
    re.compile(r"opacity\s*:\s*0", re.IGNORECASE),
    re.compile(r"width\s*:\s*1px", re.IGNORECASE),
    re.compile(r"height\s*:\s*1px", re.IGNORECASE),
    re.compile(r"position\s*:\s*absolute", re.IGNORECASE),
]

SHORTENER_DOMAINS = [
    "bit.ly", "goo.gl", "tinyurl.com", "t.co", "ow.ly",
    "is.gd", "buff.ly", "adf.ly", "tiny.cc", "short.to",
]

TRUST_LEVEL_BY_SOURCE = {
    "search_engine": "low",
    "social_media": "low",
    "forum": "low",
    "blog": "medium",
    "news": "medium",
    "documentation": "high",
    "government": "high",
    "academic": "high",
}


def compute_page_risk(suspicious: list) -> str:
    if not suspicious:
        return "low"
    severities = [s["severity"] for s in suspicious]
    if "critical" in severities:
        return "critical"
    if "high" in severities:
        return "high"
    if "medium" in severities:
        return "medium"
    return "low"


def infer_trust_level(source_type: str, page_risk: str, suspicious: list) -> str:
    base = TRUST_LEVEL_BY_SOURCE.get(source_type, "low")
    if page_risk in ("critical", "high"):
        return "low"
    return base


def scan_text_for_injections(text: str) -> list:
    findings = []
    for pattern, kind, severity in INJECTION_PATTERNS:
        matches = pattern.findall(text)
        for match in matches:
            findings.append({
                "type": kind,
                "severity": severity,
                "text": match if len(match) <= 200 else match[:200] + "...",
                "mitigation": "stripped from agent instruction context",
                "lane": "potential_instructions",
            })
    return findings


def scan_hidden_elements(html: str) -> list:
    findings = []
    for pattern in HIDDEN_ELEMENTS_PATTERNS:
        if pattern.search(html):
            findings.append({
                "type": "hidden_instruction",
                "severity": "medium",
                "text": f"hidden element detected via CSS: {pattern.pattern}",
                "mitigation": "isolated and flagged for review",
                "lane": "hidden_text",
            })
    return findings


def classify_url_risk(url: str) -> dict:
    from urllib.parse import urlparse
    try:
        parsed = urlparse(url)
        domain = parsed.netloc.lower()
        for short in SHORTENER_DOMAINS:
            if short in domain:
                return {"risk": "high", "reason": "shortened URL — redirect chain unresolved", "allowed": False}
        if domain.startswith(("http://", "https://")):
            return {"risk": "low", "reason": "standard URL", "allowed": True}
    except Exception:
        pass
    return {"risk": "medium", "reason": "URL could not be parsed", "allowed": False}


def build_packet(
    url: str,
    fetched_at: str,
    packet_origin: str,
    source_type: str,
    extracted: dict,
    suspicious: list,
    links: list,
    forms: list,
    memory_write: bool,
    publisher_signature: Optional[str] = None,
    publisher_verified: bool = False,
) -> dict:
    page_risk = compute_page_risk(suspicious)
    trust_level = infer_trust_level(source_type, page_risk, suspicious)

    packet = {
        "airlock_version": "1.0",
        "packet_origin": packet_origin,
        "url": url,
        "fetched_at": fetched_at,
        "source_type": source_type,
        "trust_level": trust_level,
        "page_risk": page_risk,
        "publisher_signature": publisher_signature,
        "publisher_verified": publisher_verified,
        "agent_instruction_policy": {
            "external_content_has_authority": False,
            "tool_calls_allowed_from_page": False,
            "memory_write_allowed": memory_write,
            "outbound_links_require_review": True,
        },
        "extracted_content": {
            "title": extracted.get("title", ""),
            "visible_text_summary": extracted.get("text", "")[:5000],
            "key_claims": extracted.get("claims", []),
        },
        "suspicious_content": suspicious,
        "links": links,
        "forms": forms,
        "blocked_sinks": BLOCKED_SINKS,
        "allowed_sinks": ALLOWED_SINKS,
        "recommendation": _build_recommendation(page_risk, trust_level, suspicious),
        "scan_id": str(uuid.uuid4()),
        "packet_hash": "",
    }

    packet["packet_hash"] = hashlib.sha256(
        str(packet).encode("utf-8")
    ).hexdigest()

    return packet


def _build_recommendation(page_risk: str, trust_level: str, suspicious: list) -> str:
    if page_risk == "critical":
        return "Block all agent interactions with this page. Evidence packet logged for Noriko review."
    if page_risk == "high":
        return "Treat as unverified. Summarize only with explicit citation. Memory promotion blocked."
    if trust_level == "high" and page_risk == "low":
        return "Treat as evidence with standard citation. Memory promotion requires context note."
    return "Treat as unverified anecdotal evidence. Do not promote to memory without Noriko review."