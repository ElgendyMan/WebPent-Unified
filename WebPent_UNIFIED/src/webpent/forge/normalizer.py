"""U-FORGE-4 — The Normalizer.

One schema for every payload (THE FORGE spec, U-FORGE-4): stable
payload ids (sha256 of the raw string), five encoding variants, and
documented, deterministic arithmetic for family, complexity, tech
requirements and novelty. No randomness anywhere (FORGE-L-6).
"""
from __future__ import annotations

import base64
import hashlib
import html as html_mod
import urllib.parse

from webpent.forge.schemas import Family, NormalizedPayload, PayloadAttribution

# ---------------------------------------------------------------------------
# Published detection markers (reviewable arithmetic, not magic)
# ---------------------------------------------------------------------------

_FAMILY_MARKERS: list[tuple[Family, tuple[str, ...]]] = [
    (Family.SQLI, ("union select", " or 1=1", "1=1--", "sleep(", "waitfor",
                   "or '1'='1", "'--")),
    (Family.XSS, ("<script", "onload=", "onerror=", "javascript:", "<svg",
                  "<img src")),
    (Family.SSTI, ("{{", "{%", "<%=")),
    (Family.PATH_TRAVERSAL, ("../", "..\\", "%2e%2e")),
    (Family.LFI, ("file://", "/etc/passwd", "php://filter")),
    (Family.SSRF, ("127.0.0.1", "169.254.169.254", "metadata.google")),
    (Family.CMD_INJECTION, ("; ls", "| ls", "$(id)", "`id`", "; id")),
    (Family.XXE, ("<!doctype", "<!entity", "system \"file://")),
    (Family.OPEN_REDIRECT, ("//evil.com", "http://evil.com")),
    (Family.RCE, ("jndi:", "javax.script", "runtime.exec")),
]

# Family markers whose co-presence makes a payload a polyglot. HTML/JS
# structural markers plus SQL quoting markers in one string mean the
# payload speaks at least two syntaxes.
_POLYGLOT_GROUPS: list[tuple[str, tuple[str, ...]]] = [
    ("html", ("<", ">", "/>")),
    ("sql", ("'", "--", "1=1")),
    ("template", ("{{", "<%=", "${")),
    ("javascript", ("javascript:", "onload=", "onerror=")),
]

_TECH_MARKERS: list[tuple[str, tuple[str, ...]]] = [
    ("mysql", ("sleep(", "union select", "/*!", "information_schema")),
    ("mssql", ("waitfor", "xp_cmdshell")),
    ("postgres", ("pg_sleep", "pg_catalog")),
    ("oracle", ("dbms_", "utl_http")),
    ("php", ("php://", )),
    ("linux", ("/etc/passwd", )),
    ("windows", ("..\\", "cmd.exe", "powershell")),
]

# WAF fingerprint markers: bypass idioms known to target specific WAFs.
_WAF_MARKERS: list[tuple[str, tuple[str, ...]]] = [
    ("modsecurity", ("/**/", "%00")),
    ("mysql-native", ("/*!", )),
    ("iis", ("%00", "ASPX")),
]

_CONTEXT_MARKERS: list[tuple[str, tuple[str, ...]]] = [
    ("javascript", ("javascript:", "onload=", "onerror=", "<script")),
    ("html_body", ("<svg", "<img", "<iframe")),
    ("html_attribute", ("\"><", "'>", "\" on")),
    ("template", ("{{", "<%=", "${")),
]

_OBFUSCATION_MARKERS = ("char(", "0x", "chr(", "concat(", "%25", "\\u00")

# Payloads seen everywhere are not novel (L-2, L-5): a fixed, reviewed
# list of the most common ones, published so the deduction is
# checkable.
_COMMON_PATTERNS = (
    "' or 1=1--", "\" or \"1\"=\"1", "<script>alert(1)</script>",
    "../../etc/passwd", "admin'--", "' or '1'='1", "1' or '1'='1",
    "<svg onload=alert(1)>", "';--", "../..//", "%2e%2e%2f",
)

NOVELTY_BASE = 1.0
NOVELTY_COMMON_PENALTY = 0.3
COMPLEXITY_ADVANCED_THRESHOLD = 200


def detect_family(raw: str) -> Family:
    """First family whose markers appear (deterministic scan order)."""
    lowered = raw.lower()
    for family, markers in _FAMILY_MARKERS:
        if any(m in lowered for m in markers):
            return family
    return Family.SQLI  # corpus default for unmarked strings


def _detect_polyglot(raw: str) -> bool:
    lowered = raw.lower()
    groups_hit = sum(
        1 for _group, markers in _POLYGLOT_GROUPS
        if any(m in lowered for m in markers))
    return groups_hit >= 2


def _detect_complexity(raw: str, polyglot: bool) -> str:
    if polyglot or len(raw) >= COMPLEXITY_ADVANCED_THRESHOLD:
        return "expert"
    lowered = raw.lower()
    if any(m in lowered for m in _OBFUSCATION_MARKERS):
        return "advanced"
    if any(m in lowered for m in ("select", "script", "union")):
        return "moderate"
    return "simple"


def _extract(raw: str, table: list[tuple[str, tuple[str, ...]]]) -> list[str]:
    lowered = raw.lower()
    hits: list[str] = []
    for name, markers in table:
        if any(m in lowered for m in markers) and name not in hits:
            hits.append(name)
    return hits


def _score_novelty(raw: str) -> float:
    lowered = raw.lower()
    novelty = NOVELTY_BASE - (
        NOVELTY_COMMON_PENALTY
        * sum(1 for p in _COMMON_PATTERNS if p in lowered))
    return round(max(0.0, novelty), 4)


def _encodings(raw: str) -> dict[str, str]:
    return {
        "url": urllib.parse.quote(raw),
        "html": html_mod.escape(raw, quote=True),
        "hex": raw.encode().hex(),
        "unicode": "".join(
            f"\\u{ord(ch):04x}" if ord(ch) > 127 or ch in "\"'<>& " else ch
            for ch in raw),
        "base64": base64.b64encode(raw.encode()).decode(),
    }


class Normalizer:
    """Normalize a raw payload into the corpus schema."""

    def payload_id(self, raw: str) -> str:
        return hashlib.sha256(raw.encode()).hexdigest()[:16]

    def normalize(self, raw: str, attribution: PayloadAttribution,
                  family: Family | None = None,
                  subfamily: str = "") -> NormalizedPayload:
        if not raw.strip():
            raise ValueError("refusing to normalize an empty payload")
        payload_id = self.payload_id(raw)
        settled_family = family if family is not None else detect_family(raw)
        polyglot = _detect_polyglot(raw)
        attribution = PayloadAttribution(
            payload_id=payload_id,
            original_source=attribution.original_source,
            original_url=attribution.original_url,
            original_author=attribution.original_author,
            license=attribution.license,
            license_url=attribution.license_url,
            ingested_at=attribution.ingested_at,
            source_trust=attribution.source_trust,
            verified_by=attribution.verified_by,
        )
        quality = self.score_quality(attribution)
        novelty = _score_novelty(raw)
        return NormalizedPayload(
            payload_id=payload_id,
            family=settled_family,
            subfamily=subfamily,
            raw=raw,
            encoded_variants=_encodings(raw),
            target_tech=tuple(_extract(raw, _TECH_MARKERS)),
            target_waf=tuple(_extract(raw, _WAF_MARKERS)),
            target_context=tuple(_extract(raw, _CONTEXT_MARKERS)),
            complexity=_detect_complexity(raw, polyglot),
            source=attribution.original_source,
            attribution=attribution,
            quality_score=quality,
            novelty_score=novelty,
            is_polyglot=polyglot,
        )

    def score_quality(self, attribution: PayloadAttribution) -> float:
        """Trust-driven quality prior (gate refines it later, L-2)."""
        return round(attribution.source_trust, 4)
