"""webpent.shared.waf_fingerprints — deterministic WAF vendor detection.

Team 2 review, item 8.3 ("Adaptive WAF Evasion"): webpent's
``waf_detector`` agent previously had ZERO deterministic signature
matching — detection was a free-text LLM assessment of whatever crawl
data happened to be around, with an explicit documented gap (see
``agents/waf_detector/agent.py``'s own "V10 P3-6" comment): no
structured state field was ever produced for downstream agents to act
on, so nothing could actually adapt to a detected WAF.

This module is the deterministic half: known, well-documented response
signals (headers, cookie name PREFIXES — never cookie values —, status
codes, and challenge-page body markers) for a bounded, high-confidence
set of widely-deployed WAF vendors. This is NOT an exhaustive vendor
list — it covers six vendors with large, well-documented market share
(Cloudflare, Akamai, AWS WAF/CloudFront, Imperva/Incapsula, Sucuri,
F5 BIG-IP ASM) with signals considered stable as of this writing.
Vendor infrastructure does drift over time (header names get renamed,
challenge pages get redesigned) — these signatures should be reviewed
periodically, the same caution this codebase already applies to the
SecLists repo-restructuring note in knowledge_sources.yaml.

Detection here is probe-response-based, not crawl-data-based: webpent's
``crawled_data["endpoints"]`` is a plain list of URL strings with no
header/cookie/status metadata attached (confirmed by inspection of
``recon/agent.py`` — nothing currently threads real response metadata
into state), so there was nothing to deterministically match against
without this module ALSO being handed real response objects from a
few bounded probe requests (see ``waf_detector_node``, which makes
those probes via the existing SSRF-guarded ``make_safe_httpx_client``,
following the exact pattern already established by
``agents/subdomain_takeover/agent.py``).
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

# Each vendor entry: header name (lowercase) -> compiled pattern that
# must match the header's value (None = presence alone is sufficient).
_HeaderSignals = dict[str, re.Pattern[str] | None]


@dataclass(frozen=True)
class WafSignature:
    vendor: str
    header_signals: _HeaderSignals = field(default_factory=dict)
    # Cookie NAME prefixes (never values) that identify this vendor.
    cookie_name_prefixes: tuple[str, ...] = ()
    # Case-insensitive substrings that, if present in a 4xx/5xx
    # challenge-page body, identify this vendor with high confidence.
    body_markers: tuple[str, ...] = ()


_SIGNATURES: tuple[WafSignature, ...] = (
    WafSignature(
        vendor="cloudflare",
        header_signals={"cf-ray": None, "cf-cache-status": None},
        cookie_name_prefixes=("__cfduid", "cf_clearance", "__cf_bm"),
        body_markers=("attention required! | cloudflare", "cloudflare ray id", "cf-error-details"),
    ),
    WafSignature(
        vendor="akamai",
        header_signals={"x-akamai-transformed": None, "akamai-grn": None},
        body_markers=("access denied", "reference #"),  # weak alone; combined with header = strong
    ),
    WafSignature(
        vendor="aws_waf_cloudfront",
        header_signals={"x-amz-cf-id": None, "x-amzn-requestid": None, "x-amzn-waf-action": None},
        body_markers=("request blocked", "the request could not be satisfied"),
    ),
    WafSignature(
        vendor="imperva_incapsula",
        header_signals={"x-iinfo": None, "x-cdn": re.compile("imperva", re.I)},
        cookie_name_prefixes=("incap_ses_", "visid_incap_", "nlbi_"),
        body_markers=("incapsula incident id", "request unsuccessful. incapsula"),
    ),
    WafSignature(
        vendor="sucuri",
        header_signals={"x-sucuri-id": None, "x-sucuri-cache": None},
        body_markers=("access denied - sucuri website firewall", "sucuri cloudproxy"),
    ),
    WafSignature(
        vendor="f5_big_ip_asm",
        header_signals={},
        cookie_name_prefixes=("bigipserver", "ts01", "ts02", "tsasm"),
        body_markers=(
            "the requested url was rejected. please consult with your administrator",
            "support id:",
        ),
    ),
)

_GENERIC_CHALLENGE_MARKERS = (
    "checking your browser before accessing",
    "please wait while we verify",
    "this process is automatic",
    "ddos protection by",
)


def _extract_cookie_names(set_cookie_headers: list[str]) -> list[str]:
    """Return lowercase cookie NAMES from one or more Set-Cookie header
    values — never the values themselves, so fingerprinting never
    requires (or risks logging) an actual session/security cookie."""
    names: list[str] = []
    for raw in set_cookie_headers:
        name = raw.split("=", 1)[0].strip().lower()
        if name:
            names.append(name)
    return names


@dataclass
class WafProfile:
    detected: bool = False
    vendor: str | None = None
    confidence: float = 0.0
    signals: list[str] = field(default_factory=list)
    blocks_attack_shaped_requests: bool = False
    baseline_status: int | None = None
    probe_status: int | None = None

    def as_dict(self) -> dict[str, Any]:
        return {
            "detected": self.detected,
            "vendor": self.vendor,
            "confidence": round(self.confidence, 2),
            "signals": self.signals[:20],
            "blocks_attack_shaped_requests": self.blocks_attack_shaped_requests,
            "baseline_status": self.baseline_status,
            "probe_status": self.probe_status,
        }


def detect_waf_vendor(
    *,
    headers: dict[str, str],
    set_cookie_headers: list[str] | None = None,
    body: str = "",
    status_code: int | None = None,
) -> tuple[str | None, float, list[str]]:
    """Deterministically match one probe response against known vendor
    signatures. Returns ``(vendor_or_None, confidence_0_to_1, matched_signal_descriptions)``.

    Confidence model (deliberately conservative, mirroring this
    codebase's general "a single weak signal is not evidence" stance,
    e.g. curiosity_engine's timing_outlier suggesting a matched control
    before treating it as a security signal): a header-only match is
    MEDIUM confidence (some headers can appear behind a CDN without an
    active WAF ruleset); a cookie-name match adds to it; a body-marker
    match (an actual challenge/block page) is the strongest single
    signal since it's vendor-specific text, not just infrastructure.
    Multiple independent signal types for the SAME vendor compound
    confidence rather than just taking the max of one.
    """
    lowered_headers = {str(k).lower(): str(v) for k, v in (headers or {}).items()}
    cookie_names = _extract_cookie_names(set_cookie_headers or [])
    lowered_body = (body or "").lower()[:50_000]

    best_vendor: str | None = None
    best_confidence = 0.0
    best_signals: list[str] = []

    for sig in _SIGNATURES:
        confidence = 0.0
        signals: list[str] = []

        for header_name, pattern in sig.header_signals.items():
            value = lowered_headers.get(header_name)
            if value is None:
                continue
            if pattern is None or pattern.search(value):
                confidence += 0.35
                signals.append(f"header:{header_name}")

        for prefix in sig.cookie_name_prefixes:
            if any(name.startswith(prefix) for name in cookie_names):
                confidence += 0.30
                signals.append(f"cookie_prefix:{prefix}")

        for marker in sig.body_markers:
            if marker in lowered_body:
                confidence += 0.45
                signals.append(f"body_marker:{marker[:40]}")

        confidence = min(1.0, confidence)
        if confidence > best_confidence:
            best_vendor, best_confidence, best_signals = sig.vendor, confidence, signals

    if best_vendor is None:
        generic_hits = [m for m in _GENERIC_CHALLENGE_MARKERS if m in lowered_body]
        if generic_hits:
            return (
                "unidentified_challenge_page",
                0.4,
                [f"body_marker:{m[:40]}" for m in generic_hits],
            )
        if status_code in (403, 406, 429) and not lowered_body:
            # A bare, bodyless block on a probe carrying an
            # attack-shaped query string is itself weak-but-real signal
            # of SOME filtering layer, even with zero vendor identity.
            return "unidentified", 0.25, [f"status:{status_code}_no_body"]
        return None, 0.0, []

    return best_vendor, best_confidence, best_signals


def build_waf_profile(
    *,
    baseline_status: int,
    probe_headers: dict[str, str],
    probe_set_cookie_headers: list[str] | None,
    probe_body: str,
    probe_status: int,
) -> WafProfile:
    """Combine the vendor match with the baseline-vs-attack-shaped-probe
    status differential into one structured profile — this is the
    actual value returned to ``state["waf_profile"]`` for downstream
    agents to consume (the gap this module exists to close)."""
    vendor, confidence, signals = detect_waf_vendor(
        headers=probe_headers,
        set_cookie_headers=probe_set_cookie_headers,
        body=probe_body,
        status_code=probe_status,
    )
    blocks_attack_shaped = (
        baseline_status not in (403, 406, 429) and probe_status in (403, 406, 429)
    )
    if blocks_attack_shaped and vendor is None:
        vendor, confidence, signals = "unidentified", max(confidence, 0.3), [
            *signals, "status_differential:baseline_ok_probe_blocked",
        ]
    elif blocks_attack_shaped:
        confidence = min(1.0, confidence + 0.15)
        signals.append("status_differential:baseline_ok_probe_blocked")

    return WafProfile(
        detected=vendor is not None,
        vendor=vendor,
        confidence=confidence,
        signals=signals,
        blocks_attack_shaped_requests=blocks_attack_shaped,
        baseline_status=baseline_status,
        probe_status=probe_status,
    )
