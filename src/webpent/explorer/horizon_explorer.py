"""Proposal 2 — Unlimited Horizon Explorer + Contextual Hypothesis Generator.

Three components that let the hunter discover attack surface beyond the
pre-programmed scenario catalog:

1. ``DynamicBehaviorAnalyzer`` — compares responses to mutated requests;
   flags params/endpoints that behave anomalously and generates test
   hypotheses on the fly.
2. ``AttackSurfaceExpander`` — extracts new endpoints/params from error
   messages, redirects, response bodies. Each discovered endpoint carries a
   confidence score by source; static assets are filtered.
3. ``CreativeHypothesisGenerator`` — combines observed capabilities into
   hybrid attack scenarios that exist in NO catalog. Supports single-capability
   patterns and a deep_exploration mode that treats anomalies as capabilities.

All outputs are hypotheses only (candidate-level) — never promoted without
causal validation.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

_URL_RE = re.compile(r"https?://[^\s\"'<>]+")
_PATH_RE = re.compile(r"(?:/api/|/v\d+/|/internal/|/admin/)[^\s\"'<>]+")
_PARAM_RE = re.compile(r"[?&]([a-zA-Z_][a-zA-Z0-9_]{2,})=")

# Static assets to filter out of discovered endpoints (noise).
_STATIC_EXTENSIONS = re.compile(r"\.(css|js|png|jpe?g|gif|svg|ico|woff2?|ttf|eot|map|mp4|webp)(\?|$)", re.I)

# Confidence by discovery source.
_SOURCE_CONFIDENCE = {
    "error_message": 0.8,
    "location_header": 0.9,
    "form_action": 0.85,
    "response_body_link": 0.6,
    "redirect_chain": 0.75,
}


@dataclass
class Anomaly:
    endpoint: str
    param: str
    signal: str  # "status_diff" | "timing_diff" | "error_diff" | "state_change"
    hypothesis: str


class DynamicBehaviorAnalyzer:
    """Detects anomalous behavior from response deltas — no fixed rules."""

    def analyze(self, baseline: dict[str, Any], mutated: dict[str, Any]) -> list[Anomaly]:
        anomalies: list[Anomaly] = []
        ep = str(mutated.get("endpoint", "/unknown"))
        param = str(mutated.get("param", "unknown"))
        b_status = int(baseline.get("status_code", 0) or 0)
        m_status = int(mutated.get("status_code", 0) or 0)
        if b_status and m_status and b_status != m_status:
            anomalies.append(Anomaly(ep, param, "status_diff",
                f"status changed {b_status}->{m_status} when {param} mutated — possible missing validation"))
        b_time = float(baseline.get("elapsed_ms", 0) or 0)
        m_time = float(mutated.get("elapsed_ms", 0) or 0)
        if b_time and m_time and m_time > b_time * 5:
            anomalies.append(Anomaly(ep, param, "timing_diff",
                f"response slowed {b_time:.0f}->{m_time:.0f}ms when {param} mutated — possible blind injection / heavy operation"))
        b_err = str(baseline.get("error", "") or "")
        m_err = str(mutated.get("error", "") or "")
        if m_err and m_err != b_err and any(k in m_err.lower() for k in ("sql", "syntax", "stack", "trace", "internal")):
            anomalies.append(Anomaly(ep, param, "error_diff",
                f"verbose error revealed when {param} mutated: {m_err[:80]}"))
        return anomalies


class AttackSurfaceExpander:
    """Extracts new endpoints/params from responses — grows the surface.
    Each discovered endpoint carries a confidence score by source. Static
    assets are filtered out."""

    def _classify(self, url: str, source: str) -> dict[str, Any]:
        return {"url": url, "source": source, "confidence": _SOURCE_CONFIDENCE.get(source, 0.5)}

    def expand(self, responses: list[dict[str, Any]]) -> dict[str, list[str]]:
        """Backward-compatible: returns plain endpoint/param lists (filtered)."""
        detailed = self.expand_with_confidence(responses)
        return {
            "new_endpoints": [e["url"] for e in detailed["endpoints"]],
            "new_params": sorted(detailed["params"]),
        }

    def expand_with_confidence(self, responses: list[dict[str, Any]]) -> dict[str, Any]:
        """Returns endpoints with source + confidence, filtered of static noise."""
        endpoints: dict[str, dict[str, Any]] = {}
        params: set[str] = set()
        for resp in responses:
            body = str(resp.get("body", "") or "")
            location = str(resp.get("location", "") or "")
            source = "location_header" if location else ("error_message" if resp.get("error") else "response_body_link")
            for text, src in ((body, source), (location, "location_header")):
                for m in _URL_RE.findall(text):
                    if _STATIC_EXTENSIONS.search(m):
                        continue
                    if m not in endpoints:
                        endpoints[m] = self._classify(m, src)
                    else:
                        endpoints[m]["confidence"] = max(endpoints[m]["confidence"], _SOURCE_CONFIDENCE.get(src, 0.5))
                for m in _PATH_RE.findall(text):
                    p = m.rstrip(".,;)")
                    if _STATIC_EXTENSIONS.search(p):
                        continue
                    if p not in endpoints:
                        endpoints[p] = self._classify(p, src)
                for m in _PARAM_RE.findall(text):
                    params.add(m)
        sorted_eps = sorted(endpoints.values(), key=lambda e: -e["confidence"])
        return {"endpoints": sorted_eps, "params": sorted(params)}


# Hybrid patterns requiring TWO capabilities.
_HYBRID_PATTERNS: list[tuple[str, str, str]] = [
    ("file_upload_allowed", "direct_object_reference", "upload svg containing reference to another user's object; read it on preview → stored XSS / IDOR chain"),
    ("rate_limit_bypass", "otp_or_reset_flow", "race the reset flow with burst → OTP brute force via race window"),
    ("oauth_redirect_bypass", "open_redirect", "chain open-redirect into OAuth state theft → account takeover"),
    ("mass_assignment_allowed", "role_param_present", "tamper role field on write → privilege escalation without auth bypass"),
    ("cors_misconfigured", "sensitive_endpoint", "exfiltrate data via CORS-allowed origin → data leak chain"),
    ("ssrf_allowed", "internal_endpoint_discovered", "SSRF into newly discovered internal endpoint → metadata credential theft"),
]

# Single-capability patterns — one capability + a generic system property.
_SINGLE_CAPABILITY_PATTERNS: list[tuple[str, str]] = [
    ("file_upload_allowed", "system renders uploaded content inline → upload SVG with script → stored XSS via preview"),
    ("verbose_errors_enabled", "error messages leak stack traces → fingerprint framework + find hidden endpoints"),
    ("cors_misconfigured", "any authenticated endpoint → exfiltrate via victim browser → data leak"),
    ("rate_limit_bypass", "any write endpoint → brute force enumeration / resource exhaustion"),
    ("ssrf_allowed", "cloud metadata endpoint → credential theft → full account takeover"),
    ("anomalous_behavior_detected", "param causes unusual response delay → probe for blind injection / heavy operation"),
]


class CreativeHypothesisGenerator:
    """Combines observed capabilities into hybrid attack scenarios. Supports
    single-capability patterns and a deep_exploration mode that treats
    detected anomalies as capabilities."""

    def generate(self, observed_capabilities: set[str], *, deep_exploration: bool = False) -> list[dict[str, Any]]:
        hyps: list[dict[str, Any]] = []
        caps = set(observed_capabilities)
        if deep_exploration:
            caps.add("anomalous_behavior_detected")
        for cap_a, cap_b, description in _HYBRID_PATTERNS:
            if cap_a in caps and cap_b in caps:
                hyps.append({
                    "hypothesis_id": f"hybrid-{cap_a}-{cap_b}",
                    "requires": [cap_a, cap_b],
                    "description": description,
                    "confidence": "speculative",
                    "source": "creative_hypothesis_generator",
                })
        for cap, description in _SINGLE_CAPABILITY_PATTERNS:
            if cap in caps:
                hyps.append({
                    "hypothesis_id": f"single-{cap}",
                    "requires": [cap],
                    "description": description,
                    "confidence": "speculative",
                    "source": "creative_hypothesis_generator",
                })
        return hyps


__all__ = [
    "Anomaly",
    "AttackSurfaceExpander",
    "CreativeHypothesisGenerator",
    "DynamicBehaviorAnalyzer",
]
