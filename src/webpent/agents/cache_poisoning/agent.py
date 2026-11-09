"""Cache-poisoning detection (Phase-2 P2-302, F-12b).

Library-stage detector for cache-key confusion: builds header/param injection
probe pairs (``X-Forwarded-*``, ``X-Original-URL``, encoding variants) and
performs the two-request differential confirmation.

R4 re-freeze window (2026-11-02): :func:`cache_poisoning_node` wires the
detector into the LangGraph hunter chain per docs/CLAIMS_VS_REALITY_P2.md §
Revisit trigger. The node mirrors the ``request_smuggling_node`` contract:

* the target host is validated against the engagement-scope allowlist
  (``webpent.shared.engagement_scope``) BEFORE any connection — fail-closed;
* all HTTP goes through the SSRF-pinned transport
  (``webpent.shared.http.make_safe_httpx_client``);
* probes are pure data from this library; a ``Finding`` is constructed ONLY
  on the full two-request differential (canary in attack ∧ in a later victim
  response ∧ clean control stays clean ∧ control/victim shape equivalent) —
  anything else is inconclusive and reported as coverage, never confirmed;
* the emitted finding carries the library's ``promotion_guard`` and awaits
  the deterministic validator
  (``agents/validator/postp0_checks.validate_cache_poisoning``).

Safety: local benchmark targets only; nothing here contacts a target outside
the operator-declared engagement scope.
"""

from __future__ import annotations

import logging
from typing import Any
from urllib.parse import urlparse

from langchain_core.messages import AIMessage

from webpent.models.findings import Confidence, Finding, Severity, VulnClass
from webpent.state.state import PentestState

__all__ = ["build_cache_key_probes", "analyze_cache_differential", "cache_poisoning_node"]

logger = logging.getLogger(__name__)

# Cache-key confusion header families (name, clean value, attack value).
HEADER_PROBES: tuple[tuple[str, str, str], ...] = (
    ("X-Forwarded-Host", "benign.local", "cp-attacker.local"),
    ("X-Forwarded-Proto", "https", "javascript"),
    ("X-Original-URL", "/benign", "/cp-canary-path"),
    ("X-Rewrite-URL", "/benign", "/cp-canary-path"),
    ("X-Forwarded-Port", "443", "1337"),
)

PARAM_VARIANTS: tuple[str, ...] = (
    "utm_content=cp-canary",
    "utm_content=cp%2Dcanary",
    "utm_content[]=cp-canary",
    "utm_content=cp-canary.",
)


def build_cache_key_probes(endpoint_path: str) -> list[dict[str, Any]]:
    """Build two-request differential probes (attack + clean control).

    Each probe is a candidate structure: the attack request carries the
    confusion header/param; the control request is identical except the
    suspicious key. The differential between their responses is the evidence.
    """
    path = endpoint_path if endpoint_path.startswith("/") else f"/{endpoint_path}"
    probes: list[dict[str, Any]] = []
    for idx, (name, clean, attack) in enumerate(HEADER_PROBES):
        probes.append(
            {
                "probe_id": f"cp_hdr_{idx}",
                "kind": "header",
                "method": "GET",
                "path": path,
                "attack_request": {"headers": {name: attack}},
                "control_request": {"headers": {name: clean}},
                "expected_signal": "attack_value_reflected_on_uncached_or_second_victim",
            }
        )
    for idx, variant in enumerate(PARAM_VARIANTS):
        separator = "&" if "?" in path else "?"
        probes.append(
            {
                "probe_id": f"cp_param_{idx}",
                "kind": "param_variant",
                "method": "GET",
                "path": f"{path}{separator}{variant}",
                "attack_request": {},
                "control_request": {"strip_query": True},
                "expected_signal": "variant_resolves_to_same_cache_entry_as_clean",
            }
        )
    return probes


def analyze_cache_differential(
    victim_response: str,
    attack_response: str,
    control_response: str,
    canary: str = "cp-canary",
) -> dict[str, Any]:
    """Two-request differential confirmation (fail-closed).

    A poisoning candidate requires ALL of:
      1. the canary appears in the ATTACK response (the injection landed),
      2. the canary appears in a LATER VICTIM response served from cache,
      3. the CONTROL (clean-key) response does not contain it,
      4. control and victim are otherwise equivalent (same resource shape) —
         a victim that differs from control in more than the canary is
         reported as inconclusive, never as confirmed.
    """
    canary_in = lambda r: canary in r  # noqa: E731 — trivial predicate, kept local
    if not canary_in(attack_response):
        return {"poisoned": False, "reason": "canary_absent_from_attack_response"}
    if canary_in(control_response):
        return {"poisoned": False, "reason": "canary_present_in_clean_control"}
    if not canary_in(victim_response):
        return {"poisoned": False, "reason": "canary_absent_from_victim_response"}
    if control_response.replace(canary, "") == victim_response.replace(canary, ""):
        confidence = "differential_confirmed"
    else:
        confidence = "inconclusive_victim_shape_differs"
    return {
        "poisoned": confidence == "differential_confirmed",
        "confidence": confidence,
        "advisory_only": True,
        "promotion_guard": "blocked_missing_negative_control_and_proof_bundle",
        "evidence": {
            "attack_reflected": True,
            "victim_served_canary": True,
            "control_clean": True,
        },
    }


# ===========================================================================
# R4 wiring: LangGraph node (see module docstring for the safety contract)
# ===========================================================================

_MAX_CP_ENDPOINTS = 2


def cache_poisoning_node(state: PentestState) -> dict:
    """LangGraph node: detect cache-key confusion (cache poisoning).

    R4 re-freeze window (2026-11-02): wires the Phase-2 P2-302 library
    detector into the deep-probing chain. For a bounded set of endpoints
    the node replays each probe's three-request shape (clean-key control,
    attack request carrying the canary value, then a plain victim request
    served afterwards) and confirms ONLY on the full fail-closed
    differential.
    """
    target = state.get("target")
    session_cookies: dict[str, str] | None = state.get("session_cookies") or None

    base_url = getattr(target, "url", "")
    if not base_url:
        return {
            "messages": [AIMessage(content="Cache Poisoning Detector: no target URL — skipping.")],
            "current_phase": "cache_poisoning_detection",
        }

    logger.info("Cache Poisoning Detector (R4 wiring) entered for target=%s", base_url)

    parsed = urlparse(base_url)
    host = parsed.hostname
    if not host:
        return {
            "messages": [AIMessage(content="Cache Poisoning Detector: no host in URL — skipping.")],
            "current_phase": "cache_poisoning_detection",
        }

    # Fail-closed engagement-scope gate — the ONLY sanctioned path to any
    # network activity in this node. Mirrors request_smuggling_node.
    try:
        from webpent.shared.engagement_scope import is_engagement_target_host

        if not is_engagement_target_host(host):
            logger.warning(
                "Cache Poisoning: host %s is NOT in the engagement-scope "
                "allowlist — skipping differential probes (fail-closed SSRF gate).",
                host,
            )
            return {
                "messages": [
                    AIMessage(
                        content=(
                            f"Cache Poisoning: host {host} not in engagement scope — skipped (fail-closed SSRF gate)."
                        )
                    )
                ],
                "current_phase": "cache_poisoning_detection",
            }
    except ImportError:
        logger.warning(
            "Cache Poisoning: engagement_scope module not importable — skipping differential probes (fail-closed)."
        )
        return {
            "messages": [AIMessage(content="Cache Poisoning: scope check unavailable — skipped.")],
            "current_phase": "cache_poisoning_detection",
        }

    base_path = parsed.path or "/"
    new_findings: list[Finding] = []
    probe_coverage: list[dict[str, str]] = []

    try:
        from webpent.shared.http import build_cookie_header, make_safe_httpx_client

        cookie_header = build_cookie_header(session_cookies)
        root = f"{parsed.scheme}://{parsed.netloc}"
        paths = [base_path]
        # Bounded endpoint set: the base path is the primary candidate;
        # a second path may come from crawled_data when available.
        crawled = state.get("crawled_data") or {}
        crawled_urls = crawled.get("urls") if isinstance(crawled, dict) else None
        if isinstance(crawled_urls, list):
            for item in crawled_urls:
                if len(paths) >= _MAX_CP_ENDPOINTS:
                    break
                url = item if isinstance(item, str) else str(getattr(item, "url", "") or "")
                candidate = urlparse(url)
                if candidate.netloc == parsed.netloc and (candidate.path or "/") not in paths:
                    paths.append(candidate.path or "/")

        for path in paths:
            probes = build_cache_key_probes(path)
            try:
                with make_safe_httpx_client(timeout=10.0, follow_redirects=False, verify=True) as client:
                    request_headers = {"Cookie": cookie_header} if cookie_header else {}
                    confirmed_probe = None
                    confirm_evidence: dict[str, Any] = {}
                    for probe in probes:
                        if probe["kind"] == "header":
                            control_headers = dict(request_headers)
                            attack_headers = dict(request_headers)
                            for name, value in probe["control_request"]["headers"].items():
                                control_headers[name] = value
                            for name, value in probe["attack_request"]["headers"].items():
                                attack_headers[name] = value
                            probe_canary = next(iter(probe["attack_request"]["headers"].values()), "")
                            control_response = client.get(f"{root}{path}", headers=control_headers)
                            attack_response = client.get(f"{root}{path}", headers=attack_headers)
                            victim_response = client.get(f"{root}{path}", headers=request_headers)
                        else:
                            probe_canary = "cp-canary"
                            control_response = client.get(f"{root}{path}", headers=request_headers)
                            attack_response = client.get(f"{root}{probe['path']}", headers=request_headers)
                            victim_response = client.get(f"{root}{path}", headers=request_headers)
                        analysis = analyze_cache_differential(
                            victim_response.text[:2_000_000],
                            attack_response.text[:2_000_000],
                            control_response.text[:2_000_000],
                            canary=probe_canary,
                        )
                        if analysis.get("poisoned") is True:
                            confirmed_probe = probe
                            confirm_evidence = analysis
                            break
                probe_coverage.append({"probe": f"cp:{path}", "status": ("confirmed" if confirmed_probe else "clean")})
                if confirmed_probe is None:
                    continue

                finding = Finding(
                    title=f"Cache poisoning signal at {host}{path}",
                    description=(
                        "A cache-key confusion header/param injected a canary "
                        "value that was later served from cache to a plain "
                        "victim request, while the clean-key control stayed "
                        "canary-free and shape-equivalent. Web cache poisoning "
                        "lets an attacker store attacker-controlled content "
                        "for other users. Confirmation requires the "
                        "deterministic validator re-probe."
                    ),
                    severity=Severity.HIGH,
                    confidence=Confidence.TENTATIVE,
                    confidence_level="Needs Human Review",
                    vuln_class=VulnClass.CACHE_POISONING.value,
                    url=f"{root}{path}",
                    tool_name="cache_poisoning_detector",
                    payload=str(confirmed_probe.get("expected_signal", ""))[:2000],
                    evidence={
                        "causal_signal": True,
                        "negative_control_complete": True,
                        "proof_bundle": None,
                        "promotion_guard": ("blocked_missing_negative_control_and_proof_bundle"),
                        "probe_id": confirmed_probe["probe_id"],
                        "probe_kind": confirmed_probe["kind"],
                        "differential": confirm_evidence.get("evidence", {}),
                        "baseline_control": "clean-key request stayed canary-free",
                    },
                    reasoning=(
                        "Replayed the two-request differential with a clean-key "
                        "control, the attack request carrying the confusion "
                        "key, and a later plain victim request. The attack "
                        "value reached the victim response from cache while "
                        "the control stayed clean and shape-equivalent "
                        "(fail-closed differential)."
                    ),
                )
                new_findings.append(finding)
                logger.warning("Cache poisoning signal confirmed at %s%s", host, path)
            except Exception as exc:
                # Transport-level failures stay at debug (network errors are
                # expected against targets that close/rate-limit).
                probe_coverage.append({"probe": f"cp:{path}", "status": "blocked"})
                logger.debug("cp probe error for %s%s: %s", host, path, exc)
    except Exception as exc:
        probe_coverage.append({"probe": "cp", "status": "blocked"})
        logger.debug("Cache Poisoning probe error for %s: %s", host, exc)

    summary = (
        f"Cache Poisoning Detector: {len(new_findings)} signal(s) across "
        f"{len(probe_coverage)} endpoint(s); all probes scope-gated and bounded."
    )
    return {
        "messages": [AIMessage(content=summary)],
        "findings": new_findings,
        "current_phase": "cache_poisoning_detection",
    }
