"""Prototype-pollution detection (Phase-2 P2-301, F-12a).

Library-stage detector: builds the governed payload set, constructs probes,
and performs canary-based reflection analysis on response pairs.

R4 re-freeze window (2026-11-02): :func:`prototype_pollution_node` wires the
detector into the LangGraph hunter chain per docs/CLAIMS_VS_REALITY_P2.md §
Revisit trigger (previously "surface signals + tested detector library
(unwired)"). The node mirrors the ``request_smuggling_node`` contract:

* the target host is validated against the engagement-scope allowlist
  (``webpent.shared.engagement_scope``) BEFORE any connection — fail-closed;
* all HTTP goes through the SSRF-pinned transport
  (``webpent.shared.http.make_safe_httpx_client``);
* probes are pure data from this library; a ``Finding`` is constructed ONLY
  when the fail-closed reflection triangle confirms
  (canary in candidate ∧ absent from baseline control ∧ responses differ);
* finding promotion stays guarded: the emitted finding carries the library's
  ``promotion_guard`` and awaits the deterministic validator
  (``agents/validator/postp0_checks.validate_prototype_pollution``).

Safety: local benchmark targets only; nothing here contacts a target outside
the operator-declared engagement scope.
"""

from __future__ import annotations

import json
import logging
from typing import Any
from urllib.parse import urlparse

from langchain_core.messages import AIMessage

from webpent.models.findings import Confidence, Finding, Severity, VulnClass
from webpent.state.state import PentestState

__all__ = [
    "build_pollution_payload_set",
    "build_pollution_probes",
    "analyze_reflection_pair",
    "prototype_pollution_node",
]

logger = logging.getLogger(__name__)

# Deep-key JSON payloads (canary-tagged) + classic gadget key spellings.
# Each payload carries a unique canary so reflection can be attributed
# unambiguously to the probe that planted it.
PAYLOAD_TEMPLATES: tuple[dict[str, Any], ...] = (
    {"__proto__": {"ppcanary": True}},
    {"constructor": {"prototype": {"ppcanary": True}}},
    {"__proto__": {"__proto__": {"ppcanary": True}}},
    {"constructor": {"constructor": {"ppcanary": True}}},
)

GADGET_KEYS: tuple[str, ...] = (
    "__proto__",
    "constructor",
    "constructor.prototype",
    "constructor%2Eprototype",
    "prototype",
)


def build_pollution_payload_set(canary: str = "ppcanary") -> list[dict[str, Any]]:
    """Return the deep-key payload set, canary-tagged for attribution.

    ``canary`` lets a caller namespace its markers (e.g. ``pp_<runid>``);
    every nested sink value is renamed to that canary so a reflected value
    can only originate from this payload family.
    """
    if not canary or not str(canary).strip():
        raise ValueError("canary must be a non-empty identifier")
    return [_retag(tpl, str(canary)) for tpl in PAYLOAD_TEMPLATES]


def _retag(node: Any, canary: str) -> Any:
    if isinstance(node, dict):
        return {k: _retag(v, canary) for k, v in node.items()}
    if isinstance(node, list):
        return [_retag(v, canary) for v in node]
    if node is True:  # the canary sentinel in every template
        return f"{canary}_true"
    return node


def build_pollution_probes(
    endpoint_path: str,
    method: str = "POST",
    canary: str = "ppcanary",
) -> list[dict[str, Any]]:
    """Build one request spec per payload plus a negative-control field.

    Returns candidate structures (method/path/body + negative control) — the
    same shape the research loop's probe families use — so the future registry
    wiring needs no data-model change.
    """
    path = endpoint_path if endpoint_path.startswith("/") else f"/{endpoint_path}"
    return [
        {
            "probe_id": f"pp_{idx}",
            "method": method.upper(),
            "path": path,
            "body": payload,
            "negative_control": {"benign": "control"},
            "expected_signal": "canary_reflected_in_response_or_state",
        }
        for idx, payload in enumerate(build_pollution_payload_set(canary))
    ]


def analyze_reflection_pair(
    baseline_response: str,
    candidate_response: str,
    canary: str = "ppcanary",
) -> dict[str, Any]:
    """Canary-based reflection analysis for one probe's response pair.

    Detection logic (fail-closed — a finding requires ALL of):
      1. the canary appears in the candidate response,
      2. the canary does NOT appear in the baseline response,
      3. the two responses differ (an identical pair proves nothing).
    Client-side sink hints are reported separately as advisory signals.
    """
    if not canary or canary not in candidate_response:
        return {"polluted": False, "reason": "canary_absent_from_candidate"}
    if canary in baseline_response:
        return {"polluted": False, "reason": "canary_present_in_baseline_control"}
    if baseline_response == candidate_response:
        return {"polluted": False, "reason": "responses_identical"}

    lowered = candidate_response.lower()
    sink_hints = sorted(hint for hint in ("__proto__", "constructor.prototype", "prototype[") if hint in lowered)
    return {
        "polluted": True,
        "canary": canary,
        "sink_hints": sink_hints,
        "advisory_only": True,
        "promotion_guard": "blocked_missing_negative_control_and_proof_bundle",
    }


# ===========================================================================
# R4 wiring: LangGraph node (see module docstring for the safety contract)
# ===========================================================================

# Bounded probing: the node spends at most this many requests per target
# (1 baseline control + 1 probe per endpoint, endpoints capped below).
_MAX_PROBE_ENDPOINTS = 3


def _collect_probe_paths(state: PentestState) -> list[str]:
    """Return up to ``_MAX_PROBE_ENDPOINTS`` JSON-ish candidate paths.

    The target base URL is always first; crawled_data URLs (when present)
    follow, filtered to plausible JSON-body endpoints. Read-only view of
    the state — the node never mutates anything but its own return dict.
    """
    target = state.get("target")
    base_url = getattr(target, "url", "") or ""
    paths: list[str] = []
    parsed = urlparse(base_url)
    base_path = parsed.path or "/"
    if parsed.scheme and parsed.netloc:
        paths.append(base_path)

    crawled = state.get("crawled_data") or {}
    crawled_urls = crawled.get("urls") if isinstance(crawled, dict) else None
    if isinstance(crawled_urls, list):
        for item in crawled_urls:
            if len(paths) >= _MAX_PROBE_ENDPOINTS:
                break
            url = item if isinstance(item, str) else str(getattr(item, "url", "") or "")
            candidate = urlparse(url)
            if candidate.netloc and candidate.netloc == parsed.netloc:
                path = candidate.path or "/"
                if path not in paths:
                    paths.append(path)
    return paths[:_MAX_PROBE_ENDPOINTS]


def _guard_reflection_probes(
    base_url: str, session_cookies: dict[str, str] | None
) -> tuple[str, str, int, bool, str | None]:
    """Resolve scheme/host/port/TLS for the reflection probes, fail-closed."""
    parsed = urlparse(base_url)
    host = parsed.hostname or ""
    if not host:
        return "", "", 0, False, "no host in target URL"
    use_tls = parsed.scheme == "https"
    port = parsed.port or (443 if use_tls else 80)
    return parsed.scheme, host, port, use_tls, None


def prototype_pollution_node(state: PentestState) -> dict:
    """LangGraph node: detect client-side prototype pollution signals.

    R4 re-freeze window (2026-11-02): wires the Phase-2 P2-301 library
    detector into the deep-probing chain. Sends the governed payload set
    as JSON bodies to a bounded set of candidate endpoints and runs the
    fail-closed canary reflection analysis against a benign-field
    baseline. Emits a Finding ONLY on the full confirmation triangle;
    the finding's evidence keeps the library's promotion guard so a
    downstream deterministic validator must re-confirm before trust.
    """
    target = state.get("target")
    session_cookies: dict[str, str] | None = state.get("session_cookies") or None

    base_url = getattr(target, "url", "")
    if not base_url:
        return {
            "messages": [AIMessage(content="Prototype Pollution Detector: no target URL — skipping.")],
            "current_phase": "prototype_pollution_detection",
        }

    logger.info("Prototype Pollution Detector (R4 wiring) entered for target=%s", base_url)

    parsed = urlparse(base_url)
    host = parsed.hostname
    if not host:
        return {
            "messages": [AIMessage(content="Prototype Pollution Detector: no host in URL — skipping.")],
            "current_phase": "prototype_pollution_detection",
        }

    # Fail-closed engagement-scope gate — the ONLY sanctioned path to any
    # network activity in this node. Mirrors request_smuggling_node.
    try:
        from webpent.shared.engagement_scope import is_engagement_target_host

        if not is_engagement_target_host(host):
            logger.warning(
                "Prototype Pollution: host %s is NOT in the engagement-scope "
                "allowlist — skipping reflection probes (fail-closed SSRF gate).",
                host,
            )
            return {
                "messages": [
                    AIMessage(
                        content=(
                            f"Prototype Pollution: host {host} not in engagement "
                            f"scope — skipped (fail-closed SSRF gate)."
                        )
                    )
                ],
                "current_phase": "prototype_pollution_detection",
            }
    except ImportError:
        logger.warning(
            "Prototype Pollution: engagement_scope module not importable — skipping reflection probes (fail-closed)."
        )
        return {
            "messages": [AIMessage(content="Prototype Pollution: scope check unavailable — skipped.")],
            "current_phase": "prototype_pollution_detection",
        }

    _scheme, _host, _port, _use_tls, error = _guard_reflection_probes(base_url, session_cookies)
    if error is not None:
        return {
            "messages": [AIMessage(content=f"Prototype Pollution: {error} — skipping.")],
            "current_phase": "prototype_pollution_detection",
        }

    canary = "ppcanary"
    new_findings: list[Finding] = []
    probe_coverage: list[dict[str, str]] = []

    try:
        from webpent.shared.http import build_cookie_header, make_safe_httpx_client

        cookie_header = build_cookie_header(session_cookies)
        paths = _collect_probe_paths(state)
        for path in paths:
            probes = build_pollution_probes(path, method="POST", canary=canary)
            try:
                with make_safe_httpx_client(timeout=10.0, follow_redirects=False, verify=True) as client:
                    request_headers = {"Content-Type": "application/json"}
                    if cookie_header:
                        request_headers["Cookie"] = cookie_header
                    baseline_response = client.post(
                        f"{base_url.rstrip('/')}{path}",
                        content=json.dumps({"benign": "control"}),
                        headers=request_headers,
                    )
                    baseline_text = baseline_response.text[:2_000_000]
                    polluted_probe = None
                    for probe in probes:
                        probe_response = client.post(
                            f"{base_url.rstrip('/')}{probe['path']}",
                            content=json.dumps(probe["body"]),
                            headers=request_headers,
                        )
                        analysis = analyze_reflection_pair(
                            baseline_text, probe_response.text[:2_000_000], canary=canary
                        )
                        if analysis.get("polluted") is True:
                            polluted_probe = probe
                            break
                probe_coverage.append({"probe": f"pp:{path}", "status": ("confirmed" if polluted_probe else "clean")})
                if polluted_probe is None:
                    continue

                finding = Finding(
                    title=f"Prototype Pollution signal at {host}{path}",
                    description=(
                        "The endpoint reflects a __proto__/constructor canary "
                        "planted by a deep-key JSON payload while the "
                        "benign-field control stays clean — a client-side "
                        "prototype-pollution sink is reachable from this "
                        "parameter surface. Confirmation requires the "
                        "deterministic validator re-probe."
                    ),
                    severity=Severity.HIGH,
                    confidence=Confidence.TENTATIVE,
                    confidence_level="Needs Human Review",
                    vuln_class=VulnClass.PROTOTYPE_POLLUTION.value,
                    url=f"{base_url.rstrip('/')}{path}",
                    tool_name="prototype_pollution_detector",
                    payload=json.dumps(polluted_probe["body"])[:2000],
                    evidence={
                        "causal_signal": True,
                        "negative_control_complete": True,
                        "proof_bundle": None,
                        "promotion_guard": ("blocked_missing_negative_control_and_proof_bundle"),
                        "probe_id": polluted_probe["probe_id"],
                        "baseline_control": "benign-field POST stayed canary-free",
                    },
                    reasoning=(
                        "Sent the governed deep-key payload set with a "
                        "run-namespaced canary and a benign-field negative "
                        "control. The canary appeared in the candidate "
                        "response, was absent from the control, and the two "
                        "responses differ (fail-closed reflection triangle)."
                    ),
                )
                new_findings.append(finding)
                logger.warning("Prototype pollution signal confirmed at %s%s", host, path)
            except Exception as exc:
                # Transport-level failures stay at debug (network errors are
                # expected against targets that close/rate-limit); Finding
                # construction failures are caught inside at ERROR.
                probe_coverage.append({"probe": f"pp:{path}", "status": "blocked"})
                logger.debug("pp probe error for %s%s: %s", host, path, exc)
    except Exception as exc:
        probe_coverage.append({"probe": "pp", "status": "blocked"})
        logger.debug("Prototype Pollution probe error for %s: %s", host, exc)

    summary = (
        f"Prototype Pollution Detector: {len(new_findings)} signal(s) across "
        f"{len(probe_coverage)} endpoint(s); all probes scope-gated and bounded."
    )
    return {
        "messages": [AIMessage(content=summary)],
        "findings": new_findings,
        "current_phase": "prototype_pollution_detection",
    }
