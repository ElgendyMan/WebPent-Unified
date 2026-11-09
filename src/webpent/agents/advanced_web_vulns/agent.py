# src/webpent/agents/advanced_web_vulns/agent.py
"""Advanced web vulnerability probes: cache poisoning + prototype
pollution (2026-10-25 capability batch).

Runs TWO bounded, deterministic probe sets and emits TENTATIVE
findings whose evidence is shaped exactly for the canonical validators
in ``production/advanced_validators.py`` (baseline / candidate /
negative_control plus the probe marker).

Proof discipline: cache poisoning is only ever alleged through a
TWO-request proof — a poison request followed by an UNPOISONED victim
request. The candidate evidence never carries the poison headers, so
the validator can distinguish caching from request reflection.

Hard bounds:

  * ``_MAX_TOTAL_PROBES = 10`` requests per engagement, enforced by a
    counter every request path must pass;
  * per-request timeout 8s through ``make_safe_httpx_client`` (the
    SSRF-guarded client every other agent uses) and the engagement
    ``RequestRateGovernor`` for pacing;
  * probes are GET-only with a unique one-shot marker; nothing
    destructive, no payloads beyond the inert marker values.

Gating (zero side effects by construction):

  * flag ``enable_advanced_web_vulns`` (default False) — off means the
    node returns the state untouched without constructing a client;
  * internally gated: with the flag on the node still probes only the
    engagement's own target path (never third-party hosts) and stops
    after the cap.

Findings stay TENTATIVE until a canonical validator confirms them;
nothing here routes into EXPLOITABLE_CLASSES.
"""
from __future__ import annotations

import secrets
import time
from typing import Any
from urllib.parse import urlsplit

from langchain_core.messages import AIMessage

from webpent.state.state import PentestState
from webpent.config.settings import get_settings
from webpent.models.findings import Confidence, Finding, Severity, VulnClass
from webpent.shared.http import make_safe_httpx_client
from webpent.shared.rate_governor import RequestRateGovernor

logger = __import__("logging").getLogger(__name__)

NODE_NAME = "advanced_web_vulns"

_MAX_TOTAL_PROBES = 10
_REQUEST_TIMEOUT_S = 8
_MAX_BODY_SNAPSHOT = 4096

_POISON_HEADER = "X-Forwarded-Host"


def _probe_budget() -> list[int]:
    return [_MAX_TOTAL_PROBES]


def _bounded_body(text: str) -> str:
    return (text or "")[:_MAX_BODY_SNAPSHOT]


def _evidence(resp: Any, elapsed_ms: int,
              marker: str | None = None,
              request_headers: dict[str, str] | None = None) -> dict[str, Any]:
    ev: dict[str, Any] = {
        "status_code": getattr(resp, "status_code", 0),
        "response_body": _bounded_body(getattr(resp, "text", "") or ""),
        "headers": dict(getattr(resp, "headers", {}) or {}),
        "elapsed_ms": elapsed_ms,
        "url": str(getattr(resp, "url", "")),
    }
    if marker:
        ev["poison_marker"] = marker
    if request_headers:
        # Recorded so the validator can prove the candidate did NOT
        # carry the poison headers itself (reflection vs caching).
        ev["request_headers"] = request_headers
    return ev


def _fail_soft(probe_name: str, exc: Exception) -> None:
    logger.warning("Advanced web probe %s failed (skipped): %s", probe_name, exc)


def _request(client: Any, url: str, *,
             method: str = "GET",
             params: dict[str, str] | None = None,
             json_body: Any | None = None,
             headers: dict[str, str] | None = None,
             marker: str | None = None,
             budget: list[int],
             governor: RequestRateGovernor,
             host: str) -> dict[str, Any] | None:
    if budget[0] <= 0:
        logger.warning("Advanced web probe budget exhausted — remaining probes skipped")
        return None
    budget[0] -= 1
    with governor.acquire(host) as permit:
        if permit.aborted:
            logger.warning("Advanced web probe aborted by governor: %s", permit.reason)
            return None
        start = time.monotonic()
        try:
            if method == "POST":
                resp = client.post(url, params=params, json=json_body, headers=headers)
            else:
                resp = client.get(url, params=params, headers=headers)
        except Exception as exc:  # noqa: BLE001 — network probe, fail-soft
            _fail_soft(method.lower(), exc)
            return None
        governor.record_response(host, getattr(resp, "status_code", 0))
        elapsed_ms = int((time.monotonic() - start) * 1000)
        return _evidence(resp, elapsed_ms, marker=marker,
                         request_headers=dict(headers or {}))


def _make_finding(
    vuln_class: VulnClass,
    title: str,
    url: str,
    evidence: dict[str, Any],
    description: str,
) -> Finding:
    return Finding(
        title=title,
        severity=Severity.MEDIUM,
        description=description,
        tool_name=NODE_NAME,
        url=url,
        vuln_class=vuln_class,
        confidence=Confidence.TENTATIVE,
        confidence_level="Pending",
        evidence=evidence,
    )


def _probe_refutation_suppressed(state: PentestState, vuln_class: str) -> bool:
    """Proposal 1 (2026-10-25): delay-not-delete gate for one probe set.

    True only when ``enable_refutation_learning`` is ON and the
    refutation ledger has accumulated >= the suppression threshold of
    refuted outcomes for this (vuln class, target) pair. Fail-open by
    contract: any error means "run the probe" — suppression is a
    budget optimization and must never block detection.
    """
    try:
        if not get_settings().enable_refutation_learning:
            return False
        target = state.get("target")
        url = getattr(target, "url", "") or ""
        if not url:
            return False
        from webpent.learning.refutation_ledger import (
            get_ledger,
            target_fingerprint_from_url,
        )

        return get_ledger().should_suppress(
            vuln_class=vuln_class, target_fingerprint=target_fingerprint_from_url(url)
        )
    except Exception:  # noqa: BLE001 — fail-open
        return False


def advanced_web_vulns_node(state: PentestState) -> dict:
    """LangGraph node: bounded cache-poisoning + prototype-pollution probes.

    No-op unless ``enable_advanced_web_vulns`` is on. Probes are
    GET-only, marker-based, capped, and fail-soft; findings are
    TENTATIVE pending canonical validation.
    """
    if not get_settings().enable_advanced_web_vulns:
        return {
            "messages": [
                AIMessage(
                    content="Advanced Web Vulns: disabled (enable_advanced_web_vulns=False) — no probes sent."
                )
            ],
            "current_phase": NODE_NAME,
        }

    target = state.get("target")
    base_url = getattr(target, "url", "") or ""
    if not base_url.startswith("http"):
        return {
            "messages": [
                AIMessage(
                    content="Advanced Web Vulns: no usable target URL — zero probes sent."
                )
            ],
            "current_phase": NODE_NAME,
        }

    parts = urlsplit(base_url)
    host = parts.netloc
    origin = f"{parts.scheme}://{host}"
    path = parts.path or "/"
    poison_path = origin + path

    # One-shot markers for this engagement only.
    run_id = secrets.token_hex(4)
    cache_marker = f"webpent-poison-{run_id}"
    poison_host_value = f"{cache_marker}.example"
    pp_marker = f"webpent-ppoll-{run_id}"

    findings: list[Finding] = list(state.get("findings") or [])
    probes_log: list[str] = []
    budget = _probe_budget()
    governor = RequestRateGovernor()

    try:
        with make_safe_httpx_client(timeout=_REQUEST_TIMEOUT_S) as client:
            # Probe set 1 — cache poisoning via header keying
            # (4 requests: baseline, poison, victim, control).
            # Proposal 1 delay gate: skip when the refutation ledger has
            # >= threshold refutations of this class on this target
            # (flag-gated, fail-open). ``baseline`` is shared with probe
            # set 2, so it starts None and set 2 fetches its own when
            # set 1 was suppressed.
            baseline = None
            if _probe_refutation_suppressed(state, VulnClass.CACHE_POISONING.value):
                probes_log.append("cache_poisoning:suppressed")
            else:
                baseline = _request(client, poison_path, budget=budget,
                                    governor=governor, host=host)
                poison = _request(
                    client, poison_path, budget=budget, governor=governor, host=host,
                    headers={
                        _POISON_HEADER: poison_host_value,
                        "X-Forwarded-Scheme": "noxhttps",
                    },
                    marker=cache_marker)
                victim = _request(client, poison_path, budget=budget,
                                  governor=governor, host=host)
                control = _request(
                    client, origin + path + (("&" if "?" in path else "?")
                                             + "webpent_control_probe=1"),
                    budget=budget, governor=governor, host=host)
                if baseline and poison and victim and control:
                    # FIX (2026-10-25 critique): the marker must live on
                    # EVERY role dict, not only the finding level — the
                    # canonical validator reads _marker_of(<role dict>),
                    # so a finding-level-only marker made every probe
                    # finding REFUTE as "no_marker" downstream.
                    findings.append(_make_finding(
                        VulnClass.CACHE_POISONING,
                        "Web cache poisoning via header keying (probe)",
                        poison_path,
                        {"baseline": {**baseline, "poison_marker": cache_marker},
                         "poison_request": poison,
                         "candidate": {**victim, "poison_marker": cache_marker},
                         "negative_control": {**control, "poison_marker": cache_marker},
                         "poison_marker": cache_marker},
                        "A header-keyed poison request was followed by an "
                        "unpoisoned victim request; the canonical validator "
                        "decides whether the poisoned entry was served from "
                        "cache (two-request proof).",
                    ))
                    probes_log.append("cache_poisoning")

            # Probe set 2 — client-side prototype pollution via
            # __proto__ query keying (3 requests: baseline, candidate,
            # benign-key control).
            # Proposal 1 delay gate (same contract as probe set 1).
            if _probe_refutation_suppressed(state, VulnClass.PROTOTYPE_POLLUTION.value):
                probes_log.append("prototype_pollution:suppressed")
            else:
                pp_candidate = _request(
                    client, origin + path, budget=budget, governor=governor, host=host,
                    params={"__proto__[webpent_probe]": pp_marker},
                    marker=pp_marker)
                pp_control = _request(
                    client, origin + path, budget=budget, governor=governor, host=host,
                    params={"benign[webpent_probe]": pp_marker},
                    marker=pp_marker)
                pp_baseline = baseline  # same path, no probe params
                if pp_baseline is None:
                    # Probe set 1 was suppressed: fetch this set's own
                    # baseline (the pollution validator needs one).
                    pp_baseline = _request(
                        client, origin + path, budget=budget, governor=governor,
                        host=host)
                if pp_baseline and pp_candidate and pp_control:
                    # FIX (2026-10-25 critique): tag every role dict with
                    # the marker (same reason as the cache-poisoning fix
                    # above). The control's OWN marker key stays on its
                    # evidence so the validator's reflection scan sees it.
                    findings.append(_make_finding(
                        VulnClass.PROTOTYPE_POLLUTION,
                        "Prototype pollution via __proto__ parameter (probe)",
                        origin + path,
                        {"baseline": {**pp_baseline, "poison_marker": pp_marker},
                         "candidate": pp_candidate,
                         "negative_control": {**pp_control, "poison_marker": pp_marker},
                         "poison_marker": pp_marker},
                        "A __proto__-carrying parameter was submitted next to "
                        "a benign-key control carrying the same value; the "
                        "canonical validator decides whether the pollution "
                        "marker reflects a real prototype merge.",
                    ))
                    probes_log.append("prototype_pollution")
    except Exception as exc:  # noqa: BLE001 — probe session, fail-soft
        _fail_soft("session", exc)

    summary = (
        f"Advanced Web Vulns: {len(probes_log)} probe set(s) run "
        f"({', '.join(probes_log) or 'none'}) in ≤{_MAX_TOTAL_PROBES} requests, "
        f"{len(findings)} tentative finding(s) queued for canonical validation."
    )
    logger.info(summary)
    return {
        "messages": [AIMessage(content=summary)],
        "current_phase": NODE_NAME,
        "findings": findings,
    }


__all__ = ["advanced_web_vulns_node", "NODE_NAME"]
