# src/webpent/production/advanced_validators.py
"""Canonical deterministic validators for cache poisoning and prototype
pollution (2026-10-25 capability batch).

Same contract as every validator in ``production/validators.py``: pure
functions over captured evidence (baseline / candidate /
negative_control), fail closed on malformed evidence, CONFIRMED only
through an observed differential the negative control does not
reproduce. The probe side (``agents/advanced_web_vulns/agent.py``) is
hard-capped; these validators only analyze already-captured evidence.

Proof discipline for cache poisoning mirrors ``chain_composer.py``:
the finding exists ONLY if two real, sequential requests demonstrate
it — a poison request followed by an unpoisoned victim request that
serves the poisoned content. No single-request reflection, no guessing.
"""
from __future__ import annotations

import json
from typing import Any

from webpent.production.validators import (
    EvidenceQuality,
    ValidationOutcome,
    ValidationResult,
    _body,
    _require_evidence,
    _status,
)

# Bounded-analysis caps.
_MAX_BODY_SCAN = 2_000_000
_MIN_MARKER_LEN = 6


def _scan(text: str, marker: str) -> bool:
    if not text or not marker or len(marker) < _MIN_MARKER_LEN:
        return False
    return marker in text[:_MAX_BODY_SCAN]


def _marker_of(evidence: dict[str, Any]) -> str:
    marker = (
        evidence.get("poison_marker")
        or (evidence.get("evidence", {}) or {}).get("poison_marker")
        or ""
    )
    return str(marker).strip()


def _reflection_text(evidence: dict[str, Any]) -> str:
    """Body + serialized response headers, for marker reflection scans.

    FIX (2026-10-25 critique): poisoning frequently manifests in a
    RESPONSE HEADER (e.g. a ``Location`` redirect carrying the injected
    host) rather than the body; scanning only the body produced false
    refutations ("marker_missing_after_poison") for exactly the strongest
    real-world cases.
    """
    parts = [_body(evidence)]
    headers = evidence.get("headers") or evidence.get("response_headers") or {}
    if isinstance(headers, dict) and headers:
        parts.append(json.dumps({str(k): str(v) for k, v in headers.items()}))
    return "\n".join(parts)


def validate_cache_poisoning(
    *,
    baseline: dict[str, Any],
    candidate: dict[str, Any],
    negative_control: dict[str, Any],
    **kwargs: Any,
) -> ValidationResult:
    """Confirm cache poisoning from a poison-then-victim two-request proof.

    Evidence contract (produced by the bounded probe):
      * ``baseline``        — victim request BEFORE poisoning: clean body,
                              no poison marker.
      * ``candidate``       — victim request (NO special headers) AFTER the
                              poison request: body carries the poison
                              marker → the poisoned cache entry is being
                              served to other clients.
      * ``negative_control``— a different cacheable path fetched clean:
                              no marker → the marker is a cached response
                              for the poisoned URL, not generic behavior.
    REFUTED when the marker appears in the baseline or the control, or
    when the candidate carries the probe's poison headers itself (that
    would be request reflection, not cache poisoning).
    """
    _require_evidence("baseline", baseline)
    cand = _require_evidence("candidate", candidate)
    neg = _require_evidence("negative_control", negative_control)
    marker = _marker_of(cand)
    if len(marker) < _MIN_MARKER_LEN:
        return ValidationResult(
            "cache_poisoning", ValidationOutcome.REFUTED,
            EvidenceQuality.HEURISTIC_SIGNAL,
            "no usable poison marker in candidate evidence",
            baseline, cand, neg,
            refutation_path="no_marker")
    if _scan(_reflection_text(baseline), marker):
        return ValidationResult(
            "cache_poisoning", ValidationOutcome.REFUTED,
            EvidenceQuality.HEURISTIC_SIGNAL,
            "poison marker present in the pre-poison baseline — the marker is not poisoning-derived",
            baseline, cand, neg,
            refutation_path="marker_in_baseline")
    if not _scan(_reflection_text(cand), marker):
        return ValidationResult(
            "cache_poisoning", ValidationOutcome.REFUTED,
            EvidenceQuality.HEURISTIC_SIGNAL,
            "victim response after poisoning does not carry the poison marker",
            baseline, cand, neg,
            refutation_path="marker_missing_after_poison")
    if _scan(_reflection_text(neg), marker):
        return ValidationResult(
            "cache_poisoning", ValidationOutcome.REFUTED,
            EvidenceQuality.HEURISTIC_SIGNAL,
            "negative control path also serves the marker — not a cached entry for the poisoned URL",
            baseline, cand, neg,
            refutation_path="marker_in_control")
    # FIX (2026-10-25 critique): self-reflection is detected from the
    # REQUEST headers the probe itself sent (recorded by the probe as
    # ``request_headers``). The previous check read the candidate's
    # RESPONSE headers, which actively refuted real poisonings whose
    # poisoned ``Location``/echo header carried the injected host.
    request_headers = {
        str(k).lower(): str(v) for k, v in (cand.get("request_headers") or {}).items()
    }
    if any(
        k.startswith("x-forwarded-")
        for k, v in request_headers.items()
        if marker in v
    ):
        return ValidationResult(
            "cache_poisoning", ValidationOutcome.REFUTED,
            EvidenceQuality.HEURISTIC_SIGNAL,
            "candidate request itself carried the poison header — reflection, not cache poisoning",
            baseline, cand, neg,
            refutation_path="self_reflection")
    if _status(baseline) not in range(200, 300) or _status(cand) not in range(200, 300):
        return ValidationResult(
            "cache_poisoning", ValidationOutcome.INCONCLUSIVE,
            EvidenceQuality.HEURISTIC_SIGNAL,
            "baseline or victim request was not a healthy 2xx — cacheability unknown",
            baseline, cand, neg,
            refutation_path="unhealthy_victim")
    return ValidationResult(
        "cache_poisoning", ValidationOutcome.CONFIRMED,
        EvidenceQuality.OBSERVED_DIFFERENTIAL,
        "unpoisoned victim request served content injected by the earlier poison request; control path unaffected",
        baseline, cand, neg,
        details={"poison_marker": marker})


def validate_prototype_pollution(
    *,
    baseline: dict[str, Any],
    candidate: dict[str, Any],
    negative_control: dict[str, Any],
    **kwargs: Any,
) -> ValidationResult:
    """Confirm client-side prototype pollution from reflected pollution evidence.

    Evidence contract:
      * ``baseline``        — normal request/response without the probe:
                              no pollution marker.
      * ``candidate``       — response after submitting a
                              ``__proto__``-carrying payload
                              (JSON body or ``?__proto__[key]=value``):
                              the pollution marker appears in server-
                              processed output (reflected merged object,
                              altered serialization, or gadget output).
      * ``negative_control``— same request carrying the SAME value under
                              a benign key (no ``__proto__``): no marker
                              → the reflection is prototype-merge-driven,
                              not plain echo.
    """
    _require_evidence("baseline", baseline)
    cand = _require_evidence("candidate", candidate)
    neg = _require_evidence("negative_control", negative_control)
    marker = _marker_of(cand)
    if len(marker) < _MIN_MARKER_LEN:
        return ValidationResult(
            "prototype_pollution", ValidationOutcome.REFUTED,
            EvidenceQuality.HEURISTIC_SIGNAL,
            "no usable pollution marker in candidate evidence",
            baseline, cand, neg,
            refutation_path="no_marker")
    if _scan(_reflection_text(baseline), marker):
        return ValidationResult(
            "prototype_pollution", ValidationOutcome.REFUTED,
            EvidenceQuality.HEURISTIC_SIGNAL,
            "marker present without the __proto__ payload — not pollution-derived",
            baseline, cand, neg,
            refutation_path="marker_in_baseline")
    if not _scan(_reflection_text(cand), marker):
        return ValidationResult(
            "prototype_pollution", ValidationOutcome.REFUTED,
            EvidenceQuality.HEURISTIC_SIGNAL,
            "__proto__ payload produced no reflected pollution marker",
            baseline, cand, neg,
            refutation_path="no_pollution_reflection")
    if _scan(_reflection_text(neg), marker):
        return ValidationResult(
            "prototype_pollution", ValidationOutcome.REFUTED,
            EvidenceQuality.HEURISTIC_SIGNAL,
            "benign-key control also reflects the marker — plain echo, not prototype merge",
            baseline, cand, neg,
            refutation_path="control_also_reflects")
    return ValidationResult(
        "prototype_pollution", ValidationOutcome.CONFIRMED,
        EvidenceQuality.OBSERVED_DIFFERENTIAL,
        "__proto__ payload was merged and reflected while the benign-key control was not",
        baseline, cand, neg,
        details={"pollution_marker": marker})


__all__ = ["validate_cache_poisoning", "validate_prototype_pollution"]
