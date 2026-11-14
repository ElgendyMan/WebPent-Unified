"""Bridge advisory Target Brain hypotheses into the existing kernel model.

This module adds no execution authority.  It only creates structured,
unexplored :class:`Hypothesis` objects from endpoint metadata that was already
admitted by the target-understanding node.
"""

from __future__ import annotations

import hashlib
from collections.abc import Iterable, Mapping
from typing import Any
from uuid import NAMESPACE_URL, UUID, uuid5

from webpent.intelligence.contracts import (
    EndpointIntelligence,
    build_endpoint_hypotheses,
)
from webpent.models.hypothesis import Hypothesis

_MAX_HYPOTHESES = 32


def _model_value(value: Any, key: str, default: Any = None) -> Any:
    if isinstance(value, Mapping):
        return value.get(key, default)
    return getattr(value, key, default)


def hypothesis_fingerprint(value: Hypothesis | Mapping[str, Any]) -> str:
    """Return a stable semantic key without including secrets or raw payloads."""
    target_url = str(_model_value(value, "target_url", "")).strip().lower()
    vuln_class = str(_model_value(value, "vuln_class", "unknown")).strip().lower()
    statement = str(
        _model_value(value, "statement", _model_value(value, "reason", ""))
    ).strip().lower()
    return hashlib.sha256(f"{target_url}|{vuln_class}|{statement}".encode()).hexdigest()


def _stable_id(engagement_id: str, fingerprint: str) -> UUID:
    return uuid5(NAMESPACE_URL, f"webpent:target-brain:{engagement_id}:{fingerprint}")


def build_kernel_hypotheses(
    *,
    engagement_id: str,
    endpoints: Iterable[EndpointIntelligence] = (),
    existing: Iterable[Hypothesis | Mapping[str, Any]] = (),
    observed_signals: Iterable[str] = (),
    max_items: int = _MAX_HYPOTHESES,
) -> list[Hypothesis]:
    """Create new, deduplicated kernel hypotheses from advisory endpoint views.

    Existing hypotheses are never replaced.  A returned hypothesis is always
    ``unexplored`` and remains subject to the normal strategist, scope,
    ActionAuthority, validation, proof, and replay gates.
    """
    safe_engagement_id = str(engagement_id).strip()[:200]
    if not safe_engagement_id:
        return []
    try:
        limit = max(1, min(int(max_items), _MAX_HYPOTHESES))
    except (TypeError, ValueError):
        limit = _MAX_HYPOTHESES

    fingerprints = {
        hypothesis_fingerprint(item)
        for item in existing
        if isinstance(item, (Hypothesis, Mapping))
    }
    result: list[Hypothesis] = []
    for endpoint in endpoints:
        if not isinstance(endpoint, EndpointIntelligence):
            continue
        candidates = build_endpoint_hypotheses(
            endpoint,
            target_url=endpoint.path,
            observed_signals=(*endpoint.hypotheses, *observed_signals),
        )
        for candidate in candidates:
            kernel_hypothesis = candidate.to_kernel_hypothesis()
            fingerprint = hypothesis_fingerprint(kernel_hypothesis)
            if fingerprint in fingerprints:
                continue
            kernel_hypothesis = kernel_hypothesis.model_copy(
                update={
                    "id": _stable_id(safe_engagement_id, fingerprint),
                    "request_method": endpoint.method,
                    "hint_provenance": ["target_brain", "observed_endpoint"],
                    "deterministic_match": False,
                }
            )
            result.append(kernel_hypothesis)
            fingerprints.add(fingerprint)
            if len(result) >= limit:
                return result
    return result


__all__ = ["build_kernel_hypotheses", "hypothesis_fingerprint"]

