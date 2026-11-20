"""UM-DR-39 RC-2 — the authorization-observation projection.

One evidence-backed observation per Tool-Confirmed finding, written at
the promotion boundary onto the ``authorization_observations`` state
channel (declared in UM-DR-39; previously the key was undeclared on
``PentestState`` — LangGraph silently drops undeclared keys — and no
producer existed, so the discovery funnel reported zero authorization
observations in every campaign while the CausalGuard evidence carried
the full actor/resource context).

Honesty contract: every value is extracted from the finding's OWN
CausalGuard evidence — the ``authorization_differential`` context
(actor_id / resource_id / resource_owner) the guard REQUIRED to
adjudicate, plus the AVI merge's explicit ``avi_actor_id`` /
``avi_resource_id`` when present. Absent values are recorded as
``None`` — never inferred, never defaulted from names, never renamed.
The projection is additive channel data only: it never promotes, never
changes scope, and never touches the confirmation authority
(CausalGuard stays the sole confirmation path).
"""
from __future__ import annotations

from collections.abc import Mapping
from datetime import datetime, timezone
from typing import Any

_ACTOR_KEYS = ("actor_id", "candidate_actor_id", "source_actor_id")
_RESOURCE_KEYS = ("resource_id", "candidate_resource_id")
_OWNER_KEYS = ("resource_owner", "owner_id")


def _deep_first(value: Any, keys: tuple[str, ...],
                depth: int = 0) -> str | None:
    """First non-empty string for any of ``keys`` in a nested mapping;
    ``None`` when absent (never fabricated)."""
    if depth > 4 or not isinstance(value, Mapping):
        return None
    for key in keys:
        candidate = value.get(key)
        if isinstance(candidate, str) and candidate.strip():
            return candidate.strip()
    for child in value.values():
        found = _deep_first(child, keys, depth + 1)
        if found:
            return found
    return None


def build_authorization_observation(finding: Any,
                                    source_node: str) -> dict[str, Any] | None:
    """Project one Tool-Confirmed finding onto the channel, or None."""
    # both pydantic findings and plain dict findings are accepted
    # (the graph state carries dicts after serialization)
    if isinstance(finding, Mapping):

        def _get(key: str, default: Any = None) -> Any:
            return finding.get(key, default)
    else:

        def _get(key: str, default: Any = None) -> Any:
            return getattr(finding, key, default)

    if str(_get("confidence_level", "") or "") != "Tool-Confirmed":
        return None
    finding_id = str(_get("id", "") or "")
    if not finding_id:
        return None
    evidence = _get("evidence", None)
    evidence = evidence if isinstance(evidence, Mapping) else {}
    guard = evidence.get("causal_guard")
    guard = guard if isinstance(guard, Mapping) else {}
    differential = guard.get("authorization_differential")
    differential = differential if isinstance(differential, Mapping) else {}
    url = str(_get("url", "") or "")
    object_id = (url.rstrip("/").rsplit("/", 1)[-1]
                 if "/" in url else None)
    owner = (_deep_first(differential, _OWNER_KEYS) or None)
    return {
        "finding_id": finding_id,
        "vuln_class": str(_get("vuln_class", "") or ""),
        "source_node": source_node,
        "guard_verdict": (str(guard.get("verdict", "") or "") or None),
        "actor_id": (_deep_first(differential, _ACTOR_KEYS)
                     or evidence.get("avi_actor_id") or None),
        "resource_id": (_deep_first(differential, _RESOURCE_KEYS)
                        or evidence.get("avi_resource_id") or None),
        "object_id_from_url": object_id,
        "resource_owner": owner,
        "ownership_basis": (
            "CausalGuard authorization_differential context"
            if owner else None),
        "observed_at_utc": datetime.now(timezone.utc).isoformat(),
    }
