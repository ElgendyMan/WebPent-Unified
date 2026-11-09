# src/webpent/state/reducers.py
"""webpent.state.reducers

LangGraph reducer functions for the WebPent Framework V3.

V3 extends V2's reducers with :func:`merge_retries` to support the
Payload Optimizer loop's retry-count tracking.
"""

from __future__ import annotations

import json
from typing import Any, TypeVar

from webpent.models.findings import Finding

_T = TypeVar("_T")


def _extract_id(obj: Any) -> Any:
    """Extract an id from a Finding/Hypothesis instance OR a dict.

    V10 AUDIT FIX (C6): LangGraph's SqliteSaver serializes state to JSON
    on checkpoint save and does NOT re-validate Pydantic models on load.
    After a checkpoint round-trip, findings/hypotheses are plain dicts,
    not Finding/Hypothesis instances. The previous ``finding.id`` /
    ``getattr(hyp, "id", None)`` patterns crashed on dicts (AttributeError)
    or returned None (dicts have no .id attribute) → dedup defeated,
    unbounded growth. This helper handles both shapes.
    """
    if isinstance(obj, dict):
        return obj.get("id")
    return getattr(obj, "id", None)


def model_get(obj: Any, key: str, default: Any = None) -> Any:
    """Get a field from a Pydantic model instance OR a plain dict.

    V10 EXHAUSTIVE AUDIT FIX (P0-1): after a LangGraph checkpoint
    round-trip, findings and hypotheses in state are plain dicts, not
    Pydantic model instances. Routing functions that used direct
    attribute access (``finding.severity``, ``hypothesis.status``)
    crashed with AttributeError on dicts. This helper transparently
    handles both shapes so callers don't need to know which they have.

    Usage:
        severity = model_get(finding, "severity")
        status = model_get(hypothesis, "status", "unexplored")
    """
    if isinstance(obj, dict):
        return obj.get(key, default)
    return getattr(obj, key, default)


def deterministic_evidence_count(findings: Any) -> int:
    """Count deterministic validation outcomes in a findings collection.

    IMPL Phase 2-G: shared by the post-validation replan gate
    (graph.builder) and the smart-campaigns replan router so both bounded
    loops measure evidence identically. Evidence = findings whose
    persisted-class outcome is deterministic: ``Tool-Confirmed`` or
    ``Refuted``. Unconfirmed/AI-assessed/pending candidates are NOT
    evidence — replanning on them would re-rank on noise.
    """
    count = 0
    for finding in (findings or []):
        level = str(model_get(finding, "confidence_level") or "")
        if level in ("Tool-Confirmed", "Refuted"):
            count += 1
    return count


def _finding_strength(obj: Any) -> int:
    """Return a monotonic confidence rank for same-ID reducer updates."""
    confidence = str(model_get(obj, "confidence", "")).lower()
    level = str(model_get(obj, "confidence_level", "")).lower()
    if confidence == "confirmed" or "tool-confirmed" in level:
        return 3
    if confidence == "firm" or "firm" in level:
        return 2
    if confidence == "tentative" or "human review" in level:
        return 1
    return 0


def merge_findings(
    existing: list[Finding] | None,
    new: list[Finding] | None,
) -> list[Finding]:
    """Append-only reducer for the ``findings`` state field, with dedup by ``id``.

    V10 AUDIT FIX (C6): handles dict-shaped findings from checkpoint
    round-trips. Previously ``finding.id`` on a dict raised
    ``AttributeError`` — crashing the reducer and blocking the state
    update on resume. Now uses :func:`_extract_id` which works for both
    Finding instances and dicts.
    """
    merged: dict[Any, Any] = {}
    for finding in (existing or []):
        fid = _extract_id(finding)
        if fid is not None:
            merged[fid] = finding
        else:
            # No id — append with a synthetic key to preserve it.
            merged[("__noid__", id(finding))] = finding
    for finding in (new or []):
        fid = _extract_id(finding)
        if fid is not None:
            previous = merged.get(fid)
            if previous is None or _finding_strength(finding) >= _finding_strength(previous):
                merged[fid] = finding
        else:
            merged[("__noid__", id(finding))] = finding
    return list(merged.values())


def merge_auth_state(
    existing: dict[str, Any] | None,
    new: dict[str, Any] | None,
) -> dict[str, Any]:
    """V9 P0-B-2 FIX: reducer for the ``auth_state`` state field.

    ``auth_state["cookies"]`` is a list-of-dict (Playwright shape:
    ``{"name", "value", "domain"}``) that needs upsert-by-name
    semantics: a mid-scan reauth (see
    ``agents.validator.agent._validate_with_tool``) replaces the
    value for an EXISTING cookie name, it doesn't add a second entry
    for it.

    Plain :func:`merge_dicts` cannot express this — its "both values
    are lists" branch concatenates, which is the correct behaviour for
    other dict fields (``crawled_data``, ``mental_model``'s edge
    lists) but wrong here. Before this reducer existed, a reauth that
    refreshed ``auth_state["cookies"]`` and returned it would have had
    the fresh entry concatenated onto the stale one from auth_node's
    original write — leaving BOTH the dead and fresh ``PHPSESSID`` in
    the list, with ``execution_sandbox``'s ``_inject_cookies`` sending
    whichever happened to land last in Playwright's own last-write-
    wins cookie application, not necessarily the fresh one.

    This mirrors :func:`merge_hypotheses`'s upsert-by-id pattern:
    existing cookie names keep their position; a new entry with the
    same name replaces the value in place; brand-new names are
    appended. Every other key falls through to normal
    :func:`merge_dicts` behaviour unchanged.
    """
    merged: dict[str, Any] = dict(existing or {})
    new = dict(new or {})
    new_cookies = new.pop("cookies", None)
    if isinstance(new_cookies, list):
        by_name: dict[Any, dict[str, Any]] = {}
        order: list[Any] = []
        for c in list(merged.get("cookies") or []) + new_cookies:
            if not isinstance(c, dict):
                continue
            key = c.get("name")
            if key not in by_name:
                order.append(key)
            by_name[key] = c  # last write (the newer entry) wins
        merged["cookies"] = [by_name[k] for k in order]
    return merge_dicts(merged, new)


def merge_lists(
    existing: list[_T] | None,
    new: list[_T] | None,
) -> list[_T]:
    """Generic append-only reducer for arbitrary list items."""
    base: list[_T] = list(existing) if existing else []
    if new:
        base.extend(new)
    return base


def replace_runtime_capability_gaps(
    _existing: list[dict[str, Any]] | None,
    new: list[dict[str, Any]] | None,
) -> list[dict[str, Any]]:
    """Project the current runtime gaps instead of accumulating old snapshots.

    Capability gaps describe the current DI/runtime state, not historical
    observations.  A later node may register a policy-checked adapter and
    resolve a prior gap, including resolving to an empty list.  Keeping this
    field append-only would report resolved gaps forever and could incorrectly
    block qualification decisions.
    """
    return list(new or [])


def merge_hypotheses(
    existing: list[Any] | None,
    new: list[Any] | None,
) -> list[Any]:
    """V9 P0 B2: upsert-by-id reducer for the ``hypotheses`` state field.

    Previously ``hypotheses`` used :func:`merge_lists` (append-only),
    which meant every ``model_copy(update={"status": ...})`` returned by
    the Strategist on promote/abandon was appended as a NEW item —
    producing duplicates in state and in the final report.

    This reducer mirrors :func:`merge_findings`'s upsert semantics:
    each hypothesis is keyed by its ``id`` UUID, and a new item with
    the same id replaces the existing one. This means promote-then-
    abandon leaves exactly one entry with the final status.

    Items without an ``id`` attribute (legacy/defensive) are appended.

    V10 AUDIT FIX (C6): handles dict-shaped hypotheses from checkpoint
    round-trips. Previously ``getattr(hyp, "id", None)`` on a dict
    returned None (dicts have no .id attribute) → ALL dict-shaped
    hypotheses were appended with synthetic keys → unbounded growth on
    resume. Now uses :func:`_extract_id` which works for both Hypothesis
    instances and dicts.
    """
    merged: dict[Any, Any] = {}
    order: list[Any] = []  # preserve insertion order for determinism
    for hyp in (existing or []):
        hid = _extract_id(hyp)
        if hid is not None:
            if hid not in merged:
                order.append(hid)
            merged[hid] = hyp
        else:
            # No id — append-only (defensive, shouldn't happen).
            order.append(("__noid__", id(hyp)))
            merged[("__noid__", id(hyp))] = hyp
    for hyp in (new or []):
        hid = _extract_id(hyp)
        if hid is not None:
            if hid not in merged:
                order.append(hid)
            merged[hid] = hyp  # upsert: replaces existing
        else:
            order.append(("__noid__", id(hyp)))
            merged[("__noid__", id(hyp))] = hyp
    return [merged[key] for key in order]


def merge_payloads(
    existing: dict[str, list[str]] | None,
    new: dict[str, list[str]] | None,
) -> dict[str, list[str]]:
    """Keyed-dict reducer for the ``payloads_to_test`` state field."""
    merged: dict[str, list[str]] = {
        key: list(values) for key, values in (existing or {}).items()
    }
    for key, payloads in (new or {}).items():
        if not isinstance(payloads, list):
            payloads = [payloads]
        merged.setdefault(key, [])
        merged[key].extend(payloads)
    return merged


def merge_retries(
    existing: dict[str, int] | None,
    new: dict[str, int] | None,
) -> dict[str, int]:
    """Reducer for the ``optimization_retries`` state field.

    Overwrites existing keys with the new integer values from ``new``.
    Keys present in ``existing`` but not in ``new`` are preserved.
    """
    merged: dict[str, int] = {
        key: int(value) for key, value in (existing or {}).items()
        if isinstance(value, (int, float))
    }
    for key, value in (new or {}).items():
        try:
            merged[key] = int(value)
        except (TypeError, ValueError):
            continue
    return merged


def merge_dicts(
    existing: dict[str, Any] | None,
    new: dict[str, Any] | None,
) -> dict[str, Any]:
    """Deep-merge two dictionaries for parallel-execution safety.

    V3.5 Phase 4: Replaces last-write-wins semantics for ``crawled_data``
    and ``auth_state``. This prevents silent data overwrites when parallel
    branches write to the same dict concurrently.

    Merge rules:
      * Keys present in ``new`` but not ``existing`` are added.
      * If both values are dicts, they are merged recursively.
      * If both values are lists, the ``new`` list is appended to the
        ``existing`` list.
      * Otherwise, the ``new`` value overwrites the ``existing`` value.

    V10 AUDIT FIX (C5): if ``new_value`` is ``None``, the key is SKIPPED
    (not written). Previously a node returning ``{"mental_model": None}``
    or ``{"session_cookies": None}`` would OVERWRITE the existing
    dict/list/value with None — wiping the entire field. A single buggy
    node could destroy the entire Mental Model or cookie jar. Now: None
    means "no update for this key."

    Args:
        existing: The dict accumulated so far in the graph run.
        new: The dict returned by the current node.

    Returns:
        A new dict containing the merged result.
    """
    merged: dict[str, Any] = dict(existing or {})
    for key, new_value in (new or {}).items():
        # V10 AUDIT FIX (C5): skip None values — they mean "no update"
        # rather than "delete this key." Without this, a buggy node
        # returning None for a dict-typed field wipes the entire field.
        if new_value is None:
            continue
        if key in merged:
            existing_value = merged[key]
            if isinstance(existing_value, dict) and isinstance(new_value, dict):
                merged[key] = merge_dicts(existing_value, new_value)
            elif isinstance(existing_value, list) and isinstance(new_value, list):
                # V10 AUDIT FIX (M3): dedup list-concatenation for
                # mental_model.edges to prevent quadratic growth with
                # duplicate edges. For lists of dicts (edges, cookies),
                # dedup by a stable identity if available; for lists of
                # strings (lessons), dedup by value; for Finding/Hypothesis
                # lists, the merge_findings/merge_hypotheses reducers
                # handle dedup (this path is for crawled_data etc.).
                merged[key] = _dedup_list_concat(existing_value, new_value)
            else:
                merged[key] = new_value
        else:
            merged[key] = new_value
    return merged


def _dedup_list_concat(existing: list, new: list) -> list:
    """Concatenate two lists with best-effort dedup.

    V10 AUDIT FIX (M3): prevents quadratic growth of edge lists and
    other append-only list fields when parallel branches extract the
    same item. Dedup strategy:
      - For lists of dicts: dedup by JSON-serialized form (stable for
        hashable inner values).
      - For lists of strings/numbers: dedup by value.
      - For mixed lists: no dedup (preserve order, append all).
    """
    if not existing:
        return list(new)
    if not new:
        return list(existing)
    # Try dict-dedup first.
    if all(isinstance(x, dict) for x in existing + new):
        seen: set[str] = set()
        result: list = []
        for item in existing + new:
            try:
                key = json.dumps(item, sort_keys=True, default=str)
            except (TypeError, ValueError):
                key = str(id(item))
            if key not in seen:
                seen.add(key)
                result.append(item)
        return result
    # Try scalar-dedup.
    if all(isinstance(x, (str, int, float, bool)) for x in existing + new):
        seen_vals: set = set()
        result2: list = []
        for item in existing + new:
            if item not in seen_vals:
                seen_vals.add(item)
                result2.append(item)
        return result2
    # Mixed — no dedup.
    return existing + new
