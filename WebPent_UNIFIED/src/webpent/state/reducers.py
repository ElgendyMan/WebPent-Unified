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

    UM-DR-43C: the key is normalized to ``str`` — a checkpointed dict
    carries ``"id"`` as a uuid STRING while a live model carries a
    ``UUID`` object, and ``UUID(...) != "uuid-string"`` in a dict
    lookup, so a model re-emission NEVER met its own checkpointed
    record and both copies accumulated in the pool. Normalizing here
    makes the upsert key shape-independent; the original id value is
    untouched on the record itself.
    """
    if isinstance(obj, dict):
        raw = obj.get("id")
    else:
        raw = getattr(obj, "id", None)
    return None if raw is None else str(raw)


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


# UM-DR-43C lifecycle contract (directive §6). A flat numeric rank is
# DELIBERATELY wrong for these states — the model's own docstring
# documents the state machine as one-way-per-branch, not a total
# order. What the reducer needs is narrower: "may a NEW record's
# status overwrite an EXISTING one?" — answered by the transition
# table below, not by comparing ranks.
#
# The table lists every LEGITIMATE transition (from-status → to-status
# pairs the engine's own nodes perform). Anything absent is refused: a
# stale re-emission (e.g. a regenerated copy still carrying
# ``unexplored``) can never drag a hypothesis that already reached
# ``investigating``/``promoted``/terminal back to an earlier state.
# Refused transitions do NOT drop the update silently: the incoming
# status is recorded in the hypothesis's origin_detail provenance
# block as a lifecycle conflict (auditable, bounded), and every other
# incoming field is still merged field-by-field under the preservation
# rules (evidence_refs, origin, parent, decision refs accumulate).
_LEGITIMATE_HYPOTHESIS_TRANSITIONS: frozenset[tuple[str, str]] = frozenset({
    # initial work states
    ("unexplored", "investigating"),
    ("unexplored", "abandoned"),
    ("unexplored", "promoted"),
    # investigation outcomes
    ("investigating", "promoted"),
    ("investigating", "abandoned"),
    ("investigating", "resolved_true"),
    ("investigating", "resolved_false"),
    ("investigating", "learned"),
    # post-promotion outcomes (debunked findings stay ``promoted`` as
    # an audit trail — see HypothesisStatus docstring — but a promoted
    # hypothesis can still be closed out by the engine)
    ("promoted", "resolved_true"),
    ("promoted", "resolved_false"),
    ("promoted", "learned"),
    # learning from any terminal state
    ("abandoned", "learned"),
    ("resolved_true", "learned"),
    ("resolved_false", "learned"),
    # reopening a CLOSED hypothesis requires an explicit, legitimate
    # reopen transition — a stale copy re-entering the pool is not one
    ("abandoned", "investigating"),
    # self-transitions (idempotent re-emission at the same state)
    ("unexplored", "unexplored"),
    ("investigating", "investigating"),
    ("promoted", "promoted"),
    ("abandoned", "abandoned"),
    ("resolved_true", "resolved_true"),
    ("resolved_false", "resolved_false"),
    ("learned", "learned"),
})

# Terminal statuses: reached once, they survive stale re-emissions.
# resolved_true/resolved_false are ALSO contradictory-pair aware: a
# record that already holds a terminal verdict keeps it, and a NEW
# contradictory verdict is recorded as a conflict instead of
# overwriting it (§6: "any irresolvable conflict is recorded, never
# hidden").
_HYPOTHESIS_TERMINAL_STATUSES = frozenset({
    "resolved_true", "resolved_false", "learned",
})


def _merge_hypothesis_records(existing: Any, new: Any) -> Any:
    """Field-wise merge of a re-emitted hypothesis (§6 preservation).

    Order matters: the NEW record provides defaults for fields the old
    one lacks; the OLD record's advanced lifecycle data wins over the
    stale copy's. Returns a dict or model matching the EXISTING
    record's shape (dict-shaped checkpoint state stays dict-shaped).
    """
    import datetime as _dt

    existing_is_dict = isinstance(existing, dict)
    if existing_is_dict:
        base = dict(existing)
    else:
        base = {
            k: model_get(existing, k) for k in (
                "id", "target_url", "statement", "vuln_class", "status",
                "confidence_score", "evidence_refs", "origin",
                "origin_detail", "estimated_cost", "parent_hypothesis_id",
                "created_at", "updated_at", "request_method", "request_data",
                "target_param", "preconditions", "alternatives",
                "expected_behavior", "negative_control", "hint_provenance",
            ) if model_get(existing, k) is not None
        }

    # --- preservation rules (§6): accumulate, never replace ------
    old_refs = list(model_get(existing, "evidence_refs") or [])
    new_refs = list(model_get(new, "evidence_refs") or [])
    merged_refs, seen = [], set()
    for ref in old_refs + new_refs:
        key = str(ref)
        if key not in seen:
            seen.add(key)
            merged_refs.append(ref)
    base["evidence_refs"] = merged_refs[:64]  # bounded

    # provenance: keep the original origin; append the re-emission's
    # origin detail (truncated, bounded) so the audit trail grows
    # without overwriting who first created the hypothesis.
    old_detail = str(model_get(existing, "origin_detail") or "")
    new_detail = str(model_get(new, "origin_detail") or "")
    if new_detail and new_detail != old_detail:
        addition = f" | re-emitted[{new_detail[:200]}]"
        if addition not in old_detail:
            base["origin_detail"] = (old_detail + addition)[-500:]
    else:
        base["origin_detail"] = old_detail

    # parent link, preconditions, alternatives, hints: union (bounded)
    base["parent_hypothesis_id"] = (
        model_get(existing, "parent_hypothesis_id")
        or model_get(new, "parent_hypothesis_id"))
    for field_name in ("preconditions", "alternatives", "hint_provenance"):
        merged_l, seen_l = [], set()
        for value in (list(model_get(existing, field_name) or [])
                      + list(model_get(new, field_name) or [])):
            if str(value) not in seen_l:
                seen_l.add(str(value))
                merged_l.append(value)
        base[field_name] = merged_l[:32]

    # numeric fields: keep the existing (measured) values unless the
    # existing record has none (a re-emission may carry the first
    # estimate).
    for field_name in ("estimated_cost", "confidence_score",
                       "novelty_score", "info_gain", "risk"):
        if model_get(existing, field_name) is None:
            base[field_name] = model_get(new, field_name)

    # --- lifecycle: apply the transition contract ----------------
    # status may arrive as a HypothesisStatus enum, a raw str, or a
    # dict value after a checkpoint round-trip — normalize to the
    # plain string value before consulting the transition table.
    def _status_value(candidate: Any) -> str:
        raw = model_get(candidate, "status")
        if raw is None:
            return "unexplored"
        # HypothesisStatus is a str-enum: str(enum) is
        # "HypothesisStatus.X" but .value is the plain name — accept
        # enum, str and dict-value shapes without dynamic resolution.
        from enum import Enum
        if isinstance(raw, Enum):
            raw = raw.value
        return str(raw).strip().lower() or "unexplored"

    old_status = _status_value(existing)
    new_status = _status_value(new)
    if old_status == new_status or (
            (old_status, new_status)
            in _LEGITIMATE_HYPOTHESIS_TRANSITIONS):
        base["status"] = new_status
    elif old_status in _HYPOTHESIS_TERMINAL_STATUSES:
        # stale/contradictory update on a terminal record: record the
        # conflict, keep the terminal verdict (§6 lifecycle case 6).
        base["status"] = old_status
        conflict = (f"lifecycle-conflict[{new_status} rejected: "
                    f"terminal {old_status} preserved]")
        detail = str(base.get("origin_detail") or "")
        if conflict not in detail:
            base["origin_detail"] = (detail + " | " + conflict)[-500:]
    else:
        # refused backward/invalid transition: keep the advanced
        # status, record what was refused (auditable, not hidden).
        base["status"] = old_status
        conflict = (f"lifecycle-conflict[{old_status} -> {new_status} "
                    "refused: not a legitimate transition]")
        detail = str(base.get("origin_detail") or "")
        if conflict not in detail:
            base["origin_detail"] = (detail + " | " + conflict)[-500:]

    # timestamps: created_at never changes; updated_at advances only
    # when the record actually changed state or gained evidence.
    base["created_at"] = (model_get(existing, "created_at")
                          or model_get(new, "created_at"))
    if (base["status"] != old_status
            or len(merged_refs) != len(old_refs)):
        base["updated_at"] = (
            model_get(new, "updated_at")
            or _dt.datetime.now(_dt.timezone.utc).isoformat())

    # request context: fill from the new record only where missing.
    for field_name in ("request_method", "request_data", "target_param",
                       "expected_behavior", "negative_control"):
        if model_get(base, field_name) in (None, "", {}, []):
            base[field_name] = model_get(new, field_name)

    if existing_is_dict:
        return base
    try:  # revalidate into the model when handed a model instance
        from webpent.models.hypothesis import Hypothesis
        return Hypothesis.model_validate(base)
    except Exception:  # pragma: no cover — defensive: keep dict shape
        return base


def merge_hypotheses(
    existing: list[Any] | None,
    new: list[Any] | None,
) -> list[Any]:
    """V9 P0 B2 → UM-DR-43C: upsert-by-id reducer with lifecycle
    integrity for the ``hypotheses`` state field.

    Previously ``hypotheses`` used :func:`merge_lists` (append-only),
    which meant every ``model_copy(update={"status": ...})`` returned by
    the Strategist on promote/abandon was appended as a NEW item —
    producing duplicates in state and in the final report.

    This reducer mirrors :func:`merge_findings`' upsert semantics:
    each hypothesis is keyed by its ``id`` UUID. UM-DR-43C sharpens
    the upsert into a field-wise merge (see
    :func:`_merge_hypothesis_records`): a re-emitted hypothesis can
    no longer reset an advanced status, and evidence refs, origin
    provenance and parent links accumulate instead of being replaced.

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
            if hid in merged:
                # UM-DR-43C: same id arriving again — merge the records
                # under the lifecycle contract instead of replacing the
                # existing entry with the (possibly stale) new one.
                merged[hid] = _merge_hypothesis_records(merged[hid], hyp)
            else:
                order.append(hid)
                merged[hid] = hyp
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
