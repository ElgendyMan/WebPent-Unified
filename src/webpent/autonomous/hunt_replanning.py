"""Gap-driven re-hypothesis for the autonomous hunt loop.

Suggestion 1 of the autonomous-convergence program: the hunt generated
hypotheses exactly once, before the execute loop, so every iteration
after the first replayed the same planned tasks until a governance stop
fired. This module closes that loop: knowledge gaps observed during one
iteration become bounded, advisory hypothesis seeds for the next.

Design constraints, all enforced here rather than trusted to callers:

* Advisory only: a synthesized hypothesis is a ranked candidate. It
  carries no request, no promotion, and no evidence of its own; the
  planner, executor, and proof path still gate everything downstream.
* No invention: the only ``target_url`` ever attached is the hunt's own
  target origin, which the planner's same-origin check re-validates.
* Bounded: at most ``max_new`` hypotheses per round (default 8), each
  priority clamped to [0, 0.75] so a gap seed can reorder but never
  dominate the deterministic ranking.
* Deduplicated: against the hypotheses the hunt already holds and
  within the batch itself, by ``hypothesis_id``.
* Fail-closed: anything that is not a coercible, unresolved gap record
  is skipped, never guessed into shape.

Accepted gap-record shapes (v2, post-critique C1):

* Synthetic/legacy: ``{gap_id, description, severity?, required_evidence?,
  resolved?}``.
* Real controller coverage-ledger entry: ``{key, status, attempts, gaps?,
  reason?, evidence_complete?, proof_confirmed?}`` -- exactly what
  ``AutonomousController`` maintains and emits in its update.
* Projected gap entry from ``CoverageIntelligence.project()``: ``{id, key,
  status, attempts, evidence_complete, proof_action_id, task_id, reason,
  gaps[]}``.

The real shapes were verified against the controller's result-assembly code
and the coverage-ledger projection; the synthetic shape is kept so existing
callers and tests keep working unchanged.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any, Final

_PATTERN_ID = "knowledge_gap_followup"
_PRIORITY_BASE = 0.35
_PRIORITY_SPAN = 0.4
_PRIORITY_CEILING = 0.75
_MAX_DESCRIPTION = 200
_MAX_EVIDENCE = 8
_MAX_LEDGER_GAPS = 16

# Statuses on a coverage-ledger entry that represent OPEN, chaseable gaps,
# with the advisory severity each earns. ``tool_confirmed``/``candidate``/
# ``clean`` are terminal in the good direction and are never re-hypothesized.
# ``missing-validator`` is the highest-value gap: a deterministic validator
# simply does not exist yet for that class.
_OPEN_GAP_SEVERITY: Final[dict[str, float]] = {
    "missing-validator": 0.9,
    "human_review_only": 0.85,
    "inconclusive": 0.7,
    "blocked_by_precondition": 0.5,
    "policy_block": 0.3,
    "infrastructure_failure": 0.5,
    "not_scanned": 0.4,
    "unknown": 0.4,
}
_GOOD_TERMINAL_STATUSES = frozenset({"tool_confirmed", "candidate", "clean"})

__all__ = ["gaps_from_coverage_ledger", "synthesize_gap_hypotheses"]


def _field(record: Any, name: str) -> Any:
    if isinstance(record, Mapping):
        return record.get(name)
    return getattr(record, name, None)


def _severity_for(status: str) -> float:
    return _OPEN_GAP_SEVERITY.get(status, 0.4)


def gaps_from_coverage_ledger(
    ledger: Any,
    *,
    max_gaps: int = _MAX_LEDGER_GAPS,
) -> list[dict[str, Any]]:
    """Derive normalized knowledge-gap records from a controller ledger.

    The real ``AutonomousController`` never emits a ``knowledge_gaps`` key;
    its per-class coverage lives in ``coverage_ledger`` entries of the shape
    ``{key, attempts, last_status, proof_confirmed, ...}`` (raw ledger) or
    ``{key, status, attempts, gaps[], reason}`` (projected ledger). This
    helper converts the open (non-confirmed, non-clean) entries into the
    normalized gap records the re-hypothesis path consumes.

    Bounded and deterministic: at most ``max_gaps`` records, ordered by
    descending severity then key, so the loop cannot be flooded by a wide
    ledger and repeated runs see the same ordering.
    """
    if not isinstance(ledger, Mapping):
        return []
    limit = max(0, min(64, int(max_gaps)))
    records: list[dict[str, Any]] = []
    for raw_key, raw_entry in ledger.items():
        if not isinstance(raw_entry, Mapping):
            continue
        key = str(raw_key or raw_entry.get("key") or "").strip()[:160]
        if not key:
            continue
        status = str(
            raw_entry.get("status") or raw_entry.get("last_status") or "unknown"
        ).strip().lower()[:80]
        if status in _GOOD_TERMINAL_STATUSES or status == "clean":
            continue
        gaps = raw_entry.get("gaps")
        gap_strings = [str(item)[:120] for item in list(gaps)[:8]] if gaps else []
        attempts = raw_entry.get("attempts")
        try:
            attempts_value = max(0, int(attempts))
        except (TypeError, ValueError):
            attempts_value = 0
        reason = str(raw_entry.get("reason") or "").strip()
        description = reason or (
            f"coverage gap for {key}: status={status}"
            + (f", gaps={','.join(gap_strings)}" if gap_strings else "")
        )
        records.append(
            {
                "gap_id": f"ledger:{key}",
                "description": description[:_MAX_DESCRIPTION],
                "severity": _severity_for(status),
                "required_evidence": gap_strings,
                "resolved": False,
                "source": "coverage_ledger",
                "vulnerability_class": key,
                "status": status,
                "attempts": attempts_value,
            }
        )
    records.sort(key=lambda r: (-float(r["severity"]), str(r["vulnerability_class"])))
    return records[:limit]


def synthesize_gap_hypotheses(
    knowledge_gaps: Sequence[Any] | None,
    *,
    engagement_id: str,
    target_url: str,
    seen_hypotheses: Sequence[Any] | None = None,
    max_new: int = 8,
) -> list[dict[str, Any]]:
    """Turn unresolved knowledge gaps into bounded hypothesis seeds.

    Accepts legacy synthetic gap records and the real controller shapes
    (coverage-ledger entries and projected gap entries). Returns a list
    sorted by descending priority (ties broken by ``hypothesis_id`` for
    determinism). Returns ``[]`` when nothing coercible remains; callers
    must treat that as "no new work", not as a failure.
    """
    if not knowledge_gaps:
        return []
    seen_ids: set[str] = set()
    for existing in seen_hypotheses or []:
        key = str(_field(existing, "hypothesis_id") or _field(existing, "id") or "")
        if key:
            seen_ids.add(key[:160])

    limit = max(0, min(32, int(max_new)))
    origin = str(target_url or "")[:500]
    synthesized: list[dict[str, Any]] = []
    for gap in knowledge_gaps:
        if len(synthesized) >= limit:
            break
        if gap is None or isinstance(gap, (str, bytes, int, float, bool)):
            continue
        normalized = _normalize_gap(gap)
        if normalized is None:
            continue
        gap_id, description, severity_value, evidence_refs = normalized
        hypothesis_id = f"gap:{gap_id}"
        if hypothesis_id in seen_ids:
            continue
        seen_ids.add(hypothesis_id)
        synthesized.append(
            {
                "hypothesis_id": hypothesis_id,
                "pattern_id": _PATTERN_ID,
                "priority": min(
                    _PRIORITY_CEILING, _PRIORITY_BASE + _PRIORITY_SPAN * severity_value
                ),
                "target_url": origin,
                "origin": "knowledge_gap",
                "rationale": description[:_MAX_DESCRIPTION],
                "evidence_refs": evidence_refs,
                "engagement_id": str(engagement_id or "")[:160],
            }
        )

    synthesized.sort(key=lambda h: (-h["priority"], h["hypothesis_id"]))
    return synthesized


def _normalize_gap(gap: Any) -> tuple[str, str, float, list[str]] | None:
    """Coerce one gap record of any accepted shape into seed fields.

    Returns ``None`` for resolved, terminal-good, or non-coercible records.
    """
    resolved = _field(gap, "resolved")
    if bool(resolved):
        return None

    gap_id = str(_field(gap, "gap_id") or _field(gap, "key") or "").strip()[:160]
    if not gap_id:
        return None

    status = str(_field(gap, "status") or _field(gap, "last_status") or "").strip().lower()[:80]
    if status in _GOOD_TERMINAL_STATUSES or status == "clean":
        return None

    description = str(_field(gap, "description") or _field(gap, "reason") or "").strip()
    if not description:
        if status:
            description = f"coverage gap: status={status}"
        else:
            return None

    severity = _field(gap, "severity")
    try:
        severity_value = max(0.0, min(1.0, float(severity)))
    except (TypeError, ValueError):
        severity_value = _severity_for(status) if status else 0.5

    evidence = _field(gap, "required_evidence") or _field(gap, "gaps")
    evidence_refs = (
        [str(item)[:200] for item in list(evidence)[:_MAX_EVIDENCE]] if evidence else []
    )
    return gap_id, description, severity_value, evidence_refs
