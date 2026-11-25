"""UM-DR-46 Phase I — autonomous QC (deterministic checks).

Quality checks over the research artifacts — hypotheses, lessons,
experiment plans — each checked against its producer's contract:

* hypotheses: canonical fields complete, evidence contract present,
  origin a registered HypothesisOrigin member, deterministic_match
  declared;
* lessons: the Phase C record keys (lesson_id, vuln_class,
  refuted_hypothesis_id, evidence_refs);
* experiment plans: a COMPLETE principal matrix (primary AND
  secondary observed) — the Phase F planner's contract, verified here.

QC records are DEFICIENCY REPORTS — artifacts are never deleted or
silently "fixed"; deficiencies stay flagged for the operator. Pure,
bounded, advisory.
"""

from __future__ import annotations

from typing import Any

from webpent.models.hypothesis import HypothesisOrigin

__all__ = ["qc_channel_report", "qc_hypothesis_pool"]

_CANONICAL_FIELDS = (
    "statement", "vuln_class", "origin", "origin_detail", "target_url",
    "expected_behavior", "negative_control",
)
_LESSON_REQUIRED = (
    "lesson_id", "vuln_class", "refuted_hypothesis_id", "evidence_refs",
)
_REGISTERED_ORIGINS = {member.value for member in HypothesisOrigin}


def _status_of(hyp: Any) -> str:
    raw = str(getattr(hyp, "status", ""))
    return raw.split(".")[-1].lower() if raw else ""


def qc_single_hypothesis(hyp: Any) -> dict[str, Any]:
    """One QC record for one hypothesis (deficiencies listed)."""
    checks = {
        "canonical_fields_complete": all(
            str(getattr(hyp, field, "") or "").strip()
            for field in _CANONICAL_FIELDS
        ),
        "evidence_contract_present": bool(getattr(hyp, "evidence_contract", None)),
        "deterministic_match_declared": bool(
            getattr(hyp, "deterministic_match", False)),
        "origin_registered": str(
            getattr(getattr(hyp, "origin", None), "value",
                    getattr(hyp, "origin", "")) or ""
        ) in _REGISTERED_ORIGINS,
    }
    deficiencies = [
        name for name, ok in checks.items() if not ok
    ]
    return {
        "hypothesis_id": str(getattr(hyp, "id", "")),
        "status": _status_of(hyp),
        "checks": checks,
        "deficiencies": deficiencies,
        "qc_verdict": "pass" if not deficiencies else "deficient",
        "advisory_only": True,
    }


def qc_hypothesis_pool(pool: list[Any]) -> list[dict[str, Any]]:
    """QC records for the whole pool (bounded 256, order-stable)."""
    return [qc_single_hypothesis(hyp) for hyp in list(pool)[:256]]


def _lesson_deficiencies(lesson: Any) -> list[str]:
    if not isinstance(lesson, dict):
        return ["not_a_record"]
    return [
        key for key in _LESSON_REQUIRED
        if not lesson.get(key)
    ]


def _plan_deficiencies(plan: Any) -> list[str]:
    if not isinstance(plan, dict):
        return ["not_a_record"]
    matrix = plan.get("principal_matrix")
    if not isinstance(matrix, dict) or not matrix.get("primary") or (
        not matrix.get("secondary")
    ):
        return ["incomplete_principal_matrix"]
    return []


def qc_channel_report(state: Any) -> dict[str, Any]:
    """Channel-level QC over hypotheses, lessons and plans."""
    get = state.get if isinstance(state, dict) else (lambda k, d=None: d)
    pool = list(get("hypotheses") or [])[:256]
    lessons = list(get("research_lessons") or [])[:64]
    plans = list(get("experiment_plans") or [])[:16]

    hypothesis_records = qc_hypothesis_pool(pool)
    lesson_records = [
        {"lesson_id": str(lesson.get("lesson_id") or "")
         if isinstance(lesson, dict) else "not_a_record",
         "deficiencies": _lesson_deficiencies(lesson)}
        for lesson in lessons
    ]
    plan_records = [
        {"plan_id": str(plan.get("plan_id") or "")
         if isinstance(plan, dict) else "not_a_record",
         "deficiencies": _plan_deficiencies(plan)}
        for plan in plans
    ]
    return {
        "built": True,
        "advisory_only": True,
        "hypothesis_count": len(hypothesis_records),
        "hypothesis_deficient_count": sum(
            1 for r in hypothesis_records if r["qc_verdict"] == "deficient"),
        "hypothesis_records": hypothesis_records,
        "lesson_count": len(lesson_records),
        "lesson_deficient_count": sum(
            1 for r in lesson_records if r["deficiencies"]),
        "lesson_records": lesson_records,
        "plan_count": len(plan_records),
        "plan_deficient_count": sum(
            1 for r in plan_records if r["deficiencies"]),
        "plan_records": plan_records,
        "qc_contract": (
            "QC records are deficiency reports — artifacts are never "
            "deleted or silently modified by QC"
        ),
    }
