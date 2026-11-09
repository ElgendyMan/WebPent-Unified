"""Glue for learning lifecycle events outside the trust spine."""
from __future__ import annotations

from typing import Any

from webpent.memory.improvement_tracker import ImprovementTracker
from webpent.memory.lesson_extractor import extract_campaign_lessons
from webpent.memory.lessons import LessonsManager


def persist_campaign_learning(
    result: dict[str, Any], *, campaign_id: str, client_id: str | None,
    target_type: str = "generic_web", lessons_manager: LessonsManager | None = None,
    tracker: ImprovementTracker | None = None, cost_total: float = 0.0,
    time_total: float | None = None, time_to_first_finding: float | None = None,
    audit_chain: Any | None = None,
) -> dict[str, Any]:
    """Extract/persist lessons and metrics without changing security outcomes."""
    extracted = extract_campaign_lessons(
        result, campaign_id=campaign_id, client_id=client_id, target_type=target_type,
    )
    manager = lessons_manager or LessonsManager()
    saved_ids: list[str] = []
    for lesson in extracted.get("lessons", []):
        saved = manager.save_structured_lesson(lesson)
        if saved:
            saved_ids.append(saved)
    summary = dict(extracted.get("summary") or {})
    summary["saved_lesson_ids"] = saved_ids
    summary["saved_count"] = len(saved_ids)
    if audit_chain is not None:
        audit_chain.append_event(
            event_type="lesson.extracted",
            details={
                "campaign_id": str(campaign_id)[:160],
                "lesson_ids": saved_ids[:200],
                "lesson_count": len(saved_ids),
                "by_type": summary.get("by_type", {}),
            },
        )
    metric = None
    if tracker is not None and str(client_id or "").strip():
        metric = tracker.record_campaign(
            campaign_id=campaign_id, client_id=str(client_id), target_type=target_type,
            result=result, cost_total=cost_total, time_total=time_total,
            time_to_first_finding=time_to_first_finding,
        ).as_dict()
        if audit_chain is not None:
            audit_chain.append_event(
                event_type="learning.metrics_recorded",
                details={
                    "campaign_id": str(campaign_id)[:160],
                    "metric_digest": str(hash(str(metric)))[:16],
                    "hypotheses_tested": metric.get("hypotheses_tested", 0),
                },
            )
    return {"extraction": summary, "metrics": metric}


def record_consultation_audit(
    consultation: dict[str, Any], *, campaign_id: str, audit_chain: Any | None = None,
) -> dict[str, Any]:
    """Record only value-free consultation metadata."""
    event = {
        "campaign_id": str(campaign_id)[:160],
        "target_type": str(consultation.get("target_type") or "generic_web")[:80],
        "applied_lesson_ids": [str(x)[:160] for x in consultation.get("applied_lesson_ids", [])[:200]],
        "route_hits": int(consultation.get("route_hits", 0)),
        "family_hits": int(consultation.get("family_hits", 0)),
        "knowledge_hits": int(consultation.get("knowledge_hits", 0)),
    }
    if audit_chain is not None:
        audit_chain.append_event(event_type="lesson.consulted", details=event)
    return event


__all__ = ["persist_campaign_learning", "record_consultation_audit"]
