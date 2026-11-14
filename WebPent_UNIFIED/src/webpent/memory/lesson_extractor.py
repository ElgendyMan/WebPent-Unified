"""Deterministic extraction of advisory lessons from actual campaign results.

This module consumes evidence; it never changes a finding status and never has
execution, authorization, validation, sealing, replay, or promotion authority.
"""
from __future__ import annotations

from collections import Counter, defaultdict
from typing import Any, Iterable

from webpent.memory.lesson_models import (
    LessonType,
    StructuredLesson,
    normalize_family,
    normalize_route_pattern,
)

DEFAULT_ACTIVE_FAMILIES = ("IDOR", "BOLA", "SSRF", "OPEN_REDIRECT", "INFO_DISCLOSURE", "XSS", "SQLI")


def _decision_list(result: dict[str, Any]) -> list[dict[str, Any]]:
    campaign = result.get("campaign") if isinstance(result.get("campaign"), dict) else result
    decisions = campaign.get("decisions") if isinstance(campaign, dict) else []
    return [item for item in decisions if isinstance(item, dict)]


def _hypothesis_map(result: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {
        str(item.get("hypothesis_id") or item.get("id")): item
        for item in result.get("hypotheses", [])
        if isinstance(item, dict) and (item.get("hypothesis_id") or item.get("id"))
    }


def _family(decision: dict[str, Any], hypotheses: dict[str, dict[str, Any]]) -> str | None:
    raw = decision.get("vulnerability_class") or decision.get("family")
    if not raw:
        raw = hypotheses.get(str(decision.get("hypothesis_id")), {}).get("vulnerability_class")
    return normalize_family(raw)


def _route(decision: dict[str, Any], hypotheses: dict[str, dict[str, Any]]) -> str:
    raw = decision.get("route") or decision.get("path")
    if not raw:
        raw = hypotheses.get(str(decision.get("hypothesis_id")), {}).get("route")
    return normalize_route_pattern(raw or "/")


def _parameter(decision: dict[str, Any], hypotheses: dict[str, dict[str, Any]]) -> str | None:
    raw = decision.get("parameter")
    if raw is None:
        raw = hypotheses.get(str(decision.get("hypothesis_id")), {}).get("parameter")
    return str(raw).strip()[:100] or None if raw is not None else None


def _is_promoted(decision: dict[str, Any]) -> bool:
    promotion = decision.get("promotion") if isinstance(decision.get("promotion"), dict) else {}
    proof = decision.get("proof_result") if isinstance(decision.get("proof_result"), dict) else {}
    return bool(
        promotion.get("decision") == "PROMOTED"
        and decision.get("proof_seal_verified") is True
        and decision.get("replay_verified") is True
        and decision.get("identity_bound") is True
        and (proof.get("seal_digest") or decision.get("seal_digest"))
    )


def _is_refuted(decision: dict[str, Any]) -> bool:
    return str(decision.get("validator_outcome") or decision.get("status") or "").upper() == "REFUTED"


def _failure_reason(decision: dict[str, Any]) -> str:
    raw = str(decision.get("validator_reason") or decision.get("promotion_reason") or decision.get("reason") or "validator_refuted")
    lowered = raw.lower()
    for marker, label in (
        ("ssrf", "no_differential_ssrf_signal"),
        ("identity", "identity_binding_not_established"),
        ("causal", "causal_difference_not_established"),
        ("replay", "replay_verification_failed"),
        ("status", "no_differential_status_signal"),
    ):
        if marker in lowered:
            return label
    return "validator_refuted"


def extract_campaign_lessons(
    result: dict[str, Any], *, campaign_id: str, client_id: str | None,
    target_type: str = "generic_web", active_families: Iterable[str] = DEFAULT_ACTIVE_FAMILIES,
) -> dict[str, Any]:
    """Extract structural lessons and a value-free summary from real results."""
    if not str(campaign_id).strip() or not str(client_id or "").strip():
        return {"lessons": [], "summary": {"skipped": "missing_scope"}}
    campaign_id = str(campaign_id).strip()[:160]
    client_id = str(client_id).strip()[:128]
    hypotheses = _hypothesis_map(result)
    decisions = _decision_list(result)
    lessons: list[StructuredLesson] = []
    tested_by_family: Counter[str] = Counter()
    promoted_by_family: Counter[str] = Counter()
    generated_by_family: Counter[str] = Counter()
    executable_by_family: Counter[str] = Counter()

    for item in result.get("hypotheses", []):
        fam = normalize_family(item.get("vulnerability_class")) if isinstance(item, dict) else None
        if fam:
            generated_by_family[fam] += 1
            if item.get("executable"):
                executable_by_family[fam] += 1

    for decision in decisions:
        fam = _family(decision, hypotheses)
        if not fam:
            continue
        route = _route(decision, hypotheses)
        parameter = _parameter(decision, hypotheses)
        tested_by_family[fam] += 1
        if _is_promoted(decision):
            promoted_by_family[fam] += 1
            finding_id = str((decision.get("promotion") or {}).get("finding_id") or decision.get("finding_id") or "")[:160]
            lessons.append(StructuredLesson(
                lesson_type=LessonType.POSITIVE, route_pattern=route, parameter_name=parameter,
                family=fam, target_type=target_type,
                reason="verified promoted finding on this structural route and family",
                boost_factor=0.3, evidence_count=1, confidence=0.9,
                source_campaign_ids=(campaign_id,), source_finding_ids=(finding_id,) if finding_id else (),
                client_id=client_id,
            ))
        elif _is_refuted(decision):
            lessons.append(StructuredLesson(
                lesson_type=LessonType.NEGATIVE, route_pattern=route, parameter_name=parameter,
                family=fam, target_type=target_type,
                reason=f"validator refuted this route/family: {_failure_reason(decision)}",
                boost_factor=-0.2, evidence_count=1, confidence=0.7,
                source_campaign_ids=(campaign_id,), client_id=client_id,
            ))

    # A priority lesson requires repeated, actual observations and is only a
    # ranking hint; it cannot turn a refutation into a finding.
    for fam, tested in tested_by_family.items():
        if tested >= 2 and promoted_by_family[fam] > 0:
            rate = promoted_by_family[fam] / tested
            lessons.append(StructuredLesson(
                lesson_type=LessonType.PRIORITY, family=fam, target_type=target_type,
                route_pattern="/*",
                reason=f"observed {promoted_by_family[fam]} promoted result(s) in {tested} tested hypothesis(es)",
                boost_factor=min(0.5, round(rate * 0.5, 3)), evidence_count=tested,
                confidence=min(0.95, 0.5 + rate / 2), source_campaign_ids=(campaign_id,), client_id=client_id,
            ))

    active = {normalize_family(item) for item in active_families}
    active.discard(None)
    campaign = result.get("campaign") if isinstance(result.get("campaign"), dict) else result
    stopped_early = bool(
        result.get("crawl", {}).get("budget_exhausted")
        or campaign.get("budget_exhausted")
        or campaign.get("halted_before_execution")
    )
    for fam in sorted(active):
        if executable_by_family[fam] > tested_by_family[fam] and (stopped_early or executable_by_family[fam] > 0):
            lessons.append(StructuredLesson(
                lesson_type=LessonType.COVERAGE_GAP, family=fam, target_type=target_type,
                route_pattern="/*", reason="budget_or_decision_window_exhausted_before testing all executable hypotheses",
                boost_factor=0.0, evidence_count=max(1, executable_by_family[fam] - tested_by_family[fam]),
                confidence=0.8, source_campaign_ids=(campaign_id,), client_id=client_id,
            ))

    type_counts = Counter(str(item.lesson_type) for item in lessons)
    return {
        "lessons": lessons,
        "summary": {
            "campaign_id": campaign_id,
            "client_id": client_id,
            "target_type": target_type,
            "lesson_count": len(lessons),
            "by_type": dict(type_counts),
            "tested_by_family": dict(tested_by_family),
            "promoted_by_family": dict(promoted_by_family),
            "generated_by_family": dict(generated_by_family),
            "executable_by_family": dict(executable_by_family),
        },
    }


__all__ = ["extract_campaign_lessons", "DEFAULT_ACTIVE_FAMILIES"]
