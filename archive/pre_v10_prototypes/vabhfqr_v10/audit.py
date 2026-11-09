"""Deterministic final-audit composition over recorded project evidence only."""

from __future__ import annotations

from collections.abc import Iterable, Mapping

from .contracts import (
    AuditStatus,
    CapabilityAssessmentV10,
    GapRecordV10,
    ImplementationStatus,
    ProjectStateReportV10,
    VipReadinessScorecardV10,
)

AUDIT_VERSION = "vabh-final-audit-v10"

CAPABILITY_WEIGHTS: dict[str, float] = {
    "autonomous_research_loop": 1.0,
    "target_intelligence": 1.0,
    "security_reasoning": 1.0,
    "attack_graph": 0.8,
    "hypothesis_generation": 1.0,
    "research_planning": 1.0,
    "adaptive_strategy": 0.8,
    "memory_and_learning": 0.8,
    "evidence_pipeline": 1.0,
    "causal_validation": 1.0,
    "proofbundle_integrity": 1.0,
    "replay_capability": 1.0,
    "benchmark_framework": 1.0,
    "metrics_system": 1.0,
    "governance_boundaries": 1.2,
}


def _bounded(value: object, default: float = 0.0) -> float:
    try:
        number = float(value)
    except (TypeError, ValueError):
        return default
    return min(100.0, max(0.0, number))


def _assessment(name: str, value: Mapping[str, object]) -> CapabilityAssessmentV10:
    status = AuditStatus(str(value.get("status", AuditStatus.PARTIAL)))
    limitation = str(value.get("limitation", ""))
    if status is AuditStatus.PASS:
        limitation = ""
    refs = tuple(str(item) for item in value.get("evidence_refs", ()) if str(item))
    return CapabilityAssessmentV10(
        capability=name,
        status=status,
        maturity_score=_bounded(value.get("maturity_score", 0.0)),
        evidence_refs=refs,
        limitation=limitation,
    )


def build_capabilities(
    values: Mapping[str, Mapping[str, object]],
) -> tuple[CapabilityAssessmentV10, ...]:
    """Build a stable ordered capability map, defaulting absent data to partial."""

    return tuple(
        _assessment(
            name,
            values.get(
                name,
                {
                    "status": AuditStatus.PARTIAL,
                    "maturity_score": 0.0,
                    "limitation": "no recorded audit evidence",
                },
            ),
        )
        for name in CAPABILITY_WEIGHTS
    )


def weighted_readiness(capabilities: Iterable[CapabilityAssessmentV10]) -> float:
    items = tuple(capabilities)
    if not items:
        return 0.0
    total = sum(CAPABILITY_WEIGHTS.get(item.capability, 1.0) for item in items)
    score = sum(
        item.maturity_score * CAPABILITY_WEIGHTS.get(item.capability, 1.0) for item in items
    )
    return round(score / total, 2)


def build_project_state_report(
    *,
    repository: str,
    commit: str,
    branch_parity: bool,
    working_tree_clean: bool,
    inventory: Mapping[str, int],
    capability_values: Mapping[str, Mapping[str, object]],
    gaps: Iterable[GapRecordV10],
    technical_debt: Iterable[str],
    risks: Iterable[str],
    test_summary: Mapping[str, object],
    governance: Mapping[str, object],
    remaining_external_requirements: Iterable[str],
) -> ProjectStateReportV10:
    capabilities = build_capabilities(capability_values)
    return ProjectStateReportV10(
        audit_version=AUDIT_VERSION,
        repository=repository,
        commit=commit,
        branch_parity=branch_parity,
        working_tree_clean=working_tree_clean,
        inventory={str(key): int(value) for key, value in inventory.items()},
        capabilities=capabilities,
        gaps=tuple(gaps),
        technical_debt=tuple(str(item) for item in technical_debt),
        risks=tuple(str(item) for item in risks),
        test_summary=dict(test_summary),
        governance=dict(governance),
        remaining_external_requirements=tuple(
            str(item) for item in remaining_external_requirements
        ),
        readiness_percentage=weighted_readiness(capabilities),
    )


def build_scorecard(
    report: ProjectStateReportV10,
    *,
    blockers: Iterable[str],
    external_requirements: Iterable[str],
) -> VipReadinessScorecardV10:
    by_name = {item.capability: item.maturity_score for item in report.capabilities}

    def average(*names: str) -> float:
        values = [by_name[name] for name in names if name in by_name]
        return round(sum(values) / len(values), 2) if values else 0.0

    component_scores = {
        "architecture_maturity": average(
            "autonomous_research_loop", "evidence_pipeline", "governance_boundaries"
        ),
        "autonomous_intelligence": average(
            "target_intelligence",
            "security_reasoning",
            "attack_graph",
            "hypothesis_generation",
            "research_planning",
            "adaptive_strategy",
            "memory_and_learning",
        ),
        "detection_capability": average("causal_validation", "evidence_pipeline"),
        "evidence_quality": average(
            "evidence_pipeline", "proofbundle_integrity", "replay_capability"
        ),
        "benchmark_maturity": average("benchmark_framework", "metrics_system"),
        "reliability": average("replay_capability", "governance_boundaries"),
        "governance_readiness": by_name.get("governance_boundaries", 0.0),
    }
    return VipReadinessScorecardV10(
        audit_version=AUDIT_VERSION,
        component_scores=component_scores,
        engineering_readiness_percentage=report.readiness_percentage,
        engineering_claim=(
            "engineering-complete for formal qualification evaluation within the bounded, "
            "offline, advisory-only scope"
        ),
        official_qualification="NOT_QUALIFIED",
        blockers=tuple(str(item) for item in blockers),
        external_requirements=tuple(str(item) for item in external_requirements),
        methodology=(
            "Weighted capability maturity from recorded implementation and gate evidence; "
            "no blocked, inconclusive, observation-only, or external qualification result is "
            "promoted to a positive detection metric."
        ),
    )


def gap(
    gap_id: str,
    capability: str,
    severity: str,
    impact: str,
    solution: str,
    *,
    internal: bool,
    status: ImplementationStatus,
    evidence_refs: tuple[str, ...] = (),
) -> GapRecordV10:
    return GapRecordV10(
        gap_id=gap_id,
        missing_capability=capability,
        severity=severity,
        impact=impact,
        recommended_solution=solution,
        implementation_status=status,
        internal=internal,
        evidence_refs=evidence_refs,
    )


__all__ = [
    "AUDIT_VERSION",
    "CAPABILITY_WEIGHTS",
    "build_capabilities",
    "build_project_state_report",
    "build_scorecard",
    "gap",
    "weighted_readiness",
]
