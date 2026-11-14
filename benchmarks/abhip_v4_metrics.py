"""Internal ABHIP v5 research-capability metrics.

This module scores recorded report fields only.  It never turns advisory
research measurements into detection or qualification claims.
"""

from __future__ import annotations

from typing import Any


def _ratio(numerator: int | float, denominator: int | float) -> float | None:
    return round(numerator / denominator, 6) if denominator else None


def score_report(
    report: dict[str, Any],
    *,
    previous_report: dict[str, Any] | None = None,
) -> dict[str, Any]:
    classes = report.get("classes", [])
    scorable = [item for item in classes if item.get("scorable") is True]
    blocked = [item for item in classes if item.get("status") == "BLOCKED"]
    cases = [
        case
        for item in scorable
        for case in item.get("cases", [])
        if isinstance(case, dict)
    ]
    capability = report.get("metrics", {}).get("research_capability", {})
    execution = report.get("execution", {})
    governance = report.get("governance", {})
    result: dict[str, Any] = {
        "registered_class_count": len(classes),
        "scorable_class_count": len(scorable),
        "blocked_class_count": len(blocked),
        "recorded_scorable_case_count": len(cases),
        "readiness_coverage": _ratio(len(scorable), len(classes)),
        "research_capability": {
            "autonomy": capability.get("autonomy"),
            "decision_quality": capability.get("decision_quality"),
            "hypothesis_quality": capability.get("hypothesis_quality"),
            "evidence_completeness": capability.get("evidence_completeness"),
            "investigation_efficiency": capability.get("investigation_efficiency"),
            "coverage_improvement": capability.get("coverage_improvement"),
            "learning_effectiveness": capability.get("learning_effectiveness"),
        },
        "production_metrics_available": False,
        "production_detection_rate": None,
        "precision": None,
        "recall": None,
        "f1": None,
        "quality_claim": "recorded_research_capability_coverage_only",
        "reason_metrics_unavailable": (
            "no approved multi-run ground-truth denominator and no production "
            "detection measurement; blocked cases are excluded"
        ),
        "execution_integrity": {
            "offline": execution.get("offline") is True,
            "runner_creates_observations": execution.get("runner_creates_observations") is False,
            "requests_sent": execution.get("requests_sent"),
            "credentials_used": execution.get("credentials_used"),
            "mutations_performed": execution.get("mutations_performed"),
            "external_targets_contacted": execution.get("external_targets_contacted"),
        },
        "governance_integrity": {
            "official_isolated_p10_runs_authorized": governance.get(
                "official_isolated_p10_runs_authorized"
            ),
            "qualification_effect": governance.get("qualification_effect"),
            "vip_status": governance.get("vip_status"),
        },
    }
    if previous_report is None:
        result["previous_version_comparison"] = {
            "status": "NOT_AVAILABLE",
            "reason": "previous report was not supplied",
        }
    else:
        previous_classes = previous_report.get("classes", [])
        previous_scorable = [
            item for item in previous_classes if item.get("scorable") is True
        ]
        previous_cases = sum(
            int(item.get("case_count", 0) or 0) for item in previous_scorable
        )
        result["previous_version_comparison"] = {
            "status": "RECORDED_ARTIFACT_COMPARISON",
            "previous_benchmark_id": previous_report.get("benchmark_id"),
            "class_count_delta": len(classes) - len(previous_classes),
            "scorable_class_count_delta": len(scorable) - len(previous_scorable),
            "scorable_case_count_delta": len(cases) - previous_cases,
            "evidence_completeness_delta": round(
                float(capability.get("evidence_completeness") or 0.0)
                - float(
                    previous_report.get("quality_score", {}).get(
                        "evidence_completeness", 0.0
                    )
                    or 0.0
                ),
                6,
            ),
            "interpretation": "internal recorded-capability comparison; not detection uplift",
        }
    return result


__all__ = ["score_report"]
