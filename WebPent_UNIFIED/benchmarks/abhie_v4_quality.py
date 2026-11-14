"""Conservative quality scoring for the ABHIE v4 recorded benchmark."""

from __future__ import annotations

from typing import Any


def score_report(report: dict[str, Any]) -> dict[str, Any]:
    classes = report.get("classes", [])
    scorable = [item for item in classes if item.get("scorable") is True]
    blocked = [item for item in classes if item.get("status") == "BLOCKED"]
    recorded_cases = sum(int(item.get("case_count", 0) or 0) for item in scorable)
    complete_case_fields = 0
    total_case_fields = 0
    for item in scorable:
        for case in item.get("cases", []):
            required = (
                "evidence_quality",
                "hypothesis_generated",
                "ground_truth_outcome",
                "validation_outcome",
                "proof_complete",
                "ground_truth_source",
                "recorded_proof_bundle_ref",
            )
            total_case_fields += len(required)
            complete_case_fields += sum(bool(case.get(field)) for field in required)

    evidence_completeness = (
        complete_case_fields / total_case_fields if total_case_fields else 0.0
    )
    execution = report.get("execution", {})
    governance = report.get("governance", {})
    production_metrics_available = False
    return {
        "registered_class_count": len(classes),
        "scorable_class_count": len(scorable),
        "blocked_class_count": len(blocked),
        "recorded_scorable_case_count": recorded_cases,
        "readiness_coverage": len(scorable) / len(classes) if classes else 0.0,
        "evidence_completeness": evidence_completeness,
        "research_depth": None,
        "adaptive_efficiency": None,
        "production_metrics_available": production_metrics_available,
        "precision": None,
        "recall": None,
        "f1": None,
        "real_world_detection_rate": None,
        "quality_claim": "recorded_evidence_coverage_only",
        "reason_metrics_unavailable": (
            "no approved multi-run ground-truth denominator and no live detection "
            "measurement; blocked and missing cases are excluded"
        ),
        "execution_integrity": {
            "offline": execution.get("offline") is True,
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
