"""ABHIP v5 controlled benchmark v4, offline and evidence-conservative.

The runner reads a previously recorded artifact only.  It does not execute
requests, create observations, synthesize proof, or promote a hypothesis.
"""

from __future__ import annotations

import argparse
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

CLASSES = (
    "idor",
    "privilege_escalation",
    "business_logic_authorization_failure",
    "tenant_isolation",
    "workflow_abuse",
    "sensitive_information_exposure",
)

_REQUIRED_SEMANTICS = (
    "hidden security assumptions",
    "multiple possible research paths",
    "autonomous decision requirement",
    "causal oracle result",
    "sealed ProofBundle",
    "replay verification",
)

_CLASS_ALIASES = {
    "business_logic": "business_logic_authorization_failure",
    "business_logic_authorization": "business_logic_authorization_failure",
    "business_logic_authorization_failure": "business_logic_authorization_failure",
    "information_disclosure": "sensitive_information_exposure",
    "information_exposure": "sensitive_information_exposure",
    "sensitive_information_exposure": "sensitive_information_exposure",
    "privilege_escalation_chain": "privilege_escalation",
    "tenant_isolation_failure": "tenant_isolation",
    "workflow_authorization_issue": "workflow_abuse",
}


def _load(path: Path) -> dict[str, Any]:
    with path.open(encoding="utf-8") as handle:
        data = json.load(handle)
    if not isinstance(data, dict):
        raise ValueError("source_artifact_must_be_object")
    return data


def _case_entries(source: dict[str, Any]) -> list[dict[str, Any]]:
    evaluation = source.get("evaluation")
    containers = [source]
    if isinstance(evaluation, dict):
        containers.append(evaluation)
    for container in containers:
        for key in ("cases", "results", "scenarios", "case_results"):
            value = container.get(key)
            if isinstance(value, list):
                return [item for item in value if isinstance(item, dict)]
    return []


def _class_of(case: dict[str, Any]) -> str:
    value = (
        case.get("class")
        or case.get("vulnerability_class")
        or case.get("category")
        or case.get("type")
    )
    normalized = str(value).strip().lower().replace(" ", "_") if value else ""
    return _CLASS_ALIASES.get(normalized, normalized)


def _proof_reference(source: dict[str, Any], case: dict[str, Any]) -> str:
    direct = case.get("recorded_proof_bundle_ref")
    provenance = source.get("provenance")
    inherited = (
        provenance.get("source_proof_bundle_ref_recorded")
        if isinstance(provenance, dict)
        else None
    )
    return str(direct or inherited or "").strip()


def _complete_recorded_case(source: dict[str, Any], case: dict[str, Any]) -> bool:
    explicit = (
        bool(case.get("causal_oracle_passed")),
        bool(case.get("negative_control_complete")),
        bool(case.get("proof_bundle_sealed")),
        bool(case.get("replay_verified")),
    )
    if all(explicit):
        return True
    return (
        case.get("validation_outcome") == "confirmed"
        and case.get("ground_truth_outcome") == "confirmed"
        and case.get("proof_complete") is True
        and bool(case.get("ground_truth_source"))
        and case.get("hypothesis_generated") is True
        and bool(_proof_reference(source, case))
    )


def _case_record(source: dict[str, Any], case: dict[str, Any]) -> dict[str, Any]:
    return {
        "case_id": str(case.get("case_id", case.get("id", "unlabelled"))),
        "target_id": str(case.get("target_id", "")),
        "evidence_basis": "explicit_v4_fields" if all(
            bool(case.get(field))
            for field in (
                "causal_oracle_passed",
                "negative_control_complete",
                "proof_bundle_sealed",
                "replay_verified",
            )
        ) else "historical_equivalent_fields_only",
        "hidden_assumptions_recorded": bool(case.get("hidden_security_assumptions")),
        "candidate_paths_considered": int(case.get("candidate_paths_considered") or 0),
        "autonomous_decision_recorded": bool(case.get("hypothesis_generated")),
        "causal_oracle_recorded": bool(case.get("causal_oracle_passed"))
        or case.get("validation_outcome") == "confirmed",
        "negative_control_recorded": bool(case.get("negative_control_complete")),
        "proof_bundle_recorded": bool(case.get("proof_complete")) and bool(
            _proof_reference(source, case)
        ),
        "replay_recorded": bool(case.get("replay_verified")),
        "ground_truth_outcome": case.get("ground_truth_outcome"),
        "ground_truth_source": case.get("ground_truth_source"),
        "hypothesis_generated": case.get("hypothesis_generated") is True,
        "proof_complete": case.get("proof_complete") is True,
        "recorded_proof_bundle_ref": _proof_reference(source, case),
        "validation_outcome": case.get("validation_outcome"),
        "evidence_quality": case.get("evidence_quality"),
        "requests_used": int(case.get("requests_used") or 0),
        "unnecessary_paths_executed": int(case.get("unnecessary_paths_executed") or 0),
        "rank": case.get("rank"),
        "expected_rank": case.get("expected_rank"),
    }


def _catalog_entry(category: str, cases: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        "class": category,
        "status": "SCORABLE_FROM_RECORDED_ARTIFACT" if cases else "BLOCKED",
        "scorable": bool(cases),
        "case_count": len(cases),
        "cases": cases,
        "readiness_contract": {
            "target_neutral": True,
            "missing_evidence_is_blocking": True,
            "required_semantics": list(_REQUIRED_SEMANTICS),
            "runner_must_not_execute": True,
        },
        "reason": (
            "complete recorded oracle/control/proof/replay evidence joined"
            if cases
            else "no complete recorded evidence satisfying the v4 readiness contract"
        ),
    }


def _previous_comparison() -> dict[str, Any]:
    previous_path = Path("reports/evaluation/abhie/abhie_v4_controlled_benchmark.json")
    if not previous_path.exists():
        return {
            "status": "NOT_AVAILABLE",
            "previous_artifact": None,
            "reason": "previous ABHIE v4 artifact is not present",
        }
    previous = _load(previous_path)
    previous_quality = previous.get("quality_score", {})
    previous_classes = previous.get("classes", [])
    previous_scorable = [
        item for item in previous_classes if item.get("scorable") is True
    ]
    previous_cases = sum(
        int(item.get("case_count", 0) or 0) for item in previous_scorable
    )
    return {
        "status": "RECORDED_ARTIFACT_COMPARISON",
        "previous_artifact": str(previous_path),
        "previous_benchmark_id": previous.get("benchmark_id"),
        "class_count_delta": len(CLASSES) - len(previous_classes),
        "previous_scorable_class_count": len(previous_scorable),
        "previous_scorable_case_count": previous_cases,
        "interpretation": "use abhip_v4_metrics.score_report for computed deltas",
        "previous_quality_evidence_completeness": previous_quality.get(
            "evidence_completeness"
        ),
    }


def build_report(source_path: Path) -> dict[str, Any]:
    source = _load(source_path)
    entries = _case_entries(source)
    complete_by_class: dict[str, list[dict[str, Any]]] = {category: [] for category in CLASSES}
    for case in entries:
        category = _class_of(case)
        if category in complete_by_class and _complete_recorded_case(source, case):
            complete_by_class[category].append(_case_record(source, case))

    classes = [_catalog_entry(category, complete_by_class[category]) for category in CLASSES]
    complete_cases = [case for cases in complete_by_class.values() for case in cases]
    ranked_cases = [
        case
        for case in complete_cases
        if case["rank"] is not None and case["expected_rank"] is not None
    ]
    decision_quality = (
        sum(case["rank"] == case["expected_rank"] for case in ranked_cases)
        / len(ranked_cases)
        if ranked_cases
        else None
    )
    hypothesis_quality = (
        sum(case["hypothesis_generated"] for case in complete_cases) / len(complete_cases)
        if complete_cases
        else None
    )
    evidence_fields = (
        "ground_truth_outcome",
        "ground_truth_source",
        "hypothesis_generated",
        "proof_complete",
        "recorded_proof_bundle_ref",
        "validation_outcome",
    )
    evidence_completeness = (
        sum(bool(case.get(field)) for case in complete_cases for field in evidence_fields)
        / (len(complete_cases) * len(evidence_fields))
        if complete_cases
        else 0.0
    )
    efficiency = (
        sum(
            max(0, case["candidate_paths_considered"] - case["unnecessary_paths_executed"])
            for case in complete_cases
        )
        / sum(case["candidate_paths_considered"] for case in complete_cases)
        if complete_cases and sum(case["candidate_paths_considered"] for case in complete_cases)
        else None
    )
    return {
        "benchmark_id": "ABHIP-v5-controlled-benchmark-v4",
        "schema_version": "abhip-v5-controlled-benchmark-v4",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "source_artifact": str(source_path),
        "source_artifact_read_only": True,
        "registered_classes": list(CLASSES),
        "classes": classes,
        "recorded_complete_case_ids": sorted(
            case["case_id"] for case in complete_cases
        ),
        "execution": {
            "offline": True,
            "runner_creates_observations": False,
            "requests_sent": 0,
            "credentials_used": False,
            "mutations_performed": False,
            "external_targets_contacted": False,
        },
        "metrics": {
            "registered_class_count": len(CLASSES),
            "scorable_class_count": sum(item["scorable"] for item in classes),
            "blocked_class_count": sum(not item["scorable"] for item in classes),
            "recorded_scorable_case_count": len(complete_cases),
            "research_capability": {
                "autonomy": hypothesis_quality,
                "decision_quality": decision_quality,
                "hypothesis_quality": hypothesis_quality,
                "evidence_completeness": round(evidence_completeness, 6),
                "investigation_efficiency": efficiency,
                "coverage_improvement": None,
                "learning_effectiveness": None,
            },
            "precision": None,
            "recall": None,
            "f1": None,
            "production_detection_rate": None,
            "real_world_detection_rate": None,
            "valid_ground_truth": False,
            "reason_metrics_unavailable": (
                "no approved multi-run denominator; blocked or missing classes are "
                "excluded and production detection is not measured"
            ),
        },
        "previous_version_comparison": _previous_comparison(),
        "self_review": {
            "status": "ADVISORY_ONLY",
            "challenges": [
                "finding validity",
                "evidence quality",
                "impact",
                "reasoning",
                "reproducibility",
            ],
            "qualification_approved": False,
            "oracle_overridden": False,
            "evidence_modified": False,
        },
        "governance": {
            "official_isolated_p10_runs_authorized": False,
            "p10_status": "NOT_QUALIFIED",
            "p9_status": "NOT_QUALIFIED",
            "vip_status": "NOT_QUALIFIED",
            "bug_bounty_status": "BLOCKED",
            "human_signoff": False,
            "qualification_effect": False,
        },
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--source-artifact",
        type=Path,
        default=Path("reports/evaluation/asros/asros_advanced_controlled_benchmark_v1.json"),
    )
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    report = build_report(args.source_artifact)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    print(json.dumps(report["metrics"], sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
