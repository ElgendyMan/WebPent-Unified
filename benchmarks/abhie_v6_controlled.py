"""ABHIE v6 controlled benchmark v5.

The benchmark is replay-only.  It reads a previously recorded artifact, applies
 the v6 research-intelligence contract, and never sends requests, creates
observations, modifies evidence, or promotes a hypothesis.
"""

from __future__ import annotations

import argparse
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

CLASSES = (
    "multi_step_idor",
    "privilege_escalation_chain",
    "business_workflow_abuse",
    "tenant_isolation_failure",
    "complex_authorization_issue",
    "sensitive_data_exposure_chain",
)

_CLASS_ALIASES = {
    "idor": "multi_step_idor",
    "multi_step_idor": "multi_step_idor",
    "privilege_escalation": "privilege_escalation_chain",
    "privilege_escalation_chain": "privilege_escalation_chain",
    "business_logic_authorization_failure": "business_workflow_abuse",
    "business_logic": "business_workflow_abuse",
    "business_workflow_abuse": "business_workflow_abuse",
    "tenant_isolation": "tenant_isolation_failure",
    "tenant_isolation_failure": "tenant_isolation_failure",
    "complex_authorization_issue": "complex_authorization_issue",
    "authorization": "complex_authorization_issue",
    "sensitive_information_exposure": "sensitive_data_exposure_chain",
    "information_disclosure": "sensitive_data_exposure_chain",
    "sensitive_data_exposure_chain": "sensitive_data_exposure_chain",
}

_REQUIRED_SEMANTICS = (
    "realistic target model",
    "hidden security assumptions",
    "multiple investigation paths",
    "autonomous reasoning",
    "causal oracle",
    "sealed ProofBundle",
    "replay verification",
)


def _load(path: Path) -> dict[str, Any]:
    with path.open(encoding="utf-8") as handle:
        value = json.load(handle)
    if not isinstance(value, dict):
        raise ValueError("source_artifact_must_be_object")
    return value


def _entries(source: dict[str, Any]) -> list[dict[str, Any]]:
    containers: list[dict[str, Any]] = [source]
    evaluation = source.get("evaluation")
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


def _proof_ref(source: dict[str, Any], case: dict[str, Any]) -> str:
    direct = case.get("recorded_proof_bundle_ref")
    provenance = source.get("provenance")
    inherited = (
        provenance.get("source_proof_bundle_ref_recorded")
        if isinstance(provenance, dict)
        else None
    )
    return str(direct or inherited or "").strip()


def _target_model_recorded(source: dict[str, Any], case: dict[str, Any]) -> bool:
    provenance = source.get("provenance")
    inherited = provenance.get("target_model") if isinstance(provenance, dict) else None
    return bool(case.get("target_model") or case.get("target_spec") or inherited)


def _assumptions_recorded(case: dict[str, Any]) -> bool:
    value = case.get("hidden_security_assumptions")
    return bool(value) and value not in ([], {}, "")


def _paths_recorded(case: dict[str, Any]) -> bool:
    paths = case.get("investigation_paths")
    if isinstance(paths, list):
        return len(paths) >= 2
    return int(case.get("candidate_paths_considered") or 0) >= 2


def _autonomous_recorded(case: dict[str, Any]) -> bool:
    return bool(
        case.get("autonomous_reasoning")
        or case.get("autonomous_decision_recorded")
        or case.get("hypothesis_generated")
    )


def _causal_recorded(case: dict[str, Any]) -> bool:
    return bool(case.get("causal_oracle_passed")) or case.get(
        "validation_outcome"
    ) == "confirmed"


def _proof_recorded(source: dict[str, Any], case: dict[str, Any]) -> bool:
    return bool(case.get("proof_bundle_sealed")) or (
        case.get("proof_complete") is True and bool(_proof_ref(source, case))
    )


def _replay_recorded(case: dict[str, Any]) -> bool:
    return bool(case.get("replay_verified"))


def _readiness(source: dict[str, Any], case: dict[str, Any]) -> dict[str, bool]:
    return {
        "realistic_target_model": _target_model_recorded(source, case),
        "hidden_security_assumptions": _assumptions_recorded(case),
        "multiple_investigation_paths": _paths_recorded(case),
        "autonomous_reasoning": _autonomous_recorded(case),
        "causal_oracle": _causal_recorded(case),
        "sealed_proof_bundle": _proof_recorded(source, case),
        "replay_verification": _replay_recorded(case),
    }


def _case_record(source: dict[str, Any], case: dict[str, Any]) -> dict[str, Any]:
    readiness = _readiness(source, case)
    missing = [key for key, present in readiness.items() if not present]
    return {
        "case_id": str(case.get("case_id", case.get("id", "unlabelled"))),
        "target_id": str(case.get("target_id", "")),
        "readiness": readiness,
        "missing_requirements": missing,
        "scorable": not missing,
        "status": "SCORABLE" if not missing else "BLOCKED",
        "ground_truth_outcome": case.get("ground_truth_outcome"),
        "ground_truth_source": case.get("ground_truth_source"),
        "hypothesis_generated": case.get("hypothesis_generated") is True,
        "recorded_proof_bundle_ref": _proof_ref(source, case),
        "validation_outcome": case.get("validation_outcome"),
        "requests_used": int(case.get("requests_used") or 0),
        "evidence_modified": False,
    }


def _catalog(category: str, candidates: list[dict[str, Any]]) -> dict[str, Any]:
    scorable = [item for item in candidates if item["scorable"]]
    return {
        "class": category,
        "status": "SCORABLE" if scorable else "BLOCKED",
        "scorable": bool(scorable),
        "case_count": len(scorable),
        "candidate_count": len(candidates),
        "cases": scorable,
        "blocked_candidates": [
            {
                "case_id": item["case_id"],
                "missing_requirements": item["missing_requirements"],
            }
            for item in candidates
            if not item["scorable"]
        ],
        "readiness_contract": {
            "target_neutral": True,
            "missing_evidence_is_blocking": True,
            "required_semantics": list(_REQUIRED_SEMANTICS),
            "runner_must_not_execute": True,
        },
        "reason": (
            "all v6 research-intelligence requirements are recorded"
            if scorable
            else "one or more required v6 research-intelligence requirements are missing"
        ),
    }


def build_report(source_path: Path) -> dict[str, Any]:
    source = _load(source_path)
    candidates_by_class: dict[str, list[dict[str, Any]]] = {
        category: [] for category in CLASSES
    }
    for case in _entries(source):
        category = _class_of(case)
        if category in candidates_by_class:
            candidates_by_class[category].append(_case_record(source, case))

    classes = [_catalog(category, candidates_by_class[category]) for category in CLASSES]
    scorable_cases = [
        case
        for category in candidates_by_class.values()
        for case in category
        if case["scorable"]
    ]
    quality_dimensions = {
        "discovery_depth": None,
        "reasoning_quality": None,
        "evidence_strength": None,
        "research_efficiency": None,
        "strategy_improvement": None,
        "coverage_growth": None,
    }
    if scorable_cases:
        quality_dimensions = {
            "discovery_depth": round(
                sum(
                    int(case.get("candidate_paths_considered") or 0)
                    for case in scorable_cases
                )
                / len(scorable_cases),
                6,
            ),
            "reasoning_quality": round(
                sum(bool(case["hypothesis_generated"]) for case in scorable_cases)
                / len(scorable_cases),
                6,
            ),
            "evidence_strength": round(
                sum(
                    bool(case["ground_truth_outcome"])
                    and bool(case["ground_truth_source"])
                    for case in scorable_cases
                )
                / len(scorable_cases),
                6,
            ),
            "research_efficiency": None,
            "strategy_improvement": None,
            "coverage_growth": None,
        }

    return {
        "benchmark_id": "ABHIE-v6-vip-research-benchmark-v5",
        "schema_version": "abhie-v6-controlled-benchmark-v5",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "source_artifact": str(source_path),
        "source_artifact_read_only": True,
        "registered_classes": list(CLASSES),
        "classes": classes,
        "recorded_complete_case_ids": sorted(
            case["case_id"] for case in scorable_cases
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
            "recorded_scorable_case_count": len(scorable_cases),
            "research_intelligence": quality_dimensions,
            "precision": None,
            "recall": None,
            "f1": None,
            "real_world_detection_rate": None,
            "valid_ground_truth": False,
            "reason_metrics_unavailable": (
                "v6 requires complete target-model, assumption, path, oracle, "
                "proof, and replay evidence; blocked candidates are excluded"
            ),
        },
        "benchmark_quality": {
            "claim": "research_intelligence_contract_readiness_only",
            "hardcoded_detection": False,
            "missing_requirements_block": True,
            "production_detection_measured": False,
        },
        "self_review": {
            "status": "ADVISORY_ONLY",
            "challenges": [
                "assumption validity",
                "evidence sufficiency",
                "realistic impact",
                "alternative explanations",
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
        default=Path(
            "reports/evaluation/asros/asros_advanced_controlled_benchmark_v1.json"
        ),
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


__all__ = ["CLASSES", "build_report"]


# The benchmark deliberately does not expose an execution adapter.  All input
# is a recorded artifact and all output is an analysis report.
