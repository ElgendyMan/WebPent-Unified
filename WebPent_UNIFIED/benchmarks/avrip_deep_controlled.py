"""Offline AVRIP v2 benchmark over recorded controlled evidence only.

This benchmark evaluates whether the AVRIP intelligence layers can be assessed
from an existing recorded artifact without pretending that the older artifact
contains intent, assumption, cross-domain, or optimizer telemetry. It never
contacts a target, creates observations, creates proof bundles, or promotes a
hypothesis.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from benchmarks.avrp_multiclass_controlled import (
    SCENARIO_CLASSES,
    build_scenario_inventory,
)


def _complete_case(case: dict[str, Any]) -> bool:
    return (
        case.get("validation_outcome") == "confirmed"
        and case.get("ground_truth_outcome") == "confirmed"
        and case.get("proof_complete") is True
        and bool(case.get("ground_truth_source"))
        and bool(case.get("hypothesis_generated"))
    )


def _recorded_quality(cases: tuple[dict[str, Any], ...]) -> dict[str, Any]:
    complete = tuple(case for case in cases if _complete_case(case))
    return {
        "metric_scope": "recorded_controlled_evidence_only",
        "recorded_case_count": len(cases),
        "complete_recorded_case_count": len(complete),
        "recorded_hypothesis_relevance": (
            sum(bool(case.get("hypothesis_generated")) for case in complete) / len(complete)
            if complete
            else None
        ),
        "recorded_evidence_completeness": (
            sum(
                sum(
                    bool(case.get(field))
                    for field in ("ground_truth_source", "hypothesis_generated", "proof_complete")
                )
                / 3
                for case in complete
            )
            / len(complete)
            if complete
            else None
        ),
        "recorded_proof_completeness": (
            sum(bool(case.get("proof_complete")) for case in complete) / len(complete)
            if complete
            else None
        ),
        "intent_projection_coverage": None,
        "security_assumption_coverage": None,
        "deep_reasoning_quality": None,
        "cross_domain_join_quality": None,
        "strategy_adaptation_quality": None,
        "reason_unavailable": (
            "The source artifact predates AVRIP v2 telemetry and contains no recorded "
            "intent, assumption lineage, cross-domain join, or optimizer outcome fields."
        ),
        "production_precision": None,
        "production_recall": None,
        "real_world_detection_rate_measured": False,
    }


def evaluate_recorded_artifact(source_path: Path) -> dict[str, Any]:
    """Evaluate an existing artifact without changing or extending its evidence."""

    source = json.loads(source_path.read_text(encoding="utf-8"))
    raw_cases = source.get("evaluation", {}).get("cases", [])
    cases = tuple(case for case in raw_cases if isinstance(case, dict))
    inventory = build_scenario_inventory(cases)
    scorable = tuple(
        case
        for item in inventory
        for case in item.get("source_cases", ())
        if isinstance(case, dict)
    )
    return {
        "schema_version": "avrip-deep-controlled-benchmark-v2",
        "benchmark_scope": {
            "mode": "offline_replay_of_recorded_controlled_artifact",
            "network_scope": "none",
            "external_network": False,
            "credentials": False,
            "state_mutation": False,
            "persistent_service": False,
            "requests_sent_by_this_runner": 0,
            "synthetic_observations_created": False,
            "synthetic_proof_bundles_created": False,
            "source_artifact": str(source_path),
        },
        "registered_vulnerability_classes": list(SCENARIO_CLASSES),
        "scenario_inventory": list(inventory),
        "recorded_scorable_case_ids": [str(case["case_id"]) for case in scorable],
        "research_intelligence_metrics": _recorded_quality(cases),
        "detection_metrics": {
            "precision": None,
            "recall": None,
            "f1": None,
            "reason": (
                "AVRIP v2 has no approved multi-case ground truth or official isolated runs; "
                "production detection metrics remain unavailable."
            ),
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
        "provenance": {
            "source_artifact": str(source_path),
            "source_schema_version": source.get("schema_version"),
            "source_campaign_id": source.get("provenance", {}).get("source_campaign_id"),
            "historical_artifact_unchanged": True,
        },
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Build the offline AVRIP v2 benchmark artifact.")
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    result = evaluate_recorded_artifact(args.source)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(
        json.dumps(
            {
                "output": str(args.output),
                "scenario_count": len(SCENARIO_CLASSES),
                "scorable_case_count": len(result["recorded_scorable_case_ids"]),
                "requests_sent": 0,
            }
        )
    )


if __name__ == "__main__":
    main()


__all__ = ["evaluate_recorded_artifact"]
