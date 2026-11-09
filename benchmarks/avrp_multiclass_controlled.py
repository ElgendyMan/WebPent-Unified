"""Truth-preserving AVRP v1 multiclass benchmark contracts.

This runner is an offline inventory over an existing recorded artifact. It never
contacts a target, creates observations, creates proof bundles, or promotes a
hypothesis. A scenario is scorable only when the source artifact already
contains a complete ground-truth-backed candidate/control chain.
"""

from __future__ import annotations

import argparse
import json
from collections.abc import Iterable, Mapping
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

SCENARIO_CLASSES = (
    "idor",
    "privilege_escalation",
    "business_logic_authorization_failure",
    "information_disclosure",
    "authentication_boundary_issue",
)

_CLASS_ALIASES = {
    "business_logic": "business_logic_authorization_failure",
    "business_logic_abuse": "business_logic_authorization_failure",
    "broken_access_control": "idor",
    "auth_boundary": "authentication_boundary_issue",
    "authentication": "authentication_boundary_issue",
}


@dataclass(frozen=True)
class AVRPScenarioContract:
    """A target-neutral readiness contract, not a live execution adapter."""

    scenario_id: str
    vulnerability_class: str
    target_model_requirement: str
    campaign_requirement: str
    hypothesis_requirement: str
    validation_requirement: str
    causal_oracle_requirement: str
    proof_bundle_requirement: str
    replay_requirement: str
    allowed_methods: tuple[str, ...] = ("GET", "HEAD")
    execution_status: str = "not_executed"

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


SCENARIO_CONTRACTS = tuple(
    AVRPScenarioContract(
        scenario_id=f"avrp-{class_id}-v1",
        vulnerability_class=class_id,
        target_model_requirement=(
            "recorded local target model and protected security boundary; "
            "route reachability is insufficient"
        ),
        campaign_requirement=(
            "recorded bounded research campaign with immutable scope and lineage"
        ),
        hypothesis_requirement=(
            "generated hypothesis links the boundary, affected asset, and expected evidence"
        ),
        validation_requirement=(
            "recorded baseline/candidate/control validation under the same safe conditions"
        ),
        causal_oracle_requirement=(
            "central causal oracle distinguishes the candidate from the independent control"
        ),
        proof_bundle_requirement=(
            "redacted central ProofBundle is sealed only from actual observations"
        ),
        replay_requirement=(
            "central verifier replays the redacted evidence and verifies the seal offline"
        ),
    )
    for class_id in SCENARIO_CLASSES
)


def _canonical_class(value: object) -> str:
    normalized = str(value or "").strip().lower()
    return _CLASS_ALIASES.get(normalized, normalized)


def _complete_recorded_case(case: Mapping[str, Any]) -> bool:
    """Return true only for complete recorded ground-truth-backed evidence."""

    return (
        case.get("validation_outcome") == "confirmed"
        and case.get("ground_truth_outcome") == "confirmed"
        and case.get("proof_complete") is True
        and bool(case.get("ground_truth_source"))
        and bool(case.get("hypothesis_generated"))
    )


def _matching_cases(
    cases: Iterable[Mapping[str, Any]], contract: AVRPScenarioContract
) -> tuple[Mapping[str, Any], ...]:
    return tuple(
        case
        for case in cases
        if _canonical_class(case.get("vulnerability_class")) == contract.vulnerability_class
    )


def build_scenario_inventory(
    recorded_cases: Iterable[Mapping[str, Any]],
) -> tuple[dict[str, Any], ...]:
    """Join five contracts to recorded cases without manufacturing missing fields."""

    cases = tuple(case for case in recorded_cases if isinstance(case, Mapping))
    inventory: list[dict[str, Any]] = []
    for contract in SCENARIO_CONTRACTS:
        matching = _matching_cases(cases, contract)
        scorable = tuple(case for case in matching if _complete_recorded_case(case))
        item: dict[str, Any] = {
            **contract.as_dict(),
            "status": "scorable" if scorable else "blocked",
            "included_in_scoring": bool(scorable),
            "recorded_case_ids": tuple(str(case.get("case_id")) for case in matching),
            "scorable_case_ids": tuple(str(case.get("case_id")) for case in scorable),
            "source_artifact": (
                "reports/evaluation/asros/asros_advanced_controlled_benchmark_v1.json"
                if matching
                else None
            ),
        }
        if scorable:
            item["source_cases"] = tuple(dict(case) for case in scorable)
            item["blocked_reason"] = None
        else:
            item["blocked_reason"] = (
                "No complete recorded candidate/control causal evidence, ground truth, "
                "sealed ProofBundle, and replay record are available for this scenario."
            )
        inventory.append(item)
    return tuple(inventory)


def compute_research_quality_metrics(
    recorded_cases: Iterable[Mapping[str, Any]],
    inventory: Iterable[Mapping[str, Any]],
) -> dict[str, Any]:
    """Compute bounded quality indicators only from complete recorded cases."""

    cases = tuple(case for case in recorded_cases if isinstance(case, Mapping))
    scorable = tuple(case for case in cases if _complete_recorded_case(case))
    inventory_items = tuple(inventory)
    ranks = [int(case["rank"]) for case in scorable if case.get("rank") is not None]
    requests = [max(int(case.get("requests_used", 0)), 1) for case in scorable]
    return {
        "metric_scope": "recorded_controlled_avrp_research_only",
        "registered_scenario_count": len(inventory_items),
        "scorable_case_count": len(scorable),
        "blocked_scenario_count": sum(item["status"] == "blocked" for item in inventory_items),
        "scorable_class_count": len(
            {_canonical_class(case.get("vulnerability_class")) for case in scorable}
        ),
        "hypothesis_relevance": (
            sum(bool(case.get("hypothesis_generated")) for case in scorable) / len(scorable)
            if scorable
            else None
        ),
        "evidence_completeness": (
            sum(
                sum(
                    bool(case.get(field))
                    for field in ("ground_truth_source", "hypothesis_generated", "proof_complete")
                )
                / 3
                for case in scorable
            )
            / len(scorable)
            if scorable
            else None
        ),
        "proof_completeness": (
            sum(bool(case.get("proof_complete")) for case in scorable) / len(scorable)
            if scorable
            else None
        ),
        "validation_efficiency": len(scorable) / sum(requests) if requests else None,
        "research_path_efficiency": (
            sum(1 / max(rank, 1) for rank in ranks) / len(ranks) if ranks else None
        ),
        "production_precision": None,
        "production_recall": None,
        "real_world_detection_rate_measured": False,
        "production_precision_recall_calculated": False,
    }


def evaluate_recorded_artifact(source_path: Path) -> dict[str, Any]:
    """Build the AVRP artifact from a source file without changing that source."""

    source = json.loads(source_path.read_text(encoding="utf-8"))
    cases = source.get("evaluation", {}).get("cases", [])
    inventory = build_scenario_inventory(cases)
    return {
        "schema_version": "avrp-multiclass-controlled-benchmark-v1",
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
        "scenario_contracts": [contract.as_dict() for contract in SCENARIO_CONTRACTS],
        "scenario_inventory": list(inventory),
        "research_quality_metrics": compute_research_quality_metrics(cases, inventory),
        "detection_metrics": {
            "precision": None,
            "recall": None,
            "f1": None,
            "reason": (
                "No approved multi-case ground truth and no official isolated runs; "
                "unavailable metrics stay null."
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
    parser = argparse.ArgumentParser(description="Build the offline AVRP v1 multiclass artifact.")
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    result = evaluate_recorded_artifact(args.source)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps({"output": str(args.output), "scenario_count": 5, "requests_sent": 0}))


if __name__ == "__main__":
    main()


__all__ = [
    "AVRPScenarioContract",
    "SCENARIO_CLASSES",
    "SCENARIO_CONTRACTS",
    "build_scenario_inventory",
    "compute_research_quality_metrics",
    "evaluate_recorded_artifact",
]
