"""Offline contracts for AVDE's six-class controlled benchmark.

The definitions in this module are target-neutral readiness contracts.  They do
not execute a target, synthesize observations, or turn a class definition into
scoring evidence.  A class is scorable only when an input artifact contains a
recorded, confirmed, ground-truthed, proof-complete case for that class.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import asdict, dataclass
from typing import Any

CANONICAL_CLASSES = (
    "broken_access_control",
    "privilege_escalation",
    "business_logic_abuse",
    "information_disclosure",
    "authentication_boundary_issue",
    "data_exposure",
)

CLASS_ALIASES = {
    "idor": "broken_access_control",
    "business_logic": "business_logic_abuse",
    "auth_boundary": "authentication_boundary_issue",
    "authentication": "authentication_boundary_issue",
}


@dataclass(frozen=True)
class ControlledClassContract:
    """A bounded adapter/oracle contract, not a live target implementation."""

    class_id: str
    adapter_id: str
    causal_oracle_id: str
    baseline_contract: str
    candidate_contract: str
    negative_control_contract: str
    proof_bundle_procedure: str
    replay_procedure: str
    allowed_methods: tuple[str, ...] = ("GET", "HEAD")
    execution_status: str = "not_executed"

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


CONTROLLED_CLASS_CONTRACTS = tuple(
    ControlledClassContract(
        class_id=class_id,
        adapter_id=f"avde-local-contract-adapter:{class_id}:v1",
        causal_oracle_id=f"avde-causal-oracle:{class_id}:v1",
        baseline_contract=(
            "record an authorized reference response for the protected boundary; "
            "route reachability alone is insufficient"
        ),
        candidate_contract=(
            "record the same-condition candidate response only after an approved "
            "local precondition is verified"
        ),
        negative_control_contract=(
            "record an independently protected control and require the oracle to "
            "distinguish candidate from control"
        ),
        proof_bundle_procedure=(
            "central verifier receives baseline/candidate/control observations, "
            "causal result, redaction manifest, and a sealed bundle"
        ),
        replay_procedure=(
            "replay the recorded redacted observations and verify the seal without network access"
        ),
    )
    for class_id in CANONICAL_CLASSES
)


def canonical_class(value: object) -> str:
    """Map recorded aliases to the six benchmark classes."""

    normalized = str(value).strip().lower()
    return CLASS_ALIASES.get(normalized, normalized)


def _strict_recorded_case(case: Mapping[str, Any]) -> bool:
    """Return whether a recorded case may enter controlled scoring."""

    return (
        case.get("validation_outcome") == "confirmed"
        and case.get("ground_truth_outcome") == "confirmed"
        and case.get("proof_complete") is True
        and bool(case.get("ground_truth_source"))
    )


def build_class_inventory(
    recorded_cases: Iterable[Mapping[str, Any]],
) -> tuple[dict[str, Any], ...]:
    """Join contracts to actual recorded cases without creating cases."""

    cases = tuple(case for case in recorded_cases if isinstance(case, Mapping))
    inventory: list[dict[str, Any]] = []
    for contract in CONTROLLED_CLASS_CONTRACTS:
        matching = tuple(
            case
            for case in cases
            if canonical_class(case.get("vulnerability_class")) == contract.class_id
        )
        scorable_ids = tuple(
            str(case.get("case_id")) for case in matching if _strict_recorded_case(case)
        )
        status = "scorable" if scorable_ids else "blocked"
        inventory.append(
            {
                **contract.as_dict(),
                "status": status,
                "recorded_case_ids": tuple(str(case.get("case_id")) for case in matching),
                "scorable_case_ids": scorable_ids,
                "blocked_reason": (
                    None
                    if status == "scorable"
                    else "no complete recorded candidate/control causal evidence for this class"
                ),
                "included_in_scoring": status == "scorable",
            }
        )
    return tuple(inventory)


def compute_internal_metrics(
    cases: Iterable[Mapping[str, Any]], inventory: Iterable[Mapping[str, Any]]
) -> dict[str, Any]:
    """Compute bounded research-quality metrics, never production precision/recall."""

    items = tuple(case for case in cases if isinstance(case, Mapping))
    scorable = tuple(case for case in items if _strict_recorded_case(case))
    duplicates = len(items) - len({case.get("case_id") for case in items})
    ranks = [int(case["rank"]) for case in scorable if case.get("rank") is not None]
    completeness = [
        sum(
            bool(case.get(field))
            for field in (
                "ground_truth_source",
                "proof_complete",
                "hypothesis_generated",
            )
        )
        / 3
        for case in scorable
    ]
    return {
        "metric_scope": "recorded_controlled_research_only",
        "hypothesis_relevance": (
            sum(bool(case.get("hypothesis_generated")) for case in scorable) / len(scorable)
            if scorable
            else 0.0
        ),
        "validation_efficiency": (
            len(scorable) / sum(max(int(case.get("requests_used", 0)), 1) for case in scorable)
            if scorable
            else 0.0
        ),
        "evidence_completeness": sum(completeness) / len(completeness) if completeness else 0.0,
        "research_path_efficiency": (
            sum(1 / max(rank, 1) for rank in ranks) / len(ranks) if ranks else 0.0
        ),
        "duplicate_investigation_reduction": (1 - (duplicates / len(items)) if items else 1.0),
        "benchmark_coverage": len(
            {canonical_class(case.get("vulnerability_class")) for case in scorable}
        )
        / len(CANONICAL_CLASSES),
        "production_precision": None,
        "production_recall": None,
        "real_world_detection_rate_measured": False,
        "scorable_case_count": len(scorable),
        "registered_class_count": len(tuple(inventory)),
    }


__all__ = [
    "CANONICAL_CLASSES",
    "CLASS_ALIASES",
    "CONTROLLED_CLASS_CONTRACTS",
    "ControlledClassContract",
    "build_class_inventory",
    "canonical_class",
    "compute_internal_metrics",
]
