"""Offline ADI multi-step benchmark contracts.

These contracts describe the reasoning required for an ADI scenario. They are
not adapters that execute targets and they do not create observations, findings,
or proof bundles. A scenario becomes scorable only when a recorded artifact
contains the complete chain evidence and ground-truth-backed proof.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import asdict, dataclass
from typing import Any


@dataclass(frozen=True)
class ADIChainContract:
    """Target-neutral contract for one multi-step research chain."""

    scenario_id: str
    vulnerability_class: str
    target_model: str
    hypothesis_requirement: str
    research_plan_requirement: str
    validation_requirement: str
    oracle_requirement: str
    proof_bundle_requirement: str
    replay_requirement: str
    execution_status: str = "not_executed"

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


ADI_CHAIN_CONTRACTS = (
    ADIChainContract(
        scenario_id="idor_chain",
        vulnerability_class="broken_access_control",
        target_model="owned-versus-unowned object relationship with a protected read boundary",
        hypothesis_requirement=(
            "hypothesis links object identity, subject ownership, and boundary assumption"
        ),
        research_plan_requirement=(
            "plan contains baseline, candidate, and independent negative control"
        ),
        validation_requirement=(
            "same-condition validation differentiates owned and unowned access"
        ),
        oracle_requirement=(
            "causal oracle proves unauthorized object access rather than route reachability"
        ),
        proof_bundle_requirement=(
            "sealed bundle contains redacted candidate/control observations and lineage"
        ),
        replay_requirement="central verifier replays the recorded chain without network access",
    ),
    ADIChainContract(
        scenario_id="privilege_boundary_chain",
        vulnerability_class="privilege_escalation",
        target_model="lower-privilege subject versus protected operation boundary",
        hypothesis_requirement=(
            "hypothesis identifies a privilege assumption and affected operation"
        ),
        research_plan_requirement=(
            "plan compares authorized lower-privilege control with candidate boundary behavior"
        ),
        validation_requirement=(
            "validation is safe, same-condition, and records the privilege contrast"
        ),
        oracle_requirement=(
            "causal oracle proves privilege boundary violation with an independent control"
        ),
        proof_bundle_requirement=(
            "sealed bundle includes privilege context, redacted observations, and verifier result"
        ),
        replay_requirement="replay verifies the privilege contrast and seal offline",
    ),
    ADIChainContract(
        scenario_id="business_workflow_chain",
        vulnerability_class="business_logic_abuse",
        target_model="workflow state transition with a protected approval or ownership invariant",
        hypothesis_requirement=(
            "hypothesis identifies a workflow/state assumption beyond endpoint existence"
        ),
        research_plan_requirement=(
            "plan records permitted baseline and non-mutating candidate/control checks"
        ),
        validation_requirement=(
            "validation demonstrates a causal workflow boundary without destructive mutation"
        ),
        oracle_requirement=(
            "causal oracle distinguishes workflow violation from normal response behavior"
        ),
        proof_bundle_requirement=(
            "sealed bundle records state context, oracle inputs, and redacted evidence"
        ),
        replay_requirement=(
            "replay validates the recorded workflow reasoning without target contact"
        ),
    ),
)

_REQUIRED_CHAIN_FIELDS = (
    "target_model",
    "hypothesis_generated",
    "research_plan_recorded",
    "validation_recorded",
    "oracle_verified",
    "proof_complete",
    "replay_verified",
    "ground_truth_source",
)


def _complete_recorded_chain(case: Mapping[str, Any]) -> bool:
    """Return true only for complete, recorded, ground-truth-backed chain evidence."""

    return (
        case.get("validation_outcome") == "confirmed"
        and case.get("ground_truth_outcome") == "confirmed"
        and all(bool(case.get(field)) for field in _REQUIRED_CHAIN_FIELDS)
    )


def build_chain_inventory(
    recorded_cases: Iterable[Mapping[str, Any]],
) -> tuple[dict[str, Any], ...]:
    """Join ADI chain contracts to actual recorded cases without creating cases."""

    cases = tuple(case for case in recorded_cases if isinstance(case, Mapping))
    inventory: list[dict[str, Any]] = []
    for contract in ADI_CHAIN_CONTRACTS:
        matching = tuple(
            case
            for case in cases
            if str(case.get("adi_scenario_id", "")) == contract.scenario_id
            or (
                contract.scenario_id == "idor_chain"
                and str(case.get("vulnerability_class", "")).strip().lower()
                in {"idor", "broken_access_control"}
            )
        )
        scorable_ids = tuple(
            str(case.get("case_id")) for case in matching if _complete_recorded_chain(case)
        )
        status = "scorable" if scorable_ids else "blocked"
        inventory.append(
            {
                **contract.as_dict(),
                "status": status,
                "recorded_case_ids": tuple(str(case.get("case_id")) for case in matching),
                "scorable_case_ids": scorable_ids,
                "included_in_scoring": status == "scorable",
                "blocked_reason": (
                    None
                    if status == "scorable"
                    else (
                        "complete recorded multi-step chain fields and "
                        "ground-truth-backed proof are unavailable"
                    )
                ),
            }
        )
    return tuple(inventory)


def compute_adi_efficiency_metrics(
    cases: Iterable[Mapping[str, Any]],
    inventory: Iterable[Mapping[str, Any]],
) -> dict[str, Any]:
    """Compute only recorded research-efficiency indicators, never detection rate."""

    items = tuple(case for case in cases if isinstance(case, Mapping))
    chain_scorable = tuple(case for case in items if _complete_recorded_chain(case))
    duplicate_count = len(items) - len({case.get("case_id") for case in items})

    useful_denominators = [
        (case.get("useful_hypotheses"), case.get("hypotheses_considered"))
        for case in items
        if case.get("useful_hypotheses") is not None
        and case.get("hypotheses_considered") is not None
        and int(case.get("hypotheses_considered", 0)) > 0
    ]
    depth_values = [
        float(case["investigation_depth"])
        for case in chain_scorable
        if isinstance(case.get("investigation_depth"), (int, float))
    ]
    completeness_values = [
        sum(bool(case.get(field)) for field in _REQUIRED_CHAIN_FIELDS) / len(_REQUIRED_CHAIN_FIELDS)
        for case in chain_scorable
    ]
    capability_values = [
        bool(case["blocked_capability_detected"]) == bool(case["blocked_capability_expected"])
        for case in items
        if case.get("blocked_capability_detected") is not None
        and case.get("blocked_capability_expected") is not None
    ]
    inventory_items = tuple(inventory)
    return {
        "metric_scope": "recorded_controlled_adi_research_only",
        "average_useful_hypothesis_ratio": (
            sum(float(useful) / float(total) for useful, total in useful_denominators)
            / len(useful_denominators)
            if useful_denominators
            else None
        ),
        "duplicate_hypothesis_reduction": (1 - duplicate_count / len(items)) if items else 1.0,
        "investigation_depth": sum(depth_values) / len(depth_values) if depth_values else None,
        "evidence_completeness": (
            sum(completeness_values) / len(completeness_values) if completeness_values else None
        ),
        "blocked_capability_detection_accuracy": (
            sum(capability_values) / len(capability_values) if capability_values else None
        ),
        "registered_chain_count": len(inventory_items),
        "scorable_chain_count": sum(item.get("status") == "scorable" for item in inventory_items),
        "real_world_detection_rate_measured": False,
        "production_precision": None,
        "production_recall": None,
    }


__all__ = [
    "ADI_CHAIN_CONTRACTS",
    "ADIChainContract",
    "build_chain_inventory",
    "compute_adi_efficiency_metrics",
]


if __name__ == "__main__":
    raise SystemExit("offline_contract_module_only")
