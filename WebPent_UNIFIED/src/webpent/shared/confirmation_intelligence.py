"""Bounded confirmation intelligence for autonomous security research.

The module evaluates already-recorded, redacted observations.  It does not
send requests, create findings, mutate state, approve policy, or grant
qualification.  Its purpose is to make the reasoning boundary explicit:
semantic causal confirmation is stronger than transport observation, and
multi-step chains are valid only when every step has independently replayable
support.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from enum import Enum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from webpent.models.proof_bundle import (
    ProofBundle,
    proof_bundle_promotion_ready,
    validate_proof_bundle,
)
from webpent.shared.proof_oracles import (
    CausalDecision,
    CausalOracleContract,
    CausalOracleResult,
    OracleEngine,
)
from webpent.validators.replay_validator import validate_replay


class ConfirmationPosture(str, Enum):
    """Closed set of non-authoritative confirmation states."""

    BLOCKED = "blocked"
    INCONCLUSIVE = "inconclusive"
    CLEAN = "clean"
    NEEDS_PROOF = "needs_proof"
    ENGINEERING_CONFIRMED = "engineering_confirmed"


class ConfirmationAssessment(BaseModel):
    """Auditable result for one recorded candidate/control experiment."""

    model_config = ConfigDict(extra="forbid", frozen=True, use_enum_values=True)

    posture: ConfirmationPosture
    oracle_decision: CausalDecision
    score: float = Field(default=0.0, ge=0.0, le=1.0)
    causal_signal: bool = False
    negative_control_observed: bool = False
    semantic_delta_verified: bool = False
    proof_bundle_valid: bool = False
    replay_verified: bool = False
    target_runtime_consistent: bool = False
    scoring_eligible: bool = False
    official_qualification_granted: bool = False
    missing: tuple[str, ...] = Field(default_factory=tuple, max_length=24)
    reasons: tuple[str, ...] = Field(default_factory=tuple, max_length=24)
    oracle_analysis: dict[str, Any] = Field(default_factory=dict, max_length=32)


class ChainStep(BaseModel):
    """One already-evaluated step in a bounded vulnerability chain."""

    model_config = ConfigDict(extra="forbid", frozen=True, use_enum_values=True)

    step_id: str = Field(min_length=1, max_length=160)
    hypothesis_id: str = Field(min_length=1, max_length=160)
    prerequisite_step_ids: tuple[str, ...] = Field(default_factory=tuple, max_length=8)
    assessment: ConfirmationAssessment
    evidence_refs: tuple[str, ...] = Field(default_factory=tuple, max_length=32)


class ChainAssessment(BaseModel):
    """Non-authoritative posture for a bounded, dependency-aware chain."""

    model_config = ConfigDict(extra="forbid", frozen=True, use_enum_values=True)

    chain_id: str = Field(min_length=1, max_length=160)
    complete: bool = False
    score: float = Field(default=0.0, ge=0.0, le=1.0)
    confirmed_step_ids: tuple[str, ...] = Field(default_factory=tuple, max_length=12)
    blocked_step_ids: tuple[str, ...] = Field(default_factory=tuple, max_length=12)
    missing_dependencies: tuple[str, ...] = Field(default_factory=tuple, max_length=24)
    reasons: tuple[str, ...] = Field(default_factory=tuple, max_length=24)
    official_qualification_granted: bool = False


def _as_mapping(value: Any) -> Mapping[str, Any]:
    if isinstance(value, Mapping):
        return value
    dumper = getattr(value, "model_dump", None)
    if callable(dumper):
        try:
            dumped = dumper(mode="json")
        except TypeError:
            dumped = dumper()
        return dumped if isinstance(dumped, Mapping) else {}
    return {}


def _observation_roles_valid(contract: CausalOracleContract) -> bool:
    observations = (contract.baseline, contract.candidate, contract.negative_control)
    return tuple(item.role for item in observations) == (
        "baseline",
        "candidate",
        "negative_control",
    )


def _runtime_consistent(contract: CausalOracleContract) -> bool:
    observations = (contract.baseline, contract.candidate, contract.negative_control)
    origins = {item.evidence_origin for item in observations}
    backed = {item.target_backed for item in observations}
    return (
        len(origins) == 1
        and len(backed) == 1
        and next(iter(origins)) == ("target_runtime" if next(iter(backed)) else "offline_fixture")
    )


def _semantic_contract_complete(contract: CausalOracleContract) -> tuple[str, ...]:
    missing: list[str] = []
    required = (
        (contract.baseline, "baseline", ("invariant_holds",)),
        (contract.candidate, "candidate", ("invariant_violated", "invariant_holds")),
        (contract.negative_control, "negative_control", ("invariant_holds",)),
    )
    for observation, role, keys in required:
        if not any(
            key in observation.signals and isinstance(observation.signals[key], bool)
            for key in keys
        ):
            missing.append(f"{role}_invariant_boolean")
    for observation in (
        contract.baseline,
        contract.candidate,
        contract.negative_control,
    ):
        if not observation.has_meaningful_signal:
            missing.append(f"{observation.role}_meaningful_signal")
    return tuple(dict.fromkeys(missing))


def _replay_verified(
    proof_bundle: Any,
    evidence_payloads: Sequence[Any],
    negative_control: Any,
    replay_context: Mapping[str, Any] | None,
) -> bool:
    if not evidence_payloads or negative_control is None:
        return False
    return bool(
        validate_replay(
            proof_bundle,
            list(evidence_payloads),
            negative_control,
            replay_context=replay_context,
        )
    )


def evaluate_confirmation(
    contract: CausalOracleContract | Mapping[str, Any],
    *,
    proof_bundle: ProofBundle | Mapping[str, Any] | None = None,
    evidence_payloads: Sequence[Any] = (),
    negative_control_payload: Any = None,
    replay_context: Mapping[str, Any] | None = None,
) -> ConfirmationAssessment:
    """Evaluate a recorded experiment with strict proof and replay gates.

    The result may be ``engineering_confirmed`` for a fully replayable
    offline experiment, but ``scoring_eligible`` remains false for offline
    evidence.  No result from this function authorizes execution or changes
    any finding/qualification state.
    """
    try:
        parsed = (
            contract
            if isinstance(contract, CausalOracleContract)
            else CausalOracleContract.model_validate(contract)
        )
    except Exception:
        return ConfirmationAssessment(
            posture=ConfirmationPosture.BLOCKED,
            oracle_decision=CausalDecision.BLOCKED,
            missing=("causal_contract_invalid",),
            reasons=("contract_validation_failed",),
        )

    structural_missing = list(_semantic_contract_complete(parsed))
    if not _observation_roles_valid(parsed):
        structural_missing.append("observation_roles_invalid")
    observation_refs = {
        item.observation_ref
        for item in (parsed.baseline, parsed.candidate, parsed.negative_control)
    }
    if len(observation_refs) != 3:
        structural_missing.append("observation_refs_not_independent")
    if parsed.candidate.request_digest == parsed.negative_control.request_digest:
        structural_missing.append("negative_control_request_not_independent")
    if not _runtime_consistent(parsed):
        structural_missing.append("observation_runtime_origin_inconsistent")

    oracle: CausalOracleResult = OracleEngine.evaluate_experiment(parsed)
    structural_missing.extend(oracle.missing)
    structural_missing = list(dict.fromkeys(structural_missing))
    if structural_missing:
        return ConfirmationAssessment(
            posture=ConfirmationPosture.BLOCKED,
            oracle_decision=CausalDecision.BLOCKED,
            missing=tuple(structural_missing),
            reasons=("confirmation_contract_structurally_blocked",),
            oracle_analysis=oracle.invariant_analysis,
        )

    if oracle.decision == CausalDecision.CLEAN:
        return ConfirmationAssessment(
            posture=ConfirmationPosture.CLEAN,
            oracle_decision=oracle.decision,
            score=1.0,
            negative_control_observed=oracle.negative_control_observed,
            semantic_delta_verified=False,
            target_runtime_consistent=_runtime_consistent(parsed),
            reasons=("candidate_preserves_invariant",),
            oracle_analysis=oracle.invariant_analysis,
        )
    if oracle.decision != CausalDecision.CONFIRMED:
        return ConfirmationAssessment(
            posture=ConfirmationPosture.INCONCLUSIVE,
            oracle_decision=oracle.decision,
            score=0.25 if oracle.negative_control_observed else 0.0,
            negative_control_observed=oracle.negative_control_observed,
            target_runtime_consistent=_runtime_consistent(parsed),
            missing=("causal_predicate_not_satisfied",),
            reasons=("oracle_not_confirmed",),
            oracle_analysis=oracle.invariant_analysis,
        )

    valid_bundle = validate_proof_bundle(proof_bundle, require_negative_control=True)
    promotion_ready = proof_bundle_promotion_ready(proof_bundle)
    replay_ok = _replay_verified(
        proof_bundle,
        evidence_payloads,
        negative_control_payload,
        replay_context,
    )
    target_runtime = _runtime_consistent(parsed) and parsed.candidate.is_target_runtime
    missing: list[str] = []
    if not valid_bundle:
        missing.append("sealed_proof_bundle")
    if not promotion_ready:
        missing.append("promotion_ready_proof_bundle")
    if not replay_ok:
        missing.append("verified_replay")
    if not oracle.negative_control_observed:
        missing.append("negative_control_observed")

    if not valid_bundle or not replay_ok:
        return ConfirmationAssessment(
            posture=ConfirmationPosture.NEEDS_PROOF,
            oracle_decision=oracle.decision,
            score=0.55,
            causal_signal=True,
            negative_control_observed=oracle.negative_control_observed,
            semantic_delta_verified=True,
            proof_bundle_valid=valid_bundle,
            replay_verified=replay_ok,
            target_runtime_consistent=target_runtime,
            missing=tuple(dict.fromkeys(missing)),
            reasons=("oracle_confirmed_but_proof_or_replay_incomplete",),
            oracle_analysis=oracle.invariant_analysis,
        )

    # A complete offline bundle is engineering evidence only.  Even a
    # promotion-ready target-runtime bundle does not grant official
    # qualification; that remains owned by the external governance process.
    scoring_eligible = bool(promotion_ready and target_runtime)
    return ConfirmationAssessment(
        posture=ConfirmationPosture.ENGINEERING_CONFIRMED,
        oracle_decision=oracle.decision,
        score=1.0,
        causal_signal=True,
        negative_control_observed=oracle.negative_control_observed,
        semantic_delta_verified=True,
        proof_bundle_valid=valid_bundle,
        replay_verified=True,
        target_runtime_consistent=target_runtime,
        scoring_eligible=scoring_eligible,
        official_qualification_granted=False,
        reasons=(
            "replayable_causal_confirmation_complete",
            (
                "offline_evidence_not_scoring_eligible"
                if not target_runtime
                else "qualification_decision_remains_external"
            ),
        ),
        oracle_analysis=oracle.invariant_analysis,
    )


def evaluate_bounded_chain(
    chain_id: str,
    steps: Sequence[ChainStep],
    *,
    max_depth: int = 6,
) -> ChainAssessment:
    """Evaluate explicit dependencies between already-assessed chain steps."""
    if not chain_id.strip() or not steps or len(steps) > max_depth:
        return ChainAssessment(
            chain_id=chain_id or "chain:invalid",
            reasons=("chain_empty_or_exceeds_bounded_depth",),
        )

    by_id = {step.step_id: step for step in steps}
    missing_dependencies: list[str] = []
    confirmed: list[str] = []
    blocked: list[str] = []
    for step in steps:
        for dependency in step.prerequisite_step_ids:
            if dependency not in by_id:
                missing_dependencies.append(f"{step.step_id}->{dependency}")
        if step.assessment.posture == ConfirmationPosture.ENGINEERING_CONFIRMED:
            confirmed.append(step.step_id)
        else:
            blocked.append(step.step_id)

    ordered_ids = [step.step_id for step in steps]
    order_index = {step_id: index for index, step_id in enumerate(ordered_ids)}
    for step in steps:
        for dependency in step.prerequisite_step_ids:
            if dependency in order_index and order_index[dependency] >= order_index[step.step_id]:
                missing_dependencies.append(f"{step.step_id}->ordering:{dependency}")
            if (
                dependency in by_id
                and by_id[dependency].assessment.posture
                != ConfirmationPosture.ENGINEERING_CONFIRMED
            ):
                missing_dependencies.append(f"{step.step_id}->unconfirmed:{dependency}")

    missing_dependencies = list(dict.fromkeys(missing_dependencies))
    complete = bool(
        len(confirmed) == len(steps)
        and not missing_dependencies
        and all(step.evidence_refs for step in steps)
    )
    score = round(len(confirmed) / len(steps), 4)
    reasons = (
        ("all_bounded_chain_steps_replayable", "chain_dependencies_satisfied")
        if complete
        else ("chain_requires_independent_step_confirmation",)
    )
    return ChainAssessment(
        chain_id=chain_id,
        complete=complete,
        score=score,
        confirmed_step_ids=tuple(confirmed),
        blocked_step_ids=tuple(blocked),
        missing_dependencies=tuple(missing_dependencies),
        reasons=reasons,
        official_qualification_granted=False,
    )


__all__ = [
    "ChainAssessment",
    "ChainStep",
    "ConfirmationAssessment",
    "ConfirmationPosture",
    "evaluate_bounded_chain",
    "evaluate_confirmation",
]
