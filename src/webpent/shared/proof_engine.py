"""Evidence-driven proof planning with external scope and approval gates."""

from __future__ import annotations

import hashlib
import logging
from collections import Counter
from collections.abc import Iterable, Mapping
from typing import Any

from webpent.models.evidence import redact_sensitive, sha256_text
from webpent.models.evidence_ledger import EvidenceLedgerEntry
from webpent.models.proof_bundle import proof_bundle_promotion_ready
from webpent.models.proof_engine import (
    ProofActionProposal,
    ProofActionStatus,
    ProofGapAssessment,
    ProofGapType,
    ProofObservabilitySnapshot,
    ProofPlan,
)
from webpent.shared.coverage_ledger import project_coverage_ledger
from webpent.shared.evidence_ledger import merge_evidence_ledger

_GAP_FROM_LABEL = {
    "missing-surface": ProofGapType.MISSING_SURFACE,
    "missing-identity-context": ProofGapType.MISSING_IDENTITY,
    "missing-body": ProofGapType.MISSING_BODY_CONTENT_TYPE,
    "missing-content-type": ProofGapType.MISSING_BODY_CONTENT_TYPE,
    "missing-precondition": ProofGapType.MISSING_PRECONDITION,
    "missing-negative-control": ProofGapType.MISSING_NEGATIVE_CONTROL,
    "weak-oracle": ProofGapType.WEAK_ORACLE,
    "missing-validator": ProofGapType.MISSING_VALIDATOR,
    "blocked-by-policy": ProofGapType.POLICY_BLOCK,
    "policy-block": ProofGapType.POLICY_BLOCK,
}

_ACTION_SPECS = {
    ProofGapType.MISSING_SURFACE: (
        "collect_targeted_surface",
        ["target remains in scope", "surface family is declared"],
        ["new surface observation", "response fingerprint"],
        "stop after one bounded surface observation or a scope/policy block",
        3,
        60,
    ),
    ProofGapType.MISSING_IDENTITY: (
        "prepare_identity_context",
        ["identity is approved by the engagement", "credential reference is opaque"],
        ["identity-bound observation", "authorization result"],
        "stop when an approved identity context is observed or blocked",
        4,
        90,
    ),
    ProofGapType.MISSING_BODY_CONTENT_TYPE: (
        "collect_body_contract",
        ["request shape is in scope"],
        ["body schema", "content type", "parser outcome"],
        "stop after one bounded body/content-type contract is captured",
        3,
        60,
    ),
    ProofGapType.MISSING_PRECONDITION: (
        "prepare_campaign_precondition",
        ["precondition is explicitly listed in campaign contract"],
        ["precondition state", "transition evidence"],
        "stop when the precondition is met, rejected, or policy-blocked",
        3,
        90,
    ),
    ProofGapType.MISSING_NEGATIVE_CONTROL: (
        "collect_negative_control",
        ["control request remains in scope"],
        ["paired negative-control result"],
        "stop when a paired negative control is recorded",
        2,
        60,
    ),
    ProofGapType.WEAK_ORACLE: (
        "strengthen_oracle",
        ["an observable differential is defined"],
        ["causal oracle signal", "baseline comparison"],
        "stop when the oracle is causal or the candidate is inconclusive",
        3,
        90,
    ),
    ProofGapType.POLICY_BLOCK: (
        "request_policy_review",
        [],
        ["policy disposition"],
        "stop without execution; require an external policy/approval decision",
        1,
        30,
    ),
    ProofGapType.MISSING_VALIDATOR: (
        "register_validator_review",
        [],
        ["validator capability disposition"],
        "stop until a complete validator plugin is available",
        1,
        30,
    ),
}


logger = logging.getLogger(__name__)


def _text(value: Any) -> str:
    return value.strip() if isinstance(value, str) else ""


def _safe_mapping(value: Any) -> dict[str, Any]:
    if isinstance(value, Mapping):
        clean, _ = redact_sensitive(dict(value))
        return clean if isinstance(clean, dict) else {}
    return {}


def _fingerprint(value: Any) -> str:
    return f"sha256:{sha256_text(_safe_mapping(value))}"


def _stable_id(*parts: str) -> str:
    raw = "|".join(part.strip().lower() for part in parts if part.strip())
    return f"proof-{hashlib.sha256(raw.encode('utf-8')).hexdigest()[:24]}"


def _assessment(
    campaign_key: str,
    gap_type: ProofGapType,
    reason: str,
    evidence: Mapping[str, Any],
    source_refs: Iterable[str] = (),
) -> ProofGapAssessment:
    fingerprint = _fingerprint(evidence)
    return ProofGapAssessment(
        gap_id=_stable_id(campaign_key, gap_type.value, fingerprint),
        gap_type=gap_type,
        campaign_key=campaign_key,
        source_refs=list(dict.fromkeys(str(ref) for ref in source_refs if str(ref)))[:20],
        reason=reason,
        evidence_fingerprint=fingerprint,
    )


def classify_probe_gaps(
    *,
    campaign_key: str,
    evidence: Mapping[str, Any] | None = None,
    source_refs: Iterable[str] = (),
    required: Iterable[str] = (),
) -> list[ProofGapAssessment]:
    """Classify missing proof prerequisites without treating them as no finding."""
    data = _safe_mapping(evidence)
    gaps: list[ProofGapAssessment] = []
    checks = {
        "surface": (ProofGapType.MISSING_SURFACE, "surface observation is missing"),
        "identity": (ProofGapType.MISSING_IDENTITY, "approved identity context is missing"),
        "body": (ProofGapType.MISSING_BODY_CONTENT_TYPE, "request body is missing"),
        "content_type": (
            ProofGapType.MISSING_BODY_CONTENT_TYPE,
            "request content type is missing",
        ),
        "precondition": (ProofGapType.MISSING_PRECONDITION, "campaign precondition is missing"),
        "negative_control": (
            ProofGapType.MISSING_NEGATIVE_CONTROL,
            "negative control is missing",
        ),
        "oracle": (ProofGapType.WEAK_ORACLE, "causal oracle is missing or weak"),
        "validator_id": (ProofGapType.MISSING_VALIDATOR, "deterministic validator is missing"),
    }
    for field in required:
        gap = checks.get(str(field))
        if gap and not data.get(str(field)):
            gaps.append(_assessment(campaign_key, gap[0], gap[1], data, source_refs))
    if data.get("policy_block") or data.get("scope_block"):
        gaps.append(
            _assessment(
                campaign_key,
                ProofGapType.POLICY_BLOCK,
                "external policy or scope gate blocked the proof path",
                data,
                source_refs,
            )
        )
    if data.get("oracle") and isinstance(data["oracle"], Mapping):
        oracle = _safe_mapping(data["oracle"])
        if not oracle.get("differential") and not oracle.get("causal_signal"):
            gaps.append(
                _assessment(
                    campaign_key,
                    ProofGapType.WEAK_ORACLE,
                    "oracle has no causal differential signal",
                    data,
                    source_refs,
                )
            )
    return list({assessment.gap_id: assessment for assessment in gaps}.values())


def _normalise_assessment(value: Any) -> ProofGapAssessment | None:
    if isinstance(value, ProofGapAssessment):
        return value
    try:
        return ProofGapAssessment.model_validate(value)
    except Exception:
        logger.warning("_normalise_assessment: malformed ProofGapAssessment", exc_info=True)
        return None


def plan_next_proof_actions(
    assessments: Iterable[ProofGapAssessment | Mapping[str, Any]],
    *,
    existing_actions: Iterable[Mapping[str, Any]] = (),
    max_actions: int = 10,
) -> tuple[list[ProofActionProposal], int]:
    """Create bounded proposals and suppress repeats without new evidence."""
    existing_keys = {
        (
            _text(action.get("campaign_key")),
            _text(action.get("gap_id")),
            _text(action.get("evidence_fingerprint")),
        )
        for action in existing_actions
        if isinstance(action, Mapping)
    }
    proposals: list[ProofActionProposal] = []
    dropped = 0
    seen: set[tuple[str, str, str]] = set()
    for raw in assessments:
        assessment = _normalise_assessment(raw)
        if assessment is None or assessment.resolved:
            continue
        key = (assessment.campaign_key, assessment.gap_id, assessment.evidence_fingerprint)
        if key in existing_keys or key in seen:
            dropped += 1
            continue
        seen.add(key)
        gap_type = ProofGapType(assessment.gap_type)
        action_type, preconditions, expected, exit_condition, requests, seconds = _ACTION_SPECS[
            gap_type
        ]
        status = (
            ProofActionStatus.TERMINAL
            if gap_type in {ProofGapType.POLICY_BLOCK, ProofGapType.MISSING_VALIDATOR}
            else ProofActionStatus.APPROVAL_REQUIRED
        )
        proposals.append(
            ProofActionProposal(
                action_id=_stable_id(assessment.campaign_key, assessment.gap_id),
                campaign_key=assessment.campaign_key,
                gap_id=assessment.gap_id,
                action_type=action_type,
                preconditions=preconditions,
                expected_evidence=expected,
                identity_refs=[ref for ref in assessment.source_refs if "identity" in ref.lower()],
                payload_strategy=(
                    "no-payload-policy-review"
                    if gap_type in {ProofGapType.POLICY_BLOCK, ProofGapType.MISSING_VALIDATOR}
                    else "evidence-minimal"
                ),
                exit_condition=exit_condition,
                chain_state={"gap_id": assessment.gap_id, "state": "awaiting_external_gate"},
                cleanup_steps=["record cleanup outcome", "release temporary proof state"],
                budget_requests=requests,
                budget_seconds=seconds,
                status=status,
                approval_required=True,
                evidence_fingerprint=assessment.evidence_fingerprint,
            )
        )
        if len(proposals) >= max(0, int(max_actions)):
            break
    return proposals, dropped


def _proof_outcome_promotion_ready(outcome: Mapping[str, Any]) -> bool:
    """Require all causal flags and a sealed, replayable bundle for promotion."""
    return bool(
        _text(outcome.get("status")).lower() == "confirmed"
        and bool(outcome.get("evidence_complete"))
        and bool(outcome.get("causal_signal"))
        and bool(outcome.get("negative_control_observed"))
        and proof_bundle_promotion_ready(outcome.get("proof_bundle"))
    )


def apply_proof_outcome(
    action: ProofActionProposal,
    outcome: Mapping[str, Any],
) -> ProofActionProposal:
    """Apply a normalized outcome without promoting a finding automatically."""
    action_id = _text(outcome.get("action_id"))
    if action_id != action.action_id:
        raise ValueError("outcome.action_id does not match action.action_id")
    status = _text(outcome.get("status")).lower()
    evidence_complete = bool(outcome.get("evidence_complete"))
    causal_signal = bool(outcome.get("causal_signal"))
    negative_control = bool(outcome.get("negative_control_observed"))
    promotion_ready = _proof_outcome_promotion_ready(outcome)
    ready_for_review = evidence_complete and causal_signal and negative_control and promotion_ready
    confidence_after = "evidence_ready_for_review" if ready_for_review else "needs_human_review"
    if status in {"blocked_by_scope", "policy_block"}:
        action_status = ProofActionStatus.TERMINAL
    elif status in {"inconclusive", "budget_exhausted"}:
        action_status = ProofActionStatus.INCONCLUSIVE
    else:
        action_status = ProofActionStatus.EXECUTED
    clean_refs, _ = redact_sensitive(outcome.get("evidence_refs") or [])
    return action.model_copy(
        update={
            "status": action_status,
            "evidence_refs": list(dict.fromkeys([*action.evidence_refs, *clean_refs]))[:20],
            "cleanup_status": _text(outcome.get("cleanup_status")) or "pending",
            "confidence_after": confidence_after,
            "chain_state": {
                **action.chain_state,
                "state": (
                    status
                    if not (status == "confirmed" and not promotion_ready)
                    else "needs_human_review"
                )
                or "inconclusive",
                "promotion_ready": promotion_ready,
            },
        }
    )


def build_proof_observability(
    *,
    assessments: Iterable[ProofGapAssessment],
    actions: Iterable[ProofActionProposal],
    existing_actions: Iterable[Mapping[str, Any]] = (),
    outcomes: Iterable[Mapping[str, Any]] = (),
) -> ProofObservabilitySnapshot:
    assessments_list = list(assessments)
    actions_list = list(actions)
    outcomes_list = [item for item in outcomes if isinstance(item, Mapping)]
    gap_counts = Counter(ProofGapType(item.gap_type).value for item in assessments_list)
    return ProofObservabilitySnapshot(
        probes_considered=len(assessments_list),
        actions_proposed=len(actions_list),
        actions_dropped_duplicate=max(0, len(list(existing_actions)) - len(actions_list)),
        confirmations=sum(1 for item in outcomes_list if item.get("status") == "confirmed"),
        inconclusive=sum(1 for item in outcomes_list if item.get("status") == "inconclusive"),
        scope_blocks=sum(1 for item in outcomes_list if item.get("status") == "blocked_by_scope"),
        policy_blocks=sum(
            1
            for item in assessments_list
            if ProofGapType(item.gap_type) == ProofGapType.POLICY_BLOCK
        ),
        retries=sum(1 for item in outcomes_list if int(item.get("attempts", 0) or 0) > 1),
        budget_exhaustions=sum(
            1 for item in outcomes_list if item.get("status") == "budget_exhausted"
        ),
        guard_failures=sum(1 for item in outcomes_list if item.get("guard_failure")),
        evidence_complete=sum(1 for item in outcomes_list if item.get("evidence_complete")),
        evidence_incomplete=sum(
            1 for item in outcomes_list if item.get("evidence_complete") is False
        ),
        total_latency_ms=sum(int(item.get("latency_ms", 0) or 0) for item in outcomes_list),
        gap_counts=dict(gap_counts),
    )


def build_proof_plan(
    assessments: Iterable[ProofGapAssessment | Mapping[str, Any]],
    *,
    existing_actions: Iterable[Mapping[str, Any]] = (),
    outcomes: Iterable[Mapping[str, Any]] = (),
    max_actions: int = 10,
) -> ProofPlan:
    normalised = [item for raw in assessments if (item := _normalise_assessment(raw))]
    prior = list(existing_actions)
    actions, dropped = plan_next_proof_actions(
        normalised,
        existing_actions=prior,
        max_actions=max_actions,
    )
    observability = build_proof_observability(
        assessments=normalised,
        actions=actions,
        existing_actions=[*prior, *({"action_id": action.action_id} for action in actions)],
        outcomes=outcomes,
    ).model_copy(update={"actions_dropped_duplicate": dropped})
    edges = [
        {
            "source": assessment.gap_id,
            "target": action.action_id,
            "relation": "gap_requires_action",
        }
        for assessment in normalised
        for action in actions
        if action.gap_id == assessment.gap_id
    ]
    return ProofPlan(
        assessments=normalised,
        actions=actions,
        causal_edges=edges,
        observability=observability,
    )


def _assessments_from_campaign_plan(state: Mapping[str, Any]) -> list[ProofGapAssessment]:
    plan = state.get("campaign_plan") or {}
    entries = plan.get("entries", []) if isinstance(plan, Mapping) else []
    assessments: list[ProofGapAssessment] = []
    for entry in entries:
        if not isinstance(entry, Mapping):
            continue
        campaign_key = _text(entry.get("key"))
        for raw_gap in entry.get("gaps", []) or []:
            label = _text(raw_gap).split(":", 1)[0]
            gap_type = _GAP_FROM_LABEL.get(label)
            if not campaign_key or gap_type is None:
                continue
            assessments.append(
                _assessment(
                    campaign_key,
                    gap_type,
                    f"planner reported gap: {label}",
                    {"campaign_key": campaign_key, "gap": label},
                    entry.get("matched_observation_refs", []),
                )
            )
    return assessments


def _proof_outcome_ledger_entries(state: Mapping[str, Any]) -> list[dict[str, Any]]:
    """Project executor outcomes into reviewable ledger records, never findings."""
    proof_plan = state.get("proof_plan") or {}
    raw_actions = proof_plan.get("actions", []) if isinstance(proof_plan, Mapping) else []
    actions = {
        _text(item.get("action_id")): item
        for item in raw_actions
        if isinstance(item, Mapping) and _text(item.get("action_id"))
    }
    entries: list[dict[str, Any]] = []
    for raw in state.get("proof_outcomes") or []:
        if not isinstance(raw, Mapping):
            continue
        action_id = _text(raw.get("action_id"))
        action = actions.get(action_id, {})
        campaign_key = _text(raw.get("campaign_key")) or _text(action.get("campaign_key"))
        if not action_id or not campaign_key:
            continue
        status = _text(raw.get("status")).lower()
        evidence_complete = bool(raw.get("evidence_complete"))
        causal_signal = bool(raw.get("causal_signal"))
        negative_control = bool(raw.get("negative_control_observed"))
        if status == "confirmed" and _proof_outcome_promotion_ready(raw):
            ledger_status = "tool_confirmed"
        elif status in {"inconclusive", "budget_exhausted", "blocked_by_scope", "policy_block"}:
            ledger_status = "inconclusive"
        else:
            ledger_status = "needs_human_review"
        cleanup_status = _text(raw.get("cleanup_status"))
        if cleanup_status not in {"pending", "complete", "failed", "not_applicable"}:
            cleanup_status = "pending"
        refs = raw.get("evidence_refs")
        identity_refs = action.get("identity_refs", [])
        identity = _text(raw.get("identity_ref"))
        if not identity and isinstance(identity_refs, list) and identity_refs:
            identity = _text(identity_refs[0])
        entry = EvidenceLedgerEntry(
            entry_id=f"proof:{action_id}",
            campaign_key=campaign_key,
            vuln_class=_text(raw.get("vuln_class")) or "unknown",
            target=_text(raw.get("target")) or f"proof://{campaign_key}",
            identity=identity or None,
            request_metadata=raw.get("request_metadata")
            if isinstance(raw.get("request_metadata"), Mapping)
            else {},
            response_metadata={
                "status": status,
                "evidence_complete": evidence_complete,
                "causal_signal": causal_signal,
                "negative_control_observed": negative_control,
                "latency_ms": int(raw.get("latency_ms", 0) or 0),
                "requests_used": int(raw.get("requests_used", 0) or 0),
            },
            baseline=raw.get("baseline") if isinstance(raw.get("baseline"), Mapping) else {},
            negative_control=(
                raw.get("negative_control")
                if isinstance(raw.get("negative_control"), Mapping)
                else {"observed": negative_control}
            ),
            oracle=raw.get("oracle") if isinstance(raw.get("oracle"), Mapping) else {},
            evidence_hashes=(
                raw.get("evidence_hashes")
                if isinstance(raw.get("evidence_hashes"), Mapping)
                else {}
            ),
            evidence_refs=[str(ref) for ref in refs[:20]] if isinstance(refs, list) else [],
            cleanup_status=cleanup_status,
            status=ledger_status,
            reason=_text(raw.get("note"))[:500] or None,
        )
        entries.append(entry.model_dump(mode="json"))
    return entries


def build_proof_engine_update(state: Mapping[str, Any]) -> dict[str, Any]:
    """Return additive proof state; all execution gates remain outside this module."""
    raw_assessments = state.get("proof_gap_assessments") or _assessments_from_campaign_plan(state)
    existing_plan = state.get("proof_plan") or {}
    existing_actions = (
        existing_plan.get("actions", []) if isinstance(existing_plan, Mapping) else []
    )
    plan = build_proof_plan(
        raw_assessments,
        existing_actions=existing_actions,
        outcomes=state.get("proof_outcomes") or [],
    )
    ledger_entries = _proof_outcome_ledger_entries(state)
    coverage_ledger = project_coverage_ledger({**state, "proof_plan": plan.model_dump(mode="json")})
    return {
        "proof_gap_assessments": [item.model_dump(mode="json") for item in plan.assessments],
        "proof_plan": plan.model_dump(mode="json"),
        "proof_observability": plan.observability.model_dump(mode="json"),
        "coverage_ledger": coverage_ledger,
        "evidence_ledger": merge_evidence_ledger(
            state.get("evidence_ledger") or [],
            ledger_entries,
        ),
    }


def build_causal_engineering_metrics(
    experiments: Iterable[Mapping[str, Any]],
) -> dict[str, Any]:
    """Summarize only operational causal-foundation counters.

    Non-confirmed decisions are retained as decisions, never converted into
    findings or quality labels. The returned schema intentionally contains no
    ground-truth or classifier-quality measurements.
    """
    records = [item for item in experiments if isinstance(item, Mapping)]
    decisions = {"CONFIRMED": 0, "CLEAN": 0, "INCONCLUSIVE": 0, "BLOCKED": 0}
    scoring_bundles = 0
    replay_successes = 0
    for record in records:
        raw_decision = record.get("oracle_decision", record.get("decision", ""))
        decision = getattr(raw_decision, "value", raw_decision)
        decision_key = str(decision).upper()
        if decision_key in decisions:
            decisions[decision_key] += 1
        if decision_key == "CONFIRMED" and bool(record.get("scoring_bundle_created")):
            scoring_bundles += 1
        if bool(record.get("replay_success")):
            replay_successes += 1
    return {
        "experiments_executed": len(records),
        "oracle_decisions": decisions,
        "scoring_proof_bundles_created": scoring_bundles,
        "replay_successes": replay_successes,
    }


__all__ = [
    "apply_proof_outcome",
    "build_causal_engineering_metrics",
    "build_proof_engine_update",
    "build_proof_observability",
    "build_proof_plan",
    "classify_probe_gaps",
    "plan_next_proof_actions",
]
