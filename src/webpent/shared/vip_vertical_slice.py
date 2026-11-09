"""Fail-closed VIP Autonomous Vertical Slice v1.

The slice is transport-agnostic: callers inject a bounded metadata-only handler.
No LLM, planner, adapter, or target intelligence can bypass ActionAuthority.
The core never performs network I/O, credentials, mutation, or qualification.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any
from urllib.parse import urlsplit

from webpent.models.evidence import redact_sensitive, sha256_text
from webpent.models.proof_bundle import (
    ProofBundle,
    build_proof_bundle,
    proof_bundle_promotion_ready,
)
from webpent.shared.action_authority import ActionAuthority, ActionRisk
from webpent.shared.campaign_executor import CampaignExecutor, CampaignTask


class LifecycleStage(StrEnum):
    CREATE_CAMPAIGN = "CREATE_CAMPAIGN"
    VALIDATE_SCOPE = "VALIDATE_SCOPE"
    CHECK_TARGET_READINESS = "CHECK_TARGET_READINESS"
    DISCOVER_CAPABILITIES = "DISCOVER_CAPABILITIES"
    SELECT_SAFE_CASES = "SELECT_SAFE_CASES"
    RUN_BASELINE = "RUN_BASELINE"
    EXECUTE_BOUNDED_ACTIONS = "EXECUTE_BOUNDED_ACTIONS"
    COLLECT_REDACTED_OBSERVATIONS = "COLLECT_REDACTED_OBSERVATIONS"
    RUN_INDEPENDENT_NEGATIVE_CONTROL = "RUN_INDEPENDENT_NEGATIVE_CONTROL"
    EVALUATE_CENTRAL_ORACLE = "EVALUATE_CENTRAL_ORACLE"
    CREATE_PROOFBUNDLE = "CREATE_PROOFBUNDLE"
    VERIFY_SEAL = "VERIFY_SEAL"
    REPLAY = "REPLAY"
    EVALUATE_DETECTION_QUALITY = "EVALUATE_DETECTION_QUALITY"
    DIAGNOSE_FAILURES = "DIAGNOSE_FAILURES"
    CREATE_IMPROVEMENT_PROPOSAL = "CREATE_IMPROVEMENT_PROPOSAL"
    CLASSIFY_CHANGE = "CLASSIFY_CHANGE"
    IMPLEMENT_SAFE_LOCAL_CHANGE = "IMPLEMENT_SAFE_LOCAL_CHANGE"
    RUN_REGRESSION = "RUN_REGRESSION"
    RETEST = "RE-TEST"
    COMPARE_BEFORE_AFTER = "COMPARE_BEFORE_AFTER"
    GENERATE_REPORT = "GENERATE_REPORT"


class OutcomeStatus(StrEnum):
    CONFIRMED = "confirmed"
    PROBABLE = "probable"
    OBSERVATION_ONLY = "observation_only"
    BLOCKED = "blocked"
    UNSUPPORTED = "unsupported"
    INCONCLUSIVE = "inconclusive"


_LOOPBACK_HOSTS = frozenset({"127.0.0.1", "localhost", "::1"})
_READ_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})
_FORBIDDEN_TEXT = frozenset(
    {
        "credential",
        "credentials",
        "password",
        "cookie",
        "token",
        "otp",
        "mfa",
        "captcha",
        "mutation",
        "destructive",
        "external",
        "bug bounty",
    }
)


def _clean(value: Any, limit: int = 800) -> Any:
    cleaned, _ = redact_sensitive(value)
    if isinstance(cleaned, str):
        return cleaned[:limit]
    return cleaned


def _now_utc() -> datetime:
    return datetime.now(UTC)


def _origin(value: str) -> str:
    parsed = urlsplit(str(value or "").strip())
    if parsed.scheme.lower() not in {"http", "https"} or not parsed.hostname:
        return ""
    host = parsed.hostname.lower()
    port = parsed.port
    default = (parsed.scheme.lower() == "http" and port in {None, 80}) or (
        parsed.scheme.lower() == "https" and port in {None, 443}
    )
    return f"{parsed.scheme.lower()}://{host}{'' if default else f':{port}'}"


@dataclass(frozen=True)
class TargetSpec:
    """Explicit authorization object for one bounded local campaign."""

    target_id: str
    canonical_origin: str
    scope: tuple[str, ...] = ("/",)
    method_policy: tuple[str, ...] = ("GET",)
    request_budget: int = 8
    redirect_policy: str = "same_origin_only"
    expires_at: str = ""
    authorization_ref: str = ""

    @property
    def normalized_origin(self) -> str:
        return _origin(self.canonical_origin)

    def validate(self, *, now: datetime | None = None) -> tuple[bool, tuple[str, ...]]:
        reasons: list[str] = []
        parsed = urlsplit(self.canonical_origin)
        host = (parsed.hostname or "").lower()
        if not self.target_id.strip():
            reasons.append("target:target_id_required")
        if not self.normalized_origin:
            reasons.append("scope:canonical_origin_invalid")
        if host not in _LOOPBACK_HOSTS:
            reasons.append("scope:loopback_origin_required")
        if parsed.username or parsed.password:
            reasons.append("scope:embedded_credentials_forbidden")
        if "*" in self.canonical_origin:
            reasons.append("scope:wildcard_origin_forbidden")
        if not self.scope:
            reasons.append("scope:explicit_scope_required")
        methods = {str(item).upper().strip() for item in self.method_policy}
        if not methods or not methods.issubset(_READ_METHODS):
            reasons.append("policy:read_only_methods_required")
        if self.request_budget < 1 or self.request_budget > 64:
            reasons.append("budget:bounded_request_budget_required")
        if self.redirect_policy not in {"same_origin_only", "deny"}:
            reasons.append("policy:redirect_policy_not_fail_closed")
        if not self.authorization_ref.strip():
            reasons.append("authorization:authorization_ref_required")
        try:
            expiry = datetime.fromisoformat(self.expires_at.replace("Z", "+00:00"))
            if expiry.astimezone(UTC) <= (now or _now_utc()):
                reasons.append("authorization:expired")
        except (TypeError, ValueError, AttributeError):
            reasons.append("authorization:valid_expiry_required")
        return not reasons, tuple(reasons)

    def as_dict(self) -> dict[str, Any]:
        return {
            "target_id": self.target_id,
            "canonical_origin": self.normalized_origin,
            "scope": list(self.scope),
            "method_policy": [item.upper() for item in self.method_policy],
            "request_budget": self.request_budget,
            "redirect_policy": self.redirect_policy,
            "expires_at": self.expires_at,
            "authorization_ref": self.authorization_ref,
        }


@dataclass(frozen=True)
class CaseContract:
    """Proof-aware case contract selected from capabilities, never from hostname."""

    case_id: str
    vulnerability_class: str
    capability: str
    path: str
    causal_predicate: str
    safe_preconditions: tuple[str, ...] = ()
    negative_control_contract: str = "independent_control_passed"
    proof_contract: str = "central-causal-negative-sealed-replay-v1"
    method: str = "GET"
    action_family: str = "http_read"
    enabled: bool = True
    target_local: bool = False

    def validate(self) -> tuple[bool, tuple[str, ...]]:
        reasons: list[str] = []
        if not self.case_id.strip() or not self.vulnerability_class.strip():
            reasons.append("case:identity_required")
        if not self.capability.strip():
            reasons.append("case:capability_required")
        if not self.path.startswith("/"):
            reasons.append("case:path_must_be_absolute")
        if not self.causal_predicate.strip():
            reasons.append("oracle:causal_predicate_required")
        if not self.safe_preconditions:
            reasons.append("precondition:safe_precondition_required")
        if not self.negative_control_contract.strip():
            reasons.append("oracle:negative_control_contract_required")
        if self.method.upper() not in _READ_METHODS:
            reasons.append("policy:case_must_be_read_only")
        joined = " ".join(
            str(item).lower()
            for item in (
                self.case_id,
                self.vulnerability_class,
                self.path,
                self.proof_contract,
                self.negative_control_contract,
            )
        )
        for forbidden in _FORBIDDEN_TEXT:
            if forbidden in joined:
                reasons.append(f"policy:forbidden_contract_text:{forbidden}")
        return not reasons, tuple(reasons)

    def as_dict(self) -> dict[str, Any]:
        return {
            "case_id": self.case_id,
            "vulnerability_class": self.vulnerability_class,
            "capability": self.capability,
            "path": self.path,
            "causal_predicate": self.causal_predicate,
            "safe_preconditions": list(self.safe_preconditions),
            "negative_control_contract": self.negative_control_contract,
            "proof_contract": self.proof_contract,
            "method": self.method.upper(),
            "action_family": self.action_family,
            "enabled": self.enabled,
            "target_local": self.target_local,
        }


@dataclass(frozen=True)
class OwnerDecisionPacket:
    """Schema only; creating this packet never grants approval."""

    decision_requested: str
    why_it_is_needed: str
    evidence: tuple[str, ...]
    options: tuple[str, ...]
    risk: tuple[str, ...]
    files_or_commits_affected: tuple[str, ...]
    rollback: tuple[str, ...]
    recommended_decision: str
    status: str = "pending_owner_approval"

    def as_dict(self) -> dict[str, Any]:
        return {
            "decision_requested": _clean(self.decision_requested),
            "why_it_is_needed": _clean(self.why_it_is_needed),
            "evidence": list(map(_clean, self.evidence)),
            "options": list(map(_clean, self.options)),
            "risk": list(map(_clean, self.risk)),
            "files_or_commits_affected": list(map(_clean, self.files_or_commits_affected)),
            "rollback": list(map(_clean, self.rollback)),
            "recommended_decision": _clean(self.recommended_decision),
            "status": self.status,
        }


@dataclass(frozen=True)
class ImprovementProposal:
    """A proposal is not approval and does not authorize implementation by itself."""

    failure_record: Mapping[str, Any]
    root_cause: str
    change_class: str
    safety_scope: str
    proposed_action: str
    status: str = "proposed"

    def as_dict(self) -> dict[str, Any]:
        return _clean(
            {
                "failure_record": dict(self.failure_record),
                "root_cause": self.root_cause,
                "change_class": self.change_class,
                "safety_scope": self.safety_scope,
                "proposed_action": self.proposed_action,
                "status": self.status,
            }
        )


CapabilityProvider = Callable[[TargetSpec], Mapping[str, Any]]
ReadinessProvider = Callable[[TargetSpec], Mapping[str, Any]]
ObservationHandler = Callable[[CampaignTask], Mapping[str, Any]]
SafeChangeHandler = Callable[[Mapping[str, Any]], Mapping[str, Any]]


class VIPAutonomousVerticalSlice:
    """Execute one bounded, explainable campaign without autonomous escalation."""

    lifecycle = tuple(LifecycleStage)

    def __init__(
        self,
        *,
        authority: ActionAuthority,
        executor: CampaignExecutor,
        capability_provider: CapabilityProvider,
        readiness_provider: ReadinessProvider,
        observation_handler: ObservationHandler,
        safe_change_handler: SafeChangeHandler | None = None,
    ) -> None:
        self.authority = authority
        self.executor = executor
        self.capability_provider = capability_provider
        self.readiness_provider = readiness_provider
        self.observation_handler = observation_handler
        self.safe_change_handler = safe_change_handler

    def _event(
        self, stage: LifecycleStage, status: str = "completed", **details: Any
    ) -> dict[str, Any]:
        return {"stage": stage.value, "status": status, **_clean(details)}

    def _task(
        self, target: TargetSpec, engagement_id: str, contract: CaseContract, phase: str
    ) -> CampaignTask:
        return CampaignTask(
            task_id=f"{engagement_id}:{contract.case_id}:{phase}",
            engagement_id=engagement_id,
            asset_id=target.target_id,
            source_evidence_ids=(f"contract:{contract.case_id}",),
            vulnerability_class=contract.vulnerability_class,
            hypothesis_id=f"hypothesis:{contract.case_id}",
            preconditions=contract.safe_preconditions,
            identity_context="anonymous",
            workflow_state=phase,
            probe_family="bounded_read_only_contract",
            negative_control="required",
            oracle=contract.causal_predicate,
            risk_tier=ActionRisk.READ_ONLY,
            budget=1.0,
            expected_information_gain=0.5,
            idempotency_key=f"{engagement_id}:{contract.case_id}:{phase}",
            cleanup_plan=("no_mutation",),
            rollback_plan=("discard_metadata_only_artifact",),
            method=contract.method.upper(),
            capability=contract.capability,
            action_family=contract.action_family,
            target_url=target.normalized_origin + contract.path,
            metadata={
                "phase": phase,
                "case_id": contract.case_id,
                "causal_predicate": contract.causal_predicate,
                "adapter_name": "vip_vertical_slice_contract_adapter",
            },
            validator_id="vip_vertical_slice_central_verifier",
        )

    def _execute(self, task: CampaignTask, *, preconditions_met: bool = True) -> dict[str, Any]:
        """Use CampaignExecutor; its authority and metadata redaction remain central."""
        record = self.executor.execute(
            task,
            lambda _task: dict(_clean(self.observation_handler(_task))),
            preconditions_met=preconditions_met,
        )
        return _clean(record)

    @staticmethod
    def _payload(record: Mapping[str, Any]) -> Mapping[str, Any]:
        observation = record.get("observation")
        if isinstance(observation, Mapping):
            return observation
        return {}

    def _central_verify(
        self,
        contract: CaseContract,
        baseline: Mapping[str, Any],
        candidate: Mapping[str, Any],
        negative: Mapping[str, Any],
    ) -> dict[str, Any]:
        predicate_match = candidate.get(
            "semantic_reason"
        ) == contract.causal_predicate and candidate.get("observation_role") in {
            "candidate",
            "retest",
        }
        causal_signal = (
            candidate.get("semantic_oracle_ready") is True
            and candidate.get("semantic_match") is True
            and predicate_match
        )
        negative_passed = (
            negative.get("observation_role") == "negative_control"
            and negative.get("semantic_oracle_ready") is True
            and negative.get("semantic_match") is False
            and negative.get("semantic_reason") == contract.negative_control_contract
        )
        baseline_present = baseline.get("observation_role") == "baseline"
        return {
            "verifier_id": "vip_vertical_slice_central_verifier",
            "verifier_version": "1",
            "causal_signal": causal_signal,
            "predicate_match": predicate_match,
            "baseline_present": baseline_present,
            "negative_control_complete": negative_passed,
            "requires_target_backed": True,
            "decision": "confirmed"
            if causal_signal and negative_passed and baseline_present
            else "inconclusive",
        }

    def _proof(
        self,
        *,
        engagement_id: str,
        target: TargetSpec,
        contract: CaseContract,
        baseline: Mapping[str, Any],
        candidate: Mapping[str, Any],
        negative: Mapping[str, Any],
        oracle: Mapping[str, Any],
    ) -> tuple[ProofBundle | None, dict[str, Any]]:
        finding_id = f"finding:{contract.case_id}"
        evidence = (baseline, candidate, oracle)
        replay_context = {
            "engagement_id": engagement_id,
            "finding_id": finding_id,
            "hypothesis_id": f"hypothesis:{contract.case_id}",
            "target_fingerprint": f"loopback:{target.target_id}",
            "scope_context": {"origin": target.normalized_origin, "scope": list(target.scope)},
            "identity_context": {"mode": "anonymous", "credentials": False},
        }
        bundle = build_proof_bundle(
            engagement_id=engagement_id,
            finding_id=finding_id,
            evidence=evidence,
            evidence_refs=(
                f"baseline:{contract.case_id}",
                f"candidate:{contract.case_id}",
                f"oracle:{contract.case_id}",
            ),
            negative_control=negative,
            hypothesis_id=f"hypothesis:{contract.case_id}",
            target_fingerprint=f"loopback:{target.target_id}",
            scope_context=replay_context["scope_context"],
            identity_context=replay_context["identity_context"],
            baseline=baseline,
            request_evidence=(
                {"method": contract.method.upper(), "path": contract.path, "phase": "candidate"},
            ),
            response_evidence=(candidate,),
            causal_oracle=dict(oracle),
            target_backed=True,
            negative_control_independent=True,
            validator_id="vip_vertical_slice_central_verifier",
            validator_version="1",
            validator_config={
                "contract_id": contract.case_id,
                "proof_contract": contract.proof_contract,
            },
            replay_metadata={"replayable": True, "replay_context_ref": f"campaign:{engagement_id}"},
            cleanup_status="not_applicable",
            redaction_manifest=("raw_body", "raw_headers", "cookies", "credentials", "payloads"),
        ).seal(actor="vip_vertical_slice")
        verified = bundle.verify_seal()
        replayed = bundle.replay(list(evidence), negative, replay_context=replay_context)
        promotion_ready = proof_bundle_promotion_ready(bundle)
        return (
            bundle if verified and replayed and promotion_ready else None,
            {
                "bundle_id": bundle.bundle_id,
                "sealed": verified,
                "verify_seal": verified,
                "replay_status": "passed" if replayed else "failed",
                "promotion_ready": promotion_ready,
            },
        )

    def _improvement_plan(
        self,
        *,
        target: TargetSpec,
        contract: CaseContract,
        status: OutcomeStatus,
        oracle: Mapping[str, Any],
    ) -> tuple[ImprovementProposal | None, OwnerDecisionPacket | None]:
        if status is OutcomeStatus.CONFIRMED:
            return None, None
        gated = contract.method.upper() not in _READ_METHODS or not contract.target_local
        failure_record = {
            "failure_id": f"failure:{contract.case_id}",
            "case_id": contract.case_id,
            "observed_status": status.value,
            "oracle_decision": oracle.get("decision", "unknown"),
            "causal_signal": oracle.get("causal_signal") is True,
            "negative_control_complete": oracle.get("negative_control_complete") is True,
            "target": target.normalized_origin,
            "recorded_as": "failure_or_inconclusive_evidence",
        }
        change_class = "target_local" if not gated else "generic_candidate_requires_owner_review"
        proposal = ImprovementProposal(
            failure_record=failure_record,
            root_cause="missing_or_insufficient_causal_contract_evidence",
            change_class=change_class,
            safety_scope=(
                "bounded local read-only fixture change"
                if not gated
                else "gated change; no implementation without explicit owner approval"
            ),
            proposed_action=(
                "implement bounded local improvement and repeat regression/retest"
                if not gated
                else "prepare owner decision packet; do not implement"
            ),
            status="proposed",
        )
        if not gated:
            return proposal, None
        packet = OwnerDecisionPacket(
            decision_requested="owner approval required for any gated improvement",
            why_it_is_needed=(
                f"{contract.case_id} ended as {status.value}; causal evidence was insufficient"
            ),
            evidence=(
                f"decision:{oracle.get('decision', 'unknown')}",
                f"target:{target.normalized_origin}",
                f"case:{contract.case_id}",
            ),
            options=("leave blocked/inconclusive", "implement bounded local improvement"),
            risk=(
                "no network escalation",
                "no credentials",
                "no mutation",
                "no frozen artifact changes",
            ),
            files_or_commits_affected=("target-local adapter/profile only",),
            rollback=("revert isolated commit", "discard metadata-only campaign artifact"),
            recommended_decision="keep gate closed until explicit owner approval",
        )
        return proposal, packet

    def run(
        self,
        *,
        target: TargetSpec,
        engagement_id: str,
        contracts: Sequence[CaseContract],
    ) -> dict[str, Any]:
        events: list[dict[str, Any]] = [
            self._event(LifecycleStage.CREATE_CAMPAIGN, engagement_id=engagement_id)
        ]
        valid_target, target_reasons = target.validate()
        if self.authority.allowed_origin != target.normalized_origin:
            target_reasons = (*target_reasons, "authority:origin_mismatch")
            valid_target = False
        if not valid_target:
            events.append(
                self._event(LifecycleStage.VALIDATE_SCOPE, "blocked", reasons=target_reasons)
            )
            return self._report(target, engagement_id, events, [], "blocked")
        events.append(
            self._event(LifecycleStage.VALIDATE_SCOPE, authorization_ref=target.authorization_ref)
        )

        readiness = _clean(self.readiness_provider(target))
        if (
            readiness.get("ready") is not True
            or readiness.get("external_contact") is True
            or readiness.get("mutation") is True
        ):
            events.append(
                self._event(LifecycleStage.CHECK_TARGET_READINESS, "blocked", readiness=readiness)
            )
            return self._report(target, engagement_id, events, [], "blocked")
        events.append(self._event(LifecycleStage.CHECK_TARGET_READINESS, readiness=readiness))

        capabilities = _clean(self.capability_provider(target))
        available = {
            str(key)
            for key, value in capabilities.items()
            if isinstance(value, Mapping) and value.get("available") is True
        }
        events.append(self._event(LifecycleStage.DISCOVER_CAPABILITIES, capabilities=capabilities))
        selected: list[CaseContract] = []
        rejected: list[dict[str, Any]] = []
        for contract in contracts:
            valid, reasons = contract.validate()
            if not contract.enabled:
                valid = False
                reasons = (*reasons, "case:disabled")
            if contract.capability not in available:
                valid = False
                reasons = (*reasons, "capability:unavailable")
            if valid and len(selected) < target.request_budget:
                selected.append(contract)
            else:
                rejected.append(
                    {
                        "case_id": contract.case_id,
                        "reasons": list(reasons) or ["budget:selection_limit"],
                    }
                )
        events.append(
            self._event(
                LifecycleStage.SELECT_SAFE_CASES,
                selected=[item.case_id for item in selected],
                rejected=rejected,
            )
        )

        case_results: list[dict[str, Any]] = []
        for contract in selected:
            base_task = self._task(target, engagement_id, contract, "baseline")
            events.append(self._event(LifecycleStage.RUN_BASELINE, case_id=contract.case_id))
            baseline_record = self._execute(base_task, preconditions_met=True)
            baseline = self._payload(baseline_record)
            candidate_task = self._task(target, engagement_id, contract, "candidate")
            events.append(
                self._event(LifecycleStage.EXECUTE_BOUNDED_ACTIONS, case_id=contract.case_id)
            )
            candidate_record = self._execute(candidate_task, preconditions_met=True)
            candidate = self._payload(candidate_record)
            events.append(
                self._event(LifecycleStage.COLLECT_REDACTED_OBSERVATIONS, case_id=contract.case_id)
            )
            control_task = self._task(target, engagement_id, contract, "negative_control")
            events.append(
                self._event(
                    LifecycleStage.RUN_INDEPENDENT_NEGATIVE_CONTROL, case_id=contract.case_id
                )
            )
            negative_record = self._execute(control_task, preconditions_met=True)
            negative = self._payload(negative_record)
            oracle = self._central_verify(contract, baseline, candidate, negative)
            events.append(
                self._event(
                    LifecycleStage.EVALUATE_CENTRAL_ORACLE, case_id=contract.case_id, oracle=oracle
                )
            )
            bundle, proof = (
                self._proof(
                    engagement_id=engagement_id,
                    target=target,
                    contract=contract,
                    baseline=baseline,
                    candidate=candidate,
                    negative=negative,
                    oracle=oracle,
                )
                if oracle["causal_signal"]
                and oracle["negative_control_complete"]
                and oracle["baseline_present"]
                else (
                    None,
                    {
                        "sealed": False,
                        "verify_seal": False,
                        "replay_status": "not_run",
                        "promotion_ready": False,
                    },
                )
            )
            events.extend(
                [
                    self._event(
                        LifecycleStage.CREATE_PROOFBUNDLE,
                        case_id=contract.case_id,
                        bundle_id=proof.get("bundle_id"),
                    ),
                    self._event(
                        LifecycleStage.VERIFY_SEAL,
                        case_id=contract.case_id,
                        verify_seal=proof.get("verify_seal"),
                    ),
                    self._event(
                        LifecycleStage.REPLAY,
                        case_id=contract.case_id,
                        replay_status=proof.get("replay_status"),
                    ),
                ]
            )
            status = (
                OutcomeStatus.CONFIRMED
                if bundle is not None
                else (
                    OutcomeStatus.OBSERVATION_ONLY
                    if oracle["baseline_present"] and oracle["negative_control_complete"]
                    else OutcomeStatus.INCONCLUSIVE
                )
            )
            quality = {
                "status": status.value,
                "causal_signal": oracle["causal_signal"],
                "proof": proof,
            }
            events.append(
                self._event(
                    LifecycleStage.EVALUATE_DETECTION_QUALITY,
                    case_id=contract.case_id,
                    quality=quality,
                )
            )
            before_status = status
            before_oracle = oracle
            before_proof = proof
            proposal, packet = self._improvement_plan(
                target=target, contract=contract, status=status, oracle=oracle
            )
            improvement = None
            if proposal is not None:
                events.append(
                    self._event(
                        LifecycleStage.DIAGNOSE_FAILURES,
                        case_id=contract.case_id,
                        failure_record=proposal.failure_record,
                        root_cause=proposal.root_cause,
                    )
                )
                events.append(
                    self._event(
                        LifecycleStage.CREATE_IMPROVEMENT_PROPOSAL,
                        case_id=contract.case_id,
                        proposal=proposal.as_dict(),
                        owner_decision_packet=packet.as_dict() if packet else None,
                    )
                )
                change_class = (
                    "target_local" if contract.target_local else "generic_candidate_requires_review"
                )
                events.append(
                    self._event(
                        LifecycleStage.CLASSIFY_CHANGE,
                        case_id=contract.case_id,
                        change_class=change_class,
                    )
                )
                if contract.target_local and self.safe_change_handler is not None:
                    try:
                        improvement = _clean(
                            self.safe_change_handler(
                                {
                                    "case_id": contract.case_id,
                                    "change_class": change_class,
                                    "proposal": proposal.as_dict(),
                                }
                            )
                        )
                    except Exception as exc:  # pragma: no cover - defensive boundary
                        improvement = {
                            "status": "implementation_failed",
                            "regression_passed": False,
                            "error_type": type(exc).__name__,
                        }
                    events.append(
                        self._event(
                            LifecycleStage.IMPLEMENT_SAFE_LOCAL_CHANGE,
                            case_id=contract.case_id,
                            result=improvement,
                        )
                    )
                    regression_passed = improvement.get("regression_passed") is True
                    events.append(
                        self._event(
                            LifecycleStage.RUN_REGRESSION,
                            case_id=contract.case_id,
                            status="passed" if regression_passed else "blocked",
                        )
                    )
                    after_status = before_status
                    after_oracle = before_oracle
                    after_proof = before_proof
                    retest_result: dict[str, Any] = {"status": "not_run"}
                    if regression_passed:
                        retest_task = self._task(target, engagement_id, contract, "retest")
                        retest_record = self._execute(retest_task, preconditions_met=True)
                        retest_candidate = self._payload(retest_record)
                        after_oracle = self._central_verify(
                            contract, baseline, retest_candidate, negative
                        )
                        after_bundle, after_proof = (
                            self._proof(
                                engagement_id=engagement_id,
                                target=target,
                                contract=contract,
                                baseline=baseline,
                                candidate=retest_candidate,
                                negative=negative,
                                oracle=after_oracle,
                            )
                            if (
                                after_oracle["causal_signal"]
                                and after_oracle["negative_control_complete"]
                                and after_oracle["baseline_present"]
                            )
                            else (
                                None,
                                {
                                    "sealed": False,
                                    "verify_seal": False,
                                    "replay_status": "not_run",
                                    "promotion_ready": False,
                                },
                            )
                        )
                        after_status = (
                            OutcomeStatus.CONFIRMED
                            if after_bundle is not None
                            else (
                                OutcomeStatus.OBSERVATION_ONLY
                                if after_oracle["baseline_present"]
                                and after_oracle["negative_control_complete"]
                                else OutcomeStatus.INCONCLUSIVE
                            )
                        )
                        retest_result = {
                            "status": "completed",
                            "oracle": after_oracle,
                            "proof": after_proof,
                        }
                        events.append(
                            self._event(
                                LifecycleStage.RETEST,
                                case_id=contract.case_id,
                                status="completed",
                                result=retest_result,
                            )
                        )
                    else:
                        events.append(
                            self._event(
                                LifecycleStage.RETEST,
                                case_id=contract.case_id,
                                status="blocked_by_regression",
                            )
                        )
                    improvement = {
                        **(improvement if isinstance(improvement, Mapping) else {}),
                        "status": "completed" if regression_passed else "blocked",
                        "before_status": before_status.value,
                        "after_status": after_status.value,
                        "before_oracle": before_oracle,
                        "after_oracle": after_oracle,
                        "retest": retest_result,
                        "scoring_promotion": False,
                    }
                    status = after_status
                    oracle = after_oracle
                    proof = after_proof
                    events.append(
                        self._event(
                            LifecycleStage.COMPARE_BEFORE_AFTER,
                            case_id=contract.case_id,
                            comparison={
                                "before": before_status.value,
                                "after": after_status.value,
                                "evidence_changed": after_status != before_status,
                                "scoring_promotion": False,
                            },
                        )
                    )
                else:
                    events.extend(
                        [
                            self._event(
                                LifecycleStage.IMPLEMENT_SAFE_LOCAL_CHANGE,
                                "blocked",
                                case_id=contract.case_id,
                                reason=(
                                    "owner_approval_required"
                                    if not contract.target_local
                                    else "safe_local_change_handler_not_configured"
                                ),
                            ),
                            self._event(
                                LifecycleStage.RUN_REGRESSION,
                                "blocked",
                                case_id=contract.case_id,
                                reason="no_approved_implementation",
                            ),
                            self._event(
                                LifecycleStage.RETEST,
                                "blocked",
                                case_id=contract.case_id,
                                reason="no_approved_implementation",
                            ),
                            self._event(
                                LifecycleStage.COMPARE_BEFORE_AFTER,
                                "skipped",
                                case_id=contract.case_id,
                                comparison={
                                    "before": status.value,
                                    "after": "not_run",
                                    "scoring_promotion": False,
                                },
                            ),
                        ]
                    )
            case_results.append(
                {
                    "case_id": contract.case_id,
                    "vulnerability_class": contract.vulnerability_class,
                    "status": status.value,
                    "oracle": oracle,
                    "proof": proof,
                    "failure_record": (proposal.failure_record if proposal is not None else None),
                    "improvement_proposal": proposal.as_dict() if proposal else None,
                    "owner_decision_packet": packet.as_dict() if packet else None,
                    "improvement": improvement,
                    "scoring_promotion": False,
                    "raw_payloads_persisted": False,
                }
            )
        return self._report(target, engagement_id, events, case_results, "completed")

    def _report(
        self,
        target: TargetSpec,
        engagement_id: str,
        events: list[dict[str, Any]],
        case_results: list[dict[str, Any]],
        status: str,
    ) -> dict[str, Any]:
        events = [
            *events,
            self._event(LifecycleStage.GENERATE_REPORT, final_status=status),
        ]
        report_identity = _clean(
            {
                "engagement_id": engagement_id,
                "target": target.as_dict(),
                "cases": case_results,
            }
        )
        report = {
            "schema": "vip-autonomous-vertical-slice-v1",
            "status": status,
            "engagement_id": engagement_id,
            "target": target.as_dict(),
            "lifecycle": events,
            "cases": case_results,
            "safety": {
                "loopback_only": True,
                "external_contact": False,
                "credentials_used": False,
                "state_mutation": False,
                "raw_bodies_persisted": False,
                "raw_headers_persisted": False,
                "qualification_claim": None,
                "official_isolated_p10_runs_authorized": False,
            },
            "hash": f"sha256:{sha256_text(report_identity)}",
        }
        return _clean(report)


__all__ = [
    "CaseContract",
    "LifecycleStage",
    "OutcomeStatus",
    "ImprovementProposal",
    "OwnerDecisionPacket",
    "TargetSpec",
    "VIPAutonomousVerticalSlice",
]


# End of module
