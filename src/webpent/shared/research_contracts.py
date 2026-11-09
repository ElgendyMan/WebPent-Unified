"""Adapters and fail-closed decision utilities for bounded research planning.

This module intentionally sits above the existing campaign executor. It ranks
validated proposals only; it never performs I/O, authorizes a request, or
promotes a finding.
"""

from __future__ import annotations

from collections.abc import Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any

from webpent.models.research import (
    CandidateAction,
    InformationObservation,
    ResearchContext,
    SurfaceCoverage,
)
from webpent.shared.research_intelligence import ActionClass, InformationAction


@dataclass(frozen=True)
class ResearchDecision:
    """Explainable score for one validated candidate action."""

    candidate: CandidateAction
    score: float
    reasons: tuple[str, ...] = ()
    status: str = "ranked"
    utility_trace: Mapping[str, Any] = field(default_factory=dict)

    def as_dict(self) -> dict[str, Any]:
        return {
            "candidate": self.candidate.as_dict(),
            "score": self.score,
            "reasons": list(self.reasons),
            "status": self.status,
            "utility_trace": dict(self.utility_trace),
        }


@dataclass(frozen=True)
class SpecializedResearcherContract:
    """Advisory contract describing which researcher owns an action class."""

    researcher_id: str
    action_classes: tuple[ActionClass, ...]
    evidence_focus: str
    contract_version: int = 1

    def as_dict(self) -> dict[str, Any]:
        return {
            "researcher_id": self.researcher_id,
            "action_classes": [item.value for item in self.action_classes],
            "evidence_focus": self.evidence_focus,
            "contract_version": self.contract_version,
            "advisory_only": True,
        }


@dataclass(frozen=True)
class SpecialistResearcherProfile:
    """Domain routing metadata; it cannot authorize or execute a probe."""

    domain_id: str
    researcher_id: str
    action_classes: tuple[ActionClass, ...]
    evidence_focus: str
    capability_hints: tuple[str, ...] = ()
    contract_version: int = 1

    def as_dict(self) -> dict[str, Any]:
        return {
            "domain_id": self.domain_id,
            "researcher_id": self.researcher_id,
            "action_classes": [item.value for item in self.action_classes],
            "evidence_focus": self.evidence_focus,
            "capability_hints": list(self.capability_hints),
            "contract_version": self.contract_version,
            "advisory_only": True,
        }


_SPECIALIST_PROFILES: tuple[SpecialistResearcherProfile, ...] = (
    SpecialistResearcherProfile(
        "auth",
        "auth-researcher",
        (ActionClass.IDENTITY_ACQUISITION, ActionClass.BROWSER_ACTION),
        "authorized identity state and session prerequisites",
        ("http_read", "browser_read"),
    ),
    SpecialistResearcherProfile(
        "authorization",
        "authorization-researcher",
        (ActionClass.ACTIVE_PROBE, ActionClass.NEGATIVE_CONTROL),
        "owner/foreign differential and negative-control prerequisites",
        ("http_read", "http_write"),
    ),
    SpecialistResearcherProfile(
        "business_logic",
        "business-logic-researcher",
        (ActionClass.WORKFLOW_REPLAY, ActionClass.BASELINE),
        "observed state transitions and invariant boundaries",
        ("http_read", "workflow_replay"),
    ),
    SpecialistResearcherProfile(
        "api",
        "api-researcher",
        (ActionClass.DISCOVERY, ActionClass.PARSER_PROBE, ActionClass.ACTIVE_PROBE),
        "API surface, parser behavior, and bounded response observations",
        ("http_read", "schema_read"),
    ),
    SpecialistResearcherProfile(
        "client_side",
        "client-side-researcher",
        (ActionClass.DISCOVERY, ActionClass.BROWSER_ACTION, ActionClass.PARSER_PROBE),
        "client-rendered routes, forms, and parser/oracle observations",
        ("browser_read", "http_read"),
    ),
)

_SPECIALIST_PROFILE_BY_DOMAIN = {
    profile.domain_id: profile for profile in _SPECIALIST_PROFILES
}


def specialist_profile_for_domain(
    domain_id: str,
) -> SpecialistResearcherProfile | None:
    """Return bounded domain routing metadata, never an execution capability."""
    return _SPECIALIST_PROFILE_BY_DOMAIN.get(str(domain_id or "").strip().lower())


def specialist_domains_for_action(action_class: ActionClass | str) -> tuple[str, ...]:
    """Return deterministic domain labels associated with an action class."""
    try:
        normalized = (
            action_class
            if isinstance(action_class, ActionClass)
            else ActionClass(str(action_class))
        )
    except (TypeError, ValueError):
        return ()
    return tuple(
        profile.domain_id
        for profile in _SPECIALIST_PROFILES
        if normalized in profile.action_classes
    )


_SPECIALIZED_RESEARCHER_CONTRACTS: tuple[SpecializedResearcherContract, ...] = (
    SpecializedResearcherContract(
        "surface-researcher", (ActionClass.DISCOVERY,), "bounded surface and asset coverage"
    ),
    SpecializedResearcherContract(
        "identity-researcher",
        (ActionClass.IDENTITY_ACQUISITION,),
        "authorized identity and ownership context",
    ),
    SpecializedResearcherContract(
        "workflow-researcher",
        (ActionClass.WORKFLOW_REPLAY,),
        "observed workflow transitions and replay prerequisites",
    ),
    SpecializedResearcherContract(
        "baseline-researcher", (ActionClass.BASELINE,), "independent baseline observations"
    ),
    SpecializedResearcherContract(
        "negative-control-researcher",
        (ActionClass.NEGATIVE_CONTROL,),
        "independent negative controls",
    ),
    SpecializedResearcherContract(
        "active-probe-researcher",
        (ActionClass.ACTIVE_PROBE, ActionClass.BROWSER_ACTION),
        "bounded active observations without confirmation authority",
    ),
    SpecializedResearcherContract(
        "parser-researcher", (ActionClass.PARSER_PROBE,), "parser and oracle behavior"
    ),
    SpecializedResearcherContract(
        "validation-researcher",
        (ActionClass.VALIDATOR_RETRY, ActionClass.PROOF_REPLAY),
        "validator and sealed proof replay prerequisites",
    ),
    SpecializedResearcherContract(
        "safe-stop-researcher", (ActionClass.SAFE_STOP,), "safe stop and unresolved state"
    ),
)

_RESEARCHER_CONTRACT_BY_ACTION: dict[ActionClass, SpecializedResearcherContract] = {
    action_class: contract
    for contract in _SPECIALIZED_RESEARCHER_CONTRACTS
    for action_class in contract.action_classes
}


def researcher_contract_for_action(
    action_class: ActionClass | str,
) -> SpecializedResearcherContract | None:
    """Return the advisory owner contract for an action class, if mapped."""
    try:
        normalized = (
            action_class
            if isinstance(action_class, ActionClass)
            else ActionClass(str(action_class))
        )
    except (TypeError, ValueError):
        return None
    return _RESEARCHER_CONTRACT_BY_ACTION.get(normalized)


def researcher_metadata_for_action(action_class: ActionClass | str) -> dict[str, Any]:
    """Return bounded researcher metadata without granting execution authority."""
    contract = researcher_contract_for_action(action_class)
    if contract is None:
        return {
            "researcher_id": "unassigned",
            "researcher_contract_status": "unmapped",
            "researcher_contract_version": 1,
            "specialist_domains": list(specialist_domains_for_action(action_class)),
            "advisory_only": True,
        }
    return {
        "researcher_id": contract.researcher_id,
        "researcher_contract_status": "mapped",
        "researcher_contract_version": contract.contract_version,
        "researcher_evidence_focus": contract.evidence_focus,
        "specialist_domains": list(specialist_domains_for_action(action_class)),
        "advisory_only": True,
    }


def candidate_from_information_action(
    action: InformationAction,
    *,
    gap_id: str = "",
    hypothesis_id: str = "",
    likelihood: float = 0.5,
    impact: float = 0.5,
    evidence_potential: float = 0.5,
    novelty: float = 0.5,
    coverage_value: float = 0.5,
) -> CandidateAction:
    """Convert the legacy dataclass proposal into the new validated contract."""
    return CandidateAction(
        action_id=action.action_id,
        action_class=action.action_class.value,
        objective=action.objective,
        target_ref=action.target_ref,
        method=action.method,
        gap_id=gap_id,
        hypothesis_id=hypothesis_id,
        identity_context=action.identity_context,
        tenant_context=action.tenant_context,
        workflow_state=action.workflow_state,
        expected_information_gain=action.expected_information_gain,
        likelihood=likelihood,
        impact=impact,
        evidence_potential=evidence_potential,
        novelty=novelty,
        coverage_value=coverage_value,
        cost=action.cost,
        failure_probability=action.failure_probability,
        scope_risk=action.scope_risk,
        rate_limit_cost=action.rate_limit_cost,
        dependency_penalty=action.dependency_penalty,
        capability=action.capability,
        required_capabilities=[action.capability] if action.capability else [],
        requires_approval=action.requires_approval,
        idempotency_key=action.idempotency_key,
        justification=action.justification,
        metadata={
            **researcher_metadata_for_action(action.action_class),
            **dict(action.metadata),
        },
    )


def research_context_from_state(state: Mapping[str, Any]) -> ResearchContext:
    """Return a checkpoint-safe context without mutating LangGraph state."""
    return ResearchContext.from_state(dict(state))


class ResearchDecisionEngine:
    """Rank candidates with hard safety gates before utility scoring.

    The utility is the product of bounded likelihood, impact, evidence
    potential, information gain, novelty, and coverage value divided by
    bounded cost/risk terms. Missing capability, explicit scope mismatch, and
    exhausted budget are hard stops, not low scores.
    """

    def __init__(
        self,
        *,
        duplicate_penalty: float = 0.05,
        failed_path_penalty: float = 0.15,
    ) -> None:
        self.duplicate_penalty = max(0.0, min(1.0, float(duplicate_penalty)))
        self.failed_path_penalty = max(0.0, min(1.0, float(failed_path_penalty)))

    @staticmethod
    def _bounded(value: Any, default: float = 0.0) -> float:
        try:
            return max(0.0, min(1.0, float(value)))
        except (TypeError, ValueError):
            return default

    @staticmethod
    def _utility_trace(
        candidate: CandidateAction,
        *,
        status: str,
        factors: Mapping[str, float],
        cost_terms: Mapping[str, float],
        base_score: float | None,
        final_score: float,
        penalties: Iterable[str] = (),
        blocked_reasons: Iterable[str] = (),
    ) -> dict[str, Any]:
        """Return bounded, report-safe utility telemetry for one decision."""
        return {
            "version": "research-utility-v1",
            "status": status,
            "factors": {key: round(float(value), 6) for key, value in factors.items()},
            "cost_terms": {
                key: round(float(value), 6) for key, value in cost_terms.items()
            },
            "base_score": None if base_score is None else round(float(base_score), 8),
            "penalties": [str(item)[:120] for item in penalties][:12],
            "blocked_reasons": [str(item)[:160] for item in blocked_reasons][:12],
            "final_score": round(float(final_score), 8),
            "advisory_only": True,
        }

    @classmethod
    def _candidate_utility_inputs(
        cls, candidate: CandidateAction
    ) -> tuple[dict[str, float], dict[str, float]]:
        factors = {
            "likelihood": cls._bounded(candidate.likelihood, 0.5),
            "impact": cls._bounded(candidate.impact, 0.5),
            "evidence_potential": cls._bounded(candidate.evidence_potential, 0.5),
            "information_gain": cls._bounded(candidate.expected_information_gain),
            "novelty": cls._bounded(candidate.novelty, 0.5),
            "coverage_value": cls._bounded(candidate.coverage_value, 0.5),
        }
        cost_terms = {
            "cost": max(0.0, min(100000.0, float(candidate.cost))),
            "failure_probability": cls._bounded(candidate.failure_probability),
            "scope_risk": cls._bounded(candidate.scope_risk),
            "rate_limit_cost": cls._bounded(candidate.rate_limit_cost),
            "dependency_penalty": cls._bounded(candidate.dependency_penalty),
        }
        return factors, cost_terms

    @staticmethod
    def _capability_names(capabilities: Mapping[str, Any] | Iterable[str]) -> set[str]:
        if isinstance(capabilities, Mapping):
            return {
                str(name)
                for name, record in capabilities.items()
                if isinstance(record, Mapping) and record.get("available") is True
            }
        return {str(item) for item in capabilities}

    def score(
        self,
        candidate: CandidateAction,
        *,
        available_capabilities: Mapping[str, Any] | Iterable[str] = (),
        attempted_fingerprints: Iterable[str] = (),
        failed_path_fingerprints: Iterable[str] = (),
        new_evidence: bool = False,
        revisit_authorized: bool = False,
        budget_remaining: float | None = None,
        target_allowed: bool | None = None,
        known_facts: Iterable[str] = (),
        experiment_outcome_tracker: Any | None = None,
        candidate_unresolved_questions: Mapping[str, list[str]] | None = None,
    ) -> ResearchDecision:
        factors, cost_terms = self._candidate_utility_inputs(candidate)

        def blocked(reason: str) -> ResearchDecision:
            return ResearchDecision(
                candidate=candidate,
                score=-1.0,
                reasons=(reason,),
                status="blocked",
                utility_trace=self._utility_trace(
                    candidate,
                    status="blocked",
                    factors=factors,
                    cost_terms=cost_terms,
                    base_score=None,
                    final_score=-1.0,
                    blocked_reasons=(reason,),
                ),
            )

        available = self._capability_names(available_capabilities)
        required = {str(item) for item in candidate.required_capabilities if str(item)}
        missing = sorted(required - available) if required else []
        if missing:
            return blocked("missing_capability:" + ",".join(missing))
        if target_allowed is False:
            return blocked("target_scope_denied")
        if budget_remaining is not None and candidate.cost > max(0.0, float(budget_remaining)):
            return blocked("budget_exhausted")
        known = {str(item).strip() for item in known_facts if str(item).strip()}
        missing_prerequisites = sorted(
            {
                str(item).strip()
                for item in candidate.prerequisites
                if str(item).strip() and str(item).strip() not in known
            }
        )
        if missing_prerequisites:
            return blocked("missing_prerequisite:" + ",".join(missing_prerequisites))

        numerator = 1.0
        for value in factors.values():
            numerator *= max(0.01, value)
        denominator = max(0.05, cost_terms["cost"])
        for key in (
            "failure_probability",
            "scope_risk",
            "rate_limit_cost",
            "dependency_penalty",
        ):
            denominator *= 1.0 + cost_terms[key]
        base_score = numerator / max(0.01, denominator)
        score = base_score
        reasons: list[str] = []
        penalties: list[str] = []

        attempted = {str(item) for item in attempted_fingerprints}
        failed = {str(item) for item in failed_path_fingerprints}
        fingerprint = candidate.fingerprint()
        if fingerprint in attempted and not new_evidence:
            score *= self.duplicate_penalty
            reasons.append("duplicate_without_new_evidence_penalty")
            penalties.append(
                f"duplicate_without_new_evidence:{self.duplicate_penalty:.6f}"
            )
        if fingerprint in failed and not (new_evidence or revisit_authorized):
            score *= self.failed_path_penalty
            reasons.append("failed_path_revisit_penalty")
            penalties.append(f"failed_path_revisit:{self.failed_path_penalty:.6f}")
        if candidate.requires_approval:
            reasons.append("approval_boundary_required")
        if factors["information_gain"] >= 0.7:
            reasons.append("high_information_gain")
        if factors["coverage_value"] >= 0.7:
            reasons.append("coverage_gap_value")
        if target_allowed is True:
            reasons.append("explicit_scope_match")

        # === SEMANTIC REDUNDANCY ADJUSTMENT (research stagnation fix) ===
        # Adjust value based on actual research history for this semantic
        # experiment identity. This is a VALUE ADJUSTMENT only — never
        # blocks. Different actor/query/branch = different fingerprint.
        semantic_factor = 1.0
        unresolved_bonus = 1.0
        semantic_fp = None

        if experiment_outcome_tracker is not None:
            try:
                from webpent.llm_researcher.semantic_fingerprint import (
                    semantic_fingerprint_from_candidate,
                )
                semantic_fp = semantic_fingerprint_from_candidate(candidate)
                if semantic_fp:
                    semantic_factor = experiment_outcome_tracker.semantic_redundancy_factor(
                        semantic_fp
                    )
                    if semantic_factor < 1.0:
                        reasons.append("semantic_redundancy_adjustment")
                        penalties.append(f"semantic_redundancy:{semantic_factor:.6f}")

                    # Unresolved questions bonus
                    if candidate_unresolved_questions:
                        branch_id = (candidate.metadata or {}).get("branch_id", "")
                        unresolved = candidate_unresolved_questions.get(branch_id, [])
                        if unresolved:
                            unresolved_bonus = experiment_outcome_tracker.unresolved_questions_benefit(
                                semantic_fp, unresolved
                            )
                            if unresolved_bonus > 1.0:
                                reasons.append("unresolved_questions_benefit")
                                penalties.append(f"unresolved_bonus:{unresolved_bonus:.6f}")
            except Exception:
                # Fail-open: if semantic fingerprinting fails, no adjustment
                semantic_factor = 1.0
                unresolved_bonus = 1.0

        score = score * semantic_factor * unresolved_bonus
        final_score = round(score, 8)
        return ResearchDecision(
            candidate=candidate,
            score=final_score,
            reasons=tuple(reasons),
            utility_trace=self._utility_trace(
                candidate,
                status="ranked",
                factors=factors,
                cost_terms=cost_terms,
                base_score=base_score,
                final_score=final_score,
                penalties=penalties,
            ),
        )

    def rank(self, candidates: Sequence[CandidateAction], **kwargs: Any) -> list[ResearchDecision]:
        return sorted(
            (self.score(candidate, **kwargs) for candidate in candidates),
            key=lambda item: (-item.score, item.candidate.action_id),
        )


@dataclass(frozen=True)
class ActiveResearchResult:
    """Safe output of one active step; no raw transport response is retained."""

    context: ResearchContext
    selected: ResearchDecision | None
    observation: InformationObservation
    coverage: SurfaceCoverage

    def as_dict(self) -> dict[str, Any]:
        return {
            "context": self.context.as_dict(),
            "selected": self.selected.as_dict() if self.selected else None,
            "observation": self.observation.model_dump(mode="json"),
            "coverage": self.coverage.as_dict(),
        }


class CoverageIntelligence:
    """Track bounded surface coverage and expose gaps for future planning."""

    def __init__(self, *, expected_action_classes: Iterable[str] = ()) -> None:
        self.expected_action_classes = {str(item) for item in expected_action_classes if str(item)}
        self._surfaces: dict[str, SurfaceCoverage] = {}

    def update(
        self,
        *,
        surface_id: str,
        target_ref: str,
        action: CandidateAction,
        observation: InformationObservation,
    ) -> SurfaceCoverage:
        current = self._surfaces.get(surface_id) or SurfaceCoverage(
            surface_id=surface_id,
            target_ref=target_ref,
            coverage_score=0.0,
        )
        attempted = list(dict.fromkeys([*current.attempted_action_ids, action.action_id]))[-100:]
        classes = list(dict.fromkeys([*current.covered_action_classes, action.action_class]))[-100:]
        positive = list(dict.fromkeys([*current.positive_observation_ids]))
        negative = list(dict.fromkeys([*current.negative_observation_ids]))
        inconclusive = list(dict.fromkeys([*current.inconclusive_observation_ids]))
        if observation.status == "positive":
            positive.append(observation.observation_id)
        elif observation.status == "negative":
            negative.append(observation.observation_id)
        else:
            inconclusive.append(observation.observation_id)
        expected = self.expected_action_classes or set(classes)
        coverage_score = len(set(classes) & expected) / max(1, len(expected))
        current = SurfaceCoverage(
            surface_id=surface_id,
            target_ref=target_ref,
            surface_type=current.surface_type,
            attempted_action_ids=attempted,
            covered_action_classes=classes,
            uncovered_action_classes=sorted(expected - set(classes)),
            positive_observation_ids=positive[-100:],
            negative_observation_ids=negative[-100:],
            inconclusive_observation_ids=inconclusive[-100:],
            coverage_score=coverage_score,
        )
        self._surfaces[surface_id] = current
        return current

    def snapshot(self) -> dict[str, dict[str, Any]]:
        return {key: value.as_dict() for key, value in self._surfaces.items()}


class ActiveResearchLoop:
    """Execute at most one policy-approved, injected research action per step."""

    def __init__(
        self,
        *,
        decision_engine: ResearchDecisionEngine | None = None,
        coverage: CoverageIntelligence | None = None,
        max_steps: int = 10,
        llm_selector: Any | None = None,
        experiment_outcome_tracker: Any | None = None,
    ) -> None:
        self.decision_engine = decision_engine or ResearchDecisionEngine()
        self.coverage = coverage or CoverageIntelligence()
        self.max_steps = max(1, min(100, int(max_steps)))
        # Additive LLM advisory selector (default None -> deterministic path
        # byte-identical). Set only by active_research_node when the explicit
        # opt-in flag AND a real provider are both present.
        self.llm_selector = llm_selector
        # Additive: outcome tracker feeds redundancy-aware ranking (default
        # None -> historical ranking byte-identical).
        self.experiment_outcome_tracker = experiment_outcome_tracker

    @staticmethod
    def _blocked_observation(
        candidate: CandidateAction | None, reason: str
    ) -> InformationObservation:
        action_id = candidate.action_id if candidate else "action:none"
        fingerprint = candidate.fingerprint() if candidate else "0" * 32
        return InformationObservation(
            observation_id=f"observation:blocked:{fingerprint}",
            action_id=action_id,
            action_fingerprint=fingerprint,
            status="blocked",
            reason=reason,
            revisit_conditions=["explicit policy/capability/scope change"],
        )

    def step(
        self,
        context: ResearchContext,
        candidates: Sequence[CandidateAction],
        *,
        handler: Callable[[CandidateAction], Mapping[str, Any]] | None = None,
        available_capabilities: Mapping[str, Any] | Iterable[str] = (),
        target_allowed: bool | None = None,
        approved: bool = False,
        failed_path_fingerprints: Iterable[str] = (),
    ) -> ActiveResearchResult:
        """Select and optionally execute one action, requiring explicit scope."""
        if context.depth >= min(context.max_depth, self.max_steps):
            observation = self._blocked_observation(None, "research_depth_exhausted")
            return ActiveResearchResult(
                context, None, observation, SurfaceCoverage(surface_id="none")
            )
        if context.budget_remaining <= 0:
            observation = self._blocked_observation(None, "research_budget_exhausted")
            return ActiveResearchResult(
                context, None, observation, SurfaceCoverage(surface_id="none")
            )
        decisions = self.decision_engine.rank(
            candidates,
            available_capabilities=available_capabilities,
            attempted_fingerprints=context.attempted_action_fingerprints,
            failed_path_fingerprints=failed_path_fingerprints,
            budget_remaining=context.budget_remaining,
            target_allowed=target_allowed,
            known_facts=context.known_facts,
            experiment_outcome_tracker=self.experiment_outcome_tracker,
        )
        selected = next((item for item in decisions if item.status == "ranked"), None)
        # Additive LLM advisory override (default off). The LLM may only pick
        # an already-ranked admissible candidate; any failure/malformed/
        # non-executable decision is rejected (structural diagnostic recorded)
        # and the deterministic selection stands. No silent mock fallback.
        if self.llm_selector is not None and selected is not None:
            llm_pick = self.llm_selector.select_from_candidates(context, decisions)
            if llm_pick is not None:
                matched = next(
                    (d for d in decisions if d.candidate is llm_pick), None
                )
                if matched is not None:
                    selected = matched
        if selected is None:
            observation = self._blocked_observation(None, "no_policy_approved_candidate")
            return ActiveResearchResult(
                context, None, observation, SurfaceCoverage(surface_id="none")
            )
        candidate = selected.candidate
        if target_allowed is not True:
            observation = self._blocked_observation(
                candidate, "target_scope_not_explicitly_allowed"
            )
        elif candidate.requires_approval and not approved:
            observation = self._blocked_observation(candidate, "human_approval_required")
        elif handler is None:
            observation = self._blocked_observation(candidate, "no_authorized_handler")
        else:
            try:
                raw = handler(candidate)
                observation = InformationObservation.model_validate(raw)
            except Exception as exc:  # handler boundary must fail closed
                observation = InformationObservation(
                    observation_id=f"observation:infrastructure:{candidate.fingerprint()}",
                    action_id=candidate.action_id,
                    action_fingerprint=candidate.fingerprint(),
                    status="infrastructure_failure",
                    reason=type(exc).__name__,
                    revisit_conditions=["repair handler and retry with fresh evidence"],
                )
        context.current_action_id = candidate.action_id
        context.attempted_action_fingerprints = list(
            dict.fromkeys([*context.attempted_action_fingerprints, candidate.fingerprint()])
        )[-200:]
        context.depth += 1
        context.budget_remaining = max(0.0, context.budget_remaining - candidate.cost)
        context.known_facts = list(
            dict.fromkeys([*context.known_facts, *observation.new_facts])
        )[-100:]
        coverage = self.coverage.update(
            surface_id=candidate.target_ref or candidate.action_id,
            target_ref=candidate.target_ref,
            action=candidate,
            observation=observation,
        )
        return ActiveResearchResult(context, selected, observation, coverage)


def active_research_node(
    state: Mapping[str, Any],
    *,
    handler: Callable[[CandidateAction], Mapping[str, Any]] | None = None,
    target_allowed: bool | None = None,
    approved: bool = False,
) -> dict[str, Any]:
    """Run one active research step under explicit scope and handler gates.

    The function is intentionally not auto-wired into legacy graph routes. A
    caller must inject an authorized handler and pass ``target_allowed=True``.
    """
    context = ResearchContext.from_state(dict(state))
    raw_candidates = state.get("research_candidate_actions") or []
    candidates: list[CandidateAction] = []
    for raw in raw_candidates[:100]:
        if not isinstance(raw, Mapping):
            continue
        try:
            candidate_payload = dict(raw)
            candidate_payload.pop("fingerprint", None)
            candidates.append(CandidateAction.model_validate(candidate_payload))
        except Exception:
            continue
    budget = state.get("action_budget") or {}
    if isinstance(budget, Mapping):
        context.budget_remaining = float(
            budget.get("research_budget_remaining", budget.get("remaining_cost", 0.0)) or 0.0
        )
    manifest = state.get("capability_manifest") or {}
    available = manifest.get("capabilities", {}) if isinstance(manifest, Mapping) else {}
    previous_coverage = state.get("surface_coverage") or {}
    coverage = CoverageIntelligence(
        expected_action_classes={candidate.action_class for candidate in candidates}
    )
    surfaces = (
        previous_coverage.get("surfaces", {})
        if isinstance(previous_coverage, Mapping)
        else {}
    )
    for surface_id, raw_surface in surfaces.items():
        if isinstance(raw_surface, Mapping):
            try:
                coverage._surfaces[str(surface_id)] = SurfaceCoverage.model_validate(raw_surface)
            except Exception:
                continue
    failed_paths = {
        str(item.get("action_fingerprint"))
        for item in state.get("research_failed_paths", [])
        if isinstance(item, Mapping) and item.get("action_fingerprint")
    }
    # Additive LLM advisory selector: constructed ONLY when the explicit
    # opt-in flag AND a real provider are both present (else None ->
    # deterministic path byte-identical). Lazy import keeps the hard
    # dependency optional; any failure degrades to deterministic (no mock).
    llm_selector: Any | None = None
    try:
        from webpent.integration.llm_research_adapter import LLMResearchSelector
        # Lifecycle fix: session-scoped selector (reused across invocations
        # within one research session). No cross-session leakage.
        _session_key = (
            str(getattr(context, "session_id", "")),
            str(getattr(context, "engagement_id", "")),
            str(getattr(context, "client_id", "")),
        )
        llm_selector = LLMResearchSelector.build_if_enabled(_session_key)
    except Exception:
        llm_selector = None
    result = ActiveResearchLoop(
        coverage=coverage,
        llm_selector=llm_selector,
        experiment_outcome_tracker=(llm_selector.outcome_tracker if llm_selector is not None else None),
    ).step(
        context,
        candidates,
        handler=handler,
        available_capabilities=available,
        target_allowed=target_allowed,
        approved=approved,
        failed_path_fingerprints=failed_paths,
    )
    # V4 outcome-aware: record actual execution outcome into the session-scoped
    # outcome tracker (feeds future redundancy factors). Structural only.
    if llm_selector is not None and getattr(result, "selected", None) is not None:
        try:
            llm_selector.record_outcome(result.selected.candidate, result.observation)
        except Exception:
            pass
    observation = result.observation.model_dump(mode="json")
    failed_update = []
    if observation["status"] in {"negative", "inconclusive", "infrastructure_failure"}:
        failed_update.append(
            {
                "action_id": observation["action_id"],
                "action_fingerprint": observation["action_fingerprint"],
                "status": observation["status"],
                "reason": observation["reason"],
                "revisit_conditions": observation["revisit_conditions"],
            }
        )
    return {
        "research_context": result.context.as_dict(),
        "research_active_observations": [observation],
        "surface_coverage": {
            "surfaces": {result.coverage.surface_id: result.coverage.as_dict()}
        },
        "research_failed_paths": failed_update,
    }


__all__ = [
    "ActiveResearchLoop",
    "active_research_node",
    "ActiveResearchResult",
    "CoverageIntelligence",
    "ResearchDecision",
    "ResearchDecisionEngine",
    "SpecializedResearcherContract",
    "SpecialistResearcherProfile",
    "candidate_from_information_action",
    "specialist_domains_for_action",
    "specialist_profile_for_domain",
    "researcher_contract_for_action",
    "researcher_metadata_for_action",
    "research_context_from_state",
]
