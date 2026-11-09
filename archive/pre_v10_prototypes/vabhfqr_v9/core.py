"""Unified VABH-FQR v9 operating core; deterministic and advisory-only."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from webpent.attack_graph.engine import AttackGraph
from webpent.knowledge.model_v2 import TargetKnowledgeV2
from webpent.research.decision_loop import DecisionLoopContext, decide_next_step
from webpent.research.hypothesis_generator import HypothesisGenerator
from webpent.research.planner import ResearchPlanner
from webpent.shared.confirmation_intelligence import evaluate_confirmation

from .contracts import (
    EvidenceDisposition,
    EvidenceRecordV9,
    LoopStage,
    LoopStepV9,
    ResearchExperimentPlanV9,
    ResearchMemorySnapshotV9,
    SecurityArchitectureMapV9,
    SecurityHypothesisV9,
    UnifiedIntelligenceSnapshotV9,
    VABHFQRV9Result,
)


def _value(source: object | None, *names: str, default: object = None) -> object:
    for name in names:
        if isinstance(source, dict) and name in source:
            return source[name]
        if source is not None and hasattr(source, name):
            return getattr(source, name)
    return default


def _strings(value: object | None, limit: int = 12) -> tuple[str, ...]:
    if value is None:
        return ()
    if isinstance(value, str):
        return (value,) if value else ()
    try:
        return tuple(str(item) for item in value if str(item))[:limit]
    except TypeError:
        return (str(value),)


def _stable(*parts: object) -> str:
    import hashlib

    return hashlib.sha256("|".join(str(part) for part in parts).encode()).hexdigest()[:16]


@dataclass(frozen=True, slots=True)
class VABHFQRV9Core:
    """Composition root for the v9 lifecycle; it never performs transport."""

    VERSION = "vabh-fqr-v9"

    def run(
        self,
        *,
        engagement_id: str,
        target_id: str,
        recorded_state: object | None = None,
        evidence_refs: tuple[str, ...] = (),
        previous_failures: tuple[str, ...] = (),
    ) -> VABHFQRV9Result:
        state = recorded_state
        assets = _strings(_value(state, "critical_assets", "assets"), 10)
        boundaries = _strings(
            _value(state, "threat_boundaries", "boundaries", "trust_boundaries"), 10
        )
        workflows = _strings(_value(state, "workflows", "user_journeys"), 10)
        assumptions = _strings(_value(state, "assumptions", "hidden_assumptions"), 12)
        invariants = _strings(_value(state, "invariants"), 10)
        privileges = _strings(_value(state, "privilege_model", "roles", "privileges"), 10)
        purpose = str(
            _value(state, "purpose", "business_purpose", default="recorded target research")
        )
        if not assets:
            assets = ("recorded critical asset",)
        if not boundaries:
            boundaries = ("recorded trust boundary",)
        if not workflows:
            workflows = ("recorded user workflow",)
        if not assumptions:
            assumptions = ("authorization and state assumptions require evidence",)
        architecture = SecurityArchitectureMapV9(
            map_id=f"arch-{_stable(engagement_id, target_id)}",
            purpose=purpose,
            critical_assets=assets,
            threat_boundaries=boundaries,
            privilege_model=privileges or ("recorded privilege model is incomplete",),
            workflows=workflows,
            invariants=invariants or ("intended behavior must be distinguished from weakness",),
            trust_relationships=_strings(_value(state, "trust_relationships"), 10)
            or ("trust relationship unverified",),
            assumptions=assumptions,
            source_refs=evidence_refs,
        )
        experiments = tuple(
            ResearchExperimentPlanV9(
                experiment_id=f"exp-{_stable(engagement_id, target_id, assumption)}",
                question=f"What recorded evidence would falsify assumption: {assumption}?",
                selected_action="offline evidence review and causal-oracle design",
                expected_information_gain=0.65,
                uncertainty_reduction=0.55,
                evidence_value=0.75,
                estimated_cost=0.10,
                risk=0.0,
                available_capability="recorded_state_only",
                preconditions=(
                    "recorded artifact exists",
                    "scope is local and authorized",
                    "no transport is permitted",
                ),
                success_criteria=(
                    "alternative explanations are documented",
                    "causal oracle requirements are explicit",
                ),
                stop_conditions=(
                    "missing observation",
                    "no causal oracle",
                    "scope or evidence uncertainty",
                ),
                source_refs=evidence_refs,
            )
            for assumption in assumptions[:6]
        )
        hypotheses = tuple(
            SecurityHypothesisV9(
                hypothesis_id=f"hyp-{_stable(engagement_id, target_id, assumption)}",
                origin="architecture-assumption-analysis",
                statement=(
                    f"The assumption may fail under a recorded state transition: {assumption}."
                ),
                reasoning_chain=(
                    f"assumption={assumption}",
                    "identify affected trust or authorization relationship",
                    "require causal observation and independent negative control",
                ),
                supporting_evidence=tuple(evidence_refs),
                conflicting_evidence=("no live causal observation is available",),
                confidence_history=(0.20,),
                next_validation_action="design safe offline validation criteria",
                source_refs=evidence_refs,
            )
            for assumption in assumptions[:6]
        )
        evidence = tuple(
            EvidenceRecordV9(
                evidence_id=f"ev-{_stable(hypothesis.hypothesis_id)}",
                subject_id=hypothesis.hypothesis_id,
                observation_refs=(),
                causal_oracle=(
                    "requires candidate/control observations and intended-behavior predicate"
                ),
                reproducibility_requirements=(
                    "sealed ProofBundle",
                    "replay verification",
                    "independent reviewer",
                ),
                proof_bundle_ref="",
                seal_verified=False,
                replay_verified=False,
                explanation="recorded reasoning only; no observation exists, so this is blocked",
                disposition=EvidenceDisposition.BLOCKED,
            )
            for hypothesis in hypotheses
        )
        steps = tuple(
            LoopStepV9(
                stage=stage,
                completed=stage
                in {LoopStage.OBSERVE, LoopStage.UNDERSTAND, LoopStage.REASON, LoopStage.PLAN},
                rationale=self._rationale(stage, previous_failures),
                inputs=(target_id,),
                outputs=(),
            )
            for stage in LoopStage
        )
        snapshot = ResearchMemorySnapshotV9(
            target_id=target_id,
            engagement_id=engagement_id,
            version=self.VERSION,
            lessons=("no causal claim without observations, oracle, sealed proof, and replay",),
            rejected_hypotheses=(),
            failed_experiments=previous_failures,
            state_digest=_stable(engagement_id, target_id, repr(state)),
        )
        return VABHFQRV9Result(
            engagement_id=engagement_id,
            target_id=target_id,
            architecture_map=architecture,
            experiments=experiments,
            hypotheses=hypotheses,
            evidence=evidence,
            memory_snapshot=snapshot,
            loop_steps=steps,
        )

    def build_unified_intelligence(
        self,
        *,
        knowledge: TargetKnowledgeV2,
        graph: AttackGraph,
        engagement_id: str,
        target_id: str,
        available_capabilities: tuple[str, ...] = (),
        scope_verified: bool = False,
        policy_allows_proposal: bool = True,
        remaining_budget: int = 0,
        completed_steps: int = 0,
        max_steps: int = 1,
        attempted_task_ids: tuple[str, ...] = (),
        attempted_hypothesis_ids: tuple[str, ...] = (),
        completed_task_ids: tuple[str, ...] = (),
        available_evidence: tuple[str, ...] = (),
        required_evidence: tuple[str, ...] = (),
        negative_control_complete: bool = False,
        replay_verified: bool = False,
        confirmation_contract: Any | None = None,
        proof_bundle: Any | None = None,
        evidence_payloads: tuple[Any, ...] = (),
        negative_control_payload: Any = None,
        replay_context: dict[str, Any] | None = None,
    ) -> UnifiedIntelligenceSnapshotV9:
        """Compose generic discovery, planning, decision, and confirmation.

        The method consumes recorded knowledge/graph/evidence only.  It never
        performs transport, mutates state, creates findings, or changes
        qualification state.  Missing scope, evidence, controls, or replay
        remain visible as blocked/replan decisions.
        """
        if not isinstance(knowledge, TargetKnowledgeV2) or not isinstance(graph, AttackGraph):
            return UnifiedIntelligenceSnapshotV9(
                engagement_id=engagement_id,
                target_id=target_id,
                hypothesis_ids=(),
                hypothesis_classes=(),
                queue_task_ids=(),
                selected_task_id=None,
                decision_status="blocked",
                decision_stage="discovery",
                confirmation_posture="not_evaluated",
                confirmation_score=None,
                engineering_confirmed=False,
                scoring_eligible=False,
                recommendations=("typed_recorded_knowledge_and_graph_required",),
            )
        hypotheses = HypothesisGenerator().generate(knowledge, graph)
        capabilities = tuple(available_capabilities)
        if not capabilities:
            capabilities = tuple(sorted({str(item.required_capability) for item in hypotheses}))
        planner = ResearchPlanner()
        queue = planner.build_queue(
            hypotheses,
            engagement_id=engagement_id,
            target_id=target_id,
            available_capabilities=capabilities,
            completed_task_ids=completed_task_ids,
            attempted_hypothesis_ids=attempted_hypothesis_ids,
        )
        decision = decide_next_step(
            queue,
            DecisionLoopContext(
                scope_verified=scope_verified,
                policy_allows_proposal=policy_allows_proposal,
                remaining_budget=remaining_budget,
                attempted_task_ids=frozenset(attempted_task_ids),
                available_evidence=frozenset(available_evidence),
                required_evidence=frozenset(required_evidence),
                negative_control_complete=negative_control_complete,
                replay_verified=replay_verified,
                max_steps=max_steps,
                completed_steps=completed_steps,
            ),
        )

        assessment = None
        if confirmation_contract is not None:
            assessment = evaluate_confirmation(
                confirmation_contract,
                proof_bundle=proof_bundle,
                evidence_payloads=evidence_payloads,
                negative_control_payload=negative_control_payload,
                replay_context=replay_context,
            )
        posture = "not_evaluated"
        score = None
        engineering_confirmed = False
        scoring_eligible = False
        recommendations = list(decision.rationale)
        missing_evidence = sorted(set(required_evidence).difference(available_evidence))
        recommendations.extend(missing_evidence)
        if assessment is not None:
            posture_value = (
                assessment.posture.value
                if hasattr(assessment.posture, "value")
                else assessment.posture
            )
            posture = str(posture_value)
            score = float(assessment.score)
            engineering_confirmed = posture == "engineering_confirmed"
            scoring_eligible = bool(assessment.scoring_eligible)
            recommendations.extend(assessment.missing)
            recommendations.extend(assessment.reasons)
        recommendations = tuple(dict.fromkeys(str(item) for item in recommendations))
        return UnifiedIntelligenceSnapshotV9(
            engagement_id=engagement_id,
            target_id=target_id,
            hypothesis_ids=tuple(str(item.id) for item in hypotheses),
            hypothesis_classes=tuple(
                str(getattr(item.vuln_class, "value", item.vuln_class)) for item in hypotheses
            ),
            queue_task_ids=tuple(str(item.task_id) for item in queue.tasks),
            selected_task_id=decision.selected_task_id,
            decision_status=str(getattr(decision.status, "value", decision.status)),
            decision_stage=decision.stage,
            confirmation_posture=posture,
            confirmation_score=score,
            engineering_confirmed=engineering_confirmed,
            scoring_eligible=scoring_eligible,
            recommendations=recommendations,
        )

    @staticmethod
    def _rationale(stage: LoopStage, previous_failures: tuple[str, ...]) -> str:
        if stage in {LoopStage.VALIDATE, LoopStage.REVIEW, LoopStage.LEARN, LoopStage.IMPROVE}:
            return "blocked until causal evidence and replayable proof exist"
        if previous_failures:
            return "adapted from recorded failure history without repeating unsupported actions"
        return f"deterministic recorded-state {stage.value} stage"


__all__ = ["VABHFQRV9Core"]
