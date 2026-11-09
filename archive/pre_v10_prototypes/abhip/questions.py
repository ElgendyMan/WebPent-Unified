"""Automatic, target-neutral security question generation for ABHIP v5."""

from __future__ import annotations

import hashlib
from collections.abc import Mapping, Sequence

from webpent.shared.research_intelligence import GapKind, KnowledgeGap, KnowledgeGapEngine

from .contracts import SecurityQuestion, TargetIntelligenceGraph


class SecurityQuestionGenerator:
    """Turn explicit knowledge gaps into bounded research questions."""

    def __init__(self, *, max_questions: int = 32) -> None:
        self.max_questions = max(1, min(128, int(max_questions)))
        self.gap_engine = KnowledgeGapEngine(max_gaps=self.max_questions)

    @staticmethod
    def _question_id(target_id: str, text: str) -> str:
        digest = hashlib.sha256(f"{target_id}|{text}".encode()).hexdigest()[:24]
        return f"question:{digest}"

    @staticmethod
    def _from_gap(gap: KnowledgeGap) -> SecurityQuestion:
        if gap.kind == GapKind.OWNERSHIP:
            question = "Can another identity access this object under the recorded ownership model?"
            assumption = (
                "Object access is restricted to the recorded owner or explicitly permitted actor."
            )
            evidence = ("owner_context", "foreign_identity_control", "recorded_response_pair")
            strategy = ("compare_owner_and_foreign_identity_observations", "require_causal_oracle")
        elif gap.kind == GapKind.AUTHORIZATION:
            question = "Can this resource be accessed without the required role or permission?"
            assumption = "The role and permission boundary is enforced for the affected resource."
            evidence = ("role_context", "permission_mapping", "negative_control_observation")
            strategy = (
                "compare_authorized_and_unauthorized_contexts",
                "stop_if_scope_oracle_missing",
            )
        elif gap.kind == GapKind.WORKFLOW:
            question = (
                "Can this workflow transition happen without the required privilege or state?"
            )
            assumption = (
                "Workflow transitions require the documented predecessor state and privilege."
            )
            evidence = ("workflow_state_observation", "transition_rule", "independent_control")
            strategy = (
                "compare_allowed_and_forbidden_transition_states",
                "require_replayable_evidence",
            )
        elif gap.kind == GapKind.IDENTITY_TENANT:
            question = "Can this tenant influence or observe another tenant's resource?"
            assumption = "Tenant isolation prevents cross-tenant influence or observation."
            evidence = ("tenant_context_pair", "ownership_relation", "negative_control_observation")
            strategy = ("compare_tenant_a_and_tenant_b_contexts", "require_causal_oracle")
        elif gap.kind == GapKind.ORACLE:
            question = (
                "Is there a deterministic causal oracle that can distinguish the candidate "
                "from its control?"
            )
            assumption = "A candidate result is not meaningful without an independent oracle."
            evidence = ("candidate_observation", "control_observation", "oracle_contract")
            strategy = ("define_oracle_before_execution", "fail_closed_when_oracle_is_missing")
        else:
            question = f"What recorded evidence is still needed to resolve: {gap.unknown}?"
            assumption = "The observed surface is incomplete until the named evidence is recorded."
            evidence = ("target_backed_observation", "source_reference", "validation_record")
            strategy = ("rank_low_risk_information_gain", "avoid_repeating_attempted_paths")
        return SecurityQuestion(
            question_id=SecurityQuestionGenerator._question_id(gap.target_ref, question),
            question=question,
            affected_assets=tuple(
                item for item in (gap.target_ref, gap.affected_object, gap.affected_actor) if item
            ),
            security_assumption=assumption,
            expected_evidence=tuple(dict.fromkeys((*evidence, *gap.supporting_evidence))),
            validation_strategy=strategy,
            source_refs=gap.supporting_evidence,
            priority=max(0.0, min(1.0, gap.priority())),
        )

    def generate_from_gaps(self, gaps: Sequence[KnowledgeGap]) -> tuple[SecurityQuestion, ...]:
        questions = [self._from_gap(gap) for gap in gaps if gap.status.value == "open"]
        return tuple(
            sorted(
                questions, key=lambda item: (-item.priority, item.question_id)
            )[: self.max_questions]
        )

    def generate(
        self,
        graph: TargetIntelligenceGraph,
        *,
        state: Mapping[str, object] | None = None,
        gaps: Sequence[KnowledgeGap] = (),
    ) -> tuple[SecurityQuestion, ...]:
        """Generate questions only from explicit gaps or graph coverage metadata."""
        if not isinstance(graph, TargetIntelligenceGraph):
            raise TypeError("target_intelligence_graph_required")
        derived = list(gaps)
        if state is not None:
            derived.extend(self.gap_engine.derive(state))
        if graph.coverage_gaps:
            for item in graph.coverage_gaps:
                derived.append(
                    KnowledgeGap(
                        gap_id=self._question_id(graph.target_id, item),
                        kind=GapKind.COVERAGE,
                        objective="resolve an explicitly recorded target coverage gap",
                        unknown=item,
                        target_ref=graph.target_id,
                        supporting_evidence=("coverage_map",),
                        expected_information_gain=0.6,
                        cost=1.0,
                        risk=0.05,
                    )
                )
        if not derived:
            derived.extend(self._graph_questions_as_gaps(graph))
        unique: dict[str, KnowledgeGap] = {gap.gap_id: gap for gap in derived}
        return self.generate_from_gaps(tuple(unique.values()))

    @staticmethod
    def _graph_questions_as_gaps(graph: TargetIntelligenceGraph) -> tuple[KnowledgeGap, ...]:
        gaps: list[KnowledgeGap] = []
        for node in graph.nodes:
            if node.kind in {"object", "resource"}:
                gaps.append(
                    KnowledgeGap(
                        gap_id=f"graph:{node.node_id}:ownership",
                        kind=GapKind.OWNERSHIP,
                        objective="clarify ownership boundary for a recorded object or resource",
                        unknown="owner and foreign-identity behavior",
                        target_ref=node.node_id,
                        affected_object=node.label,
                        affected_actor="owner_vs_foreign",
                        supporting_evidence=node.evidence_refs or (node.evidence_source,),
                        expected_information_gain=0.8,
                        cost=1.0,
                        risk=0.05,
                    )
                )
            elif node.kind in {"workflow", "permission", "role"}:
                gaps.append(
                    KnowledgeGap(
                        gap_id=f"graph:{node.node_id}:authorization",
                        kind=GapKind.AUTHORIZATION,
                        objective="clarify the recorded role or workflow boundary",
                        unknown="required privilege and forbidden transition",
                        target_ref=node.node_id,
                        affected_object=node.label,
                        affected_actor=node.kind,
                        supporting_evidence=node.evidence_refs or (node.evidence_source,),
                        expected_information_gain=0.7,
                        cost=1.0,
                        risk=0.05,
                    )
                )
        return tuple(gaps)


__all__ = ["SecurityQuestionGenerator"]
