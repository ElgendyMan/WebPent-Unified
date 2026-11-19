"""Compatibility builder facade for the canonical attack-graph projection."""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from typing import Any

from webpent.shared.attack_graph import build_attack_graph


class AttackGraphBuilder:
    """Build an evidence-backed graph without network or finding authority."""

    def build(
        self,
        mental_model: Any = None,
        *,
        relational_evidence: Iterable[Any] = (),
        findings: Iterable[Any] = (),
        hypotheses: Iterable[Any] = (),
        novel_behaviors: Iterable[Any] = (),
        causal_edges: Iterable[Any] = (),
        coverage_gaps: Iterable[Any] = (),
        knowledge_gaps: Iterable[Any] = (),
        runtime_capability_gaps: Iterable[Any] = (),
        target_knowledge: Mapping[str, Any] | None = None,
    ) -> dict[str, Any]:
        return build_attack_graph(
            mental_model,
            relational_evidence=relational_evidence,
            findings=findings,
            hypotheses=hypotheses,
            novel_behaviors=novel_behaviors,
            causal_edges=causal_edges,
            coverage_gaps=coverage_gaps,
            knowledge_gaps=knowledge_gaps,
            runtime_capability_gaps=runtime_capability_gaps,
            target_knowledge=target_knowledge,
        )


__all__ = ["AttackGraphBuilder"]
