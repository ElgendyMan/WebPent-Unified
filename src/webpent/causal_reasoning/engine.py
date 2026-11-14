# src/webpent/causal_reasoning/engine.py
"""CausalReasoningEngine — Proposal #1 unified facade.

Ties together the three sub-systems into one engagement-scoped object:

    engine = CausalReasoningEngine(fingerprint=..., memory_dir=...)
    transferred = engine.start()               # knowledge from past targets
    for finding in confirmed_findings:
        result = engine.ingest_finding(finding, knowledge)
        ... result.at_risk_regions  # reprioritise the search queue
    clusters = engine.end_engagement(...)       # root-cause clusters + persist

The engine is additive and read-only with respect to engagement state: it
never issues requests, never promotes a hypothesis to a finding, never
mutates the LangGraph state.  It emits bounded, confidence-scored
inferences that downstream agents MAY consume.  All outputs are
deterministic given the same inputs (replay-safe, audit-friendly).
"""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable, Mapping

from webpent.causal_reasoning.architecture_inferrer import ArchitectureInferrer
from webpent.causal_reasoning.contextual_memory import (
    DEFAULT_MEMORY_DIR,
    ContextualMemory,
)
from webpent.causal_reasoning.contracts import (
    ContextFingerprint,
    InferenceResult,
    RootCauseCluster,
    TransferredLesson,
    WeaknessCategory,
)
from webpent.causal_reasoning.root_cause_analyzer import RootCauseAnalyzer


@dataclass
class CausalReasoningEngine:
    """Engagement-scoped facade for Proposal #1.

    Args:
        fingerprint: the current target's ContextFingerprint.  Required for
            knowledge transfer; if omitted, `start()` returns [].
        memory_dir: where ContextualMemory persists cross-engagement records.
        inferrer: injectable ArchitectureInferrer (defaults constructed).
        analyzer: injectable RootCauseAnalyzer (defaults constructed).
    """

    fingerprint: ContextFingerprint | None = None
    memory_dir: Path = field(default_factory=lambda: DEFAULT_MEMORY_DIR)
    inferrer: ArchitectureInferrer | None = None
    analyzer: RootCauseAnalyzer | None = None

    def __post_init__(self) -> None:
        self._memory = ContextualMemory(memory_dir=self.memory_dir)
        if self.inferrer is None:
            self.inferrer = ArchitectureInferrer()
        if self.analyzer is None:
            self.analyzer = RootCauseAnalyzer(inferrer=self.inferrer)
        self._findings_seen: list[dict[str, Any]] = []
        self._inference_log: list[InferenceResult] = []
        self._transferred: list[TransferredLesson] = []
        self._knowledge_entities: dict[str, Any] | None = None
        self._knowledge_relations: tuple[Any, ...] = ()
        self._started = False

    # ------------------------------------------------------------------
    # Engagement lifecycle
    # ------------------------------------------------------------------
    def start(self) -> list[TransferredLesson]:
        """Begin engagement: transfer knowledge from analogous past targets.

        Call once at engagement start.  Returns TransferredLesson list sorted
        by (similarity * confidence) desc.  Empty on first-ever target or
        when no analogue exceeds the similarity threshold.
        """
        self._started = True
        if self.fingerprint is None:
            return []
        self._transferred = self._memory.begin_engagement(self.fingerprint)
        return list(self._transferred)

    def ingest_finding(
        self,
        finding: Mapping[str, Any],
        knowledge_entities: Mapping[str, Mapping[str, Any]] | None = None,
        knowledge_relations: Iterable[Mapping[str, Any]] | None = None,
    ) -> InferenceResult:
        """Ingest one confirmed finding; emit hypotheses + at-risk regions.

        Safe to call repeatedly as findings arrive.  Findings are accumulated
        so that `already_covered` marking improves over time (regions with a
        confirmed finding are down-weighted in favour of uncovered siblings).
        """
        if not self._started:
            self.start()
        finding_dict = dict(finding)
        self._findings_seen.append(finding_dict)
        if knowledge_entities is not None:
            self._knowledge_entities = dict(knowledge_entities)
        if knowledge_relations is not None:
            self._knowledge_relations = tuple(knowledge_relations)
        result = self.inferrer.ingest_finding(
            finding_dict,
            knowledge_entities=knowledge_entities,
            knowledge_relations=knowledge_relations,
            existing_findings=self._findings_seen,
        )
        self._inference_log.append(result)
        return result

    def end_engagement(
        self,
        *,
        finding_families: Iterable[str] = (),
        persist: bool = True,
    ) -> dict[str, Any]:
        """End engagement: root-cause clusters + optional memory persistence.

        Returns:
            {
              "root_cause_clusters": [RootCauseCluster...],
              "transferred_lessons_applied": [TransferredLesson...],
              "inference_count": int,
              "persisted_record": EngagementContextRecord | None,
            }
        """
        clusters = self.analyzer.analyze(
            self._findings_seen,
            knowledge_entities=self._knowledge_entities,
            knowledge_relations=self._knowledge_relations,
        )
        # Merge uncovered at-risk regions from the full inference log into
        # each cluster's predicted sibling paths.  The per-finding analyzer
        # pass only sees one finding at a time; the union across all
        # inferences gives the complete "probe next" list.
        uncovered_by_weakness: dict[str, set[str]] = {}
        for inf in self._inference_log:
            for hyp in inf.hypotheses:
                key = hyp.weakness_category.value
                uncovered_by_weakness.setdefault(key, set())
            for region in inf.at_risk_regions:
                if region.already_covered:
                    continue
                for hyp_id in region.supporting_hypothesis_ids:
                    for inf2 in self._inference_log:
                        for hyp in inf2.hypotheses:
                            if hyp.hypothesis_id == hyp_id:
                                uncovered_by_weakness.setdefault(hyp.weakness_category.value, set()).add(region.canonical_key)
        merged_clusters: list[RootCauseCluster] = []
        for c in clusters:
            extra = uncovered_by_weakness.get(c.weakness_category.value, set())
            siblings = tuple(sorted(set(c.sibling_paths_predicted) | extra))[:512]
            merged_clusters.append(RootCauseCluster(
                cluster_id=c.cluster_id,
                weakness_category=c.weakness_category,
                member_finding_ids=c.member_finding_ids,
                sibling_paths_predicted=siblings,
                confidence=c.confidence,
                remediation_hint=c.remediation_hint,
            ))
        clusters = tuple(merged_clusters)
        persisted = None
        if persist and self.fingerprint is not None:
            confirmed_weaknesses = [
                c.weakness_category.value
                for c in clusters
                if c.weakness_category != WeaknessCategory.UNKNOWN and c.confidence >= 0.5
            ]
            routes_by_weakness = {
                c.weakness_category.value: list(c.sibling_paths_predicted) + [
                    str(f.get("route") or f.get("url") or "")
                    for f in self._findings_seen
                ]
                for c in clusters
                if c.weakness_category != WeaknessCategory.UNKNOWN
            }
            persisted = self._memory.record_engagement_outcome(
                self.fingerprint,
                finding_families=finding_families,
                confirmed_weaknesses=confirmed_weaknesses,
                routes_by_weakness=routes_by_weakness,
                total_findings=len(self._findings_seen),
            )
        return {
            "root_cause_clusters": clusters,
            "transferred_lessons_applied": list(self._transferred),
            "inference_count": len(self._inference_log),
            "persisted_record": persisted,
        }

    # ------------------------------------------------------------------
    # Introspection (audit / debug)
    # ------------------------------------------------------------------
    @property
    def inference_log(self) -> tuple[InferenceResult, ...]:
        return tuple(self._inference_log)

    @property
    def findings_seen(self) -> tuple[dict[str, Any], ...]:
        return tuple(self._findings_seen)

    def pattern_summary(self) -> dict[str, Any]:
        """Expose the memory's distilled cross-engagement pattern summary."""
        return self._memory.pattern_summary()


__all__ = ["CausalReasoningEngine"]
