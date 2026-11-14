"""EGAIE investigation state schemas.

Explicit, persisted, inspectable investigation state: hypotheses,
experiments, evidence, decisions, observations, world-model and
attack-graph updates. Everything round-trips through plain JSON so an
interrupted investigation resumes deterministically.
"""
from __future__ import annotations

import enum
from dataclasses import dataclass, field, replace
from typing import Any

_UNRESOLVED = ("proposed", "supported")


class HypothesisStatus(enum.Enum):
    PROPOSED = "proposed"
    SUPPORTED = "supported"
    CONTRADICTED = "contradicted"
    CONFIRMED = "confirmed"
    REFUTED = "refuted"


class EvidenceKind(enum.Enum):
    SUPPORTING = "supporting"
    CONTRADICTING = "contradicting"
    NEUTRAL = "neutral"


class DecisionAction(enum.Enum):
    SELECT = "select"
    STRATEGY_SWITCH = "strategy_switch"
    TERMINATE = "terminate"


@dataclass(frozen=True)
class HypothesisRecord:
    hypothesis_id: str
    family: str
    statement: str
    source: str = "advisory"
    origin: str = ""
    status: HypothesisStatus = HypothesisStatus.PROPOSED

    def with_status(self, status: HypothesisStatus) -> HypothesisRecord:
        return replace(self, status=status)

    def to_dict(self) -> dict[str, Any]:
        return {
            "hypothesis_id": self.hypothesis_id,
            "family": self.family,
            "statement": self.statement,
            "source": self.source,
            "origin": self.origin,
            "status": self.status.value,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> HypothesisRecord:
        return cls(
            hypothesis_id=data["hypothesis_id"],
            family=data["family"],
            statement=data["statement"],
            source=data.get("source", "advisory"),
            origin=data.get("origin", ""),
            status=HypothesisStatus(data.get("status", "proposed")),
        )


@dataclass(frozen=True)
class ProposedExperiment:
    experiment_id: str
    family: str
    signature: str
    description: str
    cost: float
    risk: float
    gain_estimate: float
    rationale: str
    hypothesis_id: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "experiment_id": self.experiment_id,
            "family": self.family,
            "signature": self.signature,
            "description": self.description,
            "cost": self.cost,
            "risk": self.risk,
            "gain_estimate": self.gain_estimate,
            "rationale": self.rationale,
            "hypothesis_id": self.hypothesis_id,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> ProposedExperiment:
        return cls(
            experiment_id=data["experiment_id"],
            family=data["family"],
            signature=data["signature"],
            description=data["description"],
            cost=data["cost"],
            risk=data["risk"],
            gain_estimate=data["gain_estimate"],
            rationale=data["rationale"],
            hypothesis_id=data.get("hypothesis_id", ""),
        )


@dataclass(frozen=True)
class EvidenceItem:
    evidence_id: str
    kind: EvidenceKind
    source: str
    ref: str
    summary: str
    round: int

    def to_dict(self) -> dict[str, Any]:
        return {
            "evidence_id": self.evidence_id,
            "kind": self.kind.value,
            "source": self.source,
            "ref": self.ref,
            "summary": self.summary,
            "round": self.round,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> EvidenceItem:
        return cls(
            evidence_id=data["evidence_id"],
            kind=EvidenceKind(data["kind"]),
            source=data["source"],
            ref=data["ref"],
            summary=data["summary"],
            round=data["round"],
        )


@dataclass(frozen=True)
class DecisionRecord:
    round: int
    action: DecisionAction
    selected_experiment_id: str
    scores: dict[str, float]
    alternatives: tuple[tuple[str, float], ...]
    rationale: str

    def to_dict(self) -> dict[str, Any]:
        # Deterministic: scores sorted by key, alternatives already ordered.
        return {
            "round": self.round,
            "action": self.action.value,
            "selected_experiment_id": self.selected_experiment_id,
            "scores": dict(sorted(self.scores.items())),
            "alternatives": [[cid, score] for cid, score in self.alternatives],
            "rationale": self.rationale,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> DecisionRecord:
        return cls(
            round=data["round"],
            action=DecisionAction(data["action"]),
            selected_experiment_id=data["selected_experiment_id"],
            scores=dict(data["scores"]),
            alternatives=tuple(
                (cid, score) for cid, score in data["alternatives"]
            ),
            rationale=data["rationale"],
        )


@dataclass
class InvestigationState:
    """The single source of truth for one autonomous investigation."""

    engagement_id: str
    target_url: str
    round: int = 0
    terminal_reason: str = ""
    hypotheses: list[HypothesisRecord] = field(default_factory=list)
    experiments: list[ProposedExperiment] = field(default_factory=list)
    evidence: list[EvidenceItem] = field(default_factory=list)
    decisions: list[DecisionRecord] = field(default_factory=list)
    observations: list[dict[str, Any]] = field(default_factory=list)
    world_model_updates: list[dict[str, Any]] = field(default_factory=list)
    attack_graph_updates: list[dict[str, Any]] = field(default_factory=list)
    experiment_outcomes: dict[str, str] = field(default_factory=dict)
    # Append-only proposal log (l10 Phase 5): one entry per proposer
    # pass, {"round": int, "experiment_ids": [..]}. Kept small and
    # structured so instrumentation/provenance can reconstruct how
    # the candidate pool grew without re-running the proposer.
    # UNIFIED MERGE (2026-11-02): restored from the l10 lineage.
    proposal_log: list[dict[str, Any]] = field(default_factory=list)
    proof_bundles_verified: list[dict[str, Any]] = field(
        default_factory=list)

    def add_hypothesis(self, record: HypothesisRecord) -> None:
        self.hypotheses.append(record)

    def add_experiment(self, experiment: ProposedExperiment) -> None:
        self.experiments.append(experiment)

    def add_evidence(self, item: EvidenceItem) -> None:
        self.evidence.append(item)

    def record_decision(self, decision: DecisionRecord) -> None:
        self.decisions.append(decision)

    def set_hypothesis_status(
        self, hypothesis_id: str, status: HypothesisStatus
    ) -> None:
        for index, record in enumerate(self.hypotheses):
            if record.hypothesis_id == hypothesis_id:
                self.hypotheses[index] = record.with_status(status)
                return

    def mark_experiment_outcome(
        self, experiment_id: str, outcome: str
    ) -> None:
        self.experiment_outcomes[experiment_id] = outcome

    def experiment_outcome(self, experiment_id: str) -> str:
        return self.experiment_outcomes.get(experiment_id, "")

    def unresolved_hypotheses(self) -> list[HypothesisRecord]:
        return [
            h for h in self.hypotheses if h.status.value in _UNRESOLVED
        ]

    def pending_experiments(self) -> list[ProposedExperiment]:
        return [
            e for e in self.experiments
            if e.experiment_id not in self.experiment_outcomes
        ]

    def decision_records(self) -> list[DecisionRecord]:
        return list(self.decisions)

    def to_dict(self) -> dict[str, Any]:
        return {
            "engagement_id": self.engagement_id,
            "target_url": self.target_url,
            "round": self.round,
            "terminal_reason": self.terminal_reason,
            "hypotheses": [h.to_dict() for h in self.hypotheses],
            "experiments": [e.to_dict() for e in self.experiments],
            "evidence": [e.to_dict() for e in self.evidence],
            "decisions": [d.to_dict() for d in self.decisions],
            "observations": list(self.observations),
            "world_model_updates": list(self.world_model_updates),
            "attack_graph_updates": list(self.attack_graph_updates),
            "experiment_outcomes": dict(self.experiment_outcomes),
            "proposal_log": [dict(entry) for entry in self.proposal_log],
            "proof_bundles_verified": [
                dict(record) for record in self.proof_bundles_verified
            ],
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> InvestigationState:
        return cls(
            engagement_id=data["engagement_id"],
            target_url=data["target_url"],
            round=data.get("round", 0),
            terminal_reason=data.get("terminal_reason", ""),
            hypotheses=[
                HypothesisRecord.from_dict(h) for h in data.get("hypotheses", [])
            ],
            experiments=[
                ProposedExperiment.from_dict(e)
                for e in data.get("experiments", [])
            ],
            evidence=[
                EvidenceItem.from_dict(e) for e in data.get("evidence", [])
            ],
            decisions=[
                DecisionRecord.from_dict(d) for d in data.get("decisions", [])
            ],
            observations=list(data.get("observations", [])),
            world_model_updates=list(data.get("world_model_updates", [])),
            attack_graph_updates=list(data.get("attack_graph_updates", [])),
            experiment_outcomes=dict(data.get("experiment_outcomes", {})),
            proposal_log=[
                dict(entry)
                for entry in data.get("proposal_log", [])
            ],
            proof_bundles_verified=[
                dict(record)
                for record in data.get("proof_bundles_verified", [])
            ],
        )
