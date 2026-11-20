# src/webpent/integration/research_agenda.py
"""Adaptive research agenda with deterministic, bounded prioritization.

Part of the Shannon→GOED protected integration (docs/integration/).
This is **BUILD** per the capability matrix: GOED needs a unified,
dynamically-reprioritized research agenda and Shannon does not provide
one (Shannon's lanes are fixed; its budgets are turn caps only).

What this module is (protocol §11, §12):

* A deterministic, bounded, auditable, reproducible research agenda.
* Signals raise/lower branch priority via the versioned policy in
  :mod:`webpent.integration.priority_policy`; LLM input is limited to
  clamped, recorded *proposals*.
* Budget follows evidence: strong signals earn additional exploration
  budget; weak signals get the base allocation; refutation
  deprioritizes or terminates a branch; exhausted budgets terminate
  safely; resumed agendas never blindly repeat completed work.

What this module is NOT:

* It is **not** a verdict authority — CausalGuard
  (:mod:`webpent.cqa_v2.causal_guard`) remains the ONLY CONFIRMED
  authority (protocol §8).
* It performs **no I/O and no execution** — it is a planning/policy
  layer consumed by GOED's existing loops (Executor ≠ Evaluator;
  no ground truth is ever read, protocol §22).
* It does **not** replace GOED's LangGraph checkpointer, rabbit-hole
  graph policy, or research_engine primitives — it composes with them.

Determinism: all state transitions are pure functions of
(current state, event). No clocks, no randomness. Branch ids derive
deterministically from hypothesis ids; ordering tiebreaks are the
branch id (lexicographic).
"""

from __future__ import annotations

from enum import Enum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, model_validator

from webpent.integration.priority_policy import (
    PriorityDecision,
    PriorityInput,
    PriorityProposal,
    compute_priority,
)

AGENDA_VERSION = "integration-research-agenda-1.0"

# Error reasons (stable strings for auditable decisions).
E_MAX_ACTIVE_BRANCHES = "max_active_branches_reached"
E_MAX_BRANCH_DEPTH = "max_branch_depth_exceeded"
E_MAX_EXPERIMENTS = "max_experiments_per_branch_exceeded"
E_BUDGET_EXHAUSTED = "branch_budget_exhausted"
E_TERMINATED = "branch_terminated"
E_COMPLETED = "branch_already_completed"
E_NOT_FOUND = "branch_not_found"


class BranchStatus(str, Enum):
    """Lifecycle of one research branch (auditable)."""

    ACTIVE = "active"
    DEPRIORITIZED = "deprioritized"
    TERMINATED = "terminated"
    COMPLETED = "completed"


class AgendaLimits(BaseModel):
    """Hard bounds preventing infinite rabbit holes (protocol §12).

    These bounds compose with (and never relax) GOED's existing
    ``RabbitHolePolicy`` and ``ResearchBudget`` contracts.
    """

    model_config = ConfigDict(extra="forbid", frozen=True, str_strip_whitespace=True)

    max_active_branches: int = Field(default=6, ge=1, le=64)
    max_branch_depth: int = Field(default=4, ge=1, le=32)
    max_experiments_per_branch: int = Field(default=8, ge=1, le=1000)
    base_experiments: int = Field(default=2, ge=1, le=100)
    high_priority_budget_boost: int = Field(default=4, ge=0, le=100)
    high_priority_threshold: int = Field(default=70, ge=1, le=100)
    low_priority_threshold: int = Field(default=30, ge=0, le=100)
    max_total_experiments: int = Field(default=64, ge=1, le=100_000)

    @model_validator(mode="after")
    def _sane_thresholds(self) -> AgendaLimits:
        if self.low_priority_threshold >= self.high_priority_threshold:
            raise ValueError("low_priority_threshold_must_be_below_high")
        if self.base_experiments > self.max_experiments_per_branch:
            raise ValueError("base_experiments_must_not_exceed_per_branch_cap")
        return self


class AgendaSignal(BaseModel):
    """A research signal observed on the target (advisory input).

    ``source_refs`` must reference GOED evidence/observation artifacts
    (they are recorded verbatim; this module never fabricates refs).
    An empty tuple is allowed at first-sight time — the signal is then
    weak by construction (evidence_strength is still caller-supplied
    and bounded; fabricated strength is a caller bug, not hidden here).
    """

    model_config = ConfigDict(extra="forbid", frozen=True, str_strip_whitespace=True)

    signal_id: str = Field(min_length=1, max_length=120)
    hypothesis_id: str = Field(min_length=1, max_length=120)
    severity_potential: int = Field(ge=0, le=10)
    evidence_strength: float = Field(ge=0.0, le=1.0)
    exploitability: float = Field(ge=0.0, le=1.0)
    asset_criticality: float = Field(ge=0.0, le=1.0)
    confidence: float = Field(ge=0.0, le=1.0)
    novelty: float = Field(ge=0.0, le=1.0)
    exploration_cost: int = Field(default=0, ge=0, le=10)
    source_refs: tuple[str, ...] = Field(default=())
    note: str = Field(default="", max_length=240)

    @model_validator(mode="after")
    def _sane_refs(self) -> AgendaSignal:
        for ref in self.source_refs:
            if not ref.strip():
                raise ValueError("source_refs_must_be_non_empty")
        return self


class AgendaBranchState(BaseModel):
    """Serializable per-branch state (checkpoint-friendly)."""

    model_config = ConfigDict(extra="forbid", frozen=True, str_strip_whitespace=True)

    branch_id: str = Field(min_length=1, max_length=160)
    hypothesis_id: str = Field(min_length=1, max_length=120)
    depth: int = Field(ge=0, le=32)
    status: BranchStatus = BranchStatus.ACTIVE
    priority: int = Field(ge=0, le=100)
    severity_potential: int = Field(ge=0, le=10)
    evidence_strength: float = Field(ge=0.0, le=1.0)
    exploitability: float = Field(ge=0.0, le=1.0)
    asset_criticality: float = Field(ge=0.0, le=1.0)
    confidence: float = Field(ge=0.0, le=1.0)
    novelty: float = Field(ge=0.0, le=1.0)
    exploration_cost: int = Field(default=0, ge=0, le=10)
    experiments_allocated: int = Field(ge=1, le=2000)
    experiments_used: int = Field(default=0, ge=0)
    completed_markers: tuple[str, ...] = Field(default=())
    decision_log: tuple[dict[str, Any], ...] = Field(default=())
    signal_ids: tuple[str, ...] = Field(default=())

    @model_validator(mode="after")
    def _used_not_over_cap(self) -> AgendaBranchState:
        if self.experiments_used > self.experiments_allocated:
            raise ValueError("experiments_used_exceeds_allocated")
        return self

    def branch_priority_inputs(self) -> PriorityInput:
        return PriorityInput(
            severity_potential=self.severity_potential,
            evidence_strength=self.evidence_strength,
            exploitability=self.exploitability,
            asset_criticality=self.asset_criticality,
            confidence=self.confidence,
            novelty=self.novelty,
            dependency_depth=self.depth,
            exploration_cost=self.exploration_cost,
        )


class AllocationDecision(BaseModel):
    """Result of an experiment-allocation request (pure, auditable)."""

    model_config = ConfigDict(extra="forbid", frozen=True, str_strip_whitespace=True)

    granted: int = Field(ge=0)
    reason: str = Field(min_length=1, max_length=80)
    remaining_budget: int = Field(ge=0)


def branch_id_for(hypothesis_id: str) -> str:
    """Deterministic branch id derived from the hypothesis id."""
    clean = hypothesis_id.strip()
    if not clean:
        raise ValueError("hypothesis_id_required")
    safe = clean.replace(" ", "-")
    return f"branch::{safe}"


class ResearchAgenda:
    """Bounded adaptive research agenda (planning-only, no I/O)."""

    def __init__(self, limits: AgendaLimits | None = None) -> None:
        self.limits = limits or AgendaLimits()
        self._branches: dict[str, AgendaBranchState] = {}
        self._total_experiments_used = 0

    # ------------------------------------------------------------------
    # Signal ingestion (Case A / Case B entry point)
    # ------------------------------------------------------------------
    def ingest_signal(
        self,
        signal: AgendaSignal,
        proposal: PriorityProposal | None = None,
    ) -> PriorityDecision:
        """Record a signal; create or update its branch deterministically.

        High-severity signals receive additional exploration budget
        (Case A); weak signals receive only the base allocation
        (Case B). The exact allocation follows the deterministic
        policy, never the LLM proposal (which is clamped + recorded).
        """
        bid = branch_id_for(signal.hypothesis_id)
        existing = self._branches.get(bid)
        if existing is not None and existing.status is not BranchStatus.ACTIVE:
            # Reactivating a terminated/completed branch is forbidden:
            # a terminated branch stays terminated (append-only audit).
            decision = compute_priority(
                existing.branch_priority_inputs(),
                proposal=proposal,
            )
            rejected = self._append_log(
                existing,
                {
                    "event": "ingest_rejected",
                    "reason": (
                        E_TERMINATED
                        if existing.status is BranchStatus.TERMINATED
                        else E_COMPLETED
                    ),
                    "signal_id": signal.signal_id,
                    "priority": decision.priority,
                },
            )
            self._store(rejected)
            return decision

        if existing is not None:
            branch = AgendaBranchState(
                branch_id=bid,
                hypothesis_id=existing.hypothesis_id,
                depth=existing.depth,
                status=BranchStatus.ACTIVE,
                priority=existing.priority,
                severity_potential=max(existing.severity_potential, signal.severity_potential),
                evidence_strength=max(existing.evidence_strength, signal.evidence_strength),
                exploitability=max(existing.exploitability, signal.exploitability),
                asset_criticality=max(existing.asset_criticality, signal.asset_criticality),
                confidence=max(existing.confidence, signal.confidence),
                novelty=max(existing.novelty, signal.novelty),
                exploration_cost=existing.exploration_cost,
                experiments_allocated=existing.experiments_allocated,
                experiments_used=existing.experiments_used,
                completed_markers=existing.completed_markers,
                decision_log=existing.decision_log,
                signal_ids=tuple(dict.fromkeys((*existing.signal_ids, signal.signal_id))),
            )
            decision = compute_priority(branch.branch_priority_inputs(), proposal=proposal)
            # Team-1 priority-persistence fix: persist the recomputed priority
            # on the existing branch. Previously only experiments_allocated was
            # updated here, so branch.priority stayed at the old value and the
            # scheduler never saw the recomputed score.
            branch = branch.model_copy(update={"priority": decision.priority})
        else:
            depth = self._depth_for_new_branch(signal.hypothesis_id)
            if depth > self.limits.max_branch_depth:
                raise ValueError(E_MAX_BRANCH_DEPTH)
            branch = AgendaBranchState(
                branch_id=bid,
                hypothesis_id=signal.hypothesis_id,
                depth=depth,
                priority=0,  # computed below before the cap check
                severity_potential=signal.severity_potential,
                evidence_strength=signal.evidence_strength,
                exploitability=signal.exploitability,
                asset_criticality=signal.asset_criticality,
                confidence=signal.confidence,
                novelty=signal.novelty,
                experiments_allocated=self.limits.base_experiments,
                signal_ids=(signal.signal_id,),
            )
            decision = compute_priority(branch.branch_priority_inputs(), proposal=proposal)
            # Admit only within the active-branch bound; a strictly
            # higher-priority newcomer may deprioritize the weakest.
            self._enforce_active_cap(incoming_priority=decision.priority)
            branch = branch.model_copy(update={"priority": decision.priority})
        # Budget allocation follows the deterministic priority (Case A/B).
        allocated = self._allocation_for(decision.priority)
        branch = branch.model_copy(update={"experiments_allocated": allocated})
        branch = self._append_log(
            branch,
            {
                "event": "ingest_signal",
                "signal_id": signal.signal_id,
                "priority": decision.priority,
                "allocated": allocated,
                "proposal_applied": decision.proposal_applied,
                "proposal_proposer": decision.proposal_proposer,
                "policy": decision.policy_version,
                "contributions": decision.contributions,
                "source_refs": list(signal.source_refs),
                "note": signal.note,
            },
        )
        self._store(branch)
        return decision

    def _depth_for_new_branch(self, hypothesis_id: str) -> int:
        """Default depth for a root branch; children are created explicitly."""
        return 0

    def _allocation_for(self, priority: int) -> int:
        allocation = self.limits.base_experiments
        if priority >= self.limits.high_priority_threshold:
            allocation += self.limits.high_priority_budget_boost
        return min(allocation, self.limits.max_experiments_per_branch)

    def _enforce_active_cap(self, incoming_priority: int) -> None:
        """Admit a new branch only within the active-branch bound.

        When at the cap, the lowest-priority active branch is
        deprioritized to make room **only if** the incoming branch is
        strictly higher priority; otherwise creation fails closed.
        Ties are broken lexicographically by branch_id.
        """
        active = [b for b in self._branches.values() if b.status is BranchStatus.ACTIVE]
        if len(active) < self.limits.max_active_branches:
            return
        lowest = min(active, key=lambda b: (b.priority, b.branch_id))
        if incoming_priority <= lowest.priority:
            raise ValueError(E_MAX_ACTIVE_BRANCHES)
        demoted = lowest.model_copy(update={"status": BranchStatus.DEPRIORITIZED})
        demoted = self._append_log(
            demoted, {"event": "deprioritized_for_cap", "by_priority": incoming_priority}
        )
        self._store(demoted)

    # ------------------------------------------------------------------
    # Child branches (bounded rabbit-hole exploration)
    # ------------------------------------------------------------------
    def spawn_child_branch(
        self,
        parent_branch_id: str,
        signal: AgendaSignal,
        proposal: PriorityProposal | None = None,
    ) -> PriorityDecision:
        """Explore a related sub-hypothesis one level below the parent.

        Depth is hard-bounded by ``limits.max_branch_depth``
        (bounded rabbit-hole exploration, protocol §11/§12).
        """
        parent = self._require_branch(parent_branch_id)
        if parent.status is not BranchStatus.ACTIVE:
            raise ValueError(
                E_TERMINATED if parent.status is BranchStatus.TERMINATED else E_COMPLETED
            )
        depth = parent.depth + 1
        if depth > self.limits.max_branch_depth:
            raise ValueError(E_MAX_BRANCH_DEPTH)
        bid = branch_id_for(signal.hypothesis_id)
        if bid in self._branches:
            raise ValueError("branch_already_exists")
        branch = AgendaBranchState(
            branch_id=bid,
            hypothesis_id=signal.hypothesis_id,
            depth=depth,
            priority=0,  # computed below before the cap check
            severity_potential=signal.severity_potential,
            evidence_strength=signal.evidence_strength,
            exploitability=signal.exploitability,
            asset_criticality=signal.asset_criticality,
            confidence=signal.confidence,
            novelty=signal.novelty,
            exploration_cost=signal.exploration_cost,
            experiments_allocated=self.limits.base_experiments,
            signal_ids=(signal.signal_id,),
        )
        decision = compute_priority(
            branch.branch_priority_inputs(),
            proposal=proposal,
        )
        self._enforce_active_cap(incoming_priority=decision.priority)
        branch = branch.model_copy(update={"priority": decision.priority})
        branch = self._append_log(
            branch,
            {
                "event": "spawn_child",
                "parent": parent_branch_id,
                "depth": depth,
                "priority": decision.priority,
            },
        )
        self._store(branch)
        return decision

    # ------------------------------------------------------------------
    # Evidence updates (Case C / Case D)
    # ------------------------------------------------------------------
    def record_evidence(
        self,
        branch_id: str,
        *,
        evidence_strength: float,
        refuted: bool = False,
        evidence_ref: str = "",
        note: str = "",
    ) -> PriorityDecision:
        """Fold new evidence into a branch and reprioritize deterministically.

        * Case D: stronger confirmation raises priority deterministically.
        * Case C: refutation lowers priority; a fully-refuted signal
          (``evidence_strength == 0`` and ``refuted``) terminates the
          branch. Refuted-but-partial evidence deprioritizes below the
          low threshold.
        """
        branch = self._require_branch(branch_id)
        if branch.status is not BranchStatus.ACTIVE:
            decision = compute_priority(branch.branch_priority_inputs())
            rejected = self._append_log(
                branch,
                {
                    "event": "evidence_rejected",
                    "reason": (
                        E_TERMINATED
                        if branch.status is BranchStatus.TERMINATED
                        else E_COMPLETED
                    ),
                    "evidence_ref": evidence_ref,
                    "priority": decision.priority,
                },
            )
            self._store(rejected)
            return decision

        new_strength = evidence_strength
        if refuted:
            # Refutation can only lower recorded strength (max-with-old
            # would let a disproven branch keep its inflated score).
            new_strength = min(branch.evidence_strength, evidence_strength)
        new_strength = max(0.0, min(1.0, new_strength))

        updated = branch.model_copy(
            update={
                "evidence_strength": new_strength,
                "confidence": (
                    branch.confidence
                    if refuted
                    else max(branch.confidence, min(1.0, new_strength))
                ),
            },
        )
        decision = compute_priority(updated.branch_priority_inputs())
        update: dict[str, Any] = {"priority": decision.priority}
        if refuted and evidence_strength <= 0.0:
            update["status"] = BranchStatus.TERMINATED
        elif refuted and decision.priority < self.limits.low_priority_threshold:
            update["status"] = BranchStatus.DEPRIORITIZED
        branch = updated.model_copy(update=update)
        branch = self._append_log(
            branch,
            {
                "event": "record_evidence",
                "evidence_ref": evidence_ref,
                "refuted": refuted,
                "new_strength": new_strength,
                "priority": decision.priority,
                "status": branch.status.value,
                "note": note,
            },
        )
        self._store(branch)
        return decision

    # ------------------------------------------------------------------
    # Experiment budget (Case A/B allocation, Case E exhaustion)
    # ------------------------------------------------------------------
    def request_experiment(self, branch_id: str, requested: int = 1) -> AllocationDecision:
        """Grant experiment budget against the branch allocation.

        Case E: once the branch allocation is consumed the branch
        terminates safely (``TERMINATED``) — no infinite rabbit hole.
        The global experiment cap terminates the whole agenda budget.
        """
        branch = self._require_branch(branch_id)
        if branch.status is BranchStatus.COMPLETED:
            return AllocationDecision(granted=0, reason=E_COMPLETED, remaining_budget=0)
        if branch.status is BranchStatus.TERMINATED:
            return AllocationDecision(granted=0, reason=E_TERMINATED, remaining_budget=0)
        if branch.status is BranchStatus.DEPRIORITIZED:
            return AllocationDecision(granted=0, reason="branch_deprioritized", remaining_budget=0)

        if self._total_experiments_used + requested > self.limits.max_total_experiments:
            return AllocationDecision(
                granted=0,
                reason=E_BUDGET_EXHAUSTED,
                remaining_budget=max(
                    0, self.limits.max_total_experiments - self._total_experiments_used
                ),
            )

        remaining = branch.experiments_allocated - branch.experiments_used
        granted = max(0, min(requested, remaining))
        if granted == 0:
            terminated = branch.model_copy(update={"status": BranchStatus.TERMINATED})
            terminated = self._append_log(
                terminated, {"event": "terminate", "reason": E_MAX_EXPERIMENTS}
            )
            self._store(terminated)
            return AllocationDecision(granted=0, reason=E_MAX_EXPERIMENTS, remaining_budget=0)

        updated = branch.model_copy(update={"experiments_used": branch.experiments_used + granted})
        updated = self._append_log(
            updated,
            {"event": "experiment_granted", "granted": granted, "used": updated.experiments_used},
        )
        self._store(updated)
        self._total_experiments_used += granted
        if updated.experiments_used >= updated.experiments_allocated:
            terminated = updated.model_copy(update={"status": BranchStatus.TERMINATED})
            terminated = self._append_log(
                terminated, {"event": "terminate", "reason": E_BUDGET_EXHAUSTED}
            )
            self._store(terminated)
        return AllocationDecision(
            granted=granted,
            reason="granted",
            remaining_budget=max(
                0, self.limits.max_experiments_per_branch - updated.experiments_used
            ),
        )

    # ------------------------------------------------------------------
    # Completion + checkpoint/resume (Case F)
    # ------------------------------------------------------------------
    def mark_completed(self, branch_id: str, marker: str) -> None:
        """Mark a work item complete so resume never repeats it (Case F)."""
        branch = self._require_branch(branch_id)
        marker = marker.strip()
        if not marker:
            raise ValueError("marker_required")
        if marker in branch.completed_markers:
            return
        updated = branch.model_copy(
            update={
                "completed_markers": tuple(dict.fromkeys((*branch.completed_markers, marker))),
                "status": BranchStatus.COMPLETED,
            },
        )
        updated = self._append_log(updated, {"event": "completed", "marker": marker})
        self._store(updated)

    def checkpoint(self) -> dict[str, Any]:
        """Serialize full agenda state (JSON-safe, deterministic)."""
        return {
            "agenda_version": AGENDA_VERSION,
            "limits": self.limits.model_dump(),
            "total_experiments_used": self._total_experiments_used,
            "branches": {
                bid: branch.model_dump(mode="json")
                for bid, branch in sorted(self._branches.items())
            },
        }

    def restore(self, state: dict[str, Any]) -> None:
        """Restore a checkpoint produced by :meth:`checkpoint`.

        Completed branches stay completed; resumed work therefore never
        blindly repeats completed items (protocol §23 Case F).
        """
        if state.get("agenda_version") != AGENDA_VERSION:
            raise ValueError("agenda_checkpoint_version_mismatch")
        limits = AgendaLimits(**state["limits"])
        branches: dict[str, AgendaBranchState] = {}
        for bid, raw in state["branches"].items():
            branches[bid] = AgendaBranchState(**raw)
        self.limits = limits
        self._branches = branches
        self._total_experiments_used = int(state["total_experiments_used"])

    # ------------------------------------------------------------------
    # Read-only views
    # ------------------------------------------------------------------
    def ordered_active(self) -> list[AgendaBranchState]:
        """Active branches ordered by (priority desc, branch_id asc)."""
        active = [b for b in self._branches.values() if b.status is BranchStatus.ACTIVE]
        return sorted(active, key=lambda b: (-b.priority, b.branch_id))

    def get_branch(self, branch_id: str) -> AgendaBranchState | None:
        return self._branches.get(branch_id)

    def audit_trail(self) -> list[dict[str, Any]]:
        """Flattened decision log across branches (auditable, §12)."""
        rows: list[tuple[int, str, dict[str, Any]]] = []
        for bid, branch in self._branches.items():
            for i, entry in enumerate(branch.decision_log):
                rows.append((i, bid, entry))
        rows.sort(key=lambda r: (r[0], r[1]))
        return [{"branch": bid, **entry} for _, bid, entry in rows]

    # ------------------------------------------------------------------
    # internals
    # ------------------------------------------------------------------
    def _require_branch(self, branch_id: str) -> AgendaBranchState:
        branch = self._branches.get(branch_id)
        if branch is None:
            raise KeyError(E_NOT_FOUND)
        return branch

    def _append_log(self, branch: AgendaBranchState, entry: dict[str, Any]) -> AgendaBranchState:
        """Return a copy of ``branch`` with ``entry`` appended to its log."""
        return branch.model_copy(
            update={"decision_log": (*branch.decision_log, dict(entry))},
        )

    def _store(self, branch: AgendaBranchState) -> None:
        self._branches[branch.branch_id] = branch


__all__ = [
    "AGENDA_VERSION",
    "AgendaBranchState",
    "AgendaLimits",
    "AgendaSignal",
    "AllocationDecision",
    "BranchStatus",
    "ResearchAgenda",
    "branch_id_for",
]
