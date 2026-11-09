# src/webpent/research_engine/agenda_bridge.py
"""Bridge between the Shannon-pattern integration layer and GOED's
research engine (additive wiring; RESTRICTED zone, new file only).

Part of the Shannon→GOED protected integration (docs/integration/).
This module is the **additive wiring point** that makes
:mod:`webpent.integration` consumable by GOED's native research
contracts (:class:`~webpent.research_engine.research_state.ResearchTask`,
:class:`~webpent.research_engine.research_state.ResearchState`) without
touching any FORBIDDEN file (graph builder, CausalGuard, workers, API
contracts are untouched — see GOED_PROTECTED_INVENTORY.md §5, which
designates ``research_engine/`` as the intended integration surface).

Responsibilities (all deterministic, planning-only, no I/O):

* Convert reconciliation tasks and auth-validation verdicts into
  bounded :class:`~webpent.integration.research_agenda.AgendaSignal`
  inputs (an auth verdict contributes its deterministic
  :meth:`~webpent.integration.auth_session_contract.AuthValidationVerdict.to_signal_strength`
  evidence weight — advisory only).
* Project agenda branches into GOED ``ResearchTask`` rows
  (priority normalized 0..1) and admit them into a ``ResearchState``
  through GOED's own budget-aware ``admit_task`` gate.
* Plan exploitation entries through the evidence-gated
  :class:`~webpent.integration.exploitation_queue.ExploitationQueue`
  (pending entries → deterministic gate → strict outcome union).

Security contract (protocol §8, §12, §22):

* CausalGuard remains the ONLY verdict authority; this bridge never
  creates, mutates, or scores findings/verdicts.
* The LLM can influence priorities only through clamped
  ``PriorityProposal`` objects handled inside the agenda.
* No ground truth, no I/O, no execution; actual exploitation stays
  inside GOED's ActionAuthority/sandbox path.
* Fail-closed: malformed upstream rows are rejected, never guessed.
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator

from webpent.integration.auth_session_contract import AuthValidationVerdict
from webpent.integration.exploitation_queue import (
    ExploitationQueue,
    ExploitAttemptRecord,
    GateResult,
)
from webpent.integration.priority_policy import PriorityDecision, PriorityProposal
from webpent.integration.reconciliation import ResearchTask as ReconciliationTask
from webpent.integration.research_agenda import (
    AgendaLimits,
    AgendaSignal,
    ResearchAgenda,
)

BRIDGE_VERSION = "integration-agenda-bridge-1.0"

# GOED research-engine contracts (imported here, not re-exported as
# different names, so provenance stays obvious).
from webpent.research_engine.research_state import ResearchState  # noqa: E402
from webpent.research_engine.research_state import (  # noqa: E402
    ResearchTask as EngineResearchTask,
)

# Deterministic caps for projection (mirrors GOED's bounded-tuple style).
MAX_EVIDENCE_REFS = 16
OBJECTIVE_MAX = 240
REASON_MAX = 400

# Priority bands (0..100 agenda scale) → GOED risk labels.
_RISK_MEDIUM_THRESHOLD = 70


class BridgePlannedTask(BaseModel):
    """One projected GOED research task + its planning provenance."""

    model_config = ConfigDict(extra="forbid", frozen=True, str_strip_whitespace=True)

    task: EngineResearchTask
    branch_id: str = Field(min_length=1, max_length=160)
    agenda_priority: int = Field(ge=0, le=100)
    bridge_version: str = Field(default=BRIDGE_VERSION, min_length=1)

    @field_validator("branch_id")
    @classmethod
    def _branch_namespace(cls, value: str) -> str:
        if not value.startswith("branch::"):
            raise ValueError("branch_id_namespace_violation")
        return value


class BridgePlanResult(BaseModel):
    """Deterministic result of one planning/admission run."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    bridge_version: str = Field(default=BRIDGE_VERSION, min_length=1)
    planned: tuple[BridgePlannedTask, ...] = ()
    admitted: int = Field(default=0, ge=0)
    stop_reason: str = Field(default="", max_length=240)
    updated_state: ResearchState | None = None


def _clamp01(value: float) -> float:
    return max(0.0, min(1.0, float(value)))


def signal_from_reconciliation_task(
    task: ReconciliationTask,
    *,
    severity_potential: int,
    evidence_strength: float,
    exploitability: float = 0.0,
    asset_criticality: float = 0.0,
    confidence: float = 0.0,
    novelty: float = 0.0,
    exploration_cost: int = 0,
    signal_id: str | None = None,
) -> AgendaSignal:
    """Convert a reconciliation task into a bounded agenda signal.

    The task's stable ``task_ref`` seeds the signal id and its
    materialized observation/producer refs become ``source_refs`` —
    provenance recorded verbatim, never fabricated.
    """
    sid = signal_id or f"rec::{task.task_ref}"
    refs = list(task.evidence_candidate_refs) or list(task.observation_ids)
    return AgendaSignal(
        signal_id=sid[:120],
        hypothesis_id=task.suggested_hypothesis_id()[:120],
        severity_potential=severity_potential,
        evidence_strength=_clamp01(evidence_strength),
        exploitability=_clamp01(exploitability),
        asset_criticality=_clamp01(asset_criticality),
        confidence=_clamp01(confidence),
        novelty=_clamp01(novelty),
        exploration_cost=exploration_cost,
        source_refs=tuple(r[:160] for r in refs[:MAX_EVIDENCE_REFS]),
        note=f"reconciliation:{task.kind}"[:240],
    )


def signal_from_auth_verdict(
    verdict: AuthValidationVerdict,
    *,
    hypothesis_id: str,
    signal_id: str | None = None,
) -> AgendaSignal:
    """Convert an auth-validation verdict into an agenda signal.

    Uses the verdict's deterministic :meth:`to_signal_strength` weight
    (1.0 for verified success, 0.2 for a classified failure). Auth
    posture is research-relevant context for authorization hypotheses;
    it is never a finding and never a verdict (protocol §8).
    """
    sid = signal_id or "auth::session_validation"
    return AgendaSignal(
        signal_id=sid[:120],
        hypothesis_id=hypothesis_id.strip()[:120],
        severity_potential=4,
        evidence_strength=verdict.to_signal_strength(),
        exploitability=0.0,
        asset_criticality=0.4,
        confidence=verdict.to_signal_strength(),
        novelty=0.0,
        exploration_cost=1,
        source_refs=("auth_validation_contract",),
        note=f"auth_posture:{verdict.failure_point.value}"[:240],
    )


class AgendaBridge:
    """Compose agenda + exploitation queue with GOED research state."""

    def __init__(
        self,
        *,
        engagement_id: str,
        target_id: str,
        agenda: ResearchAgenda | None = None,
        queue: ExploitationQueue | None = None,
        limits: AgendaLimits | None = None,
    ) -> None:
        if not engagement_id.strip() or not target_id.strip():
            raise ValueError("bridge_scope_required")
        self.engagement_id = engagement_id.strip()[:160]
        self.target_id = target_id.strip()[:160]
        self.agenda = agenda or ResearchAgenda(limits)
        self.queue = queue or ExploitationQueue()

    # ------------------------------------------------------------------
    # Signal ingestion
    # ------------------------------------------------------------------
    def ingest(
        self,
        signal: AgendaSignal,
        proposal: PriorityProposal | None = None,
    ) -> PriorityDecision:
        """Record one signal in the agenda (deterministic, clamped)."""
        return self.agenda.ingest_signal(signal, proposal=proposal)

    # ------------------------------------------------------------------
    # Agenda → GOED research tasks
    # ------------------------------------------------------------------
    def plan_research_tasks(self, *, limit: int | None = None) -> tuple[BridgePlannedTask, ...]:
        """Project active branches into GOED ``ResearchTask`` rows.

        Deterministic ordering follows ``ResearchAgenda.ordered_active``
        (priority desc, branch id asc). ``limit`` bounds the projection;
        the projection itself never executes anything (operation=plan).
        """
        branches = self.agenda.ordered_active()
        if limit is not None:
            if limit < 0:
                raise ValueError("limit_must_be_non_negative")
            branches = branches[:limit]
        planned: list[BridgePlannedTask] = []
        for branch in branches:
            task_id = f"agenda::{branch.branch_id}"[:160]
            priority01 = round(branch.priority / 100.0, 4)
            engine_task = EngineResearchTask(
                task_id=task_id,
                engagement_id=self.engagement_id,
                target_id=self.target_id,
                objective=branch.hypothesis_id[:OBJECTIVE_MAX],
                reason=(
                    f"agenda branch {branch.branch_id} priority {branch.priority} "
                    f"(depth {branch.depth}, experiments "
                    f"{branch.experiments_used}/{branch.experiments_allocated})"
                )[:REASON_MAX],
                priority=priority01,
                risk=(
                    "medium" if branch.priority >= _RISK_MEDIUM_THRESHOLD else "low"
                ),
                expected_information_gain=_clamp01(branch.novelty),
                cost=_clamp01(branch.exploration_cost / 10.0),
                required_evidence=tuple(branch.signal_ids[:MAX_EVIDENCE_REFS]),
                operation="plan",
            )
            planned.append(
                BridgePlannedTask(
                    task=engine_task,
                    branch_id=branch.branch_id,
                    agenda_priority=branch.priority,
                )
            )
        return tuple(planned)

    def admit_into_state(
        self, state: ResearchState, *, limit: int | None = None
    ) -> BridgePlanResult:
        """Admit planned tasks into GOED's budget-aware research state.

        GOED's own ``ResearchState.admit_task`` enforces scope, dedup,
        and the request budget — this bridge never bypasses it. Tasks
        that the state refuses are simply not admitted (fail-closed).
        """
        planned = self.plan_research_tasks(limit=limit)
        current = state
        admitted = 0
        stop_reason = ""
        for item in planned:
            before = len(current.tasks)
            current = current.admit_task(item.task)
            if len(current.tasks) > before:
                admitted += 1
            if current.stop_reason and not stop_reason:
                stop_reason = current.stop_reason
                break
        return BridgePlanResult(
            planned=planned,
            admitted=admitted,
            stop_reason=stop_reason,
            updated_state=current,
        )

    # ------------------------------------------------------------------
    # Exploitation planning (evidence-gated, non-authoritative)
    # ------------------------------------------------------------------
    def plan_exploitation(self) -> list[GateResult]:
        """Gate every pending queue entry deterministically (RUN/SKIP).

        RUN here is a *planning* verdict only: the caller must still
        route execution through GOED's ActionAuthority/sandbox and feed
        outcomes to CausalGuard (protocol §9, §15).
        """
        results: list[GateResult] = []
        for entry in self.queue.pending_entries():
            results.append(self.queue.gate(entry.entry_id))
        return results

    def record_exploit_outcome(self, record: ExploitAttemptRecord) -> ExploitAttemptRecord:
        """Append a strict attempted/blocked outcome to the audit log."""
        return self.queue.record_attempt(record)

    def exploit_attempts(self) -> tuple[ExploitAttemptRecord, ...]:
        """Read-only attempt log (auditable trail)."""
        return self.queue.attempts()

    # ------------------------------------------------------------------
    # Audit view
    # ------------------------------------------------------------------
    def to_audit_dict(self) -> dict[str, Any]:
        """Flat, JSON-safe audit snapshot of the whole bridge state."""
        return {
            "bridge_version": BRIDGE_VERSION,
            "engagement_id": self.engagement_id,
            "target_id": self.target_id,
            "agenda": self.agenda.checkpoint(),
            "queue": self.queue.to_audit_dict(),
        }


__all__ = [
    "BRIDGE_VERSION",
    "BridgePlanResult",
    "BridgePlannedTask",
    "AgendaBridge",
    "signal_from_auth_verdict",
    "signal_from_reconciliation_task",
]
