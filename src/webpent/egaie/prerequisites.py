"""L9 §2 — structured, status-tracked preconditions.

Every discriminating experiment may depend on context that must
hold before the experiment can mean anything: an identity, an
ownership relation, an application state, a prior observation, a
workflow transition already performed, a capability, remaining
budget, or authoritative evidence. This module represents those
preconditions EXPLICITLY and distinguishes what is known from what
is merely assumed:

- OBSERVED: backed by a recorded observation (fact).
- INFERRED: believed from the wire model, not verified (assumption).
- ESTABLISHABLE: can be brought about through permitted actions.
- UNATTAINABLE: cannot be brought about within current scope,
  capability or budget.

The type system enforces the mission rule that an inferred
precondition is never a verified fact: only ``verify()`` moves a
precondition to OBSERVED, and it requires the id of the observation
that backs the change. An UNATTAINABLE precondition blocks
execution of the experiment but NEVER yields a negative security
verdict; ``verdict_effect`` says so explicitly.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass, field, replace
from enum import StrEnum
from typing import Any


class PreconditionKind(StrEnum):
    IDENTITY = "identity"
    OWNERSHIP = "ownership"
    APP_STATE = "app_state"
    PRIOR_OBSERVATION = "prior_observation"
    WORKFLOW_TRANSITION = "workflow_transition"
    CAPABILITY = "capability"
    BUDGET = "budget"
    EVIDENCE = "evidence"


class PreconditionStatus(StrEnum):
    OBSERVED = "observed"
    INFERRED = "inferred"
    ESTABLISHABLE = "establishable"
    UNATTAINABLE = "unattainable"


class UnattainableEffect(StrEnum):
    """What an unattainable precondition does to an investigation."""

    BLOCKS_EXECUTION = "blocks_execution"
    NEVER_A_VERDICT = "never_a_negative_security_verdict"


@dataclass(frozen=True, slots=True)
class Precondition:
    """One structured precondition of one hypothesis.

    ``target`` names the concrete thing (a resource, a state
    description, a capability id). ``basis`` is empty for INFERRED
    preconditions and carries the observation id for OBSERVED ones.
    """

    kind: PreconditionKind
    target: str
    status: PreconditionStatus = PreconditionStatus.INFERRED
    basis: str = ""
    establish_via: str = ""

    def __post_init__(self) -> None:
        if self.status is PreconditionStatus.OBSERVED and not self.basis:
            raise ValueError(
                "an OBSERVED precondition requires the observation id "
                "that backs it (an inferred precondition is never a "
                "verified fact)")

    @property
    def verified(self) -> bool:
        return self.status is PreconditionStatus.OBSERVED

    @property
    def blocks_execution(self) -> bool:
        return self.status is PreconditionStatus.UNATTAINABLE

    @property
    def verdict_effect(self) -> UnattainableEffect:
        return UnattainableEffect.NEVER_A_VERDICT


@dataclass
class PrerequisiteLedger:
    """Per-hypothesis structured preconditions with verification.

    The ledger is the single place where a precondition's status
    changes, so the rule "inferred is never observed without an
    observation" holds everywhere at once.
    """

    entries: dict[str, tuple[Precondition, ...]] = field(
        default_factory=dict)

    def declare(
            self,
            hypothesis_id: str,
            preconditions: tuple[Precondition, ...],
    ) -> None:
        if not preconditions:
            return
        merged = {p.target: p for p in
                  self.entries.get(hypothesis_id, ())}
        for p in preconditions:
            merged[p.target] = p
        self.entries[hypothesis_id] = tuple(
            merged[t] for t in sorted(merged))

    def get(self, hypothesis_id: str) -> tuple[Precondition, ...]:
        return self.entries.get(hypothesis_id, ())

    def verify(
            self,
            hypothesis_id: str,
            target: str,
            observation_id: str,
    ) -> Precondition | None:
        """Move one precondition to OBSERVED, backed by an
        observation id. Raises on an unverifiable target."""
        current = self.entries.get(hypothesis_id, ())
        for i, p in enumerate(current):
            if p.target == target:
                verified = replace(
                    p, status=PreconditionStatus.OBSERVED,
                    basis=observation_id)
                self.entries[hypothesis_id] = (
                    current[:i] + (verified,) + current[i + 1:])
                return verified
        raise KeyError(
            f"{hypothesis_id} declares no precondition {target!r}")

    def mark_establishable(self, hypothesis_id: str, target: str,
                           via: str) -> Precondition | None:
        return self._retarget(
            hypothesis_id, target, PreconditionStatus.ESTABLISHABLE,
            via)

    def mark_unattainable(self, hypothesis_id: str, target: str,
                          via: str = "") -> Precondition | None:
        return self._retarget(
            hypothesis_id, target, PreconditionStatus.UNATTAINABLE,
            via)

    def _retarget(self, hypothesis_id: str, target: str,
                  status: PreconditionStatus, via: str) -> (
            Precondition | None):
        current = self.entries.get(hypothesis_id, ())
        for i, p in enumerate(current):
            if p.target == target:
                updated = replace(p, status=status, establish_via=via)
                self.entries[hypothesis_id] = (
                    current[:i] + (updated,) + current[i + 1:])
                return updated
        return None

    def demote(self, hypothesis_id: str, target: str) -> bool:
        """Demote one OBSERVED precondition back to INFERRED (L10
        Phase 3 re-evaluation): a belief it rested on was explicitly
        invalidated, so its observation no longer backs the current
        state. The precondition gates nothing again until a NEW
        observation re-verifies it — demotion never invents
        verification and never produces a verdict either way.
        Returns True when the precondition was demoted."""
        current = self.entries.get(hypothesis_id, ())
        for i, p in enumerate(current):
            if p.target == target:
                if p.status is not PreconditionStatus.OBSERVED:
                    return False
                demoted = replace(
                    p, status=PreconditionStatus.INFERRED,
                    establish_via="re-evaluation: rested belief "
                                  "invalidated")
                self.entries[hypothesis_id] = (
                    current[:i] + (demoted,) + current[i + 1:])
                return True
        return False

    def demote_dependents(self, keys: Iterable[str]) -> list[str]:
        """Re-evaluation pass: every OBSERVED precondition across
        all hypotheses whose target is a demoted assertion key goes
        back to INFERRED. Returns the demoted ``hypothesis:target``
        pairs (the investigation's re-evaluation set)."""
        demoted: list[str] = []
        for key in sorted(set(keys)):
            for hyp_id, preconds in self.entries.items():
                if self.demote(hyp_id, key):
                    demoted.append(f"{hyp_id}:{key}")
        return demoted

    def unverified(self, hypothesis_id: str) -> tuple[Precondition, ...]:
        return tuple(p for p in self.get(hypothesis_id)
                     if not p.verified)

    def execution_blockers(
            self, hypothesis_id: str) -> tuple[Precondition, ...]:
        return tuple(p for p in self.get(hypothesis_id)
                     if p.blocks_execution)

    def verdict_gate(self, hypothesis_id: str) -> str:
        """What an investigator must honor before scoring a
        hypothesis (L9 §2/§5). ``blocked`` precludes execution and
        NEVER yields a negative security verdict; ``unverified``
        precludes confirmation (an inferred precondition is never a
        verified fact); ``clear`` permits the discriminating
        experiment. A hypothesis that declares no preconditions is
        ungated, which preserves pre-planner behavior unchanged."""
        preconds = self.get(hypothesis_id)
        if any(p.blocks_execution for p in preconds):
            return "blocked"
        if not preconds or all(p.verified for p in preconds):
            return "clear"
        return "unverified"

    @classmethod
    def from_hypotheses(cls, hypotheses: Any) -> PrerequisiteLedger:
        """Build a ledger from hypotheses that carry structured
        ``prerequisites`` tuples (see DifferentialHypothesis)."""
        ledger = cls()
        for hyp in hypotheses:
            ledger.declare(
                hyp.hypothesis_id, tuple(hyp.prerequisites))
        return ledger

    def tally(self) -> dict[str, int]:
        """§6 accounting: counts by status over all hypotheses."""
        tally = {s.value: 0 for s in PreconditionStatus}
        for preconds in self.entries.values():
            for p in preconds:
                tally[p.status.value] += 1
        return tally
