"""UM-DR-37 §6 — the unified hypothesis lifecycle registry.

A lifecycle REGISTRY layered over the existing state machines (the main
``models.hypothesis.HypothesisStatus`` + ``research/hypothesis_engine``
one-way transitions, and the EGAIE statuses mapped by
``research/lifecycle_view``). This module does NOT rewrite those
engines: it implements the mission's 12-state vocabulary with explicit,
reason-evidenced transitions, parent/child and competing relations,
duplicate merging, supersession, and evidence-gated reopening.

States (mission §6):

    GENERATED -> NORMALIZED -> DEDUPLICATED -> RANKED -> SELECTED
    -> EXECUTED -> SUPPORTED | REFUTED | INCONCLUSIVE
    any terminal -> REOPENED (ONLY with new evidence) -> back into play
    SUPERSEDED / CLOSED terminal forms

Guaranteed invariants (adversarially pinned in
tests/test_umdr37_lifecycle_registry.py):

  * every transition carries an explicit reason code + free-text reason;
  * invalid transitions are rejected (the graph is enforced, not
    advisory);
  * REOPENING requires NEW evidence references (a refuted hypothesis
    never silently returns);
  * an INCONCLUSIVE experiment never AUTOMATICALLY becomes a refutation
    (INCONCLUSIVE -> REFUTED needs an explicit reason + evidence);
  * merge/supersede bookkeeping is bidirectional (parent/child lists on
    both sides);
  * a candidate is never presented as a confirmed vulnerability —
    SUPPORTED is a hypothesis stage, confirmation belongs to the
    CausalGuard chain alone.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Iterable


class LifecycleStage(str, Enum):
    GENERATED = "GENERATED"
    NORMALIZED = "NORMALIZED"
    DEDUPLICATED = "DEDUPLICATED"
    RANKED = "RANKED"
    SELECTED = "SELECTED"
    EXECUTED = "EXECUTED"
    SUPPORTED = "SUPPORTED"
    REFUTED = "REFUTED"
    INCONCLUSIVE = "INCONCLUSIVE"
    SUPERSEDED = "SUPERSEDED"
    REOPENED = "REOPENED"
    CLOSED = "CLOSED"


#: Explicit transition graph: stage -> allowed successor stages.
#: Every recorded transition must name a reason_code; reopening
#: additionally requires NEW evidence references.
STAGE_TRANSITIONS: dict[LifecycleStage, frozenset[LifecycleStage]] = {
    LifecycleStage.GENERATED: frozenset({
        LifecycleStage.NORMALIZED, LifecycleStage.CLOSED,
        LifecycleStage.SUPERSEDED,
    }),
    LifecycleStage.NORMALIZED: frozenset({
        LifecycleStage.DEDUPLICATED, LifecycleStage.RANKED,
        LifecycleStage.CLOSED, LifecycleStage.SUPERSEDED,
    }),
    # DEDUPLICATED is the merge/duplicate gate: a duplicate merges into
    # its canonical twin (and closes); a survivor proceeds to RANKED.
    LifecycleStage.DEDUPLICATED: frozenset({
        LifecycleStage.RANKED, LifecycleStage.CLOSED,
        LifecycleStage.SUPERSEDED,
    }),
    LifecycleStage.RANKED: frozenset({
        LifecycleStage.SELECTED, LifecycleStage.CLOSED,
        LifecycleStage.SUPERSEDED,
    }),
    LifecycleStage.SELECTED: frozenset({
        LifecycleStage.EXECUTED, LifecycleStage.RANKED,
        LifecycleStage.CLOSED, LifecycleStage.SUPERSEDED,
    }),
    LifecycleStage.EXECUTED: frozenset({
        LifecycleStage.SUPPORTED, LifecycleStage.REFUTED,
        LifecycleStage.INCONCLUSIVE, LifecycleStage.CLOSED,
        LifecycleStage.SUPERSEDED,
    }),
    LifecycleStage.INCONCLUSIVE: frozenset({
        # a follow-up experiment may re-enter selection; a refutation
        # from an inconclusive result needs an EXPLICIT reason + new
        # evidence (never automatic)
        LifecycleStage.RANKED, LifecycleStage.SELECTED,
        LifecycleStage.REFUTED, LifecycleStage.CLOSED,
        LifecycleStage.SUPERSEDED, LifecycleStage.REOPENED,
    }),
    LifecycleStage.SUPPORTED: frozenset({
        LifecycleStage.CLOSED, LifecycleStage.SUPERSEDED,
        LifecycleStage.REOPENED,
    }),
    LifecycleStage.REFUTED: frozenset({
        LifecycleStage.CLOSED, LifecycleStage.REOPENED,
    }),
    LifecycleStage.SUPERSEDED: frozenset({LifecycleStage.REOPENED}),
    LifecycleStage.CLOSED: frozenset({LifecycleStage.REOPENED}),
    # REOPENED re-enters the pool at NORMALIZED (re-normalized against
    # the current model) — never straight to SELECTED.
    LifecycleStage.REOPENED: frozenset({
        LifecycleStage.NORMALIZED, LifecycleStage.CLOSED,
    }),
}

_TERMINAL_STAGES = frozenset({
    LifecycleStage.SUPPORTED, LifecycleStage.REFUTED,
    LifecycleStage.INCONCLUSIVE, LifecycleStage.SUPERSEDED,
    LifecycleStage.CLOSED,
})


@dataclass
class LifecycleEvent:
    """One auditable transition with its explicit reason."""

    from_stage: LifecycleStage
    to_stage: LifecycleStage
    reason_code: str
    reason: str
    evidence_refs: tuple[str, ...] = ()
    at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).replace(
            microsecond=0).isoformat())

    def to_dict(self) -> dict:
        return {
            "from": self.from_stage.value,
            "to": self.to_stage.value,
            "reason_code": self.reason_code,
            "reason": self.reason,
            "evidence_refs": list(self.evidence_refs),
            "at": self.at,
        }


@dataclass
class HypothesisLifecycle:
    """The lifecycle record for ONE hypothesis (the registry object).

    ``hypothesis_id`` is the stable ID of the underlying hypothesis in
    its owning engine (main model / EGAIE record); this registry never
    mints content, it tracks stage + relations + history.
    """

    hypothesis_id: str
    stage: LifecycleStage = LifecycleStage.GENERATED
    history: list[LifecycleEvent] = field(default_factory=list)
    parents: list[str] = field(default_factory=list)
    children: list[str] = field(default_factory=list)
    competing_with: list[str] = field(default_factory=list)
    superseded_by: str | None = None
    superseded_ids: list[str] = field(default_factory=list)
    merged_into: str | None = None
    merged_ids: list[str] = field(default_factory=list)

    # ------------------------------------------------------------------
    # transitions
    # ------------------------------------------------------------------

    def transition(
        self,
        to_stage: LifecycleStage,
        *,
        reason_code: str,
        reason: str,
        evidence_refs: Iterable[str] = (),
    ) -> bool:
        """Record one transition. Returns False (and records nothing)
        when the transition is not in the graph or the reason is
        missing; reopening additionally requires NEW evidence."""
        if not reason_code or not reason.strip():
            return False
        target = LifecycleStage(to_stage)
        if target not in STAGE_TRANSITIONS.get(self.stage, frozenset()):
            return False
        refs = tuple(str(ref) for ref in evidence_refs if str(ref).strip())
        if target is LifecycleStage.REOPENED and not refs:
            # reopening is ONLY valid with new evidence — a refuted or
            # superseded hypothesis never silently returns
            return False
        if (self.stage is LifecycleStage.INCONCLUSIVE
                and target is LifecycleStage.REFUTED and not refs):
            # an inconclusive experiment must never AUTOMATICALLY
            # become a refutation
            return False
        self.history.append(LifecycleEvent(
            from_stage=self.stage, to_stage=target,
            reason_code=reason_code, reason=reason.strip(),
            evidence_refs=refs))
        self.stage = target
        return True

    # ------------------------------------------------------------------
    # relations
    # ------------------------------------------------------------------

    def add_parent(self, parent_id: str) -> None:
        if parent_id and parent_id not in self.parents:
            self.parents.append(parent_id)

    def add_child(self, child_id: str) -> None:
        if child_id and child_id not in self.children:
            self.children.append(child_id)

    def competes_with(self, other_id: str) -> None:
        if other_id and other_id != self.hypothesis_id \
                and other_id not in self.competing_with:
            self.competing_with.append(other_id)

    def mark_duplicate_of(self, canonical: "HypothesisLifecycle") -> bool:
        """Merge this duplicate into its canonical twin: closes self,
        records the merge on BOTH sides. Requires self to have reached
        the DEDUPLICATED gate."""
        if self.stage is not LifecycleStage.DEDUPLICATED:
            return False
        if not self.transition(
                LifecycleStage.CLOSED,
                reason_code="duplicate_merged",
                reason=f"merged into canonical hypothesis "
                       f"{canonical.hypothesis_id}"):
            return False
        self.merged_into = canonical.hypothesis_id
        canonical.merged_ids.append(self.hypothesis_id)
        canonical.add_child(self.hypothesis_id)
        self.add_parent(canonical.hypothesis_id)
        return True

    def supersede(self, successor: "HypothesisLifecycle", *,
                  reason_code: str, reason: str) -> bool:
        """Record that ``successor`` replaces this hypothesis (a
        sharper reformulation). Bidirectional bookkeeping."""
        if not self.transition(
                LifecycleStage.SUPERSEDED,
                reason_code=reason_code, reason=reason):
            return False
        self.superseded_by = successor.hypothesis_id
        successor.superseded_ids.append(self.hypothesis_id)
        successor.add_parent(self.hypothesis_id)
        self.add_child(successor.hypothesis_id)
        return True

    # ------------------------------------------------------------------
    # queries
    # ------------------------------------------------------------------

    @property
    def is_terminal(self) -> bool:
        return self.stage in _TERMINAL_STAGES

    def reopen(self, *, new_evidence_refs: Iterable[str],
               reason_code: str = "reopened_with_new_evidence",
               reason: str = "") -> bool:
        """Reopen a terminal hypothesis — ONLY with new evidence."""
        refs = tuple(str(ref) for ref in new_evidence_refs
                     if str(ref).strip())
        if not refs:
            return False
        return self.transition(
            LifecycleStage.REOPENED,
            reason_code=reason_code,
            reason=reason or f"reopened on {len(refs)} new evidence ref(s)",
            evidence_refs=refs)

    def to_dict(self) -> dict:
        return {
            "hypothesis_id": self.hypothesis_id,
            "stage": self.stage.value,
            "is_terminal": self.is_terminal,
            "history": [event.to_dict() for event in self.history],
            "parents": list(self.parents),
            "children": list(self.children),
            "competing_with": list(self.competing_with),
            "superseded_by": self.superseded_by,
            "superseded_ids": list(self.superseded_ids),
            "merged_into": self.merged_into,
            "merged_ids": list(self.merged_ids),
        }
