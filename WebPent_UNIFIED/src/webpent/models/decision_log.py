# src/webpent/models/decision_log.py
"""webpent.models.decision_log

V7 Cognitive Upgrade — Phase 6: Decision Log.

A new append-only structured log, **distinct** from:

  * :attr:`Finding.reasoning` (per-finding justification), and
  * :attr:`PentestState.messages` (the chat transcript).

Each entry records one decision the system made (or deferred to a
human), with the deterministic rule that fired and the LLM's
contribution kept in a clearly separate field so they're never
confused. Persisted via a new SQLite table following the exact same
``CREATE TABLE IF NOT EXISTS`` + manager-class pattern already used
for ``findings`` and ``hypotheses``.

Per Phase 6 spec: "surfaced in the final report as an explainability
appendix — a natural extension of the project's existing audit-trail
ethos (``evidence_hash``, ``reasoning``, HMAC-signed master report
hash)."

Decision types (closed set — per Section 3 of the plan):

  * ``prioritization``           — Dynamic Prioritization ranked/sorted.
  * ``hypothesis_promoted``      — a Hypothesis was promoted to a Finding.
  * ``rabbit_hole_entered``      — a Rabbit Hole branch was entered.
  * ``rabbit_hole_abandoned``    — a Rabbit Hole branch was abandoned.
  * ``self_critique``            — Phase 5 Self-Critique fired.
  * ``scope_check``              — a scope check ran (initial or re-check).
  * ``risk_gate_blocked``        — the Risk Manager blocked an action.
"""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any
from uuid import UUID, uuid4

from pydantic import BaseModel, ConfigDict, Field, field_validator


class DecisionType(str, Enum):
    """Closed set of Decision Log entry types.

    Per Section 3 of the plan: ``prioritization``, ``hypothesis_promoted``,
    ``rabbit_hole_entered``, ``rabbit_hole_abandoned``, ``self_critique``,
    ``scope_check``, ``risk_gate_blocked``. Adding a new type is a code
    change, not an LLM output — keeps the audit vocabulary stable.

    POST-P0 Phase 1: added ``replan`` — emitted by the graph replan
    bookkeeping wrapper whenever a post-validation replan entry is
    consumed (evidence-monotonic gate fired), so operators can audit
    WHY the strategist re-ranked mid-run and how much of the bounded
    replan budget was spent.
    """

    PRIORITIZATION = "prioritization"
    HYPOTHESIS_PROMOTED = "hypothesis_promoted"
    RABBIT_HOLE_ENTERED = "rabbit_hole_entered"
    RABBIT_HOLE_ABANDONED = "rabbit_hole_abandoned"
    SELF_CRITIQUE = "self_critique"
    SCOPE_CHECK = "scope_check"
    RISK_GATE_BLOCKED = "risk_gate_blocked"
    REPLAN = "replan"
    # POST-P0 Phase 9: operator-facing audit events (approve/resume/OOB
    # callback/login). Recorded server-side with redacted identifiers —
    # never secrets, tokens, or cookie values.
    OPERATOR_ACTION = "operator_action"


class DecisionLogEntry(BaseModel):
    """A single append-only Decision Log entry.

    Attributes:
        id: Stable UUID for cross-referencing.
        timestamp: UTC timestamp of the decision.
        decision_type: The :class:`DecisionType`.
        rule_fired: The deterministic rule/threshold that fired
            (e.g. ``"score=0.62 >= PROMOTION_THRESHOLD=0.50"``).
            This is ALWAYS a deterministic-rule description, never
            the LLM's free text — the LLM's contribution goes in
            ``llm_contribution``.
        llm_contribution: The LLM's contribution if one was involved,
            kept in a clearly separate field so it's never confused
            with the deterministic rule itself. Empty string when no
            LLM was consulted.
        outcome: The outcome of the decision (e.g. ``"promoted"``,
            ``"deferred"``, ``"abandoned"``, ``"blocked"``).
        entity_refs: References to any Hypothesis/Finding/MentalModel
            entities involved (UUIDs as strings).
        branch_id: Optional Rabbit Hole branch ID if this decision is
            scoped to a specific branch. None for engagement-wide
            decisions.
        metadata: Free-form dict for decision-type-specific extras.
    """

    model_config = ConfigDict(
        extra="forbid",
        str_strip_whitespace=True,
        use_enum_values=True,
    )

    id: UUID = Field(
        default_factory=uuid4,
        description="Stable UUID for cross-referencing.",
    )
    timestamp: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="UTC timestamp of the decision.",
    )
    decision_type: DecisionType = Field(
        ...,
        description="The decision type. See DecisionType.",
    )
    rule_fired: str = Field(
        ...,
        min_length=1,
        description=(
            "The deterministic rule/threshold that fired. ALWAYS a "
            "deterministic-rule description, never the LLM's free text."
        ),
    )
    llm_contribution: str = Field(
        default="",
        description=(
            "The LLM's contribution if one was involved, kept separate "
            "from rule_fired so they're never confused. Empty when no "
            "LLM was consulted."
        ),
    )
    outcome: str = Field(
        default="",
        description=(
            "The outcome of the decision (e.g. 'promoted', 'deferred', "
            "'abandoned', 'blocked')."
        ),
    )
    entity_refs: list[str] = Field(
        default_factory=list,
        description=(
            "References to any Hypothesis/Finding/MentalModel entities "
            "involved (UUIDs as strings)."
        ),
    )
    branch_id: str | None = Field(
        default=None,
        description=(
            "Optional Rabbit Hole branch ID if this decision is scoped "
            "to a specific branch. None for engagement-wide decisions."
        ),
    )
    metadata: dict[str, Any] = Field(
        default_factory=dict,
        description="Free-form dict for decision-type-specific extras.",
    )

    @field_validator("decision_type", mode="before")
    @classmethod
    def _normalise_decision_type(
        cls, v: str | DecisionType | None,
    ) -> DecisionType:
        if v is None:
            raise ValueError("decision_type cannot be None.")
        if isinstance(v, DecisionType):
            return v
        return DecisionType(str(v).lower())

    def to_dict_for_state(self) -> dict[str, Any]:
        """Serialise to the dict shape stored in PentestState.decision_log.

        ``PentestState.decision_log`` is ``Annotated[list[dict[str, Any]],
        merge_lists]`` — append-only. Each entry is a JSON-safe dict.
        """
        return self.model_dump(mode="json")
