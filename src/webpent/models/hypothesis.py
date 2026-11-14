# src/webpent/models/hypothesis.py
"""webpent.models.hypothesis

V7 Cognitive Upgrade — Phase 1: Hypothesis Engine.

A :class:`Hypothesis` represents *"I suspect X might be true about this
target"* — a belief that has NOT yet consumed a tool call to test it.
This is distinct from a :class:`webpent.models.findings.Finding`, which
represents a security observation that has already been produced by an
agent or tool.

The split exists so beliefs can be:

  * **First-class, scoreable objects** — ranked, deferred, or promoted
    by Dynamic Prioritization (Phase 3) before any execution budget is
    spent on them.
  * **Persisted as structured rows** (not bare text strings) so the
    decision trail from belief -> investigation -> finding is auditable
    end-to-end. The old ``state["hypotheses"]: list[str]`` carried no
    provenance, no status, no confidence, and no parent reference — it
    was impossible to reconstruct why the system ended up investigating
    what it investigated.
  * **Tracked across Rabbit Hole branches** (Phase 7) via the
    ``parent_hypothesis_id`` field, so the chain "why did we end up
    three levels deep on this artifact" is always traceable.

The model reuses the existing :class:`VulnClass` enum from
:mod:`webpent.models.findings` — no new taxonomy is introduced. A
hypothesis that doesn't fit any known class uses ``VulnClass.UNKNOWN``,
exactly like findings do today.

Promotion discipline (Phase 1 step 3 + Phase 3):
    A hypothesis becomes an actionable :class:`Finding` (and enters the
    existing ``payload_generator`` pipeline) ONLY when Dynamic
    Prioritization selects it. Until then it sits in the hypothesis
    pool, visible in Working Memory, not consuming execution budget.
    The ``status`` field tracks this lifecycle explicitly so a human
    reviewing the engagement transcript can see at a glance which
    beliefs were promoted, deferred, abandoned, or resolved.

Numerical confidence scoring (Phase 4):
    The ``confidence_score`` field (0.0-1.0) is computed by a
    deterministic weighted formula — never an LLM-emitted raw number.
    See :func:`webpent.shared.confidence.compute_confidence_score` for
    the formula. The score is informational-only for prioritization;
    it does NOT replace the categorical ``Confidence`` /
    ``confidence_level`` tiering on :class:`Finding`, which is
    load-bearing for reporting and the PoC-or-GTFO validation pipeline.

Persistence:
    The structured-hypotheses SQLite table follows the same
    ``CREATE TABLE IF NOT EXISTS`` + manager-class pattern already used
    for ``findings`` and the legacy ``hypotheses`` table. See
    :class:`webpent.memory.lessons.LessonsManager.save_structured_hypothesis`.
"""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any
from uuid import UUID, uuid4

from pydantic import BaseModel, ConfigDict, Field, field_validator

from webpent.models.findings import VulnClass


class HypothesisStatus(str, Enum):
    """Lifecycle states for a :class:`Hypothesis`.

    The state machine is intentionally simple and one-way-per-branch:

        unexplored -> investigating -> promoted -> resolved_true
                                                -> resolved_false
                                                -> abandoned

    A hypothesis that gets promoted to a :class:`Finding` and later
    debunked by Devil's Advocate does NOT transition back to
    ``unexplored`` — the audit trail keeps it as ``promoted`` so a
    reviewer can see "we promoted this, tested it, and it didn't hold
    up." The downstream :class:`Finding` carries its own
    ``confidence_level`` lifecycle separately.
    """

    UNEXPLORED = "unexplored"
    INVESTIGATING = "investigating"
    PROMOTED = "promoted"
    ABANDONED = "abandoned"
    RESOLVED_TRUE = "resolved_true"
    RESOLVED_FALSE = "resolved_false"
    LEARNED = "learned"


class HypothesisOrigin(str, Enum):
    """Where a hypothesis came from.

    Used by the Decision Log and by Dynamic Prioritization to weight
    historical-lesson-informed hypotheses differently from pure
    heuristic ones. Mirrors the existing pattern of explicit
    provenance tracking already established by ``Finding.tool_name``.
    """

    HEURISTIC = "heuristic"          # hypothesis_analyzer_node regex match
    RAG_INFORMED = "rag_informed"    # heuristic + historical-lesson retrieval contributed
    RABBIT_HOLE = "rabbit_hole"      # spawned by a Rabbit Hole branch (Phase 7)
    CROSS_REASONS = "cross_reasons"  # proposed by cross_reasoning narrative synthesis
    HUMAN = "human"                  # operator-supplied (e.g. via API or CLI)
    # RUNTIME-INTEGRATION FIX (RIT-5): DeepReconEngine producer output.
    # Deterministic recon-derived surface hypotheses ingested through the
    # normal hypothesis path (same promotion gates, same validator routing).
    DEEP_RECON = "deep_recon"        # DeepReconEngine route/schema observation
    # UM-DR-31 (evidence-driven adaptive research loop): the research-loop
    # origins. Deterministic, evidence-backed producers inside
    # production/adaptive_research.py — an ORDINARY hypothesis citizen
    # (same strategist ranking, same promotion gates, same authorized
    # execution path; never a finding, never a confirmation).
    COVERAGE_GAP = "coverage_gap"    # open coverage-ledger cell (observed, untested)
    INVARIANT = "invariant"          # invariant-review candidate or untested
                                     # workflow authorization boundary


class Hypothesis(BaseModel):
    """A single unverified belief about the target.

    Attributes:
        id: Stable UUID for cross-referencing across the Decision Log,
            Mental Model edges, and downstream :class:`Finding` records
            (via ``Finding.hypothesis_id``).
        target_url: The target URL / asset this hypothesis concerns.
            Mirrors ``Finding.url`` for consistency.
        statement: A short natural-language statement of the belief.
            Keep this prose, not a payload — payload-shaped strings
            should be sanitised at injection time (the same
            ``_sanitize_retrieved_lessons`` defensive wrapper already
            used by ``hypothesis_analyzer_node``).
        vuln_class: The :class:`VulnClass` this hypothesis relates to.
            Reuses the existing enum — no new taxonomy. ``UNKNOWN`` is
            valid for hypotheses that don't fit a known class (e.g.
            "this admin panel looks interesting").
        status: Lifecycle state. See :class:`HypothesisStatus`.
        confidence_score: Numeric confidence (0.0-1.0). Computed by a
            deterministic weighted formula — NEVER an LLM-emitted raw
            number. Informational-only for prioritization; does not
            replace the categorical tiers on :class:`Finding`.
        evidence_refs: References to supporting evidence — finding IDs
            and/or Mental Model node IDs. A hypothesis may have zero
            evidence refs when first created (pure heuristic) and
            accumulate them as the engagement progresses.
        origin: Where this hypothesis came from. See
            :class:`HypothesisOrigin`.
        origin_detail: Free-form additional provenance — e.g. which
            regex pattern fired, which Decision Log entry created it,
            which historical lesson retrieval contributed.
        estimated_cost: Estimated cost-to-investigate, used by Dynamic
            Prioritization. A small deterministic lookup-table value
            (Phase 6 Cost-vs-Value component); ``None`` means "not yet
            estimated."
        parent_hypothesis_id: Reference to the parent hypothesis when
            this hypothesis is itself the product of following a
            rabbit hole (Phase 7). ``None`` for top-level hypotheses.
            This is what makes the chain of "why did we end up here"
            traceable.
        created_at: UTC timestamp of creation.
        updated_at: UTC timestamp of last status change. Updated
            whenever ``status`` transitions.
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
    target_url: str = Field(
        ...,
        description="The target URL / asset this hypothesis concerns.",
    )
    statement: str = Field(
        ...,
        min_length=3,
        max_length=500,
        description="Short natural-language statement of the belief.",
    )
    vuln_class: VulnClass = Field(
        default=VulnClass.UNKNOWN,
        description=(
            "Vulnerability class this hypothesis relates to. Reuses "
            "the existing enum — no new taxonomy."
        ),
    )
    status: HypothesisStatus = Field(
        default=HypothesisStatus.UNEXPLORED,
        description="Lifecycle state. See HypothesisStatus.",
    )
    confidence_score: float = Field(
        default=0.3,
        ge=0.0,
        le=1.0,
        description=(
            "Numeric confidence (0.0-1.0). Deterministic weighted "
            "formula — never an LLM-emitted raw number. "
            "Informational-only for prioritization."
        ),
    )
    evidence_refs: list[str] = Field(
        default_factory=list,
        description=(
            "References to supporting evidence — finding IDs and/or "
            "Mental Model node IDs."
        ),
    )
    origin: HypothesisOrigin = Field(
        default=HypothesisOrigin.HEURISTIC,
        description="Where this hypothesis came from.",
    )
    origin_detail: str = Field(
        default="",
        description="Additional free-form provenance detail.",
    )
    estimated_cost: float | None = Field(
        default=None,
        ge=0.0,
        description=(
            "Estimated cost-to-investigate (Phase 6 Cost-vs-Value "
            "lookup). None means not yet estimated."
        ),
    )
    parent_hypothesis_id: UUID | None = Field(
        default=None,
        description=(
            "Parent hypothesis when this is the product of a Rabbit "
            "Hole branch (Phase 7). None for top-level hypotheses."
        ),
    )
    # V9 P0 Fix 2-B: set by hypothesis_analyzer_node ONLY for hypotheses
    # produced by the deterministic URL-path classifier
    # (_classify_by_url_path), never by the probabilistic heuristics.
    #
    # Root cause this exists to fix: a deterministic path match (e.g.
    # /vulnerabilities/sqli/) is ground truth from a known vuln-path
    # signature, not an uncertain belief — but it was still gated
    # behind Dynamic Prioritization's probabilistic
    # score >= PROMOTION_THRESHOLD formula. Because Mental Model
    # ENDPOINT nodes always default to LOW criticality
    # (models/mental_model.py), the formula could never clear 0.5 for
    # a path-classified hypothesis even at confidence_score=1.0 (max
    # attainable score ~0.44) — so sqlmap/dalfox never ran despite the
    # classifier working correctly. This flag lets
    # shared.prioritization.recommend_action bypass the probabilistic
    # gate for deterministic classifications specifically, without
    # touching the threshold/weights used for every other (genuinely
    # uncertain) hypothesis.
    #
    # This does NOT bypass any other safety gate: promotion still
    # requires vuln_class in EXPLOITABLE_CLASSES
    # (promote_hypothesis_to_finding), the resulting Finding still
    # goes through scope_enforcer's prior scope check (inherited via
    # target_url) and payload_generator -> execution_sandbox's
    # mandatory HITL approval before any tool actually runs.
    deterministic_match: bool = Field(
        default=False,
        description=(
            "True when this hypothesis was produced by the "
            "deterministic URL-path classifier "
            "(_classify_by_url_path), not a probabilistic heuristic. "
            "Dynamic Prioritization promotes these directly, "
            "bypassing the score >= PROMOTION_THRESHOLD gate. Still "
            "subject to the EXPLOITABLE_CLASSES gate, scope "
            "enforcement, and mandatory HITL before any tool actually runs."
        ),
    )
    # Structured request context is populated only when discovery found a
    # safe, same-origin form. It is additive and optional so old checkpoints
    # and endpoint-only hypotheses remain loadable.
    request_method: str = Field(
        default="GET",
        min_length=3,
        max_length=10,
        description="HTTP method associated with the hypothesis target.",
    )
    request_data: dict[str, Any] = Field(
        default_factory=dict,
        description=(
            "Bounded, redacted form/query/JSON fields for a later gated validator; "
            "nested JSON values are allowed, and cookies or secrets are never stored."
        ),
    )
    target_param: str | None = Field(
        default=None,
        max_length=200,
        description="Parameter selected for a tool validator, when known.",
    )
    evidence_contract: dict[str, Any] | None = Field(
        default=None,
        description=(
            "Generic proof contract containing reusable evidence primitives "
            "such as differential_response, oob_callback, timing_differential, "
            "or error_signature_match. Invalid contracts fail closed downstream."
        ),
    )
    hint_provenance: list[str] = Field(
        default_factory=list,
        description=(
            "Bounded provenance labels for the reasoning method, e.g. "
            "business_logic, memory_pattern, heuristic, or llm_intent."
        ),
    )
    novelty_score: float = Field(
        default=0.0,
        ge=0.0,
        le=1.0,
        description="Deterministic novelty signal used by dynamic prioritization.",
    )

    # -- M3 research-brain contract (CANONICAL_PHASE_REGISTRY M3, UM-DR-16) --
    # Additive OPTIONAL fields: legacy constructors and legacy checkpoints
    # stay valid (every field defaults empty/None; `extra="forbid"` keeps
    # rejecting unknown keys). They make the research contract explicit:
    # a hypothesis names its PRECONDITIONS and the control that would
    # REFUTE it, not only the claim.
    preconditions: list[str] = Field(
        default_factory=list,
        description=(
            "Observable preconditions that must hold BEFORE the hypothesis "
            "is worth probing (e.g. 'endpoint accepts POST', 'authenticated "
            "session with role X'). Empty = no known preconditions."
        ),
    )
    alternatives: list[str] = Field(
        default_factory=list,
        description=(
            "Alternative explanations for the same observation — probing "
            "should discriminate between the hypothesis and these."
        ),
    )
    expected_behavior: str = Field(
        default="",
        description=(
            "What the world looks like if the hypothesis is TRUE — the "
            "prediction the probe tests. Empty = not yet formulated."
        ),
    )
    negative_control: str = Field(
        default="",
        description=(
            "The control probe that must NOT show the effect (e.g. the "
            "same request against a randomized non-existent path). A "
            "hypothesis whose control fires is refuted, not confirmed."
        ),
    )
    info_gain: float | None = Field(
        default=None,
        ge=0.0,
        le=1.0,
        description=(
            "Deterministic expected information gain of probing this "
            "hypothesis (0..1); None = not yet scored. Informational "
            "input to prioritization — never a confirmation signal."
        ),
    )
    risk: float | None = Field(
        default=None,
        ge=0.0,
        le=1.0,
        description=(
            "Deterministic probing-risk estimate (0..1) — how invasive or "
            "state-changing the discriminating probe is. Input to the "
            "approval-tier selection, never a bypass."
        ),
    )
    created_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="UTC timestamp of creation.",
    )
    updated_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="UTC timestamp of last status change.",
    )

    # -- Validators ----------------------------------------------------------
    @field_validator("vuln_class", mode="before")
    @classmethod
    def _normalise_vuln_class(cls, v: str | VulnClass | None) -> VulnClass:
        if v is None:
            return VulnClass.UNKNOWN
        if isinstance(v, VulnClass):
            return v
        return VulnClass(str(v).lower())

    @field_validator("status", mode="before")
    @classmethod
    def _normalise_status(cls, v: str | HypothesisStatus | None) -> HypothesisStatus:
        if v is None:
            return HypothesisStatus.UNEXPLORED
        if isinstance(v, HypothesisStatus):
            return v
        return HypothesisStatus(str(v).lower())

    @field_validator("origin", mode="before")
    @classmethod
    def _normalise_origin(cls, v: str | HypothesisOrigin | None) -> HypothesisOrigin:
        if v is None:
            return HypothesisOrigin.HEURISTIC
        if isinstance(v, HypothesisOrigin):
            return v
        return HypothesisOrigin(str(v).lower())

    @field_validator("confidence_score")
    @classmethod
    def _clamp_confidence(cls, v: float) -> float:
        """Defensive clamp in case a deterministic formula drifts.

        The scoring formula's inputs (severity rank, evidence-quality
        signals, Devil's Advocate verdict) are all bounded, so a
        well-formed formula can never produce a value outside [0, 1].
        But a future contributor could add a delta without clamping —
        this validator catches that at construction time rather than
        letting a 1.05 or -0.1 leak into the prioritization sort.
        """
        if not 0.0 <= v <= 1.0:
            # Clamp rather than raise — a hypothesis with a slightly
            # out-of-range score is still usable for ranking; rejecting
            # it would discard the whole engagement's hypothesis pool.
            return max(0.0, min(1.0, v))
        return v

    @field_validator("target_url")
    @classmethod
    def _validate_target_url(cls, v: str) -> str:
        """Looser than Finding's URL validator — a hypothesis may
        concern a host or asset that is not yet a confirmed URL (e.g.
        "the host at 10.0.0.5" before we've probed it). Accept any
        non-empty string; the scope check happens later when the
        hypothesis is promoted and actually investigated.
        """
        v = v.strip()
        if not v:
            raise ValueError("Hypothesis target_url must not be empty.")
        return v

    # -- Convenience ---------------------------------------------------------
    def is_open(self) -> bool:
        """Return True if this hypothesis is still worth considering.

        ``unexplored`` and ``investigating`` are open; ``promoted``,
        ``abandoned``, ``resolved_true``, ``resolved_false``, and ``learned``
        are closed. Dynamic Prioritization only ranks open hypotheses.
        """
        return self.status in (
            HypothesisStatus.UNEXPLORED.value,
            HypothesisStatus.INVESTIGATING.value,
        )

    def to_dict_for_logging(self) -> dict[str, Any]:
        """Return a serialisable representation safe for log output.

        Mirrors :meth:`Finding`'s lack of a logging helper but follows
        the same spirit as :meth:`Target.as_dict_for_logging` — strip
        nothing, just produce a JSON-safe dict. Pydantic's
        ``model_dump(mode="json")`` already handles UUID/datetime
        serialisation correctly.
        """
        return self.model_dump(mode="json")
