# src/webpent/models/postmortem.py
"""webpent.models.postmortem

Project Zero-tier item 6 — Postmortem structure for every mistake.

A structured, append-only record of things webpent got wrong: a
finding that was raised and then rejected (false positive), or a
vulnerability class that was present on the target but never
surfaced as a finding at all (missed/false negative). Each entry is
forced into the same fixed shape — root cause, category, fix — so
the memory layer can later be queried and aggregated ("what category
of false positive do we produce most often?") instead of accumulating
free-text war stories nobody can mine.

Distinct from, and deliberately not duplicating:

  * :class:`webpent.models.decision_log.DecisionLogEntry` — records
    *that* a decision was made (e.g. a downgrade happened) with the
    deterministic rule that fired. A Postmortem record is a *deeper*,
    retrospective analysis of *why the system was wrong in the first
    place* — root cause classification and a proposed fix, not just
    an outcome.
  * :class:`webpent.memory.lessons.LessonsManager` — free-text lessons
    extracted from write-ups / external research. Postmortems are
    specifically about webpent's *own* false positives and misses on
    *this* engagement, in a closed-vocabulary, aggregable shape.

Follows the exact same pattern as ``models/decision_log.py``: a
closed-vocabulary ``Enum`` for the category (so the audit vocabulary
stays stable and isn't an LLM free-text field), a ``BaseModel`` with
``extra="forbid"``, and a ``to_dict_for_state()`` helper for storing
inside ``PentestState``-shaped dicts.
"""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any
from uuid import UUID, uuid4

from pydantic import BaseModel, ConfigDict, Field, field_validator


class PostmortemKind(str, Enum):
    """What went wrong: a finding that shouldn't have been raised, or
    a vulnerability that should have been raised but wasn't.
    """

    FALSE_POSITIVE = "false_positive"
    MISSED_FINDING = "missed_finding"


class PostmortemCategory(str, Enum):
    """Closed set of root-cause categories (per Section 9.6 of the
    Project Zero-tier plan). Adding a new category is a code change,
    not an LLM output — keeps the audit vocabulary stable and
    aggregable (e.g. "which category causes the most false
    positives this quarter?").
    """

    # False-positive root causes.
    TOOL_MISCALIBRATION = "tool_miscalibration"
    """A scanner/tool (dalfox, sqlmap, nuclei, ...) reported a hit that
    wasn't exploitable — the tool's own heuristic was wrong."""

    CONTEXT_MISREAD = "context_misread"
    """The payload reflected/executed in a context the detector didn't
    account for (JSON vs HTML vs attribute vs comment, encoding, CSP)."""

    LLM_HALLUCINATION = "llm_hallucination"
    """An LLM-only assessment asserted something not grounded in the
    actual evidence/tool_output (ungrounded citation, invented detail)."""

    STALE_BASELINE = "stale_baseline"
    """The detector matched against an outdated signature/baseline
    (e.g. a WAF fingerprint or CVE feed entry that has since changed)."""

    ENVIRONMENTAL_NOISE = "environmental_noise"
    """A transient target-side condition (rate limiting, WAF challenge,
    flaky network) was misread as a positive signal."""

    # Missed-finding root causes.
    COVERAGE_GAP = "coverage_gap"
    """The vulnerable surface (endpoint/parameter/workflow state) was
    never exercised at all — a crawl/discovery gap, not a detection gap."""

    DETECTION_LOGIC_GAP = "detection_logic_gap"
    """The surface was exercised but the detection rule/signature for
    this vulnerability class didn't exist or didn't fire."""

    SCOPE_EXCLUSION = "scope_exclusion"
    """The vulnerable surface was deliberately out of scope or excluded
    by a scope/rate-limit guard, and the exclusion was later found to
    be too broad."""

    OTHER = "other"
    """Root cause doesn't fit the closed set above; ``root_cause_detail``
    carries the free-text explanation. Used sparingly — a category that
    is frequently ``OTHER`` is a signal the taxonomy needs a new member."""


class PostmortemRecord(BaseModel):
    """A single append-only Postmortem record.

    Attributes:
        id: Stable UUID for cross-referencing.
        timestamp: UTC timestamp the record was created.
        kind: Whether this is a false positive or a missed finding.
        category: Closed-vocabulary root-cause category.
        root_cause_detail: One or two sentences of specifics. Always
            deterministic/evidence-based prose written by the calling
            code, or — when an LLM contributed — kept separate from any
            deterministic finding in ``metadata['llm_contribution']``,
            mirroring the Decision Log's rule_fired/llm_contribution
            split.
        proposed_fix: One or two sentences describing the concrete fix
            (a detector change, a new signature, a scope adjustment).
            May be empty if no fix has been proposed yet.
        finding_id: The Finding's UUID this record is about, when the
            postmortem concerns a specific raised-then-rejected finding
            (``kind == FALSE_POSITIVE``). ``None`` for missed findings,
            which by definition never became a Finding.
        vuln_class: The vulnerability class involved, when known
            (mirrors ``Finding.vuln_class`` as a plain string so this
            model has no import-time dependency on the findings module).
        campaign_id: Optional redacted campaign identifier, mirroring
            ``Finding.campaign_id``.
        thread_id: Optional engagement/thread identifier this record
            belongs to, for scoping queries to one engagement.
        detector_name: The agent/tool/rule name responsible for the
            miss or the false positive (e.g. "dalfox", "devils_advocate",
            "waf_detector"). Empty string if not applicable/unknown.
        evidence_refs: Bounded list of evidence references (hashes,
            short labels) — never raw secrets or full HTTP bodies.
        metadata: Free-form dict for record-type-specific extras (e.g.
            ``llm_contribution``, resolved/unresolved status).
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
        description="UTC timestamp the record was created.",
    )
    kind: PostmortemKind = Field(
        ...,
        description="Whether this is a false positive or a missed finding.",
    )
    category: PostmortemCategory = Field(
        ...,
        description="Closed-vocabulary root-cause category.",
    )
    root_cause_detail: str = Field(
        default="",
        max_length=2000,
        description="One or two sentences of specifics on the root cause.",
    )
    proposed_fix: str = Field(
        default="",
        max_length=2000,
        description="Concrete fix proposal; may be empty if not yet proposed.",
    )
    finding_id: UUID | None = Field(
        default=None,
        description=(
            "The Finding's UUID, when this record concerns a specific "
            "raised-then-rejected finding. None for missed findings."
        ),
    )
    vuln_class: str | None = Field(
        default=None,
        max_length=80,
        description="The vulnerability class involved, when known.",
    )
    campaign_id: str | None = Field(
        default=None,
        max_length=160,
        description="Optional redacted campaign identifier.",
    )
    thread_id: str | None = Field(
        default=None,
        max_length=160,
        description="Optional engagement/thread identifier.",
    )
    detector_name: str = Field(
        default="",
        max_length=120,
        description="The agent/tool/rule responsible for the miss or FP.",
    )
    evidence_refs: list[str] = Field(
        default_factory=list,
        max_length=20,
        description="Bounded list of evidence references (hashes, labels).",
    )
    metadata: dict[str, Any] = Field(
        default_factory=dict,
        description="Free-form dict for record-type-specific extras.",
    )

    @field_validator("kind", mode="before")
    @classmethod
    def _normalise_kind(cls, v: str | PostmortemKind | None) -> PostmortemKind:
        if v is None:
            raise ValueError("kind cannot be None.")
        if isinstance(v, PostmortemKind):
            return v
        return PostmortemKind(str(v).lower())

    @field_validator("category", mode="before")
    @classmethod
    def _normalise_category(
        cls, v: str | PostmortemCategory | None,
    ) -> PostmortemCategory:
        if v is None:
            raise ValueError("category cannot be None.")
        if isinstance(v, PostmortemCategory):
            return v
        return PostmortemCategory(str(v).lower())

    def to_dict_for_state(self) -> dict[str, Any]:
        """Serialise to a JSON-safe dict, mirroring
        ``DecisionLogEntry.to_dict_for_state``.
        """
        return self.model_dump(mode="json")


__all__ = [
    "PostmortemCategory",
    "PostmortemKind",
    "PostmortemRecord",
]
