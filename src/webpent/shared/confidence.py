# src/webpent/shared/confidence.py
"""webpent.shared.confidence

V7 Cognitive Upgrade — Phase 4: Confidence Scoring.

Gives beliefs a real number (0.0-1.0) instead of the three categorical
buckets (``Confidence.TENTATIVE/FIRM/CONFIRMED``) and the four
``confidence_level`` tiers (``Tool-Confirmed/AI-Assessed/Needs Human
Review/Pending``) that :class:`Finding` already carries.

Design principles (per Phase 4 spec):

  * **Deterministic weighted formula** — base score from evidence type
    (heuristic match vs. tool-confirmed vs. LLM-assessed), plus/minus
    deltas from Online Learning events (Phase 6 batch), plus a bonus
    if Devil's Advocate's per-finding critique came back "plausible"
    rather than "debunked."
  * **Never LLM-emitted raw numbers.** The LLM can contribute
    qualitative signal (e.g., Devil's Advocate's verdict), but the
    score itself is computed by Python arithmetic over those signals
    — consistent with "no LLM deciding critical values alone."
  * **Do NOT touch or replace** ``Finding.confidence`` or
    ``Finding.confidence_level``. Those categorical tiers are
    load-bearing for reporting, compliance tagging, and the existing
    PoC-or-GTFO validation pipeline. The new numeric score is an
    *additional*, informational field used purely for prioritization
    and Rabbit Hole gating (via :mod:`webpent.shared.prioritization`)
    — never substituted for the tool-confirmation tiering that
    already exists for a good reason.

Inputs to the formula:

  * ``evidence_type`` — one of ``"heuristic"``, ``"tool_confirmed"``,
    ``"llm_assessed"``, ``"rag_informed"``. Each has a deterministic
    base score (see :data:`_BASE_SCORE_BY_EVIDENCE_TYPE`).
  * ``online_learning_deltas`` — a list of fixed deterministic deltas
    (Phase 6 Online Learning component). Each delta is a small float
    like ``+0.3`` ("tool-confirmed evidence found for a related
    hypothesis") or ``-0.4`` ("Devil's Advocate debunked a related
    finding"). Deliberately fixed deltas, not a Bayesian engine —
    auditable, debuggable, consistent with "no LLM deciding critical
    security-relevant values."
  * ``devils_advocate_verdict`` — one of ``"plausible"``,
    ``"debunked"``, ``"unclear"``, or ``None`` (not yet critiqued).
    ``"plausible"`` adds a small bonus; ``"debunked"`` subtracts a
    larger penalty; ``"unclear"`` and ``None`` are neutral.

The formula clamps to [0, 1] before returning. The output is suitable
for direct assignment to :attr:`Hypothesis.confidence_score` or to
:attr:`Finding.strategic_confidence_score` (the informational-only
field added to :class:`Finding` in Phase 4 step 3).
"""

from __future__ import annotations

import logging
from enum import Enum
from typing import Any

logger = logging.getLogger(__name__)


class EvidenceType(str, Enum):
    """Closed set of evidence types that feed the confidence formula.

    Each type maps to a deterministic base score in
    :data:`_BASE_SCORE_BY_EVIDENCE_TYPE`. The closed set is deliberate
    — adding a new evidence type is a code change, not an LLM output.
    """

    HEURISTIC = "heuristic"  # Regex/heuristic match only — no tool, no LLM
    RAG_INFORMED = "rag_informed"  # Heuristic + historical-lesson retrieval matched
    LLM_ASSESSED = "llm_assessed"  # LLM evaluated but no tool confirmed
    TOOL_CONFIRMED = "tool_confirmed"  # A deterministic tool confirmed the belief


class DevilsAdvocateVerdict(str, Enum):
    """Devil's Advocate per-finding critique verdict.

    Mirrors the existing verdicts ``devils_advocate_node`` already
    produces — this enum just names them so the confidence formula
    can apply deterministic deltas. ``None`` (Python None, not an
    enum member) means "not yet critiqued" and is treated as neutral.
    """

    PLAUSIBLE = "plausible"  # Critique did not debunk — small bonus
    DEBUNKED = "debunked"  # Critique debunked — larger penalty
    UNCLEAR = "unclear"  # Critique was inconclusive — neutral


# ---------------------------------------------------------------------------
# Deterministic formula constants
# ---------------------------------------------------------------------------
# Phase 4 step 2: "base score from evidence type (heuristic match vs.
# tool-confirmed vs. LLM-assessed)". The base scores below are the
# deterministic starting point. They are constants — changing one is
# a code change, reviewable in the diff, auditable in the Decision Log.
#
# Calibration rationale:
#   * HEURISTIC = 0.30 — a regex match is weak evidence; the belief
#     might be wrong (the regex matched a parameter name, but the
#     parameter might not actually be vulnerable).
#   * RAG_INFORMED = 0.40 — a historical lesson retrieval matched,
#     which is weak positive evidence the belief is plausible (a
#     similar target was vulnerable in the same way before).
#   * LLM_ASSESSED = 0.55 — an LLM evaluated the belief and did not
#     debunk it. Stronger than heuristic-only, weaker than tool-
#     confirmed (LLMs hallucinate; tools don't).
#   * TOOL_CONFIRMED = 0.85 — a deterministic tool confirmed the
#     belief. This is the strongest evidence type short of a human
#     reviewer signing off (which would be 1.0, reserved for
#     explicitly human-confirmed findings).
_BASE_SCORE_BY_EVIDENCE_TYPE: dict[str, float] = {
    EvidenceType.HEURISTIC.value: 0.30,
    EvidenceType.RAG_INFORMED.value: 0.40,
    EvidenceType.LLM_ASSESSED.value: 0.55,
    EvidenceType.TOOL_CONFIRMED.value: 0.85,
}

# Phase 4 step 2: "plus a bonus if Devil's Advocate's per-finding
# critique came back 'plausible' rather than 'debunked'." The bonus
# is small (a plausible-but-not-confirmed critique shouldn't move
# the needle as much as a tool confirmation); the penalty is larger
# (a debunking is strong negative evidence the belief is wrong).
_DEVILS_ADVOCATE_BONUS: float = 0.05  # PLAUSIBLE -> +0.05
_DEVILS_ADVOCATE_PENALTY: float = -0.15  # DEBUNKED -> -0.15

# Phase 4 step 2: "plus/minus deltas from Online Learning events
# (Phase 6 batch)". These are the fixed deterministic deltas the
# Phase 6 Online Learning component will emit. The values are
# deliberately small so a single Online Learning event can't flip a
# hypothesis from low to high confidence on its own — confidence
# shifts gradually as evidence accumulates, which is the auditability
# property the plan calls for.
_ONLINE_LEARNING_DELTA_POSITIVE: float = 0.10  # e.g. tool-confirmed related evidence
_ONLINE_LEARNING_DELTA_NEGATIVE: float = -0.10  # e.g. related finding debunked

# Hard caps on cumulative Online Learning deltas. Even if many
# positive events fire, the cumulative delta can't push the score
# above this cap — prevents runaway confidence inflation from a
# noisy evidence stream. Symmetric for negative deltas.
_ONLINE_LEARNING_DELTA_CAP_POSITIVE: float = 0.30
_ONLINE_LEARNING_DELTA_CAP_NEGATIVE: float = -0.30

# Final clamp bounds — the score MUST be in [0, 1].
_SCORE_MIN: float = 0.0
_SCORE_MAX: float = 1.0


def compute_confidence_score(
    *,
    evidence_type: EvidenceType | str,
    online_learning_deltas: list[float] | None = None,
    devils_advocate_verdict: DevilsAdvocateVerdict | str | None = None,
    evidence_signals: dict[str, Any] | None = None,
) -> float:
    """Compute a deterministic confidence score in [0, 1].

    Phase 4 step 2 + step 4: the score is computed by Python
    arithmetic over the inputs — NEVER an LLM-emitted raw number.
    The LLM can contribute qualitative signal (e.g., Devil's
    Advocate's verdict), but the score itself is deterministic.

    Args:
        evidence_type: The :class:`EvidenceType` (or its string
            value). Determines the base score from
            :data:`_BASE_SCORE_BY_EVIDENCE_TYPE`.
        online_learning_deltas: Optional list of fixed deterministic
            deltas from Phase 6's Online Learning component. Each
            delta is a small float (typically +0.10 or -0.10). The
            cumulative sum is capped at
            ``_ONLINE_LEARNING_DELTA_CAP_POSITIVE`` /
            ``_ONLINE_LEARNING_DELTA_CAP_NEGATIVE`` to prevent
            runaway confidence inflation/deflation.
        devils_advocate_verdict: Optional
            :class:`DevilsAdvocateVerdict` (or its string value, or
            ``None`` for "not yet critiqued"). ``PLAUSIBLE`` adds
            :data:`_DEVILS_ADVOCATE_BONUS`; ``DEBUNKED`` adds
            :data:`_DEVILS_ADVOCATE_PENALTY`; ``UNCLEAR`` and
            ``None`` are neutral.

    Returns:
        A float in [0, 1]. The formula is:

            base = _BASE_SCORE_BY_EVIDENCE_TYPE[evidence_type]
            ol_delta = clamp(sum(online_learning_deltas),
                             -0.30, +0.30)
            da_delta = _DEVILS_ADVOCATE_BONUS  if PLAUSIBLE
                       _DEVILS_ADVOCATE_PENALTY if DEBUNKED
                       0.0                       otherwise
            score = clamp(base + ol_delta + da_delta, 0.0, 1.0)
    """
    # Normalise evidence_type to its string value.
    if isinstance(evidence_type, EvidenceType):
        et_str = evidence_type.value
    else:
        et_str = str(evidence_type).lower()
    base = _BASE_SCORE_BY_EVIDENCE_TYPE.get(
        et_str, _BASE_SCORE_BY_EVIDENCE_TYPE[EvidenceType.HEURISTIC.value]
    )

    # Online Learning deltas — sum + cap.
    ol_sum = 0.0
    for delta in online_learning_deltas or []:
        try:
            d = float(delta)
        except (TypeError, ValueError):
            continue
        # Sign-validate: a delta outside the expected range is
        # clamped to the cap rather than rejected — defensive, so
        # a misbehaving Phase 6 caller can't blow up the formula.
        if d > 0:
            ol_sum += min(d, _ONLINE_LEARNING_DELTA_POSITIVE)
        elif d < 0:
            ol_sum += max(d, _ONLINE_LEARNING_DELTA_NEGATIVE)
    ol_sum = max(
        _ONLINE_LEARNING_DELTA_CAP_NEGATIVE,
        min(_ONLINE_LEARNING_DELTA_CAP_POSITIVE, ol_sum),
    )

    # Optional structured evidence signals. These are deliberately bounded
    # and additive; omitting the mapping preserves the legacy formula exactly.
    structured_delta = 0.0
    signals = evidence_signals or {}

    def _bounded_signal(name: str) -> float | None:
        value = signals.get(name)
        if value is None:
            return None
        try:
            return max(0.0, min(1.0, float(value)))
        except (TypeError, ValueError):
            return None

    source_quality = _bounded_signal("source_quality")
    reproducibility = _bounded_signal("reproducibility")
    identity_certainty = _bounded_signal("identity_certainty")
    oracle_strength = _bounded_signal("oracle_strength")
    for signal in (
        source_quality,
        reproducibility,
        identity_certainty,
        oracle_strength,
    ):
        if signal is not None:
            structured_delta += (signal - 0.5) * 0.10

    negative_control = signals.get("negative_control")
    if negative_control is True:
        structured_delta += 0.05
    elif negative_control is False:
        structured_delta -= 0.15

    if signals.get("deterministic_match") is True:
        structured_delta += 0.15

    contradictory = _bounded_signal("contradictory_evidence")
    if contradictory is not None:
        structured_delta -= contradictory * 0.15

    validator_status = str(signals.get("validator_status") or "").lower()
    if validator_status in {"validated", "reproducible"}:
        structured_delta += 0.05
    elif validator_status in {"rejected", "debunked"}:
        structured_delta -= 0.20

    # Keep all optional signals bounded so one malformed or over-complete
    # evidence record cannot dominate the deterministic evidence type.
    structured_delta = max(-0.30, min(0.30, structured_delta))

    # Devil's Advocate verdict delta.
    da_delta = 0.0
    if devils_advocate_verdict is not None:
        if isinstance(devils_advocate_verdict, DevilsAdvocateVerdict):
            dav_str = devils_advocate_verdict.value
        else:
            dav_str = str(devils_advocate_verdict).lower()
        if dav_str == DevilsAdvocateVerdict.PLAUSIBLE.value:
            da_delta = _DEVILS_ADVOCATE_BONUS
        elif dav_str == DevilsAdvocateVerdict.DEBUNKED.value:
            da_delta = _DEVILS_ADVOCATE_PENALTY
        # UNCLEAR and anything else -> neutral (0.0)

    raw = base + ol_sum + structured_delta + da_delta
    score = max(_SCORE_MIN, min(_SCORE_MAX, raw))
    return score


def evidence_type_from_origin(origin: Any) -> EvidenceType:
    """Map a :class:`HypothesisOrigin` to its :class:`EvidenceType`.

    Convenience helper so callers don't have to maintain the mapping
    themselves. ``HEURISTIC`` origin -> ``HEURISTIC`` evidence type;
    ``RAG_INFORMED`` -> ``RAG_INFORMED``; ``RABBIT_HOLE`` and
    ``CROSS_REASONS`` -> ``LLM_ASSESSED`` (both involve LLM judgment
    at some point); ``HUMAN`` -> ``TOOL_CONFIRMED`` (a human-supplied
    hypothesis is treated as the strongest non-tool evidence type,
    since the human is presumably authorising the investigation).
    """
    # Lazy import to avoid a circular dependency at module load time.
    from webpent.models.hypothesis import HypothesisOrigin

    origin_str = origin.value if hasattr(origin, "value") else str(origin).lower()
    mapping = {
        HypothesisOrigin.HEURISTIC.value: EvidenceType.HEURISTIC,
        HypothesisOrigin.RAG_INFORMED.value: EvidenceType.RAG_INFORMED,
        HypothesisOrigin.RABBIT_HOLE.value: EvidenceType.LLM_ASSESSED,
        HypothesisOrigin.CROSS_REASONS.value: EvidenceType.LLM_ASSESSED,
        HypothesisOrigin.HUMAN.value: EvidenceType.TOOL_CONFIRMED,
        # RIT-5: DeepReconEngine output is deterministic recon observation —
        # same evidence tier as HEURISTIC (never tool-confirmed by origin).
        HypothesisOrigin.DEEP_RECON.value: EvidenceType.HEURISTIC,
    }
    return mapping.get(origin_str, EvidenceType.HEURISTIC)


def compute_initial_hypothesis_confidence(
    origin: Any,
    *,
    source_kind: str = "heuristic",
    deterministic_match: bool = False,
) -> float:
    """Compute a bounded initial hypothesis score from observable signals.

    This construction helper never confirms a finding and never bypasses
    validator, causal-signal, negative-control, or proof gates.
    """
    evidence_type = evidence_type_from_origin(origin)
    deltas: list[float] = []
    if source_kind in {"endpoint_input", "post_form"}:
        deltas.extend([0.10, 0.10])
    if deterministic_match:
        deltas.append(0.10)
    if evidence_type.value == EvidenceType.RAG_INFORMED.value:
        deltas.append(0.10)
    return compute_confidence_score(
        evidence_type=evidence_type,
        online_learning_deltas=deltas,
        evidence_signals={
            "deterministic_match": deterministic_match,
            "source_quality": 1.0 if source_kind != "heuristic" else 0.5,
        },
    )


def recompute_hypothesis_confidence(
    hypothesis: Any,
    *,
    online_learning_deltas: list[float] | None = None,
    devils_advocate_verdict: DevilsAdvocateVerdict | str | None = None,
    evidence_signals: dict[str, Any] | None = None,
) -> float:
    """Recompute a Hypothesis's confidence_score from its origin + new signals.

    Convenience helper that pulls ``evidence_type`` from the
    hypothesis's ``origin`` field (via :func:`evidence_type_from_origin`)
    and applies the supplied Online Learning deltas + Devil's Advocate
    verdict. Returns the new score (does NOT mutate the hypothesis —
    the caller assigns it via ``hypothesis.confidence_score = ...`` or
    ``hypothesis.model_copy(update={"confidence_score": ...})``).

    Args:
        hypothesis: A :class:`Hypothesis` instance (typed as Any to
            avoid a circular import with webpent.models.hypothesis).
        online_learning_deltas: See :func:`compute_confidence_score`.
        devils_advocate_verdict: See :func:`compute_confidence_score`.

    Returns:
        A float in [0, 1] suitable for assignment to
        ``hypothesis.confidence_score``.
    """
    evidence_type = evidence_type_from_origin(getattr(hypothesis, "origin", None))
    return compute_confidence_score(
        evidence_type=evidence_type,
        online_learning_deltas=online_learning_deltas,
        devils_advocate_verdict=devils_advocate_verdict,
        evidence_signals=evidence_signals,
    )
