"""webpent.brain.lesson_emission — end-of-engagement lesson emission.

Learning-loop activation (2026-10-24, Proposal 1, Phase 3). Closes the
loop between an engagement's outcomes and the next engagement's
prioritisation: the confirmed-vs-false-positive record of a finished
engagement, per vulnerability-class family, is converted into
``scope="run"`` lessons (auto-approved by the ledger's existing gate) and
written through to the ledger's persistent store.

This module is deliberately NOT part of the frozen manifest: it is a new,
additive advisory module that only READS engagement outcome counts and
WRITES to the Lessons Ledger. It never touches findings, never sends
requests, and never promotes anything. ``brain/scorecard.py`` stays
untouched — :func:`lessons_from_scorecard_emission` consumes a
:class:`webpent.brain.scorecard.ScorecardEmission` (or an equivalent
summary) from the outside.

Determinism: lesson ids, statements, confidence values and polarity
markers are pure functions of the inputs, so re-emitting the same
engagement summary is an idempotent upsert, never a duplicate.
"""
from __future__ import annotations

from typing import Any

from webpent.brain.lessons import Lesson, LessonsLedger


def lesson_from_family_outcomes(
    *,
    family: str,
    confirmed: int,
    false_positives: int,
    run_number: int = 0,
    cycle: int = 0,
    lab: str = "",
) -> Lesson:
    """Build one deterministic ``scope="run"`` lesson for one family.

    The statement embeds the family name (so the ledger's existing
    substring retrieval ``family.lower() in statement.lower()`` matches
    it), the outcome counts, and the run/cycle context. Confidence is the
    family's precision (confirmed / (confirmed + false positives)); a
    precision below 0.5 marks the lesson negative via
    ``outcome_feedback=["negative"]`` so :func:`compute_lesson_adjustment`
    treats it as a penalty instead of a bonus.
    """
    total = max(0, int(confirmed)) + max(0, int(false_positives))
    precision = (max(0, int(confirmed)) / total) if total > 0 else 0.0
    prefix = f"run-{run_number}" + (f"-cycle-{cycle}" if cycle else "")
    location = f"[{lab}] " if lab else ""
    statement = (
        f"{location}{family}: confirmed={max(0, int(confirmed))} "
        f"false_positive={max(0, int(false_positives))} "
        f"(precision={precision:.3f}) at {prefix}"
    )
    negative = total > 0 and precision < 0.5
    return Lesson(
        lesson_id=f"L-{prefix}-{family}",
        scope="run",
        statement=statement,
        confidence=round(precision, 4) if total > 0 else 0.5,
        proposed_by="scorecard",
        outcome_feedback=["negative"] if negative else [],
    )


def emit_run_lessons(
    ledger: LessonsLedger,
    *,
    confirmed_by_family: dict[str, int],
    false_positives_by_family: dict[str, int],
    run_number: int = 0,
    cycle: int = 0,
    lab: str = "",
) -> list[Lesson]:
    """Emit one run-scoped lesson per family seen in the engagement.

    Accepts two plain dicts mapping vulnerability-class family strings to
    counts (confirmed findings and false positives respectively). Only
    families appearing in EITHER dict get a lesson — a family with no
    outcomes at all teaches nothing. Returns the recorded (auto-approved)
    lessons in deterministic family order.
    """
    families = sorted(
        set(str(k) for k in confirmed_by_family)
        | set(str(k) for k in false_positives_by_family)
    )
    recorded: list[Lesson] = []
    for family in families:
        lesson = lesson_from_family_outcomes(
            family=family,
            confirmed=int(confirmed_by_family.get(family, 0)),
            false_positives=int(false_positives_by_family.get(family, 0)),
            run_number=run_number,
            cycle=cycle,
            lab=lab,
        )
        recorded.append(ledger.record_lesson(lesson))
    return recorded


def lessons_from_scorecard_emission(
    ledger: LessonsLedger,
    emission: Any,
    *,
    run_number: int = 0,
    confirmed_by_family: dict[str, int] | None = None,
    false_positives_by_family: dict[str, int] | None = None,
    confirmed_total: int | None = None,
    false_positives_total: int | None = None,
) -> list[Lesson]:
    """Bridge from a :class:`ScorecardEmission` to run-scoped lessons.

    The scorecard's emission keeps honesty data inside its ``honesty``
    summary dict (``false_positives``) rather than as direct attributes,
    and a findings count is not always derivable from it — so the caller
    supplies what it actually knows:

      * family breakdowns (``confirmed_by_family`` /
        ``false_positives_by_family``) win when given — one lesson per
        family seen;
      * otherwise a single aggregate lesson is emitted from
        ``confirmed_total`` plus the emission's honesty-derived false
        positive count (or ``false_positives_total`` override), under
        the family-agnostic ``"engagement"`` key — the run still leaves
        a trace without inventing per-family attribution it was not
        given;
      * with nothing known, nothing is emitted (no empty lesson).
    """
    families = sorted(
        set(str(k) for k in (confirmed_by_family or {}))
        | set(str(k) for k in (false_positives_by_family or {}))
    )
    lab = str(getattr(emission, "lab", "") or "")
    cycle = int(getattr(emission, "cycle", 0) or 0)
    if families:
        return emit_run_lessons(
            ledger,
            confirmed_by_family=dict(confirmed_by_family or {}),
            false_positives_by_family=dict(false_positives_by_family or {}),
            run_number=run_number,
            cycle=cycle,
            lab=lab,
        )
    if confirmed_total is None or int(confirmed_total) <= 0:
        honesty = getattr(emission, "honesty", None)
        emission_fps = int(honesty.get("false_positives", 0) or 0) if isinstance(honesty, dict) else 0
        fps = int(false_positives_total or 0) or emission_fps
        if fps <= 0:
            return []
        return emit_run_lessons(
            ledger,
            confirmed_by_family={"engagement": 0},
            false_positives_by_family={"engagement": fps},
            run_number=run_number,
            cycle=cycle,
            lab=lab,
        )
    honesty = getattr(emission, "honesty", None)
    emission_fps = int(honesty.get("false_positives", 0) or 0) if isinstance(honesty, dict) else 0
    fps = int(false_positives_total or 0) or emission_fps
    return emit_run_lessons(
        ledger,
        confirmed_by_family={"engagement": int(confirmed_total)},
        false_positives_by_family={"engagement": fps},
        run_number=run_number,
        cycle=cycle,
        lab=lab,
    )


__all__ = [
    "lesson_from_family_outcomes",
    "emit_run_lessons",
    "lessons_from_scorecard_emission",
]
