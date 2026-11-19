"""UM-DR-37 Part 7.1 — unified hypothesis lifecycle view.

Three status vocabularies coexist in the codebase (the main
``models.hypothesis.HypothesisStatus``, the EGAIE ``HypothesisStatus``,
and the llm_researcher interface states). This module does NOT rewrite
any state machine: it is a pure, deterministic VIEW that maps each
status onto the mission's lifecycle vocabulary

    GENERATED -> EVALUATED -> RANKED -> SELECTED -> EXECUTED
              -> SUPPORTED | REFUTED | INCONCLUSIVE | CLOSED | LEARNED

so campaign reports and readiness summaries can speak one vocabulary
while the underlying transition engines (research/hypothesis_engine.py
with its reason-evidenced one-way transitions) stay authoritative.

Where the transient stages live: EVALUATED / RANKED / SELECTED are
decision-point states — they are persisted in ``decision_log`` entries
(models/decision_log.py, written by shared/prioritization.py for every
prioritization decision), not in the hypothesis status.
"""

from __future__ import annotations

from collections import Counter
from typing import Iterable

from webpent.models.hypothesis import HypothesisStatus

# Main-model status -> mission lifecycle stage (total mapping; every
# enum value appears exactly once).
_MAIN_STATUS_TO_STAGE: dict[str, str] = {
    "unexplored": "GENERATED",
    "investigating": "EXECUTED",
    "promoted": "SUPPORTED",
    "resolved_true": "SUPPORTED",
    "resolved_false": "REFUTED",
    "abandoned": "CLOSED",
    "learned": "LEARNED",
}

# EGAIE-side status -> mission lifecycle stage.
_EGAIE_STATUS_TO_STAGE: dict[str, str] = {
    "proposed": "GENERATED",
    "supported": "SUPPORTED",
    "contradicted": "REFUTED",
    "confirmed": "SUPPORTED",
    "refuted": "REFUTED",
}


def lifecycle_stage(status: object) -> str:
    """Map any known hypothesis-status value onto the mission
    vocabulary. Unknown values raise ValueError (fail-closed — an
    unmapped status must never silently render as a stage)."""
    value = getattr(status, "value", str(status))
    for table in (_MAIN_STATUS_TO_STAGE, _EGAIE_STATUS_TO_STAGE):
        if value in table:
            return table[value]
    raise ValueError(f"unmapped hypothesis status: {value!r}")


def lifecycle_snapshot(hypotheses: Iterable[object]) -> dict:
    """Per-hypothesis stage view + stage counters for a campaign report.

    ``hypotheses`` are objects with ``id``/``hypothesis_id``,
    ``status`` and (optionally) ``vuln_class``/``statement`` — the main
    Hypothesis model, EGAIE HypothesisRecords, or plain dicts.
    """
    stages: list[dict] = []
    counter: Counter[str] = Counter()
    for hypothesis in hypotheses:
        if isinstance(hypothesis, dict):
            status = hypothesis.get("status")
            identifier = (hypothesis.get("id")
                          or hypothesis.get("hypothesis_id") or "")
            vuln_class = hypothesis.get("vuln_class", "")
        else:
            status = getattr(hypothesis, "status", None)
            identifier = str(
                getattr(hypothesis, "id",
                        getattr(hypothesis, "hypothesis_id", "")) or "")
            vuln_class = str(getattr(hypothesis, "vuln_class", "") or "")
        stage = lifecycle_stage(status)
        counter[stage] += 1
        stages.append({
            "id": identifier,
            "status": str(getattr(status, "value", status)),
            "stage": stage,
            "vuln_class": vuln_class,
        })
    return {
        "schema": "umdr37-lifecycle-view/v1",
        "vocabulary": ["GENERATED", "EVALUATED", "RANKED", "SELECTED",
                       "EXECUTED", "SUPPORTED", "REFUTED", "INCONCLUSIVE",
                       "CLOSED", "LEARNED"],
        "transient_stages_note": (
            "EVALUATED / RANKED / SELECTED are decision-point states "
            "persisted in decision_log entries, not hypothesis statuses; "
            "INCONCLUSIVE is an EGAIE decision outcome recorded on the "
            "experiment/evidence, and this view surfaces it through the "
            "experiment_outcomes channel"
        ),
        "stages": stages,
        "stage_counts": dict(sorted(counter.items())),
        "total": len(stages),
    }
