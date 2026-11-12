"""UM-DR-36.4 — Measured (evidence-derived) information gain.

Static priors are NOT learning. This module computes information value
from ACTUAL experiment outcomes recorded during the campaign:

  * per-outcome classification: new information, confirmation,
    refutation, contradiction, redundancy, resolution of an unresolved
    question, low-information/inconclusive;
  * measured prior overrides: when a signal class has >=
    ``MIN_SAMPLES_FOR_OVERRIDE`` measured outcomes, the measured mean
    REPLACES the static prior in ``adaptive_research`` scoring
    (prioritization ONLY — never admission, scope, budget, or
    confirmation);
  * honest accounting: an HTTP response or a successful request is NEVER
    high information gain by itself; the score derives from observable
    state deltas (new facts, evidence classes, model changes, questions
    answered).

Consumers: adaptive_research.generate_research_hypotheses (priors),
the Discovery Funnel (gain telemetry), and the AVI outcome feedback
(stage 11). No second scheduler, no second scorer: this module only
FEEDS the existing seams.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Mapping

#: Static priors measured outcomes can override (mirrors
#: adaptive_research._INFO_GAIN_PRIORS keys).
STATIC_PRIOR_KEYS: tuple[str, ...] = (
    "coverage.observed_not_tested",
    "coverage.tested_inconclusive",
    "coverage.blocked_operational",
    "invariant.authorization_context_must_be_present",
    "invariant.state_must_progress_or_reject_replay",
    "workflow.boundary.cross_identity",
    "object_scoped",
    "role_scoped",
)

#: A measured override requires at least this many observed outcomes.
MIN_SAMPLES_FOR_OVERRIDE = 3

#: Information-gain classes (UM-DR-36.4 required distinctions).
GAIN_CLASSES: tuple[str, ...] = (
    "new_information",        # facts that did not exist before the experiment
    "confirmation",           # existing fact re-observed consistently
    "refutation",             # hypothesis decisively refuted
    "contradiction",          # evidence contradicts prior observation
    "redundant",              # no new information
    "uncertainty_resolved",   # an open question was answered
    "low_information",        # inconclusive outcome
)

#: Base values per gain class (deliberately modest: a high-value experiment
#: is one that reduces IMPORTANT uncertainty, not one that returned HTTP 200).
_GAIN_CLASS_VALUES: dict[str, float] = {
    "new_information": 0.70,
    "uncertainty_resolved": 0.75,
    "contradiction": 0.65,
    "refutation": 0.55,
    "confirmation": 0.35,
    "low_information": 0.15,
    "redundant": 0.05,
}


@dataclass
class MeasuredOutcome:
    """One experiment's measured information contribution."""
    experiment_signature: str
    signal_class: str
    gain_class: str
    new_facts: int = 0
    evidence_classes: int = 0
    questions_answered: int = 0
    semantic_model_changed: bool = False
    requests_consumed: int = 0
    tokens_consumed: int = 0

    @property
    def value(self) -> float:
        base = _GAIN_CLASS_VALUES.get(self.gain_class, 0.1)
        # Observable-delta bonuses — each is evidence of real learning.
        bonus = 0.0
        bonus += min(self.new_facts, 10) * 0.01
        bonus += min(self.evidence_classes, 5) * 0.01
        bonus += min(self.questions_answered, 5) * 0.03
        if self.semantic_model_changed:
            bonus += 0.05
        return min(0.95, base + bonus)


@dataclass
class InformationGainLedger:
    """Campaign-scoped record of measured outcomes -> measured priors."""
    outcomes: list[MeasuredOutcome] = field(default_factory=list)
    _by_class: dict[str, list[MeasuredOutcome]] = field(default_factory=dict)

    def record(self, outcome: MeasuredOutcome) -> None:
        self.outcomes.append(outcome)
        self._by_class.setdefault(outcome.signal_class, []).append(outcome)

    def measured_priors(self) -> dict[str, float]:
        """Evidence-derived prior overrides (>= MIN_SAMPLES_FOR_OVERRIDE).

        Measured values REPLACE static priors for classes with enough
        samples; classes with fewer samples keep the static prior (never
        a single-sample overreaction). Returned values stay in [0, 1].
        """
        overrides: dict[str, float] = {}
        for signal_class, group in self._by_class.items():
            if len(group) < MIN_SAMPLES_FOR_OVERRIDE:
                continue
            measured = sum(o.value for o in group) / len(group)
            overrides[signal_class] = round(min(0.95, max(0.05, measured)), 4)
        return overrides

    def stats(self) -> dict[str, Any]:
        by_gain: dict[str, int] = {}
        for outcome in self.outcomes:
            by_gain[outcome.gain_class] = by_gain.get(outcome.gain_class, 0) + 1
        return {
            "recorded_outcomes": len(self.outcomes),
            "gain_class_counts": by_gain,
            "measured_prior_overrides": self.measured_priors(),
            "avg_value": (
                round(sum(o.value for o in self.outcomes) / len(self.outcomes), 4)
                if self.outcomes else None
            ),
            "total_requests": sum(o.requests_consumed for o in self.outcomes),
            "total_tokens": sum(o.tokens_consumed for o in self.outcomes),
        }


def classify_outcome(
    *,
    hypothesis_outcome: str,
    new_facts: int = 0,
    evidence_classes: int = 0,
    questions_answered: int = 0,
    semantic_model_changed: bool = False,
    contradicts_prior: bool = False,
) -> str:
    """Classify one experiment outcome into a gain class.

    ``hypothesis_outcome`` is the deterministic validation verdict
    (CONFIRMED / REFUTED / INCONCLUSIVE / promoted / rejected ...).
    The classifier is conservative: only OBSERVABLE deltas can raise the
    class above low_information.
    """
    if contradicts_prior:
        return "contradiction"
    outcome = str(hypothesis_outcome or "").upper()
    if outcome in ("REFUTED", "REJECTED", "RESOLVED_FALSE"):
        return "refutation"
    if questions_answered > 0:
        return "uncertainty_resolved"
    if new_facts > 0 or semantic_model_changed:
        return "new_information"
    if outcome in ("CONFIRMED", "PROMOTED", "RESOLVED_TRUE"):
        return "confirmation"
    if outcome in ("INCONCLUSIVE", "BLOCKED", "NONE"):
        return "low_information"
    if evidence_classes == 0 and new_facts == 0:
        return "redundant"
    return "low_information"


def ledger_from_state(state: Mapping[str, Any]) -> InformationGainLedger:
    """Rebuild the ledger from the persisted ``information_gain`` channel."""
    ledger = InformationGainLedger()
    channel = state.get("information_gain") if isinstance(state, Mapping) else None
    if isinstance(channel, Mapping):
        for record in channel.get("outcomes") or []:
            if isinstance(record, Mapping):
                try:
                    ledger.record(MeasuredOutcome(
                        experiment_signature=str(record.get("experiment_signature") or ""),
                        signal_class=str(record.get("signal_class") or ""),
                        gain_class=str(record.get("gain_class") or "low_information"),
                        new_facts=int(record.get("new_facts") or 0),
                        evidence_classes=int(record.get("evidence_classes") or 0),
                        questions_answered=int(record.get("questions_answered") or 0),
                        semantic_model_changed=bool(record.get("semantic_model_changed")),
                        requests_consumed=int(record.get("requests_consumed") or 0),
                        tokens_consumed=int(record.get("tokens_consumed") or 0),
                    ))
                except (TypeError, ValueError):
                    continue
    return ledger


def merge_measured_priors(static_priors: Mapping[str, float],
                          ledger: InformationGainLedger) -> dict[str, float]:
    """Static priors UNION measured overrides (measured wins at >=3 samples)."""
    merged = dict(static_priors)
    merged.update(ledger.measured_priors())
    return merged
