"""THE PRISM — U-PRISM-11, the Brain Integration (v89).

Bidirectional, advisory-only wiring between the Prism and the Brain:
Brain → signal → Prism → enriched signal → Brain, Brain → finding →
Prism → validated finding → Brain, Brain → prior → Prism → adjusted
prior → Brain. The Prism never blocks a finding (PRISM-L-2): it only
raises or lowers priority and attaches evidence. Overrides are the
Brain's prerogative and require a written justification (PRISM-L-1).
No circular feedback: every call returns new objects and never mutates
its inputs (PRISM-L-9).
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass, field
from typing import Any

from webpent.prism.errors import PrismLawError
from webpent.prism.ledger import CampaignLedger
from webpent.prism.priors import PriorAdjuster, PriorAdjustment
from webpent.prism.scorer import EvidenceScorer
from webpent.prism.taxonomy import EvidenceProfile, EvidenceTaxonomy
from webpent.prism.tiering import MultiSignalIntegrator
from webpent.prism.value_weighter import (
    Signal,
    SignalWeight,
    ValueWeighter,
    WeightingContext,
)

ADVISORY_MODE = "advisory-only (PRISM-L-2)"


@dataclass(frozen=True)
class Finding:
    finding_id: str
    title: str
    anomaly_type: str
    profiles: tuple[EvidenceProfile, ...]
    baseline: float = 0.5


@dataclass(frozen=True)
class EnrichedSignal:
    signal_id: str
    weight: SignalWeight
    passed_through: bool = True   # the Prism never blocks a signal
    mode: str = ADVISORY_MODE


@dataclass(frozen=True)
class ValidatedFinding:
    finding_id: str
    verdict: str
    integrated_score: float
    reasons: tuple[str, ...]
    blocked: bool = False         # structurally impossible (PRISM-L-2)
    mode: str = ADVISORY_MODE


@dataclass(frozen=True)
class BrainState:
    priors: dict[str, float]
    context: dict[str, Any] = field(default_factory=dict)
    justifications: dict[str, str] = field(default_factory=dict)
    history: tuple[str, ...] = ()

    def with_override(self, key: str, value: float,
                      justification: str) -> BrainState:
        """A Brain override is always allowed — but never silently."""
        if not justification or not justification.strip():
            raise PrismLawError(
                "an override without a justification is a law breach "
                "(PRISM-L-1); state the reason",
                law="PRISM-L-1",
            )
        clamped = min(1.0, max(0.0, float(value)))
        return BrainState(
            priors={**self.priors, key: clamped},
            context=dict(self.context),
            justifications={**self.justifications, key: justification},
            history=self.history
            + (f"override {key} -> {clamped:.3f}: {justification}",),
        )


class PrismIntegration:
    """Bidirectional, advisory-only Brain wiring (U-PRISM-11)."""

    def __init__(self, taxonomy: EvidenceTaxonomy,
                 scorer: EvidenceScorer,
                 integrator: MultiSignalIntegrator,
                 weighter: ValueWeighter,
                 adjuster: PriorAdjuster,
                 ledger: CampaignLedger | None = None) -> None:
        self._taxonomy = taxonomy
        self._scorer = scorer
        self._integrator = integrator
        self._weighter = weighter
        self._adjuster = adjuster
        self._ledger = ledger

    # -- brain → prism -------------------------------------------------------------

    def enrich_signal(self, signal: Signal,
                      context: WeightingContext) -> EnrichedSignal:
        weight = self._weighter.weight(signal, context)
        return EnrichedSignal(signal_id=signal.signal_id, weight=weight)

    def validate_finding(self, finding: Finding) -> ValidatedFinding:
        if not finding.profiles:
            # Refusal must not crash the caller's round (PRISM-L-2: the
            # Prism never blocks a finding; "amplifier failure never
            # breaks a round"). The refusal is returned, not raised.
            return ValidatedFinding(
                finding_id=finding.finding_id,
                verdict="refused",
                integrated_score=0.0,
                reasons=(
                    "no EvidenceProfile on the finding: it cannot enter "
                    "Prism until it is scored (PRISM-L-4); finding "
                    "passes through unvalidated",
                ),
            )
        pairs = [
            (profile, self._scorer.score(profile))
            for profile in finding.profiles
        ]
        integration = self._integrator.integrate(pairs)
        reasons = (
            f"integrated_score={integration.integrated_score:.3f}",
            f"verdict={integration.verdict}",
            integration.mode,
        )
        return ValidatedFinding(
            finding_id=finding.finding_id,
            verdict=integration.verdict,
            integrated_score=integration.integrated_score,
            reasons=reasons,
        )

    # -- prism → brain ----------------------------------------------------------------

    def apply_priors(self, state: BrainState,
                     patterns: Sequence[Any]) -> BrainState:
        """Adjust the Brain's priors with learned, capped, reasoned deltas.

        Returns a NEW BrainState; the input is never mutated (no
        circular feedback). Patterns that do not profile-match the
        state's technique keys are skipped, not forced.
        """
        priors = dict(state.priors)
        history = list(state.history)
        # PRISM-L-9: the result must not depend on the caller's list
        # order. Canonical ordering by stable keys makes the sequential
        # (capped) deltas order-invariant for the same input set.
        ordered = sorted(
            patterns,
            key=lambda p: (
                getattr(p, "pattern_type", ""),
                getattr(p, "key", ""),
                getattr(p, "pattern_id", ""),
            ),
        )
        for pattern in ordered:
            key = getattr(pattern, "key", None)
            pattern_type = getattr(pattern, "pattern_type", "")
            if pattern_type != "technique_effectiveness" or key not in priors:
                continue
            adjustment = self._adjuster.adjust(
                priors[key], pattern, {"technique": key}
            )
            priors[key] = adjustment.adjusted
            history.append(
                f"prior {key}: {adjustment.delta:+.3f} "
                f"({pattern.reason}; {ADVISORY_MODE})"
            )
        return BrainState(
            priors=priors,
            context=dict(state.context),
            justifications=dict(state.justifications),
            history=tuple(history),
        )

    def record_outcome(self, finding: Finding, outcome: str,
                       campaign_id: str, notes: str = "") -> list[str]:
        """Feed a Brain outcome back into the campaign ledger."""
        if self._ledger is None:
            raise PrismLawError(
                "no ledger attached to this integration; outcomes "
                "cannot be recorded silently (PRISM-L-4)",
                law="PRISM-L-4",
            )
        if not finding.profiles:
            # Nothing is recorded for an unscored finding — recording an
            # outcome without evidence would be the real silent failure.
            # Refusal is returned (empty list), not raised: the caller's
            # round must not break on amplifier refusal (PRISM-L-2).
            return []
        recorded: list[str] = []
        outcome_id = ""
        for profile in finding.profiles:
            score = self._scorer.score(profile)
            evidence_id = self._ledger.record_evidence(
                campaign_id, profile, score
            )
            recorded.append(evidence_id)
            outcome_id = self._ledger.record_outcome(
                campaign_id, evidence_id, outcome, notes=notes
            )
            recorded.append(outcome_id)
        return recorded


__all__ = [
    "ADVISORY_MODE", "BrainState", "EnrichedSignal", "Finding",
    "PrismIntegration", "PriorAdjustment", "ValidatedFinding",
]
