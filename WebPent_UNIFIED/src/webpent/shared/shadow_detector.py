"""webpent.shared.shadow_detector — shadow/canary testing for detection logic.

Project Zero-tier item 3: "a new detection rule runs in parallel
(silent mode) against the baseline before being switched on for real,
and its results are compared against the stable version."

Generic and detector-agnostic by design: this module does not know or
care what a "detection rule" actually detects (a WAF fingerprint, an
anomaly flag, a CVE correlation, a drift report). It only needs two
callables — ``baseline_detector`` and ``canary_detector`` — that take
the SAME input and each return a list of result dicts shaped with a
stable ``key`` field the caller chooses (e.g. a finding's dedup key,
a CVE id, a node id). Everything downstream (agreement rate, new
detections, lost detections, a GO/NO-GO recommendation) is computed
from that one required contract, so item 3 works the same way whether
the candidate rule is a new WAF signature, a new anomaly heuristic, a
new CVE correlation entry, or anything built for items 1/2/4/5/7 in
this plan.

Silent mode is structural, not a flag the caller has to remember to
set: :func:`run_shadow_comparison` never returns the canary detector's
results as the "real" result for the caller to act on — it returns a
:class:`ShadowComparisonReport` whose own fields make clear everything
from the canary side is comparison-only. A caller who wants to
actually SWITCH ON the canary detector does so themselves, using the
report's ``recommendation`` as one input to that decision — this
module never flips that switch itself.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class ShadowRecommendation(str, Enum):
    """Closed-vocabulary recommendation after a shadow comparison run."""

    PROMOTE = "promote"
    """Canary strictly improved on or matched baseline with no new
    disagreements of concern — safe to switch on for real."""

    HOLD = "hold"
    """Canary disagrees with baseline in ways that need a human look
    before promotion (new detections baseline didn't have, which may
    be welcome improvements OR false positives — can't tell from
    agreement rate alone)."""

    REJECT = "reject"
    """Canary lost detections the baseline had (regressions) without a
    compensating gain, or its disagreement rate exceeds the configured
    threshold — do not promote."""


@dataclass
class DetectionDisagreement:
    """One input on which the baseline and canary detector disagreed."""

    input_label: str
    only_in_baseline: list[str] = field(default_factory=list)
    only_in_canary: list[str] = field(default_factory=list)

    def as_dict(self) -> dict[str, Any]:
        return {
            "input_label": self.input_label,
            "only_in_baseline": self.only_in_baseline[:50],
            "only_in_canary": self.only_in_canary[:50],
        }


@dataclass
class ShadowComparisonReport:
    """Result of running a baseline and a canary detector over the
    same set of inputs, in silent mode.
    """

    total_inputs: int
    agreeing_inputs: int
    disagreeing_inputs: int
    baseline_only_keys_total: int
    canary_only_keys_total: int
    disagreements: list[DetectionDisagreement] = field(default_factory=list)
    recommendation: ShadowRecommendation = ShadowRecommendation.HOLD
    recommendation_reason: str = ""

    @property
    def agreement_rate(self) -> float:
        if self.total_inputs == 0:
            return 1.0
        return round(self.agreeing_inputs / self.total_inputs, 4)

    def as_dict(self) -> dict[str, Any]:
        return {
            "total_inputs": self.total_inputs,
            "agreeing_inputs": self.agreeing_inputs,
            "disagreeing_inputs": self.disagreeing_inputs,
            "agreement_rate": self.agreement_rate,
            "baseline_only_keys_total": self.baseline_only_keys_total,
            "canary_only_keys_total": self.canary_only_keys_total,
            "recommendation": self.recommendation.value
            if hasattr(self.recommendation, "value")
            else str(self.recommendation),
            "recommendation_reason": self.recommendation_reason,
            "disagreements": [d.as_dict() for d in self.disagreements],
        }


def extract_detection_keys(results: Any) -> set[str]:
    """Normalise a detector's per-input output into a set of string keys.

    Accepts: a list of dicts with a ``"key"`` field, a list of plain
    strings/hashables (used as their own key via ``str()``), or any
    other iterable of items coerced via ``str()``. Anything that isn't
    iterable at all (``None``, a bare non-iterable value) is treated
    as "no detections" rather than raising, since a detector legitimately
    produces no output on a clean input.
    """
    if results is None:
        return set()
    keys: set[str] = set()
    try:
        iterator = iter(results)
    except TypeError:
        return {str(results)}
    for item in iterator:
        if isinstance(item, Mapping) and "key" in item:
            keys.add(str(item["key"]))
        else:
            keys.add(str(item))
    return keys


def run_shadow_comparison(
    inputs: Sequence[tuple[str, Any]],
    *,
    baseline_detector: Callable[[Any], Any],
    canary_detector: Callable[[Any], Any],
    max_disagreement_rate_for_promote: float = 0.0,
    max_regression_rate_for_hold: float = 0.10,
) -> ShadowComparisonReport:
    """Run both detectors over every input in silent mode and compare.

    Args:
        inputs: A sequence of ``(input_label, input_value)`` pairs.
            ``input_label`` is a short, human-readable identifier for
            the disagreement report (e.g. a target URL or a case ID);
            ``input_value`` is passed as-is to both detectors.
        baseline_detector: The currently-trusted, already-promoted
            detection rule. Called once per input.
        canary_detector: The new, not-yet-promoted rule being evaluated
            in silent mode. Called once per input. Its output is NEVER
            surfaced to the caller as an actionable finding by this
            function — only compared.
        max_disagreement_rate_for_promote: The canary must disagree on
            no more than this fraction of inputs to earn PROMOTE
            (default ``0.0`` — exact agreement required; a caller
            comfortable with some noise can raise this).
        max_regression_rate_for_hold: If the canary LOSES (drops)
            baseline detections on more than this fraction of inputs,
            the recommendation is REJECT rather than HOLD — a canary
            that's quietly worse than baseline on a meaningful slice
            of inputs shouldn't just sit in "needs a human look"
            limbo, it should be flagged for rejection.

    Returns:
        A :class:`ShadowComparisonReport`. Both detector callables are
        run defensively: an exception from either detector on a given
        input is treated as "no detections" for that detector on that
        input (surfaced via a disagreement entry if the other detector
        DID produce output), rather than propagating and aborting the
        whole comparison run — a single bad input should not block
        evaluation of every other input.
    """
    total_inputs = len(inputs)
    agreeing = 0
    disagreements: list[DetectionDisagreement] = []
    baseline_only_total = 0
    canary_only_total = 0
    inputs_with_regression = 0
    inputs_with_new_detection = 0

    for input_label, input_value in inputs:
        try:
            baseline_result = baseline_detector(input_value)
        except Exception:  # noqa: BLE001 — a detector crash is "no detections"
            baseline_result = None
        try:
            canary_result = canary_detector(input_value)
        except Exception:  # noqa: BLE001
            canary_result = None

        baseline_keys = extract_detection_keys(baseline_result)
        canary_keys = extract_detection_keys(canary_result)

        if baseline_keys == canary_keys:
            agreeing += 1
            continue

        only_baseline = sorted(baseline_keys - canary_keys)
        only_canary = sorted(canary_keys - baseline_keys)
        baseline_only_total += len(only_baseline)
        canary_only_total += len(only_canary)
        if only_baseline:
            inputs_with_regression += 1
        if only_canary:
            inputs_with_new_detection += 1

        disagreements.append(
            DetectionDisagreement(
                input_label=input_label,
                only_in_baseline=only_baseline,
                only_in_canary=only_canary,
            )
        )

    disagreeing = total_inputs - agreeing
    disagreement_rate = (disagreeing / total_inputs) if total_inputs else 0.0
    regression_rate = (inputs_with_regression / total_inputs) if total_inputs else 0.0

    if disagreement_rate <= max_disagreement_rate_for_promote:
        recommendation = ShadowRecommendation.PROMOTE
        reason = (
            f"Disagreement rate {disagreement_rate:.2%} is within the "
            f"promotion threshold ({max_disagreement_rate_for_promote:.2%})."
        )
    elif regression_rate > max_regression_rate_for_hold:
        recommendation = ShadowRecommendation.REJECT
        reason = (
            f"Canary lost baseline detections on {regression_rate:.2%} of "
            f"inputs, exceeding the hold threshold "
            f"({max_regression_rate_for_hold:.2%}) — likely regression, "
            "not just noisier output."
        )
    else:
        recommendation = ShadowRecommendation.HOLD
        reason = (
            f"Disagreement rate {disagreement_rate:.2%} exceeds the "
            f"promotion threshold, but regressions "
            f"({regression_rate:.2%}) stay under the reject threshold — "
            "needs a human review of the new-detection disagreements "
            "before promoting (they may be true improvements or false "
            "positives; agreement rate alone can't distinguish the two)."
        )

    return ShadowComparisonReport(
        total_inputs=total_inputs,
        agreeing_inputs=agreeing,
        disagreeing_inputs=disagreeing,
        baseline_only_keys_total=baseline_only_total,
        canary_only_keys_total=canary_only_total,
        disagreements=disagreements,
        recommendation=recommendation,
        recommendation_reason=reason,
    )


__all__ = [
    "DetectionDisagreement",
    "ShadowComparisonReport",
    "ShadowRecommendation",
    "extract_detection_keys",
    "run_shadow_comparison",
]
