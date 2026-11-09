# src/webpent/production/hypothesis_charter.py
"""The Charter §4.1 qualification gate for LLM structural hypothesis
generation (CANONICAL_PHASE_REGISTRY M3, UM-DR-16).

The charter's contract: an LLM may generate structural hypotheses and
expand its own budget ONLY after it has been MEASURED against a
deterministic baseline on a corpus with recorded ground truth, and only
while it meets the thresholds — **recall ≥ 0.5 AND precision ≥ 0.7** —
with an honest sample size. Below the gate, the LLM path stays
structurally absent; the deterministic engine remains the only
hypothesis producer.

This module is that gate. It does NOT call any LLM and does not
generate anything: it scores a producer's predictions against ground
truth and refuses (fail-closed) budget expansion otherwise. The
documented deterministic reference is the blind_v3 corpus measurement
(`reports/goed_v1_8_4/differential_v184.json` mode_a: recall 0.137,
precision 0.6667, 120 cases) — an LLM path must BEAT the deterministic
baseline to even qualify for measurement, and must clear the charter
thresholds to earn budget.

Fail-closed semantics (every refusal names its reason):

* no measurements / empty ground truth → refused;
* sample size below the corpus minimum → refused (no qualifying on a
  cherry-picked handful);
* recall or precision below its threshold → refused;
* recall not above the deterministic baseline → refused (the LLM path
  must add recall, not just re-shuffle precision);
* a verdict is required per corpus — an expired/missing measurement is
  a refusal, never a default-allow.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Iterable, Mapping

__all__ = [
    "CHARTER_MIN_PRECISION",
    "CHARTER_MIN_RECALL",
    "CHARTER_MIN_SAMPLE_SIZE",
    "DETERMINISTIC_BASELINE_PRECISION",
    "DETERMINISTIC_BASELINE_RECALL",
    "CharterVerdict",
    "charter_allows_budget_expansion",
    "evaluate_hypothesis_qualification",
]

#: Charter §4.1 thresholds — the LLM structural-hypothesis path may only
#: expand budget while it meets BOTH.
CHARTER_MIN_RECALL = 0.5
CHARTER_MIN_PRECISION = 0.7

#: An honest measurement needs a corpus, not a handful of cases.
CHARTER_MIN_SAMPLE_SIZE = 30

#: The documented deterministic reference (blind_v3, mode_a LLM-off):
#: tp=10 fp=5 fn=63 tn=42 → recall 0.137, precision 0.6667.
DETERMINISTIC_BASELINE_RECALL = 0.137
DETERMINISTIC_BASELINE_PRECISION = 0.6667


@dataclass(frozen=True)
class CharterVerdict:
    """One measured qualification verdict for one hypothesis producer."""

    producer: str
    corpus_id: str
    sample_size: int
    true_positives: int
    false_positives: int
    false_negatives: int
    recall: float
    precision: float
    measured_at: str
    qualified: bool
    reasons: tuple[str, ...] = field(default_factory=tuple)

    def as_dict(self) -> dict[str, Any]:
        return {
            "producer": self.producer,
            "corpus_id": self.corpus_id,
            "sample_size": self.sample_size,
            "true_positives": self.true_positives,
            "false_positives": self.false_positives,
            "false_negatives": self.false_negatives,
            "recall": round(self.recall, 4),
            "precision": round(self.precision, 4),
            "measured_at": self.measured_at,
            "qualified": self.qualified,
            "reasons": list(self.reasons),
        }


def _classify(
    predicted: Iterable[str], ground_truth: Mapping[str, bool]
) -> tuple[int, int, int]:
    """Count TP/FP/FN from predicted keys vs a {case_id: is_vulnerable} map."""
    predicted_set = {str(p) for p in predicted if str(p)}
    tp = fp = fn = 0
    for case_id, expected in ground_truth.items():
        hit = case_id in predicted_set
        if expected and hit:
            tp += 1
        elif expected and not hit:
            fn += 1
        elif not expected and hit:
            fp += 1
    return tp, fp, fn


def evaluate_hypothesis_qualification(
    *,
    producer: str,
    corpus_id: str,
    predicted: Iterable[str],
    ground_truth: Mapping[str, bool],
    measured_at: datetime | None = None,
) -> CharterVerdict:
    """Score one producer against ground truth and apply the charter gate.

    ``predicted`` is the iterable of case ids the producer flagged as
    vulnerable; ``ground_truth`` maps case ids to their expected
    ``is_vulnerable`` label (the blind_v3 manifest contract). The verdict
    is IMMUTABLE and names every failing reason.
    """
    ground_truth = {
        str(case_id): bool(label) for case_id, label in (ground_truth or {}).items()
    }
    tp, fp, fn = _classify(predicted or (), ground_truth)
    sample_size = len(ground_truth)
    recall = (tp / (tp + fn)) if (tp + fn) else 0.0
    precision = (tp / (tp + fp)) if (tp + fp) else 0.0

    reasons: list[str] = []
    if sample_size == 0:
        reasons.append("empty_ground_truth:no_corpus_to_qualify_on")
    if 0 < sample_size < CHARTER_MIN_SAMPLE_SIZE:
        reasons.append(
            f"sample_size_below_minimum:{sample_size}<{CHARTER_MIN_SAMPLE_SIZE}"
        )
    if sample_size and recall < CHARTER_MIN_RECALL:
        reasons.append(f"recall_below_threshold:{recall:.4f}<{CHARTER_MIN_RECALL}")
    if sample_size and precision < CHARTER_MIN_PRECISION:
        reasons.append(
            f"precision_below_threshold:{precision:.4f}<{CHARTER_MIN_PRECISION}"
        )
    if sample_size and recall <= DETERMINISTIC_BASELINE_RECALL:
        reasons.append(
            "recall_not_above_deterministic_baseline:"
            f"{recall:.4f}<={DETERMINISTIC_BASELINE_RECALL}"
        )

    stamp = (measured_at or datetime.now(timezone.utc)).isoformat()
    return CharterVerdict(
        producer=producer,
        corpus_id=corpus_id,
        sample_size=sample_size,
        true_positives=tp,
        false_positives=fp,
        false_negatives=fn,
        recall=recall,
        precision=precision,
        measured_at=stamp,
        qualified=not reasons,
        reasons=tuple(reasons),
    )


def charter_allows_budget_expansion(
    verdict: CharterVerdict | None,
    *,
    now: datetime | None = None,
) -> tuple[bool, str]:
    """The fail-closed budget decision.

    The LLM hypothesis path may expand its budget ONLY on a CURRENT,
    QUALIFIED verdict. ``None`` (never measured), a stale measurement
    (older than the freshness window), and any unqualified verdict all
    refuse with the reason — the deterministic engine stays the only
    hypothesis producer until the charter says otherwise.
    """
    if verdict is None:
        return False, "charter:no_measurement:the_LLM_path_was_never_qualified"

    freshness_hours = 24 * 7
    try:
        measured = datetime.fromisoformat(verdict.measured_at)
    except ValueError:
        return False, "charter:unparsable_measurement_timestamp"
    if measured.tzinfo is None:
        measured = measured.replace(tzinfo=timezone.utc)
    current = now or datetime.now(timezone.utc)
    if current.tzinfo is None:
        current = current.replace(tzinfo=timezone.utc)
    age_hours = (current - measured).total_seconds() / 3600.0
    if age_hours > freshness_hours:
        return (
            False,
            f"charter:stale_measurement:{age_hours:.1f}h>{freshness_hours}h",
        )

    if not verdict.qualified:
        return False, "charter:unqualified:" + ",".join(verdict.reasons)
    return True, "charter:qualified"
