"""Strict offline classification metrics for explicitly labeled benchmark evidence."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

_ALLOWED_LABELS = frozenset({"TP", "FP", "FN", "TN"})
_REJECTED_LABELS = frozenset({"BLOCKED", "INCONCLUSIVE", "OBSERVATION_ONLY", "OUT_OF_SCOPE"})


@dataclass(frozen=True, slots=True)
class ClassificationMetricsV10:
    valid: bool
    reason: str
    true_positives: int = 0
    false_positives: int = 0
    false_negatives: int = 0
    true_negatives: int = 0
    precision: float | None = None
    recall: float | None = None
    f1: float | None = None

    def as_dict(self) -> dict[str, Any]:
        return {
            "valid": self.valid,
            "reason": self.reason,
            "true_positives": self.true_positives,
            "false_positives": self.false_positives,
            "false_negatives": self.false_negatives,
            "true_negatives": self.true_negatives,
            "precision": self.precision,
            "recall": self.recall,
            "f1": self.f1,
        }


def _invalid(reason: str) -> ClassificationMetricsV10:
    return ClassificationMetricsV10(valid=False, reason=reason)


def compute_classification_metrics(
    labels: Mapping[str, tuple[str, str]],
) -> ClassificationMetricsV10:
    """Compute metrics only from explicit expected/observed classification labels.

    Every value is ``(expected_label, observed_label)``. Any rejected or unknown
    disposition invalidates the whole calculation; it is never counted as a
    negative, clean result, or confirmed finding.
    """

    if not labels:
        return _invalid("no_labeled_cases")
    counts = dict.fromkeys(_ALLOWED_LABELS, 0)
    for case_id, pair in labels.items():
        if len(pair) != 2:
            return _invalid(f"malformed_label_pair:{case_id}")
        expected, observed = (str(value).upper() for value in pair)
        if expected in _REJECTED_LABELS or observed in _REJECTED_LABELS:
            return _invalid(f"non_scorable_disposition:{case_id}")
        if expected not in {"TP", "FN", "TN", "FP"}:
            return _invalid(f"unknown_expected_label:{case_id}")
        if observed not in {"TP", "FP", "FN", "TN"}:
            return _invalid(f"unknown_observed_label:{case_id}")
        if expected != observed:
            return _invalid(f"label_disagreement:{case_id}")
        counts[observed] += 1

    tp = counts["TP"]
    fp = counts["FP"]
    fn = counts["FN"]
    tn = counts["TN"]
    precision = tp / (tp + fp) if tp + fp else None
    recall = tp / (tp + fn) if tp + fn else None
    f1 = (
        2 * precision * recall / (precision + recall)
        if precision is not None and recall is not None and precision + recall
        else None
    )
    return ClassificationMetricsV10(
        valid=True,
        reason="explicit_ground_truth_and_observation_labels",
        true_positives=tp,
        false_positives=fp,
        false_negatives=fn,
        true_negatives=tn,
        precision=precision,
        recall=recall,
        f1=f1,
    )


__all__ = ["ClassificationMetricsV10", "compute_classification_metrics"]
