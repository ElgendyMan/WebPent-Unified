"""webpent.qualification.metrics — M11 (Part 4 §13): per-family metrics.

Registry scope: "per-family metrics (TP/FP/FN/TN, precision/recall/F1,
calibration, coverage, confirmed-per-target, time-to-first,
cost-per-confirmed, requests-per-finding, reproducibility, inconclusive
rate, scope-rejection rate, human-intervention rate, crash/recovery)"
and acceptance: "no aggregate score without per-family detail and
sample size".

The structural rule: :class:`BenchmarkReportV2` REFUSES to carry an
aggregate unless the per-family table is present and every family row
carries its sample size. The aggregate is computed FROM the family
rows, never beside them.
"""

from __future__ import annotations

from typing import Any, Iterable, Mapping

from pydantic import BaseModel, ConfigDict, Field, model_validator

__all__ = [
    "BenchmarkReportV2",
    "FamilyMetrics",
    "compute_family_metrics",
]


class FamilyMetrics(BaseModel):
    """One family's measured metrics with its sample size."""

    model_config = ConfigDict(extra="forbid")

    family: str = Field(min_length=1, max_length=80)
    sample_size: int = Field(ge=0)
    true_positives: int = Field(default=0, ge=0)
    false_positives: int = Field(default=0, ge=0)
    false_negatives: int = Field(default=0, ge=0)
    true_negatives: int = Field(default=0, ge=0)
    precision: float = Field(default=0.0, ge=0.0, le=1.0)
    recall: float = Field(default=0.0, ge=0.0, le=1.0)
    f1: float = Field(default=0.0, ge=0.0, le=1.0)
    confirmed: int = Field(default=0, ge=0)
    inconclusive_rate: float = Field(default=0.0, ge=0.0, le=1.0)
    scope_rejection_rate: float = Field(default=0.0, ge=0.0, le=1.0)
    human_intervention_rate: float = Field(default=0.0, ge=0.0, le=1.0)
    crash_count: int = Field(default=0, ge=0)
    reproducibility: float = Field(default=0.0, ge=0.0, le=1.0)
    time_to_first_ms: float = Field(default=0.0, ge=0.0)
    cost_per_confirmed_usd: float = Field(default=0.0, ge=0.0)
    requests_per_finding: float = Field(default=0.0, ge=0.0)

    @property
    def defined_sample(self) -> bool:
        return self.sample_size > 0


def compute_family_metrics(
    family: str, observations: Iterable[Mapping[str, Any]]
) -> FamilyMetrics:
    """Compute one family's metrics from per-case observations.

    Each observation: ``ground_truth`` (bool), ``predicted`` (bool),
    plus optional operational fields (``inconclusive``, ``scope_rejected``,
    ``human_intervention``, ``crashed``, ``reproducible``,
    ``time_to_first_ms``, ``cost_usd``, ``requests``).
    """
    tp = fp = fn = tn = 0
    inconclusive = scope_rejected = human = crashed = 0
    reproducible = 0
    reproducible_eligible = 0
    times: list[float] = []
    costs: list[float] = []
    requests: list[float] = []
    confirmed = 0

    for observation in observations:
        expected = bool(observation.get("ground_truth"))
        predicted = bool(observation.get("predicted"))
        if expected and predicted:
            tp += 1
            confirmed += 1
        elif expected and not predicted:
            fn += 1
        elif not expected and predicted:
            fp += 1
        else:
            tn += 1
        if observation.get("inconclusive"):
            inconclusive += 1
        if observation.get("scope_rejected"):
            scope_rejected += 1
        if observation.get("human_intervention"):
            human += 1
        if observation.get("crashed"):
            crashed += 1
        if observation.get("reproducible") is not None:
            reproducible_eligible += 1
            if observation.get("reproducible"):
                reproducible += 1
        if observation.get("time_to_first_ms") is not None:
            times.append(float(observation["time_to_first_ms"]))
        if observation.get("cost_usd") is not None:
            costs.append(float(observation["cost_usd"]))
        if observation.get("requests") is not None:
            requests.append(float(observation["requests"]))

    sample = tp + fp + fn + tn
    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) else 0.0
    total_cost = sum(costs)
    return FamilyMetrics(
        family=family,
        sample_size=sample,
        true_positives=tp,
        false_positives=fp,
        false_negatives=fn,
        true_negatives=tn,
        precision=round(precision, 4),
        recall=round(recall, 4),
        f1=round(f1, 4),
        confirmed=confirmed,
        inconclusive_rate=round(inconclusive / sample, 4) if sample else 0.0,
        scope_rejection_rate=round(scope_rejected / sample, 4) if sample else 0.0,
        human_intervention_rate=round(human / sample, 4) if sample else 0.0,
        crash_count=crashed,
        reproducibility=round(reproducible / reproducible_eligible, 4)
        if reproducible_eligible
        else 0.0,
        time_to_first_ms=round(min(times), 2) if times else 0.0,
        cost_per_confirmed_usd=round(total_cost / confirmed, 6) if confirmed else 0.0,
        requests_per_finding=round(sum(requests) / confirmed, 2) if confirmed else 0.0,
    )


class BenchmarkReportV2(BaseModel):
    """A benchmark report: per-family rows FIRST, aggregate derived.

    Structural acceptance rule: ``aggregate`` cannot be set unless
    ``family_metrics`` is non-empty and every row carries a positive
    sample size. There is no aggregate score without per-family detail
    and sample size.
    """

    model_config = ConfigDict(extra="forbid")

    report_id: str = Field(min_length=3, max_length=120)
    dataset_name: str = Field(min_length=1, max_length=120)
    dataset_version: str = Field(min_length=1, max_length=40)
    dataset_commit: str = Field(default="", max_length=80)
    dataset_seed: str = Field(default="", max_length=80)
    ground_truth_ref: str = Field(min_length=1, max_length=240)
    executed_at: str = Field(min_length=4, max_length=60)
    family_metrics: list[FamilyMetrics] = Field(min_length=1)
    aggregate: dict[str, Any] = Field(default_factory=dict)
    notes: list[str] = Field(default_factory=list, max_length=50)

    @model_validator(mode="after")
    def _aggregate_requires_families(self) -> "BenchmarkReportV2":
        if not self.family_metrics:
            raise ValueError("per-family metrics are mandatory — no family rows, no report")
        for row in self.family_metrics:
            if row.sample_size <= 0:
                raise ValueError(
                    f"family {row.family!r} carries sample_size=0 — "
                    "per-family detail without sample size is forbidden"
                )
        return self

    def compute_aggregate(self) -> dict[str, Any]:
        """The pooled aggregate, computed FROM the family rows."""
        tp = sum(r.true_positives for r in self.family_metrics)
        fp = sum(r.false_positives for r in self.family_metrics)
        fn = sum(r.false_negatives for r in self.family_metrics)
        tn = sum(r.true_negatives for r in self.family_metrics)
        sample = tp + fp + fn + tn
        precision = tp / (tp + fp) if (tp + fp) else 0.0
        recall = tp / (tp + fn) if (tp + fn) else 0.0
        self.aggregate = {
            "sample_size": sample,
            "precision": round(precision, 4),
            "recall": round(recall, 4),
            "f1": round(
                2 * precision * recall / (precision + recall)
                if (precision + recall)
                else 0.0,
                4,
            ),
            "families_reported": len(self.family_metrics),
            "derived_from_family_rows": True,
        }
        return self.aggregate
