"""webpent.qualification.labels — M11 (Part 4 §13): qualification labels.

Registry scope: "qualification labels (``unit-tested`` →
``production-qualified``)" and acceptance: "results support the
declared qualification level".

The ladder (fail-closed, evidence-named):

* ``unqualified`` — nothing or contradictory evidence.
* ``unit_tested`` — the component has tests and they pass (a test
  count and a green run are the evidence).
* ``lab_qualified`` — unit_tested PLUS a measured benchmark report
  with per-family metrics + sample sizes on a recorded dataset, and
  reproducibility recorded.
* ``production_qualified`` — lab_qualified PLUS a blind-set result,
  a deception-benchmark pass (0 false positives), and — for any
  LLM-involved producer — a passing Charter §4.1 verdict.

``evaluate_qualification_label`` never grants a label the evidence
does not support, and every refusal names the missing evidence.
"""

from __future__ import annotations

from enum import Enum
from typing import Any, Mapping

from pydantic import BaseModel, ConfigDict, Field

__all__ = [
    "QualificationLabel",
    "QualificationVerdict",
    "evaluate_qualification_label",
]


class QualificationLabel(str, Enum):
    UNQUALIFIED = "unqualified"
    UNIT_TESTED = "unit_tested"
    LAB_QUALIFIED = "lab_qualified"
    PRODUCTION_QUALIFIED = "production_qualified"


class QualificationVerdict(BaseModel):
    """One component's label with the supporting and missing evidence."""

    model_config = ConfigDict(extra="forbid")

    component: str = Field(min_length=1, max_length=120)
    label: QualificationLabel
    reasons: list[str] = Field(default_factory=list, max_length=20)
    missing: list[str] = Field(default_factory=list, max_length=20)

    def as_dict(self) -> dict[str, Any]:
        return {
            "component": self.component,
            "label": self.label.value,
            "reasons": list(self.reasons),
            "missing": list(self.missing),
        }


def evaluate_qualification_label(
    component: str,
    evidence: Mapping[str, Any],
) -> QualificationVerdict:
    """The fail-closed ladder. Evidence keys (all optional):

    * ``tests_passing`` (int) / ``tests_total`` (int) — unit evidence;
    * ``benchmark_report`` (Mapping) — a BenchmarkReportV2-shaped dict
      with per-family metrics + sample sizes + reproducibility;
    * ``blind_set`` (Mapping) — {fixtures, false_positives, ...};
    * ``deception_report`` (Mapping) — {false_positives, fixtures_total};
    * ``charter_verdict`` (Mapping) — the Charter §4.1 verdict dict
      (only required when ``llm_involved`` is true);
    * ``llm_involved`` (bool).
    """
    evidence = evidence if isinstance(evidence, Mapping) else {}
    reasons: list[str] = []
    missing: list[str] = []

    tests_passing = int(evidence.get("tests_passing") or 0)
    tests_total = int(evidence.get("tests_total") or 0)
    unit_ok = tests_total > 0 and tests_passing == tests_total
    if unit_ok:
        reasons.append(f"unit_tested:{tests_passing}/{tests_total} green")
    else:
        missing.append("unit_tests_green_run")

    benchmark = evidence.get("benchmark_report")
    benchmark_ok = False
    if isinstance(benchmark, Mapping):
        family_rows = benchmark.get("family_metrics")
        if (
            isinstance(family_rows, list)
            and family_rows
            and all(
                isinstance(row, Mapping)
                and int(row.get("sample_size") or 0) > 0
                for row in family_rows
            )
        ):
            reproducible = any(
                float(row.get("reproducibility") or 0.0) > 0.0 for row in family_rows
            )
            dataset = str(benchmark.get("dataset_name") or "")
            if dataset and reproducible:
                benchmark_ok = True
                reasons.append(
                    f"lab_measured:{dataset}@{benchmark.get('dataset_version')} "
                    f"({len(family_rows)} families, reproducibility recorded)"
                )
            else:
                if not dataset:
                    missing.append("benchmark_dataset_recorded")
                if not reproducible:
                    missing.append("benchmark_reproducibility_recorded")
        else:
            missing.append("benchmark_per_family_metrics_with_sample_sizes")
    else:
        missing.append("benchmark_report")

    label = QualificationLabel.UNQUALIFIED
    if unit_ok:
        label = QualificationLabel.UNIT_TESTED
    if unit_ok and benchmark_ok:
        label = QualificationLabel.LAB_QUALIFIED

    if label == QualificationLabel.LAB_QUALIFIED:
        blind = evidence.get("blind_set")
        deception = evidence.get("deception_report")
        blind_ok = (
            isinstance(blind, Mapping)
            and int(blind.get("fixtures") or 0) > 0
            and int(blind.get("false_positives") or 0) == 0
        )
        deception_ok = (
            isinstance(deception, Mapping)
            and int(deception.get("fixtures_total") or 0) > 0
            and int(deception.get("false_positives") or 0) == 0
        )
        if blind_ok:
            reasons.append(
                f"blind_set:{blind.get('fixtures')} fixtures, 0 false positives"
            )
        else:
            missing.append("blind_set_zero_false_positives")
        if deception_ok:
            reasons.append(
                f"deception_benchmark:{deception.get('fixtures_total')} fixtures, 0 FP"
            )
        else:
            missing.append("deception_benchmark_zero_false_positives")
        charter_ok = True
        if evidence.get("llm_involved"):
            charter = evidence.get("charter_verdict")
            charter_ok = isinstance(charter, Mapping) and bool(charter.get("qualified"))
            if charter_ok:
                reasons.append("charter_gate_qualified")
            else:
                missing.append("charter_gate_qualified_verdict")
        if blind_ok and deception_ok and charter_ok:
            label = QualificationLabel.PRODUCTION_QUALIFIED

    return QualificationVerdict(
        component=component, label=label, reasons=reasons, missing=missing
    )
