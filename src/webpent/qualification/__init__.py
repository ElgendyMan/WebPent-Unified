"""webpent.qualification — M11 (Part 4 §13): benchmarking & research
qualification.

Per-family metrics with mandatory sample sizes (no aggregate without
per-family detail — structural); the qualification-label ladder
(unit_tested → lab_qualified → production_qualified, fail-closed with
named evidence); the wired weekly benchmark runner (deception corpus +
Charter baseline replay + the operator-configured ق5 dojo
self-benchmark + the label rollup).
"""
from webpent.qualification.labels import (
    QualificationLabel,
    QualificationVerdict,
    evaluate_qualification_label,
)
from webpent.qualification.metrics import (
    BenchmarkReportV2,
    FamilyMetrics,
    compute_family_metrics,
)
from webpent.qualification.weekly import (
    latest_weekly_report,
    run_weekly_benchmarks,
    weekly_report_path,
)

__all__ = [
    "BenchmarkReportV2",
    "FamilyMetrics",
    "QualificationLabel",
    "QualificationVerdict",
    "compute_family_metrics",
    "evaluate_qualification_label",
    "latest_weekly_report",
    "run_weekly_benchmarks",
    "weekly_report_path",
]
