"""Research Intelligence Scorecard for ABHIE v6.

This module scores recorded research capability contracts, not real-world
vulnerability detection.  Missing evidence remains missing and never becomes a
false negative or a clean result.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any


def _load(path: Path) -> dict[str, Any]:
    with path.open(encoding="utf-8") as handle:
        value = json.load(handle)
    if not isinstance(value, dict):
        raise ValueError("benchmark_artifact_must_be_object")
    return value


def score_report(path: Path) -> dict[str, Any]:
    benchmark = _load(path)
    classes = benchmark.get("classes", [])
    scorable = [
        case
        for item in classes
        if isinstance(item, dict)
        for case in item.get("cases", [])
        if isinstance(case, dict) and case.get("scorable") is True
    ]
    intelligence = benchmark.get("metrics", {}).get("research_intelligence", {})
    dimensions = {
        key: intelligence.get(key)
        for key in (
            "discovery_depth",
            "reasoning_quality",
            "evidence_strength",
            "research_efficiency",
            "strategy_improvement",
            "coverage_growth",
        )
    }
    return {
        "scorecard_id": "ABHIE-v6-research-intelligence-scorecard-v1",
        "benchmark_artifact": str(path),
        "basis": "recorded_research_capability_contracts_only",
        "registered_classes": int(benchmark.get("metrics", {}).get("registered_class_count", 0)),
        "scorable_classes": int(benchmark.get("metrics", {}).get("scorable_class_count", 0)),
        "blocked_classes": int(benchmark.get("metrics", {}).get("blocked_class_count", 0)),
        "scorable_cases": len(scorable),
        "dimensions": dimensions,
        "execution_integrity": benchmark.get("execution", {}),
        "production_detection": {
            "available": False,
            "precision": None,
            "recall": None,
            "f1": None,
            "real_world_detection_rate": None,
            "reason": "no approved multi-run ground-truth denominator",
        },
        "interpretation": {
            "blocked_excluded_from_metrics": True,
            "missing_evidence_is_not_false_negative": True,
            "hardcoded_detection": False,
            "qualification_effect": False,
            "advisory_only": True,
        },
        "governance": benchmark.get("governance", {}),
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--benchmark", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    report = score_report(args.benchmark)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    print(json.dumps(report, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())


__all__ = ["score_report"]
