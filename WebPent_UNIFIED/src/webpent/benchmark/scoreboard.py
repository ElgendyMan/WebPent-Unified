# src/webpent/benchmark/scoreboard.py
"""Benchmark scoreboard engine (PROPOSALS_ULTIMATE_V2 §8, 2026-10-30).

Scores a benchmark campaign run strictly against a TargetGroundTruth
declaration and emits a versioned ``benchmark_scoreboard.json``:
detection rate per vulnerability class, solve time, and token cost.
The scoreboard is byte-deterministic (no wall-clock timestamps, no
random identifiers inside the payload) so successive versions can be
diffed and regressions flagged: ANY class whose detection rate drops
between two versions is a regression attributable to the change that
produced the newer board.

Matching is strict: a finding counts toward a declared vuln only when
BOTH its class AND endpoint match exactly. A matching class at an
undeclared endpoint, or a declared class never matched, is scored
honestly — detections, false positives, and misses are separate
counts, never collapsed into one flattering number.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping, Sequence

from webpent.benchmark.ground_truth import TargetGroundTruth

__all__ = [
    "SCOREBOARD_SCHEMA_VERSION",
    "PredictedFinding",
    "ScoreboardError",
    "build_scoreboard",
    "compare_scoreboards",
    "load_scoreboard",
    "write_scoreboard",
]

SCOREBOARD_SCHEMA_VERSION = 1


class ScoreboardError(ValueError):
    """Raised on a fail-closed scoreboard schema violation."""


@dataclass(frozen=True)
class PredictedFinding:
    """One finding a benchmark campaign claims on the target."""

    vuln_class: str
    endpoint: str
    evidence: str = ""


def _rate(detected: int, expected: int) -> float:
    return (detected / expected) if expected else 0.0


def build_scoreboard(
    ground_truth: TargetGroundTruth,
    findings: Sequence[PredictedFinding],
    *,
    elapsed_seconds: float,
    llm_tokens: int,
) -> dict[str, Any]:
    """Score ``findings`` against ``ground_truth`` into a versioned board.

    Detection = an exact (vuln_class, endpoint) match with a declared
    vuln; each declared vuln is counted once. Leftover findings are
    false positives and are listed (class + endpoint) so a regression
    can be traced to what the run invented.
    """
    declared = [(v.vuln_class, v.endpoint) for v in ground_truth.vulns]
    declared_set = set(declared)
    matched: set[tuple[str, str]] = set()
    false_positives: list[dict[str, str]] = []
    for f in findings:
        pair = (f.vuln_class, f.endpoint)
        if pair in declared_set:
            matched.add(pair)
        else:
            false_positives.append(
                {"vuln_class": f.vuln_class, "endpoint": f.endpoint}
            )

    classes: dict[str, dict[str, Any]] = {}
    for vuln_class in sorted({c for c, _ in declared}):
        cls_pairs = {e for c, e in declared if c == vuln_class}
        cls_matched = {e for c, e in matched if c == vuln_class}
        classes[vuln_class] = {
            "expected_count": len(cls_pairs),
            "detected_count": len(cls_matched),
            "detection_rate": round(_rate(len(cls_matched), len(cls_pairs)), 4),
            "missed_endpoints": sorted(cls_pairs - cls_matched),
        }

    overall_expected = len(declared_set)
    overall_detected = len(matched)
    return {
        "schema_version": SCOREBOARD_SCHEMA_VERSION,
        "target": ground_truth.target,
        "classes": classes,
        "overall": {
            "expected_count": overall_expected,
            "detected_count": overall_detected,
            "detection_rate": round(
                _rate(overall_detected, overall_expected), 4
            ),
            "false_positive_count": len(false_positives),
            "false_positives": false_positives,
            "elapsed_seconds": round(float(elapsed_seconds), 3),
            "llm_tokens": int(llm_tokens),
        },
    }


def compare_scoreboards(
    previous: Mapping[str, Any],
    current: Mapping[str, Any],
) -> dict[str, Any]:
    """Diff two scoreboard versions; flag every per-class rate drop.

    Fail-closed on schema mismatch: comparing boards of different
    schema versions (or a non-board payload) raises rather than
    silently reporting a clean diff.
    """
    for label, board in (("previous", previous), ("current", current)):
        if board.get("schema_version") != SCOREBOARD_SCHEMA_VERSION:
            raise ScoreboardError(
                f"scoreboard_compare_schema: {label} board has "
                f"schema_version {board.get('schema_version')!r}, expected "
                f"{SCOREBOARD_SCHEMA_VERSION}"
            )
    prev_classes = previous.get("classes", {})
    curr_classes = current.get("classes", {})
    regressions: list[dict[str, Any]] = []
    class_deltas: dict[str, float] = {}
    for cls in sorted(set(prev_classes) | set(curr_classes)):
        prev_rate = float(prev_classes.get(cls, {}).get("detection_rate", 0.0))
        curr_rate = float(curr_classes.get(cls, {}).get("detection_rate", 0.0))
        delta = round(curr_rate - prev_rate, 4)
        class_deltas[cls] = delta
        if delta < 0:
            regressions.append(
                {
                    "vuln_class": cls,
                    "previous_rate": prev_rate,
                    "current_rate": curr_rate,
                    "delta": delta,
                }
            )
    prev_overall = float(
        previous.get("overall", {}).get("detection_rate", 0.0)
    )
    curr_overall = float(current.get("overall", {}).get("detection_rate", 0.0))
    return {
        "class_deltas": class_deltas,
        "regressions": regressions,
        "has_regressions": bool(regressions),
        "overall_delta": round(curr_overall - prev_overall, 4),
    }


def write_scoreboard(path: str | Path, board: Mapping[str, Any]) -> None:
    """Write a scoreboard JSON file (stable key order, indent=2)."""
    Path(path).write_text(
        json.dumps(board, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )


def load_scoreboard(path: str | Path) -> dict[str, Any]:
    """Load a scoreboard JSON file; fail-closed on schema-version mismatch."""
    try:
        doc = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ScoreboardError(f"scoreboard_unreadable: {exc}") from exc
    if (
        not isinstance(doc, dict)
        or doc.get("schema_version") != SCOREBOARD_SCHEMA_VERSION
    ):
        raise ScoreboardError(
            f"scoreboard_schema: not a v{SCOREBOARD_SCHEMA_VERSION} scoreboard"
        )
    return doc
