# src/webpent/benchmark/ground_truth.py
"""Target ground truth for live benchmarks (PROPOSALS_ULTIMATE_V2 §8, 2026-10-30).

A ground-truth file declares, per LOCAL benchmark target, the known
vulnerabilities (class + endpoint) the framework is expected to find.
The scoreboard engine (benchmark/scoreboard.py) scores a campaign run
strictly against this declaration: a finding counts only when its
(class, endpoint) pair matches a declared vuln exactly — near-miss
class names or different endpoints are false positives, not detections.

Fail-closed: a ground-truth file that is unreadable, invalid JSON, or
violates the schema is a hard refusal — silently benchmarking against
an empty expectation list would report perfect precision on nothing.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

__all__ = [
    "GROUND_TRUTH_SCHEMA_VERSION",
    "GroundTruthError",
    "GroundTruthVuln",
    "TargetGroundTruth",
    "load_ground_truth",
]

GROUND_TRUTH_SCHEMA_VERSION = 1


class GroundTruthError(ValueError):
    """Raised when a ground-truth file cannot be loaded fail-closed."""


@dataclass(frozen=True)
class GroundTruthVuln:
    """One declared known vulnerability: class + endpoint, both exact."""

    vuln_class: str
    endpoint: str
    notes: str = ""

    def as_dict(self) -> dict[str, str]:
        out = {"vuln_class": self.vuln_class, "endpoint": self.endpoint}
        if self.notes:
            out["notes"] = self.notes
        return out


@dataclass(frozen=True)
class TargetGroundTruth:
    """The declared universe of known vulns for one local target."""

    target: str
    vulns: "tuple[GroundTruthVuln, ...]"
    schema_version: int = GROUND_TRUTH_SCHEMA_VERSION

    def as_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "target": self.target,
            "vulns": [v.as_dict() for v in self.vulns],
        }


def _require(cond: bool, msg: str) -> None:
    if not cond:
        raise GroundTruthError(msg)


def load_ground_truth(path: str | Path) -> TargetGroundTruth:
    """Load and validate a ground-truth JSON file; fail-closed on any defect."""
    try:
        raw = Path(path).read_text(encoding="utf-8")
    except OSError as exc:
        raise GroundTruthError(f"ground_truth_unreadable: {exc}") from exc
    try:
        doc = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise GroundTruthError(f"ground_truth_invalid_json: {exc}") from exc
    _require(isinstance(doc, dict), "ground_truth_schema: top level must be an object")
    assert isinstance(doc, dict)

    version = doc.get("schema_version", GROUND_TRUTH_SCHEMA_VERSION)
    _require(
        version == GROUND_TRUTH_SCHEMA_VERSION,
        f"ground_truth_schema: unsupported schema_version {version!r}",
    )
    target = doc.get("target")
    _require(
        isinstance(target, str) and target.strip(),
        "ground_truth_schema: 'target' must be a non-empty string",
    )
    vulns_raw = doc.get("vulns")
    _require(
        isinstance(vulns_raw, list),
        "ground_truth_schema: 'vulns' must be a list",
    )
    vulns: list[GroundTruthVuln] = []
    for i, item in enumerate(vulns_raw):
        _require(
            isinstance(item, dict),
            f"ground_truth_schema: vulns[{i}] must be an object",
        )
        cls = item.get("vuln_class")
        endpoint = item.get("endpoint")
        _require(
            isinstance(cls, str) and cls.strip(),
            f"ground_truth_schema: vulns[{i}].vuln_class must be a non-empty string",
        )
        _require(
            isinstance(endpoint, str) and endpoint.strip(),
            f"ground_truth_schema: vulns[{i}].endpoint must be a non-empty string",
        )
        notes = item.get("notes", "")
        _require(
            isinstance(notes, str),
            f"ground_truth_schema: vulns[{i}].notes must be a string",
        )
        vulns.append(
            GroundTruthVuln(
                vuln_class=cls.strip(),
                endpoint=endpoint.strip(),
                notes=notes.strip(),
            )
        )
    return TargetGroundTruth(
        target=target.strip(),  # type: ignore[arg-type]
        vulns=tuple(vulns),
        schema_version=GROUND_TRUTH_SCHEMA_VERSION,
    )
