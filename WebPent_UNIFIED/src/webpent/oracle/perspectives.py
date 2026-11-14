"""THE ORACLE — U-ORACLE-8, the Multi-Perspective Analyzer (v88).

Six lenses over the same passive evidence (ORACLE-L-7): attacker,
defender, business impact, compliance, engineer, researcher. Every lens
reads only what the aggregator already gathered and never requests
anything itself (ORACLE-L-1/L-2). Perspectives, weights and observation
triggers live in config/oracle/perspectives.yaml; nothing is invented
in code (ORACLE-L-11).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from webpent.oracle.models import OracleLawError
from webpent.oracle.osint import OsintReport

KNOWN_CATEGORIES = {
    "credential", "data_leak", "endpoint", "subdomain", "tech",
}


@dataclass
class PerspectiveView:
    perspective_id: str
    name: str
    description: str
    observations: list[str] = field(default_factory=list)
    priority: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "perspective_id": self.perspective_id,
            "name": self.name,
            "description": self.description,
            "observations": list(self.observations),
            "priority": round(self.priority, 3),
        }


def _validate_perspective(raw: Any, index: int) -> dict:
    if not isinstance(raw, dict):
        raise OracleLawError(f"perspective #{index} must be a mapping")
    for key in ("perspective_id", "name", "description", "weights",
                "triggers"):
        if key not in raw:
            raise OracleLawError(
                f"perspective {raw.get('perspective_id', index)} missing "
                f"{key!r}"
            )
    for category, weight in dict(raw["weights"]).items():
        if category not in KNOWN_CATEGORIES:
            raise OracleLawError(
                f"{raw['perspective_id']}: unknown category {category!r}"
            )
        if not 0.0 <= float(weight) <= 1.0:
            raise OracleLawError(
                f"{raw['perspective_id']}: weight for {category} must be "
                f"within [0, 1]"
            )
    for trigger in raw["triggers"]:
        if trigger.get("category") not in KNOWN_CATEGORIES:
            raise OracleLawError(
                f"{raw['perspective_id']}: trigger category "
                f"{trigger.get('category')!r} is unknown"
            )
        if not trigger.get("observation"):
            raise OracleLawError(
                f"{raw['perspective_id']}: a trigger has no observation"
            )
    return raw


class PerspectiveAnalyzer:
    EXPECTED_PERSPECTIVES = 6

    def __init__(self, perspectives_path: Path) -> None:
        data = yaml.safe_load(
            Path(perspectives_path).read_text(encoding="utf-8")
        ) or {}
        raw_perspectives = data.get("perspectives")
        if not raw_perspectives or not isinstance(raw_perspectives, list):
            raise OracleLawError(
                "perspectives.yaml missing a non-empty 'perspectives' list"
            )
        self._perspectives = [
            _validate_perspective(raw, i)
            for i, raw in enumerate(raw_perspectives)
        ]

    # -- public surface ----------------------------------------------------------

    def analyze(self, report: OsintReport) -> list[PerspectiveView]:
        by_category: dict[str, list[float]] = {}
        for finding in report.findings:
            by_category.setdefault(finding.category, []).append(
                finding.confidence
            )
        views: list[PerspectiveView] = []
        for perspective in self._perspectives:
            weights = {
                k: float(v) for k, v in perspective["weights"].items()
            }
            observations: list[str] = []
            priority = 0.0
            for trigger in perspective["triggers"]:
                category = trigger["category"]
                confidences = by_category.get(category)
                if not confidences:
                    continue
                peak = max(confidences)
                observations.append(
                    f"{trigger['observation']} "
                    f"({len(confidences)} finding(s), peak confidence "
                    f"{peak:.2f})"
                )
                priority += weights.get(category, 0.0) * peak
            views.append(
                PerspectiveView(
                    perspective_id=perspective["perspective_id"],
                    name=perspective["name"],
                    description=perspective["description"],
                    observations=observations,
                    priority=round(priority, 4),
                )
            )
        views.sort(key=lambda v: (-v.priority, v.perspective_id))
        return views


__all__ = ["PerspectiveAnalyzer", "PerspectiveView"]
