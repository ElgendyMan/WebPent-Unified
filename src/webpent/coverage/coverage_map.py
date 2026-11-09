"""Read-only coverage map facade over explicit campaign outcomes."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from webpent.shared.coverage_ledger import CoverageIntelligence


class CoverageMap:
    """Expose tested entries and metrics without inferring untested behavior."""

    def __init__(self, *, intelligence: CoverageIntelligence | None = None) -> None:
        self.intelligence = intelligence or CoverageIntelligence()

    def project(self, state: Mapping[str, Any]) -> dict[str, Any]:
        return self.intelligence.project(state)

    def metrics(self, state: Mapping[str, Any]) -> dict[str, Any]:
        return self.intelligence.metrics(state)

    def tested_keys(self, state: Mapping[str, Any]) -> tuple[str, ...]:
        projection = self.project(state)
        return tuple(
            str(entry["key"])
            for entry in projection.get("entries", [])
            if isinstance(entry, Mapping) and int(entry.get("attempts", 0) or 0) > 0
        )


__all__ = ["CoverageMap"]
