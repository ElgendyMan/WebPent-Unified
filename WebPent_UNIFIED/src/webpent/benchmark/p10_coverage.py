"""Strict P10 coverage and oracle readiness contracts.

The module is pure and does not contact Juice Shop or execute probes. It keeps
planned coverage separate from executable coverage so a draft matrix cannot be
mistaken for live benchmark evidence.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class CoverageCase:
    case_id: str
    category: str
    challenge_key: str
    workflow_id: str
    oracle_id: str
    mapping_status: str
    oracle_status: str
    safe_to_execute: bool

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any]) -> CoverageCase:
        return cls(
            case_id=str(value.get("case_id") or "").strip(),
            category=str(value.get("category") or "").strip(),
            challenge_key=str(value.get("challenge_key") or "").strip(),
            workflow_id=str(value.get("workflow_id") or "").strip(),
            oracle_id=str(value.get("oracle_id") or "").strip(),
            mapping_status=str(value.get("mapping_status") or "").strip(),
            oracle_status=str(value.get("oracle_status") or "").strip(),
            safe_to_execute=bool(value.get("safe_to_execute", False)),
        )

    @property
    def executable(self) -> bool:
        return (
            bool(self.case_id)
            and bool(self.workflow_id)
            and bool(self.oracle_id)
            and self.mapping_status == "approved"
            and self.oracle_status == "ready"
            and self.safe_to_execute
        )


def validate_coverage(
    cases: Sequence[CoverageCase],
    *,
    minimum_cases: int = 10,
    minimum_classes: int = 6,
) -> dict[str, Any]:
    """Return a fail-closed coverage summary without target I/O."""
    reasons: list[str] = []
    case_ids = [case.case_id for case in cases]
    if not case_ids or len(set(case_ids)) != len(case_ids):
        reasons.append("case_ids_not_unique_or_missing")
    executable = [case for case in cases if case.executable]
    executable_classes = {case.category.lower() for case in executable if case.category}
    mapped = [case for case in cases if case.mapping_status == "approved"]
    ready_oracles = [case for case in cases if case.oracle_status == "ready"]
    if len(mapped) < minimum_cases:
        reasons.append("approved_case_mapping_below_minimum")
    if len(executable_classes) < minimum_classes:
        reasons.append("executable_class_coverage_below_minimum")
    if len(ready_oracles) < minimum_cases:
        reasons.append("ready_oracle_count_below_minimum")
    return {
        "coverage_passed": not reasons,
        "blocking_reasons": sorted(set(reasons)),
        "planned_case_count": len(cases),
        "approved_case_count": len(mapped),
        "ready_oracle_count": len(ready_oracles),
        "executable_case_count": len(executable),
        "executable_class_count": len(executable_classes),
        "planned_classes": sorted({case.category.lower() for case in cases if case.category}),
        "executable_classes": sorted(executable_classes),
    }


__all__ = ["CoverageCase", "validate_coverage"]
