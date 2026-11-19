"""Typed, advisory-only contracts for the VABH final audit v10."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from enum import StrEnum
from typing import Any


class AuditStatus(StrEnum):
    PASS = "PASS"
    PARTIAL = "PARTIAL"
    BLOCKED = "BLOCKED"
    NOT_APPLICABLE = "NOT_APPLICABLE"


class ImplementationStatus(StrEnum):
    PRESENT = "PRESENT"
    PARTIAL = "PARTIAL"
    MISSING = "MISSING"
    EXTERNAL = "EXTERNAL"


@dataclass(frozen=True, slots=True)
class CapabilityAssessmentV10:
    capability: str
    status: AuditStatus
    maturity_score: float
    evidence_refs: tuple[str, ...]
    limitation: str = ""

    def __post_init__(self) -> None:
        if not 0.0 <= self.maturity_score <= 100.0:
            raise ValueError("maturity_score_must_be_bounded")
        if self.status is AuditStatus.PASS and self.limitation:
            raise ValueError("pass_assessment_cannot_hide_limitation")

    def as_dict(self) -> dict[str, Any]:
        return {
            "capability": self.capability,
            "status": self.status.value,
            "maturity_score": self.maturity_score,
            "evidence_refs": list(self.evidence_refs),
            "limitation": self.limitation,
        }


@dataclass(frozen=True, slots=True)
class GapRecordV10:
    gap_id: str
    missing_capability: str
    severity: str
    impact: str
    recommended_solution: str
    implementation_status: ImplementationStatus
    internal: bool
    evidence_refs: tuple[str, ...]

    def as_dict(self) -> dict[str, Any]:
        record = asdict(self)
        record["implementation_status"] = self.implementation_status.value
        record["evidence_refs"] = list(self.evidence_refs)
        return record


@dataclass(frozen=True, slots=True)
class ProjectStateReportV10:
    audit_version: str
    repository: str
    commit: str
    branch_parity: bool
    working_tree_clean: bool
    inventory: dict[str, int]
    capabilities: tuple[CapabilityAssessmentV10, ...]
    gaps: tuple[GapRecordV10, ...]
    technical_debt: tuple[str, ...]
    risks: tuple[str, ...]
    test_summary: dict[str, Any]
    governance: dict[str, Any]
    remaining_external_requirements: tuple[str, ...]
    readiness_percentage: float

    def __post_init__(self) -> None:
        if not 0.0 <= self.readiness_percentage <= 100.0:
            raise ValueError("readiness_percentage_must_be_bounded")
        if self.governance.get("vip_qualified", False):
            raise ValueError("audit_cannot_grant_vip_qualification")

    def as_dict(self) -> dict[str, Any]:
        return {
            "audit_version": self.audit_version,
            "repository": self.repository,
            "commit": self.commit,
            "branch_parity": self.branch_parity,
            "working_tree_clean": self.working_tree_clean,
            "inventory": dict(self.inventory),
            "capabilities": [item.as_dict() for item in self.capabilities],
            "gaps": [item.as_dict() for item in self.gaps],
            "technical_debt": list(self.technical_debt),
            "risks": list(self.risks),
            "test_summary": dict(self.test_summary),
            "governance": dict(self.governance),
            "remaining_external_requirements": list(self.remaining_external_requirements),
            "readiness_percentage": self.readiness_percentage,
        }


@dataclass(frozen=True, slots=True)
class VipReadinessScorecardV10:
    audit_version: str
    component_scores: dict[str, float]
    engineering_readiness_percentage: float
    engineering_claim: str
    official_qualification: str
    blockers: tuple[str, ...]
    external_requirements: tuple[str, ...]
    methodology: str
    advisory_only: bool = True
    vip_qualified: bool = False
    p10_completed: bool = False

    def __post_init__(self) -> None:
        if not self.advisory_only or self.vip_qualified or self.p10_completed:
            raise ValueError("scorecard_cannot_grant_qualification")
        for value in self.component_scores.values():
            if not 0.0 <= value <= 100.0:
                raise ValueError("component_score_must_be_bounded")
        if not 0.0 <= self.engineering_readiness_percentage <= 100.0:
            raise ValueError("engineering_readiness_must_be_bounded")

    def as_dict(self) -> dict[str, Any]:
        return {
            "audit_version": self.audit_version,
            "component_scores": dict(self.component_scores),
            "engineering_readiness_percentage": self.engineering_readiness_percentage,
            "engineering_claim": self.engineering_claim,
            "official_qualification": self.official_qualification,
            "blockers": list(self.blockers),
            "external_requirements": list(self.external_requirements),
            "methodology": self.methodology,
            "advisory_only": self.advisory_only,
            "vip_qualified": self.vip_qualified,
            "p10_completed": self.p10_completed,
        }


__all__ = [
    "AuditStatus",
    "CapabilityAssessmentV10",
    "GapRecordV10",
    "ImplementationStatus",
    "ProjectStateReportV10",
    "VipReadinessScorecardV10",
]

if __name__ == "__main__":
    raise SystemExit("advisory contracts only")
