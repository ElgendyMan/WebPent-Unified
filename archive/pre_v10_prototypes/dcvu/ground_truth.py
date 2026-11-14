"""Independent fixture-backed ground truth and negative-control registry."""

from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256

from .contracts import GroundTruthRecord, VulnerabilityCase
from .fixtures import DisposableTargetFixture


@dataclass(frozen=True)
class NegativeControl:
    control_id: str
    case_id: str
    target_id: str
    requester_id: str
    owner_id: str
    tenant_id: str
    rationale: str

    def validate(self) -> None:
        if not all(
            (
                self.control_id,
                self.case_id,
                self.target_id,
                self.requester_id,
                self.owner_id,
                self.tenant_id,
                self.rationale,
            )
        ):
            raise ValueError("negative control is incomplete")


@dataclass(frozen=True)
class GroundTruthRegistry:
    records: tuple[GroundTruthRecord, ...]
    controls: tuple[NegativeControl, ...]
    independent_source_id: str

    def validate(self) -> None:
        if not self.records or not self.controls or not self.independent_source_id:
            raise ValueError("ground truth registry is incomplete")
        record_ids = {record.case.case_id for record in self.records}
        control_case_ids = {control.case_id for control in self.controls}
        if record_ids != control_case_ids:
            raise ValueError("every ground-truth case requires one negative control")
        for record in self.records:
            record.validate()
        for control in self.controls:
            control.validate()

    def record_for(self, case_id: str) -> GroundTruthRecord:
        for record in self.records:
            if record.case.case_id == case_id:
                return record
        raise KeyError(case_id)

    def control_for(self, case_id: str) -> NegativeControl:
        for control in self.controls:
            if control.case_id == case_id:
                return control
        raise KeyError(case_id)


def build_ground_truth_registry(
    fixtures: tuple[DisposableTargetFixture, ...],
) -> GroundTruthRegistry:
    """Create source-backed fixture truth without passing truth into surface discovery."""
    records: list[GroundTruthRecord] = []
    controls: list[NegativeControl] = []
    for fixture in fixtures:
        for surface in fixture.surfaces.values():
            case_id = f"{fixture.profile.target_id}.{surface.vulnerability_class}.v1"
            case = VulnerabilityCase(
                case_id=case_id,
                target_id=fixture.profile.target_id,
                vulnerability_class=surface.vulnerability_class,
                title=f"{surface.vulnerability_class} authorization contract",
                oracle_id=f"oracle.{surface.vulnerability_class}.v1",
                negative_control_id=f"control.{case_id}",
            )
            source_material = (
                f"{fixture.profile.source_digest}|{surface.surface_id}|"
                f"{surface.vulnerability_class}|{surface.vulnerable}"
            )
            source_digest = sha256(source_material.encode()).hexdigest()
            records.append(
                GroundTruthRecord(
                    case=case,
                    exists=surface.vulnerable,
                    location_fingerprint=f"{fixture.profile.target_id}:{surface.surface_id}",
                    expected_impact=surface.expected_impact,
                    source_evidence_digest=f"sha256:{source_digest}",
                    independent_review_id=f"fixture-review:{fixture.profile.target_id}:v1",
                )
            )
            controls.append(
                NegativeControl(
                    control_id=f"control.{case_id}",
                    case_id=case_id,
                    target_id=fixture.profile.target_id,
                    requester_id="editor-a",
                    owner_id="editor-a",
                    tenant_id="tenant-a",
                    rationale="same-owner and same-tenant authorized control",
                )
            )
    registry = GroundTruthRegistry(
        records=tuple(records),
        controls=tuple(controls),
        independent_source_id="dcvu-fixture-source-review-v1",
    )
    registry.validate()
    return registry
