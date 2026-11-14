"""Autonomous, read-only DCVU campaign orchestration."""

from __future__ import annotations

from dataclasses import dataclass

from .contracts import DcvRun, VulnerabilityCase
from .engine import DetectionQualityValidationEngine
from .fixtures import DisposableTargetFixture
from .ground_truth import GroundTruthRegistry


@dataclass(frozen=True)
class CampaignTrace:
    target_id: str
    discovered_surface_count: int
    proposed_case_ids: tuple[str, ...]
    evaluated_case_ids: tuple[str, ...]
    execution_events: tuple[str, ...] = ()


class AutonomousDcvCampaign:
    """Run the same generic discovery and validation loop over local fixtures."""

    def __init__(self, engine: DetectionQualityValidationEngine | None = None) -> None:
        self.engine = engine or DetectionQualityValidationEngine()

    def run(
        self,
        fixtures: tuple[DisposableTargetFixture, ...],
        registry: GroundTruthRegistry,
        run_id: str = "dcvu-v1-local-campaign",
    ) -> tuple[DcvRun, tuple[CampaignTrace, ...]]:
        if not fixtures:
            raise ValueError("DCVU campaign requires at least one local fixture")
        registry.validate()
        traces: list[CampaignTrace] = []
        evaluations = []
        targets = []
        cases: list[VulnerabilityCase] = []
        for fixture in fixtures:
            surfaces = fixture.describe_surfaces()
            proposed = self.engine.discover_case_ids(fixture)
            target_evaluations = self.engine.evaluate_target(fixture, registry)
            targets.append(fixture.profile)
            cases.extend(item.ground_truth.case for item in target_evaluations)
            evaluations.extend(target_evaluations)
            traces.append(
                CampaignTrace(
                    target_id=fixture.profile.target_id,
                    discovered_surface_count=len(surfaces),
                    proposed_case_ids=proposed,
                    evaluated_case_ids=tuple(
                        item.ground_truth.case.case_id for item in target_evaluations
                    ),
                )
            )
        run = DcvRun(
            run_id=run_id,
            targets=targets,
            cases=cases,
            evaluations=evaluations,
        )
        run.validate()
        return run, tuple(traces)
