"""Detection Capability Validation Upgrade contracts and local benchmark APIs."""

from .campaign import AutonomousDcvCampaign, CampaignTrace
from .contracts import (
    CaseDisposition,
    CaseEvaluation,
    DcvRun,
    DetectorDecision,
    GroundTruthRecord,
    MetricResult,
    Observation,
    ObservationKind,
    TargetProfile,
    Verdict,
    VulnerabilityCase,
)
from .engine import DetectionQualityValidationEngine, ProofSeal
from .fixtures import (
    DisposableTargetFixture,
    FixtureProbe,
    FixtureResponse,
    FixtureSurface,
    SyntheticIdentity,
    build_default_fixtures,
)
from .ground_truth import GroundTruthRegistry, NegativeControl, build_ground_truth_registry
from .metrics import attach_metrics, compute_metrics

__all__ = [
    "AutonomousDcvCampaign",
    "CampaignTrace",
    "DetectionQualityValidationEngine",
    "ProofSeal",
    "GroundTruthRegistry",
    "NegativeControl",
    "build_ground_truth_registry",
    "attach_metrics",
    "compute_metrics",
    "DisposableTargetFixture",
    "FixtureProbe",
    "FixtureResponse",
    "FixtureSurface",
    "SyntheticIdentity",
    "build_default_fixtures",
    "CaseDisposition",
    "CaseEvaluation",
    "DetectorDecision",
    "DcvRun",
    "GroundTruthRecord",
    "MetricResult",
    "Observation",
    "ObservationKind",
    "TargetProfile",
    "Verdict",
    "VulnerabilityCase",
]
