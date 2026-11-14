"""Shared cross-family primitives (see base.py for the contract)."""
from .base import (
    CandidateConfidence,
    EvidenceRequirement,
    FamilyAnalysis,
    FamilyAnalyzer,
    FamilyCandidate,
    FamilyId,
    ScenarioSpec,
)
from .execution_plans import ExecutionPlan, RequestPlan, build_plan_for
from .promotion import promote_confirmed_batch, promote_confirmed_finding
from .surface_adapter import detect_capabilities, surface_graph_to_inventory

__all__ = [
    "CandidateConfidence",
    "EvidenceRequirement",
    "ExecutionPlan",
    "FamilyAnalysis",
    "FamilyAnalyzer",
    "FamilyCandidate",
    "FamilyId",
    "RequestPlan",
    "ScenarioSpec",
    "build_plan_for",
    "detect_capabilities",
    "promote_confirmed_batch",
    "promote_confirmed_finding",
    "surface_graph_to_inventory",
]
