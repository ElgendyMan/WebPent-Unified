"""ABHIE v4: bounded advisory expert research reasoning."""

from .boundaries import SecurityBoundaryMapper
from .brain import ResearchBrainBuilder, ResearchBrainStateStore
from .chains import AttackChainIntelligence
from .competition import ExpertHypothesisEngine
from .contracts import (
    AttackChainHypothesis,
    BoundaryCrossing,
    BoundaryNode,
    Disposition,
    EvidenceAssessment,
    EvidenceRef,
    EvidenceState,
    Hypothesis,
    HypothesisCompetition,
    Lifecycle,
    ReflectionLesson,
    ResearchBrainState,
    ResearchQualityScore,
    ResearchStrategyDecision,
    SecurityAssumption,
    SecurityBoundaryGraph,
    SeniorSecurityReview,
    StrategyCandidate,
)
from .core import ABHIECoreV4
from .discovery import UnknownDiscoveryEngine
from .reflection import ReflectionMemory
from .review import SeniorResearchReviewer
from .strategy import ExpertStrategySelector

__all__ = [
    "ABHIECoreV4",
    "AttackChainHypothesis",
    "AttackChainIntelligence",
    "BoundaryCrossing",
    "BoundaryNode",
    "Disposition",
    "EvidenceAssessment",
    "EvidenceRef",
    "EvidenceState",
    "ExpertHypothesisEngine",
    "ExpertStrategySelector",
    "Hypothesis",
    "HypothesisCompetition",
    "Lifecycle",
    "ReflectionLesson",
    "ReflectionMemory",
    "ResearchBrainBuilder",
    "ResearchBrainState",
    "ResearchBrainStateStore",
    "ResearchQualityScore",
    "ResearchStrategyDecision",
    "SecurityAssumption",
    "SecurityBoundaryGraph",
    "SecurityBoundaryMapper",
    "SeniorResearchReviewer",
    "SeniorSecurityReview",
    "StrategyCandidate",
    "UnknownDiscoveryEngine",
]
