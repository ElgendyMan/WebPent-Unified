"""AVRP advisory research-intelligence contracts."""

from webpent.avrp.chains import AdvancedAttackChainReasoner, AttackChainHypothesis
from webpent.avrp.correlation import (
    EvidenceCorrelationEngine,
    EvidenceNode,
    EvidenceRelationshipGraph,
    SecurityRelationship,
)
from webpent.avrp.coverage import CoverageIntelligence, CoverageRecord
from webpent.avrp.improvement import (
    PriorityWeightUpdate,
    ResearchOutcome,
    ResearchSelfImprovement,
    SelfImprovementReport,
)
from webpent.avrp.loop import AutonomousResearchLoopV2, AutonomousResearchReport
from webpent.avrp.patterns import VulnerabilityPattern, VulnerabilityPatternLibrary
from webpent.avrp.review import AdvancedResearchQualityReviewer, ResearchQualityReview
from webpent.avrp.state import ResearchMemoryState, ResearchStateUpdate

__all__ = [
    "AdvancedAttackChainReasoner",
    "AdvancedResearchQualityReviewer",
    "AttackChainHypothesis",
    "AutonomousResearchLoopV2",
    "AutonomousResearchReport",
    "ResearchMemoryState",
    "CoverageIntelligence",
    "CoverageRecord",
    "EvidenceCorrelationEngine",
    "EvidenceNode",
    "EvidenceRelationshipGraph",
    "PriorityWeightUpdate",
    "ResearchOutcome",
    "ResearchQualityReview",
    "ResearchSelfImprovement",
    "ResearchStateUpdate",
    "SecurityRelationship",
    "SelfImprovementReport",
    "VulnerabilityPattern",
    "VulnerabilityPatternLibrary",
]
