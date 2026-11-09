# src/webpent/causal_reasoning_v2/__init__.py
"""Causal Reasoning Engine v2 — full rebuild addressing the critical review.

Fixes vs v1:
  * Real structural model (SystemArchitectureGraph) — not text fingerprints.
  * Root cause DERIVED from graph structure (verification ordering, shared
    flawed segments, defective shared objects) — not 12 hardcoded rules.
  * Structural siblings (same flawed segment / same defective object) — not
    route-glob text matches.
  * Two-layer memory: immutable observations + statistically-scored
    inferences (support × consistency × finite-sample factor).
  * Hard acceptance threshold (default 0.75): low-confidence patterns are
    NEVER surfaced — they stay internal only.
  * Behavior-based similarity (auth flow, verification placement, binding
    style...) — not framework-name matching.
  * Bayesian self-correction: refuted predictions reduce a pattern's
    effective confidence until it falls below threshold and stops surfacing.
  * Actual integration layer with three fail-safe hooks matching the real
    Finding/Hypothesis/TargetKnowledgeV2 shapes; disabled flag = identical
    to pre-causal behavior.
"""
from webpent.causal_reasoning_v2.architecture_extractor import (
    ArchitectureExtractor,
    CallNode,
    EndpointBinding,
    OrderFlaw,
)
from webpent.causal_reasoning_v2.architecture_graph import (
    ArchEdge,
    ArchNode,
    EdgeKind,
    NodeKind,
    PathTrace,
    SystemArchitectureGraph,
    VerificationVerdict,
)
from webpent.causal_reasoning_v2.closed_loop_integration import ClosedLoopIntegrator
from webpent.causal_reasoning_v2.contextual_memory_v2 import (
    BehaviorProfile,
    ContextualMemoryV2,
    InferencePattern,
    TransferredInsight,
)
from webpent.causal_reasoning_v2.integration_layer import CausalIntegrationLayer
from webpent.causal_reasoning_v2.root_cause_analyzer_v2 import (
    RootCauseAnalyzerV2,
    StructuralFingerprint,
    StructuralLogicMatcher,
)
from webpent.causal_reasoning_v2.root_cause_inferrer import (
    CausalConclusionV2,
    RootCauseClusterV2,
    RootCauseInferrer,
)
from webpent.causal_reasoning_v2.structural_knowledge_base import (
    ArchitecturalPattern,
    StructuralKnowledgeBase,
)
# Red-Team fix phases 1-5:
from webpent.causal_reasoning_v2.architecture_extractor_v2 import (
    ArchitectureExtractorV2,
    CallNodeV2,
    EndpointBindingV2,
    OrderFlawV2,
)
from webpent.causal_reasoning_v2.structural_matcher_v2 import (
    StructuralFingerprintV2,
    StructuralMatcherV2,
)
from webpent.causal_reasoning_v2.confidence_engine import (
    ConfidenceEngine,
    FeedbackState,
    PatternConfidence,
)
from webpent.causal_reasoning_v2.causal_adapter import (
    CausalAdapter,
    FINDING_FIELDS,
    HYPOTHESIS_FIELDS,
    HOOK_POINTS,
)
from webpent.causal_reasoning_v2.pattern_versioning import (
    ENGINE_VERSION,
    EvidenceRecord,
    RunFingerprint,
    VersionedKnowledgeBase,
    VersionedPattern,
)

__all__ = [
    "SystemArchitectureGraph", "ArchNode", "ArchEdge", "NodeKind", "EdgeKind",
    "PathTrace", "VerificationVerdict",
    "RootCauseInferrer", "CausalConclusionV2", "RootCauseClusterV2",
    "ContextualMemoryV2", "BehaviorProfile", "InferencePattern", "TransferredInsight",
    "CausalIntegrationLayer",
    # Deep-fix phases 1-4:
    "ArchitectureExtractor", "CallNode", "EndpointBinding", "OrderFlaw",
    "RootCauseAnalyzerV2", "StructuralLogicMatcher", "StructuralFingerprint",
    "StructuralKnowledgeBase", "ArchitecturalPattern",
    "ClosedLoopIntegrator",
    # Red-Team fix phases 1-5:
    "ArchitectureExtractorV2", "CallNodeV2", "EndpointBindingV2", "OrderFlawV2",
    "StructuralMatcherV2", "StructuralFingerprintV2",
    "ConfidenceEngine", "FeedbackState", "PatternConfidence",
    "CausalAdapter", "FINDING_FIELDS", "HYPOTHESIS_FIELDS", "HOOK_POINTS",
    "VersionedKnowledgeBase", "VersionedPattern", "EvidenceRecord",
    "RunFingerprint", "ENGINE_VERSION",
]
