# src/webpent/causal_reasoning/__init__.py
"""Causal Reasoning Engine — Proposal #1 (additive, non-breaking layer).

Proposal #1 transforms the system from descriptive ("we found X") to
explanatory ("X exists because of architectural weakness Y; regions Z share
that weakness and should be probed next; past targets similar to this one
suffered from pattern W").

Three sub-systems:
  * ArchitectureInferrer  — one finding -> causal hypothesis + sibling
    at-risk regions (uncovered-first prioritisation).
  * ContextualMemory      — cross-engagement persistent context store with
    fingerprint similarity and knowledge transfer.
  * RootCauseAnalyzer     — cluster findings by architectural root cause and
    enumerate every sibling path sharing that cause ("fix once, fix
    everywhere").

All three are read-only with respect to engagement state and have no
execution authority.  They emit bounded, confidence-scored, deterministic
inferences.  Downstream agents decide whether to act.
"""
from webpent.causal_reasoning.architecture_inferrer import (
    ArchitectureInferrer,
    CAUSAL_RULES,
    CausalRule,
)
from webpent.causal_reasoning.contextual_memory import (
    DEFAULT_MEMORY_DIR,
    ContextualMemory,
)
from webpent.causal_reasoning.contracts import (
    AtRiskRegion,
    CausalHypothesis,
    ContextFingerprint,
    EngagementContextRecord,
    InferenceLifecycle,
    InferenceResult,
    RootCauseCluster,
    TransferStrength,
    TransferredLesson,
    WeaknessCategory,
    glob_matches,
    route_to_glob,
    stable_id,
)
from webpent.causal_reasoning.engine import CausalReasoningEngine
from webpent.causal_reasoning.root_cause_analyzer import RootCauseAnalyzer

__all__ = [
    "ArchitectureInferrer",
    "CAUSAL_RULES",
    "CausalHypothesis",
    "CausalReasoningEngine",
    "CausalRule",
    "ContextFingerprint",
    "ContextualMemory",
    "DEFAULT_MEMORY_DIR",
    "AtRiskRegion",
    "EngagementContextRecord",
    "InferenceLifecycle",
    "InferenceResult",
    "RootCauseAnalyzer",
    "RootCauseCluster",
    "TransferStrength",
    "TransferredLesson",
    "WeaknessCategory",
    "glob_matches",
    "route_to_glob",
    "stable_id",
]
