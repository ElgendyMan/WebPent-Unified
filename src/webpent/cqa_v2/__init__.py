"""
CQA v2 — Causal Qualitative Analysis engine (UPGRADED for VIP qualification).

Includes:
- Gate 1+2: Extended observation model + authorization-differential causal oracle
- Gate 6: ProofBundle + replay verification
- Gate 7: Dynamic evidence-derived confidence
- Gate 8: Smart Autonomous Detection Loop
"""
# Gate 8 — Smart Autonomous Detection Loop
from .autonomous_loop import (
    AutonomousLoopResult,
    Hypothesis,
    SmartMemory,
    SmartStrategyEngine,
    run_autonomous_detection_loop,
)
from .causal_guard import (
    GuardedCausalResult,
    Verdict,
    _authorization_enforced,
    _authorization_mismatch,
    _extract_context,
    _observation_complete,
    _path_analogous,
    _semantic_diff_significant,
    guarded_causal_evaluate,
)
from .pipeline import PipelineTrace, run_single_case_end_to_end
from .pipeline_integration import run_cqa_v2_postprocess
from .proof_bundle_builder import build_complete_proof_bundle
from .replay_verifier import verify_replay

__all__ = [
    "guarded_causal_evaluate",
    "Verdict",
    "GuardedCausalResult",
    "_extract_context",
    "_observation_complete",
    "_authorization_mismatch",
    "_authorization_enforced",
    "_semantic_diff_significant",
    "_path_analogous",
    "build_complete_proof_bundle",
    "verify_replay",
    "run_single_case_end_to_end",
    "PipelineTrace",
    "run_cqa_v2_postprocess",
    "Hypothesis",
    "AutonomousLoopResult",
    "SmartMemory",
    "SmartStrategyEngine",
    "run_autonomous_detection_loop",
]
