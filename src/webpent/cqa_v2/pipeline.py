"""
CQA v2 — End-to-end pipeline for a single case.

Pipeline stages:
  discovery (use existing observations)
  → hypothesis
  → candidate
  → baseline
  → control
  → causal comparison
  → verdict
  → proof creation
  → seal
  → replay
  → scoring

REUSES: OracleEngine via causal_guard, ProofBundle model via proof_bundle_builder.
"""
from dataclasses import dataclass, field
from typing import Any

from webpent.cqa_v2.causal_guard import GuardedCausalResult, Verdict, guarded_causal_evaluate
from webpent.cqa_v2.proof_bundle_builder import build_complete_proof_bundle
from webpent.cqa_v2.replay_verifier import ReplayResult, verify_replay


@dataclass
class CaseObservations:
    """Raw observations from CQA v1 campaign for a single case."""
    case_id: str
    target_id: str
    baseline: dict[str, Any]
    candidate: dict[str, Any]
    negative_control: dict[str, Any]
    safe_precondition: str
    expected_labels_label: bool  # READ-ONLY from frozen truth, NOT used by detector


@dataclass
class PipelineTrace:
    """Full trace of one case through all pipeline stages."""
    case_id: str
    stages: dict[str, Any] = field(default_factory=dict)
    replay_verified: bool = False
    scoring_category: str | None = None
    bundle_json: str | None = None
    replay_result: dict[str, Any] | None = None


def score_case(
    obs: CaseObservations,
    causal: GuardedCausalResult,
    replay: ReplayResult,
) -> dict[str, Any]:
    """
    Score against FROZEN ground truth.
    BLOCKED and INCONCLUSIVE are EXCLUDED from confusion matrix.
    """
    verdict = causal.verdict
    truth = obs.expected_labels_label

    if verdict == Verdict.BLOCKED:
        return {"scored": False, "category": "BLOCKED", "tp": 0, "tn": 0, "fp": 0, "fn": 0}
    if verdict == Verdict.INCONCLUSIVE:
        return {"scored": False, "category": "INCONCLUSIVE", "tp": 0, "tn": 0, "fp": 0, "fn": 0}

    # Only CONFIRMED/CLEAN with replay_verified = True enter scoring
    if not replay.replay_verified:
        return {"scored": False, "category": "REPLAY_NOT_VERIFIED", "tp": 0, "tn": 0, "fp": 0, "fn": 0}

    detector_positive = (verdict == Verdict.CONFIRMED)
    if detector_positive and truth:
        cat = "TP"
    elif detector_positive and not truth:
        cat = "FP"
    elif (not detector_positive) and truth:
        cat = "FN"
    else:
        cat = "TN"

    result = {"scored": True, "category": cat, "tp": 0, "tn": 0, "fp": 0, "fn": 0}
    result[cat.lower()] = 1
    return result


def run_single_case_end_to_end(obs: CaseObservations) -> PipelineTrace:
    """
    Execute the full pipeline for ONE case.
    Returns a complete trace of all stages.
    """
    trace = PipelineTrace(case_id=obs.case_id)

    # Stage: discovery — observations already exist from CQA v1 campaign
    trace.stages["discovery"] = {
        "status": "ok",
        "source": "cqa_v1_campaign_observations",
        "has_baseline": bool(obs.baseline),
        "has_candidate": bool(obs.candidate),
        "has_control": bool(obs.negative_control),
    }

    # Stage: hypothesis — derived from the case identity and observation pair
    trace.stages["hypothesis"] = {
        "status": "ok",
        "case_id": obs.case_id,
        "target_id": obs.target_id,
        "hypothesis": "candidate_observation_differs_from_baseline_in_a_way_that_indicates_vulnerability",
    }

    # Stage: candidate
    trace.stages["candidate"] = {
        "status": "ok",
        "observation_present": bool(obs.candidate),
        "status_code": obs.candidate.get("status_code") if isinstance(obs.candidate, dict) else None,
    }

    # Stage: baseline
    trace.stages["baseline"] = {
        "status": "ok",
        "observation_present": bool(obs.baseline),
        "status_code": obs.baseline.get("status_code") if isinstance(obs.baseline, dict) else None,
    }

    # Stage: control (negative control)
    trace.stages["control"] = {
        "status": "ok",
        "observation_present": bool(obs.negative_control),
        "status_code": obs.negative_control.get("status_code") if isinstance(obs.negative_control, dict) else None,
    }

    # Stage: causal comparison
    causal_result = guarded_causal_evaluate(
        baseline=obs.baseline,
        candidate=obs.candidate,
        control=obs.negative_control,
        safe_precondition=obs.safe_precondition,
    )
    trace.stages["causal_comparison"] = {
        "verdict": causal_result.verdict.value if hasattr(causal_result.verdict, "value") else str(causal_result.verdict),
        "causal_signal": causal_result.causal_signal,
        "confidence": causal_result.confidence,
        "block_reason": causal_result.block_reason,
    }

    # Stage: verdict
    trace.stages["verdict"] = {
        "verdict": causal_result.verdict.value if hasattr(causal_result.verdict, "value") else str(causal_result.verdict),
    }

    # Stage: proof creation (only for CONFIRMED/CLEAN, not BLOCKED)
    bundle = None
    if causal_result.verdict in (Verdict.CONFIRMED, Verdict.CLEAN):
        bundle = build_complete_proof_bundle(
            target_identity=obs.target_id,
            case_identity=obs.case_id,
            baseline=obs.baseline,
            candidate=obs.candidate,
            negative_control=obs.negative_control,
            causal_result=causal_result,
            semantic_evidence={
                "precondition": obs.safe_precondition,
                "vulnerability_class": obs.safe_precondition.split("_")[0] if "_" in obs.safe_precondition else "generic",
            },
            source_provenance={"source": "cqa_v1_campaign", "case_id": obs.case_id},
            runtime_provenance={"pipeline": "cqa_v2", "stage": "single_case_trace"},
        )
        trace.stages["proof_creation"] = {
            "bundle_created": True,
            "bundle_id": bundle.bundle_id,
            "native_proof_bundle_valid": bundle.semantic_evidence.get("native_proof_bundle_valid"),
        }

        # Stage: seal
        trace.stages["seal"] = {
            "seal": bundle.deterministic_seal,
            "seal_length": len(bundle.deterministic_seal),
            "is_sealed": bundle.is_sealed,
            "seal_self_verifies": bundle.verify_seal(),
        }

        # Stage: replay
        replay_result = verify_replay(bundle)
        trace.replay_result = {
            "verdict_match": replay_result.verdict_match,
            "seal_valid": replay_result.seal_valid,
            "seal_match": replay_result.seal_match,
            "digest_match": replay_result.digest_match,
        }
        trace.stages["replay"] = trace.replay_result
        trace.replay_verified = replay_result.replay_verified

        # Stage: scoring
        scoring = score_case(obs, causal_result, replay_result)
        trace.scoring_category = scoring["category"]
        trace.stages["scoring"] = scoring

        trace.bundle_json = bundle.to_json()
    else:
        # BLOCKED or INCONCLUSIVE — no proof bundle, no scoring
        trace.stages["proof_creation"] = {
            "bundle_created": False,
            "reason": f"verdict_{causal_result.verdict.value}_does_not_qualify_for_proof_bundle",
        }
        trace.stages["seal"] = {"skipped": True, "reason": "no_bundle"}
        trace.stages["replay"] = {"skipped": True, "reason": "no_bundle"}
        trace.stages["scoring"] = {
            "scored": False,
            "category": causal_result.verdict.value if hasattr(causal_result.verdict, "value") else str(causal_result.verdict),
            "tp": 0, "tn": 0, "fp": 0, "fn": 0,
        }
        trace.scoring_category = trace.stages["scoring"]["category"]
        trace.replay_verified = False

    return trace
