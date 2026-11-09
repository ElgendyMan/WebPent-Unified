"""EGAIE causal validation and proof ports, wired to the real cqa_v2 stack.

CausalValidationPort delegates every verdict to
cqa_v2.causal_guard.guarded_causal_evaluate (fail-closed, unchanged).
ProofBundlePort builds a sealed CompleteProofBundle via
cqa_v2.proof_bundle_builder.build_complete_proof_bundle and verifies it
with cqa_v2.replay_verifier.verify_replay. Nothing here can confirm a
finding without a passing replay of a sealed bundle.
"""
from __future__ import annotations

from typing import Any

from webpent.cqa_v2.causal_guard import (
    GuardedCausalResult,
    Verdict,
    guarded_causal_evaluate,
)
from webpent.cqa_v2.proof_bundle_builder import build_complete_proof_bundle
from webpent.cqa_v2.replay_verifier import verify_replay


class CausalValidationPort:
    """Validate a baseline/candidate/control triple through CausalGuard."""

    def validate(
        self,
        baseline: dict[str, Any],
        candidate: dict[str, Any],
        control: dict[str, Any],
    ) -> dict[str, Any]:
        result: GuardedCausalResult = guarded_causal_evaluate(
            baseline, candidate, control,
            safe_precondition="read_only_no_state_mutation",
        )
        return {
            "verdict": result.verdict.value.lower(),
            "causal_signal": result.causal_signal,
            "confidence": result.confidence,
            "block_reason": result.block_reason,
            "raw_decision": result.raw_decision,
        }


class ProofBundlePort:
    """Build and replay-verify sealed CompleteProofBundles."""

    def __init__(
        self, runtime_provenance: dict[str, Any] | None = None,
    ) -> None:
        self._runtime_provenance = dict(
            runtime_provenance
            or {"mode": "controlled_local_target", "offline": True}
        )

    def build(
        self,
        experiment: Any = None,
        baseline: dict[str, Any] | None = None,
        candidate: dict[str, Any] | None = None,
        control: dict[str, Any] | None = None,
        causal_result: dict[str, Any] | None = None,
        *,
        experiment_id: str | None = None,
        family: str | None = None,
    ):
        if isinstance(experiment, str):
            experiment_id = experiment_id or experiment
            statement = family
        elif experiment is not None:
            experiment_id = experiment_id or experiment.experiment_id
            family = family or experiment.family
            statement = experiment.description
        else:
            statement = family
        experiment_id = experiment_id or "unknown-experiment"
        family = family or "unknown-family"
        guarded = GuardedCausalResult(
            verdict=Verdict((causal_result or {}).get("verdict", "blocked")
                            .upper()),
            causal_signal=(causal_result or {}).get("causal_signal"),
            confidence=(causal_result or {}).get("confidence", 0.0),
            block_reason=(causal_result or {}).get("block_reason"),
        )
        return build_complete_proof_bundle(
            target_identity=f"egaie:{family}",
            case_identity=experiment_id,
            baseline=baseline or {},
            candidate=candidate or {},
            negative_control=control or {},            causal_result=guarded,
            semantic_evidence={
                "precondition": "read_only_no_state_mutation",
                "vulnerability_class": family,
                "experiment_id": experiment_id,
                "statement": statement,
            },
            source_provenance={
                "source": "egaie",
                "component": "ProofBundlePort",
                "validation": "cqa_v2.causal_guard",
            },
            runtime_provenance=dict(self._runtime_provenance),
        )

    def verify(self, bundle: Any) -> dict[str, Any]:
        result = verify_replay(bundle)
        return {
            "replay_valid": result.replay_valid,
            "seal_valid": result.seal_valid,
            "verdict_match": result.verdict_match,
            "digest_match": result.digest_match,
            "seal_match": result.seal_match,
        }
