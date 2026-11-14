"""
CQA v2 — Replay Verification Protocol.

Protocol:
  create bundle → seal → destroy/reload execution context → replay →
  verify seal → recompute causal result → compare

Success only when (v1.8.4 STRICT):
  original_verdict == replay_verdict  (verdict_match)
  AND original evidence digest == replay evidence digest  (evidence_match)
  AND seal is valid  (seal_valid)
  AND seal matches  (seal_match)
  AND replay executed successfully  (replay_executed)

Therefore: CONFIRMED -> INCONCLUSIVE = REPLAY_FAILED (replay_valid = False)
Seal equality ALONE does NOT prove replay success.
"""
from dataclasses import dataclass

from webpent.cqa_v2.causal_guard import guarded_causal_evaluate
from webpent.cqa_v2.proof_bundle_builder import CompleteProofBundle, _sha256


@dataclass
class ReplayResult:
    original_verdict: str
    replay_verdict: str
    verdict_match: bool
    original_seal: str
    replay_seal: str
    seal_valid: bool
    seal_match: bool
    original_digest: str
    replay_digest: str
    digest_match: bool
    replay_verified: bool
    replay_executed: bool = True
    # Spec-required aliases (v1.8.4 strict naming)
    @property
    def evidence_match(self) -> bool:
        return self.digest_match
    @property
    def replay_valid(self) -> bool:
        """Strict replay success: verdict_match AND evidence_match AND seal_valid AND seal_match AND replay_executed.
        CONFIRMED -> INCONCLUSIVE = replay_valid = False (REPLAY_FAILED).
        Seal equality alone does NOT prove replay success."""
        return bool(self.verdict_match and self.digest_match and self.seal_valid and self.seal_match and self.replay_executed)


def _bundle_evidence_digest(b: CompleteProofBundle) -> str:
    """Canonical digest of all evidence-bearing fields in the bundle."""
    material = {
        "baseline": b.baseline_observation,
        "candidate": b.candidate_observation,
        "control": b.negative_control,
        "causal_result": b.causal_result,
        "semantic": b.semantic_evidence,
    }
    return _sha256(material)


def verify_replay(bundle: CompleteProofBundle) -> ReplayResult:
    """
    Execute the full replay verification protocol.

    1. Capture original state
    2. Serialize + destroy context
    3. Reload in fresh context
    4. Verify seal on reloaded bundle
    5. Recompute causal result from reloaded observations
    6. Compare everything
    """
    # Step 1: Capture original state
    original_verdict = str(bundle.causal_result.get("verdict", "UNKNOWN"))
    original_seal = bundle.deterministic_seal
    original_digest = _bundle_evidence_digest(bundle)

    # Step 2: Serialize + destroy context
    serialized = bundle.to_json()
    del bundle

    # Step 3: Reload in fresh context (simulated via from_json)
    reloaded = CompleteProofBundle.from_json(serialized)

    # Step 4: Verify seal on reloaded bundle
    seal_valid = reloaded.verify_seal()
    replay_seal = reloaded.deterministic_seal

    # Step 5: Recompute causal result from reloaded observations
    precondition = reloaded.semantic_evidence.get("precondition", "read_only_no_state_mutation")
    replay_causal = guarded_causal_evaluate(
        baseline=reloaded.baseline_observation,
        candidate=reloaded.candidate_observation,
        control=reloaded.negative_control,
        safe_precondition=precondition,
    )
    replay_verdict = str(
        replay_causal.verdict.value
        if hasattr(replay_causal.verdict, "value")
        else replay_causal.verdict
    )

    replay_digest = _bundle_evidence_digest(reloaded)

    # Step 6: Compare
    verdict_match = (original_verdict == replay_verdict)
    seal_match = (original_seal == replay_seal)
    digest_match = (original_digest == replay_digest)

    replay_verified = bool(verdict_match and seal_valid and digest_match)

    return ReplayResult(
        original_verdict=original_verdict,
        replay_verdict=replay_verdict,
        verdict_match=verdict_match,
        original_seal=original_seal,
        replay_seal=replay_seal,
        seal_valid=seal_valid,
        seal_match=seal_match,
        original_digest=original_digest,
        replay_digest=replay_digest,
        digest_match=digest_match,
        replay_verified=replay_verified,
        replay_executed=True,
    )
