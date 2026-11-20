"""EGAIE causal adapter: real CausalGuard/ProofBundle/Replay wiring,
positive confirms, negative cleans, incomplete blocks, tamper fails replay."""
from __future__ import annotations

from webpent.egaie.benchmark.fixture import (
    ControlledFixtureTarget,
    FixtureCase,
)
from webpent.egaie.causal_adapter import (
    CausalValidationPort,
    ProofBundlePort,
)


def _triple(case_id: str, family: str, positive: bool):
    target = ControlledFixtureTarget([
        FixtureCase(case_id=case_id, family=family, positive=positive)])
    return target.observation_triple(case_id, family)


def test_positive_triple_confirms_via_real_guard():
    baseline, candidate, control = _triple("pos-idor-1", "IDOR", True)
    result = CausalValidationPort().validate(baseline, candidate, control)
    assert result["verdict"] == "confirmed"
    assert result["causal_signal"] is True
    port = ProofBundlePort()
    bundle = port.build(
        experiment_id="e-1", family="IDOR",
        baseline=baseline, candidate=candidate, control=control,
        causal_result=result)
    verified = port.verify(bundle)
    assert verified["replay_valid"] is True
    assert verified["seal_valid"] is True


def test_negative_triple_cleans():
    baseline, candidate, control = _triple("neg-idor-1", "IDOR", False)
    result = CausalValidationPort().validate(baseline, candidate, control)
    assert result["verdict"] == "clean"


def test_incomplete_candidate_is_blocked():
    baseline, candidate, control = _triple("pos-idor-1", "IDOR", True)
    incomplete = {k: v for k, v in candidate.items() if k != "semantic_digest"}
    result = CausalValidationPort().validate(baseline, incomplete, control)
    assert result["verdict"] == "blocked"


def test_tampered_bundle_fails_replay():
    baseline, candidate, control = _triple("pos-idor-1", "IDOR", True)
    result = CausalValidationPort().validate(baseline, candidate, control)
    port = ProofBundlePort()
    bundle = port.build(
        experiment_id="e-1", family="IDOR",
        baseline=baseline, candidate=candidate, control=control,
        causal_result=result)
    # Real tamper: mutate sealed evidence after sealing.
    bundle.candidate_observation = dict(bundle.candidate_observation)
    bundle.candidate_observation["status_code"] = 499
    verified = port.verify(bundle)
    assert verified["replay_valid"] is False
    assert verified["seal_valid"] is False
