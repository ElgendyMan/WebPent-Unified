"""EGAIE Logic Breaker benchmark-integrity regression tests (L4.1).

Red-first tests for the four benchmark-integrity defects found in the
http-v3 architectural review. Each test fails against the pre-fix
implementation and passes against the corrected one:

1. Resume verification asserts real state (no lost confirmations, no
   re-confirmation, no duplicate mutation per idempotency identity)
   instead of a tautological monotonic request count.
2. Verified proofs are bound to confirmed cases one-to-one through two
   trusted identities (experiment_id + signature case prefix); missing,
   duplicated, mismatched or unrelated associations are rejected.
3. The Logic Breaker port resolves cases ONLY through the declared
   http-v3 registry: V1/V2 or unknown ids fail closed before any HTTP
   request is issued.
4. Zero-confirmation runs report undefined per-confirmation metrics
   (None, never a positive success ratio) and can never satisfy the
   acceptance thresholds, which now also require at least one valid
   confirmation.
"""
from __future__ import annotations

import pytest

from webpent.autonomous.authorization import EngagementAuthorization
from webpent.config.settings import ScanMode, Settings
from webpent.egaie.benchmark import http_runner as runner_module
from webpent.egaie.benchmark.http_ground_truth import (
    HTTP_GROUND_TRUTH_V3,
)
from webpent.egaie.benchmark.http_runner import (
    _proof_association_metrics,
    _resume_correct,
    _resume_invariants,
    _thresholds_pass,
)
from webpent.egaie.http_target import ControlledInvestigationTarget
from webpent.egaie.logic_port import build_logic_experiment_port
from webpent.egaie.schemas import (
    HypothesisRecord,
    HypothesisStatus,
    InvestigationState,
    ProposedExperiment,
)


@pytest.fixture()
def target():
    with ControlledInvestigationTarget() as server:
        yield server


def _authorization(target) -> EngagementAuthorization:
    return EngagementAuthorization(
        target_origin=target.target_origin,
        scope=(target.target_origin,),
        operator="benchmark-operator",
        authorization_reference="egaie-logic-benchmark-v3",
    )


def _v3_port(target):
    return build_logic_experiment_port(
        target=target,
        engagement_id="egaie-logic-eng-v3",
        campaign_id="egaie-logic-campaign-v3",
        authorization=_authorization(target),
        settings=Settings(
            scan_mode=ScanMode.AUTHORIZED_ACTIVE,
            smart_max_actions=200,
        ),
    )


def _experiment(case_id: str, family: str, hypothesis_id: str = "",
                ) -> ProposedExperiment:
    return ProposedExperiment(
        experiment_id=f"e-{case_id}",
        family=family,
        signature=f"{case_id}/{family}",
        description=f"probe for {case_id}",
        cost=0.1,
        risk=0.1,
        gain_estimate=0.5,
        rationale="test",
        hypothesis_id=hypothesis_id,
    )


def _state_with_confirmed_case(
    case_id: str = "pos-price-1",
    with_proof: bool = True,
) -> InvestigationState:
    state = InvestigationState(
        engagement_id="egaie-test",
        target_url="http://127.0.0.1:9",
    )
    state.add_hypothesis(HypothesisRecord(
        hypothesis_id=f"h-{case_id}",
        family="PRICE_INTEGRITY",
        statement="pricing invariant holds",
        origin=case_id,
        status=HypothesisStatus.CONFIRMED,
    ))
    state.add_experiment(_experiment(
        case_id, "PRICE_INTEGRITY", hypothesis_id=f"h-{case_id}"))
    state.experiment_outcomes[f"e-{case_id}"] = "confirmed"
    if with_proof:
        state.proof_bundles_verified.append({
            "experiment_id": f"e-{case_id}",
            "signature": f"{case_id}/PRICE_INTEGRITY",
            "replay_valid": True,
        })
    return state


class _FakeTarget:
    def __init__(self, identities):
        self._identities = list(identities)

    def applied_mutation_identities(self):
        return tuple(self._identities)


# -- Fix 1: meaningful resume verification ------------------------------

def test_resume_correct_passes_on_real_v3_run(target):
    assert _resume_correct(target, cases=HTTP_GROUND_TRUTH_V3) is True


def test_resume_invariants_detect_lost_confirmation():
    first = _state_with_confirmed_case()
    resumed = _state_with_confirmed_case(with_proof=True)
    resumed.hypotheses[0] = (
        resumed.hypotheses[0].with_status(HypothesisStatus.PROPOSED))
    ok, violations = _resume_invariants(
        first, resumed, _FakeTarget([]), set(), set())
    assert ok is False
    assert any("lost" in v for v in violations)


def test_resume_invariants_detect_duplicate_confirmation():
    first = _state_with_confirmed_case()
    resumed = _state_with_confirmed_case()
    resumed.proof_bundles_verified.append({
        "experiment_id": "e-pos-price-1",
        "signature": "pos-price-1/PRICE_INTEGRITY",
        "replay_valid": True,
    })
    ok, violations = _resume_invariants(
        first, resumed, _FakeTarget([]), set(), set())
    assert ok is False
    assert any("re-confirmed" in v for v in violations)


def test_resume_invariants_detect_duplicate_mutation():
    first = _state_with_confirmed_case()
    resumed = _state_with_confirmed_case()
    reused_token = "0" * 16
    fresh_token = "1" * 16
    # A post-resume identity that is NEW (not applied before resume)
    # but reuses a pre-resume token means the same deterministic task
    # token drove another successful mutation: a re-applied mutation.
    fake = _FakeTarget([
        ("checkout", "inv-1", reused_token),
        ("checkout", "inv-2", reused_token),
        ("checkout", "inv-3", fresh_token),
    ])
    ok, violations = _resume_invariants(
        first, resumed, fake,
        tokens_before_resume={reused_token},
        identities_before_resume={("checkout", "inv-1", reused_token)},
    )
    assert ok is False
    assert any("re-applied" in v for v in violations)


def test_resume_invariants_accept_legitimate_new_mutation():
    first = _state_with_confirmed_case()
    resumed = _state_with_confirmed_case()
    reused_token = "0" * 16
    fresh_token = "f" * 16
    fake = _FakeTarget([
        ("checkout", "inv-1", reused_token),
        ("checkout", "inv-2", fresh_token),
    ])
    ok, violations = _resume_invariants(
        first, resumed, fake,
        tokens_before_resume={reused_token},
        identities_before_resume={("checkout", "inv-1", reused_token)},
    )
    assert ok is True
    assert violations == []


# -- Fix 2: proof-to-case association -----------------------------------

def test_proof_association_one_to_one_valid():
    state = _state_with_confirmed_case()
    metrics = _proof_association_metrics(state)
    assert metrics["replay_valid_confirmed"] == 1
    assert metrics["confirmed_without_proof"] == []
    assert metrics["unrelated_replay_valid"] == 0
    assert metrics["duplicate_proof_records"] == 0
    assert metrics["mismatched_identity_records"] == 0


def test_proof_association_rejects_swapped_case_identity():
    state = _state_with_confirmed_case()
    # The experiment id belongs to pos-price-1 but the recorded
    # signature carries pos-coupon-1: neither identity is trusted.
    state.proof_bundles_verified[0]["signature"] = (
        "pos-coupon-1/PRICE_INTEGRITY")
    metrics = _proof_association_metrics(state)
    assert metrics["replay_valid_confirmed"] == 0
    assert metrics["mismatched_identity_records"] == 1


def test_proof_association_rejects_duplicate_bundles():
    state = _state_with_confirmed_case()
    state.proof_bundles_verified.append(
        dict(state.proof_bundles_verified[0]))
    metrics = _proof_association_metrics(state)
    assert metrics["replay_valid_confirmed"] == 1
    assert metrics["duplicate_proof_records"] == 1


def test_proof_association_rejects_unrelated_valid_bundle():
    state = _state_with_confirmed_case()
    state.proof_bundles_verified.append({
        "experiment_id": "e-somewhere-else",
        "signature": "somewhere-else/PRICE_INTEGRITY",
        "replay_valid": True,
    })
    metrics = _proof_association_metrics(state)
    assert metrics["replay_valid_confirmed"] == 1
    assert metrics["unrelated_replay_valid"] == 1


def test_proof_association_reports_missing_proof():
    state = _state_with_confirmed_case(with_proof=False)
    metrics = _proof_association_metrics(state)
    assert metrics["replay_valid_confirmed"] == 0
    assert metrics["confirmed_without_proof"] == ["pos-price-1"]


def test_unrelated_bundle_never_masks_missing_proof():
    # Regression against the old count-based metric: one unrelated
    # replay-valid record made replay_valid_confirmed equal the
    # confirmed count, hiding a case with no proof at all.
    state = _state_with_confirmed_case(with_proof=False)
    state.proof_bundles_verified.append({
        "experiment_id": "e-unrelated",
        "signature": "unrelated/PRICE_INTEGRITY",
        "replay_valid": True,
    })
    metrics = _proof_association_metrics(state)
    assert metrics["replay_valid_confirmed"] == 0
    assert metrics["confirmed_without_proof"] == ["pos-price-1"]
    assert metrics["unrelated_replay_valid"] == 1


# -- Fix 3: V3-only case resolution in the Logic Breaker port -----------

@pytest.mark.parametrize("case_id,family", [
    ("pos-idor-1", "IDOR"),
    ("neg-file-1", "BOLA"),
    ("pos-mutid-1", "MUT_IDOR"),
    ("neg-mutmulti-1", "MUT_IDOR"),
])
def test_v1_v2_ids_fail_closed_with_zero_requests(target, case_id, family):
    port = _v3_port(target)
    experiment = ProposedExperiment(
        experiment_id=f"e-{case_id}",
        family=family,
        signature=f"{case_id}/{family}",
        description="cross-version probe",
        cost=0.1,
        risk=0.1,
        gain_estimate=0.5,
        rationale="must be rejected",
        hypothesis_id=f"h-{case_id}",
    )
    with pytest.raises(ValueError, match="http-v3"):
        port.execute(experiment)
    assert port.requests_made == 0
    assert port.production_actions == 0


def test_unknown_case_id_fails_closed_with_zero_requests(target):
    port = _v3_port(target)
    experiment = ProposedExperiment(
        experiment_id="e-does-not-exist",
        family="PRICE_INTEGRITY",
        signature="does-not-exist/PRICE_INTEGRITY",
        description="unknown probe",
        cost=0.1,
        risk=0.1,
        gain_estimate=0.5,
        rationale="must be rejected",
        hypothesis_id="h-does-not-exist",
    )
    with pytest.raises(ValueError, match="http-v3"):
        port.execute(experiment)
    assert port.requests_made == 0
    assert port.production_actions == 0


# -- Fix 4: zero-confirmation metrics -----------------------------------

def _adaptive_metrics(confirmed_count: int, **overrides):
    metrics = {
        "confirmed_count": confirmed_count,
        "recall": 1.0 if confirmed_count else 0.0,
        "false_positives": 0,
        "requests_made": 20,
        "requests_per_confirmed": 10.0 if confirmed_count else None,
        "replay_valid_confirmed": confirmed_count,
        "proof_association": {
            "confirmed_without_proof": [],
            "unrelated_replay_valid": 0,
            "duplicate_proof_records": 0,
            "mismatched_identity_records": 0,
        },
    }
    metrics.update(overrides)
    return metrics


def test_thresholds_zero_confirmations_fail():
    adaptive = _adaptive_metrics(0)
    baseline = {"confirmed_count": 0, "false_positives": 0}
    assert _thresholds_pass(adaptive, baseline) is False
    # The undefined ratio is explicit, not a disguised positive number.
    assert adaptive["requests_per_confirmed"] is None


def test_thresholds_zero_requests_fail():
    adaptive = _adaptive_metrics(0, requests_made=0,
                                 requests_per_confirmed=None)
    baseline = {"confirmed_count": 0, "false_positives": 0}
    assert _thresholds_pass(adaptive, baseline) is False


def test_thresholds_positive_requests_zero_confirmations_fail():
    adaptive = _adaptive_metrics(0, requests_made=37,
                                 requests_per_confirmed=None)
    baseline = {"confirmed_count": 0, "false_positives": 0}
    assert _thresholds_pass(adaptive, baseline) is False


def test_thresholds_normal_run_passes():
    adaptive = _adaptive_metrics(2)
    baseline = {"confirmed_count": 1, "false_positives": 0}
    assert _thresholds_pass(adaptive, baseline) is True


def test_thresholds_baseline_zero_confirmations_is_legitimate():
    adaptive = _adaptive_metrics(2)
    baseline = {"confirmed_count": 0, "false_positives": 0}
    assert _thresholds_pass(adaptive, baseline) is True


def test_zero_confirmation_run_reports_undefined_metrics(monkeypatch):
    # A loop that executes requests but confirms nothing must report
    # requests_per_confirmed as None (never a positive ratio) and can
    # never pass the thresholds.
    class _StubPort:
        requests_made = 17

    class _StubOrchestrator:
        def run(self, state, max_rounds):
            return state

    monkeypatch.setattr(
        runner_module, "_build_port",
        lambda target, cases: _StubPort())
    monkeypatch.setattr(
        runner_module, "_build_orchestrator",
        lambda port, adaptive, cases: _StubOrchestrator())

    class _Target:
        target_origin = "http://127.0.0.1:9"

    _state, metrics = runner_module._run_loop(
        _Target(), adaptive=True, max_rounds=3,
        cases=HTTP_GROUND_TRUTH_V3)
    assert metrics["confirmed_count"] == 0
    assert metrics["requests_per_confirmed"] is None
    assert metrics["replay_valid_confirmed"] == 0
    assert metrics["recall"] == 0.0
    assert _thresholds_pass(metrics, metrics) is False
