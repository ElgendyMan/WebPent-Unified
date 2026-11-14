"""EGAIE real-HTTP execution: the loop runs through the production
ActionExecutor path against a controlled local HTTP target.

Red-first mission tests for EGAIE Phase 1-3 (real-target execution
and qualification). Every request travels as a CampaignTask through
RuntimeFactory-built ActionAuthority + ActionExecutor with the G-02
smart_http adapter; no raw-HTTP bypass exists in these modules.
"""
from __future__ import annotations

import json

import pytest

from webpent.autonomous.authorization import (
    EngagementAuthorization,
)
from webpent.config.settings import ScanMode, Settings
from webpent.egaie.benchmark.http_ground_truth import (
    HTTP_GROUND_TRUTH_V1,
)
from webpent.egaie.benchmark.http_runner import (
    HTTP_MIN_RECALL,
    run_http_comparison,
)
from webpent.egaie.benchmark.runner import FollowUpProposer
from webpent.egaie.http_port import (
    HTTPExperimentPort,
    build_http_experiment_port,
)
from webpent.egaie.http_target import ControlledInvestigationTarget
from webpent.egaie.persistence import load_state, save_state
from webpent.egaie.seeds import seed_state


@pytest.fixture()
def target():
    with ControlledInvestigationTarget() as server:
        yield server


def _authorization(target) -> EngagementAuthorization:
    return EngagementAuthorization(
        target_origin=target.target_origin,
        scope=(target.target_origin,),
        operator="benchmark-operator",
        authorization_reference="egaie-http-benchmark-1",
    )


def _port(target, max_actions: int = 200):
    return build_http_experiment_port(
        target=target,
        engagement_id="egaie-http-eng",
        campaign_id="egaie-http-campaign",
        authorization=_authorization(target),
        settings=Settings(
            scan_mode=ScanMode.SAFE_SMART,
            smart_max_actions=max_actions,
        ),
    )


def test_http_target_serves_deterministic_controlled_routes(target):
    status, headers, body = target.get(
        "/api/invoices/inv-1", params={"actor": "actor-a"})
    assert status == 200
    assert headers["x-actor-echo"] == "actor-a"
    assert headers["x-authorization-outcome"] == "granted_full"
    assert headers["x-resource-owner"] == "actor-b"
    assert json.loads(body)["resource_id"] == "inv-1"
    c_status, c_headers, _ = target.get(
        "/control/api/invoices/inv-1", params={"actor": "actor-a"})
    assert c_status == 403
    assert c_headers["x-authorization-outcome"] == "denied"


def test_http_port_executes_through_action_executor(target):
    port = _port(target)
    assert port.scope_allowed is True
    baseline, candidate, control = port.execute(
        seed_state(
            [HTTP_GROUND_TRUTH_V1[0]], "egaie-http-eng",
            target.target_origin,
        ).experiments[0],
    )
    for observation in (baseline, candidate, control):
        assert observation["status_code"] in (200, 403)
        assert observation["semantic_digest"]
        assert observation["request"]["method"] == "GET"
    assert candidate["headers"]["x-actor-echo"] == "actor-a"
    assert port.production_actions >= 3
    assert port.denied_actions == 0


def test_http_candidate_observation_is_real_response_digest(target):
    port = _port(target)
    experiment = seed_state(
        [HTTP_GROUND_TRUTH_V1[0]], "egaie-http-eng",
        target.target_origin,
    ).experiments[0]
    _, candidate, _ = port.execute(experiment)
    _, headers, body = target.get(
        "/api/invoices/inv-1", params={"actor": "actor-a"})
    import hashlib
    assert candidate["semantic_digest"] == hashlib.sha256(
        body.encode("utf-8")).hexdigest()


def test_adaptive_http_confirms_positives_with_replay_valid_bundles(
        target):
    port = _port(target)
    state = seed_state(
        list(HTTP_GROUND_TRUTH_V1), "egaie-http-eng",
        target.target_origin,
    )
    from webpent.egaie.benchmark.runner import FollowUpProposer
    from webpent.egaie.causal_adapter import CausalValidationPort
    from webpent.egaie.http_port import HTTPProofBundlePort
    from webpent.egaie.orchestrator import InvestigationOrchestrator

    class Ledger:
        def propose(self, state):
            return []

        def update(self, state, experiment, observations, causal):
            return {"world_model": [], "attack_graph": []}

    orchestrator = InvestigationOrchestrator(
        experiment_port=port,
        validation_port=CausalValidationPort(),
        proof_port=HTTPProofBundlePort(),
        model_port=Ledger(),
        proposer=FollowUpProposer(),
    )
    result = orchestrator.run(state, max_rounds=14)
    confirmed = [
        h for h in result.hypotheses
        if h.status.value == "confirmed"
    ]
    confirmed_ids = sorted(h.origin for h in confirmed)
    assert [cid for cid in confirmed_ids if cid.startswith("pos-")] == [
        "pos-authbypass-1", "pos-bola-1", "pos-idor-1", "pos-multi-1",
    ]
    negatives = [cid for cid in confirmed_ids
                 if cid.startswith("neg-")]
    assert negatives == []
    assert result.proof_bundles_verified, "no bundle verified"
    for bundle_record in result.proof_bundles_verified:
        assert bundle_record["replay_valid"] is True
        assert bundle_record["runtime_provenance"]["offline"] is False
        assert bundle_record["runtime_provenance"][
            "transport"] == "action_executor"


def test_http_negative_controls_stay_negative(target):
    port = _port(target)
    negatives = [
        case for case in HTTP_GROUND_TRUTH_V1
        if case.case_id.startswith("neg-")
    ]
    experiment = seed_state(
        negatives, "egaie-http-eng", target.target_origin,
    ).experiments[0]
    baseline, candidate, control = port.execute(experiment)
    from webpent.egaie.causal_adapter import CausalValidationPort
    verdict = CausalValidationPort().validate(
        baseline, candidate, control)["verdict"]
    assert verdict == "clean"


def test_http_inconclusive_stage1_then_stage2_confirms(target):
    port = _port(target)
    multi = [
        case for case in HTTP_GROUND_TRUTH_V1
        if case.multi_step
    ]
    state = seed_state(
        multi, "egaie-http-eng", target.target_origin,
    )
    stage1 = state.experiments[0]
    baseline, candidate, control = port.execute(stage1)
    from webpent.egaie.causal_adapter import CausalValidationPort
    verdict = CausalValidationPort().validate(
        baseline, candidate, control)["verdict"]
    assert verdict == "inconclusive"
    state.mark_experiment_outcome(stage1.experiment_id, "inconclusive")
    proposals = FollowUpProposer().propose(state)
    assert proposals, "no stage2 proposed"
    b2, c2, k2 = port.execute(proposals[0])
    verdict2 = CausalValidationPort().validate(b2, c2, k2)["verdict"]
    assert verdict2 == "confirmed"
    assert port.requests_made >= 6


def test_http_scope_denial_is_fail_closed(target):
    wrong_authorization = EngagementAuthorization(
        target_origin="http://127.0.0.1:9",
        scope=("http://127.0.0.1:9",),
        operator="benchmark-operator",
        authorization_reference="egaie-http-wrong",
    )
    port = HTTPExperimentPort(
        target=target,
        engagement_id="egaie-http-eng",
        campaign_id="egaie-http-campaign",
        authorization=wrong_authorization,
        settings=Settings(scan_mode=ScanMode.SAFE_SMART),
    )
    assert port.scope_allowed is False
    state = seed_state(
        list(HTTP_GROUND_TRUTH_V1), "egaie-http-eng",
        target.target_origin,
    )
    from webpent.egaie.benchmark.runner import FollowUpProposer
    from webpent.egaie.causal_adapter import CausalValidationPort
    from webpent.egaie.http_port import HTTPProofBundlePort
    from webpent.egaie.orchestrator import InvestigationOrchestrator

    class Ledger:
        def propose(self, state):
            return []

        def update(self, state, experiment, observations, causal):
            return {"world_model": [], "attack_graph": []}

    orchestrator = InvestigationOrchestrator(
        experiment_port=port,
        validation_port=CausalValidationPort(),
        proof_port=HTTPProofBundlePort(),
        model_port=Ledger(),
        proposer=FollowUpProposer(),
    )
    result = orchestrator.run(state, max_rounds=14)
    assert result.terminal_reason == "scope_denied"
    assert port.requests_made == 0


def test_http_budget_exhaustion_is_deterministic_terminal(target):
    port = _port(target, max_actions=3)
    state = seed_state(
        list(HTTP_GROUND_TRUTH_V1), "egaie-http-eng",
        target.target_origin,
    )
    from webpent.egaie.benchmark.runner import FollowUpProposer
    from webpent.egaie.causal_adapter import CausalValidationPort
    from webpent.egaie.http_port import HTTPProofBundlePort
    from webpent.egaie.orchestrator import InvestigationOrchestrator

    class Ledger:
        def propose(self, state):
            return []

        def update(self, state, experiment, observations, causal):
            return {"world_model": [], "attack_graph": []}

    orchestrator = InvestigationOrchestrator(
        experiment_port=port,
        validation_port=CausalValidationPort(),
        proof_port=HTTPProofBundlePort(),
        model_port=Ledger(),
        proposer=FollowUpProposer(),
    )
    result = orchestrator.run(state, max_rounds=14)
    assert port.denied_actions >= 1
    assert result.terminal_reason in (
        "action_budget_exhausted", "round_budget_exhausted",
    )


def test_http_resume_does_not_repeat_confirmed_work(target):
    port = _port(target)
    state = seed_state(
        list(HTTP_GROUND_TRUTH_V1), "egaie-http-eng",
        target.target_origin,
    )
    from webpent.egaie.benchmark.runner import FollowUpProposer
    from webpent.egaie.causal_adapter import CausalValidationPort
    from webpent.egaie.http_port import HTTPProofBundlePort
    from webpent.egaie.orchestrator import InvestigationOrchestrator

    class Ledger:
        def propose(self, state):
            return []

        def update(self, state, experiment, observations, causal):
            return {"world_model": [], "attack_graph": []}

    def build():
        return InvestigationOrchestrator(
            experiment_port=port,
            validation_port=CausalValidationPort(),
            proof_port=HTTPProofBundlePort(),
            model_port=Ledger(),
            proposer=FollowUpProposer(),
        )

    first = build().run(state, max_rounds=3)
    import pathlib as _pl
    path = _pl.Path("/tmp/egaie_http_resume_state.json")
    save_state(first, path)
    restored = load_state(path)
    before = port.requests_made
    second = build().run(restored, max_rounds=14)
    confirmed_first = sorted(
        h.origin for h in first.hypotheses
        if h.status.value == "confirmed"
    )
    confirmed_second = sorted(
        h.origin for h in second.hypotheses
        if h.status.value == "confirmed"
    )
    assert set(confirmed_first) <= set(confirmed_second)
    assert port.requests_made >= before


def test_http_benchmark_comparison_meets_declared_thresholds(target):
    report = run_http_comparison(target, max_rounds=14, repetitions=2)
    data = report.to_dict()
    assert data["thresholds_pass"] is True
    adaptive = data["adaptive"]
    assert adaptive["recall"] >= HTTP_MIN_RECALL
    assert adaptive["false_positives"] == 0
    assert adaptive["replay_valid_confirmed"] == adaptive[
        "confirmed_count"]
    assert adaptive["requests_per_confirmed"] > 0
    assert data["reproducible"] is True
    baseline = data["baseline"]
    assert baseline["false_positives"] == 0
    assert adaptive["confirmed_count"] > baseline["confirmed_count"]
