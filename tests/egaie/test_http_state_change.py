"""EGAIE state-changing HTTP families: POST probes through the
production ActionExecutor path.

Red-first mission tests for v0.14.0 (state-changing families). Every
mutating request travels as a CampaignTask through RuntimeFactory-built
ActionAuthority + ActionExecutor with the G-02 smart_http adapter under
ScanMode.AUTHORIZED_ACTIVE with explicit per-task human approval: the
production contract for active actions, not a bypass of it. Without
that mode and approval the authority must deny the write fail-closed.

Application-level idempotency: the target applies each mutation at
most once per idempotency token, so a resumed investigation can never
double-apply a completed non-idempotent action.
"""
from __future__ import annotations

import json

import pytest

from webpent.autonomous.authorization import EngagementAuthorization
from webpent.config.settings import ScanMode, Settings
from webpent.egaie.benchmark.http_ground_truth import (
    HTTP_GROUND_TRUTH_V2,
    HTTP_GROUND_TRUTH_VERSION_V2,
)
from webpent.egaie.benchmark.http_runner import run_http_comparison
from webpent.egaie.causal_adapter import CausalValidationPort
from webpent.egaie.http_port import HTTPProofBundlePort, build_http_experiment_port
from webpent.egaie.http_target import ControlledInvestigationTarget
from webpent.egaie.orchestrator import InvestigationOrchestrator
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
        authorization_reference="egaie-http-benchmark-v2",
    )


def _active_port(target, max_actions: int = 200):
    return build_http_experiment_port(
        target=target,
        engagement_id="egaie-http-eng-v2",
        campaign_id="egaie-http-campaign-v2",
        authorization=_authorization(target),
        settings=Settings(
            scan_mode=ScanMode.AUTHORIZED_ACTIVE,
            smart_max_actions=max_actions,
        ),
    )


def _orchestrator(port):
    from webpent.egaie.benchmark.runner import FollowUpProposer
    from webpent.egaie.selection import InformationGainSelector

    class Ledger:
        def propose(self, state):
            return []

        def update(self, state, experiment, observations, causal):
            return {"world_model": [], "attack_graph": []}

    return InvestigationOrchestrator(
        experiment_port=port,
        validation_port=CausalValidationPort(),
        proof_port=HTTPProofBundlePort(),
        model_port=Ledger(),
        selector=InformationGainSelector(),
        proposer=FollowUpProposer(),
    )


def test_post_target_serves_deterministic_mutating_routes(target):
    # Defective mutating route: cross-owner payment succeeds.
    status, headers, body = target.post(
        "/api/payments/inv-1",
        params={"actor": "actor-a", "idem": "tok-1"},
    )
    assert status == 200
    assert headers["x-authorization-outcome"] == "granted_full"
    assert headers["x-resource-owner"] == "actor-b"
    assert json.loads(body)["paid"] is True
    # Effect observable through a subsequent real GET on the resource.
    g_status, _, g_body = target.get(
        "/api/invoices/inv-1", params={"actor": "actor-a"})
    assert g_status == 200
    assert json.loads(g_body)["paid"] is True
    # Enforced control route denies the same cross-owner mutation.
    c_status, c_headers, _ = target.post(
        "/control/api/payments/inv-1",
        params={"actor": "actor-a", "idem": "tok-2"},
    )
    assert c_status == 403
    assert c_headers["x-authorization-outcome"] == "denied"
    g2_status, _, g2_body = target.get(
        "/api/invoices/inv-1", params={"actor": "actor-a"})
    assert json.loads(g2_body)["paid"] is True  # only the first apply


def test_post_mutation_is_idempotent_per_token(target):
    first_status, _, first_body = target.post(
        "/api/payments/inv-1", params={"actor": "actor-a", "idem": "tok-9"})
    assert first_status == 200 and json.loads(first_body)["applied"] is True
    replay_status, _, replay_body = target.post(
        "/api/payments/inv-1", params={"actor": "actor-a", "idem": "tok-9"})
    assert replay_status == 200
    assert json.loads(replay_body)["applied"] is False
    assert json.loads(replay_body)["paid"] is True
    assert target.applied_mutation_count() == 1


def test_charge_route_generic_response_requires_followup(target):
    # Multi-step mutating family: the charge route applies a cross-owner
    # charge but answers with a generic receipt that carries no
    # ownership context, so a single observation cannot confirm the
    # defect; the effect is only observable through a follow-up GET.
    status, headers, body = target.post(
        "/api/charges/inv-1",
        params={"actor": "actor-a", "idem": "tok-c1"},
    )
    assert status == 200
    assert headers["x-authorization-outcome"] == "granted_full"
    assert "x-resource-owner" not in headers
    structured = json.loads(body)
    assert structured["resource_path"] == "/api/invoices/inv-1"
    g_status, _, g_body = target.get(
        "/api/invoices/inv-1", params={"actor": "actor-a"})
    assert g_status == 200
    assert json.loads(g_body)["paid"] is True
    # The attacker's own twin charge answers with the same generic
    # shape; the follow-up GET reveals legitimate ownership there.
    own_status, own_headers, own_body = target.post(
        "/api/charges/inv-2", params={"actor": "actor-a", "idem": "tok-c2"})
    assert own_status == 200
    assert "x-resource-owner" not in own_headers
    assert json.loads(own_body)["resource_path"] == "/api/invoices/inv-2"
    twin_status, _, twin_body = target.get(
        "/api/invoices/inv-2", params={"actor": "actor-a"})
    assert twin_status == 200
    assert json.loads(twin_body)["owner"] == "actor-a"
    # Enforced control route denies the same cross-owner charge.
    c_status, c_headers, _ = target.post(
        "/control/api/charges/inv-1", params={"actor": "actor-a"})
    assert c_status == 403
    assert c_headers["x-authorization-outcome"] == "denied"


def test_post_port_executes_through_action_executor(target):
    port = _active_port(target)
    assert port.scope_allowed is True
    experiment = seed_state(
        [HTTP_GROUND_TRUTH_V2[0]], "egaie-http-eng-v2",
        target.target_origin,
    ).experiments[0]
    baseline, candidate, control = port.execute(experiment)
    for observation in (baseline, candidate, control):
        assert observation["status_code"] in (200, 403)
        assert observation["semantic_digest"]
        assert observation["request"]["method"] == "POST"
    assert candidate["headers"]["x-authorization-outcome"] == "granted_full"
    assert candidate["headers"]["x-resource-owner"] == "actor-b"
    assert port.production_actions >= 3
    assert port.denied_actions == 0
    # The candidate's own response body carries the observed effect.
    assert candidate["structured"]["paid"] is True


def test_state_change_confirmed_with_replay_valid_bundle(target):
    port = _active_port(target)
    state = seed_state(
        list(HTTP_GROUND_TRUTH_V2), "egaie-http-eng-v2",
        target.target_origin,
    )
    result = _orchestrator(port).run(state, max_rounds=14)
    confirmed = sorted(
        h.origin for h in result.hypotheses
        if h.status.value == "confirmed"
    )
    assert [cid for cid in confirmed if cid.startswith("pos-")] == [
        "pos-mutid-1",
        "pos-mutmulti-1",
    ]
    assert [cid for cid in confirmed if cid.startswith("neg-")] == []
    assert result.proof_bundles_verified, "no bundle verified"
    for bundle_record in result.proof_bundles_verified:
        assert bundle_record["replay_valid"] is True
        assert bundle_record["runtime_provenance"]["offline"] is False


def test_state_change_negative_control_verdict_is_clean(target):
    port = _active_port(target)
    negatives = [
        case for case in HTTP_GROUND_TRUTH_V2
        if case.case_id.startswith("neg-")
    ]
    experiment = seed_state(
        negatives, "egaie-http-eng-v2", target.target_origin,
    ).experiments[0]
    baseline, candidate, control = port.execute(experiment)
    verdict = CausalValidationPort().validate(
        baseline, candidate, control)["verdict"]
    assert verdict == "clean"


def test_write_is_fail_closed_without_active_mode_or_approval(target):
    # SAFE_SMART mode: the authority must deny the POST before any
    # handler runs, and the target state must be unchanged.
    port = build_http_experiment_port(
        target=target,
        engagement_id="egaie-http-eng-v2",
        campaign_id="egaie-http-campaign-v2",
        authorization=_authorization(target),
        settings=Settings(
            scan_mode=ScanMode.SAFE_SMART, smart_max_actions=200,
        ),
    )
    experiment = seed_state(
        [HTTP_GROUND_TRUTH_V2[0]], "egaie-http-eng-v2",
        target.target_origin,
    ).experiments[0]
    baseline, candidate, control = port.execute(experiment)
    assert port.production_actions == 0
    assert port.denied_actions >= 1
    for observation in (baseline, candidate, control):
        assert observation["status_code"] is None
        assert observation["_placeholder"] is True
    _, _, body = target.get("/api/invoices/inv-1", params={"actor": "actor-a"})
    assert json.loads(body)["paid"] is False


def test_resume_never_double_applies_mutation(target):
    port = _active_port(target)
    state = seed_state(
        list(HTTP_GROUND_TRUTH_V2), "egaie-http-eng-v2",
        target.target_origin,
    )
    first = _orchestrator(port).run(state, max_rounds=2)
    from pathlib import Path

    from webpent.egaie.persistence import load_state, save_state
    path = Path("/tmp/egaie_http_v2_resume_state.json")
    save_state(first, path)
    restored = load_state(path)
    _orchestrator(port).run(restored, max_rounds=14)
    # Each mutating family applied exactly once to the victim despite
    # the resume: the payment mutation and the (multi-step) charge
    # mutation are distinct applications, and neither is ever repeated.
    assert target.applied_count_for_family("payment", "inv-1") == 1
    assert target.applied_count_for_family("charge", "inv-1") == 1


def test_state_change_benchmark_comparison_meets_thresholds(target):
    report = run_http_comparison(
        target, max_rounds=14, repetitions=2,
        cases=HTTP_GROUND_TRUTH_V2,
    )
    data = report.to_dict()
    assert data["ground_truth_version"] == HTTP_GROUND_TRUTH_VERSION_V2
    assert data["thresholds_pass"] is True
    adaptive = data["adaptive"]
    assert adaptive["confirmed_case_ids"] == [
        "pos-mutid-1", "pos-mutmulti-1"]
    assert adaptive["false_positives"] == 0
    assert adaptive["replay_valid_confirmed"] == adaptive[
        "confirmed_count"]
    assert adaptive["requests_per_confirmed"] > 0
    assert data["reproducible"] is True
    assert data["resume_correct"] is True
    baseline = data["baseline"]
    assert baseline["false_positives"] == 0
    assert adaptive["confirmed_count"] > baseline["confirmed_count"]
