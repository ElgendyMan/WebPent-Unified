"""EGAIE Logic Breaker: evidence-grounded price-integrity hunting.

Red-first mission tests for the first Logic Breaker capability on
EGAIE (http-v3, family PRICE_INTEGRITY) against the controlled loopback
target. Every mutating request travels as a CampaignTask through the
production RuntimeFactory-built ActionAuthority + ActionExecutor with
the G-02 smart_http adapter under ScanMode.AUTHORIZED_ACTIVE with
explicit per-task human approval; without that mode the authority must
deny the write fail-closed. Confirmation requires an independent
invariant oracle plus a sealed proof bundle that replays valid through
an independent re-run of the same oracle on reloaded evidence:
missing data is never interpreted as success, and ground-truth labels
are never available to the oracle at runtime.

Application-level idempotency: the target applies each mutation at
most once, so a resumed investigation can never double-apply a
completed non-idempotent state change.
"""
from __future__ import annotations

import dataclasses
import json
from pathlib import Path

import pytest

from webpent.autonomous.authorization import EngagementAuthorization
from webpent.config.settings import ScanMode, Settings
from webpent.egaie.benchmark.http_ground_truth import (
    HTTP_GROUND_TRUTH_V3,
    HTTP_GROUND_TRUTH_VERSION_V3,
)
from webpent.egaie.benchmark.http_runner import run_http_comparison
from webpent.egaie.finding_bridge import logic_findings_from_state
from webpent.egaie.http_target import ControlledInvestigationTarget
from webpent.egaie.logic_port import (
    InvariantValidationPort,
    LogicFollowUpProposer,
    LogicProofBundlePort,
    build_logic_experiment_port,
)
from webpent.egaie.orchestrator import InvestigationOrchestrator
from webpent.egaie.seeds import seed_state
from webpent.models.findings import VulnClass


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


def _active_port(target, max_actions: int = 200):
    return build_logic_experiment_port(
        target=target,
        engagement_id="egaie-logic-eng-v3",
        campaign_id="egaie-logic-campaign-v3",
        authorization=_authorization(target),
        settings=Settings(
            scan_mode=ScanMode.AUTHORIZED_ACTIVE,
            smart_max_actions=max_actions,
        ),
    )


def _safe_port(target, max_actions: int = 200):
    return build_logic_experiment_port(
        target=target,
        engagement_id="egaie-logic-eng-v3",
        campaign_id="egaie-logic-campaign-v3",
        authorization=_authorization(target),
        settings=Settings(
            scan_mode=ScanMode.SAFE_SMART, smart_max_actions=max_actions,
        ),
    )


def _orchestrator(port):
    from webpent.egaie.selection import InformationGainSelector

    class Ledger:
        def propose(self, state):
            return []

        def update(self, state, experiment, observations, causal):
            return {"world_model": [], "attack_graph": []}

    return InvestigationOrchestrator(
        experiment_port=port,
        validation_port=InvariantValidationPort(),
        proof_port=LogicProofBundlePort(),
        model_port=Ledger(),
        selector=InformationGainSelector(),
        proposer=LogicFollowUpProposer(),
    )


def test_price_target_serves_deterministic_pricing_routes(target):
    # The server-authoritative price is observable on the invoice.
    status, _, body = target.get(
        "/api/invoices/inv-1", params={"actor": "actor-a"})
    assert status == 200
    assert json.loads(body)["price"] == 10000

    # Defective checkout: a client-controlled price overrides the
    # server price on a cross-owner checkout.
    status, headers, body = target.post(
        "/api/checkout/inv-1",
        params={"actor": "actor-a", "idem": "tok-1", "price": "1337"},
    )
    assert status == 200
    assert headers["x-authorization-outcome"] == "granted_full"
    assert headers["x-resource-owner"] == "actor-b"
    data = json.loads(body)
    assert data["authoritative_total"] == 10000
    assert data["charged"] == 1337
    assert data["applied"] is True
    assert data["order_id"] == "ord-inv-1"
    order = json.loads(target.get(
        "/api/orders/ord-inv-1", params={"actor": "actor-a"})[2])
    assert order["charged"] == 1337
    assert order["authoritative_total"] == 10000

    # Legitimate self-checkout without a price override charges the
    # authoritative amount.
    status, _, body = target.post(
        "/api/checkout/inv-2", params={"actor": "actor-a", "idem": "tok-2"})
    assert status == 200
    data = json.loads(body)
    assert data["charged"] == data["authoritative_total"] == 5000

    # Enforced control route denies the same cross-owner checkout.
    c_status, c_headers, _ = target.post(
        "/control/api/checkout/inv-1",
        params={"actor": "actor-a", "idem": "tok-3", "price": "1337"},
    )
    assert c_status == 403
    assert c_headers["x-authorization-outcome"] == "denied"

    # The enforcing sibling route rejects a tampered price even from
    # the invoice's own owner, and rejects cross-owner use outright.
    t_status, _, t_body = target.post(
        "/api/till/inv-2", params={"actor": "actor-a", "price": "1337"})
    assert t_status == 409
    assert json.loads(t_body)["error"] == "price_mismatch"
    x_status, _, _ = target.post(
        "/api/till/inv-1", params={"actor": "actor-a", "price": "1337"})
    assert x_status == 403


def test_coupon_surface_is_deterministic_and_generic(target):
    # Defective multi-step coupon route: applies a registered coupon
    # across owners and answers with a generic receipt that carries no
    # ownership or pricing context.
    status, headers, body = target.post(
        "/api/coupons/inv-1",
        params={"actor": "actor-a", "idem": "tok-4", "code": "SAFE10"},
    )
    assert status == 200
    assert headers["x-authorization-outcome"] == "granted_full"
    receipt = json.loads(body)
    assert receipt["status"] == "accepted"
    assert receipt["coupon_id"] == "cpn-inv-1"
    assert receipt["resource_path"] == "/api/orders/ord-inv-1"
    assert "charged" not in receipt
    assert "owner" not in receipt

    # The pricing violation is only observable through a follow-up GET
    # on the revealed order: the discount was applied by a non-owner.
    order = json.loads(target.get(
        "/api/orders/ord-inv-1", params={"actor": "actor-a"})[2])
    assert order["owner"] == "actor-b"
    assert order["charged"] == order["authoritative_total"] == 9000
    assert order["discount_code"] == "SAFE10"
    assert order["discount_applied_by"] == "actor-a"

    # Unregistered codes are rejected without any state change.
    u_status, _, _ = target.post(
        "/api/coupons/inv-1",
        params={"actor": "actor-a", "idem": "tok-5", "code": "FAKE99"},
    )
    assert u_status == 400

    # The enforced control route denies the same cross-owner coupon.
    c_status, c_headers, _ = target.post(
        "/control/api/coupons/inv-1",
        params={"actor": "actor-a", "idem": "tok-6", "code": "SAFE10"},
    )
    assert c_status == 403
    assert c_headers["x-authorization-outcome"] == "denied"


def test_price_mutation_is_idempotent_per_token(target):
    first_status, _, first_body = target.post(
        "/api/checkout/inv-1",
        params={"actor": "actor-a", "idem": "tok-9", "price": "1337"},
    )
    assert first_status == 200
    assert json.loads(first_body)["applied"] is True
    replay_status, _, replay_body = target.post(
        "/api/checkout/inv-1",
        params={"actor": "actor-a", "idem": "tok-9", "price": "1337"},
    )
    assert replay_status == 200
    assert json.loads(replay_body)["applied"] is False
    assert json.loads(replay_body)["charged"] == 1337
    assert target.applied_count_for_family("checkout", "inv-1") == 1

    c_first_status, _, c_first_body = target.post(
        "/api/coupons/inv-2",
        params={"actor": "actor-a", "idem": "tok-10", "code": "SAFE10"},
    )
    assert c_first_status == 200
    assert json.loads(c_first_body)["status"] == "accepted"
    c_replay_status, _, _ = target.post(
        "/api/coupons/inv-2",
        params={"actor": "actor-a", "idem": "tok-10", "code": "SAFE10"},
    )
    assert c_replay_status == 200
    assert target.applied_count_for_family("coupon", "inv-2") == 1
    assert target.applied_mutation_count() == 2


def test_logic_port_executes_through_action_executor(target):
    port = _active_port(target)
    assert port.scope_allowed is True
    experiment = seed_state(
        [HTTP_GROUND_TRUTH_V3[0]], "egaie-logic-eng-v3",
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
    # The candidate's own response carries the price-integrity
    # violation the invariant oracle will judge.
    assert candidate["structured"]["charged"] == 1337
    assert candidate["structured"]["authoritative_total"] == 10000


def test_price_integrity_confirmed_with_replay_valid_bundle(target):
    port = _active_port(target)
    state = seed_state(
        list(HTTP_GROUND_TRUTH_V3), "egaie-logic-eng-v3",
        target.target_origin,
    )
    result = _orchestrator(port).run(state, max_rounds=14)
    confirmed = sorted(
        h.origin for h in result.hypotheses
        if h.status.value == "confirmed"
    )
    assert confirmed == ["pos-coupon-1", "pos-price-1"]
    assert result.proof_bundles_verified, "no bundle verified"
    for bundle_record in result.proof_bundles_verified:
        assert bundle_record["replay_valid"] is True
        assert bundle_record["runtime_provenance"]["offline"] is False


def test_invariant_oracle_verdicts_are_fail_closed():
    oracle = InvariantValidationPort()

    def executed(structured, status_code=200):
        return {
            "execution": "executed",
            "status_code": status_code,
            "request": {"method": "POST", "path": "/api/x"},
            "structured": structured,
        }

    def denied():
        return {
            "_placeholder": True,
            "execution": "denied_by_authority",
            "status_code": None,
            "structured": {},
        }

    # Nothing executed: the authority denied everything -> BLOCKED.
    verdict = oracle.validate(denied(), denied(), denied())["verdict"]
    assert verdict == "blocked"

    # Partial evidence: missing data is never interpreted as success.
    verdict = oracle.validate(
        denied(),
        executed({"authoritative_total": 10000, "charged": 1337}),
        executed({}, status_code=403),
    )["verdict"]
    assert verdict == "inconclusive"

    # An accepted mutation whose response carries no pricing evidence
    # (generic receipt) is inconclusive, not clean.
    verdict = oracle.validate(
        executed({"status": "accepted", "resource_path": "/api/orders/x"}),
        executed({"status": "accepted", "resource_path": "/api/orders/x"}),
        executed({}, status_code=403),
    )["verdict"]
    assert verdict == "inconclusive"

    # A client-controlled price that overrides the authoritative
    # server price is confirmed, with the violated predicate named.
    result = oracle.validate(
        executed({"authoritative_total": 5000, "charged": 5000}),
        executed({"authoritative_total": 10000, "charged": 1337,
                  "applied": True}),
        executed({}, status_code=403),
    )
    assert result["verdict"] == "confirmed"
    assert "amount_mismatch" in result["violated_predicates"]

    # A discount applied by a non-owner violates pricing authority.
    result = oracle.validate(
        executed({"authoritative_total": 5000, "charged": 5000}),
        executed({"authoritative_total": 9000, "charged": 9000,
                  "discount_code": "SAFE10",
                  "discount_applied_by": "actor-a", "owner": "actor-b",
                  "applied": True}),
        executed({}, status_code=403),
    )
    assert result["verdict"] == "confirmed"
    assert "unauthorized_discount" in result["violated_predicates"]

    # Compliant pricing: charged matches the authoritative total and
    # any discount was applied by the owner.
    verdict = oracle.validate(
        executed({"authoritative_total": 9000, "charged": 9000,
                  "discount_code": "SAFE10",
                  "discount_applied_by": "actor-a", "owner": "actor-a",
                  "applied": True}),
        executed({"authoritative_total": 9000, "charged": 9000,
                  "discount_code": "SAFE10",
                  "discount_applied_by": "actor-a", "owner": "actor-a",
                  "applied": True}),
        executed({}, status_code=403),
    )["verdict"]
    assert verdict == "clean"

    # A denied candidate accepted nothing: clean.
    verdict = oracle.validate(
        executed({"error": "price_mismatch"}, status_code=409),
        executed({"error": "forbidden"}, status_code=403),
        executed({"error": "forbidden"}, status_code=403),
    )["verdict"]
    assert verdict == "clean"


def test_price_write_is_fail_closed_without_active_mode(target):
    # SAFE_SMART mode: the authority must deny the POST before any
    # handler runs, and the target order state must be unchanged.
    port = _safe_port(target)
    experiment = seed_state(
        [HTTP_GROUND_TRUTH_V3[0]], "egaie-logic-eng-v3",
        target.target_origin,
    ).experiments[0]
    baseline, candidate, control = port.execute(experiment)
    assert port.production_actions == 0
    assert port.denied_actions >= 1
    for observation in (baseline, candidate, control):
        assert observation["status_code"] is None
        assert observation["_placeholder"] is True
    _, _, body = target.get(
        "/api/orders/ord-inv-1", params={"actor": "actor-a"})
    order = json.loads(body)
    assert order["charged"] == 10000
    assert order["discount_code"] is None


def test_logic_resume_never_double_applies_mutation(target):
    port = _active_port(target)
    state = seed_state(
        list(HTTP_GROUND_TRUTH_V3), "egaie-logic-eng-v3",
        target.target_origin,
    )
    first = _orchestrator(port).run(state, max_rounds=2)
    from webpent.egaie.persistence import load_state, save_state
    path = Path("/tmp/egaie_logic_v3_resume_state.json")
    save_state(first, path)
    restored = load_state(path)
    _orchestrator(port).run(restored, max_rounds=14)
    # Each mutating family applied exactly once to the victim despite
    # the resume: the checkout price override and the coupon
    # application are distinct applications, and neither repeats.
    assert target.applied_count_for_family("checkout", "inv-1") == 1
    assert target.applied_count_for_family("coupon", "inv-1") == 1


def test_logic_benchmark_comparison_meets_thresholds(target):
    report = run_http_comparison(
        target, max_rounds=14, repetitions=2,
        cases=HTTP_GROUND_TRUTH_V3,
    )
    data = report.to_dict()
    assert data["ground_truth_version"] == HTTP_GROUND_TRUTH_VERSION_V3
    assert data["thresholds_pass"] is True
    adaptive = data["adaptive"]
    assert adaptive["confirmed_case_ids"] == [
        "pos-coupon-1", "pos-price-1"]
    assert adaptive["false_positives"] == 0
    assert adaptive["replay_valid_confirmed"] == adaptive[
        "confirmed_count"]
    assert adaptive["requests_per_confirmed"] > 0
    assert data["reproducible"] is True
    assert data["resume_correct"] is True
    baseline = data["baseline"]
    assert baseline["false_positives"] == 0
    assert adaptive["confirmed_count"] > baseline["confirmed_count"]


def test_logic_proof_bundle_rejects_tampering_and_mismatched_identity(
    target,
):
    port = _active_port(target)
    experiment = seed_state(
        [HTTP_GROUND_TRUTH_V3[0]], "egaie-logic-eng-v3",
        target.target_origin,
    ).experiments[0]
    baseline, candidate, control = port.execute(experiment)
    causal = InvariantValidationPort().validate(
        baseline, candidate, control)
    assert causal["verdict"] == "confirmed"

    proof_port = LogicProofBundlePort()
    bundle = proof_port.build(
        experiment, baseline, candidate, control, causal)
    verified = proof_port.verify(bundle)
    assert verified["replay_valid"] is True
    assert verified["seal_valid"] is True
    assert verified["verdict_match"] is True
    assert verified["digest_match"] is True

    # Tampering with the candidate evidence must fail verification:
    # the stored digests and seal no longer match the re-run evidence.
    tampered = dataclasses.replace(
        bundle,
        candidate={**bundle.candidate, "charged": 4242},
    )
    tampered_result = proof_port.verify(tampered)
    assert tampered_result["replay_valid"] is False

    # A bundle from a different engagement identity must be rejected.
    stranger = LogicProofBundlePort(
        expected_target_identity="egaie:OTHER_FAMILY",
    )
    assert stranger.verify(bundle)["replay_valid"] is False


def test_logic_finding_bridge_promotes_only_reportable_results(target):
    port = _active_port(target)
    state = seed_state(
        list(HTTP_GROUND_TRUTH_V3), "egaie-logic-eng-v3",
        target.target_origin,
    )
    result = _orchestrator(port).run(state, max_rounds=14)

    findings = logic_findings_from_state(result, target.target_origin)
    assert len(findings) == 2
    titles = sorted(f.title for f in findings)
    assert any("pos-coupon-1" in t for t in titles)
    assert any("pos-price-1" in t for t in titles)
    for finding in findings:
        # L4 audit: pricing-invariant violation is business logic
        # (VulnClass.UNKNOWN, explicitly typed in title/reasoning),
        # never an authorization bypass. The original auth_bypass
        # assertion encoded the mislabel and was superseded by the
        # L4 finding-semantics decision.
        assert finding.vuln_class == VulnClass.UNKNOWN
        assert finding.vuln_class != "auth_bypass"
        assert finding.severity == "high"
        assert target.target_origin in finding.url

    from webpent.egaie.schemas import InvestigationState

    # A bundle record that failed replay must never reach a Finding.
    tampered_state = InvestigationState.from_dict(result.to_dict())
    tampered_state.proof_bundles_verified[0]["replay_valid"] = False
    assert len(
        logic_findings_from_state(
            tampered_state, target.target_origin),
    ) == 1

    # A blocked or inconclusive investigation produces no findings.
    empty_state = seed_state(
        [HTTP_GROUND_TRUTH_V3[0]], "egaie-logic-eng-v3",
        target.target_origin,
    )
    assert logic_findings_from_state(
        empty_state, target.target_origin) == []


def test_logic_finding_semantics_are_price_integrity_not_auth_bypass(
    target,
):
    """L4 audit regression: a pricing-invariant violation is business
    logic, not an authorization bypass. The bridge must never export
    it as auth_bypass (the invariant oracle verified pricing
    predicates only; no authorization-boundary evidence was gathered),
    and must not fabricate a vuln_class member the taxonomy does not
    support. The price-integrity typing must survive explicitly in
    the finding's title and reasoning."""
    port = _active_port(target)
    state = seed_state(
        list(HTTP_GROUND_TRUTH_V3), "egaie-logic-eng-v3",
        target.target_origin,
    )
    result = _orchestrator(port).run(state, max_rounds=14)
    findings = logic_findings_from_state(result, target.target_origin)
    assert findings
    for finding in findings:
        # Never an authorization bypass: pricing evidence only.
        assert finding.vuln_class != VulnClass.AUTH_BYPASS
        # An existing supported taxonomy member, not a fabricated one.
        assert finding.vuln_class == VulnClass.UNKNOWN
        # Explicit business-logic typing is preserved, not lost.
        assert "price integrity" in finding.title.lower()
        assert finding.reasoning.startswith(
            "Price-integrity logic verdict")
        assert (
            "amount_mismatch" in finding.reasoning
            or "unauthorized_discount" in finding.reasoning
        )
        assert finding.severity == "high"
