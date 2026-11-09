from __future__ import annotations

import json
from pathlib import Path

import httpx

from webpent.production.production_spine import ProductionSpineError, ProductionTrace
from webpent.shared.engagement_audit import EngagementAuditChain
from webpent.recon import login_executor as login_executor_module
from webpent.recon.auth_detector import AuthDetection, AuthSignal
from webpent.recon.login_executor import LoginExecutor
from webpent.cli.loaders import load_creds_file
from webpent.agents.hunter_contracts import ExploitationResult, HunterState, HunterStatus
from webpent.agents.hunter_runner import _chain_finding_inputs


def test_audit_telemetry_is_trace_anchored_without_consuming_execution_budget(tmp_path):
    trace = ProductionTrace(config_digest="regression", entrypoint="direct_invoke")
    chain = EngagementAuditChain(
        engagement_id="regression-audit-budget",
        audit_dir=tmp_path / "audit",
        workspace_dir=tmp_path / "workspace",
        trace=trace,
    )
    for index in range(ProductionTrace.MAX_STAGES + 25):
        chain.append_event(event_type="bounded.telemetry", details={"index": index})
    assert len([item for item in trace.stages if item["stage"] == "audit_event"]) == ProductionTrace.MAX_STAGES + 25
    assert trace.summary()["bounded_stage_count"] == 0
    trace.record(stage="execution_stage", component="Regression")
    assert trace.summary()["bounded_stage_count"] == 1
    chain.finalize()


def test_execution_stages_still_fail_closed_at_bound():
    trace = ProductionTrace(config_digest="regression", entrypoint="direct_invoke")
    for index in range(ProductionTrace.MAX_STAGES):
        trace.record(stage=f"execution_{index}", component="Regression")
    try:
        trace.record(stage="execution_overflow", component="Regression")
    except ProductionSpineError as exc:
        assert "stage limit" in str(exc)
    else:
        raise AssertionError("execution-stage bound was not enforced")


def test_jwt_login_success_does_not_require_identity_validation_url(monkeypatch):
    def handler(request):
        body = json.loads(request.content.decode("utf-8"))
        assert sorted(body) == ["email", "password"]
        return httpx.Response(200, json={"authentication": {"token": "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.signature"}})

    monkeypatch.setattr(login_executor_module, "make_safe_httpx_client", lambda **_kwargs: httpx.Client(transport=httpx.MockTransport(handler)))
    signal = AuthSignal(
        auth_type="api_jwt",
        login_url="http://example.test/identity/api/auth/login",
        login_fields={"username_field": "email", "password_field": "password"},
        token_type="jwt",
        token_capture="JSON token field",
    )
    result = LoginExecutor(target_url="http://example.test").login(
        alias="owner",
        signal=signal,
        credentials={"username": "operator-email", "password": "operator-password"},
    )
    assert result.success is True
    assert result.reason == "jwt_login_response_validated"
    assert result.validation_status_code == 200


def test_credential_loader_preserves_bounded_identity_paths(tmp_path: Path):
    path = tmp_path / "profiles.json"
    path.write_text(json.dumps({
        "owner": {
            "username": "operator@example.test",
            "password": "runtime-only",
            "identity_paths": ["/rest/user/whoami"],
        }
    }))
    loaded = load_creds_file(path)
    assert loaded["owner"]["identity_paths"] == ["/rest/user/whoami"]


def test_credential_loader_preserves_bounded_registration_metadata(tmp_path: Path):
    path = tmp_path / "profiles.json"
    path.write_text(json.dumps({
        "foreign": {
            "username": "operator@example.test",
            "password": "runtime-only",
            "register_if_unauthorized": True,
            "registration_url": "/identity/api/auth/signup",
            "registration_fields": {"username_field": "email", "password_field": "password"},
            "registration_extra": {"name": "Authorized Lab User", "number": "5550100111"},
        }
    }))
    loaded = load_creds_file(path)
    assert loaded["foreign"]["register_if_unauthorized"] is True
    assert loaded["foreign"]["registration_url"] == "/identity/api/auth/signup"
    assert loaded["foreign"]["registration_extra"]["number"] == "5550100111"


def test_chain_projection_keeps_promoted_proof_bundle_from_runtime_decision():
    class PromotionModel:
        def to_dict(self):
            return {"decision": "PROMOTED", "finding_id": "finding-1", "gates_passed": [f"g{i}" for i in range(8)]}

    class BundleModel:
        def to_dict(self):
            return {"bundle_id": "proof-1", "causal_oracle": {"resource_id": "opaque-id"}}

    result = ExploitationResult(
        hypothesis_id="hyp-1",
        status=HunterStatus.VALIDATING,
        request_executed=True,
        response_received=True,
        evidence={
            "request_specs": {"candidate": {"path": "/rest/resource/opaque-id"}},
            "decision": {"promotion": PromotionModel(), "proof_bundle": BundleModel(), "replay_verified": True},
        },
    )
    projected = _chain_finding_inputs(
        HunterState(exploitation_results=[result]),
        target_url="http://127.0.0.1:3000",
        engagement_id="campaign-1",
    )
    assert len(projected) == 1
    assert projected[0]["proof_bundle_ref"] == "proof-1"
    assert projected[0]["route"] == "/rest/resource/opaque-id"
    assert projected[0]["metadata"]["resource_id"] == "opaque-id"
