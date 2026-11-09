"""Unfreeze-fix verification tests (TEAM-RED defects D2/D3/D4/D7). Synthetic, no network."""
from __future__ import annotations
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from webpent.integration.session_recovery_bridge import ExploitResultView, RecoveringExploiter
from webpent.recon.session_recovery import SessionRecoveryManager, CampaignHalted
from webpent.recon.auth_detector import AuthDetector
from webpent.recon.login_executor import LoginExecutor
from webpent.recon.hypothesis_generator import _advised_value


# -- D2: ExploitResultView understands ExploitationResult shape ----------------
def _exploit_result(**kw):
    return type("ExploitResult", (), kw)()


def test_d2_scope_error_mapped_to_scope_violation():
    view = ExploitResultView.from_result(_exploit_result(error="program_scope_blocked_request", evidence={}))
    assert view.failure == "scope_violation"


def test_d2_evidence_scope_blocked_mapped():
    view = ExploitResultView.from_result(_exploit_result(error=None, evidence={"scope_blocked": True}))
    assert view.failure == "scope_violation"


def test_d2_decision_status_code_propagates():
    view = ExploitResultView.from_result(_exploit_result(evidence={"decision": {"status_code": 401}}))
    assert view.status_code == 401


def test_d2_recovery_triggers_on_three_dead_sessions():
    calls = []
    def inner(h, state):
        calls.append(h)
        # return ExploitationResult shape with 401 decision (dead session)
        return _exploit_result(evidence={"decision": {"status_code": 401}})
    login_ok = lambda a="": type("LR", (), {"success": True})()
    rm = SessionRecoveryManager(campaign_id="c1", login=login_ok, provision=None, m4_bind=None)
    w = RecoveringExploiter(inner, recovery_manager=rm, sleep=lambda s: None)
    # 3 consecutive dead-session responses trigger recovery on the 3rd call.
    for _ in range(3):
        try:
            w("hyp1", {})
        except CampaignHalted:
            pass
    # wrapper did NOT pass through transparently: it attempted recovery (audit events exist)
    assert len(w.audit_events) >= 1
    assert any(e.event_type in ("session.expired", "session.recovered") for e in w.audit_events)


def test_d2_healthy_result_still_passes_through():
    def inner(h, state):
        return _exploit_result(evidence={"decision": {"status_code": 200}})
    rm = SessionRecoveryManager(campaign_id="c2", login=lambda a="": type("LR", (), {"success": True})())
    w = RecoveringExploiter(inner, recovery_manager=rm)
    r = w("hyp_ok", {})
    assert getattr(r, "evidence", {}).get("decision", {}).get("status_code") == 200
    assert len(w.audit_events) == 0  # no recovery on healthy


# -- D3: api_key detection reachable from real route fields --------------------
def test_d3_api_key_signal_from_auth_mechanisms():
    det = AuthDetector(target_url="https://t.local")
    surface = {"routes": [{"route": "/api/v1/data", "auth_mechanisms": ["api-key:X-API-Key"], "api_signal": True}]}
    d = det.detect(surface)
    assert "api_key" in [s.auth_type for s in d.signals]


def test_d3_api_key_signal_from_parameter_name():
    det = AuthDetector(target_url="https://t.local")
    surface = {"routes": [{"route": "/api/v1/data", "parameters": [{"name": "api_key"}], "api_signal": True}]}
    d = det.detect(surface)
    assert "api_key" in [s.auth_type for s in d.signals]


def test_d3_no_fp_without_evidence():
    det = AuthDetector(target_url="https://t.local")
    d = det.detect({"routes": [{"route": "/api/v1/data", "parameters": [{"name": "id"}], "api_signal": True}]})
    assert "api_key" not in [s.auth_type for s in d.signals]


def test_d3_generic_key_param_is_not_fp():
    det = AuthDetector(target_url="https://t.local")
    # parameter named "key" alone must NOT trigger api_key (too generic)
    d = det.detect({"routes": [{"route": "/api/v1/data?key=abc", "parameters": [{"name": "key"}]}]})
    assert "api_key" not in [s.auth_type for s in d.signals]


# -- D4: enriched payload suggestions flow through _advised_value --------------
def test_d4_enriched_payload_suggestion_used_as_fallback():
    advice = {"__enriched_payload_suggestions__": {"ids": ["family_idor_advisory"]}}
    val = _advised_value("/some/route", "id", "IDOR", advice)
    assert val == "family_idor_advisory"


def test_d4_exact_advice_still_beats_enriched_fallback():
    advice = {
        "/some/route|id|IDOR": {"payload_value": "exact_value"},
        "__enriched_payload_suggestions__": {"ids": ["fallback"]},
    }
    val = _advised_value("/some/route", "id", "IDOR", advice)
    assert val == "exact_value"


# -- D7: login_with_api_key fail-closed without validation_url -----------------
def test_d7_login_with_api_key_requires_validation_url():
    le = LoginExecutor(target_url="https://t.local")
    r = le.login_with_api_key(alias="owner", value="sk-live-123")
    assert r.success is False
    assert r.reason == "validation_url_required"


def test_d7_empty_api_key_still_rejected():
    le = LoginExecutor(target_url="https://t.local")
    r = le.login_with_api_key(alias="owner", value="", validation_url="https://t.local/me")
    assert r.success is False
    assert r.reason == "api_key_value_required"
