"""V61 Phase 1 regression contracts."""

import json

from webpent.agents.access_control import agent as access_agent
from webpent.agents.validator import agent as validator_agent
from webpent.models.findings import Finding, Severity, VulnClass
from webpent.models.hypothesis import Hypothesis, HypothesisOrigin
from webpent.reporter.export import build_report_data, export_to_html
from webpent.shared.confidence import compute_initial_hypothesis_confidence
from webpent.shared.self_critique import (
    DISCOVERIES_PER_SELF_CRITIQUE,
    SelfCritiqueAction,
    SelfCritiqueCheckpoint,
    recommend_self_critique_action,
    should_fire_every_n_discoveries,
)


def test_initial_hypothesis_confidence_is_bounded_and_signal_driven():
    heuristic = compute_initial_hypothesis_confidence(
        HypothesisOrigin.HEURISTIC,
        source_kind="heuristic",
        deterministic_match=False,
    )
    endpoint = compute_initial_hypothesis_confidence(
        HypothesisOrigin.CROSS_REASONS,
        source_kind="endpoint_input",
        deterministic_match=True,
    )

    assert 0.0 <= heuristic <= 1.0
    assert 0.0 <= endpoint <= 1.0
    assert endpoint > heuristic


def test_authorization_appendix_is_read_only_and_redacted():
    finding = Finding(
        title="Authorization candidate",
        severity=Severity.HIGH,
        description="Synthetic regression finding.",
        tool_name="access_control_mapper",
        url="https://lab.test/orders/42",
        vuln_class="idor",
    )
    matrix = {
        "rows": [
            {
                "identity_ref": "alice",
                "role": "user",
                "endpoint": "https://lab.test/orders/42?token=secret",
            },
            {
                "identity_ref": "bob",
                "role": "user",
                "endpoint": "https://lab.test/orders/42?token=secret",
            },
        ],
        "comparisons": [{"comparison_kind": "ownership_differential"}],
        "coverage_gaps": ["missing_admin_identity"],
    }

    report = build_report_data(
        "https://lab.test/",
        [finding],
        authorization_matrix=matrix,
    )
    appendix = report["authorization_matrix_appendix"]
    serialized = json.dumps(report, sort_keys=True)

    assert appendix["identity_count"] == 2
    assert appendix["role_count"] == 1
    assert appendix["comparison_count"] == 1
    assert "token=secret" not in serialized
    assert "[REDACTED]" in serialized
    assert "missing_admin_identity" in appendix["coverage_gaps"]


def test_authorization_appendix_reaches_active_html_template(tmp_path):
    finding = Finding(
        title="Authorization candidate",
        severity=Severity.HIGH,
        description="Synthetic regression finding.",
        tool_name="access_control_mapper",
        url="https://lab.test/orders/42",
        vuln_class="idor",
    )
    output = export_to_html(
        "https://lab.test/",
        [finding],
        tmp_path,
        authorization_matrix={
            "rows": [{"identity_ref": "alice", "role": "user", "endpoint": "/orders/42"}],
            "comparisons": [],
            "coverage_gaps": [],
        },
    )

    html = output.read_text(encoding="utf-8")
    assert "Authorization Matrix Appendix" in html
    assert "Identities: 1" in html


def test_state_changing_probe_is_blocked_without_explicit_approval(monkeypatch):
    calls = []

    class ForbiddenClient:
        def request(self, *args, **kwargs):
            calls.append((args, kwargs))
            return type("Response", (), {"status_code": 200, "content": b"unsafe"})()

    monkeypatch.setattr(
        "webpent.shared.http.make_safe_httpx_client",
        lambda **kwargs: type(
            "Context",
            (),
            {"__enter__": lambda self: ForbiddenClient(), "__exit__": lambda *args: None},
        )(),
    )

    status, length = access_agent._probe_url(
        "https://lab.test/delete",
        method="DELETE",
        allow_state_changing=False,
    )

    assert (status, length) == (0, 0)
    assert calls == []


def test_vertical_role_differential_maps_to_critical_auth_bypass():
    finding = access_agent._create_idor_finding(
        "https://lab.test/admin/users/42",
        200,
        128,
        "foreign identity received the owner's resource",
        owner_role="user",
        foreign_role="admin",
    )

    assert finding.severity == Severity.CRITICAL.value
    assert finding.vuln_class == VulnClass.AUTH_BYPASS.value


def test_horizontal_owner_differential_remains_high_idor():
    finding = access_agent._create_idor_finding(
        "https://lab.test/orders/42",
        200,
        128,
        "foreign identity received the owner's resource",
        owner_role="user",
        foreign_role="user",
    )

    assert finding.severity == Severity.HIGH.value
    assert finding.vuln_class == VulnClass.IDOR.value


def test_state_changing_probe_requires_explicit_approval(monkeypatch):
    calls = []

    class ApprovedClient:
        def request(self, *args, **kwargs):
            calls.append((args, kwargs))
            return type("Response", (), {"status_code": 204, "content": b""})()

    monkeypatch.setattr(
        "webpent.shared.http.make_safe_httpx_client",
        lambda **kwargs: type(
            "Context",
            (),
            {"__enter__": lambda self: ApprovedClient(), "__exit__": lambda *args: None},
        )(),
    )

    status, length = access_agent._probe_url(
        "https://lab.test/update",
        method="POST",
        allow_state_changing=True,
    )

    assert (status, length) == (204, 0)
    assert len(calls) == 1


def test_discovery_cadence_fires_at_configured_threshold():
    state = {"mental_model": {"nodes": {str(i): {} for i in range(DISCOVERIES_PER_SELF_CRITIQUE)}}}

    assert should_fire_every_n_discoveries(state, last_check_count=0)


def test_discovery_cadence_does_not_fire_before_configured_threshold():
    state = {
        "mental_model": {
            "nodes": {
                str(i): {} for i in range(DISCOVERIES_PER_SELF_CRITIQUE - 1)
            }
        }
    }

    assert not should_fire_every_n_discoveries(state, last_check_count=0)


def test_self_critique_risk_cap_abandons_without_llm(monkeypatch):
    hypothesis = Hypothesis(
        target_url="https://lab.test/orders/42",
        statement="A role boundary may be bypassed.",
        vuln_class=VulnClass.IDOR,
        origin=HypothesisOrigin.HEURISTIC,
    )
    monkeypatch.setattr(
        "webpent.shared.self_critique._ask_llm_unproductive",
        lambda *args, **kwargs: (_ for _ in ()).throw(AssertionError("LLM must not run")),
    )

    action, rule, contribution = recommend_self_critique_action(
        {"hypotheses": [hypothesis], "findings": []},
        checkpoint=SelfCritiqueCheckpoint.BEFORE_PROMOTION,
        hypothesis=hypothesis,
        risk_manager_caps={"max_depth": 1, "current_depth": 1},
    )

    assert action is SelfCritiqueAction.ABANDON
    assert "risk_manager_cap" in rule
    assert contribution == ""


def test_validator_uses_real_self_critique_checkpoint(monkeypatch):
    hypothesis = Hypothesis(
        target_url="https://lab.test/orders/42",
        statement="A validation candidate may be blocked.",
        vuln_class=VulnClass.IDOR,
        origin=HypothesisOrigin.HEURISTIC,
        confidence_score=0.7,
    )
    finding = Finding(
        title="Validation candidate",
        severity=Severity.HIGH,
        description="Synthetic validation failure.",
        tool_name="validator",
        url=hypothesis.target_url,
        vuln_class=VulnClass.IDOR,
        hypothesis_id=hypothesis.id,
        evidence={"validation_failure_reason": "waf_blocked"},
    )
    calls = []

    def fake_recommend(state, *, checkpoint, hypothesis, branch_id, **kwargs):
        calls.append((checkpoint, branch_id))
        return SelfCritiqueAction.DEPRIORITIZE, "test_rule", ""

    monkeypatch.setattr(
        "webpent.shared.self_critique.recommend_self_critique_action",
        fake_recommend,
    )

    updated, logs = validator_agent._apply_validation_failure_learning(finding, [hypothesis])

    assert updated
    assert logs[0]["metadata"]["self_critique_action"] == "deprioritize"
    assert calls == [(SelfCritiqueCheckpoint.VALIDATION_FAILURE, str(hypothesis.id))]


def test_authorization_appendix_without_comparisons_is_non_authorizing():
    finding = Finding(
        title="Authorization candidate",
        severity=Severity.HIGH,
        description="Synthetic regression finding.",
        tool_name="access_control_mapper",
        url="https://lab.test/orders/42",
        vuln_class=VulnClass.IDOR,
    )
    report = build_report_data(
        "https://lab.test/",
        [finding],
        authorization_matrix={
            "rows": [],
            "comparisons": [],
            "coverage_gaps": ["no_owner"],
        },
    )

    appendix = report["authorization_matrix_appendix"]
    assert appendix["identity_count"] == 0
    assert appendix["comparison_count"] == 0
    assert appendix["coverage_gaps"] == ["no_owner"]
