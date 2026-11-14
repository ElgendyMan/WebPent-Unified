"""P0-1 regression tests for active validators and deterministic routing."""

from __future__ import annotations

from unittest.mock import MagicMock, patch
from uuid import uuid4

from webpent.agents.validator import agent as validator_agent
from webpent.agents.validator.active_checks import (
    Replay,
    validate_lfi,
    validate_nosql_injection,
    validate_path_traversal,
    validate_ssti,
)
from webpent.models.findings import Confidence, Finding, Severity, VulnClass


def _finding(vuln_class: str, url: str = "https://target.test/view?file=home") -> Finding:
    return Finding(
        id=uuid4(),
        title=f"{vuln_class} candidate",
        severity=Severity.HIGH,
        description="candidate",
        tool_name="recon",
        url=url,
        vuln_class=vuln_class,
        target_param="file",
        request_data={"file": "home"},
    )


# webpent.shared.verifier.verify_replay_evidence rejects placeholder/empty
# engagement provenance (see verifier_provenance_incomplete_or_placeholder);
# a real-looking engagement_id must be supplied via verification_context.
_VERIFICATION_CONTEXT = {
    "engagement_id": "test-fixture-engagement",
    "scope_context": {"targets": ["target.test"], "authorized": True},
    "identity_context": {"identity": "primary", "authenticated": True},
}


def test_classifier_routes_all_p0_1_classes():
    expected = {
        VulnClass.LFI.value: "lfi",
        VulnClass.RFI.value: "rfi",
        VulnClass.SSTI.value: "ssti",
        VulnClass.XXE.value: "xxe",
        VulnClass.PATH_TRAVERSAL.value: "path_traversal",
        VulnClass.COMMAND_INJECTION.value: "command_injection",
        VulnClass.OPEN_REDIRECT.value: "open_redirect",
        VulnClass.NOSQL_INJECTION.value: "nosql_injection",
    }
    for vuln_class, route in expected.items():
        assert validator_agent._classify_finding(_finding(vuln_class)) == route


def test_dispatch_never_falls_back_for_all_p0_1_classes():
    finding_by_route = {
        "lfi": _finding(VulnClass.LFI.value),
        "rfi": _finding(VulnClass.RFI.value),
        "ssti": _finding(VulnClass.SSTI.value),
        "xxe": _finding(VulnClass.XXE.value),
        "path_traversal": _finding(VulnClass.PATH_TRAVERSAL.value),
        "command_injection": _finding(VulnClass.COMMAND_INJECTION.value),
        "open_redirect": _finding(VulnClass.OPEN_REDIRECT.value),
        "nosql_injection": _finding(VulnClass.NOSQL_INJECTION.value),
    }
    with (
        patch(
            "webpent.agents.validator.active_checks.validate_lfi", side_effect=lambda f, **_: f
        ) as lfi,
        patch(
            "webpent.agents.validator.active_checks.validate_path_traversal",
            side_effect=lambda f, **_: f,
        ) as traversal,
        patch(
            "webpent.agents.validator.active_checks.validate_ssti", side_effect=lambda f, **_: f
        ) as ssti,
        patch(
            "webpent.agents.validator.active_checks.validate_nosql_injection",
            side_effect=lambda f, **_: f,
        ) as nosql,
        patch.object(
            validator_agent, "_validate_via_oob", side_effect=lambda f, *_args, **_kwargs: f
        ) as oob,
        patch.object(
            validator_agent, "_validate_xxe_via_oob", side_effect=lambda f, **_kwargs: f
        ) as xxe,
        patch.object(
            validator_agent, "_validate_open_redirect", side_effect=lambda f, **_kwargs: f
        ) as redirect,
    ):
        for route, finding in finding_by_route.items():
            result = validator_agent._validate_with_tool(finding, route, llm=MagicMock())
            assert result.id == finding.id
            assert result.confidence_level == "Pending"
    assert lfi.called and traversal.called and ssti.called and nosql.called
    assert oob.call_count == 2  # RFI and command injection
    assert xxe.called and redirect.called


def test_lfi_and_path_traversal_require_new_passwd_marker(monkeypatch):
    def replay(_finding, _parameter, value, _cookies):
        body = "root:x:0:0:webpent:/root:/bin/sh" if "etc/passwd" in value else "safe baseline"
        return Replay("GET", f"https://target.test/view?file={value}", None, 200, body, {}, 5)

    monkeypatch.setattr("webpent.agents.validator.active_checks._replay", replay)
    for validator, vuln_class in (
        (validate_lfi, VulnClass.LFI.value),
        (validate_path_traversal, VulnClass.PATH_TRAVERSAL.value),
    ):
        result = validator(
            _finding(vuln_class),
            cookies={"PHPSESSID": "secret-cookie"},
            verification_context=_VERIFICATION_CONTEXT,
        )
        assert result.confidence_level == "Tool-Confirmed"
        assert result.confidence == Confidence.CONFIRMED.value
        assert "Cookie" not in str(result.evidence)
        assert "secret-cookie" not in str(result.evidence)


def test_ssti_requires_arithmetic_evaluation_not_payload_echo(monkeypatch):
    def replay(_finding, _parameter, value, _cookies):
        body = "391" if "17*23" in value else "baseline"
        return Replay("GET", f"https://target.test/view?file={value}", None, 200, body, {}, 5)

    monkeypatch.setattr("webpent.agents.validator.active_checks._replay", replay)
    result = validate_ssti(
        _finding(VulnClass.SSTI.value), verification_context=_VERIFICATION_CONTEXT
    )
    assert result.confidence_level == "Tool-Confirmed"
    assert result.evidence["matched_marker"] == "391"


def test_nosql_requires_unauthorized_to_success_differential(monkeypatch):
    def replay(_finding, _parameter, value, _cookies):
        if value.startswith("{"):
            return Replay(
                "GET",
                f"https://target.test/login?user={value}",
                None,
                200,
                "authenticated-user-profile-" + ("x" * 100),
                {},
                5,
            )
        return Replay(
            "GET", f"https://target.test/login?user={value}", None, 403, "denied", {}, 5
        )

    monkeypatch.setattr("webpent.agents.validator.active_checks._replay", replay)
    finding = _finding(VulnClass.NOSQL_INJECTION.value, "https://target.test/login?user=x")
    finding = finding.model_copy(
        update={"target_param": "user", "request_data": {"user": "invalid"}}
    )
    result = validate_nosql_injection(finding, verification_context=_VERIFICATION_CONTEXT)
    assert result.confidence_level == "Tool-Confirmed"
    assert result.evidence["differential"] == "unauthorized_baseline_to_success_candidate"


def test_open_redirect_confirmation_does_not_follow_canary(monkeypatch):
    class Response:
        def __init__(self, status, location=""):
            self.status_code = status
            self.headers = {"location": location} if location else {}

    class Client:
        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

        def get(self, url, headers=None):
            if "webpent-open-redirect.invalid" in url:
                return Response(302, "https://webpent-open-redirect.invalid/webpent-canary")
            return Response(200)

    monkeypatch.setattr("webpent.shared.http.make_safe_httpx_client", lambda **_: Client())
    result = validator_agent._validate_open_redirect(
        _finding(VulnClass.OPEN_REDIRECT.value), verification_context=_VERIFICATION_CONTEXT
    )
    assert result.confidence_level == "Tool-Confirmed"
    assert result.evidence["follow_redirects"] is False
