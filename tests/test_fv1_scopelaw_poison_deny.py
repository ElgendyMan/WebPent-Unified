"""FV-1 regression lock: ScopeLaw poison detection must DENY (fail closed).

Defect found during the final verification pass: when poison patterns were
detected in tool arguments (metadata SSRF IPs, ``--os-shell`` etc.) but the
target URL itself was in scope, ``ScopeDecision.in_scope`` remained ``True``
with the poison merely annotated in the reason. Any consumer honoring the
boolean alone would execute a poisoned invocation. Fixed: poison is a hard
deny regardless of the target scope verdict.
"""
from __future__ import annotations

from webpent.live_hunter.profile import AuthorizedLabProfile
from webpent.live_hunter.tool_scope import ScopeLaw


def _law() -> ScopeLaw:
    profile = AuthorizedLabProfile(
        authorized_targets=("127.0.0.1",),
        engagement_id="fv-scopelaw-poison-lock",
        operator_approval_at="2026-09-15T00:00:00+00:00",
        knowledge_ready=True, lab_fixture_mode=True,
    )
    return ScopeLaw(profile=profile, engagement_id="fv-scopelaw-poison-lock")


def test_poisoned_metadata_ip_argument_is_denied() -> None:
    d = _law().authorize_invocation(
        tool_name="sqlmap",
        target_url="http://127.0.0.1:9/x",
        arguments=("--data=1 --url=http://169.254.169.254/latest/meta-data",),
    )
    assert d.poison_detected is True
    assert d.in_scope is False, "poisoned argv must be a hard deny, not an annotation"


def test_poisoned_os_shell_argument_is_denied() -> None:
    d = _law().authorize_invocation(
        tool_name="sqlmap",
        target_url="http://127.0.0.1:9/x",
        arguments=("--os-shell",),
    )
    assert d.poison_detected is True
    assert d.in_scope is False


def test_clean_in_scope_invocation_still_allowed() -> None:
    d = _law().authorize_invocation(
        tool_name="sqlmap",
        target_url="http://127.0.0.1:9/x",
        arguments=("--batch=1",),
    )
    assert d.poison_detected is False
    assert d.in_scope is True


def test_out_of_scope_target_still_denied() -> None:
    d = _law().authorize_invocation(
        tool_name="sqlmap",
        target_url="http://evil.example.com/x",
    )
    assert d.in_scope is False
    assert d.poison_detected is False
    assert d.reason.startswith("out_of_scope")


def test_unregistered_tool_denied() -> None:
    d = _law().authorize_invocation(
        tool_name="skynet",
        target_url="http://127.0.0.1:9/x",
    )
    assert d.in_scope is False
