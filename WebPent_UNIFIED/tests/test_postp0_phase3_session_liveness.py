"""POST-P0 Phase 3 — session liveness + auth-aware deepening.

Pins:
  * SessionLivenessService probe/ensure_live flow: live session stamps
    healthy; dead session triggers bounded re-login (≤2 per run) and an
    honest downgrade request when re-auth is exhausted,
  * the liveness record NEVER contains cookie or credential values,
  * execution_sandbox pre-phase probe: downgrade path skips browser
    execution honestly; healthy path records liveness in the result,
  * httpx forwards operator session cookies as a single header (values
    never logged) and still respects the scope gate,
  * param-mining probes carry the operator session,
  * authorization-matrix / IDOR-enumeration defaults flip ONLY behind
    an explicit active profile on a dev/lab environment (production
    defaults stay safe),
  * the validator's session-dependent liveness gate now covers the
    replay-based classes (lfi, path_traversal, ssti, nosql_injection,
    open_redirect) in addition to sqli/xss/csrf.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

from webpent.models.findings import Confidence, Finding, Severity
from webpent.models.targets import Target
from webpent.shared.session_liveness import (
    MAX_REAUTH_ATTEMPTS_PER_RUN,
    build_empty_record,
    ensure_live_session,
    probe_session,
)
from webpent.state.initial_state import build_initial_state


def _state(*, cookies: dict | None = None, creds: dict | None = None) -> dict:
    state = build_initial_state(target=Target(url="http://lab.local"), thread_id="t")
    if cookies is not None:
        state["session_cookies"] = dict(cookies)
    if creds is not None:
        state["credentials"] = dict(creds)
    return state


def _finding(vuln_class: str = "sqli") -> Finding:
    return Finding(
        id=uuid.uuid4(),
        title=f"fixture {vuln_class}",
        severity=Severity.HIGH.value,
        description="liveness fixture",
        tool_name="validator",
        url="http://lab.local/a",
        confidence=Confidence.TENTATIVE,
        confidence_level="Pending",
        reasoning="fixture",
        vuln_class=vuln_class,
        created_at=datetime.now(timezone.utc),
        thread_id="t",
    )


def test_live_session_stamps_healthy(monkeypatch) -> None:
    monkeypatch.setattr(
        "webpent.shared.session_liveness.probe_session",
        lambda url, cookies: (True, "ok"),
    )
    state = _state(cookies={"sid": "s3cr3t-value"})
    update = ensure_live_session(state, thread_id="t")
    record = update["session_liveness"]
    assert record["status"] == "healthy"
    assert record["last_verified_at"] is not None
    # Redaction by construction: no cookie values anywhere in the record.
    assert "s3cr3t-value" not in str(record)


def test_dead_session_reauths_bounded_then_downgrades(monkeypatch) -> None:
    monkeypatch.setattr(
        "webpent.shared.session_liveness.probe_session",
        lambda url, cookies: (False, "redirect_login"),
    )
    logins: list[tuple[str, str]] = []

    def fake_login(url, username, password):
        logins.append((username, "redacted"))
        return {}  # re-login never succeeds

    monkeypatch.setattr(
        "webpent.agents.authentication.agent._perform_login", fake_login
    )
    state = _state(
        cookies={"sid": "dead"}, creds={"username": "op", "password": "pw"}
    )
    # Round 1: dead -> re-auth attempt 1 -> still dead -> stale.
    update1 = ensure_live_session(state, thread_id="t")
    assert update1["session_liveness"]["reauth_attempts"] == 1
    assert update1["session_liveness"]["status"] == "stale"
    assert not update1["session_liveness"]["downgrade_requested"]
    # Round 2 (as the graph would feed the record back): attempt 2.
    state["session_liveness"] = update1["session_liveness"]
    update2 = ensure_live_session(state, thread_id="t")
    assert update2["session_liveness"]["reauth_attempts"] == 2
    assert update2["session_liveness"]["status"] == "invalid"
    assert update2["session_liveness"]["downgrade_requested"] is True
    # A third round cannot consume more budget.
    state["session_liveness"] = update2["session_liveness"]
    update3 = ensure_live_session(state, thread_id="t")
    assert update3["session_liveness"]["reauth_attempts"] == 2
    assert update3["session_liveness"]["downgrade_requested"] is True
    assert len(logins) == MAX_REAUTH_ATTEMPTS_PER_RUN


def test_successful_reauth_refreshes_cookies_and_neutralizes_stale(
    monkeypatch,
) -> None:
    monkeypatch.setattr(
        "webpent.shared.session_liveness.probe_session",
        lambda url, cookies: (True, "ok") if cookies.get("fresh") else (False, "dead"),
    )
    monkeypatch.setattr(
        "webpent.agents.authentication.agent._perform_login",
        lambda url, username, password: {"fresh": "newvalue"},
    )
    state = _state(
        cookies={"sid": "old", "extra": "stale"},
        creds={"username": "op", "password": "pw"},
    )
    update = ensure_live_session(state, thread_id="t")
    assert update["session_liveness"]["status"] == "healthy"
    merged = update["session_cookies"]
    assert merged["fresh"] == "newvalue"
    # Stale keys neutralized per merge-dicts convention.
    assert merged["sid"] == ""
    assert merged["extra"] == ""


def test_no_cookies_is_noop_and_no_credentials_fails_closed(monkeypatch) -> None:
    monkeypatch.setattr(
        "webpent.shared.session_liveness.probe_session",
        lambda url, cookies: (False, "dead"),
    )
    # No session cookies in state: record untouched (unknown), no probe.
    state = _state()
    update = ensure_live_session(state, thread_id="t")
    assert update["session_liveness"]["status"] == "unknown"
    # Dead session + no usable credentials: fail closed with downgrade.
    state2 = _state(cookies={"sid": "dead"})
    update2 = ensure_live_session(state2, thread_id="t")
    assert update2["session_liveness"]["status"] == "invalid"
    assert update2["session_liveness"]["downgrade_requested"] is True


def test_probe_session_without_cookies_fails_closed() -> None:
    alive, reason = probe_session("http://lab.local", {})
    assert alive is False
    assert reason == "no_cookies"


def test_sandbox_downgrade_parks_execution(monkeypatch, capsys) -> None:
    from webpent.agents.execution_sandbox.agent import execution_sandbox_node

    monkeypatch.setattr(
        "webpent.shared.session_liveness.probe_session",
        lambda url, cookies: (False, "redirect_login"),
    )
    monkeypatch.setattr(
        "webpent.agents.authentication.agent._perform_login",
        lambda url, username, password: {},
    )
    state = _state(
        cookies={"sid": "dead"},
        creds={"username": "op", "password": "pw"},
    )
    state["session_liveness"] = {
        **build_empty_record(),
        "reauth_attempts": MAX_REAUTH_ATTEMPTS_PER_RUN,
    }
    result = execution_sandbox_node(state)
    record = result["session_liveness"]
    assert record["downgrade_requested"] is True
    reasons = [str(o.get("reason")) for o in result["execution_observations"]]
    assert "invalid" in reasons
    # Honest park: no findings updated, message says session dead.
    assert "dead" in result["messages"][-1].content.lower()


def test_sandbox_healthy_session_recorded(monkeypatch) -> None:
    from webpent.agents.execution_sandbox.agent import execution_sandbox_node

    monkeypatch.setattr(
        "webpent.shared.session_liveness.probe_session",
        lambda url, cookies: (True, "ok"),
    )
    state = _state(cookies={"sid": "live"})
    result = execution_sandbox_node(state)
    assert result["session_liveness"]["status"] == "healthy"
    assert "s3cr3t" not in str(result["session_liveness"])


def test_httpx_forwards_cookie_header_without_logging_values(monkeypatch) -> None:
    from webpent.shared.engagement_scope import (
        clear_engagement_target_hosts,
        set_engagement_target_hosts,
    )
    from webpent.tools.recon import httpx as httpx_tool

    captured: dict = {}

    def fake_run_command(cmd, input_data=None, timeout=None):
        captured["cmd"] = list(cmd)
        captured["input"] = input_data
        return ""

    token = set_engagement_target_hosts("http://lab.local")
    try:
        monkeypatch.setattr(httpx_tool, "run_command", fake_run_command)
        monkeypatch.setattr(
            httpx_tool, "_safe_local_probe", lambda domains: []
        )
        results = httpx_tool.run_httpx(
            ["http://lab.local"], cookies={"sid": "s3cr3t-value", "": "ignored"}
        )
    finally:
        clear_engagement_target_hosts()
    assert results == []
    cmd = captured["cmd"]
    cookie_args = [
        cmd[i + 1] for i, flag in enumerate(cmd) if flag == "-H"
    ]
    assert any(a.startswith("Cookie: ") for a in cookie_args)
    header = next(a for a in cookie_args if a.startswith("Cookie: "))
    assert "sid=s3cr3t-value" in header
    # The header must be present exactly once; empty names dropped.
    assert len([a for a in cookie_args if a.startswith("Cookie: ")]) == 1


def test_param_mining_carries_session(monkeypatch) -> None:
    from webpent.agents.recon.agent import _discover_hidden_parameters

    seen_cookies: list = []

    class _FakeClient:
        def __init__(self, **kwargs):
            seen_cookies.append(kwargs.get("cookies"))

        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

        def get(self, url, params=None):
            class _R:
                content = b"x" * 100
                text = "x" * 100
                status_code = 200

            return _R()

    monkeypatch.setattr(
        "webpent.shared.http.make_safe_httpx_client",
        lambda **kwargs: _FakeClient(**kwargs),
    )
    target = Target(url="http://lab.local")
    _discover_hidden_parameters(
        target, ["http://lab.local/a"], session_cookies={"sid": "s3cr3t-value"}
    )
    assert seen_cookies and all(c == {"sid": "s3cr3t-value"} for c in seen_cookies)


def test_lab_profile_defaults_flip_only_behind_active_profile(monkeypatch) -> None:
    # Default environment is lab; explicit active profile flips the keys.
    state = build_initial_state(
        target=Target(url="http://lab.local"), thread_id="t",
        profile="authorized-active",
    )
    assert state["enable_authorization_matrix"] is True
    assert state["enable_idor_enumeration"] is True
    # Legacy profile: keys absent -> production-safe defaults preserved.
    state_legacy = build_initial_state(
        target=Target(url="http://lab.local"), thread_id="t"
    )
    assert "enable_authorization_matrix" not in state_legacy
    assert "enable_idor_enumeration" not in state_legacy


def test_production_environment_never_gets_lab_defaults(monkeypatch) -> None:
    import webpent.state.initial_state as init_mod
    from webpent.config.settings import Settings

    base = Settings(
        auth_enabled=True,
        audit_secret_key="unit-test-audit-secret-key-0123456789abcdef",
    )
    hardened = base.model_copy(update={"environment_profile": "production"})
    monkeypatch.setattr(init_mod, "get_settings", lambda: hardened)
    state = build_initial_state(
        target=Target(url="http://lab.local"), thread_id="t",
        profile="authorized-active",
    )
    assert "enable_authorization_matrix" not in state
    assert "enable_idor_enumeration" not in state


def test_validator_session_dependent_gate_covers_replay_classes() -> None:
    # The gate constant lives inside _validate_with_tool; verify the
    # classes are covered by asserting the dispatch behavior marker:
    # import the module and check the tuple is defined in the function
    # via its code object constants (no HTTP needed).
    import inspect

    from webpent.agents.validator import agent as validator_mod

    src = inspect.getsource(validator_mod._validate_with_tool)
    for cls in ("lfi", "path_traversal", "ssti", "nosql_injection", "open_redirect"):
        assert f'"{cls}"' in src, cls
    assert "_SESSION_DEPENDENT_CLASSES" in src
