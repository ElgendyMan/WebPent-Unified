"""SCENARIO CONTRACT locks: two-layer recon, auth honesty, liveness gates.

Covers the operator workflow sections:
  * step 5  — pre-auth anonymous snapshot (bounded, redaction-safe),
  * step 7  — login failure is a first-class, declared outcome,
  * step 12 — anonymous × authenticated surface diff + hypothesis fuel,
  * step 9  — session liveness probes before heavy phases.
"""

from __future__ import annotations

from uuid import uuid4

from webpent.models.targets import Target
from webpent.shared.auth_surface import (
    AUTH_SURFACE_SCHEMA_VERSION,
    capture_anonymous_snapshot,
    diff_auth_surface,
)

# --------------------------------------------------------------------------
# capture_anonymous_snapshot
# --------------------------------------------------------------------------

class _FakeResponse:
    def __init__(self, status_code: int, text: str, url: str, headers: dict) -> None:
        self.status_code = status_code
        self.text = text
        self.url = url
        self.headers = headers


class _FakeClient:
    def __init__(self, response: _FakeResponse) -> None:
        self._response = response

    def get(self, url: str) -> _FakeResponse:
        return self._response

    def __enter__(self) -> _FakeClient:
        return self

    def __exit__(self, *args) -> None:
        return None


_PAGE = """
<html><head><title>Worker Portal</title></head><body>
<a href="/dashboard">Dash</a>
<a href="/invoices/182">Invoice</a>
<a href="/login">Sign in</a>
<a href="https://external.example.com/x">Ext</a>
<a href="javascript:void(0)">js</a>
<form action="/login" method="post"></form>
<form action="/search" method="get"></form>
</body></html>
"""


def test_snapshot_extracts_bounded_redaction_safe_baseline(monkeypatch) -> None:
    import webpent.shared.http as shared_http

    response = _FakeResponse(
        200,
        _PAGE,
        "http://127.0.0.1:9999/",
        {
            "content-type": "text/html",
            "server": "pytest",
            "set-cookie": "SECRET=1",  # must be excluded
            "x-powered-by": "test",
        },
    )
    monkeypatch.setattr(
        shared_http, "make_safe_httpx_client", lambda **kw: _FakeClient(response)
    )
    snapshot = capture_anonymous_snapshot("http://127.0.0.1:9999/")
    assert snapshot["status"] == "ok"
    assert snapshot["authenticated"] is False
    assert snapshot["status_code"] == 200
    assert snapshot["title"] == "Worker Portal"
    assert snapshot["body_sha256"].startswith("sha256:")
    # Same-origin links only, normalized to paths.
    assert "/dashboard" in snapshot["links"]
    assert "/invoices/182" in snapshot["links"]
    assert all(not link.startswith("http") for link in snapshot["links"])
    # External/javascript links excluded; set-cookie NEVER captured.
    assert snapshot["headers"] == {
        "content-type": "text/html",
        "server": "pytest",
        "x-powered-by": "test",
    }
    assert snapshot["form_count"] == 2
    assert snapshot["schema_version"] == AUTH_SURFACE_SCHEMA_VERSION


def test_snapshot_failure_is_a_declared_error_not_a_crash(monkeypatch) -> None:
    import webpent.shared.http as shared_http

    def _boom(**kw):
        raise RuntimeError("network down")

    monkeypatch.setattr(shared_http, "make_safe_httpx_client", _boom)
    snapshot = capture_anonymous_snapshot("http://127.0.0.1:9999/")
    assert snapshot["status"] == "error"
    assert snapshot["error"] == "RuntimeError"


# --------------------------------------------------------------------------
# diff_auth_surface
# --------------------------------------------------------------------------

def test_diff_classifies_both_auth_only_and_anonymous_only() -> None:
    snapshot = {
        "status": "ok",
        "links": ["/login", "/about", "/search"],
    }
    crawled = [
        "http://t.example.com/login",
        "http://t.example.com/dashboard",
        "http://t.example.com/invoices/182",
        {"url": "http://t.example.com/search"},
    ]
    diff = diff_auth_surface(snapshot, crawled)
    assert diff["status"] == "ok"
    assert diff["counts"]["both"] == 2  # /login + /search
    assert diff["counts"]["auth_only"] == 2  # /dashboard + /invoices/182
    assert diff["counts"]["anonymous_only"] == 1  # /about never re-crawled
    auth_urls = diff["auth_only_endpoints"]
    assert "http://t.example.com/dashboard" in auth_urls
    assert "http://t.example.com/invoices/182" in auth_urls
    assert all(r["auth_visibility"] in {"both", "auth_only"} for r in diff["records"])


def test_diff_is_honestly_unavailable_without_a_snapshot() -> None:
    diff = diff_auth_surface(None, ["http://t.example.com/x"])
    assert diff["status"] == "unavailable"
    assert diff["counts"] == {"both": 0, "auth_only": 0, "anonymous_only": 0}
    errored = diff_auth_surface({"status": "error"}, ["http://t.example.com/x"])
    assert errored["status"] == "unavailable"


# --------------------------------------------------------------------------
# auth_node honesty (steps 5 + 7)
# --------------------------------------------------------------------------

def _auth_state(**overrides):
    state = {
        "target": Target(url="http://127.0.0.1:9999/"),
        "thread_id": str(uuid4()),
        "credentials": {},
        "session_cookies": {},
        "session_headers": {},
        "identity_profiles": {},
        "engagement_id": "eng-auth-test",
        "client_id": "client-auth-test",
    }
    state.update(overrides)
    return state


def test_auth_node_no_credentials_declares_unauthenticated() -> None:
    from webpent.agents.authentication.agent import auth_node

    result = auth_node(_auth_state())
    assert result["authentication_status"] == "unauthenticated"
    codes = {lim["code"] for lim in result["engagement_limitations"]}
    assert "no_credentials_supplied" in codes


def test_auth_node_failed_login_declares_credentials_rejected(monkeypatch) -> None:
    from webpent.agents.authentication import agent as auth_agent

    monkeypatch.setattr(auth_agent, "_perform_login", lambda *a, **k: {})
    result = auth_agent.auth_node(_auth_state(credentials={"username": "user", "password": "wrong"}))
    assert result["authentication_status"] == "credentials_rejected"
    assert result["auth_state"]["login_attempted"] is True
    assert result["auth_state"]["validated"] is False
    codes = {lim["code"] for lim in result["engagement_limitations"]}
    assert "authentication_failed" in codes


def test_auth_node_successful_login_marks_authenticated(monkeypatch) -> None:
    from webpent.agents.authentication import agent as auth_agent

    cookies = {"session": "live-cookie-value"}

    def _fake_validate(url, cookie_map, **kw):
        return True, "200 OK"

    monkeypatch.setattr(
        auth_agent, "_perform_login", lambda *a, **k: cookies
    )
    monkeypatch.setattr(auth_agent, "_validate_session_cookies", _fake_validate)
    result = auth_agent.auth_node(_auth_state(credentials={"username": "user", "password": "pw"}))
    assert result["authentication_status"] == "authenticated"
    assert result["session_cookies"]["session"] == "live-cookie-value"
    # Success path must NOT emit an authentication_failed limitation.
    codes = {lim["code"] for lim in result["engagement_limitations"]}
    assert "authentication_failed" not in codes


def test_auth_node_snapshots_anonymously_before_login(monkeypatch) -> None:
    """The snapshot must be captured even when login then fails (step 5)."""
    from webpent.agents.authentication import agent as auth_agent

    captured: list[str] = []

    import webpent.shared.auth_surface as surface_mod

    def _spy_capture(url: str):
        captured.append(url)
        return {
            "status": "ok",
            "url": url,
            "links": ["/login"],
            "authenticated": False,
            "captured_at": "now",
        }

    monkeypatch.setattr(surface_mod, "capture_anonymous_snapshot", _spy_capture)
    monkeypatch.setattr(auth_agent, "_perform_login", lambda *a, **k: {})
    result = auth_agent.auth_node(_auth_state(credentials={"username": "user", "password": "wrong"}))
    assert captured == ["http://127.0.0.1:9999"]  # Target normalizes the trailing slash
    assert result["pre_auth_snapshot"]["status"] == "ok"
    assert result["pre_auth_snapshot"]["authenticated"] is False


def test_auth_node_snapshot_error_becomes_declared_limitation(monkeypatch) -> None:
    import webpent.shared.auth_surface as surface_mod
    from webpent.agents.authentication import agent as auth_agent

    monkeypatch.setattr(
        surface_mod,
        "capture_anonymous_snapshot",
        lambda url: {"status": "error", "error": "RuntimeError"},
    )
    result = auth_agent.auth_node(_auth_state())  # no credentials path
    codes = {lim["code"] for lim in result["engagement_limitations"]}
    assert "pre_auth_snapshot_unavailable" in codes
    assert result["pre_auth_snapshot"]["status"] == "error"


# --------------------------------------------------------------------------
# hypothesis fuel from auth-only surface (step 12 -> 20)
# --------------------------------------------------------------------------

def test_auth_only_endpoints_produce_auth_bypass_hypotheses() -> None:
    from webpent.agents.hypothesis_analyzer.agent import hypothesis_node

    state = {
        "target": Target(url="http://10.1.2.3/app"),
        "hypotheses": [],
        "crawled_data": {"endpoints": ["http://10.1.2.3/app/invoices/182"], "forms": []},
        "skip_recon": True,
        "thread_id": str(uuid4()),
        "auth_surface_diff": {
            "schema_version": AUTH_SURFACE_SCHEMA_VERSION,
            "status": "ok",
            "counts": {"both": 0, "auth_only": 1, "anonymous_only": 0},
            "records": [],
            "auth_only_endpoints": ["http://10.1.2.3/app/invoices/182"],
        },
    }
    result = hypothesis_node(state)
    hypotheses = result.get("hypotheses") or []
    auth_only_hyps = [
        h for h in hypotheses
        if h.vuln_class == "auth_bypass"
        and "invoices/182" in str(h.target_url)
    ]
    assert auth_only_hyps, "auth-only endpoint must yield an auth_bypass hypothesis"
    detail = auth_only_hyps[0].origin_detail or ""
    assert "auth surface diff" in detail.lower()
    # The diff is heuristic fuel only — no confirmation authority.
    assert auth_only_hyps[0].deterministic_match is not True


def test_auth_surface_producer_bounded_and_absent_safe() -> None:
    from webpent.agents.hypothesis_analyzer.agent import hypothesis_node

    base = {
        "target": Target(url="http://10.1.2.3/app"),
        "hypotheses": [],
        "crawled_data": {"endpoints": [], "forms": []},
        "skip_recon": True,
        "thread_id": str(uuid4()),
    }
    # Absent diff -> no crash, no auth_bypass hypotheses.
    result = hypothesis_node(dict(base))
    assert not [h for h in result.get("hypotheses") or [] if h.vuln_class == "auth_bypass"]
    # Unavailable diff -> same.
    unavailable = dict(base, auth_surface_diff={"status": "unavailable"})
    result = hypothesis_node(unavailable)
    assert not [h for h in result.get("hypotheses") or [] if h.vuln_class == "auth_bypass"]


# --------------------------------------------------------------------------
# phase liveness gates (step 9)
# --------------------------------------------------------------------------

def test_phase_liveness_no_cookies_is_noop() -> None:
    from webpent.shared.session_liveness import phase_liveness_update

    update = phase_liveness_update({"session_cookies": {}}, phase="crawler")
    assert update["session_liveness"]["status"] == "unknown"
    assert "engagement_limitations" not in update


def test_phase_liveness_downgrade_appends_declared_limitation(monkeypatch) -> None:
    from webpent.shared import session_liveness as sl

    monkeypatch.setattr(sl, "probe_session", lambda url, cookies: (False, "redirected to login"))
    state = {
        "target": Target(url="http://127.0.0.1:9999/"),
        "session_cookies": {"sid": "stale"},
        "session_liveness": {
            "reauth_attempts": sl.MAX_REAUTH_ATTEMPTS_PER_RUN,  # budget exhausted
        },
        "credentials": {},
    }
    update = sl.phase_liveness_update(state, phase="crawler")
    record = update["session_liveness"]
    assert record["status"] == "invalid"
    assert record["downgrade_requested"] is True
    limitations = update.get("engagement_limitations") or []
    assert any(lim["code"] == "session_downgraded" for lim in limitations)
    assert any(lim["source"] == "session_liveness:crawler" for lim in limitations)


def test_crawler_and_bac_and_blf_call_the_liveness_gate(monkeypatch) -> None:
    """Wiring lock: the three heavy phases must invoke the shared gate."""
    import inspect

    from webpent.agents.access_control import agent as bac_mod
    from webpent.agents.business_logic_fuzzer import agent as blf_mod
    from webpent.agents.crawler import agent as crawler_mod

    for module, node_name in (
        (crawler_mod, "crawler_node"),
        (bac_mod, "access_control_node"),
        (blf_mod, "business_logic_fuzzer_node"),
    ):
        source = inspect.getsource(getattr(module, node_name))
        assert "phase_liveness_update" in source, (
            f"{node_name} must call the shared phase liveness gate"
        )
        assert 'phase="' in source
