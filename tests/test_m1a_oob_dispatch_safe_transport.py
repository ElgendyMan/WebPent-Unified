"""M1-A (M-5) regression: OOB poll + notification dispatch must use the
ONE authoritative safe transport — no raw urlopen on env-shaped URLs.

Contract (M1_READINESS_REVIEW §2.5):
  * both sites route through ``make_safe_httpx_client`` (recorder test);
  * a URL pointing at a private IP outside the engagement allowlist is
    BLOCKED by the transport: oob poll → ``[]`` (fail-open read),
    notification dispatch → ``False`` (fail-open send);
  * no ``urlopen`` remains in either module (source gate);
  * legitimate https collector/endpoint behavior is unchanged.
"""
from __future__ import annotations

from pathlib import Path

import httpx
import pytest

REPO = Path(__file__).resolve().parents[1]


class _FakeSafeClient:
    def __init__(self, *, response: httpx.Response | None = None,
                 raise_error: Exception | None = None) -> None:
        self.response = response or httpx.Response(200, json=[])
        self.raise_error = raise_error
        self.calls: list[tuple[str, str]] = []

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def get(self, url, **kwargs):
        self.calls.append(("GET", url))
        if self.raise_error:
            raise self.raise_error
        self.response.request = httpx.Request("GET", url)
        return self.response

    def post(self, url, **kwargs):
        self.calls.append(("POST", url))
        if self.raise_error:
            raise self.raise_error
        self.response.request = httpx.Request("POST", url)
        return self.response

    def request(self, method, url, **kwargs):
        self.calls.append((method, url))
        if self.raise_error:
            raise self.raise_error
        return self.response


# ---------------------------------------------------------------------------
# oob.poll_remote_collector
# ---------------------------------------------------------------------------

def test_oob_poll_uses_safe_factory(monkeypatch):
    import webpent.shared.http as http_module
    from webpent.shared.oob import poll_remote_collector

    fake = _FakeSafeClient(response=httpx.Response(200, json=[
        {"protocol": "dns", "seen_at": "2026-11-05T00:00:00Z"}
    ]))
    monkeypatch.setattr(http_module, "make_safe_httpx_client", lambda **kw: fake)

    records = poll_remote_collector("https://collector.example.test", token="tok")
    assert fake.calls == [("GET", "https://collector.example.test?token=tok")]
    assert records == [{"protocol": "dns", "seen_at": "2026-11-05T00:00:00Z"}]


def test_oob_poll_fail_open_returns_empty(monkeypatch):
    import webpent.shared.http as http_module
    from webpent.shared.oob import poll_remote_collector

    fake = _FakeSafeClient(raise_error=httpx.ConnectError("unreachable"))
    monkeypatch.setattr(http_module, "make_safe_httpx_client", lambda **kw: fake)
    assert poll_remote_collector("https://collector.example.test", token="tok") == []


def test_oob_poll_private_ip_blocked_by_real_transport():
    """Private IP outside the engagement allowlist → [] (blocked, not fetched)."""
    from webpent.shared.oob import poll_remote_collector

    records = poll_remote_collector("http://192.168.1.10:8080", token="tok", timeout=2)
    assert records == []


def test_dispatch_private_ip_blocked_returns_false():
    from webpent.integrations.notifications.dispatch import _default_send

    # http scheme + non-loopback private host is rejected by the
    # scheme/loopback rule before any network activity.
    assert _default_send("http://192.168.1.10/hook", {"k": "v"}) is False


def test_dispatch_loopback_allowed_via_safe_factory(monkeypatch):
    import webpent.integrations.notifications.dispatch as dispatch_mod
    import webpent.shared.http as http_module

    fake = _FakeSafeClient(response=httpx.Response(200, json={"ok": True}))
    monkeypatch.setattr(http_module, "make_safe_httpx_client", lambda **kw: fake)

    assert dispatch_mod._default_send("http://127.0.0.1:9001/hook", {"k": "v"}) is True
    assert fake.calls == [("POST", "http://127.0.0.1:9001/hook")]


def test_dispatch_fail_open_returns_false(monkeypatch):
    import webpent.integrations.notifications.dispatch as dispatch_mod
    import webpent.shared.http as http_module

    fake = _FakeSafeClient(raise_error=httpx.ConnectError("down"))
    monkeypatch.setattr(http_module, "make_safe_httpx_client", lambda **kw: fake)
    assert dispatch_mod._default_send("https://hooks.example.test/x", {"k": "v"}) is False


def test_no_urlopen_remains_in_either_module():
    for rel in (
        "src/webpent/shared/oob.py",
        "src/webpent/integrations/notifications/dispatch.py",
    ):
        source = (REPO / rel).read_text(encoding="utf-8")
        assert "urlopen(" not in source, f"M-5 REGRESSION: urlopen call back in {rel}"
        assert "urllib.request" not in source, f"M-5 REGRESSION: urllib.request import back in {rel}"
