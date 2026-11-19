from __future__ import annotations

import hashlib
import hmac
import json
from types import SimpleNamespace

import pytest
from pydantic import SecretStr


class _FakeContext:
    def __init__(self):
        self.http_handler = None
        self.websocket_handler = None

    def route(self, pattern, handler):
        assert pattern == "**/*"
        self.http_handler = handler

    def route_web_socket(self, pattern, handler):
        assert pattern == "**/*"
        self.websocket_handler = handler


class _FailingHttpContext:
    def route(self, pattern, handler):
        raise RuntimeError("route failed")

    def route_web_socket(self, pattern, handler):
        raise AssertionError("websocket registration must not run")


class _FailingWebSocketContext:
    def __init__(self):
        self.unrouted = False

    def route(self, pattern, handler):
        self.handler = handler

    def route_web_socket(self, pattern, handler):
        raise RuntimeError("websocket route failed")

    def unroute(self, pattern, handler):
        self.unrouted = True


class _FakeWebSocket:
    def __init__(self, url):
        self.url = url
        self.closed = None
        self.connected = False

    def close(self, *, code, reason):
        self.closed = (code, reason)

    def connect_to_server(self):
        self.connected = True


def test_playwright_ssrf_guard_fails_closed_on_http_registration_error():
    import webpent.shared.http as http

    with pytest.raises(RuntimeError, match="HTTP SSRF guard installation failed"):
        http.install_playwright_ssrf_guard(_FailingHttpContext(), target_hosts=[])


def test_playwright_ssrf_guard_rolls_back_on_websocket_registration_error():
    import webpent.shared.http as http

    context = _FailingWebSocketContext()
    with pytest.raises(RuntimeError, match="WebSocket SSRF guard installation failed"):
        http.install_playwright_ssrf_guard(context, target_hosts=[])
    assert context.unrouted is True


def test_playwright_ssrf_guard_registers_websocket_route(monkeypatch):
    import webpent.shared.http as http

    monkeypatch.setattr(http, "_is_blocked_host", lambda host: host == "127.0.0.1")
    context = _FakeContext()
    http.install_playwright_ssrf_guard(context, target_hosts=[])

    assert context.websocket_handler is not None
    blocked = _FakeWebSocket("ws://127.0.0.1:6379/socket")
    context.websocket_handler(blocked)
    assert blocked.closed == (1008, "accessdenied")
    assert blocked.connected is False

    allowed = _FakeWebSocket("ws://127.0.0.1:6379/socket")
    context = _FakeContext()
    http.install_playwright_ssrf_guard(context, target_hosts=["127.0.0.1"])
    context.websocket_handler(allowed)
    assert allowed.connected is True
    assert allowed.closed is None


def test_preflight_requires_playwright_1_48_or_newer(monkeypatch):
    import webpent.shared.preflight as preflight

    fake_playwright = SimpleNamespace(__version__="1.47.2")
    monkeypatch.setitem(__import__("sys").modules, "playwright", fake_playwright)
    result = preflight._check_playwright_ws_guard()
    assert result["ws_guard_available"] is False
    assert "UNMITIGATED" in result["status"]


@pytest.mark.asyncio
async def test_webhook_sends_hmac_and_enforces_tls(monkeypatch):
    import webpent.integrations.webhook as webhook

    finding = SimpleNamespace(
        id="finding-id",
        title="Test finding",
        severity="high",
        confidence_level="Tool-Confirmed",
        vuln_class="XSS",
        url="https://target.test/item",
        tool_name="test",
        payload="marker",
        business_impact="impact",
        compliance_tags=[],
        evidence_hash="a" * 64,
        reasoning="replay evidence",
        cvss_score=7.5,
        description="description",
    )
    settings = SimpleNamespace(
        webhook_secret=SecretStr("test-signing-secret"),
        webhook_timeout=7.0,
    )
    monkeypatch.setattr(webhook, "get_settings", lambda: settings)

    captured = {}

    class _Response:
        status_code = 202
        text = "accepted"

    class _Client:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *args):
            return False

        async def post(self, url, *, content, headers):
            captured.update(url=url, content=content, headers=headers)
            return _Response()

    def fake_client(**kwargs):
        captured["client_kwargs"] = kwargs
        return _Client()

    monkeypatch.setattr(webhook, "make_safe_httpx_async_client", fake_client)
    assert await webhook.push_to_webhook(finding, "https://collector.test/hook") is True

    assert captured["client_kwargs"]["verify"] is True
    assert captured["headers"]["Content-Type"] == "application/json"
    body = captured["content"]
    expected = hmac.new(b"test-signing-secret", body, hashlib.sha256).hexdigest()
    assert captured["headers"]["X-WebPent-Signature"] == f"HMAC-SHA256={expected}"
    assert json.loads(body)["finding"]["id"] == "finding-id"


@pytest.mark.asyncio
async def test_webhook_refuses_unsigned_delivery(monkeypatch):
    import webpent.integrations.webhook as webhook

    finding = SimpleNamespace(id="finding-id")
    monkeypatch.setattr(
        webhook,
        "get_settings",
        lambda: SimpleNamespace(webhook_secret=SecretStr(""), webhook_timeout=7.0),
    )
    called = False

    def fail_if_called(**kwargs):
        nonlocal called
        called = True
        raise AssertionError("unsigned delivery must not create an HTTP client")

    monkeypatch.setattr(webhook, "make_safe_httpx_async_client", fail_if_called)
    assert await webhook.push_to_webhook(finding, "https://collector.test/hook") is False
    assert called is False
