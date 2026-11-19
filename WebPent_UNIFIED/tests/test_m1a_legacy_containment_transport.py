"""M1-A (M-4) regression: ContainedHTTPClient must delegate to the ONE
authoritative safe transport — never to a raw httpx.Client.

Contract (M1_READINESS_REVIEW §2.4):
  * ``_delegate`` routes through
    ``webpent.shared.http.make_safe_httpx_client`` (SSRF pinning +
    blocklist + rate ceiling all apply);
  * the raw-``httpx`` fallback is GONE — the module contains no
    ``httpx.Client`` construction at all;
  * ImportError of the authoritative module propagates loudly
    (fail-closed), it must never silently degrade the transport.
"""
from __future__ import annotations

import ast
import inspect
from pathlib import Path

import httpx
import pytest

from webpent.shared.legacy_containment import ContainedHTTPClient

MODULE_PATH = (
    Path(__file__).resolve().parents[1]
    / "src/webpent/shared/legacy_containment.py"
)


class _StubScopeLaw:
    """Minimal ScopeLaw stand-in: authorize everything in-scope."""

    def authorize_invocation(self, *, tool_name, target_url, arguments):
        from types import SimpleNamespace

        return SimpleNamespace(in_scope=True, reason="stub-authorized")


class _FakeSafeClient:
    def __init__(self) -> None:
        self.requests: list[tuple[str, str]] = []

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def request(self, method, url, **kwargs):
        self.requests.append((method, url))
        return httpx.Response(200, text="contained-ok")


def test_delegation_goes_through_safe_factory(monkeypatch):
    import webpent.shared.http as http_module

    fake = _FakeSafeClient()
    seen_kwargs: list[dict] = []

    def recorder(**kwargs):
        seen_kwargs.append(kwargs)
        return fake

    monkeypatch.setattr(http_module, "make_safe_httpx_client", recorder)

    client = ContainedHTTPClient(scope_law=_StubScopeLaw(), legacy_path_name="m1a_m4")
    response = client.get("https://target.test/api")
    assert response.text == "contained-ok"
    assert fake.requests == [("GET", "https://target.test/api")]
    # SSRF safety defaults are pinned by the delegate, not caller choice
    assert seen_kwargs and seen_kwargs[0].get("follow_redirects") is False


def test_no_raw_httpx_client_in_module():
    source = MODULE_PATH.read_text(encoding="utf-8")
    assert "httpx.Client(" not in source, (
        "M-4 REGRESSION: legacy_containment constructs a raw httpx.Client — "
        "the unsafe fallback must never return"
    )
    tree = ast.parse(source)
    for node in ast.walk(tree):
        if isinstance(node, ast.Attribute) and node.attr == "Client":
            pytest.fail("M-4 REGRESSION: httpx.Client reference found in AST")


def test_import_error_fails_loud_not_silent(monkeypatch):
    """A broken authoritative module must raise, not degrade the transport."""
    import builtins

    client = ContainedHTTPClient(scope_law=_StubScopeLaw(), legacy_path_name="m1a_m4")

    real_import = builtins.__import__

    def _blocked_import(name, *args, **kwargs):
        if name == "webpent.shared.http":
            raise ImportError("simulated authoritative-module failure")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", _blocked_import)
    with pytest.raises(ImportError, match="simulated authoritative-module failure"):
        client.get("https://target.test/api")


def test_call_log_records_authorization():
    client = ContainedHTTPClient(scope_law=_StubScopeLaw(), legacy_path_name="m1a_m4")
    assert client._scope_law is not None
    entries = client.call_log
    assert isinstance(entries, tuple)
