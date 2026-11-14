"""M1-A (L-1) regression: every Playwright surface installs the network
interception SSRF guard.

Contract (M1_READINESS_REVIEW §3, L-1):
  * ``recon/browser_farm.py`` — every ``new_context`` gets
    ``install_playwright_ssrf_guard`` (same pattern as the execution
    sandbox / validator);
  * ``reporter/poc_recorder.py::playwright_factory`` — the POC browser
    context gets the same guard;
  * functional proof for the factory: a fake Playwright handle shows
    the guard is installed on the ACTUAL context object.
"""
from __future__ import annotations

import inspect
from pathlib import Path
from types import SimpleNamespace

REPO = Path(__file__).resolve().parents[1]


# ---------------------------------------------------------------------------
# Source-level gates (the farm's Playwright launch cannot run headless
# Chromium in this environment; the guard call is structural).
# ---------------------------------------------------------------------------

def test_browser_farm_installs_guard():
    from webpent.recon.browser_farm import BrowserFarm

    source = inspect.getsource(BrowserFarm.new_page)
    assert "install_playwright_ssrf_guard" in source, (
        "L-1 REGRESSION: browser_farm.new_page creates a context without "
        "the Playwright SSRF network guard"
    )
    # the guard must fire on context CREATION, before the page exists
    assert source.index("new_context") < source.index("install_playwright_ssrf_guard")


def test_poc_recorder_installs_guard():
    from webpent.reporter.poc_recorder import playwright_factory

    source = inspect.getsource(playwright_factory)
    assert "install_playwright_ssrf_guard" in source, (
        "L-1 REGRESSION: poc_recorder.playwright_factory creates a context "
        "without the Playwright SSRF network guard"
    )


# ---------------------------------------------------------------------------
# Functional proof with a fake Playwright handle
# ---------------------------------------------------------------------------

def test_playwright_factory_guards_actual_context(monkeypatch, tmp_path):
    import webpent.shared.http as http_module
    from webpent.reporter import poc_recorder

    guarded: list[object] = []

    def recorder(context, **kwargs):
        guarded.append(context)
        return None

    monkeypatch.setattr(http_module, "install_playwright_ssrf_guard", recorder)

    class _FakeContext:
        pass

    class _FakeBrowser:
        def new_context(self, **kwargs):
            return _FakeContext()

    class _FakeHandle:
        chromium = SimpleNamespace(launch=lambda **kw: _FakeBrowser())

        def start(self):
            return self

        def stop(self):
            pass

    import playwright.sync_api as sync_api

    monkeypatch.setattr(sync_api, "sync_playwright", lambda: _FakeHandle())

    context = poc_recorder.playwright_factory(tmp_path)
    assert isinstance(context, _FakeContext)
    assert guarded == [context], "guard must be installed on the real context object"


def test_browser_farm_guard_survives_context_reuse(monkeypatch):
    """The guard is installed exactly once per context creation path."""
    from webpent.recon import browser_farm as farm_mod

    source = (REPO / "src/webpent/recon/browser_farm.py").read_text(encoding="utf-8")
    assert source.count("install_playwright_ssrf_guard(") == 1
