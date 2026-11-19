from pathlib import Path

import pytest

from webpent.agents.execution_sandbox import agent as sandbox_agent
from webpent.shared.capability_manifest import build_capability_manifest, resolve_browser_executable


def test_capability_manifest_records_browser_executable_metadata() -> None:
    manifest = build_capability_manifest()
    browser = manifest["capabilities"]["browser"]
    assert browser["package_available"] is True
    assert browser["browser_executable_available"] is True
    assert browser["executable_path"]
    assert len(browser["sha256"]) == 64
    assert browser["version"]


def test_configured_invalid_browser_path_fails_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("WEBPENT_CHROMIUM_PATH", "/definitely/missing/chromium")
    assert resolve_browser_executable() is None


def test_execution_sandbox_launches_validated_system_chromium() -> None:
    executable = resolve_browser_executable()
    if not executable:
        pytest.skip("No local Chromium executable is available")

    playwright, browser = sandbox_agent._try_launch_browser()
    assert playwright is not None
    assert browser is not None
    try:
        context = browser.new_context()
        page = context.new_page()
        page.goto("about:blank")
        assert page.evaluate("() => 6 * 7") == 42
        screenshot = Path("/tmp/webpent_browser_readiness_test.png")
        page.screenshot(path=str(screenshot))
        assert screenshot.is_file() and screenshot.stat().st_size > 0
        context.close()
    finally:
        browser.close()
        playwright.stop()
