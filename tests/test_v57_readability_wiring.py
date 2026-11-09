"""Contracts for v57 readability, state parity, and deterministic offline behavior."""

from __future__ import annotations

import pytest

from webpent.config.settings import Settings
from webpent.models.targets import Target
from webpent.shared import llm as llm_router
from webpent.state.initial_state import build_initial_state
from webpent.tools import registry as tool_registry


def _target() -> Target:
    return Target(url="https://example.test")


def test_initial_state_factory_is_copy_safe_and_contains_debug_surfaces() -> None:
    credentials = {"alice": "secret"}
    cookies = {"SESSION": "opaque"}
    state = build_initial_state(
        _target(),
        credentials=credentials,
        session_cookies=cookies,
        playwright_enabled=False,
        stealth_mode=True,
    )

    credentials["bob"] = "must-not-leak"
    cookies["OTHER"] = "must-not-leak"

    assert state["credentials"] == {"alice": "secret"}
    assert state["session_cookies"] == {"SESSION": "opaque"}
    assert state["surface_security"] == {}
    assert state["canonical_executions"] == []
    assert state["canonical_observations"] == []
    assert state["playwright_enabled"] is False
    assert state["stealth_mode"] is True


def test_tool_registry_discovery_is_lazy_and_idempotent() -> None:
    tool_registry.clear_registry()
    assert tool_registry._REGISTRY == {}
    assert tool_registry.get_tool("nuclei") is not None
    first_categories = tool_registry.get_all_categories()
    tool_registry.auto_discover()
    assert tool_registry.get_all_categories() == first_categories
    assert "recon" in first_categories


def test_tool_registry_diagnostics_are_redaction_safe() -> None:
    tool_registry.clear_registry()
    before = tool_registry.diagnostics()
    assert before["discovery_complete"] is False
    assert "tools" in before
    tool_registry.get_tool("nuclei")
    after = tool_registry.diagnostics()
    assert after["discovery_complete"] is True
    assert after["tool_count"] >= 1
    assert all(isinstance(name, str) for name in after["tools"])
    assert "api_key" not in repr(after).lower()


def test_llm_router_fails_closed_when_disabled(monkeypatch: pytest.MonkeyPatch) -> None:
    settings = Settings(llm_enabled=False)

    with pytest.raises(ValueError, match="LLM assistance is disabled"):
        llm_router.get_llm(llm_router.TaskType.ANALYSIS, settings=settings)

    monkeypatch.setattr(llm_router, "get_settings", lambda: settings)
    with pytest.raises(ValueError, match="LLM assistance is disabled"):
        llm_router.get_cached_llm(llm_router.TaskType.ANALYSIS)
    assert llm_router.supports_prompt_caching(llm_router.TaskType.ANALYSIS) is False


def test_anthropic_provider_is_routable_and_enables_prompt_caching(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    settings = Settings(llm_enabled=True, anthropic_api_key="test-anthropic-key")
    sentinel = object()
    calls: list[dict[str, object]] = []

    def fake_builder(**kwargs: object) -> object:
        calls.append(kwargs)
        return sentinel

    monkeypatch.setattr(llm_router, "_build_anthropic", fake_builder)
    monkeypatch.setattr(llm_router, "get_settings", lambda: settings)

    routed = llm_router.get_llm(llm_router.TaskType.ANALYSIS, settings=settings)

    assert routed is sentinel
    assert calls == [
        {
            "api_key": "test-anthropic-key",
            "model_name": "claude-sonnet-5",
            "settings": settings,
        }
    ]
    assert llm_router._api_key_for_provider("anthropic", settings) == (
        "test-anthropic-key"
    )
    assert llm_router.supports_prompt_caching(llm_router.TaskType.ANALYSIS) is True


def test_llm_diagnostics_are_local_and_redaction_safe() -> None:
    settings = Settings(llm_enabled=False)
    diagnostics = llm_router.get_llm_diagnostics(settings)

    assert diagnostics["enabled"] is False
    assert diagnostics["configured_providers"] == []
    assert diagnostics["fallback_mode"] == "deterministic"
    assert "api_key" not in repr(diagnostics).lower()
    assert set(diagnostics["tasks"]) == {task.value for task in llm_router.TaskType}


def test_llm_router_accepts_explicit_enabled_settings_without_provider_guessing() -> None:
    settings = Settings(llm_enabled=True)
    # No credentials are present in this test; the router must report the
    # configuration problem explicitly instead of manufacturing a provider.
    with pytest.raises(ValueError, match="No LLM providers configured"):
        llm_router.get_llm(llm_router.TaskType.ANALYSIS, settings=settings)
