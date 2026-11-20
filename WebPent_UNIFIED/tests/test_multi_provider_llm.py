from __future__ import annotations

import json
from pathlib import Path

import pytest

from webpent.config.settings import Settings
from webpent.llm_researcher.key_pool import KeyPool, KeyStatus
from webpent.llm_researcher.task_router import LLMTask, TaskRouter
from webpent.shared.llm import _api_key_for_provider


def test_environment_overrides_local_config_and_status_is_redacted(tmp_path: Path) -> None:
    config = {
        "providers": [
            {
                "name": "openrouter",
                "api_key": "OPENROUTER_API_KEY",
                "models": [{"id": "qwen/qwen3-coder:free", "role": "code"}],
            }
        ]
    }
    path = tmp_path / ".llm_keys.json"
    path.write_text(json.dumps(config), encoding="utf-8")
    pool = KeyPool.load(config_path=path, env={"OPENROUTER_API_KEY": "env-secret-123"})
    selected = pool.select("openrouter", "qwen/qwen3-coder:free")
    assert selected is not None and selected.secret == "env-secret-123"
    snapshot = pool.status()
    assert "env-secret-123" not in json.dumps(snapshot)
    assert snapshot[0]["key_fingerprint"].startswith("key_")


def test_priority_and_round_robin_rotation() -> None:
    pool = KeyPool.load(env={"OPENROUTER_API_KEY": "one", "OLLAMA_URL": "http://localhost:11434"})
    first = pool.select("openrouter")
    second = pool.select("openrouter")
    assert first is not None and second is not None
    assert first.definition.priority == 1
    assert first.definition.model != second.definition.model


def test_failure_classification_and_cooldown() -> None:
    pool = KeyPool.load(env={"GROQ_API_KEY": "secret"})
    selected = pool.select("groq")
    assert selected is not None

    class RateLimited(RuntimeError):
        status_code = 429

    assert pool.mark_failure(selected, RateLimited()) is KeyStatus.RATE_LIMITED
    second = pool.select("groq")
    assert second is not None and second is not selected
    assert pool.mark_failure(second, RateLimited()) is KeyStatus.RATE_LIMITED
    assert pool.select("groq") is None
    pool.reset()
    selected = pool.select("groq")
    assert selected is not None

    class Unauthorized(RuntimeError):
        status_code = 401

    assert pool.mark_failure(selected, Unauthorized()) is KeyStatus.AUTH_FAILED
    second = pool.select("groq")
    assert second is not None
    assert pool.mark_failure(second, Unauthorized()) is KeyStatus.AUTH_FAILED
    assert pool.select("groq") is None


def test_local_fallback_is_only_advertised_when_configured() -> None:
    without_local = TaskRouter(KeyPool.load(env={"OPENROUTER_API_KEY": "x"}))
    assert all(c.provider != "local" for c in without_local.route(LLMTask.OUTPUT_ANALYZE))
    with_local = TaskRouter(KeyPool.load(env={"OLLAMA_URL": "http://localhost:11434"}))
    assert any(c.provider == "local" for c in with_local.route(LLMTask.OUTPUT_ANALYZE))


def test_task_router_returns_payload_route_for_configured_free_provider() -> None:
    pool = KeyPool.load(env={"OPENROUTER_API_KEY": "x"})
    routes = TaskRouter(pool).route(LLMTask.PAYLOAD_SELECT)
    assert routes
    assert routes[0].provider == "openrouter"
    assert any("qwen3-coder" in route.model for route in routes)
    assert all(route.prompt_style == "technical" for route in routes)


def test_explicit_settings_do_not_inherit_ambient_provider_secret(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("OPENAI_API_KEY", "ambient-secret")
    explicit = Settings(llm_enabled=True)
    assert _api_key_for_provider("openai", explicit) is None
