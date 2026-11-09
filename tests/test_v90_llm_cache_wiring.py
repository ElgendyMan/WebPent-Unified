from __future__ import annotations

from types import SimpleNamespace

import webpent.shared.llm as llm_router


def test_try_get_llm_uses_cached_path_for_default_settings(monkeypatch) -> None:
    sentinel = object()
    calls: list[llm_router.TaskType] = []

    def fake_cached(task_type: llm_router.TaskType):
        calls.append(task_type)
        return sentinel

    monkeypatch.setattr(llm_router, "get_cached_llm", fake_cached)

    assert llm_router.try_get_llm(llm_router.TaskType.ANALYSIS) is sentinel
    assert calls == [llm_router.TaskType.ANALYSIS]


def test_try_get_llm_keeps_explicit_settings_uncached(monkeypatch) -> None:
    sentinel = object()
    explicit = SimpleNamespace(llm_enabled=True)
    calls: list[tuple[llm_router.TaskType, object]] = []

    def fake_get(task_type: llm_router.TaskType, *, settings):
        calls.append((task_type, settings))
        return sentinel

    monkeypatch.setattr(llm_router, "get_llm", fake_get)
    monkeypatch.setattr(
        llm_router,
        "get_cached_llm",
        lambda _task_type: (_ for _ in ()).throw(AssertionError("cache used")),
    )

    assert llm_router.try_get_llm(llm_router.TaskType.CODE, settings=explicit) is sentinel
    assert calls == [(llm_router.TaskType.CODE, explicit)]


def test_dynamic_cache_reports_hit_and_miss(monkeypatch) -> None:
    llm_router.clear_cached_llms()
    fake_settings = SimpleNamespace(llm_enabled=True)
    first = SimpleNamespace()
    builds: list[llm_router.TaskType] = []

    monkeypatch.setattr(llm_router, "get_settings", lambda: fake_settings)
    monkeypatch.setattr(
        llm_router,
        "get_llm",
        lambda task_type: builds.append(task_type) or first,
    )
    monkeypatch.setattr(
        llm_router,
        "_resolve_primary_provider",
        lambda _task_type: None,
    )

    assert llm_router.get_cached_llm(llm_router.TaskType.ANALYSIS) is first
    assert llm_router.get_cached_llm(llm_router.TaskType.ANALYSIS) is first
    metrics = llm_router.get_llm_cache_metrics()

    assert builds == [llm_router.TaskType.ANALYSIS]
    assert metrics["misses"] == 1
    assert metrics["hits"] == 1
    assert metrics["invalidations"] == 0
