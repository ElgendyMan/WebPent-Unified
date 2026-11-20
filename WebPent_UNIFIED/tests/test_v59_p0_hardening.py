from __future__ import annotations

import inspect

import pytest

from webpent.config.settings import Settings
from webpent.graph import builder
from webpent.state.initial_state import build_initial_state
from webpent.workers import pentest_worker


def _target() -> dict[str, str]:
    return {"url": "https://target.example", "name": "target"}


def test_initial_state_persists_auto_approve_policy() -> None:
    state = build_initial_state(_target(), thread_id="thread-p0", auto_approve=True)
    assert state["auto_approve"] is True


def test_initial_state_defaults_auto_approve_to_false() -> None:
    state = build_initial_state(_target(), thread_id="thread-legacy")
    assert state["auto_approve"] is False


def test_initial_state_accepts_explicit_false() -> None:
    state = build_initial_state(_target(), thread_id="thread-false", auto_approve=False)
    assert state["auto_approve"] is False


def test_run_task_threads_auto_approve_into_initial_state() -> None:
    source = inspect.getsource(pentest_worker.run_pentest_task.run)
    assert "auto_approve=auto_approve" in source


def test_resume_restores_checkpointed_auto_approve() -> None:
    source = inspect.getsource(pentest_worker.resume_pentest_task.run)
    assert 'checkpoint_values.get("auto_approve", False)' in source
    assert "auto_approve=True" in source


def test_resume_legacy_checkpoint_fails_closed() -> None:
    source = inspect.getsource(pentest_worker.resume_pentest_task.run)
    assert "legacy checkpoints" in source
    assert "defaulting auto_approve=False" in source
    assert "auto_approve=False" in source


def test_resume_returns_restored_policy_metadata() -> None:
    source = inspect.getsource(pentest_worker.resume_pentest_task.run)
    assert '"auto_approve": resume_auto_approve' in source


@pytest.mark.parametrize(
    ("enabled", "expected_attr"),
    [
        (True, "reporter_node_bug_bounty"),
        (False, "reporter_node"),
    ],
)
def test_reporter_selection_is_feature_flagged(
    monkeypatch: pytest.MonkeyPatch,
    enabled: bool,
    expected_attr: str,
) -> None:
    captured: dict[str, object] = {}
    original_add_node = builder.StateGraph.add_node

    def spy_add_node(
        graph: object,
        name: str,
        action: object,
        *args: object,
        **kwargs: object,
    ) -> object:
        if name == builder.NODE_REPORTER:
            captured["action"] = action
        return original_add_node(graph, name, action, *args, **kwargs)

    monkeypatch.setattr(builder.StateGraph, "add_node", spy_add_node)
    monkeypatch.setattr(
        builder,
        "get_settings",
        lambda: Settings(enable_bug_bounty_reporter=enabled),
    )

    builder.build_graph(auto_approve=True)

    # R-B: nodes are registered through the step-budget tracer wrapper;
    # the flag contract is that the wrapper's __wrapped__ IS the selected
    # reporter (tracer transparency preserves feature-flag selection).
    registered = getattr(captured["action"], "__wrapped__", captured["action"])
    assert registered is getattr(builder, expected_attr)


def test_no_local_target_is_embedded_in_resume_contract() -> None:
    source = inspect.getsource(pentest_worker.resume_pentest_task.run)
    assert "127.0.0.1:4280" not in source


def test_contracts_are_callable_and_local_only() -> None:
    assert callable(build_initial_state)
    assert callable(pentest_worker.resume_pentest_task.run)
    assert "socket" not in inspect.getsource(build_initial_state)


assert "auto_approve" in inspect.signature(build_initial_state).parameters
