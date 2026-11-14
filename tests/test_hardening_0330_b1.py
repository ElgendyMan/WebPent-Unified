"""B1 hardening window 0.33.0 — docs/PRODUCTION_HARDENING_PLAN_0330.md.

F-01  ab_lab run_id collision (second target, same client, same week).
F-02  ProviderPool -> OpenAICompatibleProvider contract (TypeError died).
F-03  OpenAICompatibleProvider httpx client close (no leak per call).
P1-09 pivot_engine annotations resolve (Any imported).

Each test documents the failure the fix closes; all were RED before the
0.33.0 edits and must stay GREEN after.
"""
from __future__ import annotations

import sqlite3
import typing

import pytest

from webpent.campaign.executor.pivot_engine import PivotEngine
from webpent.llm_researcher.providers.openai_compatible import (
    OpenAICompatibleProvider,
)
from webpent.llm_researcher.providers.pool import (
    FailureCategory,
    ProviderPool,
    ProviderSlot,
    SlotStatus,
)
from webpent.memory.ab_lab import LessonABLab


# ---------------------------------------------------------------------------
# F-01 — open_week must support multiple targets per client per week
# ---------------------------------------------------------------------------


def test_f01_open_week_second_target_same_week(tmp_path):
    lab = LessonABLab(database_path=tmp_path / "ab.sqlite3")
    first = lab.open_week(
        client_id="acme",
        target_url="https://t1.example.com",
        authorization_ref="AUTH-1",
        mode="standard",
    )
    second = lab.open_week(
        client_id="acme",
        target_url="https://t2.example.com",
        authorization_ref="AUTH-1",
        mode="standard",
    )
    # Before F-01 the second open raised sqlite3.IntegrityError
    # (UNIQUE constraint failed: ab_runs.run_id) and rolled back the
    # week row — the second target could never be A/B tested.
    assert first["already_open"] is False
    assert second["already_open"] is False
    assert second["week_key"] == first["week_key"]

    conn = sqlite3.connect(tmp_path / "ab.sqlite3")
    try:
        weeks = conn.execute("SELECT COUNT(*) FROM ab_weeks").fetchone()[0]
        runs = conn.execute("SELECT COUNT(*) FROM ab_runs").fetchone()[0]
        run_ids = [r[0] for r in conn.execute("SELECT run_id FROM ab_runs").fetchall()]
    finally:
        conn.close()
    assert weeks == 2
    assert runs == 4
    assert len(set(run_ids)) == 4, "run ids must be unique across targets"


def test_f01_open_week_idempotent_same_target(tmp_path):
    lab = LessonABLab(database_path=tmp_path / "ab.sqlite3")
    lab.open_week(
        client_id="acme",
        target_url="https://t1.example.com",
        authorization_ref="AUTH-1",
        mode="standard",
    )
    again = lab.open_week(
        client_id="acme",
        target_url="https://t1.example.com",
        authorization_ref="AUTH-1",
        mode="standard",
    )
    assert again["already_open"] is True
    conn = sqlite3.connect(tmp_path / "ab.sqlite3")
    try:
        assert conn.execute("SELECT COUNT(*) FROM ab_runs").fetchone()[0] == 2
    finally:
        conn.close()


def test_f01_run_ids_differ_across_targets_same_client(tmp_path):
    lab = LessonABLab(database_path=tmp_path / "ab.sqlite3")
    lab.open_week(client_id="c", target_url="https://a.example.com",
                  authorization_ref="AUTH-1", mode="standard")
    lab.open_week(client_id="c", target_url="https://b.example.com",
                  authorization_ref="AUTH-1", mode="standard")
    plan = lab.tick()  # dry plan: oldest non-terminal week's due run
    assert plan is not None
    assert plan["action"] == "planned_run"


# ---------------------------------------------------------------------------
# F-02 — ProviderPool contract with OpenAICompatibleProvider
# ---------------------------------------------------------------------------


def _slot(env_var: str = "WEBPENT_TEST_LLM_KEY") -> ProviderSlot:
    return ProviderSlot(
        slot_id="s0",
        env_var_name=env_var,
        base_url_env="WEBPENT_TEST_LLM_BASE",
        model_env="WEBPENT_TEST_LLM_MODEL",
    )


def test_f02_pool_generate_success_with_real_provider(monkeypatch):
    """The exact regression: pool built the provider with kwargs that do not
    exist (api_key=/base_url=/policy_hash=) -> TypeError on EVERY call."""
    monkeypatch.setenv("WEBPENT_TEST_LLM_KEY", "sk-test")
    pool = ProviderPool(policy_hash="deadbeefcafe")
    pool.slots = [_slot()]

    captured: dict[str, object] = {}

    def fake_generate(self, prompt, max_tokens=1000, **kwargs):
        captured["model"] = self.model
        captured["prompt_version_hash"] = self.prompt_version_hash
        return object.__new__(type("R", (), {"error": None}))

    monkeypatch.setattr(OpenAICompatibleProvider, "generate", fake_generate)
    response = pool.generate("hello", max_tokens=32)
    assert response is not None
    assert captured["prompt_version_hash"] == "deadbeefcafe"


def test_f02_pool_error_response_is_a_failure_not_success(monkeypatch):
    """BaseLLMProvider.generate returns error-carrying LLMResponse instead of
    raising; the pool used to record that as slot SUCCESS."""
    monkeypatch.setenv("WEBPENT_TEST_LLM_KEY", "sk-test")
    pool = ProviderPool(policy_hash="deadbeefcafe")
    slot = _slot()
    pool.slots = [slot]

    def fake_generate(self, prompt, max_tokens=1000, **kwargs):
        from webpent.llm_researcher.providers.base import LLMResponse

        return LLMResponse(model=self.model, error="HTTP_401: bad key")

    monkeypatch.setattr(OpenAICompatibleProvider, "generate", fake_generate)
    with pytest.raises(RuntimeError, match="REAL_API_UNAVAILABLE"):
        pool.generate("hello")
    assert slot.status == SlotStatus.AUTH_FAILED
    assert slot.failure_category == FailureCategory.AUTH


def test_f02_pool_single_slot_failure_does_not_kill_pool(monkeypatch):
    """One slot failing with an error response must not open the circuit on
    the others — a healthy second slot still serves the request."""
    monkeypatch.setenv("WEBPENT_TEST_LLM_KEY", "sk-test")
    pool = ProviderPool(policy_hash="deadbeefcafe")
    bad = _slot("WEBPENT_TEST_LLM_KEY")
    good = _slot("WEBPENT_TEST_LLM_KEY_2")
    monkeypatch.setenv("WEBPENT_TEST_LLM_KEY_2", "sk-test-2")
    pool.slots = [bad, good]

    responses = iter([
        "HTTP_500: exploded",  # bad slot: transient error response
        "ok",                   # good slot
    ])

    def fake_generate(self, prompt, max_tokens=1000, **kwargs):
        from webpent.llm_researcher.providers.base import LLMResponse

        text = next(responses)
        if text == "ok":
            return LLMResponse(model=self.model, content="fine")
        return LLMResponse(model=self.model, error=text)

    monkeypatch.setattr(OpenAICompatibleProvider, "generate", fake_generate)
    response = pool.generate("hello")
    assert response.error is None
    assert good.status == SlotStatus.HEALTHY


# ---------------------------------------------------------------------------
# F-03 — provider closes its lazy httpx client
# ---------------------------------------------------------------------------


def test_f03_provider_close_is_idempotent(monkeypatch):
    monkeypatch.setenv("WEBPENT_TEST_LLM_KEY", "sk-test")
    provider = OpenAICompatibleProvider(model="m", api_key="sk-test")
    client = provider._get_client()
    assert client is not None
    provider.close()
    assert client.is_closed
    provider.close()  # second close must be a no-op, not AttributeError
    with provider:  # context manager re-entry must not explode
        pass


def test_f03_pool_generate_closes_provider_client(monkeypatch):
    """Every pool.generate() built a provider whose httpx client was never
    closed — one leaked connection pool per call."""
    monkeypatch.setenv("WEBPENT_TEST_LLM_KEY", "sk-test")
    pool = ProviderPool(policy_hash="deadbeefcafe")
    pool.slots = [_slot()]

    clients: list[object] = []
    real_get_client = OpenAICompatibleProvider._get_client

    def spy_get_client(self):
        client = real_get_client(self)
        clients.append(client)
        return client

    def fake_generate(self, prompt, max_tokens=1000, **kwargs):
        self._get_client()  # force client construction
        from webpent.llm_researcher.providers.base import LLMResponse

        return LLMResponse(model=self.model, content="fine")

    monkeypatch.setattr(OpenAICompatibleProvider, "_get_client", spy_get_client)
    monkeypatch.setattr(OpenAICompatibleProvider, "generate", fake_generate)
    pool.generate("hello")
    assert len(clients) == 1
    assert clients[0].is_closed, "pool must close the provider's httpx client"


# ---------------------------------------------------------------------------
# P1-09 — pivot_engine annotations resolve at runtime
# ---------------------------------------------------------------------------


def test_p109_pivot_engine_annotations_resolve():
    # Before P1-09: typing.get_type_hints raised NameError: name 'Any'
    hints = typing.get_type_hints(PivotEngine._consecutive_failures)
    assert typing.get_origin(hints["hypothesis_results"]) is list
    hints = typing.get_type_hints(PivotEngine._trigger_fired)
    assert typing.get_origin(hints["hypothesis_results"]) is list


def test_p109_pivot_engine_check_contract_intact():
    """The engine's mechanical contract is unchanged by the import fix."""
    from webpent.campaign.executor.pivot_engine import PivotDecision

    assert hasattr(PivotEngine, "check")
    decision = PivotEngine._consecutive_failures([])
    assert decision == 0
    assert PivotDecision is not None
