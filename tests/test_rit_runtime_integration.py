"""RUNTIME-INTEGRATION (RIT) contract locks.

These tests lock the runtime-integration fixes delivered by the
IMPLEMENTATION + RUNTIME INTEGRATION pass. Each test exists to prevent a
specific wiring regression from silently returning:

RIT-1  Settings field-name kwargs (fail-closed ``Settings(llm_enabled=False)``)
RIT-5  DeepReconEngine is reachable from the real graph node (hypothesis_node)
RIT-6  planner_node imports its advisory-memory formatter (no silent fallback)
RIT-7  authenticated mode fails loud instead of downgrading to anonymous
"""
from __future__ import annotations

import pytest

from webpent.agents.hypothesis_analyzer.agent import hypothesis_node
from webpent.config.settings import Settings
from webpent.models.findings import VulnClass
from webpent.models.hypothesis import HypothesisOrigin
from webpent.models.targets import Target


def test_rit1_settings_kwargs_respected_for_alias_fields() -> None:
    """A programmatic fail-closed switch must not be silently dropped."""
    settings = Settings(llm_enabled=False)
    assert settings.llm_enabled is False
    assert Settings(LLM_ENABLED=False).llm_enabled is False


def _deep_recon_state(tmp_endpoints: list) -> dict:
    return {
        "target": Target(url="https://lab.example.test"),
        "skip_recon": False,
        "auto_approve": False,
        "engagement_id": "rit-lock-test",
        "crawled_data": {"endpoints": tmp_endpoints},
        "hypotheses": [],
        "findings": [],
        "javascript_intelligence": {},
    }


def test_rit5_deep_recon_reachable_from_hypothesis_node() -> None:
    """DeepReconEngine must produce hypotheses through the real node path."""
    state = _deep_recon_state(
        [
            "https://lab.example.test/",
            "https://lab.example.test/users/1234",
            "https://lab.example.test/api/v2/orders/987654321012",
        ]
    )
    result = hypothesis_node(state)
    deep_recon_hyps = [
        h for h in result["hypotheses"] if h.origin == HypothesisOrigin.DEEP_RECON.value
    ]
    assert deep_recon_hyps, (
        "DeepReconEngine unreachable from hypothesis_node — RIT-5 wiring regressed"
    )
    summary = result.get("deep_recon_summary")
    assert summary and summary.get("ingested_endpoints", 0) >= 2
    # Structural question only — never a confirmed vulnerability claim.
    for h in deep_recon_hyps:
        assert h.vuln_class == VulnClass.UNKNOWN.value
        assert "NOT a vulnerability claim" in h.origin_detail
        assert h.confidence_score <= 0.5


def test_rit5_deep_recon_respects_declared_method() -> None:
    """Dict-shaped crawler records must keep their observed HTTP method."""
    state = _deep_recon_state(
        [
            "https://lab.example.test/users/1",
            {"url": "https://lab.example.test/admin/settings", "method": "POST"},
        ]
    )
    result = hypothesis_node(state)
    posted = [
        h for h in result["hypotheses"] if "/admin/settings" in h.target_url
        and h.origin == HypothesisOrigin.DEEP_RECON.value
    ]
    assert posted and "POST" in posted[0].statement


def test_rit5_deep_recon_does_not_fabricate_auth_observations() -> None:
    """Discovered routes must not register principals (status_code=0 rule)."""
    state = _deep_recon_state(["https://lab.example.test/users/1"])
    result = hypothesis_node(state)
    summary = result.get("deep_recon_summary") or {}
    # ingest_route_observation(status_code=0) never yields an anonymous
    # principal: only a real 401/403 HTTP response may register one.
    assert summary.get("principals", 0) == 0


def test_rit6_planner_imports_learned_context_formatter(monkeypatch: pytest.MonkeyPatch) -> None:
    """planner_node must not NameError on its advisory-memory formatter."""
    import webpent.agents.planner.agent as planner_agent

    assert hasattr(planner_agent, "planner_node")
    # Import the symbol the way planner_node must be able to.

    state = {
        "target": Target(url="https://example.test"),
        "llm_enabled_override": True,
        "hypotheses": [],
        "learned_strategy": {"branch": "probe", "confidence": 0.4},
    }
    # Force the LLM-enabled branch: it must reach the provider-failure
    # fallback for a NON-NameError reason (no providers configured here).
    try:
        planner_agent.planner_node(state)
    except NameError:
        pytest.fail("planner_node raised NameError — RIT-6 regressed")
    except ValueError as exc:  # provider chain failure is honest and expected
        assert "LLM" in str(exc) or "provider" in str(exc).lower()


def test_rit7_authenticated_mode_fails_loud_without_vault(monkeypatch: pytest.MonkeyPatch) -> None:
    """Operator-supplied cookies + unavailable vault = hard failure, not
    silent anonymous scanning."""
    from webpent.workers import pentest_worker

    # Simulate a vault that cannot retain anything (encryption unavailable).
    monkeypatch.setattr(pentest_worker, "seal_session_cookies", lambda *a, **k: None)
    monkeypatch.setattr(pentest_worker, "unseal_session_cookies", lambda *a, **k: {})
    monkeypatch.setattr(pentest_worker, "sweep_expired", lambda *a, **k: 0)
    monkeypatch.setattr(
        pentest_worker, "seal_reauth_secret", lambda *a, **k: None
    )
    monkeypatch.setattr(
        pentest_worker, "unseal_reauth_secret", lambda *a, **k: None
    )

    # celery bind=True auto-injects self through Task.run; do NOT pass a
    # fake self positionally. The vault seam is patched at module level.
    from webpent.workers.pentest_worker import run_pentest_task as _bound

    with pytest.raises(RuntimeError, match="silently downgrade"):
        _bound.run(
            target_url="https://example.test",
            is_portswigger=False,
            thread_id="rit7-test",
            auto_approve=True,
            skip_recon=True,
            credentials={},
            session_cookies={"sid": "operator-session"},
            identity_profiles={},
        )
