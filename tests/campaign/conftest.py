"""Shared fixtures for the Campaign package tests.

The Campaign is a NEW, isolated package: it imports NOTHING from the
webpent core (same rule as verdict/emulator/rehearsal). All fixtures
here are plain dataclass/namespace stand-ins for the real upstream
signals (Oracle report, Prism pattern matches, Economist score) —
ThesisBuilder consumes them through duck-typed Protocols, so tests
never need the real modules.
"""
from __future__ import annotations

from types import SimpleNamespace

import pytest

from webpent.campaign.executor.budget_guard import (
    BudgetGuard,
    BudgetSnapshot,
)
from webpent.campaign.executor.phase_runner import (
    HypothesisResult,
    PhaseRunner,
)
from webpent.campaign.executor.pivot_engine import PivotEngine
from webpent.campaign.schemas import CampaignBudget, Family
from webpent.campaign.storage.campaign_store import CampaignStore
from webpent.campaign.strategist.phase_planner import PhasePlanner
from webpent.campaign.strategist.thesis_builder import ThesisBuilder


# ---------------------------------------------------------------------------
# Oracle stand-ins (U-ORACLE shape, duck-typed)
# ---------------------------------------------------------------------------

@pytest.fixture
def oracle_full():
    return SimpleNamespace(
        tech_stack={"backend": "node", "framework": "express", "version": "4.17"},
        subdomains=[
            "api.example.com", "legacy.example.com", "dev.example.com",
            "vpn.example.com", "mail.example.com", "old.example.com",
        ],
        historical_endpoints=[
            "/api/v1/users/{id}", "/api/v1/orders/{id}",
            "/api/v1/transactions/{id}",
        ],
        leaked_signals=[],
        crown_jewel_hints=["payment data"],
    )


@pytest.fixture
def oracle_minimal():
    return SimpleNamespace(
        tech_stack={},
        subdomains=[],
        historical_endpoints=[],
        leaked_signals=[],
        crown_jewel_hints=[],
    )


@pytest.fixture
def oracle_node_full(oracle_full):
    return oracle_full


@pytest.fixture
def oracle_with_leaks():
    return SimpleNamespace(
        tech_stack={"backend": "django", "version": "3.2"},
        subdomains=[
            "api.example.com", "legacy.example.com", "dev.example.com",
            "staging.example.com", "internal.example.com", "old.example.com",
        ],
        historical_endpoints=["/api/v1/users/{id}", "/admin/"],
        leaked_signals=[{"type": "credentials", "where": "js bundle"}],
        crown_jewel_hints=["user PII"],
    )


# ---------------------------------------------------------------------------
# Prism / Economist stand-ins
# ---------------------------------------------------------------------------

def _pattern(archetype, confidence, families):
    return SimpleNamespace(
        archetype_name=archetype,
        confidence=confidence,
        typical_families=families,
        typical_techniques=["mass assignment", "id enumeration"],
    )


@pytest.fixture
def patterns_fintech():
    return [
        _pattern("fintech_api", 0.85, {
            Family.BOLA: 0.8, Family.IDOR: 0.7,
            Family.AUTH_BYPASS: 0.45, Family.XSS: 0.35,
        }),
    ]


@pytest.fixture
def patterns_strong():
    return [
        _pattern("fintech_api", 0.9, {
            Family.BOLA: 0.85, Family.IDOR: 0.75, Family.AUTH_BYPASS: 0.5,
        }),
    ]


@pytest.fixture
def patterns_multi():
    return [
        _pattern("fintech_api", 0.8, {
            Family.BOLA: 0.8, Family.SQLI: 0.7, Family.SSRF: 0.6,
            Family.XSS: 0.5, Family.IDOR: 0.9,
        }),
    ]


@pytest.fixture
def patterns_many():
    return [
        _pattern("saas_dashboard", 0.9, {
            Family.BOLA: 0.9, Family.IDOR: 0.85, Family.SQLI: 0.8,
            Family.SSRF: 0.75, Family.XSS: 0.7, Family.AUTH_BYPASS: 0.65,
        }),
    ]


@pytest.fixture
def econ_a():
    return SimpleNamespace(tier="A", payout_potential=0.8, effort_estimate=6.0)


@pytest.fixture
def econ_b():
    return SimpleNamespace(tier="B", payout_potential=0.5, effort_estimate=8.0)


@pytest.fixture
def econ_c():
    return SimpleNamespace(tier="C", payout_potential=0.3, effort_estimate=12.0)


# ---------------------------------------------------------------------------
# Theses
# ---------------------------------------------------------------------------

@pytest.fixture
def thesis_fintech(oracle_full, patterns_fintech, econ_a):
    return ThesisBuilder().build(
        "target-1", oracle_full, patterns_fintech, econ_a)


@pytest.fixture
def thesis_with_multiple_families(oracle_full, patterns_multi, econ_a):
    return ThesisBuilder().build(
        "target-2", oracle_full, patterns_multi, econ_a)


@pytest.fixture
def thesis_with_many_families(oracle_full, patterns_many, econ_a):
    return ThesisBuilder().build(
        "target-3", oracle_full, patterns_many, econ_a)


# ---------------------------------------------------------------------------
# Budgets
# ---------------------------------------------------------------------------

@pytest.fixture
def budget_1000():
    return CampaignBudget(
        max_requests=1000, max_time_minutes=120, max_llm_calls=50)


@pytest.fixture
def tight_budget():
    return CampaignBudget(
        max_requests=20, max_time_minutes=5, max_llm_calls=3)


# ---------------------------------------------------------------------------
# Storage
# ---------------------------------------------------------------------------

@pytest.fixture
def store(tmp_path):
    return CampaignStore(tmp_path / "campaigns")


# ---------------------------------------------------------------------------
# Executor fixtures
# ---------------------------------------------------------------------------

class StubBrain:
    """Deterministic brain stub: same answer for every hypothesis."""

    def __init__(self, success=True, findings=None, requests_used=10):
        self._success = success
        self._findings = list(findings or [])
        self._requests_used = requests_used

    def evaluate(self, hypothesis, remaining_budget):
        return HypothesisResult(
            hypothesis_id=hypothesis.hypothesis_id,
            success=self._success,
            findings=list(self._findings),
            requests_used=self._requests_used,
            time_seconds=1.0,
            llm_calls_used=1,
            failure_reason=None if self._success else "hypothesis refuted",
        )


@pytest.fixture
def stub_brain_success():
    return StubBrain(success=True, findings=[{"kind": "stub-finding"}])


@pytest.fixture
def stub_brain_failing():
    return StubBrain(success=False)


@pytest.fixture
def runner(stub_brain_success):
    return PhaseRunner(
        brain=stub_brain_success,
        apex=None,
        budget_guard=BudgetGuard(),
        pivot_engine=PivotEngine(),
    )


@pytest.fixture
def runner_with_stub_brain(runner):
    return runner


@pytest.fixture
def runner_with_stub_brain_failing(stub_brain_failing):
    return PhaseRunner(
        brain=stub_brain_failing,
        apex=None,
        budget_guard=BudgetGuard(),
        pivot_engine=PivotEngine(),
    )


@pytest.fixture
def runner_with_budget_guard(stub_brain_success):
    return PhaseRunner(
        brain=stub_brain_success,
        apex=None,
        budget_guard=BudgetGuard(),
        pivot_engine=PivotEngine(),
    )


@pytest.fixture
def phases_fintech(thesis_fintech, budget_1000):
    return PhasePlanner().plan(thesis_fintech, budget_1000)


@pytest.fixture
def phase_idor(phases_fintech):
    return phases_fintech[0]


@pytest.fixture
def phase_with_pivot():
    """A family phase whose consecutive-failure trigger fires after 2."""
    from webpent.campaign.schemas import (
        Family, Hypothesis, Phase, PhaseBudget, PivotAction, PivotTrigger,
    )

    hypotheses = [
        Hypothesis(
            hypothesis_id=f"hyp-idor-{i}",
            family=Family.IDOR,
            statement=f"hypothesis {i}",
            success_indicator="data leak",
            failure_indicator="403 returned",
            probe_strategy="GET without auth",
            estimated_requests=50,
            estimated_llm_calls=2,
            estimated_duration_seconds=30,
            order=i,
        )
        for i in range(1, 4)
    ]
    return Phase(
        phase_id="phase-1-idor",
        order=1,
        goal="Test IDOR on user-scoped endpoints",
        thesis_alignment="Tests IDOR — thesis predicted high probability",
        hypotheses=hypotheses,
        budget=PhaseBudget(
            max_requests=500, max_time_minutes=30, max_llm_calls=20),
        exit_criteria=["Found at least 1 IDOR finding"],
        success_indicators=["found IDOR"],
        failure_indicators=["all endpoints require proper auth"],
        pivot_triggers=[
            PivotTrigger(
                trigger_id="pivot-idor-failures",
                condition="2 consecutive hypothesis failures",
                condition_type="consecutive_failures",
                threshold=2,
                action=PivotAction.NEXT_PHASE,
                reason="Family IDOR refuted — move to next phase",
            ),
        ],
    )


@pytest.fixture
def campaign_budget():
    return CampaignBudget(
        max_requests=1000, max_time_minutes=120, max_llm_calls=50)


@pytest.fixture
def engine():
    return PivotEngine()


# Pivot-engine PhaseResult / budget fixtures live in test_pivot_engine.py
# (they import the types directly).

# ---------------------------------------------------------------------------
# Budget-guard fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def guard():
    return BudgetGuard()
