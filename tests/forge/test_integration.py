"""U-FORGE-18 — The Integration Layer (red tests).

The bridge that lets ORACLE, PRISM, APEX, DOJO and CAMPAIGN use
THE FORGE's corpus through one surface: get_payloads_for_phase,
enrich_oracle_with_payloads, feed_outcome_to_prism,
get_tool_chain_for_payloads, get_payloads_for_scenario,
explain_payload_choice. Uses the real types; advisory-only —
nothing here executes anything.
"""
from __future__ import annotations

import pytest

from webpent.forge.integration import ForgeIntegration
from webpent.forge.schemas import Family, NormalizedPayload
from webpent.forge.indexer import PayloadIndexer
from webpent.forge.query_engine import PayloadQueryEngine as QueryEngine
from webpent.forge.contextualizer import Contextualizer
from webpent.apex.tool_chain_builder import ChainStep, ToolChain

from webpent.campaign.schemas import (
    Family as CampaignFamily,
    Hypothesis,
    Phase,
    PhaseBudget,
)
from webpent.models.targets import Target
from webpent.dojo.scenario_library import Scenario


def _payload(pid: str, family: Family,
             raw: str | None = None) -> NormalizedPayload:
    return NormalizedPayload(
        payload_id=pid, family=family, subfamily="",
        raw=raw or f"{pid}-{{INJECT}}-raw",
        target_context=("json",), quality_score=0.7)


@pytest.fixture
def rig():
    indexer = PayloadIndexer()
    for pid in ("sqli-1", "sqli-2", "xss-1", "ssrf-1"):
        indexer.store_payload(
            _payload(pid, Family[pid.split("-")[0].upper()]))
    integration = ForgeIntegration(
        indexer=indexer,
        query_engine=QueryEngine(indexer),
        contextualizer=Contextualizer())
    return indexer, integration


def _phase(family: CampaignFamily = CampaignFamily.SQLI,
           limit: int = 5) -> Phase:
    return Phase(
        phase_id="ph-1", order=1, goal="prove sqli",
        thesis_alignment="t",
        hypotheses=[Hypothesis(
            hypothesis_id="h-1", family=family, statement="s",
            success_indicator="ok", failure_indicator="blocked",
            probe_strategy="single-shot",
            estimated_requests=10, estimated_llm_calls=1,
            estimated_duration_seconds=60, order=0)],
        budget=PhaseBudget(
            max_requests=100, max_time_minutes=10, max_llm_calls=5),
        exit_criteria=(),
        success_indicators=(),
        failure_indicators=())


def _target() -> Target:
    return Target(url="http://lab.example.test/shop",
                  tags=("tech:php", "waf:cloudflare"))


def test_get_payloads_for_phase_uses_family_and_adapts(rig):
    indexer, integration = rig
    bundles = integration.get_payloads_for_phase(_phase(), _target())
    assert bundles
    assert all(b.payload.family == Family.SQLI for b in bundles)
    assert all(b.adapted_raw and b.context == "json" for b in bundles)


def test_get_payloads_for_phase_respects_limit(rig):
    indexer, integration = rig
    bundles = integration.get_payloads_for_phase(_phase(), _target(),
                                                 limit=1)
    assert len(bundles) == 1


def test_get_tool_chain_for_payloads(rig):
    indexer, integration = rig
    bundles = integration.get_payloads_for_phase(_phase(), _target())
    chain = integration.get_tool_chain_for_payloads(
        bundles, target=_target())
    assert isinstance(chain, ToolChain)
    assert len(chain.steps) == len(bundles)
    assert all(isinstance(step, ChainStep) for step in chain.steps)
    assert chain.advisory_note


def test_enrich_oracle_with_payloads(rig):
    indexer, integration = rig

    class _Report:
        report_id = "rep-1"
        sections = {"findings": [{"family": "SQLI"}],
                    "evidence": ()}

    enriched = integration.enrich_oracle_with_payloads(_Report())
    suggestions = enriched.sections["payload_suggestions"]
    assert suggestions
    assert suggestions["SQLI"]
    assert all(p.family == Family.SQLI
               for p in suggestions["SQLI"])


def test_feed_outcome_to_prism(rig):
    indexer, integration = rig
    sent = []

    def prism_sink(evidence):
        sent.append(evidence)

    outcome = {"payload_id": "sqli-1", "family": "SQLI",
               "success": True, "target_id": "t1"}
    integration.feed_outcome_to_prism(outcome, prism_sink)
    assert sent == [outcome]


def test_get_payloads_for_scenario(rig):
    indexer, integration = rig
    scenario = Scenario(
        scenario_id="sc-1", family="SQLI", title="auth bypass",
        description="bypass the login", difficulty=3,
        template_id="tpl-1", seed=7,
        ground_truth={"vuln_class": "SQLI", "location": "login"},
        hints=(), lesson_tags=(), skill_families=(),
        request_budget=50)
    payloads = integration.get_payloads_for_scenario(scenario)
    assert payloads
    assert all(p.family == Family.SQLI for p in payloads)


def test_explain_payload_choice(rig):
    indexer, integration = rig
    text = integration.explain_payload_choice("sqli-1")
    assert "sqli-1" in text
    assert "quality" in text.lower()
    assert "license" in text.lower()


def test_advisory_only_no_execution(rig):
    indexer, integration = rig
    bundles = integration.get_payloads_for_phase(_phase(), _target())
    chain = integration.get_tool_chain_for_payloads(
        bundles, target=_target())
    assert "advisory" in chain.advisory_note.lower()
    # the integration layer holds no transport: nothing to execute
    assert not hasattr(integration, "send")
    assert not hasattr(integration, "execute")


# -- FULL SWEEP 2026-10-20 fixes (F-01, F-03) ------------------------------
# F-01: the campaign families with no forge counterpart are pinned, so
# the divergence can never silently drift again.

UNMAPPABLE = {"BOLA", "IDOR", "AUTH_BYPASS", "INFO_DISCLOSURE"}


def test_unmappable_campaign_families_are_pinned_exactly():
    from webpent.forge.integration import UNMAPPABLE_CAMPAIGN_FAMILIES
    forge_names = {f.name for f in Family}
    campaign_names = {f.name for f in CampaignFamily}
    unmapped = campaign_names - forge_names
    assert set(UNMAPPABLE_CAMPAIGN_FAMILIES) == unmapped
    assert unmapped == UNMAPPABLE


def test_bola_only_phase_returns_empty_without_error(rig):
    indexer, integration = rig
    bundles = integration.get_payloads_for_phase(
        _phase(family=CampaignFamily.BOLA), _target())
    assert bundles == []


def test_family_docstring_carries_the_correction():
    import inspect
    from webpent.forge import schemas
    source = inspect.getsource(schemas)
    assert "Not a superset" in source


# F-03: the duck-typed family contract is handled with a direct type
# check, and the module carries no dynamic attribute resolution.

def test_string_family_hypothesis_still_yields_bundles(rig):
    indexer, integration = rig
    bundles = integration.get_payloads_for_phase(
        _phase(family="sqli"), _target())
    assert bundles
    assert all(b.payload.family == Family.SQLI for b in bundles)


def test_integration_has_no_dynamic_resolution():
    import inspect
    from webpent.forge import integration
    source = inspect.getsource(integration)
    assert "hasattr" not in source
    assert "getattr" not in source
