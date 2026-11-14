"""Wave 3 — CAMPAIGN wiring into ModernOrchestrator (red tests).

The bridge that lets a completed AUTONOMOUS VALIDATION CAMPAIGN
result feed the CAMPAIGN strategist: the bridge adapts the result
into an oracle view, builds the thesis, plans the phases, and
registers the brief as PENDING for the operator — the bridge itself
holds no approval code path, so the machine can never approve its
own campaign. Where the operator HAS approved a brief for the
target, the bridge surfaces the approved plan as advisory guidance
(fail-open; it gates nothing).

Same pattern as the verdict bridge: typed blockers (never an
exception into a completed campaign), zero getattr (direct-I/O
inventory discipline), zero network, advisory only.
"""
from __future__ import annotations

import dataclasses
import inspect
from types import SimpleNamespace

from webpent.production import campaign_bridge

# -- fakes -------------------------------------------------------------


def _rich_avi_result() -> dict:
    """A result-shaped dict with enough signals for a thesis."""
    return {
        "target_url": "https://target.example",
        "tech_stack": {"backend": "python", "framework": "django"},
        "subdomains": ["api.target.example", "admin.target.example"],
        "historical_endpoints": ["/api/v1/orders", "/admin/users"],
        "leaked_signals": [{"kind": "header", "value": "Server: gunicorn"}],
        "crown_jewel_hints": [{"kind": "auth", "value": "session cookie"}],
    }


def _pattern(family: str) -> SimpleNamespace:
    from webpent.campaign.schemas import Family
    return SimpleNamespace(
        pattern_id=f"pat-{family}", archetype_name=f"{family}-archetype",
        family=family, confidence=0.8,
        typical_families={Family.SQLI: 0.8} if family == "sqli" else {})


def _store(tmp_path) -> campaign_bridge.CampaignStore:
    return campaign_bridge._resolve_store(str(tmp_path))


# -- version + shape ---------------------------------------------------


def test_version_marker():
    assert campaign_bridge.CAMPAIGN_BRIDGE_VERSION == "campaign_bridge_v1"


def test_oracle_view_maps_avi_fields():
    view = campaign_bridge.OracleView(_rich_avi_result())
    assert view.tech_stack
    assert view.subdomains
    assert view.historical_endpoints


def test_oracle_view_defaults_are_empty():
    view = campaign_bridge.OracleView({})
    assert view.tech_stack == {}
    assert view.subdomains == ()
    assert view.historical_endpoints == ()
    assert view.leaked_signals == ()


# -- the advisory brief ------------------------------------------------


def test_brief_registered_pending(tmp_path):
    store = _store(tmp_path)
    block = campaign_bridge.campaign_advisory_brief(
        _rich_avi_result(), "https://target.example", store=store)
    assert block["registered"] is True
    assert block["decision"] == "PENDING"
    assert block["bridge"] == campaign_bridge.CAMPAIGN_BRIDGE_VERSION
    assert block["campaign_id"] in {b.campaign_id
                                    for b in store.list_briefs()}


def test_brief_persists_in_store_round_trip(tmp_path):
    store = _store(tmp_path)
    campaign_bridge.campaign_advisory_brief(
        _rich_avi_result(), "https://roundtrip.example", store=store)
    briefs = store.list_briefs()
    assert any(b.thesis.target_id == "https://roundtrip.example"
               for b in briefs)


def test_brief_has_planned_phases(tmp_path):
    store = _store(tmp_path)
    block = campaign_bridge.campaign_advisory_brief(
        _rich_avi_result(), "https://phases.example", store=store)
    assert block["phases"] >= 2
    assert isinstance(block["families"], list)


def test_thin_evidence_is_typed_blocker_not_exception(tmp_path):
    store = _store(tmp_path)
    block = campaign_bridge.campaign_advisory_brief(
        {}, "https://empty.example", store=store)
    assert block["registered"] is False
    assert block["blocker"]
    assert "campaign_id" not in block


def test_pattern_evidence_enriches_brief(tmp_path):
    store = _store(tmp_path)
    block = campaign_bridge.campaign_advisory_brief(
        _rich_avi_result(), "https://patterns.example", store=store,
        patterns=[_pattern("sqli")])
    assert block["registered"] is True
    assert "sqli" in block["families"]


# -- operator sovereignty ----------------------------------------------


def test_bridge_never_approves(tmp_path):
    store = _store(tmp_path)
    block = campaign_bridge.campaign_advisory_brief(
        _rich_avi_result(), "https://sovereign.example", store=store)
    assert block["decision"] == "PENDING"
    # no approval code path anywhere in the module: no function
    # defines an approval, nothing calls one
    source = inspect.getsource(campaign_bridge)
    import re
    assert not re.search(r"def approve\b", source)
    assert ".approve(" not in source


def test_bridge_has_no_transport():
    assert not hasattr(campaign_bridge, "send")
    assert not hasattr(campaign_bridge, "execute")
    assert not hasattr(campaign_bridge, "request")


# -- the approved-plan surface -----------------------------------------


def test_no_approved_brief_records_reason(tmp_path):
    store = _store(tmp_path)
    out = campaign_bridge.approved_plan_for("https://nobody.example",
                                            store=store)
    assert out["attached"] is False
    assert out["reason"] == "no_approved_brief"


def test_approved_plan_attaches_after_operator_approval(tmp_path):
    from webpent.campaign.schemas import Decision

    url = "https://approved.example"
    store = _store(tmp_path)
    campaign_bridge.campaign_advisory_brief(
        _rich_avi_result(), url, store=store)
    brief = next(b for b in store.list_briefs()
                 if b.thesis.target_id == url)
    # the OPERATOR approves (the machine never does): the ruling is
    # recorded on the brief and persisted through the store
    store.save_brief(dataclasses.replace(brief,
                                         decision=Decision.APPROVED))
    out = campaign_bridge.approved_plan_for(url, store=store)
    assert out["attached"] is True
    assert out["plan"]["phases"]
    assert out["plan"]["phases"][0]["goal"]
