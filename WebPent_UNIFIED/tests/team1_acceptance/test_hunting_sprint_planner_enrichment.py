"""Hunting Intelligence Sprint — planner enrichment / priority / payload tests.

Synthetic only. Covers: priority scoring ordering (forms > admin > user APIs
> static > session MEDIUM); context-aware payload selection; context
enrichment + forbidden-field rejection; lesson-priority application.
"""
from __future__ import annotations

import pytest

from webpent.integration.hypothesis_priority_contract import EndpointProfile, PriorityLevel
from webpent.integration.planner_enrichment_bridge import (
    ContextEnricher,
    ContextAwarePayloadSelector,
    PriorityScorer,
    apply_lesson_priorities,
    secure_prompt_value,
)


def _ep(**kw):
    base = dict(route="/x", method="GET")
    base.update(kw)
    return EndpointProfile(**base)


# -- priority scoring (Part 2.3) ---------------------------------------------
def test_forms_with_params_high():
    level, score, _ = PriorityScorer().score(_ep(has_form=True, has_parameters=True))
    assert level is PriorityLevel.HIGH


def test_admin_and_debug_high():
    assert PriorityScorer().score(_ep(is_admin=True))[0] is PriorityLevel.HIGH
    assert PriorityScorer().score(_ep(is_debug=True))[0] is PriorityLevel.HIGH


def test_user_data_api_high():
    assert PriorityScorer().score(_ep(is_api=True, returns_user_data=True))[0] is PriorityLevel.HIGH


def test_session_auth_medium():
    level, score, _ = PriorityScorer().score(_ep(requires_session=True))
    assert level is PriorityLevel.MEDIUM


def test_static_asset_low_always():
    # Even with form+params, a static asset is LOW (zero-FP / no waste)
    level, score, rationale = PriorityScorer().score(_ep(is_static_asset=True, has_form=True, has_parameters=True))
    assert level is PriorityLevel.LOW
    assert rationale == "static_asset"


def test_priority_ordering_forms_admin_userapi_static():
    endpoints = [
        ("h_form", _ep(route="/f", has_form=True, has_parameters=True)),
        ("h_admin", _ep(route="/a", is_admin=True)),
        ("h_userapi", _ep(route="/u", is_api=True, returns_user_data=True)),
        ("m_session", _ep(route="/s", requires_session=True)),
        ("l_static", _ep(route="/st", is_static_asset=True)),
    ]
    prioritized = PriorityScorer().prioritize(endpoints)
    order = [h.hypothesis_id for h in prioritized]
    # HIGH group before MEDIUM before LOW
    assert order.index("l_static") > order.index("m_session")
    assert order.index("m_session") > order.index("h_userapi")
    # All HIGH items precede MEDIUM and LOW
    high_positions = [order.index(i) for i in ("h_form", "h_admin", "h_userapi")]
    assert max(high_positions) < order.index("m_session")


# -- payload selection (Part 2.4) --------------------------------------------
def test_json_endpoint_gets_json_payloads():
    sel = ContextAwarePayloadSelector()
    assert sel.subtype_for(_ep(content_type="application/json")) == "json"


def test_form_endpoint_gets_form_payloads():
    sel = ContextAwarePayloadSelector()
    assert sel.subtype_for(_ep(content_type="application/x-www-form-urlencoded", has_form=True)) == "form"


def test_waf_detected_gets_obfuscation_waf_bypass():
    sel = ContextAwarePayloadSelector()
    assert sel.subtype_for(_ep(content_type="application/json", waf_detected=True)) == "waf_bypass"


def test_jwt_target_gets_jwt_payloads():
    sel = ContextAwarePayloadSelector()
    assert sel.subtype_for(_ep(content_type="application/json", uses_jwt=True)) == "jwt"


def test_payload_selector_delegates_to_frozen_library():
    class _StubLib:
        def get_payloads(self, family, sub_type=None, context=None, limit=3):
            return [type("E", (), {"entry_id": f"p{i}"})() for i in range(limit)]

    out = ContextAwarePayloadSelector().select(_ep(content_type="application/json"), library=_StubLib(), limit=2)
    assert out["subtype"] == "json"
    assert out["payload_count"] == 2
    assert out["payload_ids"] == ["p0", "p1"]


# -- context enrichment (Part 2.2) -------------------------------------------
def test_enricher_assembles_all_context():
    enricher = ContextEnricher(target_url="https://t.local")
    ctx = enricher.assemble(
        tech_stack=("flask", "postgres"),
        auth_type="jwt",
        prior_findings=("IDOR on /api/users",),
        payload_suggestions=("jwt_none_alg",),
        lessons={"route_modifiers": {"/api/*": 0.3}},
        endpoints=(_ep(route="/api/users"),),
    )
    d = ctx.as_dict()
    assert d["tech_stack"] == ["flask", "postgres"]
    assert d["auth_type"] == "jwt"
    assert d["prior_finding_patterns"] == ["IDOR on /api/users"]
    assert d["payload_suggestions"] == ["jwt_none_alg"]
    assert d["lesson_priorities"] == {"route_modifiers": {"/api/*": 0.3}}


def test_enricher_rejects_forbidden_authority_fields():
    enricher = ContextEnricher(target_url="https://t.local")
    with pytest.raises(ValueError, match="forbidden_context_field"):
        enricher.assemble(lessons={"confirmed": True})


def test_secure_prompt_value_strips_path_injection():
    assert secure_prompt_value("../../etc/passwd") == ""
    assert secure_prompt_value("normal text") == "normal text"


# -- lesson priority application ---------------------------------------------
def test_apply_lesson_priorities_reorders():
    from webpent.memory.lesson_models import PriorityAdjustmentMap

    scorer = PriorityScorer()
    hyps = scorer.prioritize([
        ("h1", _ep(route="/api/users", is_api=True, returns_user_data=True)),
        ("h2", _ep(route="/static/x.js", is_static_asset=True)),
    ])
    adj = PriorityAdjustmentMap(
        target_type="rest_api",
        route_modifiers={"/api/*": 0.5},  # boost api routes
        family_modifiers={},
        minimum_family_quota={},
    )
    re = apply_lesson_priorities(hyps, adj)
    # api hypothesis boosted to top
    assert re[0].endpoint.route == "/api/users"
    assert "lesson_delta" in re[0].rationale
