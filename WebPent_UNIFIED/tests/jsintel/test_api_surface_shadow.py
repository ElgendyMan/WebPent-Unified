"""FEATURE_PROPOSALS ق8 — unified JS pass (API surface shadow).

Pins:
  * build_api_surface_shadow() is the ONE pass the proposal asks for:
    every bundle → analyze_javascript_source (routes/secrets/hints/
    map refs) + source-map agent outputs → merged surface → direct
    hypotheses, offline and bounded,
  * shadow diff: JS-only paths (absent from documented endpoints)
    become shadow_endpoints and undocumented_api_endpoint hypotheses;
    documented paths produce NO endpoint hypothesis,
  * redaction stance: only same-origin redacted paths can enter the
    surface; secret candidates carry "[REDACTED]" values only,
  * advisory posture pinned on every hypothesis; stable ids; fail-soft
    per bundle (a bad bundle is a coverage gap, not an exception),
  * empty input ⇒ falsy shadow with a "no_bundles" gap.
"""

from __future__ import annotations

import json

from webpent.jsintel import (
    ApiSurfaceShadow,
    ShadowHypothesis,
    build_api_surface_shadow,
    shadow_from_crawl_surfaces,
)

TARGET = "https://target.example"

BUNDLE_APP = {
    "asset_url": "https://target.example/static/app.js",
    "source": (
        "fetch('/api/v2/internal/users', {method:'GET'});\n"
        "fetch('/api/v1/orders', {method:'POST'});\n"
        "const adminConfig = true;\n"
        "isAdmin && grantPanel();\n"
    ),
    "content_type": "application/javascript",
    "status_code": 200,
}

KNOWN = ["/api/v1/orders"]


# ---------------------------------------------------------------------------
# The one pass
# ---------------------------------------------------------------------------


def test_one_pass_builds_surface_from_bundles() -> None:
    shadow = build_api_surface_shadow(
        bundles=[BUNDLE_APP], target_url=TARGET, known_endpoints=KNOWN
    )
    assert shadow  # non-empty
    paths = {e["path"] for e in shadow.endpoints}
    assert "/api/v2/internal/users" in paths
    assert "/api/v1/orders" in paths
    assert shadow.stats["bundles_seen"] == 1
    assert shadow.stats["endpoints"] == 2


def test_shadow_diff_flags_only_js_only_paths() -> None:
    shadow = build_api_surface_shadow(
        bundles=[BUNDLE_APP], target_url=TARGET, known_endpoints=KNOWN
    )
    assert "/api/v2/internal/users" in shadow.shadow_endpoints
    assert "/api/v1/orders" not in shadow.shadow_endpoints
    subjects = {h.subject for h in shadow.hypotheses}
    assert "/api/v2/internal/users" in subjects
    assert "/api/v1/orders" not in subjects
    kinds = {h.kind for h in shadow.hypotheses}
    assert "undocumented_api_endpoint" in kinds


def test_secret_candidates_stay_redacted_and_emit_hypotheses() -> None:
    bundle = {
        "asset_url": "https://target.example/static/app.js",
        "source": (
            "const api_key = 'FAKE-KEY-0123456789abcdef';\n"
            "fetch('/api/v1/ping');\n"
        ),
    }
    shadow = build_api_surface_shadow(bundles=[bundle], target_url=TARGET)
    assert shadow.stats["secret_candidates"] >= 1
    for secret in shadow.secret_candidates:
        assert secret["value"] == "[REDACTED]"
        assert secret["kind"]
    kinds = {h.kind for h in shadow.hypotheses}
    assert "hardcoded_secret_candidate" in kinds
    # rationale never contains a secret-shaped literal
    for hypothesis in shadow.hypotheses:
        assert "FAKE-KEY" not in hypothesis.rationale
        assert "FAKE-KEY" not in hypothesis.title


def test_out_of_origin_route_cannot_enter_the_surface() -> None:
    bundle = {
        "asset_url": "https://target.example/static/app.js",
        "source": "fetch('https://evil.example/api/v1/steal');\n",
    }
    shadow = build_api_surface_shadow(
        bundles=[bundle], target_url=TARGET, known_endpoints=[]
    )
    assert shadow.endpoints == []
    assert shadow.shadow_endpoints == []


def test_source_map_disclosure_and_agent_paths_merge() -> None:
    bundle = {
        "asset_url": "https://target.example/static/app.js",
        "source": "//# sourceMappingURL=app.js.map\nfetch('/api/v1/x');\n",
    }
    shadow = build_api_surface_shadow(
        bundles=[bundle],
        target_url=TARGET,
        known_endpoints=[],
        sourcemap_api_paths=["src/api/payments.ts"],
    )
    assert shadow.stats["map_disclosures"] == 1
    disclosure = shadow.source_map_disclosures[0]
    assert disclosure["map_path"].endswith("app.js.map")
    paths = {e["path"] for e in shadow.endpoints}
    assert "/src/api/payments.ts" in paths
    kinds = {h.kind for h in shadow.hypotheses}
    assert "source_map_disclosure" in kinds
    assert "undocumented_api_endpoint" in kinds


def test_bad_bundle_is_a_coverage_gap_not_an_exception() -> None:
    shadow = build_api_surface_shadow(
        bundles=[
            {"asset_url": "", "source": "x"},  # no url — skipped silently
            {"asset_url": "https://target.example/a.js", "source": None},  # no source
            {"asset_url": "https://target.example/b.js", "source": "fetch('/api/ok');"},
        ],
        target_url=TARGET,
    )
    assert shadow.stats["bundles_seen"] == 1
    assert shadow.stats["endpoints"] == 1


def test_empty_input_is_falsy_with_no_bundles_gap() -> None:
    shadow = build_api_surface_shadow(bundles=[], target_url=TARGET)
    assert not shadow
    assert "no_bundles" in shadow.coverage_gaps
    assert shadow.as_dict()["hypotheses"] == []


def test_default_constructible_and_json_round_trip() -> None:
    empty = ApiSurfaceShadow()
    assert not empty
    shadow = build_api_surface_shadow(
        bundles=[BUNDLE_APP], target_url=TARGET, known_endpoints=KNOWN
    )
    payload = shadow.as_dict()
    encoded = json.dumps(payload)  # must not raise
    assert isinstance(encoded, str)
    assert payload["advisory_only"] is True
    assert payload["does_not_confirm"] is True
    assert payload["redaction"] == "source_content_and_secret_values_omitted"


def test_hypotheses_have_stable_ids_and_deterministic_order() -> None:
    first = build_api_surface_shadow(
        bundles=[BUNDLE_APP], target_url=TARGET, known_endpoints=KNOWN
    )
    second = build_api_surface_shadow(
        bundles=[BUNDLE_APP], target_url=TARGET, known_endpoints=KNOWN
    )
    assert [h.hypothesis_id for h in first.hypotheses] == [
        h.hypothesis_id for h in second.hypotheses
    ]
    priorities = [h.priority for h in first.hypotheses]
    assert priorities == sorted(priorities, reverse=True)
    assert all(h.hypothesis_id.startswith("jsshadow-") for h in first.hypotheses)
    assert all(h.advisory_only and h.does_not_confirm for h in first.hypotheses)


def test_shadow_hypothesis_is_frozen() -> None:
    hypothesis = ShadowHypothesis(
        hypothesis_id="jsshadow-x",
        kind="undocumented_api_endpoint",
        subject="/api/x",
        title="t",
        rationale="r",
        source_asset="a",
        priority=0.6,
    )
    assert hypothesis.hypothesis_kind == "undocumented_api_endpoint"
    try:
        hypothesis.priority = 0.1  # type: ignore[misc]
    except AttributeError:
        pass
    else:
        raise AssertionError("ShadowHypothesis must be frozen")


def test_bundle_budget_bounds_the_pass() -> None:
    from webpent.jsintel import api_surface_shadow as mod

    bundles = [
        {
            "asset_url": f"https://target.example/b{i}.js",
            "source": f"fetch('/api/p{i}');\n",
        }
        for i in range(mod._MAX_BUNDLES + 5)
    ]
    shadow = build_api_surface_shadow(bundles=bundles, target_url=TARGET)
    assert shadow.stats["bundles_seen"] == mod._MAX_BUNDLES
    assert "bundle_budget_exceeded" in shadow.coverage_gaps


# ---------------------------------------------------------------------------
# js_discovery adapter
# ---------------------------------------------------------------------------


def test_shadow_from_crawl_surfaces_maps_discovery_output() -> None:
    class Surface:
        def __init__(self, raw: str) -> None:
            self.raw = raw

    shadow = shadow_from_crawl_surfaces(
        surfaces_by_url={
            "https://target.example/app.js": [Surface("/api/v2/hidden"), Surface("/api/v1/known")]
        },
        target_url=TARGET,
        known_endpoints=["/api/v1/known"],
    )
    assert "/api/v2/hidden" in shadow.shadow_endpoints
    assert "/api/v1/known" not in shadow.shadow_endpoints


def test_shadow_from_crawl_surfaces_empty_input_fails_soft() -> None:
    shadow = shadow_from_crawl_surfaces(surfaces_by_url={}, target_url=TARGET)
    assert not shadow
    assert "no_bundles" in shadow.coverage_gaps
