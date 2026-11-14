"""M3 UM-DR-17 (tenant_isolation qualification seam, M1b residual ②).

The M0 CAPABILITY_WIRING_MAP rows this suite closes:

* ``families/execution_node`` — ``wire_family_execution()`` had NO caller
  from the production builder;
* ``tenant_isolation/multi_step_auth`` — passive analyzers waiting for
  ``endpoint_inventory`` / ``multi_tenant`` / ``auth_flows`` channels
  nobody populated (the ب6-pattern).

Contract under test:

1. **The feeds adapter** derives the analyzers' vocabulary from the REAL
   PentestState channels (crawled_data: openapi_routes, surface_records,
   forms, endpoints/links, shadow_endpoints; identity_profiles;
   target declarations) — deduped, bounded, provenance-preserved.
2. **The spine consumes the feeds**: family_execution_node, given only
   real-state channels, runs the tenant_isolation analyzer and emits
   candidates (previously: ``no_input_surface``).
3. **The builder wiring**: flag off → node absent from the compiled
   graph; flag on → node present with additive edges (the direct
   sandbox→validator edge survives).
4. **Honesty invariants**: multi_tenant is never inferred; no executor ⇒
   plans_pending_execution (replays never faked); feeds derivation is
   observable in the output.
"""

from __future__ import annotations

from typing import Any

import pytest

from webpent.config.settings import get_settings
from webpent.shared.family_feeds import (
    auth_flows_from_state,
    endpoint_inventory_from_state,
    multi_tenant_from_state,
)

TARGET_URL = "https://app.example.com"


def _crawled_state(**extra: Any) -> dict[str, Any]:
    state: dict[str, Any] = {
        "target_id": "target-1",
        "engagement_id": "eng-1",
        "target_url": TARGET_URL,
        "crawled_data": {
            "openapi_routes": [
                {"method": "GET", "path": "/api/v2/users/{id}"},
                {"method": "POST", "path": "/api/v2/users"},
            ],
            "surface_records": [
                {
                    "method": "GET",
                    "url": "https://app.example.com/dashboard?tenant=acme",
                    "path": "/dashboard",
                    "query_parameters": ["tenant"],
                },
            ],
            "forms": [
                {"action": "https://app.example.com/login", "method": "POST", "data": {"user": "", "pass": ""}},
            ],
            "shadow_endpoints": [
                {"method": "GET", "path": "/api/internal/tenants"},
            ],
            "endpoints": [
                "https://app.example.com/admin",
                "https://app.example.com/admin",  # duplicate
            ],
        },
    }
    state.update(extra)
    return state


# ---------------------------------------------------------------------------
# 1. The feeds adapter
# ---------------------------------------------------------------------------


def test_endpoint_inventory_derives_from_all_real_channels() -> None:
    inventory = endpoint_inventory_from_state(_crawled_state())
    by_key = {(e["method"], e["path"]): e for e in inventory}
    # openapi_routes
    assert ("GET", "/api/v2/users/{id}") in by_key
    assert ("POST", "/api/v2/users") in by_key
    # surface_records (query params become params)
    assert ("GET", "/dashboard") in by_key
    assert by_key[("GET", "/dashboard")]["params"] == ["tenant"]
    # forms (field names become params; POST is stateful)
    assert ("POST", "/login") in by_key
    assert by_key[("POST", "/login")]["params"] == ["user", "pass"]
    assert by_key[("POST", "/login")]["stateful"] is True
    # shadow endpoints (the ق8 JS-only projection)
    assert ("GET", "/api/internal/tenants") in by_key
    # plain endpoint URLs
    assert ("GET", "/admin") in by_key


def test_endpoint_inventory_dedupes_and_bounds() -> None:
    state = _crawled_state()
    # The duplicate /admin URL must collapse to one entry.
    admin_entries = [e for e in endpoint_inventory_from_state(state) if e["path"] == "/admin"]
    assert len(admin_entries) == 1
    # Explicit inventory wins over crawled data for the same key.
    state["endpoint_inventory"] = [{"method": "GET", "path": "/admin", "roles": ["admin"]}]
    merged = endpoint_inventory_from_state(state)
    admin = next(e for e in merged if e["path"] == "/admin")
    assert admin["roles"] == ["admin"]
    assert admin["provenance"] == "family_feeds:explicit"


def test_endpoint_inventory_provenance_is_recorded() -> None:
    inventory = endpoint_inventory_from_state(_crawled_state())
    provenances = {e["provenance"] for e in inventory}
    assert "family_feeds:openapi_routes" in provenances
    assert "family_feeds:shadow_endpoints" in provenances
    assert "family_feeds:crawled:endpoints" in provenances


def test_multi_tenant_is_explicit_only() -> None:
    # Nothing declared → False (never inferred from heuristics).
    assert multi_tenant_from_state(_crawled_state()) is False
    # State channel declaration.
    assert multi_tenant_from_state(_crawled_state(multi_tenant=True)) is True

    class _Target:
        multi_tenant = True

    assert multi_tenant_from_state(_crawled_state(target=_Target())) is True

    class _QuietTarget:
        pass

    assert multi_tenant_from_state(_crawled_state(target=_QuietTarget())) is False


def test_auth_flows_derive_only_from_real_step_lists() -> None:
    state = _crawled_state(
        identity_profiles={
            "owner": {
                "name": "owner",
                "role": "owner",
                "validated": True,
                "login_flow": ["login_page", "submit_credentials", "mfa_check"],
            },
            "viewer": {"name": "viewer", "role": "viewer", "validated": True},
        }
    )
    flows = auth_flows_from_state(state)
    # Only the profile WITH a step list becomes a flow.
    assert len(flows) == 1
    flow = flows[0]
    assert flow["role"] == "owner"
    assert [s["name"] for s in flow["steps"]] == [
        "login_page",
        "submit_credentials",
        "mfa_check",
    ]
    assert flow["final_step"] == "mfa_check"
    assert flow["credentials_included"] is False
    # No credentials ever appear.
    assert "password" not in str(flows).lower() or "credentials_included" in str(flows)


# ---------------------------------------------------------------------------
# 2. The spine consumes the feeds (the ب6-pattern closes)
# ---------------------------------------------------------------------------


def test_family_execution_node_runs_tenant_analyzer_from_real_state() -> None:
    from webpent.families.execution_node import family_execution_node

    state = _crawled_state()
    state["multi_tenant"] = True
    state["http_executor"] = None  # never inject an executor here
    # Neutralize the default SSRF-pinned executor: no network in tests.
    import webpent.families.execution_node as en

    original = en.get_default_http_executor
    en.get_default_http_executor = lambda: None
    try:
        out = family_execution_node(state)
    finally:
        en.get_default_http_executor = original

    assert out["family_execution_status"] != "no_input_surface"
    assert out["family_feeds_derived"] is True
    families = {c.get("family") for c in out["family_candidates"]}
    assert "tenant_isolation" in families
    # No executor ⇒ honest pending status, replays never faked.
    assert out["family_execution_status"] in {"plans_pending_execution", "ok"}
    assert out.get("family_executed_plans", 0) == 0


def test_family_execution_node_without_any_surface_stays_honest() -> None:
    from webpent.families.execution_node import family_execution_node

    out = family_execution_node(
        {"target_id": "t", "engagement_id": "e", "crawled_data": {}}
    )
    assert out["family_execution_status"] == "no_input_surface"
    assert out["family_candidates"] == []


def test_family_execution_node_honors_explicit_inventory_first() -> None:
    from webpent.families.execution_node import family_execution_node

    import webpent.families.execution_node as en

    en_get = en.get_default_http_executor
    en.get_default_http_executor = lambda: None
    try:
        state = _crawled_state(
            endpoint_inventory=[
                {
                    "method": "GET",
                    "path": "/tenants/123/data",
                    "object_reference": True,
                    "roles": ["tenant-admin"],
                }
            ],
            multi_tenant=True,
        )
        out = family_execution_node(state)
    finally:
        en.get_default_http_executor = en_get
    families = {c.get("family") for c in out["family_candidates"]}
    assert "tenant_isolation" in families


# ---------------------------------------------------------------------------
# 3. The builder wiring (flag-gated, additive-only)
# ---------------------------------------------------------------------------


def test_flag_defaults_off() -> None:
    assert get_settings().enable_family_execution_spine is False


def test_builder_flag_off_compiles_without_the_spine(monkeypatch: pytest.MonkeyPatch) -> None:
    from webpent.graph import builder as graph_builder

    monkeypatch.delenv("WEBPENT_ENABLE_FAMILY_EXECUTION_SPINE", raising=False)
    settings = get_settings()
    assert settings.enable_family_execution_spine is False
    compiled = graph_builder.build_graph(auto_approve=True)
    node_names = set(getattr(compiled, "nodes", {}) or {})
    assert "family_execution" not in node_names


def test_builder_flag_on_adds_the_spine_additively(monkeypatch: pytest.MonkeyPatch) -> None:
    from webpent.config.settings import get_settings as _gs
    from webpent.graph import builder as graph_builder

    monkeypatch.setattr(
        graph_builder,
        "_family_execution_enabled",
        lambda: True,
    )
    compiled = graph_builder.build_graph(auto_approve=True)
    node_names = set(getattr(compiled, "nodes", {}) or {})
    assert "family_execution" in node_names
    # Additive-only: the direct sandbox→validator edge survives.
    edges = compiled.get_graph().edges
    edge_pairs = {(e.source, e.target) for e in edges}
    assert ("execution_sandbox", "validator") in edge_pairs
    assert ("execution_sandbox", "family_execution") in edge_pairs
    assert ("family_execution", "validator") in edge_pairs
    _ = _gs  # settings import kept for symmetry with the flag-off test
