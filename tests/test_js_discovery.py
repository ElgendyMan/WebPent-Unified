# tests/test_js_discovery.py
"""Proposal 4 (2026-10-25) test suite: JS/SPA surface discovery.

Covers the pure extractors (webpent.tools.js_extractors) and the
flag-gated js_discovery node (webpent.agents.js_discovery.agent):
default-off byte-identity, same-origin fetch bounds, deterministic
extraction, GraphQL merge into crawled_data, and fail-soft session
degradation.
"""
from __future__ import annotations

from types import SimpleNamespace
from typing import Any

import pytest

from webpent.config.settings import Settings, activate_settings
from webpent.tools.js_extractors import (
    MAX_SURFACES_PER_KIND,
    discover_surfaces,
    extract_api_endpoints,
    extract_graphql_operations,
    extract_spa_routes,
    extract_secret_hints,
)


SYNTHETIC_BUNDLE = """
const routes = [{ path: "/dashboard" }, { path: "/admin/settings" }];
const hashRoute = "#/orders/42";
const q = `query GetOrders($id: ID!) { orders(id: $id) }`;
const m = "mutation UpdateUser($name: String!) { updateUser { id } }";
fetch("/api/v2/orders").then(r => r.json());
axios.get("/api/internal/switch-tenant");
client.request({ url: "/api/health" });
const token = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.SflKxwRJSMeKKF2Qt";
const cfg = { apiKey: "sk-live-abcdef123456789012345" };
"""


class TestExtractors:
    def test_spa_routes_extracted_and_deduped(self) -> None:
        routes = extract_spa_routes(SYNTHETIC_BUNDLE)
        assert "/dashboard" in routes
        assert "/admin/settings" in routes
        assert "#/orders/42" in routes

    def test_graphql_operations_shape_matches_crawler(self) -> None:
        ops = extract_graphql_operations(SYNTHETIC_BUNDLE)
        names = {op["name"] for op in ops}
        assert {"GetOrders", "UpdateUser"} <= names
        get_orders = next(op for op in ops if op["name"] == "GetOrders")
        assert get_orders["args"] == [{"name": "id", "type": "ID"}]
        assert all(op["source"] == "js_bundle" for op in ops)

    def test_api_endpoints_include_fetch_and_url_fields(self) -> None:
        endpoints = extract_api_endpoints(SYNTHETIC_BUNDLE)
        assert "/api/v2/orders" in endpoints
        assert "/api/internal/switch-tenant" in endpoints
        assert "/api/health" in endpoints

    def test_secret_hints_are_redacted_never_verbatim(self) -> None:
        hints = extract_secret_hints(SYNTHETIC_BUNDLE)
        kinds = {h["kind"] for h in hints}
        assert "jwt_on_client" in kinds
        assert "hardcoded_key_pattern" in kinds
        for hint in hints:
            preview = hint["preview"]
            assert "..." in preview and "len=" in preview
            # Never the full secret: the JWT and the API key must not
            # appear verbatim in any hint.
            assert "SflKxwRJSMeKKF2Qt" not in preview
            assert "sk-live-abcdef123456789012345" not in preview

    def test_extractors_degenerate_inputs(self) -> None:
        for text in ("", "   ", "const x = 1;"):
            assert extract_spa_routes(text) == []
            assert extract_graphql_operations(text) == []
            assert extract_api_endpoints(text) == []
            assert extract_secret_hints(text) == []

    def test_bounded_output_per_kind(self) -> None:
        many = "\n".join(f'{{ path: "/r{i}" }}' for i in range(200))
        routes = extract_spa_routes(many)
        assert len(routes) == MAX_SURFACES_PER_KIND

    def test_discover_surfaces_deterministic_order(self) -> None:
        a = discover_surfaces(SYNTHETIC_BUNDLE, source_url="https://x/app.js")
        b = discover_surfaces(SYNTHETIC_BUNDLE, source_url="https://x/app.js")
        assert a == b
        kinds = [s.kind for s in a]
        # Order: routes, GraphQL, endpoints, secrets.
        first_secret = kinds.index("secret_hint")
        assert all(k == "secret_hint" for k in kinds[first_secret:])
        assert all(s.source_url == "https://x/app.js" for s in a)


def _state(**crawled: Any) -> dict[str, Any]:
    target = SimpleNamespace(url="https://lab.local")
    state: dict[str, Any] = {"target": target, "crawled_data": dict(crawled)}
    return state


class TestJsDiscoveryNode:
    def test_flag_off_is_noop(self) -> None:
        from webpent.agents.js_discovery.agent import js_discovery_node

        settings = Settings()
        assert settings.enable_js_discovery is False  # default off
        state = _state(javascript_urls=["https://lab.local/app.js"])
        assert js_discovery_node(state) == {}

    def test_flag_on_without_js_urls_is_noop(self) -> None:
        from webpent.agents.js_discovery.agent import js_discovery_node

        with activate_settings(Settings(enable_js_discovery=True)):
            assert js_discovery_node(_state()) == {}
            # Non-JS URLs are also ignored.
            assert js_discovery_node(_state(urls=["https://lab.local/x.css"])) == {}

    def test_flag_on_merges_surfaces(self, monkeypatch) -> None:
        from webpent.agents.js_discovery.agent import js_discovery_node

        def fake_fetcher(url: str) -> str:
            return SYNTHETIC_BUNDLE

        with activate_settings(Settings(enable_js_discovery=True)):
            state = _state(javascript_urls=["https://lab.local/app.js"])
            update = js_discovery_node(state, fetcher=fake_fetcher)

        crawled = update["crawled_data"]
        assert "/api/v2/orders" in crawled["js_discovered_endpoints"]
        ops = crawled.get("graphql_operations", [])
        assert any(op["name"] == "GetOrders" for op in ops)
        summary = update["target_knowledge"]["js_surface"]
        assert summary["bundles_analyzed"] == 1
        assert "/dashboard" in summary["spa_routes"]
        assert any(h["kind"] == "jwt_on_client" for h in summary["secret_hints"])
        assert update["current_phase"] == "js_discovery"

    def test_cross_origin_bundles_are_ignored(self) -> None:
        from webpent.agents.js_discovery.agent import js_discovery_node

        fetched: list[str] = []

        def fake_fetcher(url: str) -> str:
            fetched.append(url)
            return SYNTHETIC_BUNDLE

        with activate_settings(Settings(enable_js_discovery=True)):
            state = _state(
                javascript_urls=[
                    "https://lab.local/app.js",
                    "https://evil.example.com/hostile.js",
                ]
            )
            update = js_discovery_node(state, fetcher=fake_fetcher)

        assert fetched == ["https://lab.local/app.js"]
        assert "hostile.js" not in update["target_knowledge"]["js_surface"].get(
            "endpoints", []
        )

    def test_fetch_failure_degrades_fail_soft(self) -> None:
        from webpent.agents.js_discovery.agent import js_discovery_node

        def broken_fetcher(url: str) -> str:
            raise RuntimeError("network down")

        with activate_settings(Settings(enable_js_discovery=True)):
            state = _state(javascript_urls=["https://lab.local/app.js"])
            update = js_discovery_node(state, fetcher=broken_fetcher)
        # Fail-soft: no exception, no surfaces merged.
        assert update == {}

    def test_relative_urls_resolved_against_target(self) -> None:
        from webpent.agents.js_discovery.agent import js_discovery_node

        fetched: list[str] = []

        def fake_fetcher(url: str) -> str:
            fetched.append(url)
            return 'fetch("/api/rel")'

        with activate_settings(Settings(enable_js_discovery=True)):
            state = _state(javascript_urls=["/static/app.js"])
            js_discovery_node(state, fetcher=fake_fetcher)
        assert fetched == ["https://lab.local/static/app.js"]

    def test_graphql_merge_does_not_duplicate_existing_ops(self) -> None:
        from webpent.agents.js_discovery.agent import js_discovery_node

        def fake_fetcher(url: str) -> str:
            return SYNTHETIC_BUNDLE

        with activate_settings(Settings(enable_js_discovery=True)):
            state = _state(
                javascript_urls=["https://lab.local/app.js"],
                graphql_operations=[{"name": "GetOrders", "args": [], "source": "crawl"}],
            )
            update = js_discovery_node(state, fetcher=fake_fetcher)
        names = [op["name"] for op in update["crawled_data"].get("graphql_operations", [])]
        assert names == ["UpdateUser"]

    def test_request_budget_bounded(self, monkeypatch) -> None:
        from webpent.agents.js_discovery import agent as mod

        fetched: list[str] = []

        def fake_fetcher(url: str) -> str:
            fetched.append(url)
            return 'fetch("/api/x")'

        with activate_settings(Settings(enable_js_discovery=True)):
            state = _state(
                javascript_urls=[f"https://lab.local/b{i}.js" for i in range(30)]
            )
            update = mod.js_discovery_node(state, fetcher=fake_fetcher)
        # Hard bound on bundles fetched (node budget, not the 30 offered).
        assert len(fetched) <= mod._MAX_FILES
        assert update["target_knowledge"]["js_surface"]["bundles_analyzed"] <= mod._MAX_FILES
