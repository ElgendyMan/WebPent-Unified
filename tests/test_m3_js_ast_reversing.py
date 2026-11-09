"""M3 Fix ف3.2 (UM-DR-17): the esprima AST JS reverser.

Contract under test (CANONICAL_PHASE_REGISTRY M3 scope: "real JS reversing
replacing the 2-regex analyzer"):

1. **Structural recall the regex engine cannot reach** — routes assembled
   from multi-level string constants, template literals with dynamic
   segments, axios/jQuery config-object call forms.
2. **Structural precision the regex engine cannot reach** — call-site /
   assignment-verified sinks (comments and prose never produce sinks or
   routes; ``String.prototype.replace`` is not ``location.replace``).
3. **Graceful degradation** — esprima unavailable or unparseable source
   falls back to the frozen regex engine with an observable ``js_ast_*``
   coverage gap; the legacy engine stays the safety net, not the primary.
4. **Flag-off identity** — ``enable_js_ast_reversing`` defaults False and
   the frozen agent dispatches to the legacy engine byte-identically.
5. **Same typed output and safety contract** — JavaScriptIntelligence only,
   in-scope-only, redacted URLs, hashed secret values (raw values never
   leave the analyzer), same caps.
"""

from __future__ import annotations

import re
from typing import Any

import pytest

from webpent.config.settings import get_settings
from webpent.jsintel.js_reversing import reverse_javascript_source
from webpent.shared.javascript_intelligence import (
    analyze_javascript_source,
    merge_javascript_intelligence,
)

ASSET = "https://app.example.com/static/app.js"
TARGET = "https://app.example.com"


def _routes(result: Any) -> set[tuple[str, str]]:
    return {(r.method_hint, r.route) for r in result.routes}


def _sinks(result: Any) -> set[str]:
    return {s.sink for s in result.sinks}


# ---------------------------------------------------------------------------
# 1. Structural recall beyond the regex engine
# ---------------------------------------------------------------------------


def test_ast_finds_routes_assembled_from_multi_level_constants() -> None:
    source = (
        'const base = "/api/v2";\n'
        'const users = base + "/users";\n'
        "fetch(users);\n"
    )
    ast_result = reverse_javascript_source(
        asset_url=ASSET, source=source, target_url=TARGET
    )
    legacy = analyze_javascript_source(
        asset_url=ASSET, source=source, target_url=TARGET
    )
    # The AST engine resolves the two-level constant into the real route.
    assert ("GET", "https://app.example.com/api/v2/users") in _routes(ast_result)
    # The regex engine structurally cannot: the route exists only as
    # `base + "/users"` — proof this is NEW recall, not a reshuffle.
    assert ("GET", "https://app.example.com/api/v2/users") not in _routes(legacy)
    assert "https://app.example.com/api/v2/users" not in {
        r.route for r in legacy.routes
    }


def test_ast_renders_template_literal_dynamic_segments_as_placeholders() -> None:
    source = "axios.post(`/api/admin/${id}/permissions`, payload);\n"
    result = reverse_javascript_source(
        asset_url=ASSET, source=source, target_url=TARGET
    )
    assert ("POST", "https://app.example.com/api/admin/{expr}/permissions") in _routes(
        result
    )


def test_ast_resolves_config_object_call_forms() -> None:
    source = (
        'axios({url: "/api/config-form", method: "POST"});\n'
        '$.ajax({url: "/api/jquery-endpoint", method: "PUT"});\n'
    )
    result = reverse_javascript_source(
        asset_url=ASSET, source=source, target_url=TARGET
    )
    assert ("POST", "https://app.example.com/api/config-form") in _routes(result)
    assert ("PUT", "https://app.example.com/api/jquery-endpoint") in _routes(result)


def test_ast_resolves_xhr_open_with_constant_concentration() -> None:
    source = (
        'const api = "/api/items";\n'
        "const xhr = new XMLHttpRequest();\n"
        'xhr.open("GET", api + "?page=2");\n'
    )
    result = reverse_javascript_source(
        asset_url=ASSET, source=source, target_url=TARGET
    )
    assert ("GET", "https://app.example.com/api/items?page=2") in _routes(result)


def test_ast_counts_unresolvable_dynamic_arguments_as_a_coverage_gap() -> None:
    source = "fetch(buildUrl(userId));\n"
    result = reverse_javascript_source(
        asset_url=ASSET, source=source, target_url=TARGET
    )
    assert "js_ast_dynamic_route_arguments" in result.coverage_gaps
    assert not result.routes


# ---------------------------------------------------------------------------
# 2. Structural precision beyond the regex engine
# ---------------------------------------------------------------------------


def test_ast_ignores_code_inside_comments_where_regex_finds_false_positives() -> None:
    source = (
        "// fetch(\"/api/comment-only-route\")\n"
        "/* el.innerHTML = userInput; */\n"
        "fetch(\"/api/real-route\");\n"
    )
    ast_result = reverse_javascript_source(
        asset_url=ASSET, source=source, target_url=TARGET
    )
    legacy = analyze_javascript_source(
        asset_url=ASSET, source=source, target_url=TARGET
    )
    ast_route_paths = {r.route for r in ast_result.routes}
    assert "https://app.example.com/api/real-route" in {
        p for p in ast_route_paths
    }
    # The comment route is invisible to the AST (it is not code)...
    assert "https://app.example.com/api/comment-only-route" not in ast_route_paths
    # ...while the regex engine still reports it (documented false positive
    # the structural pass eliminates).
    assert "https://app.example.com/api/comment-only-route" in {
        r.route for r in legacy.routes
    }
    assert "innerHTML" in _sinks(legacy)
    assert "innerHTML" not in _sinks(ast_result)


def test_ast_sinks_are_assignment_or_call_verified() -> None:
    source = (
        "el.innerHTML = userInput;\n"
        "el.insertAdjacentHTML('beforeend', html);\n"
        "document.write(html);\n"
        "eval(code);\n"
        "new Function(body);\n"
        'setTimeout("run()");\n'
        "location.assign(next);\n"
        "worker.postMessage(data);\n"
    )
    result = reverse_javascript_source(
        asset_url=ASSET, source=source, target_url=TARGET
    )
    sinks = _sinks(result)
    assert sinks == {
        "innerHTML",
        "insertAdjacentHTML",
        "document.write",
        "eval",
        "Function",
        "setTimeout(string)",
        "location.assign",
        "postMessage",
    }
    lines = {s.sink: s.line for s in result.sinks}
    assert lines["innerHTML"] == 1
    assert lines["eval"] == 4


def test_ast_does_not_confuse_string_replace_with_location_replace() -> None:
    source = 'const out = "a-b".replace("-", "+");\n'
    result = reverse_javascript_source(
        asset_url=ASSET, source=source, target_url=TARGET
    )
    assert "location.replace" not in _sinks(result)


# ---------------------------------------------------------------------------
# 3. Secrets, auth hints and the safety contract
# ---------------------------------------------------------------------------


def test_ast_secret_candidates_are_hashed_and_never_carry_raw_values() -> None:
    source = (
        'const apiKey = "super-secret-key-12345";\n'
        'const cfg = { client_secret: "another-secret-value" };\n'
        'const note = "AKIAIOSFODNN7EXAMPLE";\n'
    )
    result = reverse_javascript_source(
        asset_url=ASSET, source=source, target_url=TARGET
    )
    kinds = [s.kind for s in result.secret_candidates]
    assert "assignment_secret" in kinds
    assert "aws_access_key" in kinds
    dumped = result.model_dump(mode="json")
    assert "super-secret-key-12345" not in str(dumped)
    assert "another-secret-value" not in str(dumped)
    for candidate in result.secret_candidates:
        assert re.fullmatch(r"[0-9a-f]{64}", candidate.value_sha256)


def test_ast_auth_hints_from_conditions_and_properties() -> None:
    source = (
        "if (isAdmin) { grant(); }\n"
        'const cfg = { csrfToken: "tok", role: "viewer" };\n'
        "const h = { Authorization: token };\n"
    )
    result = reverse_javascript_source(
        asset_url=ASSET, source=source, target_url=TARGET
    )
    hints = {(h.hint, h.identifier) for h in result.auth_hints}
    assert ("role_check", "isAdmin") in hints
    assert ("csrf_hint", "csrfToken") in hints
    assert ("role_check", "role") in hints
    assert ("auth_header", "Authorization") in hints


def test_scope_and_size_gates_mirror_the_frozen_engine() -> None:
    cross_origin = reverse_javascript_source(
        asset_url="https://evil.example.com/app.js",
        source='fetch("/api/x");',
        target_url=TARGET,
    )
    assert cross_origin.coverage_gaps == ["js_asset_out_of_scope"]
    assert not cross_origin.routes

    oversized = reverse_javascript_source(
        asset_url=ASSET,
        source='fetch("/api/x");' + " " * 100,
        target_url=TARGET,
        max_bytes=8,
    )
    assert oversized.coverage_gaps == ["js_asset_size_limit"]
    assert oversized.assets[0].redacted is True


def test_cross_origin_routes_are_rejected_and_flagged() -> None:
    source = 'fetch("https://evil.example.com/api/steal");\n'
    result = reverse_javascript_source(
        asset_url=ASSET, source=source, target_url=TARGET
    )
    assert not any("evil.example.com" in r.route for r in result.routes)
    assert "js_route_out_of_scope" in result.coverage_gaps


def test_sensitive_query_values_are_redacted_in_resolved_routes() -> None:
    source = 'fetch("/api/items?token=abc123&page=1");\n'
    result = reverse_javascript_source(
        asset_url=ASSET, source=source, target_url=TARGET
    )
    get_routes = [r.route for r in result.routes if r.method_hint == "GET"]
    assert get_routes, result.routes
    route = get_routes[0]
    assert "token=abc123" not in route
    assert "token=%5BREDACTED%5D" in route or "token=[REDACTED]" in route


def test_merge_is_deterministic_across_assets() -> None:
    a = reverse_javascript_source(
        asset_url=ASSET, source='fetch("/api/a");', target_url=TARGET
    )
    b = reverse_javascript_source(
        asset_url=ASSET, source='fetch("/api/a");', target_url=TARGET
    )
    merged = merge_javascript_intelligence([a, b])
    # Merging identical analyses is the identity: nothing duplicated,
    # nothing reordered.
    assert merged.model_dump(mode="json") == a.model_dump(mode="json")
    assert len(merged.assets) == 1


def test_tasks_are_generated_for_ast_discovered_routes() -> None:
    result = reverse_javascript_source(
        asset_url=ASSET,
        source='fetch("/api/tasked");',
        target_url=TARGET,
    )
    assert any(t.task_type == "js_route_mapping" for t in result.targeted_tasks)


# ---------------------------------------------------------------------------
# 4. Graceful degradation
# ---------------------------------------------------------------------------


def test_unparseable_source_degrades_to_the_regex_engine_observably() -> None:
    # Structurally broken JS the regex engine can still scan textually.
    source = 'function broken( { fetch("/api/still-visible");'
    result = reverse_javascript_source(
        asset_url=ASSET, source=source, target_url=TARGET
    )
    assert "js_ast_parse_failed_regex_fallback" in result.coverage_gaps
    # The fallback keeps the regex engine's recall on the same text.
    assert "https://app.example.com/api/still-visible" in {
        r.route for r in result.routes
    }


def test_missing_esprima_degrades_to_the_regex_engine_observably(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def _raise() -> Any:
        raise ImportError("esprima unavailable")

    monkeypatch.setattr("webpent.jsintel.js_reversing._load_esprima", _raise)
    result = reverse_javascript_source(
        asset_url=ASSET, source='fetch("/api/no-esprima");', target_url=TARGET
    )
    assert "js_ast_unavailable_regex_fallback" in result.coverage_gaps
    assert "https://app.example.com/api/no-esprima" in {
        r.route for r in result.routes
    }


def test_source_map_reference_is_still_extracted_by_the_ast_path() -> None:
    source = (
        'fetch("/api/mapped");\n'
        "//# sourceMappingURL=app.js.map\n"
    )
    result = reverse_javascript_source(
        asset_url=ASSET, source=source, target_url=TARGET
    )
    assert (
        result.assets[0].source_map_url
        == "https://app.example.com/static/app.js/app.js.map"
    )
    assert "source_map_discovered_not_fetched" in result.coverage_gaps


# ---------------------------------------------------------------------------
# 5. Flag contract + agent dispatch
# ---------------------------------------------------------------------------


def test_flag_defaults_off_and_settings_carry_it() -> None:
    settings = get_settings()
    assert settings.enable_js_ast_reversing is False


def test_agent_dispatcher_uses_legacy_engine_when_flag_off(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from webpent.agents.javascript_intelligence import agent as js_agent

    settings = get_settings()
    assert settings.enable_js_ast_reversing is False
    calls: list[str] = []

    def _fake_legacy(**kwargs: Any) -> Any:
        calls.append("legacy")
        return analyze_javascript_source(**kwargs)

    def _fail_ast(**kwargs: Any) -> Any:  # pragma: no cover - must not run
        raise AssertionError("AST reverser must not run with the flag off")

    monkeypatch.setattr(js_agent, "analyze_javascript_source", _fake_legacy)
    monkeypatch.setattr(
        "webpent.jsintel.js_reversing.reverse_javascript_source", _fail_ast
    )
    out = js_agent._analyze_asset(
        settings=settings,
        asset_url=ASSET,
        source='fetch("/api/dispatch");',
        target_url=TARGET,
        content_type="application/javascript",
        status_code=200,
    )
    assert calls == ["legacy"]
    assert "https://app.example.com/api/dispatch" in {r.route for r in out.routes}


def test_agent_dispatcher_uses_ast_reverser_when_flag_on(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from webpent.agents.javascript_intelligence import agent as js_agent

    settings = get_settings().model_copy(update={"enable_js_ast_reversing": True})
    calls: list[str] = []

    def _fake_ast(**kwargs: Any) -> Any:
        calls.append("ast")
        return reverse_javascript_source(**kwargs)

    def _fail_legacy(**kwargs: Any) -> Any:  # pragma: no cover - must not run
        raise AssertionError("legacy engine must not run with the flag on")

    monkeypatch.setattr(
        "webpent.jsintel.js_reversing.reverse_javascript_source", _fake_ast
    )
    monkeypatch.setattr(js_agent, "analyze_javascript_source", _fail_legacy)
    source = 'const b = "/api/d"; fetch(b + "/e");'
    out = js_agent._analyze_asset(
        settings=settings,
        asset_url=ASSET,
        source=source,
        target_url=TARGET,
        content_type="application/javascript",
        status_code=200,
    )
    assert calls == ["ast"]
    assert ("GET", "https://app.example.com/api/d/e") in _routes(out)


def test_flag_off_produces_byte_identical_legacy_results() -> None:
    source = (
        'const base = "/api/v2";\n'
        'const users = base + "/users";\n'
        "fetch(users);\n"
        "el.innerHTML = x;\n"
    )
    via_agent = js_agent_analyze_flag_off(source)
    direct = analyze_javascript_source(asset_url=ASSET, source=source, target_url=TARGET)
    assert via_agent.model_dump(mode="json") == direct.model_dump(mode="json")


def js_agent_analyze_flag_off(source: str) -> Any:
    from webpent.agents.javascript_intelligence import agent as js_agent

    settings = get_settings()
    assert settings.enable_js_ast_reversing is False
    return js_agent._analyze_asset(
        settings=settings,
        asset_url=ASSET,
        source=source,
        target_url=TARGET,
        content_type="application/javascript",
        status_code=200,
    )
