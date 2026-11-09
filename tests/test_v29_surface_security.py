from __future__ import annotations

from types import SimpleNamespace

from webpent.config.settings import Settings
from webpent.models.targets import Target
from webpent.shared.surface_security import analyze_security_surface


def _categories(summary: dict) -> set[str]:
    return {str(item["category"]) for item in summary["observations"]}


def test_surface_analyzer_maps_collected_signals_to_categories() -> None:
    crawled_data = {
        "endpoints": [
            "https://lab.test/graphql?query=secret-value",
            "https://lab.test/api/orders?id=42",
            "https://lab.test/download?file=../../etc/passwd",
            "https://lab.test/redirect?url=https%3A%2F%2Fexample.test",
            "https://lab.test/chat?prompt=hello",
            "https://lab.test/ws",
        ],
        "forms": [
            {
                "action": "https://lab.test/upload?folder=private",
                "method": "POST",
                "data": {"avatar": "", "type": "file"},
            }
        ],
        "headers": {
            "access-control-allow-origin": "*",
            "cache-control": "public, max-age=60",
        },
    }

    result = analyze_security_surface(crawled_data, "https://lab.test", max_observations=100)
    categories = _categories(result)

    expected_categories = {
        "api",
        "graphql",
        "path_traversal",
        "ssrf",
        "web_llm",
        "websockets",
    }
    assert expected_categories.issubset(categories)
    assert "file_upload" in categories
    assert result["bounded"] is True
    assert result["passive_only"] is True
    assert len(result["observations"]) <= 100


def test_surface_endpoint_references_redact_query_values_and_fragments() -> None:
    result = analyze_security_surface(
        {
            "endpoints": [
                "https://lab.test/search?q=do-not-store&token=super-secret",
                "https://lab.test/profile#private-fragment",
            ]
        },
        "https://lab.test",
    )

    serialised = str(result)
    assert "do-not-store" not in serialised
    assert "super-secret" not in serialised
    assert "private-fragment" not in serialised
    endpoint_refs = [ref for obs in result["observations"] for ref in obs["endpoint_refs"]]
    assert any("q=[REDACTED]" in ref for ref in endpoint_refs)
    assert all("[REDACTED]" not in ref or "=" in ref for ref in endpoint_refs)


def test_surface_summary_exposes_coverage_gaps_when_no_signal_exists() -> None:
    result = analyze_security_surface(
        {"endpoints": ["https://lab.test/home"]},
        "https://lab.test",
    )

    assert result["coverage_gaps"]
    assert any("sql_injection:" in gap for gap in result["coverage_gaps"])
    assert any("race_condition:" in gap for gap in result["coverage_gaps"])
    assert any("oauth:" in gap for gap in result["coverage_gaps"])


def test_surface_analyzer_never_returns_findings() -> None:
    result = analyze_security_surface(
        {"endpoints": ["https://lab.test/graphql"]},
        "https://lab.test",
    )

    assert "findings" not in result
    assert all("finding" not in observation for observation in result["observations"])
    assert all(
        observation["status"] != "confirmed"
        for observation in result["observations"]
    )


def test_surface_flag_defaults_off() -> None:
    settings = Settings()
    assert settings.enable_surface_security_analysis is False
    assert settings.max_surface_security_observations == 100


def test_crawler_feature_flag_off_keeps_surface_security_empty(monkeypatch) -> None:
    from webpent.agents.crawler import agent as crawler_agent

    endpoints = ["https://lab.test/graphql?query=hidden"]

    class _LLM:
        def invoke(self, _messages):
            return SimpleNamespace(content=endpoints)

    monkeypatch.setattr(crawler_agent, "run_katana", lambda *_args, **_kwargs: endpoints)
    monkeypatch.setattr(crawler_agent, "get_llm", lambda *_args, **_kwargs: _LLM())
    monkeypatch.setattr(crawler_agent, "_fetch_and_analyze_js", lambda *_args, **_kwargs: [])
    monkeypatch.setattr(crawler_agent, "_discover_html_forms", lambda *_args, **_kwargs: [])
    monkeypatch.setattr(
        "webpent.config.settings.get_settings",
        lambda: SimpleNamespace(
            enable_structure_aware_triage=False,
            max_structure_aware_triage_endpoints=25,
            enable_surface_security_analysis=False,
            max_surface_security_observations=100,
        ),
    )

    result = crawler_agent.crawler_node(
        {
            "target": Target(url="https://lab.test"),
            "session_cookies": {},
            "auth_state": {},
            "findings": [],
            "surface_security": {},
        }
    )

    assert result.get("surface_security", {}) == {}
    assert result.get("findings") is None


def test_crawler_feature_flag_on_returns_bounded_passive_surface(monkeypatch) -> None:
    from webpent.agents.crawler import agent as crawler_agent

    endpoints = [
        "https://lab.test/graphql?query=private",
        "https://lab.test/api/orders?id=1",
    ]

    class _LLM:
        def invoke(self, _messages):
            return SimpleNamespace(content=endpoints)

    monkeypatch.setattr(crawler_agent, "run_katana", lambda *_args, **_kwargs: endpoints)
    monkeypatch.setattr(crawler_agent, "get_llm", lambda *_args, **_kwargs: _LLM())
    monkeypatch.setattr(crawler_agent, "_fetch_and_analyze_js", lambda *_args, **_kwargs: [])
    monkeypatch.setattr(crawler_agent, "_discover_html_forms", lambda *_args, **_kwargs: [])
    monkeypatch.setattr(
        "webpent.config.settings.get_settings",
        lambda: SimpleNamespace(
            enable_structure_aware_triage=False,
            max_structure_aware_triage_endpoints=25,
            enable_surface_security_analysis=True,
            max_surface_security_observations=2,
        ),
    )

    result = crawler_agent.crawler_node(
        {
            "target": Target(url="https://lab.test"),
            "session_cookies": {},
            "auth_state": {},
            "findings": [],
            "surface_security": {},
            "javascript_intelligence": {},
        }
    )

    surface = result["surface_security"]
    assert surface["bounded"] is True
    assert surface["passive_only"] is True
    assert len(surface["observations"]) <= 2
    assert "findings" not in surface
    assert "private" not in str(surface)


def test_surface_analyzer_projects_redacted_javascript_secret_candidates() -> None:
    result = analyze_security_surface(
        {"endpoints": ["https://lab.test/app"]},
        "https://lab.test",
        javascript_intelligence={
            "secret_candidates": [
                {
                    "kind": "assignment_secret",
                    "source_asset": "https://lab.test/static/app.js?token=do-not-store",
                    "line": 42,
                    "value_sha256": "a" * 64,
                    "redacted_value": "[REDACTED]",
                    "confidence": "medium",
                    "validation_status": "advisory",
                    "evidence_ref": "secret:app.js:assignment_secret:42:hash",
                    "raw_value": "do-not-export-this-value",
                }
            ]
        },
    )

    observations = result["observations"]
    secret_observations = [
        item for item in observations if item["category"] == "secrets_exposure"
    ]
    assert len(secret_observations) == 1
    observation = secret_observations[0]
    assert observation["status"] == "needs_active_validation"
    assert observation["active_validation_required"] is True
    assert observation["human_review_required"] is True
    assert observation["metadata"]["candidate_count"] == 1
    assert observation["metadata"]["values_redacted"] is True
    assert "do-not-export-this-value" not in str(result)
    assert "do-not-store" not in str(result)
    assert "secret:app.js:assignment_secret:42:hash" in observation["evidence_refs"]


def test_surface_analyzer_keeps_secret_category_as_coverage_not_a_finding() -> None:
    result = analyze_security_surface(
        {"endpoints": ["https://lab.test/home"]},
        "https://lab.test",
        javascript_intelligence={"secret_candidates": []},
    )

    assert any(
        gap.startswith("secrets_exposure: no relevant passive signal")
        for gap in result["coverage_gaps"]
    )
    assert "findings" not in result
    assert all(item["status"] != "confirmed" for item in result["observations"])


def test_surface_analyzer_secret_projection_is_bounded() -> None:
    candidates = [
        {
            "kind": "assignment_secret",
            "source_asset": f"https://lab.test/static/{index}.js",
            "value_sha256": "b" * 64,
            "redacted_value": "[REDACTED]",
            "confidence": "low",
            "validation_status": "advisory",
            "evidence_ref": f"secret:{index}",
        }
        for index in range(20)
    ]
    result = analyze_security_surface(
        {},
        "https://lab.test",
        javascript_intelligence={"secret_candidates": candidates},
        max_observations=1,
    )

    assert len(result["observations"]) <= 1
    secret_observation = next(
        item for item in result["observations"] if item["category"] == "secrets_exposure"
    )
    assert len(secret_observation["endpoint_refs"]) <= 12
    assert len(secret_observation["signal_refs"]) <= 12
    assert len(secret_observation["evidence_refs"]) <= 12
    assert secret_observation["metadata"]["candidate_count"] == 20


