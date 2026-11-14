from __future__ import annotations

from types import SimpleNamespace

from webpent.config.settings import Settings
from webpent.shared.recon_triage import (
    build_coverage_preserving_queue,
    classify_endpoint,
)


def test_classify_endpoint_extracts_passive_structure_signals() -> None:
    record = classify_endpoint("https://lab.test/api/v1/admin/upload?return_url=%2Fhome&id=7")
    assert record is not None
    assert {"api", "admin", "upload", "callback", "parameterized"}.issubset(set(record.signals))
    assert record.parameter_names == ("id", "return_url")
    assert "7" not in record.as_dict()["parameter_names"]


def test_llm_parser_preserves_bounded_endpoint_coverage_beyond_five() -> None:
    from webpent.agents.crawler.agent import _MAX_URLS_FOR_LLM, _parse_llm_url_list

    endpoints = [f"https://lab.test/endpoint-{index}" for index in range(6)]
    selected = _parse_llm_url_list(str(endpoints).replace("'", '"'), [])

    assert len(selected) == 6
    assert len(selected) <= _MAX_URLS_FOR_LLM


def test_coverage_queue_preserves_observed_signal_families() -> None:
    endpoints = [
        "https://lab.test/home",
        "https://lab.test/search?q=one",
        "https://lab.test/api/v1/orders?id=1",
        "https://lab.test/login",
        "https://lab.test/admin/users",
        "https://lab.test/upload/avatar",
        "https://lab.test/graphql",
        "https://lab.test/websocket",
        "https://lab.test/redirect?url=https%3A%2F%2Flab.test",
        "https://lab.test/checkout/submit",
        "https://lab.test/.env",
    ]
    queue, audit = build_coverage_preserving_queue(endpoints, max_items=25)

    assert len(queue) == len(endpoints)
    assert set(audit["observed_signal_groups"]) <= set(audit["covered_signal_groups"])
    assert audit["coverage_gaps"] == []
    assert audit["mode"] == "structure-aware-deterministic"
    assert all("do-not-store" not in str(item).lower() for item in audit["endpoint_observations"])


def test_coverage_queue_is_bounded_stable_and_deduplicated() -> None:
    endpoints = [
        "https://lab.test/plain",
        "https://lab.test/plain/",
        "https://lab.test/api?q=1",
        "https://lab.test/api?q=1",
        "not-a-url",
    ] * 20
    first, audit = build_coverage_preserving_queue(endpoints, max_items=3)
    second, second_audit = build_coverage_preserving_queue(endpoints, max_items=3)

    assert first == second
    assert audit == second_audit
    assert len(first) <= 3
    assert len(first) == len(set(first))
    assert audit["raw_endpoint_count"] == 2


def test_structure_aware_triage_is_opt_in_and_bounded() -> None:
    settings = Settings()
    assert settings.enable_structure_aware_triage is False
    assert settings.max_structure_aware_triage_endpoints == 25
    bounded = Settings(
        enable_structure_aware_triage=True,
        max_structure_aware_triage_endpoints=40,
    )
    assert bounded.enable_structure_aware_triage is True
    assert bounded.max_structure_aware_triage_endpoints == 40


def test_triage_metadata_is_redacted_and_has_no_response_or_cookie_fields() -> None:
    _, audit = build_coverage_preserving_queue(
        ["https://lab.test/account?session=do-not-store&user=alice"],
        max_items=5,
    )
    serialised = str(audit).lower()
    assert "do-not-store" not in serialised
    assert "cookie" not in serialised
    assert "response_body" not in serialised
    assert "session" in serialised


def test_crawler_structure_aware_queue_overrides_url_only_llm_bias(monkeypatch) -> None:
    from webpent.agents.crawler import agent as crawler_agent
    from webpent.models.targets import Target

    endpoints = [
        "https://lab.test/home",
        "https://lab.test/api/v1/orders?id=1",
        "https://lab.test/login",
        "https://lab.test/upload/avatar",
        "https://lab.test/graphql",
        "https://lab.test/checkout/submit",
    ]

    class _LLM:
        def invoke(self, _messages):
            return SimpleNamespace(content=endpoints[0])

    monkeypatch.setattr(crawler_agent, "run_katana", lambda *_args, **_kwargs: endpoints)
    monkeypatch.setattr(crawler_agent, "get_llm", lambda *_args, **_kwargs: _LLM())
    monkeypatch.setattr(crawler_agent, "_fetch_and_analyze_js", lambda *_args, **_kwargs: [])
    monkeypatch.setattr(crawler_agent, "_discover_html_forms", lambda *_args, **_kwargs: [])
    monkeypatch.setattr(
        "webpent.config.settings.get_settings",
        lambda: SimpleNamespace(
            enable_structure_aware_triage=True,
            max_structure_aware_triage_endpoints=25,
        ),
    )

    result = crawler_agent.crawler_node(
        {
            "target": Target(url="https://lab.test"),
            "session_cookies": {},
            "auth_state": {},
        }
    )
    crawled = result["crawled_data"]
    assert len(crawled["endpoints"]) == len(endpoints)
    assert len(crawled["endpoints"]) > 1
    assert crawled["endpoint_triage"]["llm_advisory_selection"] == [endpoints[0]]
    assert "api" in crawled["endpoint_triage"]["covered_signal_groups"]
    assert "upload" in crawled["endpoint_triage"]["covered_signal_groups"]
    assert "graphql" in crawled["endpoint_triage"]["covered_signal_groups"]


def test_business_logic_probe_limits_are_configurable_and_bounded(monkeypatch) -> None:
    from webpent.agents.business_logic_fuzzer import agent as fuzzer_agent

    defaults = Settings()
    assert defaults.business_logic_burst_size == 10
    assert defaults.business_logic_max_endpoints == 10

    configured = Settings(
        business_logic_burst_size=3,
        business_logic_max_endpoints=2,
    )
    assert configured.business_logic_burst_size == 3
    assert configured.business_logic_max_endpoints == 2

    monkeypatch.setattr(
        "webpent.config.settings.get_settings",
        lambda: configured,
    )
    assert fuzzer_agent._runtime_business_logic_limits() == (3, 2)


def test_crawler_structure_aware_fallback_message_is_not_stale() -> None:
    from pathlib import Path

    from webpent.agents.crawler import agent as crawler_agent

    source = Path(crawler_agent.__file__).read_text()
    assert "the structure-aware coverage queue" in source
    assert "Falling back to raw top-%d katana endpoints." not in source
