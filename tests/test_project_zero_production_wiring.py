"""Project Zero production wiring (2026-10-22) — regression tests.

Pins the wiring of the six library-tier Project Zero modules to their
production callers:

  * surface_influence_graph  -> shared/surface_security.analyze_security_surface
  * surface_drift            -> agents/crawler (diffs the previous
                                surface_security summary against the
                                fresh one, every crawl)
  * tech_stack_cve           -> agents/crawler (fingerprints the stack
                                from response headers already collected,
                                correlates against the injected feed)
  * taint_tracker            -> agents/crawler (form fields recorded as
                                SOURCES) + agents/validator (confirmed
                                findings' payloads recorded as SINKS)
  * shadow_detector          -> composed inside red_vs_blue (item 3
                                supplies the detection-key extraction
                                the escape comparison runs on)
  * red_vs_blue              -> agents/devils_advocate (self-check of
                                the production SSRF indicator detector,
                                escapes fed to the Postmortem store)

Every wiring site is pinned to be: default-off (a settings flag),
fail-soft (a failure logs and degrades, never raises into the host
node), and advisory-only (advisory state keys; findings, graph topology
and outbound requests are never touched).
"""

from __future__ import annotations

from types import SimpleNamespace
from uuid import uuid4

import pytest

from webpent.config.settings import Settings
from webpent.models.findings import Finding
from webpent.models.targets import Target
from webpent.state.state import PentestState

PZ_SETTINGS_FLAGS = (
    "enable_surface_influence_graph",
    "enable_surface_drift_analysis",
    "enable_tech_stack_cve_correlation",
    "enable_taint_tracking",
    "enable_red_vs_blue_selfcheck",
)


# ---------------------------------------------------------------------------
# Feature flags: all default-off
# ---------------------------------------------------------------------------


def test_pz_settings_flags_exist_and_default_off() -> None:
    settings = Settings()
    for flag in PZ_SETTINGS_FLAGS:
        assert hasattr(settings, flag), f"missing settings flag: {flag}"
        assert getattr(settings, flag) is False, f"{flag} must default to False"


def test_pentest_state_declares_pz_advisory_keys() -> None:
    # LangGraph silently DROPS node-update keys that are not declared in
    # the state schema; these annotations are what makes the advisory
    # outputs actually reachable downstream.
    annotations = PentestState.__annotations__
    for key in (
        "surface_drift",
        "tech_stack_cve",
        "taint_sources_recorded",
        "red_vs_blue_selfcheck",
    ):
        assert key in annotations, f"PentestState is missing advisory key: {key}"


# ---------------------------------------------------------------------------
# surface_influence_graph -> analyze_security_surface
# ---------------------------------------------------------------------------


def test_surface_influence_graph_flag_on_attaches_to_summary(monkeypatch) -> None:
    from webpent.shared.surface_security import analyze_security_surface

    monkeypatch.setattr(
        "webpent.config.settings.get_settings",
        lambda: SimpleNamespace(enable_surface_influence_graph=True),
    )
    result = analyze_security_surface(
        {"endpoints": ["https://lab.test/app"], "forms": []},
        "https://lab.test",
    )
    influence = result.get("surface_influence_graph")
    assert isinstance(influence, dict)
    assert influence  # non-empty graph payload


def test_surface_influence_graph_flag_off_stays_out_of_summary(monkeypatch) -> None:
    from webpent.shared.surface_security import analyze_security_surface

    monkeypatch.setattr(
        "webpent.config.settings.get_settings",
        lambda: SimpleNamespace(enable_surface_influence_graph=False),
    )
    result = analyze_security_surface(
        {"endpoints": ["https://lab.test/app"], "forms": []},
        "https://lab.test",
    )
    assert result.get("surface_influence_graph") is None


# ---------------------------------------------------------------------------
# surface_drift + taint sources -> crawler_node
# ---------------------------------------------------------------------------


def _mock_crawl(monkeypatch, *, endpoints, forms=None):
    from webpent.agents.crawler import agent as crawler_agent

    class _LLM:
        def invoke(self, _messages):
            return SimpleNamespace(content=endpoints)

    monkeypatch.setattr(
        crawler_agent, "run_katana", lambda *_a, **_k: list(endpoints)
    )
    monkeypatch.setattr(crawler_agent, "get_llm", lambda *_a, **_k: _LLM())
    monkeypatch.setattr(
        crawler_agent, "_fetch_and_analyze_js", lambda *_a, **_k: []
    )
    monkeypatch.setattr(
        crawler_agent,
        "_discover_html_forms",
        lambda *_a, **_k: list(forms or []),
    )


def _pz_settings(**overrides) -> SimpleNamespace:
    base = {
        "enable_structure_aware_triage": False,
        "max_structure_aware_triage_endpoints": 25,
        "enable_surface_security_analysis": True,
        "max_surface_security_observations": 100,
        "enable_surface_influence_graph": False,
        "enable_surface_drift_analysis": False,
        "enable_tech_stack_cve_correlation": False,
        "enable_taint_tracking": False,
        "enable_red_vs_blue_selfcheck": False,
    }
    base.update(overrides)
    return SimpleNamespace(**base)


def test_crawler_node_flag_off_emits_no_pz_advisory_state(monkeypatch) -> None:
    from webpent.agents.crawler import agent as crawler_agent

    _mock_crawl(monkeypatch, endpoints=["https://lab.test/a"])
    monkeypatch.setattr(
        "webpent.config.settings.get_settings", lambda: _pz_settings()
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

    assert "surface_drift" not in result
    assert "tech_stack_cve" not in result
    assert "taint_sources_recorded" not in result


def test_crawler_node_flag_on_emits_drift_and_taint_advisories(monkeypatch, tmp_path) -> None:
    from webpent.agents.crawler import agent as crawler_agent
    from webpent.memory.taint_tracker import TaintTracker
    from webpent.shared.surface_evidence_graph import build_surface_evidence_graph

    _mock_crawl(
        monkeypatch,
        endpoints=["https://lab.test/a", "https://lab.test/b"],
        forms=[
            {
                "source_url": "https://lab.test/a",
                "action": "https://lab.test/a",
                "data": {"user": "alice"},
            }
        ],
    )
    monkeypatch.setattr(
        "webpent.config.settings.get_settings",
        lambda: _pz_settings(
            enable_surface_influence_graph=True,
            enable_surface_drift_analysis=True,
            enable_taint_tracking=True,
        ),
    )

    baseline_graph = build_surface_evidence_graph(
        {"endpoints": ["https://lab.test/a"]}, target_url="https://lab.test"
    ).as_dict()
    tracker = TaintTracker(database_url=str(tmp_path / "taint.sqlite3"))
    monkeypatch.setattr(
        "webpent.memory.taint_tracker.get_taint_tracker", lambda: tracker
    )

    result = crawler_agent.crawler_node(
        {
            "target": Target(url="https://lab.test"),
            "session_cookies": {},
            "auth_state": {},
            "findings": [],
            "surface_security": {"surface_graph": baseline_graph},
            "javascript_intelligence": {},
        }
    )

    surface = result["surface_security"]
    assert isinstance(surface.get("surface_influence_graph"), dict)

    drift = result["surface_drift"]
    assert drift["baseline_node_count"] >= 1
    assert drift["current_node_count"] >= drift["baseline_node_count"]
    assert isinstance(drift["appeared"], list)

    assert result["taint_sources_recorded"] == 1


def test_crawler_taint_sources_are_fingerprint_queryable(monkeypatch, tmp_path) -> None:
    from webpent.agents.crawler.agent import _pz_record_taint_sources
    from webpent.memory.taint_tracker import TaintTracker

    tracker = TaintTracker(database_url=str(tmp_path / "taint.sqlite3"))
    monkeypatch.setattr(
        "webpent.memory.taint_tracker.get_taint_tracker", lambda: tracker
    )

    recorded = _pz_record_taint_sources(
        [
            {
                "source_url": "https://lab.test/login",
                "data": {"user": "alice", "pass": "", "comment": "hi"},
            }
        ],
        thread_id="t1",
    )
    # The empty value is skipped; the two non-empty fields are recorded.
    assert recorded == 2


# ---------------------------------------------------------------------------
# tech_stack_cve -> crawler helper
# ---------------------------------------------------------------------------


def test_pz_tech_stack_cve_update_fingerprints_and_correlates() -> None:
    from webpent.agents.crawler.agent import _pz_tech_stack_cve_update

    crawled_data = {
        "response_headers": [
            {"server": "Apache/2.4.49"},
            {"set-cookie": "session=abc; HttpOnly"},
        ]
    }
    feed = [
        {
            "cve_id": "CVE-2021-41773",
            "product": "apache_httpd",
            "version_lte": "2.4.49",
            "kev": True,
            "severity": "critical",
        }
    ]
    result = _pz_tech_stack_cve_update(crawled_data, feed)

    products = [c["product"] for c in result["components"]]
    assert "apache_httpd" in products
    assert result["correlations"], "vulnerable version must correlate"
    assert result["correlations"][0]["cve_id"] == "CVE-2021-41773"
    assert result["correlations"][0]["advisory_only"] is True


def test_pz_tech_stack_cve_update_is_fail_soft_on_garbage() -> None:
    from webpent.agents.crawler.agent import _pz_tech_stack_cve_update

    assert _pz_tech_stack_cve_update({"response_headers": "not-a-list"}, None) == {}
    assert _pz_tech_stack_cve_update({}, None) == {}


def test_pz_surface_drift_update_is_fail_soft(monkeypatch) -> None:
    from webpent.agents.crawler.agent import _pz_surface_drift_update

    # No previous summary -> no drift computation, no crash.
    assert _pz_surface_drift_update(None, {"surface_graph": {"nodes": []}}) == {}
    # Corrupt graph payload -> empty dict, never an exception.
    assert (
        _pz_surface_drift_update(
            {"surface_graph": {"nodes": "corrupt"}},
            {"surface_graph": {"nodes": "corrupt"}},
        )
        == {}
    )


# ---------------------------------------------------------------------------
# taint_tracker sink -> validator
# ---------------------------------------------------------------------------


def _finding(payload: str, url: str = "https://lab.test/item") -> Finding:
    return Finding(
        title="Reflected probe in item page",
        severity="MEDIUM",
        description="Probe value reappeared unescaped in the response.",
        tool_name="validator",
        payload=payload,
        url=url,
        confidence_level="Pending",
    )


def test_validator_taint_sink_records_fingerprint_link(monkeypatch, tmp_path) -> None:
    from webpent.agents.validator.agent import _pz_record_taint_sink
    from webpent.memory.taint_tracker import TaintTracker

    tracker = TaintTracker(database_url=str(tmp_path / "taint.sqlite3"))
    monkeypatch.setattr(
        "webpent.memory.taint_tracker.get_taint_tracker", lambda: tracker
    )
    monkeypatch.setattr(
        "webpent.config.settings.get_settings",
        lambda: SimpleNamespace(enable_taint_tracking=True),
    )

    payload = "probe-value-xyz-123"
    # Source side: the value was introduced somewhere earlier (e.g. by the
    # crawler's form recording, or an earlier session).
    tracker.record_source(
        value=payload,
        endpoint_label="https://lab.test/search",
        parameter_name="q",
        thread_id="t1",
    )

    assert _pz_record_taint_sink(_finding(payload), thread_id="t1") is True

    # Sink side recorded, and both ends share ONE fingerprint (the raw
    # value is never stored; only its salted hash links them).
    from webpent.memory.taint_tracker import fingerprint_taint_value

    fingerprint = fingerprint_taint_value(payload)
    linked = tracker.get_points_by_fingerprint(fingerprint)
    kinds = sorted(p["kind"] for p in linked)
    assert kinds == ["sink", "source"]


def test_validator_taint_sink_flag_off_is_noop(monkeypatch) -> None:
    from webpent.agents.validator.agent import _pz_record_taint_sink

    monkeypatch.setattr(
        "webpent.config.settings.get_settings",
        lambda: SimpleNamespace(enable_taint_tracking=False),
    )
    assert _pz_record_taint_sink(_finding("probe"), thread_id="t1") is False


def test_validator_taint_sink_fail_soft_on_bad_finding(monkeypatch, tmp_path) -> None:
    from webpent.agents.validator.agent import _pz_record_taint_sink
    from webpent.memory.taint_tracker import TaintTracker

    tracker = TaintTracker(database_url=str(tmp_path / "taint.sqlite3"))
    monkeypatch.setattr(
        "webpent.memory.taint_tracker.get_taint_tracker", lambda: tracker
    )
    monkeypatch.setattr(
        "webpent.config.settings.get_settings",
        lambda: SimpleNamespace(enable_taint_tracking=True),
    )
    # No payload and no url -> advisory helper reports False, raises nothing.
    bare = _finding("probe")
    assert _pz_record_taint_sink(bare, thread_id="t1") is True  # payload+url present
    no_url = bare.model_copy(update={"url": ""})
    assert _pz_record_taint_sink(no_url, thread_id="t1") is False


# ---------------------------------------------------------------------------
# red_vs_blue (composing shadow_detector) -> devils_advocate
# ---------------------------------------------------------------------------


def test_da_red_vs_blue_selfcheck_flag_off_returns_none(monkeypatch) -> None:
    from webpent.agents.devils_advocate import agent as da_agent

    monkeypatch.setattr(
        "webpent.config.settings.get_settings",
        lambda: SimpleNamespace(enable_red_vs_blue_selfcheck=False),
    )
    assert da_agent._pz_run_red_vs_blue_selfcheck(thread_id="t1") is None


def test_da_red_vs_blue_selfcheck_flag_on_reports_and_feeds_postmortem(
    monkeypatch,
) -> None:
    from webpent.agents.devils_advocate import agent as da_agent

    monkeypatch.setattr(
        "webpent.config.settings.get_settings",
        lambda: SimpleNamespace(enable_red_vs_blue_selfcheck=True),
    )

    recorded: list[dict] = []

    class _StubManager:
        def record_missed_finding(self, **kwargs):
            recorded.append(kwargs)
            return uuid4()

    import webpent.memory.postmortem as postmortem_mod

    monkeypatch.setattr(
        postmortem_mod,
        "get_postmortem_manager",
        lambda: _StubManager(),
    )

    result = da_agent._pz_run_red_vs_blue_selfcheck(thread_id="t1")

    assert result is not None
    assert result["detector"] == "extract_ssrf_indicators"
    assert result["vuln_class"] == "ssrf"
    assert result["techniques_tested"] >= 5
    # The cloud-metadata seed IS detected canonically (frozenset of
    # indicator classes is non-empty), so the loop is a genuine
    # red-vs-blue run, not a "never detected" no-op.
    escapes = result["escapes"]
    assert isinstance(escapes, list)
    assert all(isinstance(e, str) for e in escapes)
    # Every escape became exactly one detection_logic_gap postmortem
    # entry (the "strengthen detection" feedback half of the loop).
    assert len(recorded) == len(escapes)
    for entry in recorded:
        assert entry["metadata"]["evasion_technique"] in escapes
        assert entry["metadata"]["source"] == "red_vs_blue_internal_loop"


def test_da_red_vs_blue_selfcheck_fail_soft(monkeypatch) -> None:
    from webpent.agents.devils_advocate import agent as da_agent

    monkeypatch.setattr(
        "webpent.config.settings.get_settings",
        lambda: SimpleNamespace(enable_red_vs_blue_selfcheck=True),
    )

    import webpent.shared.red_vs_blue as rvb_mod

    def _boom(**_kwargs):
        raise RuntimeError("injected failure")

    monkeypatch.setattr(rvb_mod, "run_red_vs_blue", _boom)
    assert da_agent._pz_run_red_vs_blue_selfcheck(thread_id="t1") is None


def test_da_node_attaches_selfcheck_to_update(monkeypatch) -> None:
    from webpent.agents.devils_advocate import agent as da_agent

    monkeypatch.setattr(
        da_agent, "try_get_llm", lambda *_a, **_k: SimpleNamespace(invoke=lambda _m: None)
    )
    monkeypatch.setattr(
        da_agent,
        "_devils_advocate_finding",
        lambda finding, llm, allow_downgrade=True: finding,
    )
    import webpent.agents.validator.agent as validator_agent

    monkeypatch.setattr(
        validator_agent,
        "_persist_finding_incrementally",
        lambda finding, thread_id=None: True,
    )
    selfcheck_payload = {"detector": "x", "escapes": []}
    monkeypatch.setattr(
        da_agent,
        "_pz_run_red_vs_blue_selfcheck",
        lambda *, thread_id: selfcheck_payload,
    )

    result = da_agent.devils_advocate_node(
        {"findings": [_finding("probe")], "thread_id": "t1"}
    )

    assert result["red_vs_blue_selfcheck"] == selfcheck_payload
    assert result["findings"][0].title == "Reflected probe in item page"


def test_da_node_without_selfcheck_omits_key(monkeypatch) -> None:
    from webpent.agents.devils_advocate import agent as da_agent

    monkeypatch.setattr(
        da_agent, "try_get_llm", lambda *_a, **_k: SimpleNamespace(invoke=lambda _m: None)
    )
    monkeypatch.setattr(
        da_agent,
        "_devils_advocate_finding",
        lambda finding, llm, allow_downgrade=True: finding,
    )
    import webpent.agents.validator.agent as validator_agent

    monkeypatch.setattr(
        validator_agent,
        "_persist_finding_incrementally",
        lambda finding, thread_id=None: True,
    )
    monkeypatch.setattr(
        "webpent.config.settings.get_settings",
        lambda: SimpleNamespace(enable_red_vs_blue_selfcheck=False),
    )

    result = da_agent.devils_advocate_node(
        {"findings": [_finding("probe")], "thread_id": "t1"}
    )
    assert "red_vs_blue_selfcheck" not in result


# ---------------------------------------------------------------------------
# 2026-10-24 red-team fixes: operator catalog injection (cve_feed_catalog /
# kev_catalog previously had no declaration/producer) + tech_stack_cve end-
# to-end through crawler_node with a feed loaded from the operator file.
# ---------------------------------------------------------------------------


def test_operator_catalog_state_takes_precedence_over_file(tmp_path) -> None:
    from webpent.shared.operator_catalogs import (
        load_cve_feed_catalog,
        load_kev_catalog,
    )

    feed_file = tmp_path / "feed.json"
    feed_file.write_text('[{"cve_id": "CVE-2020-0001"}]', encoding="utf-8")
    monkey_state = ["ignored-because-state-wins"]

    state_value = [{"cve_id": "CVE-2021-41773", "product": "apache_httpd"}]
    with pytest.MonkeyPatch.context() as mp:
        mp.setattr(
            "webpent.config.settings.get_settings",
            lambda: _pz_settings(cve_feed_catalog_path=str(feed_file)),
        )
        assert load_cve_feed_catalog(state_value) == state_value
        assert load_kev_catalog(["CVE-2021-0001", {"cve_id": "CVE-2022-0002"}]) == [
            "CVE-2021-0001",
            "CVE-2022-0002",
        ]
        # Empty state value falls through to the file.
        loaded = load_cve_feed_catalog(None)
        assert loaded == [{"cve_id": "CVE-2020-0001"}]


def test_operator_catalog_loads_from_settings_path(tmp_path) -> None:
    from webpent.shared.operator_catalogs import (
        load_cve_feed_catalog,
        load_kev_catalog,
    )

    feed_file = tmp_path / "feed.json"
    feed_file.write_text(
        '[{"cve_id": "CVE-2021-41773", "product": "apache_httpd", '
        '"version_lte": "2.4.49", "kev": true, "severity": "critical"}]',
        encoding="utf-8",
    )
    kev_file = tmp_path / "kev.json"
    kev_file.write_text('{"kev": ["cve-2024-1234", "CVE-2023-0001"]}', encoding="utf-8")
    with pytest.MonkeyPatch.context() as mp:
        mp.setattr(
            "webpent.config.settings.get_settings",
            lambda: _pz_settings(
                cve_feed_catalog_path=str(feed_file),
                kev_catalog_path=str(kev_file),
            ),
        )
        feed = load_cve_feed_catalog(None)
        assert feed[0]["cve_id"] == "CVE-2021-41773"
        assert load_kev_catalog(None) == ["CVE-2024-1234", "CVE-2023-0001"]


def test_operator_catalog_is_fail_soft(tmp_path) -> None:
    from webpent.shared.operator_catalogs import (
        load_cve_feed_catalog,
        load_kev_catalog,
    )

    missing = tmp_path / "missing.json"
    garbage = tmp_path / "garbage.json"
    garbage.write_text("{not json", encoding="utf-8")
    wrong_shape = tmp_path / "wrong.json"
    wrong_shape.write_text('"just a string"', encoding="utf-8")
    with pytest.MonkeyPatch.context() as mp:
        mp.setattr(
            "webpent.config.settings.get_settings",
            lambda: _pz_settings(
                cve_feed_catalog_path=str(missing),
                kev_catalog_path=str(garbage),
            ),
        )
        assert load_cve_feed_catalog(None) == []
        assert load_kev_catalog(None) == []
        mp.setattr(
            "webpent.config.settings.get_settings",
            lambda: _pz_settings(
                cve_feed_catalog_path=str(garbage), kev_catalog_path=str(wrong_shape)
            ),
        )
        assert load_cve_feed_catalog(None) == []
        assert load_kev_catalog(None) == []


def test_crawler_node_flag_on_tech_stack_cve_correlates_via_operator_file(
    monkeypatch, tmp_path
) -> None:
    """End-to-end: crawler_node + flag on + feed only via settings path.

    This closes the coverage gap that hid the dead cve_feed_catalog key:
    the helper test passed the feed directly, so the production path
    (state -> catalog resolution -> correlation) was never exercised.
    """
    import json as _json

    from webpent.agents.crawler import agent as crawler_agent
    from webpent.shared.surface_evidence_graph import build_surface_evidence_graph

    feed_file = tmp_path / "cve_feed.json"
    feed_file.write_text(
        _json.dumps(
            [
                {
                    "cve_id": "CVE-2021-41773",
                    "product": "apache_httpd",
                    "version_lte": "2.4.49",
                    "kev": True,
                    "severity": "critical",
                }
            ]
        ),
        encoding="utf-8",
    )
    # Force the HTTP-discovery path (katana returns nothing) and provide the
    # header evidence the way discover_http_surface actually does: inside
    # surface_records[*]["response_headers"]. This also pins the 2026-10-24
    # helper fix that reads header evidence from surface_records.
    _mock_crawl(
        monkeypatch,
        endpoints=[],
        forms=[],
    )
    monkeypatch.setattr(
        "webpent.agents.crawler.agent.discover_http_surface",
        lambda *_a, **_k: {
            "endpoints": ["https://lab.test/a"],
            "pages_fetched": 1,
            "forms": [],
            "coverage_gaps": [],
            "surface_records": [
                {
                    "record_id": "http:1",
                    "url": "https://lab.test/a",
                    "response_headers": {"server": "Apache/2.4.49"},
                }
            ],
        },
    )
    monkeypatch.setattr(
        "webpent.config.settings.get_settings",
        lambda: _pz_settings(
            enable_tech_stack_cve_correlation=True,
            cve_feed_catalog_path=str(feed_file),
        ),
    )

    baseline_graph = build_surface_evidence_graph(
        {"endpoints": []}, target_url="https://lab.test"
    ).as_dict()

    result = crawler_agent.crawler_node(
        {
            "target": Target(url="https://lab.test"),
            "session_cookies": {},
            "auth_state": {},
            "findings": [],
            "surface_security": {"surface_graph": baseline_graph},
            "javascript_intelligence": {},
        }
    )

    tech = result["tech_stack_cve"]
    assert tech, "flag on + operator feed must produce a correlation update"
    products = [c["product"] for c in tech.get("components", [])]
    assert "apache_httpd" in products
    assert tech["correlations"], "vulnerable version must correlate through the node"
    assert tech["correlations"][0]["cve_id"] == "CVE-2021-41773"
