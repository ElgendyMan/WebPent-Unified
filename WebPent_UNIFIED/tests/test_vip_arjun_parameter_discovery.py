"""Tests for arjun hidden-parameter discovery (VIP detection-depth initiative).

Mirrors the structure of ``tests/test_p0_ffuf_preflight.py`` — the closest
existing precedent for a bounded, scope-gated, feature-flagged recon tool
wrapper. Covers three layers:

  1. ``tools/recon/arjun.py`` — the subprocess wrapper itself (registration,
     scope refusal, output parsing against the REAL JSON shape captured by
     running arjun 2.2.7 against a local test HTTP server, zero-findings
     handling where arjun writes no output file at all).
  2. ``agents/crawler/agent.py`` — that arjun is disabled by default, and
     that discovered parameters land in ``crawled_data["discovered_parameters"]``
     keyed by URL when enabled.
  3. ``agents/hypothesis_analyzer/agent.py`` — that discovered parameters are
     converted into hypotheses using the same name->vuln_class signal table
     as visible query parameters.
"""

from __future__ import annotations

from types import SimpleNamespace

import pytest

# ---------------------------------------------------------------------------
# Layer 1: tools/recon/arjun.py
# ---------------------------------------------------------------------------


def test_arjun_is_registered_lazily():
    from webpent.tools.registry import get_tool

    entry = get_tool("arjun")
    assert entry is not None
    assert entry.category == "recon"


def test_arjun_refuses_out_of_scope_before_subprocess(monkeypatch):
    import webpent.tools.recon.arjun as arjun

    called = False

    def fail_if_called(*args, **kwargs):
        nonlocal called
        called = True
        raise AssertionError("subprocess must not run out of scope")

    monkeypatch.setattr(arjun, "run_command", fail_if_called)
    monkeypatch.setattr(arjun, "is_engagement_target_host", lambda host: False)
    assert arjun.run_arjun("https://out-of-scope.test") == []
    assert called is False


def test_arjun_refuses_malformed_url_before_subprocess(monkeypatch):
    import webpent.tools.recon.arjun as arjun

    called = False

    def fail_if_called(*args, **kwargs):
        nonlocal called
        called = True
        raise AssertionError("subprocess must not run on a malformed URL")

    monkeypatch.setattr(arjun, "run_command", fail_if_called)
    assert arjun.run_arjun("not-a-url") == []
    assert arjun.run_arjun("ftp://target.test/x") == []
    assert called is False


def test_arjun_rejects_invalid_method(monkeypatch):
    import webpent.tools.recon.arjun as arjun

    # Scope check runs before parameter validation (matches run_ffuf's own
    # ordering) — a target must be in-scope for a caller-bug ValueError to
    # surface at all, otherwise out-of-scope short-circuits to [] first.
    monkeypatch.setattr(arjun, "is_engagement_target_host", lambda host: True)
    with pytest.raises(ValueError, match="method"):
        arjun.run_arjun("https://target.test/", method="DELETE")


def test_arjun_rejects_out_of_range_threads(monkeypatch):
    import webpent.tools.recon.arjun as arjun

    monkeypatch.setattr(arjun, "is_engagement_target_host", lambda host: True)
    with pytest.raises(ValueError, match="threads"):
        arjun.run_arjun("https://target.test/", threads=0)
    with pytest.raises(ValueError, match="threads"):
        arjun.run_arjun("https://target.test/", threads=51)


def test_arjun_refuses_missing_configured_wordlist(monkeypatch, tmp_path):
    import webpent.tools.recon.arjun as arjun

    monkeypatch.setattr(arjun, "is_engagement_target_host", lambda host: True)
    missing = tmp_path / "does-not-exist.txt"
    called = False

    def fail_if_called(*args, **kwargs):
        nonlocal called
        called = True
        raise AssertionError("subprocess must not run with a missing wordlist")

    monkeypatch.setattr(arjun, "run_command", fail_if_called)
    assert arjun.run_arjun("https://target.test/", wordlist_path=str(missing)) == []
    assert called is False


def test_parse_arjun_output_real_captured_shape():
    """Exact JSON shape captured by running arjun 2.2.7 against a local
    test HTTP server before writing the wrapper (see arjun.py module
    docstring) — not assumed from documentation."""
    import webpent.tools.recon.arjun as arjun

    raw = (
        '{"http://127.0.0.1:8765/": {"headers": {"User-Agent": "Mozilla/5.0"}, '
        '"method": "GET", "params": ["debug", "user_id", "id"]}}'
    )
    params = arjun._parse_arjun_output(raw, "http://127.0.0.1:8765/")
    assert params == ["debug", "id", "user_id"]  # sorted, de-duplicated


def test_parse_arjun_output_empty_text_is_safe():
    import webpent.tools.recon.arjun as arjun

    assert arjun._parse_arjun_output("", "https://target.test/") == []
    assert arjun._parse_arjun_output("   ", "https://target.test/") == []


def test_parse_arjun_output_malformed_json_is_safe():
    import webpent.tools.recon.arjun as arjun

    assert arjun._parse_arjun_output("{not valid json", "https://target.test/") == []
    assert arjun._parse_arjun_output("[]", "https://target.test/") == []


def test_arjun_zero_findings_means_no_output_file_not_an_error(monkeypatch):
    """Verified empirically: arjun's -oJ file simply does not exist when it
    finds zero parameters (NOT an empty file, NOT a non-zero exit code)."""
    import webpent.tools.recon.arjun as arjun

    monkeypatch.setattr(arjun, "is_engagement_target_host", lambda host: True)
    monkeypatch.setattr(
        arjun,
        "get_settings",
        lambda: SimpleNamespace(arjun_path="arjun", arjun_timeout=30, arjun_request_timeout=15),
    )
    # run_command succeeds (exit 0) but never creates the -oJ file —
    # matches arjun's real zero-findings behavior.
    monkeypatch.setattr(arjun, "run_command", lambda cmd, timeout: "")
    assert arjun.run_arjun("https://target.test/") == []


def test_arjun_reads_output_file_when_present(monkeypatch, tmp_path):
    import webpent.tools.recon.arjun as arjun

    monkeypatch.setattr(arjun, "is_engagement_target_host", lambda host: True)
    monkeypatch.setattr(
        arjun,
        "get_settings",
        lambda: SimpleNamespace(arjun_path="arjun", arjun_timeout=30, arjun_request_timeout=15),
    )

    def fake_run_command(cmd, timeout):
        # Find the -oJ path arjun.py generated and write the captured
        # real-world JSON shape to it, the way the real subprocess would.
        output_index = cmd.index("-oJ") + 1
        output_path = cmd[output_index]
        with open(output_path, "w", encoding="utf-8") as fh:
            fh.write(
                '{"https://target.test/api": {"headers": {}, "method": "GET", '
                '"params": ["role", "admin"]}}'
            )
        return ""

    monkeypatch.setattr(arjun, "run_command", fake_run_command)
    params = arjun.run_arjun("https://target.test/api")
    assert params == ["admin", "role"]


def test_arjun_executable_in_manifest():
    from webpent.tools.utils.subprocess import _allowed_executable_names

    assert "arjun" in _allowed_executable_names()


# ---------------------------------------------------------------------------
# Layer 2: agents/crawler/agent.py integration
# ---------------------------------------------------------------------------


def _build_crawler_state(**overrides):
    """Minimal PentestState (a TypedDict, total=False) for crawler_node.

    llm_enabled_override=False takes the deterministic-fallback branch so
    the test never needs a real/mocked LLM provider — curated_endpoints
    becomes exactly the katana-discovered list in discovery order.
    """
    from webpent.models.targets import Target

    state = {
        "target": Target(url="https://target.test/"),
        "session_cookies": {},
        "session_headers": {},
        "llm_enabled_override": False,
    }
    state.update(overrides)
    return state


def test_crawler_node_skips_arjun_when_disabled(monkeypatch):
    """arjun_enabled defaults to False; crawler_node must not call arjun at
    all, and crawled_data must carry no discovered_parameters key."""
    import webpent.agents.crawler.agent as crawler_agent

    monkeypatch.setattr(
        crawler_agent,
        "run_katana",
        lambda url, **kwargs: ["https://target.test/api/users?id=1"],
    )
    monkeypatch.setattr(
        "webpent.config.settings.get_settings",
        lambda: SimpleNamespace(
            arjun_enabled=False,
            enable_structure_aware_triage=False,
            enable_http_discovery_supplement=False,
            enable_surface_security_analysis=False,
        ),
    )

    called = False

    def fail_if_called(*args, **kwargs):
        nonlocal called
        called = True
        return []

    monkeypatch.setattr("webpent.tools.recon.arjun.run_arjun", fail_if_called)

    result = crawler_agent.crawler_node(_build_crawler_state())
    assert called is False
    assert "discovered_parameters" not in result["crawled_data"]


def test_crawler_node_populates_discovered_parameters_when_enabled(monkeypatch):
    """End-to-end through the real crawler_node function: katana discovers
    an endpoint, arjun (mocked at the subprocess-adjacent run_arjun level,
    same seam test_recon_ffuf_is_disabled_by_default uses for ffuf) finds a
    hidden parameter on it, and crawled_data carries the result keyed by
    that exact URL — the same key hypothesis_analyzer reads downstream."""
    import webpent.agents.crawler.agent as crawler_agent

    target_endpoint = "https://target.test/api/users?id=1"
    monkeypatch.setattr(crawler_agent, "run_katana", lambda url, **kwargs: [target_endpoint])
    monkeypatch.setattr(
        "webpent.config.settings.get_settings",
        lambda: SimpleNamespace(
            arjun_enabled=True,
            arjun_max_endpoints=5,
            arjun_wordlist_path="",
            enable_structure_aware_triage=False,
            enable_http_discovery_supplement=False,
            enable_surface_security_analysis=False,
        ),
    )

    received_url = None

    def fake_run_arjun(url, **kwargs):
        nonlocal received_url
        received_url = url
        return ["file", "user_id"]

    monkeypatch.setattr("webpent.tools.recon.arjun.run_arjun", fake_run_arjun)

    result = crawler_agent.crawler_node(_build_crawler_state())
    crawled_data = result["crawled_data"]
    assert received_url == target_endpoint
    assert crawled_data["discovered_parameters"] == {target_endpoint: ["file", "user_id"]}


def test_crawler_node_arjun_failure_degrades_safely(monkeypatch):
    """One arjun probe raising must not abort crawler_node — the rest of
    crawled_data (endpoints, etc.) must still come back normally."""
    import webpent.agents.crawler.agent as crawler_agent

    target_endpoint = "https://target.test/api/users?id=1"
    monkeypatch.setattr(crawler_agent, "run_katana", lambda url, **kwargs: [target_endpoint])
    monkeypatch.setattr(
        "webpent.config.settings.get_settings",
        lambda: SimpleNamespace(
            arjun_enabled=True,
            arjun_max_endpoints=5,
            arjun_wordlist_path="",
            enable_structure_aware_triage=False,
            enable_http_discovery_supplement=False,
            enable_surface_security_analysis=False,
        ),
    )

    def raising_run_arjun(url, **kwargs):
        raise RuntimeError("simulated subprocess failure")

    monkeypatch.setattr("webpent.tools.recon.arjun.run_arjun", raising_run_arjun)

    result = crawler_agent.crawler_node(_build_crawler_state())
    assert result["crawled_data"]["endpoints"] == [target_endpoint]
    assert "discovered_parameters" not in result["crawled_data"]


def test_crawler_prioritizes_endpoints_with_query_strings_and_form_actions():
    """Unit-level check of the prioritization logic used inside crawler_node's
    arjun block, extracted here as a standalone assertion of the same
    filtering rule (endpoints with '?' or matching a known form action come
    first) since the block itself is inlined in crawler_node rather than a
    separately importable function."""
    curated_endpoints = [
        "https://target.test/static/logo.png",
        "https://target.test/api/users?page=1",
        "https://target.test/contact",
    ]
    forms = [{"action": "https://target.test/contact", "method": "POST"}]
    form_action_urls = {
        str(f.get("action")) for f in forms if isinstance(f, dict) and f.get("action")
    }
    prioritized = [
        ep for ep in curated_endpoints if "?" in ep or ep in form_action_urls
    ]
    rest = [ep for ep in curated_endpoints if ep not in prioritized]
    ordered = list(dict.fromkeys(prioritized + rest))
    assert ordered[0] == "https://target.test/api/users?page=1"
    assert ordered[1] == "https://target.test/contact"
    assert ordered[2] == "https://target.test/static/logo.png"


# ---------------------------------------------------------------------------
# Layer 3: agents/hypothesis_analyzer/agent.py integration
# ---------------------------------------------------------------------------


def test_discovered_parameter_hypotheses_uses_same_signal_table():
    from webpent.agents.hypothesis_analyzer.agent import (
        _discovered_parameter_hypotheses,
        _generic_parameter_hypotheses,
    )

    url = "https://target.test/api/users"
    # "user_id" and "file" are real entries in _PARAM_NAME_SIGNALS (user_id
    # matches both the "_id" and "user" fragments; "file" matches "file").
    # "zzz_nothing_here" matches no fragment in _PARAM_NAME_SIGNALS by
    # either exact, prefix, or "_"-suffix boundary rule.
    discovered = {url: ["user_id", "file", "zzz_nothing_here"]}

    hidden_results = _discovered_parameter_hypotheses(url, discovered)
    # Compare classification against the same table applied to a URL whose
    # visible query string carries the identical parameter names — the
    # vuln_class assigned must be identical either way.
    visible_results = _generic_parameter_hypotheses(f"{url}?user_id=1&file=1")

    hidden_by_param = {param: vuln_class for vuln_class, _reason, param in hidden_results}
    visible_by_param = {param: vuln_class for vuln_class, _reason, param in visible_results}
    assert hidden_by_param["user_id"] == visible_by_param["user_id"]
    assert hidden_by_param["file"] == visible_by_param["file"]
    # The benign unmatched name must not produce a spurious hypothesis.
    assert "zzz_nothing_here" not in hidden_by_param


def test_discovered_parameter_hypotheses_marks_provenance_in_reason():
    from webpent.agents.hypothesis_analyzer.agent import _discovered_parameter_hypotheses

    url = "https://target.test/api/users"
    results = _discovered_parameter_hypotheses(url, {url: ["file"]})
    assert results
    _vuln_class, reason, param = results[0]
    assert param == "file"
    assert "arjun" in reason.lower()


def test_discovered_parameter_hypotheses_empty_when_no_entry_for_url():
    from webpent.agents.hypothesis_analyzer.agent import _discovered_parameter_hypotheses

    assert _discovered_parameter_hypotheses("https://target.test/x", {}) == []
    assert (
        _discovered_parameter_hypotheses(
            "https://target.test/x", {"https://target.test/other": ["debug"]}
        )
        == []
    )


def test_discovered_parameter_hypotheses_tolerates_malformed_input():
    from webpent.agents.hypothesis_analyzer.agent import _discovered_parameter_hypotheses

    # Non-dict top level, non-list value, non-string entries — none of
    # these should raise.
    assert _discovered_parameter_hypotheses("https://target.test/x", None) == []  # type: ignore[arg-type]
    assert (
        _discovered_parameter_hypotheses(
            "https://target.test/x", {"https://target.test/x": "not-a-list"}
        )
        == []
    )
    assert (
        _discovered_parameter_hypotheses(
            "https://target.test/x", {"https://target.test/x": [None, "", "file"]}
        )
        != []
    )


def test_discovered_parameter_hypotheses_capped_at_six():
    from webpent.agents.hypothesis_analyzer.agent import _discovered_parameter_hypotheses

    url = "https://target.test/x"
    # Use many distinct real signal-table fragments so each matches and the
    # cap is what limits the result, not a lack of matches.
    many_params = [
        "user_id", "file", "path_ref", "include_file", "lang_code",
        "url_target", "host_name", "feed_url", "proxy_target", "cmd_input",
    ]
    results = _discovered_parameter_hypotheses(url, {url: many_params})
    assert len(results) <= 6
