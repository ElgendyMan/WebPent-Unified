# tests/test_dom_xss.py
"""PROPOSALS_ULTIMATE_V2 §2 (2026-10-29) test suite: DOM XSS static taint.

Fixture-driven, all deterministic, no network and no browser required for
the analysis half. The browser-confirmation half is tested at the probe
contract level: the three EphemeralProbes, distinct negative control, and
the causal predicate's positive/negative behaviour — the replay itself
remains browser_proof_runner's job (per the §2 spec: reuse, don't re-write).
"""

from __future__ import annotations

import pytest

from webpent.agents.dom_xss import (
    AstBudgetExceeded,
    DomXssAnalyzer,
    build_browser_probes,
    dom_xss_causal_predicate,
    find_taint_flows,
    parse_script,
)
from webpent.agents.dom_xss import payloads


class _FakeSettings:
    def __init__(self, *, enable: bool = True, max_nodes: int = 50_000) -> None:
        self.enable_dom_xss = enable
        self.dom_xss_max_ast_nodes = max_nodes


def _flows(js: str, **kwargs) -> list:
    parsed = parse_script(js, max_nodes=kwargs.pop("max_nodes", 50_000))
    return find_taint_flows(parsed.tree, **kwargs)


def _flow_keys(js: str, **kwargs) -> set[tuple[str, str, str]]:
    return {(f.source, f.sink, f.function) for f in _flows(js, **kwargs)}


class TestConfirmedFlows:
    def test_hash_to_innerhtml_via_getelementbyid(self) -> None:
        # THE fixture flow the proposal's success criterion names. The
        # sink string keeps the element for operator context ("el"), so
        # match on the property.
        js = 'var el = document.getElementById("out");\nel.innerHTML = location.hash;'
        assert any(
            src == "location.hash" and sink.endswith("innerHTML") and fn == "<script>"
            for src, sink, fn in _flow_keys(js)
        )

    def test_hash_to_innerhtml_chained_call(self) -> None:
        js = 'document.getElementById("out").innerHTML = location.hash;'
        assert ("location.hash", "innerHTML", "<script>") in _flow_keys(js)

    def test_search_to_document_write(self) -> None:
        js = "document.write(location.search);"
        assert ("location.search", "document.write", "<script>") in _flow_keys(js)

    def test_sink_inside_if_block_is_found(self) -> None:
        # A sink buried in a conditional is still reachable — the walk
        # must descend into ifs/loops/try blocks, not just top level.
        js = (
            "var v = location.hash;\n"
            "if (v.length > 3) {\n"
            "  document.getElementById('out').innerHTML = v;\n"
            "}\n"
        )
        assert ("location.hash", "innerHTML", "<script>") in _flow_keys(js)

    def test_sink_inside_try_block_is_found(self) -> None:
        js = (
            "try {\n"
            "  eval(location.search);\n"
            "} catch (e) {}\n"
        )
        assert ("location.search", "eval", "<script>") in _flow_keys(js)

    def test_sink_inside_loop_is_found(self) -> None:
        js = (
            "var parts = location.hash.split(',');\n"
            "for (var i = 0; i < parts.length; i++) {\n"
            "  document.write(parts[i]);\n"
            "}\n"
        )
        assert any(sink == "document.write" for _src, sink, _fn in _flow_keys(js))

    def test_hash_through_variable_to_eval(self) -> None:
        js = "var h = location.hash;\nwindow.setTimeout(function(){ eval(h); }, 10);"
        keys = _flow_keys(js)
        assert any(k[0] == "location.hash" and k[1] == "eval" for k in keys)

    def test_hash_to_location_href_navigation(self) -> None:
        js = "location.href = location.hash;"
        assert ("location.hash", "location.href", "<script>") in _flow_keys(js)

    def test_referrer_to_innerhtml(self) -> None:
        js = 'document.getElementById("r").innerHTML = document.referrer;'
        assert ("document.referrer", "innerHTML", "<script>") in _flow_keys(js)

    def test_localstorage_getitem_to_innerhtml(self) -> None:
        js = 'el.innerHTML = localStorage.getItem("cfg");'
        assert any(src == "localStorage.getItem" and sink.endswith("innerHTML") for src, sink, _ in _flow_keys(js))

    def test_postmessage_data_to_innerhtml(self) -> None:
        js = (
            'window.addEventListener("message", function(ev){ '
            'document.getElementById("x").innerHTML = ev.data; });'
        )
        assert ("postMessage.data", "innerHTML", "<script>") in _flow_keys(js)

    def test_jquery_html_sink(self) -> None:
        js = '$("#out").html(location.hash);'
        assert ("location.hash", "html", "<script>") in _flow_keys(js)

    def test_interprocedural_flow_through_named_function(self) -> None:
        js = (
            "function render(name) { document.getElementById('o').innerHTML = name; }\n"
            "render(location.hash);"
        )
        keys = _flow_keys(js)
        assert ("location.hash", "innerHTML", "render()") in keys
        flows = _flows(js)
        assert any(f.function == "render()" and f.depth >= 1 for f in flows)

    def test_interprocedural_depth_three(self) -> None:
        js = (
            "function a(p) { b(p); }\n"
            "function b(p) { c(p); }\n"
            "function c(p) { document.getElementById('o').innerHTML = p; }\n"
            "a(location.hash);"
        )
        flows = [f for f in _flows(js, max_depth=3) if f.function == "c()"]
        assert flows and flows[0].depth == 3

    def test_depth_four_is_refused_by_default(self) -> None:
        js = (
            "function a(p) { b(p); }\n"
            "function b(p) { c(p); }\n"
            "function c(p) { d(p); }\n"
            "function d(p) { document.getElementById('o').innerHTML = p; }\n"
            "a(location.hash);"
        )
        assert not any(f.function == "d()" for f in _flows(js, max_depth=3))


class TestNegativeCases:
    def test_sink_without_source_is_nothing(self) -> None:
        js = 'document.getElementById("o").innerHTML = "static text";'
        assert _flow_keys(js) == set()

    def test_source_without_sink_is_nothing(self) -> None:
        js = "var q = location.hash;"
        assert _flow_keys(js) == set()

    def test_sanitized_sink_is_nothing(self) -> None:
        js = "el.innerHTML = encodeURIComponent(location.hash);"
        assert _flow_keys(js) == set()

    def test_dompurify_sanitized_sink_is_nothing(self) -> None:
        js = "el.innerHTML = DOMPurify.sanitize(location.hash);"
        assert _flow_keys(js) == set()

    def test_sanitizer_breaks_var_propagation(self) -> None:
        js = "var h = encodeURIComponent(location.hash);\nel.innerHTML = h;"
        assert _flow_keys(js) == set()

    def test_out_of_depth_interprocedural_is_nothing(self) -> None:
        js = (
            "function a(p) { b(p); }\n"
            "function b(p) { document.getElementById('o').innerHTML = p; }\n"
            "a(location.hash);"
        )
        assert not any(f.function == "b()" for f in _flows(js, max_depth=0))


class TestAstBudget:
    def test_budget_exceeded_fail_closed(self) -> None:
        js = "var a = 1;" * 3
        with pytest.raises(AstBudgetExceeded):
            parse_script(js, max_nodes=1)

    def test_parse_error_raises_syntax_error(self) -> None:
        with pytest.raises(SyntaxError):
            parse_script("var var var ;;;", max_nodes=50_000)

    def test_minified_bundle_still_parses(self) -> None:
        js = "var h=location.hash;document.getElementById('o').innerHTML=h;"
        assert ("location.hash", "innerHTML", "<script>") in _flow_keys(js)


class TestAgentGateAndReport:
    def test_disabled_by_default_flag(self) -> None:
        analyzer = DomXssAnalyzer(_FakeSettings(enable=False))
        report = analyzer.analyze("el.innerHTML = location.hash;")
        assert report.skipped == "disabled"
        assert report.candidates == ()

    def test_enabled_finds_fixture_flow(self) -> None:
        analyzer = DomXssAnalyzer(_FakeSettings(enable=True))
        report = analyzer.analyze(
            'var h = location.hash;\ndocument.getElementById("o").innerHTML = h;'
        )
        assert report.skipped == ""
        assert len(report.candidates) == 1
        cand = report.candidates[0]
        assert cand.source == "location.hash"
        assert cand.sink_kind == "html"
        assert cand.probe_fragment.startswith("#")
        assert payloads.marker_for(cand.probe_id) in cand.payload

    def test_ast_budget_skip_is_reported_not_raised(self) -> None:
        analyzer = DomXssAnalyzer(_FakeSettings(enable=True, max_nodes=1))
        report = analyzer.analyze("el.innerHTML = location.hash;")
        assert report.skipped == "ast_budget_exceeded"

    def test_parse_error_skip(self) -> None:
        analyzer = DomXssAnalyzer(_FakeSettings(enable=True))
        report = analyzer.analyze("%%%not js%%%")
        assert report.skipped == "parse_error"

    def test_non_url_addressable_source_is_not_probed(self) -> None:
        analyzer = DomXssAnalyzer(_FakeSettings(enable=True))
        report = analyzer.analyze(
            'el.innerHTML = localStorage.getItem("k");'
        )
        assert report.candidates == ()  # real flow, but no silent URL probe


class TestPayloads:
    def test_marker_present_and_deterministic(self) -> None:
        p1 = payloads.payload_for_sink("html", "dx-0")
        p2 = payloads.payload_for_sink("html", "dx-0")
        assert p1 == p2
        assert "webpent-dx-dx-0" in p1

    def test_navigation_payload_is_javascript_url(self) -> None:
        assert payloads.payload_for_sink("navigation", "dx-1").startswith("javascript:")

    def test_exec_payload_sets_window_flag(self) -> None:
        p = payloads.payload_for_sink("exec", "dx-2")
        assert payloads.WINDOW_FLAG in p and "webpent-dx-dx-2" in p

    def test_unknown_sink_kind_fails_closed(self) -> None:
        with pytest.raises(ValueError):
            payloads.payload_for_sink("mystery", "dx-3")

    def test_fragment_for_hash_and_search(self) -> None:
        assert payloads.probe_fragment_for_source("location.hash", "P").startswith("#")
        assert payloads.probe_fragment_for_source("location.search", "P").startswith("?")

    def test_fragment_for_storage_source_fails_closed(self) -> None:
        with pytest.raises(ValueError):
            payloads.probe_fragment_for_source("localStorage.getItem", "P")

    def test_negative_marker_is_distinct(self) -> None:
        assert payloads.negative_marker("dx-0") != payloads.marker_for("dx-0")

    def test_bypass_variants_are_deterministic(self) -> None:
        p = payloads.payload_for_sink("html", "dx-0")
        assert payloads.apply_basic_bypass(p, "none") == p
        assert "&quot;" in payloads.apply_basic_bypass(p, "html_entity_quotes")
        with pytest.raises(ValueError):
            payloads.apply_basic_bypass(p, "nope")


class TestBrowserProbeContract:
    """The §2 confirmation half: reuse browser_proof_runner, probe-side only."""

    def _candidate(self) -> object:
        analyzer = DomXssAnalyzer(_FakeSettings(enable=True))
        report = analyzer.analyze('el.innerHTML = location.hash;')
        assert len(report.candidates) == 1
        return report.candidates[0]

    def test_three_probes_with_distinct_negative_control(self) -> None:
        cand = self._candidate()
        bundle = build_browser_probes(cand)
        assert bundle["baseline"].role == "baseline"
        assert bundle["candidate"].role == "candidate"
        assert bundle["negative_control"].role == "negative_control"
        for probe in (bundle["baseline"], bundle["candidate"], bundle["negative_control"]):
            probe.validate(probe.role)
        values = bundle["probe_values"]
        assert values[bundle["candidate"].probe_ref].startswith("#")
        assert (
            values[bundle["negative_control"].probe_ref]
            != values[bundle["candidate"].probe_ref]
        )

    def test_predicate_passes_only_on_executed_marker(self) -> None:
        cand = self._candidate()
        bundle = build_browser_probes(cand)
        predicate = bundle["causal_predicate"]
        marker = payloads.marker_for(cand.probe_id)
        baseline, _candidate, negative = {}, {}, {}
        candidate_obs = {"dom_text": f"page {marker} page", "console": []}
        negative_obs = {"dom_text": "page clean page", "console": []}
        # candidate shows the marker, negative does not: causal pass
        assert predicate(baseline, candidate_obs, negative_obs) == (
            True,
            "dom_marker_executed_in_candidate_absent_in_negative_control",
        )
        # marker in BOTH: reflection, not causation
        assert predicate(baseline, candidate_obs, candidate_obs)[0] is False
        # marker nowhere: nothing proven
        assert predicate(baseline, negative_obs, negative_obs)[0] is False

    def test_predicate_marker_from_negative_never_passes(self) -> None:
        # A page that reflects ANY hash content must not pass: the
        # negative control carries a different marker and only the
        # candidate's marker satisfies the predicate.
        cand = self._candidate()
        predicate = build_browser_probes(cand)["causal_predicate"]
        negative_marker_text = payloads.negative_marker(cand.probe_id)
        assert predicate({}, {"dom_text": negative_marker_text}, {})[0] is False


class TestSettingsDefaults:
    def test_dom_xss_flags_default_off_and_bounded(self) -> None:
        from webpent.config.settings import Settings

        settings = Settings()
        assert settings.enable_dom_xss is False
        assert settings.dom_xss_max_ast_nodes == 50_000
