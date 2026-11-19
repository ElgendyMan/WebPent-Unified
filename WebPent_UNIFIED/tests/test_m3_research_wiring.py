# tests/test_m3_research_wiring.py
"""M3 acceptance (UM-DR-16) — research-brain wiring + hypothesis contract.

Covers the CANONICAL_PHASE_REGISTRY M3 scope items delivered this window:

* ق6 — the offline CVE/KEV/EPSS advisory engine feeds n-day-exposure
  hypotheses into ``target_understanding``'s hypotheses channel
  (flag-gated fail-closed, fail-soft, provenance-preserved, deduped,
  never auto-confirmed);
* ق8 — the api-surface-shadow engine derives hypotheses from the JS
  intelligence pass (same observations, no second fetch) and projects
  ``shadow_endpoints`` for the planner's replan passes;
* the M3 hypothesis-record contract fields (preconditions, alternatives,
  expected_behavior, negative_control, info_gain, risk) are additive and
  checkpoint-safe;
* the Charter §4.1 gate — an LLM hypothesis path may expand budget ONLY
  on a current, qualified measurement (recall ≥ 0.5 AND precision ≥ 0.7
  AND above the deterministic 0.137 baseline AND ≥ 30 samples); the
  gate fails closed on None/stale/unqualified verdicts.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from webpent.models.hypothesis import Hypothesis
from webpent.shared.cve_advisory import (
    advisory_for_target_state,
    advisory_hypothesis_to_state_hypothesis,
)
from types import SimpleNamespace

FEED = [
    {
        "cve_id": "CVE-2024-0001",
        "product": "apache_httpd",
        "version_lte": "2.4.49",
        "severity": "critical",
        "kev": True,
        "source": "nvd",
    },
]
EPSS = [{"cve_id": "CVE-2024-0001", "epss": 0.94, "percentile": 0.99}]


def _target():
    from webpent.models.targets import Target

    return Target(url="http://lab.local")


def _tu_flags(monkeypatch, *, enable_cve_advisory_hypotheses: bool):
    """Point the target-understanding node's settings at a probe namespace."""
    import webpent.agents.target_understanding.agent as tu_agent

    monkeypatch.setattr(
        tu_agent,
        "get_settings",
        lambda: SimpleNamespace(enable_cve_advisory_hypotheses=enable_cve_advisory_hypotheses),
    )


def _js_flags(monkeypatch, *, enable_api_surface_shadow_hypotheses: bool):
    """Point the JS intelligence node's settings at a probe namespace."""
    import webpent.agents.javascript_intelligence.agent as js_agent

    monkeypatch.setattr(
        js_agent,
        "get_settings",
        lambda: SimpleNamespace(
            enable_js_intelligence=True,
            enable_api_surface_shadow_hypotheses=enable_api_surface_shadow_hypotheses,
            max_js_assets=10,
            max_js_asset_bytes=2_000_000,
            max_js_targeted_tasks=10,
            http_timeout=5.0,
            enable_surface_security_analysis=False,
        ),
    )


def _state() -> dict:
    return {
        "target": _target(),
        "crawled_data": {
            "endpoints": ["http://lab.local/checkout"],
            "response_headers": {"Server": "Apache/2.4.49 (Unix)"},
            "response_body": "<html>powered by Apache</html>",
        },
        "cve_feed": FEED,
        "epss_catalog": EPSS,
    }


# ---------------------------------------------------------------------------
# ق6 — cve_advisory → target_understanding
# ---------------------------------------------------------------------------


def test_cve_advisory_adapter_reads_dict_states():
    advisory = advisory_for_target_state(_state())
    assert advisory, "the adapter must find the Apache evidence in a dict state"
    assert advisory.hypotheses, "an affected version + KEV feed must yield guidance"
    guidance = advisory.hypotheses[0]
    assert guidance.cve_id == "CVE-2024-0001"
    assert guidance.advisory_only is True and guidance.does_not_confirm is True


def test_cve_advisory_conversion_is_provenance_preserving_and_pinned():
    advisory = advisory_for_target_state(_state())
    hypothesis = advisory_hypothesis_to_state_hypothesis(
        advisory.hypotheses[0], target_url="http://lab.local"
    )
    assert isinstance(hypothesis, Hypothesis)
    assert hypothesis.hint_provenance == [f"cve_advisory:{advisory.hypotheses[0].guidance_id}"]
    assert hypothesis.origin_detail.startswith("cve_advisory:")
    assert hypothesis.evidence_contract["advisory_only"] is True
    assert hypothesis.evidence_contract["does_not_confirm"] is True
    assert hypothesis.preconditions, "the version detection must be a named precondition"
    assert hypothesis.expected_behavior, "n-day guidance names the expected probe result"
    assert hypothesis.negative_control == "" or isinstance(hypothesis.negative_control, str)


def test_target_understanding_q6_flag_off_is_structurally_absent(monkeypatch):
    from webpent.agents.target_understanding.agent import target_understanding_node

    _tu_flags(monkeypatch, enable_cve_advisory_hypotheses=False)
    result = target_understanding_node(_state())  # type: ignore[arg-type]
    advisory_hypotheses = [
        h
        for h in result.get("hypotheses") or []
        if "cve_advisory" in str(getattr(h, "origin_detail", ""))
        or (isinstance(h, dict) and "cve_advisory" in str(h.get("origin_detail", "")))
    ]
    assert advisory_hypotheses == [], "flag off: no advisory hypotheses may appear"


def test_target_understanding_q6_flag_on_merges_advisory_hypotheses(monkeypatch):
    from webpent.agents.target_understanding.agent import target_understanding_node

    _tu_flags(monkeypatch, enable_cve_advisory_hypotheses=True)
    result = target_understanding_node(_state())  # type: ignore[arg-type]
    hypotheses = result.get("hypotheses") or []
    advisory = [
        h for h in hypotheses if "cve_advisory:" in str(getattr(h, "origin_detail", ""))
    ]
    assert advisory, "flag on + affected stack: the advisory hypothesis must merge"
    merged = advisory[0]
    assert merged.evidence_contract["advisory_only"] is True
    assert merged.status == "unexplored"
    # the advisory record is a Hypothesis in the SAME channel the kernel
    # hypotheses use (the minimal fixture may yield zero kernel records)
    assert all(isinstance(h, Hypothesis) for h in hypotheses)


def test_target_understanding_q6_dedupes_on_rerun(monkeypatch):
    from webpent.agents.target_understanding.agent import target_understanding_node

    state = _state()
    _tu_flags(monkeypatch, enable_cve_advisory_hypotheses=True)
    first = target_understanding_node(state)  # type: ignore[arg-type]
    state["hypotheses"] = list(first.get("hypotheses") or [])
    second = target_understanding_node(state)  # type: ignore[arg-type]
    tags_first = sorted(
        str(getattr(h, "origin_detail", ""))
        for h in first.get("hypotheses") or []
        if "cve_advisory:" in str(getattr(h, "origin_detail", ""))
    )
    tags_second = sorted(
        str(getattr(h, "origin_detail", ""))
        for h in second.get("hypotheses") or []
        if "cve_advisory:" in str(getattr(h, "origin_detail", ""))
    )
    assert tags_first == tags_second, "a rerun must not duplicate advisory hypotheses"


def test_target_understanding_q6_is_fail_soft_on_garbage(monkeypatch):
    from webpent.agents.target_understanding.agent import target_understanding_node

    state = _state()
    state["cve_feed"] = [{"not": "a feed entry"}, 42, None]
    state["response_headers"] = {"Server": "\x00garbage"}
    _tu_flags(monkeypatch, enable_cve_advisory_hypotheses=True)
    result = target_understanding_node(state)  # type: ignore[arg-type]
    assert result["current_phase"] == "target_understanding"
    assert "hypotheses" in result


# ---------------------------------------------------------------------------
# ق8 — api_surface_shadow → hypotheses + crawled_data projection
# ---------------------------------------------------------------------------


def _js_state() -> dict:
    return {
        "target": _target(),
        "crawled_data": {
            "endpoints": [
                "http://lab.local/api/v1/known",
                {"url": "http://lab.local/static/app.js"},
            ],
        },
    }


BUNDLE_JS = (
    'fetch("/api/v2/admin/users", {method: "POST"});\n'
    'const legacy = "/api/v1/known";\n'
    'var cfg = {apiKey: "sk-live-probe-value-123"};\n'
)


def _patch_js_fetch(monkeypatch):
    """Serve one synthetic bundle through the node's safe client path.

    The node imports the factory INSIDE the function from
    ``webpent.shared.http``, so the patch goes on that module
    (monkeypatch restores it after the test).
    """
    import httpx

    import webpent.shared.http as http_module

    def fake_make_safe_httpx_client(**kwargs):
        transport = httpx.MockTransport(
            lambda request: httpx.Response(
                200,
                content=BUNDLE_JS.encode(),
                headers={"content-type": "application/javascript"},
            )
        )
        return httpx.Client(
            transport=transport,
            **{k: v for k, v in kwargs.items() if k in {"timeout", "follow_redirects"}},
        )

    monkeypatch.setattr(
        http_module, "make_safe_httpx_client", fake_make_safe_httpx_client
    )


def test_js_intelligence_q8_flag_on_yields_shadow_hypotheses(monkeypatch):
    from webpent.agents.javascript_intelligence.agent import javascript_intelligence_node

    _patch_js_fetch(monkeypatch)
    state = _js_state()
    _js_flags(monkeypatch, enable_api_surface_shadow_hypotheses=True)
    result = javascript_intelligence_node(state)  # type: ignore[arg-type]
    hypotheses = result.get("hypotheses") or []
    shadow = [
        h
        for h in hypotheses
        if "api_surface_shadow:" in str(getattr(h, "origin_detail", ""))
    ]
    assert shadow, "flag on: the JS-referenced endpoint must yield a shadow hypothesis"
    undocumented = [
        h
        for h in shadow
        if h.evidence_contract.get("hypothesis_kind") == "undocumented_api_endpoint"
    ]
    assert undocumented, "the JS-only path is undocumented by the crawl"
    assert undocumented[0].negative_control, (
        "the undocumented-endpoint hypothesis carries its negative control"
    )
    assert result["crawled_data"]["shadow_endpoints"], (
        "the projection the planner reads must be present"
    )


def test_js_intelligence_q8_flag_off_is_structurally_absent(monkeypatch):
    from webpent.agents.javascript_intelligence.agent import javascript_intelligence_node

    _patch_js_fetch(monkeypatch)
    state = _js_state()
    _js_flags(monkeypatch, enable_api_surface_shadow_hypotheses=False)
    result = javascript_intelligence_node(state)  # type: ignore[arg-type]
    assert "hypotheses" not in result
    assert "shadow_endpoints" not in (result.get("crawled_data") or {})


# ---------------------------------------------------------------------------
# Hypothesis record contract — additive fields
# ---------------------------------------------------------------------------


def test_hypothesis_m3_fields_default_and_roundtrip():
    legacy = Hypothesis(target_url="https://lab.example", statement="legacy constructor")
    assert legacy.preconditions == [] and legacy.info_gain is None

    full = Hypothesis(
        target_url="https://lab.example",
        statement="full research record",
        preconditions=["endpoint accepts POST"],
        alternatives=["cache poisoning", "WAF interference"],
        expected_behavior="403 for role B, 200 for role A",
        negative_control="randomized path returns the same 403",
        info_gain=0.8,
        risk=0.3,
    )
    dumped = full.model_dump(mode="json")
    assert Hypothesis.model_validate(dumped) == full


# ---------------------------------------------------------------------------
# Charter §4.1 gate
# ---------------------------------------------------------------------------


def _ground_truth(vulnerable_ids: set[str], clean_ids: set[str]) -> dict[str, bool]:
    truth = {case_id: True for case_id in vulnerable_ids}
    truth.update({case_id: False for case_id in clean_ids})
    return truth


def test_charter_refuses_never_measured():
    from webpent.production.hypothesis_charter import charter_allows_budget_expansion

    allowed, reason = charter_allows_budget_expansion(None)
    assert allowed is False and "no_measurement" in reason


def test_charter_refuses_below_thresholds():
    from webpent.production.hypothesis_charter import (
        charter_allows_budget_expansion,
        evaluate_hypothesis_qualification,
    )

    truth = _ground_truth({f"v{i}" for i in range(60)}, {f"c{i}" for i in range(40)})
    # recall 0.5 - boundary: 29/60 hits → below 0.5
    verdict = evaluate_hypothesis_qualification(
        producer="llm-probe",
        corpus_id="test-corpus",
        predicted={f"v{i}" for i in range(29)} | {f"c{i}" for i in range(3)},
        ground_truth=truth,
    )
    assert verdict.qualified is False
    allowed, reason = charter_allows_budget_expansion(verdict)
    assert allowed is False and "recall_below_threshold" in reason


def test_charter_refuses_below_deterministic_baseline():
    from webpent.production.hypothesis_charter import (
        charter_allows_budget_expansion,
        evaluate_hypothesis_qualification,
    )

    truth = _ground_truth({f"v{i}" for i in range(10)}, {f"c{i}" for i in range(60)})
    verdict = evaluate_hypothesis_qualification(
        producer="llm-probe",
        corpus_id="test-corpus",
        predicted={f"v{i}" for i in range(1)},  # recall 0.1 <= 0.137 baseline
        ground_truth=truth,
    )
    # the baseline reason is recorded on the VERDICT (subsumed by the recall
    # threshold in the budget refusal, but always recorded for the audit)
    assert any("deterministic_baseline" in r for r in verdict.reasons)
    allowed, reason = charter_allows_budget_expansion(verdict)
    assert allowed is False and "unqualified" in reason


def test_charter_refuses_tiny_sample():
    from webpent.production.hypothesis_charter import (
        charter_allows_budget_expansion,
        evaluate_hypothesis_qualification,
    )

    verdict = evaluate_hypothesis_qualification(
        producer="llm-probe",
        corpus_id="handful",
        predicted={"v1", "v2", "v3", "v4", "v5"},
        ground_truth=_ground_truth({f"v{i}" for i in range(5)}, {f"c{i}" for i in range(5)}),
    )
    allowed, reason = charter_allows_budget_expansion(verdict)
    assert allowed is False and "sample_size_below_minimum" in reason


def test_charter_allows_qualified_measurement():
    from webpent.production.hypothesis_charter import (
        charter_allows_budget_expansion,
        evaluate_hypothesis_qualification,
    )

    truth = _ground_truth({f"v{i}" for i in range(60)}, {f"c{i}" for i in range(40)})
    verdict = evaluate_hypothesis_qualification(
        producer="llm-probe",
        corpus_id="test-corpus",
        predicted={f"v{i}" for i in range(33)} | {f"c{i}" for i in range(9)},
        ground_truth=truth,
    )
    # recall 33/60 = 0.55 ≥ 0.5; precision 33/42 ≈ 0.786 ≥ 0.7
    assert verdict.qualified is True, verdict.reasons
    allowed, reason = charter_allows_budget_expansion(verdict)
    assert allowed is True, reason


def test_charter_refuses_stale_measurement():
    from webpent.production.hypothesis_charter import (
        charter_allows_budget_expansion,
        evaluate_hypothesis_qualification,
    )

    truth = _ground_truth({f"v{i}" for i in range(60)}, {f"c{i}" for i in range(40)})
    verdict = evaluate_hypothesis_qualification(
        producer="llm-probe",
        corpus_id="test-corpus",
        predicted={f"v{i}" for i in range(33)},
        ground_truth=truth,
        measured_at=datetime.now(timezone.utc) - timedelta(days=30),
    )
    allowed, reason = charter_allows_budget_expansion(verdict)
    assert allowed is False and "stale_measurement" in reason
