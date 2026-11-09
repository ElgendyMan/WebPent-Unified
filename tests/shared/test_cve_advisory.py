"""FEATURE_PROPOSALS ق6 — CVE/KEV/EPSS advisory engine.

Pins:
  * build_cve_advisory() is the ONE pass the proposal asks for:
    fingerprint → correlate → KEV merge → EPSS enrich → KEV/EPSS-first
    sort → hypothesis guidance, all offline over operator-injected
    catalogs,
  * output is advisory guidance ONLY: every emitted object pins
    advisory_only/does_not_confirm and no field can hold target-
    identifying data (product names / CVE ids / scores only),
  * campaign-state catalogs win over settings-file catalogs; a missing
    layer degrades to a coverage gap, never an exception,
  * priorities are deterministic (KEV > EPSS > severity > version
    match, scaled by fingerprint confidence) and identical inputs give
    identical guidance_ids,
  * empty tech evidence ⇒ empty advisory, falsy, with coverage gaps.
"""

from __future__ import annotations

import json
from types import SimpleNamespace

from webpent.shared.cve_advisory import (
    AdvisoryHypothesis,
    CveAdvisory,
    advisory_for_target_state,
    build_cve_advisory,
    load_cve_feed,
    load_kev_ids,
)

FEED = [
    {
        "cve_id": "CVE-2024-0001",
        "product": "apache_httpd",
        "version_lte": "2.4.49",
        "severity": "critical",
        "kev": True,
        "source": "nvd",
    },
    {
        "cve_id": "CVE-2024-0002",
        "product": "apache_httpd",
        "version_lte": "2.4.49",
        "severity": "high",
    },
    {
        "cve_id": "CVE-2024-0003",
        "product": "express",
        "severity": "medium",
    },
]
EPSS = [
    {"cve_id": "CVE-2024-0002", "epss": 0.94, "percentile": 0.99},
    {"cve_id": "CVE-2024-0003", "epss": 0.10},
]
KEV = ["cve-2024-0003"]

HEADERS = {"Server": "Apache/2.4.49", "X-Powered-By": "Express"}


# ---------------------------------------------------------------------------
# load_cve_feed / load_kev_ids
# ---------------------------------------------------------------------------


def test_load_cve_feed_state_wins_over_file(tmp_path, monkeypatch) -> None:
    state_feed = [
        {"cve_id": "CVE-2024-0009", "product": "nginx", "version_lte": "1.2.3"}
    ]
    loaded = load_cve_feed(state_feed)
    assert len(loaded) == 1
    assert loaded[0].cve_id == "CVE-2024-0009"
    assert loaded[0].source == "injected_catalog"


def test_load_cve_feed_from_operator_file(tmp_path, monkeypatch) -> None:
    feed_file = tmp_path / "feed.json"
    feed_file.write_text(json.dumps(FEED), encoding="utf-8")
    monkeypatch.setattr(
        "webpent.config.settings.get_settings",
        lambda: SimpleNamespace(cve_feed_catalog_path=str(feed_file)),
    )
    loaded = load_cve_feed(None)
    assert [e.cve_id for e in loaded] == [
        "CVE-2024-0001",
        "CVE-2024-0002",
        "CVE-2024-0003",
    ]


def test_load_cve_feed_unreadable_file_fails_soft(tmp_path, monkeypatch) -> None:
    feed_file = tmp_path / "broken.json"
    feed_file.write_text("{not json", encoding="utf-8")
    monkeypatch.setattr(
        "webpent.config.settings.get_settings",
        lambda: SimpleNamespace(cve_feed_catalog_path=str(feed_file)),
    )
    assert load_cve_feed(None) == []


def test_load_cve_feed_drops_unusable_entries() -> None:
    loaded = load_cve_feed([{"product": "nginx"}, {"cve_id": "CVE-1", "product": "x"}])
    assert len(loaded) == 1
    assert loaded[0].cve_id == "CVE-1"


def test_load_kev_ids_normalizes_and_accepts_both_shapes() -> None:
    ids = load_kev_ids(["cve-2024-0003", {"cve_id": "CVE-2024-0004"}, "not-a-cve"])
    assert ids == {"CVE-2024-0003", "CVE-2024-0004"}


# ---------------------------------------------------------------------------
# build_cve_advisory — the combined pass
# ---------------------------------------------------------------------------


def test_combined_pass_enriches_sorts_and_emits_guidance() -> None:
    advisory = build_cve_advisory(
        headers=HEADERS,
        cve_feed=FEED,
        epss_records=EPSS,
        kev_ids=KEV,
    )
    assert advisory  # non-empty
    # three correlations for apache (2) + express (1)
    assert advisory.stats["correlations"] == 3
    # KEV catalog flagged CVE-2024-0003 whose feed entry lacked the flag
    kev_ids = {c["cve_id"] for c in advisory.correlations if c["kev"]}
    assert kev_ids == {"CVE-2024-0001", "CVE-2024-0003"}
    # EPSS enrichment landed
    epss_by_cve = {c["cve_id"]: c["epss"] for c in advisory.correlations}
    assert epss_by_cve["CVE-2024-0002"] == 0.94
    assert epss_by_cve["CVE-2024-0001"] is None
    # every correlation keeps the advisory posture
    assert all(c["advisory_only"] and c["does_not_confirm"] for c in advisory.correlations)
    # guidance bounded to correlations, sorted by priority desc
    assert advisory.stats["hypotheses"] == 3
    priorities = [h.priority for h in advisory.hypotheses]
    assert priorities == sorted(priorities, reverse=True)
    assert all(h.advisory_only and h.does_not_confirm for h in advisory.hypotheses)


def test_kev_and_epss_dominate_priority_order() -> None:
    # One fingerprint (equal confidence) + three feed entries that differ
    # ONLY in their dominant factor, to pin the ordering: KEV > EPSS-high
    # > baseline (same version match, no severity anywhere).
    feed = [
        {"cve_id": "CVE-2024-000A", "product": "apache_httpd", "version_lte": "2.4.49", "kev": True},
        {"cve_id": "CVE-2024-000B", "product": "apache_httpd", "version_lte": "2.4.49"},
        {"cve_id": "CVE-2024-000C", "product": "apache_httpd", "version_lte": "2.4.49"},
    ]
    epss = [{"cve_id": "CVE-2024-000B", "epss": 0.94}]
    advisory = build_cve_advisory(
        headers={"Server": "Apache/2.4.49"}, cve_feed=feed, epss_records=epss
    )
    by_cve = {h.cve_id: h for h in advisory.hypotheses}
    assert by_cve["CVE-2024-000A"].priority > by_cve["CVE-2024-000B"].priority
    assert by_cve["CVE-2024-000B"].priority > by_cve["CVE-2024-000C"].priority
    assert by_cve["CVE-2024-000A"].kev is True
    assert by_cve["CVE-2024-000B"].epss == 0.94


def test_version_newer_than_bound_produces_no_correlation() -> None:
    advisory = build_cve_advisory(
        headers={"Server": "Apache/2.4.50"},
        cve_feed=FEED,
        epss_records=EPSS,
        kev_ids=KEV,
    )
    assert advisory.stats["correlations"] == 0
    assert advisory.hypotheses == []
    assert advisory.coverage_gaps == []  # evidence+feed existed; simply no match


def test_missing_layers_record_coverage_gaps_not_exceptions() -> None:
    advisory = build_cve_advisory(headers={"Server": "Apache/2.4.49"})
    assert not advisory
    assert advisory.coverage_gaps == ["no_cve_feed", "no_epss_catalog"]
    assert advisory.stats["components_fingerprinted"] == 1


def test_no_tech_evidence_yields_falsy_empty_advisory() -> None:
    advisory = build_cve_advisory(cve_feed=FEED, epss_records=EPSS, kev_ids=KEV)
    assert not advisory
    assert advisory.coverage_gaps == ["no_tech_evidence"]
    assert advisory.stats["correlations"] == 0


def test_identical_inputs_yield_identical_guidance_ids() -> None:
    first = build_cve_advisory(headers=HEADERS, cve_feed=FEED, epss_records=EPSS)
    second = build_cve_advisory(headers=HEADERS, cve_feed=FEED, epss_records=EPSS)
    assert [h.guidance_id for h in first.hypotheses] == [
        h.guidance_id for h in second.hypotheses
    ]
    assert all(h.guidance_id.startswith("cveadv-") for h in first.hypotheses)


def test_guidance_titles_and_rationales_carry_aggregates_only() -> None:
    advisory = build_cve_advisory(headers=HEADERS, cve_feed=FEED, epss_records=EPSS)
    for hypothesis in advisory.hypotheses:
        assert isinstance(hypothesis, AdvisoryHypothesis)
        assert "advisory" in hypothesis.title.lower()
        assert hypothesis.rationale.endswith("verify before any report.")
        # no URL/host-shaped material can leak through title/rationale
        for text in (hypothesis.title, hypothesis.rationale):
            assert "http://" not in text and "https://" not in text


def test_advisory_as_dict_round_trip_is_json_serialisable() -> None:
    advisory = build_cve_advisory(
        headers=HEADERS, cve_feed=FEED, epss_records=EPSS, kev_ids=KEV
    )
    payload = advisory.as_dict()
    encoded = json.dumps(payload)  # must not raise
    assert isinstance(encoded, str)
    assert payload["advisory_only"] is True
    assert payload["does_not_confirm"] is True
    assert payload["source"] == "operator-injected-catalogs"
    assert len(payload["hypotheses"]) == len(advisory.hypotheses)


def test_hypothesis_is_frozen_dataclass() -> None:
    advisory = build_cve_advisory(headers=HEADERS, cve_feed=FEED)
    hypothesis = advisory.hypotheses[0]
    try:
        hypothesis.priority = 0.99  # type: ignore[misc]
    except AttributeError:
        pass
    else:
        raise AssertionError("AdvisoryHypothesis must be frozen")


def test_cve_advisory_default_constructible() -> None:
    empty = CveAdvisory()
    assert not empty
    assert empty.as_dict()["hypotheses"] == []


# ---------------------------------------------------------------------------
# advisory_for_target_state — the stage wiring adapter
# ---------------------------------------------------------------------------


def test_adapter_extracts_header_evidence_defensively() -> None:
    state = SimpleNamespace(
        response_headers={"Server": "Apache/2.4.49", "X-Powered-By": "Express"},
        response_body="<html>login page</html>",
        cookie_names=["session", "csrftoken"],
        cve_feed=FEED,
        epss_catalog=EPSS,
        kev_catalog=KEV,
    )
    advisory = advisory_for_target_state(state)
    assert advisory.stats["components_fingerprinted"] == 2
    assert advisory.stats["correlations"] == 3


def test_adapter_derives_cookie_names_from_set_cookie_header() -> None:
    state = SimpleNamespace(
        response_headers={"Set-Cookie": "PHPSESSID=abc123; Path=/; HttpOnly"},
        cve_feed=FEED,
    )
    advisory = advisory_for_target_state(state)
    assert advisory.stats["components_fingerprinted"] == 1  # php cookie fingerprint


def test_adapter_on_empty_state_fails_soft() -> None:
    advisory = advisory_for_target_state(SimpleNamespace())
    assert not advisory
    assert set(advisory.coverage_gaps) == {
        "no_tech_evidence",
        "no_cve_feed",
        "no_epss_catalog",
    }
