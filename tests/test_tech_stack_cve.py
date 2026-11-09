"""Project Zero-tier item 7 — CVE/version correlation.

Pins:
  * fingerprint_tech_stack() is a pure function: header-match-with-
    version is the strongest single signal, body/meta-tag markers are
    weaker, cookie-name matches are weakest alone but compound,
  * cookie fingerprinting matches NAME prefixes only, never a cookie
    value (mirrors waf_fingerprints.py's redaction stance),
  * correlate_cves() only matches feed entries for the SAME product
    (case-insensitive), respects the inclusive version_lte upper
    bound, excludes components whose detected version is strictly
    newer than a bounded entry, treats an unparseable version as
    "unknown" rather than a silent match, and always carries
    advisory_only/does_not_confirm — this is cross-reference evidence,
    never a confirmed finding,
  * KEV-flagged correlations sort first.
"""

from __future__ import annotations

from webpent.shared.tech_stack_cve import (
    CveFeedEntry,
    TechStackComponent,
    _version_lte,
    correlate_cves,
    fingerprint_tech_stack,
)

# ---------------------------------------------------------------------------
# fingerprint_tech_stack
# ---------------------------------------------------------------------------


def test_header_match_with_version_is_strongest_signal() -> None:
    comps = fingerprint_tech_stack(headers={"Server": "Apache/2.4.49"})
    assert len(comps) == 1
    assert comps[0].product == "apache_httpd"
    assert comps[0].version == "2.4.49"
    assert comps[0].confidence == 0.6


def test_header_match_without_version_is_weaker() -> None:
    comps = fingerprint_tech_stack(headers={"X-Powered-By": "Express"})
    assert len(comps) == 1
    assert comps[0].product == "express"
    assert comps[0].version is None
    assert comps[0].confidence == 0.4


def test_body_marker_match_with_version() -> None:
    comps = fingerprint_tech_stack(
        body='<meta name="generator" content="WordPress 6.2" />'
    )
    assert len(comps) == 1
    assert comps[0].product == "wordpress"
    assert comps[0].version == "6.2"
    assert comps[0].confidence == 0.35


def test_cookie_match_is_weak_alone() -> None:
    comps = fingerprint_tech_stack(
        set_cookie_headers=["PHPSESSID=deadbeef1234; Path=/; HttpOnly"]
    )
    assert len(comps) == 1
    assert comps[0].product == "php"
    assert comps[0].confidence == 0.25
    # The actual cookie value must never appear in signals.
    assert "deadbeef1234" not in str(comps[0].signals)


def test_cookie_corroborates_header_match_for_same_product() -> None:
    comps = fingerprint_tech_stack(
        headers={"X-Powered-By": "PHP/8.1.0"},
        set_cookie_headers=["PHPSESSID=abc"],
    )
    assert len(comps) == 1
    php = comps[0]
    assert php.product == "php"
    assert php.version == "8.1.0"
    # header (0.6) + cookie (0.25) compounds, capped at 1.0.
    assert php.confidence == 0.85


def test_no_signals_returns_empty_list() -> None:
    comps = fingerprint_tech_stack(headers={"Content-Type": "text/html"})
    assert comps == []


def test_results_sorted_by_descending_confidence() -> None:
    comps = fingerprint_tech_stack(
        headers={"Server": "nginx/1.18.0"},
        set_cookie_headers=["jsessionid=xyz"],
    )
    assert comps[0].confidence >= comps[-1].confidence


def test_malformed_version_in_header_does_not_crash() -> None:
    # Server header present with a trailing-slash-but-empty version
    # suffix should not raise, and should not fabricate a version.
    comps = fingerprint_tech_stack(headers={"Server": "nginx/"})
    assert comps == [] or comps[0].version is None


def test_bare_product_name_with_no_slash_does_not_match() -> None:
    # A bare "nginx" (no "/version", however malformed) is not a
    # reliable-enough signal under this pattern set and correctly
    # produces no component, rather than a low-confidence guess.
    comps = fingerprint_tech_stack(headers={"Server": "nginx"})
    assert comps == []


# ---------------------------------------------------------------------------
# _version_lte
# ---------------------------------------------------------------------------


def test_version_lte_basic_true() -> None:
    assert _version_lte("2.4.10", "2.4.49") is True


def test_version_lte_basic_false() -> None:
    assert _version_lte("2.4.50", "2.4.49") is False


def test_version_lte_equal_versions() -> None:
    assert _version_lte("2.4.49", "2.4.49") is True


def test_version_lte_differing_length() -> None:
    # 4.2 vs 4.2.1 should compare as 4.2.0 <= 4.2.1 -> True
    assert _version_lte("4.2", "4.2.1") is True
    # 4.2.1 vs 4.2 should compare as 4.2.1 <= 4.2.0 -> False
    assert _version_lte("4.2.1", "4.2") is False


def test_version_lte_strips_non_numeric_suffix() -> None:
    assert _version_lte("4.2.0-beta", "4.2.0") is True


def test_version_lte_unparseable_returns_none() -> None:
    assert _version_lte("unknown", "2.4.49") is None
    assert _version_lte("2.4.49", "unknown") is None


def test_version_lte_rc_suffix_does_not_corrupt_comparison() -> None:
    # Regression test: a pre-release suffix ending in a digit (rc1,
    # beta2, p1, ...) must NOT be absorbed as an extra version
    # component. Before the fix, "2.4.49rc1" parsed as (2, 4, 49, 1),
    # making it compare as newer than "2.4.49" (4 components > 3) and
    # so NOT match a "vulnerable <= 2.4.49" CVE bound — a false
    # negative on the exact vulnerable version, just with an rc/beta/p
    # suffix attached, which is common in real Server headers.
    assert _version_lte("2.4.49rc1", "2.4.49") is True
    assert _version_lte("2.4.49", "2.4.49rc1") is True
    assert _version_lte("2.4.49-beta2", "2.4.49") is True
    assert _version_lte("2.4.49p1", "2.4.49") is True


# ---------------------------------------------------------------------------
# correlate_cves
# ---------------------------------------------------------------------------


def test_correlate_matches_vulnerable_version() -> None:
    comp = TechStackComponent(product="apache_httpd", version="2.4.49", confidence=0.6)
    feed = [
        CveFeedEntry(
            cve_id="CVE-2021-41773",
            product="apache_httpd",
            version_lte="2.4.49",
            kev=True,
            severity="critical",
        )
    ]
    results = correlate_cves([comp], feed)
    assert len(results) == 1
    assert results[0].cve_id == "CVE-2021-41773"
    assert results[0].version_match == "matched"
    assert results[0].kev is True
    assert results[0].as_dict()["advisory_only"] is True
    assert results[0].as_dict()["does_not_confirm"] is True


def test_correlate_excludes_newer_than_bound() -> None:
    comp = TechStackComponent(product="apache_httpd", version="2.4.60", confidence=0.6)
    feed = [CveFeedEntry(cve_id="CVE-OLD", product="apache_httpd", version_lte="2.4.49")]
    results = correlate_cves([comp], feed)
    assert results == []


def test_correlate_is_case_insensitive_on_product() -> None:
    comp = TechStackComponent(product="Apache_HTTPD", version="2.4.10", confidence=0.6)
    feed = [CveFeedEntry(cve_id="CVE-X", product="apache_httpd", version_lte="2.4.49")]
    results = correlate_cves([comp], feed)
    assert len(results) == 1


def test_correlate_different_product_does_not_match() -> None:
    comp = TechStackComponent(product="nginx", version="1.18.0", confidence=0.6)
    feed = [CveFeedEntry(cve_id="CVE-X", product="apache_httpd", version_lte="2.4.49")]
    results = correlate_cves([comp], feed)
    assert results == []


def test_correlate_product_wide_entry_with_no_version_bound() -> None:
    comp = TechStackComponent(product="wordpress", version=None, confidence=0.3)
    feed = [CveFeedEntry(cve_id="CVE-WP", product="wordpress", version_lte=None)]
    results = correlate_cves([comp], feed)
    assert len(results) == 1
    assert results[0].version_match == "product_wide"


def test_correlate_unknown_when_component_version_missing() -> None:
    comp = TechStackComponent(product="php", version=None, confidence=0.25)
    feed = [CveFeedEntry(cve_id="CVE-PHP", product="php", version_lte="8.0.0")]
    results = correlate_cves([comp], feed)
    assert len(results) == 1
    assert results[0].version_match == "unknown"


def test_correlate_unknown_when_detected_version_unparseable() -> None:
    comp = TechStackComponent(product="php", version="dev-main", confidence=0.6)
    feed = [CveFeedEntry(cve_id="CVE-PHP", product="php", version_lte="8.0.0")]
    results = correlate_cves([comp], feed)
    assert len(results) == 1
    assert results[0].version_match == "unknown"


def test_correlate_accepts_plain_dict_feed_entries() -> None:
    comp = TechStackComponent(product="php", version="7.4.0", confidence=0.6)
    feed = [{"cve_id": "CVE-DICT", "product": "php", "version_lte": "8.0.0"}]
    results = correlate_cves([comp], feed)
    assert len(results) == 1
    assert results[0].cve_id == "CVE-DICT"


def test_correlate_skips_malformed_dict_entries() -> None:
    comp = TechStackComponent(product="php", version="7.4.0", confidence=0.6)
    feed = [{"product": "php"}]  # missing required cve_id
    results = correlate_cves([comp], feed)
    assert results == []


def test_correlate_kev_entries_sort_first() -> None:
    comp = TechStackComponent(product="apache_httpd", version="2.4.10", confidence=0.6)
    feed = [
        CveFeedEntry(cve_id="CVE-NOTKEV", product="apache_httpd", version_lte="2.4.49", kev=False),
        CveFeedEntry(cve_id="CVE-KEV", product="apache_httpd", version_lte="2.4.49", kev=True),
    ]
    results = correlate_cves([comp], feed)
    assert results[0].cve_id == "CVE-KEV"
    assert results[0].kev is True


def test_correlate_multiple_components_multiple_entries() -> None:
    comps = [
        TechStackComponent(product="apache_httpd", version="2.4.49", confidence=0.6),
        TechStackComponent(product="php", version="7.4.3", confidence=0.6),
    ]
    feed = [
        CveFeedEntry(cve_id="CVE-APACHE", product="apache_httpd", version_lte="2.4.49"),
        CveFeedEntry(cve_id="CVE-PHP", product="php", version_lte="8.0.0"),
        CveFeedEntry(cve_id="CVE-UNRELATED", product="nginx", version_lte="1.0.0"),
    ]
    results = correlate_cves(comps, feed)
    assert {r.cve_id for r in results} == {"CVE-APACHE", "CVE-PHP"}


def test_correlate_empty_feed_returns_empty() -> None:
    comp = TechStackComponent(product="php", version="7.4.3", confidence=0.6)
    assert correlate_cves([comp], []) == []


def test_correlate_empty_components_returns_empty() -> None:
    feed = [CveFeedEntry(cve_id="CVE-X", product="php", version_lte="8.0.0")]
    assert correlate_cves([], feed) == []
