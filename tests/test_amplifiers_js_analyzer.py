"""v82 Task 4: deep JS analyzer (static, advisory leads only)."""

from __future__ import annotations

from webpent.autonomous.amplifiers.js_analyzer import analyze_javascript

SOURCE = """
const config = { apiKey: "AKQAWS1234567890abcdef12", token: "tok_abcdef1234567890abc" };
// if (isAdmin(user)) { grantRoot(); }
// verifyJwt(req) removed for demo
const ping = fetch("http://localhost:9000/debug");
const stage = fetch("https://api.staging.acme.dev/v1/ping");
if (flags["beta_dashboard"] && FEATURES["internal_search"]) { load(); }
const v0 = "/api/v0/internal/users";
"""


def test_extracts_all_five_kinds() -> None:
    report = analyze_javascript(SOURCE)
    leads = report["leads"]
    assert report["advisory"] is True
    assert leads["api_key_candidates"], "hardcoded key shapes must be flagged"
    assert leads["commented_auth_checks"], "commented-out checks must be flagged"
    assert any("localhost" in u for u in leads["dev_staging_urls"])
    assert "beta_dashboard" in leads["feature_flags"]
    assert any(v.startswith("/api/v0") for v in leads["internal_api_versions"])


def test_secret_values_are_never_echoed() -> None:
    report = analyze_javascript(SOURCE)
    text = str(report)
    assert "AKQAWS1234567890abcdef12" not in text
    assert "tok_abcdef1234567890abc" not in text


def test_clean_source_yields_no_leads() -> None:
    report = analyze_javascript("const x = 1;")
    assert report["scanned"] is True
    assert report["leads"] == {}


def test_empty_source_is_honest() -> None:
    report = analyze_javascript("")
    assert report["scanned"] is False
    assert report["advisory"] is True
