"""Tests for the advisory-only source-leak candidate generator
(Ultimate plan 2026-10-27, proposal 5 phase 4).

The module under test NEVER fetches, clones, or scans code — it only
generates candidate names over injected data. These tests pin that
contract: bounded output, advisory flags on every candidate, and the
domain/JS-asset heuristics.
"""

from __future__ import annotations

from webpent.shared.source_leak_discovery import (
    source_leak_advisory_enabled,
    suggest_leak_candidates,
)


def test_domain_heuristic_generates_org_guess_and_prefixed_names():
    candidates = suggest_leak_candidates("example.com", {})
    names = [c["candidate"] for c in candidates]
    assert "example" in names
    assert "example-frontend" in names
    assert "example-backend" in names
    assert "example-api" in names
    for candidate in candidates:
        assert candidate["source"] == "domain_heuristic"
        assert candidate["note"] == "advisory only — manual verification required"
        assert candidate["fetches_code"] is False


def test_org_guess_handles_www_and_full_urls():
    assert "example" in [
        c["candidate"] for c in suggest_leak_candidates("www.example.com", {})
    ]
    assert "example" in [
        c["candidate"] for c in suggest_leak_candidates("https://example.com/x", {})
    ]
    assert suggest_leak_candidates("", {}) == []


def test_js_asset_hints_from_crawled_paths():
    crawled = {"javascript_urls": ["https://example.com/static/js/app.js"]}
    candidates = suggest_leak_candidates("example.com", crawled)
    js_hinted = {c["candidate"] for c in candidates if c["source"] == "js_asset_hint"}
    # The plan's canonical example: app.js -> example-frontend,
    # example-web.
    assert "example-frontend" in js_hinted
    assert "example-web" in js_hinted


def test_js_asset_hints_distinguish_admin_and_api_assets():
    crawled = {
        "js_files": [
            "/static/admin/admin.bundle.js",
            "/static/js/graphql.api.js",
        ]
    }
    candidates = suggest_leak_candidates("example.com", crawled)
    hinted = {c["candidate"] for c in candidates if c["source"] == "js_asset_hint"}
    assert "example-admin" in hinted
    assert "example-dashboard" in hinted
    assert "example-backend" in hinted


def test_candidates_capped_at_25():
    crawled = {
        "javascript_urls": [f"/static/js/app{i}.js" for i in range(200)],
        "assets": [f"/x/admin{i}.js" for i in range(200)],
    }
    candidates = suggest_leak_candidates("example.com", crawled)
    assert len(candidates) <= 25


def test_every_candidate_is_advisory_and_never_fetches():
    candidates = suggest_leak_candidates(
        "example.com", {"javascript_urls": ["/static/js/app.js"]}
    )
    assert candidates, "expected at least the domain heuristic candidates"
    for candidate in candidates:
        assert candidate["fetches_code"] is False
        assert "manual verification" in candidate["note"]


def test_malformed_inputs_degrade_gracefully():
    assert suggest_leak_candidates("example.com", None) != []
    # Non-list / non-string entries are skipped, never crash.
    candidates = suggest_leak_candidates(
        "example.com", {"javascript_urls": ["ok.js", 42, None, ""]}
    )
    assert all(c["fetches_code"] is False for c in candidates)


def test_advisory_flag_defaults_off():
    # The settings flag gates surfacing these candidates in a run;
    # disabled by default per the plan (explicit operator opt-in).
    assert source_leak_advisory_enabled() is False
