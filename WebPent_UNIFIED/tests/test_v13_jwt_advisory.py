from __future__ import annotations

import base64
import hashlib
import hmac
import json

from webpent.agents.api_testing.agent import _analyze_captured_jwts
from webpent.agents.disclosed_report_intel.agent import disclosed_report_intel_node
from webpent.shared.disclosed_report_intel import (
    build_advisories,
    ingest_disclosed_reports,
    search_disclosed_reports,
)
from webpent.shared.jwt_deep_testing import (
    analyze_captured_jwt,
    extract_candidate_jwts,
    parse_compact_jwt,
)


def _b64(value: object) -> str:
    raw = json.dumps(value, separators=(",", ":")).encode()
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def _hs256(secret: str = "secret") -> str:
    header = _b64({"alg": "HS256", "typ": "JWT"})
    payload = _b64({"sub": "user-1", "iat": 1700000000, "exp": 1900000000})
    signing_input = f"{header}.{payload}".encode()
    signature = hmac.new(secret.encode(), signing_input, hashlib.sha256).digest()
    return f"{header}.{payload}.{base64.urlsafe_b64encode(signature).decode().rstrip('=')}"


def test_jwt_parser_and_bounded_weak_secret_evidence_do_not_return_raw_token():
    token = _hs256()
    parsed = parse_compact_jwt(token)
    assert parsed and parsed["algorithm"] == "HS256"
    assert token not in str(parsed)

    result = analyze_captured_jwt(token, weak_secret_candidates=["not-it", "secret"])
    assert result
    assert any(item["type"] == "weak_secret_match" for item in result["observations"])
    assert "'secret'" not in str(result)
    assert token not in str(result)


def test_jwt_inventory_is_bounded_and_alg_none_is_only_a_gap_offline():
    token = _hs256("not-common")
    value = {"body": f"token={token}", "nested": [token]}
    assert extract_candidate_jwts(value) == [token]
    result = analyze_captured_jwt(token, weak_secret_candidates=["secret"])
    assert result and any(
        g["type"] == "jwt_secret_strength_unverified" for g in result["coverage_gaps"]
    )


def test_api_testing_promotes_only_offline_verified_weak_secret():
    token = _hs256()
    findings, observations, gaps = _analyze_captured_jwts(
        "http://lab.local",
        {"responses": [{"body": token}]},
        weak_secret_candidates=["secret"],
        # webpent.shared.verifier's strict provenance gate (GOED) requires
        # a non-placeholder engagement_id + scope_context + identity_context
        # before promoting — see RECONCILIATION_REPORT.md.
        verification_context={
            "engagement_id": "test-fixture-engagement",
            "scope_context": {"targets": ["lab.local"], "authorized": True},
            "identity_context": {"identity": "primary", "authenticated": True},
        },
    )
    assert len(findings) == 1
    assert findings[0].vuln_class == "jwt_weakness"
    assert findings[0].confidence_level == "Tool-Confirmed"
    assert observations and observations[0]["type"] == "weak_secret_match"
    assert token not in str(findings + observations + gaps)


def test_disclosed_report_intel_is_local_text_search_and_advisory_only():
    records = ingest_disclosed_reports(
        [
            {
                "source": "local-export.json",
                "title": "Checkout IDOR",
                "text": "An IDOR in /api/orders/{id} exposed another user's order. No tokens here.",
            },
            "A separate JWT alg=none report described /api/profile.",
        ]
    )
    assert len(records) == 2
    matches = search_disclosed_reports(records, "idor order")
    assert matches and matches[0]["report_id"] == records[0]["report_id"]
    advisories, gaps = build_advisories(
        "https://example.test",
        ["https://example.test/api/orders/123"],
        records,
    )
    assert advisories
    assert not any(item.get("type") == "vulnerability" for item in advisories)
    assert not gaps


def test_advisory_node_is_explicit_noop_without_local_corpus():
    result = disclosed_report_intel_node({"crawled_data": {}})
    assert result["disclosed_report_advisories"] == []
    assert any(
        gap["type"] == "disclosed_report_corpus_missing" for gap in result["advisory_coverage_gaps"]
    )
    assert "findings" not in result
