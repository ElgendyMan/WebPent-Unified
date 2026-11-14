from __future__ import annotations

import json

import pytest

from webpent.scope import ScopeEnforcer, ScopeParseError, ScopeStatus, parse_scope_text


def test_json_hackerone_like_scope_and_redacted_fingerprint():
    policy = parse_scope_text(json.dumps({
        "structured_scopes": [{"asset_identifier": "127.0.0.1", "asset_type": "domain", "port": 3000}],
        "out_of_scope": ["127.0.0.1:3001"],
        "instructions": ["Use only the local lab"],
        "limits": {"max_requests_per_second": 4, "max_concurrent_requests": 2},
    }), source="operator.json")
    assert policy.fingerprint.startswith("sha256:")
    assert policy.limits.max_concurrent_requests == 2
    assert policy.instructions == ("Use only the local lab",)
    assert "password" not in json.dumps(policy.as_dict()).lower()


def test_yaml_bugcrowd_like_scope_path_and_methods():
    policy = parse_scope_text("""
    in_scope:
      - url: https://example.test
        path: /api
        allowed_methods: [GET, POST]
        max_severity: high
    out_of_scope:
      - domain: admin.example.test
    limits:
      max_violations: 2
    """, source="scope.yaml")
    enforcer = ScopeEnforcer(policy)
    assert enforcer.check_url("https://example.test/api/v1", method="GET", severity="high").allowed
    assert not enforcer.check_url("https://example.test/api/v1", method="DELETE", severity="high").allowed
    assert not enforcer.check_url("https://example.test/api/v1", method="GET", severity="critical").allowed
    assert not enforcer.check_url("https://admin.example.test/api", method="GET").allowed


def test_plain_text_scope_is_fail_closed_and_supports_port():
    policy = parse_scope_text("# local lab\nhttp://127.0.0.1:3000\nexclude: http://127.0.0.1:3001\n", source="scope.txt")
    enforcer = ScopeEnforcer(policy)
    assert enforcer.check_url("http://127.0.0.1:3000/login").status is ScopeStatus.IN_SCOPE
    assert not enforcer.check_url("http://127.0.0.1:3001/login").allowed
    assert not enforcer.check_url("http://127.0.0.1:3000.evil.test/login").allowed


def test_explicit_deny_wins_over_allow():
    policy = parse_scope_text(json.dumps({
        "in_scope": [{"domain": "example.test"}],
        "out_of_scope": [{"domain": "example.test", "path": "/admin"}],
    }))
    enforcer = ScopeEnforcer(policy)
    assert enforcer.check_url("https://example.test/public").allowed
    decision = enforcer.check_url("https://example.test/admin/users")
    assert decision.violation_code == "explicit_out_of_scope"


def test_destructive_blacklist_and_threshold_halt():
    policy = parse_scope_text(json.dumps({
        "in_scope": ["https://example.test"],
        "blacklisted_payloads": ["DROP TABLE"],
        "limits": {"max_violations": 2, "max_requests_per_second": 100},
    }))
    enforcer = ScopeEnforcer(policy)
    assert enforcer.check_url("https://example.test/a", method="DELETE").violation_code == "destructive_method_blocked"
    assert enforcer.check_url("https://example.test/a", payload="DROP TABLE users").violation_code == "blacklisted_payload_blocked"
    assert enforcer.halted
    assert enforcer.check_url("https://example.test/a").violation_code == "scope_halted"


def test_acquire_release_concurrency_and_rate_are_bounded():
    policy = parse_scope_text(json.dumps({
        "in_scope": ["https://example.test"],
        "limits": {"max_requests_per_second": 100, "max_concurrent_requests": 1},
    }))
    enforcer = ScopeEnforcer(policy)
    first = enforcer.acquire("https://example.test/a")
    assert first.allowed
    second = enforcer.acquire("https://example.test/b")
    assert not second.allowed
    assert second.violation_code in {"concurrency_limit", "rate_limit"}
    enforcer.release()


def test_empty_and_missing_scope_are_rejected():
    with pytest.raises(ScopeParseError):
        parse_scope_text("")
    with pytest.raises(ScopeParseError):
        parse_scope_text("instructions: only local")
