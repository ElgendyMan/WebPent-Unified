# tests/test_umdr35_scope_authority_unification.py
"""UM-DR-35.3 — Gate 35-C scope-integrity regression tests.

The canonical authority (EngagementScopeAuthority.evaluate_request) is the
ONE authorization decision engine. ScopeEnforcer delegates every allow/deny
decision to it and keeps only operational duties (counters, halt, rate,
concurrency). Canonical URL parsing failures are DENIALS, never allows.
"""
from __future__ import annotations

import pytest

from webpent.scope.authority import (
    CanonicalScopeError,
    authority_from_policy,
)
from webpent.scope.enforcer import ScopeEnforcer
from webpent.scope.models import ScopeLimits, ScopePolicy, ScopeRule


def _policy(rules, **limits) -> ScopePolicy:
    import hashlib
    import json
    policy = ScopePolicy(
        rules=[ScopeRule(**r) if isinstance(r, dict) else r for r in rules],
        limits=ScopeLimits(**limits) if limits else ScopeLimits(),
    )
    # The canonical authority requires a policy fingerprint (audit field).
    material = json.dumps([r.as_dict() for r in policy.rules], sort_keys=True)
    object.__setattr__(policy, "fingerprint", hashlib.sha256(material.encode()).hexdigest())
    return policy


_ALLOW_APP = [{"kind": "domain", "value": "app.example.com", "allow": True, "source": "operator"}]
_ALLOW_RANGE = [{"kind": "cidr", "value": "10.0.0.0/24", "allow": True, "source": "operator"}]
_ALLOW_WILD = [{"kind": "wildcard", "value": "*.example.com", "allow": True, "source": "operator"}]


class TestCanonicalAuthorityFailClosed:
    def test_malformed_url_is_denied_not_allowed(self):
        authority = authority_from_policy(_policy(_ALLOW_APP))
        decision = authority.evaluate_request("http://[::bad")
        assert decision.allowed is False
        assert decision.violation_code == "request_url_rejected"

    def test_userinfo_url_is_denied(self):
        authority = authority_from_policy(_policy(_ALLOW_APP))
        decision = authority.evaluate_request("http://app.example.com@evil.com/x")
        assert decision.allowed is False

    def test_empty_policy_is_denied(self):
        authority = authority_from_policy(_policy([]))
        decision = authority.evaluate_request("https://app.example.com/")
        assert decision.allowed is False
        assert decision.violation_code == "scope_policy_empty"

    def test_double_encoded_path_is_denied(self):
        authority = authority_from_policy(_policy(_ALLOW_APP))
        decision = authority.evaluate_request(
            "https://app.example.com/%252e%252e/admin")
        assert decision.allowed is False
        assert decision.violation_code == "scope_path_ambiguous"

    def test_unexpected_scheme_is_denied(self):
        authority = authority_from_policy(_policy(_ALLOW_APP))
        assert authority.evaluate_request("file:///etc/passwd").allowed is False
        assert authority.evaluate_request("ftp://app.example.com/x").allowed is False

    def test_port_zero_denied_and_out_of_range_denied(self):
        authority = authority_from_policy(_policy(_ALLOW_APP))
        assert authority.evaluate_request("https://app.example.com:0/x").allowed is False
        assert authority.evaluate_request(
            "https://app.example.com:99999/x").allowed is False

    def test_ip_literals_and_cidr(self):
        authority = authority_from_policy(_policy(_ALLOW_RANGE))
        assert authority.evaluate_request("http://10.0.0.7/x").allowed is True
        assert authority.evaluate_request("http://10.0.1.7/x").allowed is False
        assert authority.evaluate_request("http://10.0.0.7:8080/x").allowed is False

    def test_strict_wildcard_no_glob_metacharacters(self):
        authority = authority_from_policy(_policy(_ALLOW_WILD))
        assert authority.evaluate_request("https://api.example.com/").allowed is True
        assert authority.evaluate_request("https://example.com/").allowed is False
        # fnmatch-style metacharacters are rejected at COMPILE time
        # (fail-closed admission), never treated as a general glob.
        with pytest.raises(CanonicalScopeError):
            authority_from_policy(
                _policy([{"kind": "wildcard", "value": "*.example.?om",
                          "allow": True, "source": "op"}]))

    def test_deny_rule_precedence_over_allow(self):
        policy = _policy([
            {"kind": "wildcard", "value": "*.example.com", "allow": True, "source": "op"},
            {"kind": "domain", "value": "admin.example.com", "allow": False, "source": "op"},
        ])
        authority = authority_from_policy(policy)
        assert authority.evaluate_request("https://api.example.com/").allowed is True
        decision = authority.evaluate_request("https://admin.example.com/")
        assert decision.allowed is False
        assert decision.violation_code == "explicit_out_of_scope"

    def test_path_prefix_boundary_not_substring(self):
        policy = _policy([
            {"kind": "url", "value": "https://app.example.com/api/v1",
             "allow": True, "source": "op"},
        ])
        authority = authority_from_policy(policy)
        assert authority.evaluate_request("https://app.example.com/api/v1").allowed is True
        assert authority.evaluate_request("https://app.example.com/api/v1/users").allowed is True
        # /api/v10 must NOT match the /api/v1 prefix
        assert authority.evaluate_request("https://app.example.com/api/v10").allowed is False

    def test_method_restriction(self):
        policy = _policy([
            {"kind": "domain", "value": "app.example.com", "allow": True,
             "source": "op", "allowed_methods": frozenset({"GET"})},
        ])
        authority = authority_from_policy(policy)
        get_ok = authority.evaluate_request("https://app.example.com/x", method="GET")
        post_ok = authority.evaluate_request("https://app.example.com/x", method="POST")
        assert get_ok.allowed is True
        assert post_ok.allowed is False


class TestEnforcerDelegatesToAuthority:
    """The enforcer must not add competing scope semantics."""

    def test_enforcer_decision_equals_authority_decision(self):
        policy = _policy(_ALLOW_APP)
        enforcer = ScopeEnforcer(policy)
        authority = authority_from_policy(policy)
        for url in ("https://app.example.com/x", "https://other.com/x",
                    "http://[::bad", "https://app.example.com/%2e%2e/admin"):
            e = enforcer.check_url(url)
            a = authority.evaluate_request(url)
            assert e.allowed == a.allowed, url
            assert e.violation_code == a.violation_code, url

    def test_enforcer_malformed_url_is_denied_before_network(self):
        enforcer = ScopeEnforcer(_policy(_ALLOW_APP))
        decision = enforcer.check_url("https://app.example.com@evil.com/x")
        assert decision.allowed is False
        assert decision.request_admitted is False
        assert decision.may_proceed_to_network is False

    def test_enforcer_violation_counters_advance_on_denials(self):
        enforcer = ScopeEnforcer(_policy(_ALLOW_APP, max_violations=3))
        for _ in range(3):
            enforcer.check_url("https://evil.com/x")
        assert enforcer.violation_count == 3
        assert enforcer.halted is True
        halted = enforcer.check_url("https://app.example.com/x")
        assert halted.allowed is False
        assert halted.violation_code == "scope_halted"

    def test_enforcer_has_no_independent_rule_matcher(self):
        """UM-DR-35.3: the duplicated matcher implementation must be gone."""
        import inspect

        from webpent.scope import enforcer as enforcer_mod
        src = inspect.getsource(enforcer_mod)
        assert "def _rule_matches" not in src
        assert "def _host_match" not in src
        assert True


class TestPermitLifecycle:
    def _enforcer(self) -> ScopeEnforcer:
        return ScopeEnforcer(_policy(_ALLOW_APP, max_requests_per_second=1000,
                                     max_concurrent_requests=2))

    def test_release_exactly_once_no_negative_counter(self):
        enforcer = self._enforcer()
        d = enforcer.acquire("https://app.example.com/a")
        assert d.allowed
        enforcer.release()
        enforcer.release()  # over-release must clamp at zero
        assert enforcer.active_requests == 0

    def test_permit_released_on_scope_denial(self):
        enforcer = self._enforcer()
        denied = enforcer.acquire("https://evil.com/x")
        assert denied.allowed is False
        assert enforcer.active_requests == 0

    def test_concurrency_ceiling_admits_only_limit(self):
        import time as _time
        enforcer = self._enforcer()
        first = enforcer.acquire("https://app.example.com/a")
        _time.sleep(0.01)  # respect the 1000 rps rate window
        second = enforcer.acquire("https://app.example.com/b")
        _time.sleep(0.01)
        third = enforcer.acquire("https://app.example.com/c")
        assert first.allowed and second.allowed
        assert third.allowed is False
        assert third.violation_code == "concurrency_limit"
        enforcer.release()
        _time.sleep(0.01)
        fourth = enforcer.acquire("https://app.example.com/d")
        assert fourth.allowed is True

    def test_permits_released_via_finally_pattern(self):
        enforcer = self._enforcer()
        try:
            decision = enforcer.acquire("https://app.example.com/a")
            assert decision.allowed
            raise RuntimeError("network exception mid-request")
        except RuntimeError:
            enforcer.release()  # exception-safe release in the caller's finally
        assert enforcer.active_requests == 0
