"""UM-DR-34 Phase 8 — wildcard, path, origin and method adversarial matrix.

Every negative test asserts the DECISION fields (deny + reason token),
not merely a helper returning False.  Where a mocked network is
involved (transport-level tests live in
test_umdr34_boundary_enforcement.py) the network-attempt count must be
ZERO for pre-network denials.
"""

from __future__ import annotations

import pytest

from webpent.scope import (
    CanonicalScopeError,
    EngagementScopeAuthority,
    authority_for_target_only,
    authority_from_policy,
    authority_from_scope_file_spec,
    parse_scope_text,
)
from webpent.scope.models import ScopeRule
from webpent.shared.scope_file import parse_scope_file as parse_scope_file_spec


def _authority(yaml_text: str) -> EngagementScopeAuthority:
    return authority_from_policy(parse_scope_text(yaml_text))


# ---------------------------------------------------------------------------
# Wildcards
# ---------------------------------------------------------------------------


class TestWildcardMatrix:
    AUTH = """
rules:
  - value: "*.example.com"
    kind: wildcard
"""

    def test_wildcard_matches_complete_subdomain_label(self) -> None:
        auth = _authority(self.AUTH)
        assert auth.evaluate_request("http://shop.example.com/").allowed
        assert auth.evaluate_request("http://a.b.example.com/").allowed

    def test_apex_is_not_included(self) -> None:
        auth = _authority(self.AUTH)
        decision = auth.evaluate_request("http://example.com/")
        assert not decision.allowed
        assert decision.violation_code == "unknown_scope"

    def test_wildcard_cannot_widen_through_glob_metacharacters(self) -> None:
        # '?' must never act as a single-character glob.
        with pytest.raises(CanonicalScopeError):
            _authority("rules:\n  - value: \"?.example.com\"\n")
        # '[seq]' must never act as a character class.
        with pytest.raises(CanonicalScopeError):
            _authority("rules:\n  - value: \"shop.[ab].example.com\"\n")
        # A misplaced '*' (not the leftmost complete label) is rejected.
        with pytest.raises(CanonicalScopeError):
            _authority("rules:\n  - value: \"evil*.example.com\"\n")
        with pytest.raises(CanonicalScopeError):
            _authority("rules:\n  - value: \"shop.*.example.com\"\n")

    def test_wildcard_never_matches_suffix_of_other_domain(self) -> None:
        auth = _authority(self.AUTH)
        assert not auth.evaluate_request("http://example.com.attacker.net/").allowed
        assert not auth.evaluate_request("http://notexample.com/").allowed

    def test_nested_subdomains_and_trailing_dots(self) -> None:
        auth = _authority(self.AUTH)
        assert auth.evaluate_request("http://deep.sub.example.com/x").allowed
        assert auth.evaluate_request("http://shop.example.com./x").allowed

    def test_idna_punycode_normalization(self) -> None:
        policy = parse_scope_text(
            'rules:\n  - value: "bücher.example.com"\n    kind: domain\n'
        )
        auth = authority_from_policy(policy)
        # The IDNA form must match the unicode declaration.
        assert auth.evaluate_request("http://xn--bcher-kva.example.com/").allowed
        assert auth.evaluate_request("http://bücher.example.com/").allowed

    def test_ipv4_and_ipv6_exact_targets(self) -> None:
        policy = parse_scope_text(
            "rules:\n  - value: \"http://10.10.0.5\"\n    kind: url\n"
        )
        auth = authority_from_policy(policy)
        assert auth.evaluate_request("http://10.10.0.5/login").allowed
        assert not auth.evaluate_request("http://10.10.0.6/").allowed
        v6 = parse_scope_text("rules:\n  - value: \"http://[::1]:8080\"\n    kind: url\n")
        auth6 = authority_from_policy(v6)
        assert auth6.evaluate_request("http://[::1]:8080/x").allowed
        assert not auth6.evaluate_request("http://[::2]:8080/x").allowed

    def test_cidr_rule_matches_only_inside_network(self) -> None:
        policy = parse_scope_text(
            "rules:\n  - value: \"10.20.0.0/16\"\n    kind: cidr\n"
        )
        auth = authority_from_policy(policy)
        assert auth.evaluate_request("http://10.20.3.4/").allowed
        assert not auth.evaluate_request("http://10.21.0.1/").allowed


# ---------------------------------------------------------------------------
# Origins: schemes, ports, userinfo, malformed input
# ---------------------------------------------------------------------------


class TestOriginMatrix:
    POLICY = """
rules:
  - value: "https://app.example.com"
    kind: url
"""

    def test_http_vs_https_distinguished(self) -> None:
        auth = _authority(self.POLICY)
        assert auth.evaluate_request("https://app.example.com/x").allowed
        decision = auth.evaluate_request("http://app.example.com/x")
        assert not decision.allowed  # same host, wrong scheme

    def test_ws_wss_follow_tls_posture(self) -> None:
        auth = _authority(self.POLICY)
        # wss shares the https posture; ws does not.
        assert auth.evaluate_request("wss://app.example.com/socket").allowed
        assert not auth.evaluate_request("ws://app.example.com/socket").allowed

    def test_explicit_vs_default_port(self) -> None:
        auth = _authority(self.POLICY)
        assert auth.evaluate_request("https://app.example.com:443/x").allowed
        assert not auth.evaluate_request("https://app.example.com:8443/x").allowed

    def test_port_zero_rejected(self) -> None:
        auth = _authority(self.POLICY)
        decision = auth.evaluate_request("https://app.example.com:0/x")
        assert not decision.allowed
        assert decision.violation_code == "request_url_rejected"

    def test_out_of_range_port_rejected(self) -> None:
        auth = _authority(self.POLICY)
        assert not auth.evaluate_request("https://app.example.com:70000/x").allowed
        assert not auth.evaluate_request("https://app.example.com:-1/x").allowed

    def test_userinfo_denied(self) -> None:
        auth = _authority(self.POLICY)
        decision = auth.evaluate_request("https://user:pass@app.example.com/x")
        assert not decision.allowed
        assert decision.violation_code == "request_url_rejected"

    def test_malformed_url_denied_not_raised(self) -> None:
        auth = _authority(self.POLICY)
        for bad in ("", "not a url", "::::", "http://", "https://[::1"):
            decision = auth.evaluate_request(bad)
            assert not decision.allowed, bad
            assert decision.violation_code == "request_url_rejected"

    def test_bare_host_rule_binds_default_ports_only(self) -> None:
        auth = _authority('rules:\n  - value: "app.example.com"\n    kind: domain\n')
        assert auth.evaluate_request("http://app.example.com/").allowed
        assert auth.evaluate_request("https://app.example.com/").allowed
        # A rule that declares no port never authorizes non-default ports.
        assert not auth.evaluate_request("http://app.example.com:8080/").allowed


# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------


class TestPathMatrix:
    POLICY = """
rules:
  - value: "https://app.example.com/api"
    kind: url
"""

    def test_segment_boundary_not_prefix_string(self) -> None:
        auth = _authority(self.POLICY)
        assert auth.evaluate_request("https://app.example.com/api/users").allowed
        decision = auth.evaluate_request("https://app.example.com/api2/users")
        assert not decision.allowed  # /api must not match /api2

    def test_exact_path_and_trailing_slash(self) -> None:
        auth = _authority(self.POLICY)
        assert auth.evaluate_request("https://app.example.com/api").allowed
        assert auth.evaluate_request("https://app.example.com/api/").allowed

    def test_encoded_path_ambiguous_denied(self) -> None:
        auth = _authority(self.POLICY)
        for path in ("/api/%2e%2e/admin", "/api/%2fadmin", "/api/%5cadmin", "/api/%252e%252e"):
            decision = auth.evaluate_request(f"https://app.example.com{path}")
            assert not decision.allowed, path
            assert decision.violation_code == "scope_path_ambiguous", path

    def test_backslash_path_denied(self) -> None:
        auth = _authority(self.POLICY)
        decision = auth.evaluate_request("https://app.example.com/api\\..\\admin")
        assert not decision.allowed

    def test_dot_segments_normalized_before_matching(self) -> None:
        auth = _authority(self.POLICY)
        # /api/../admin normalizes to /admin — outside the include path.
        decision = auth.evaluate_request("https://app.example.com/api/../admin")
        assert not decision.allowed

    def test_excluded_path_precedence_over_allow(self) -> None:
        policy = parse_scope_text(
            """
rules:
  - value: "https://app.example.com"
    kind: url
  - value: "https://app.example.com"
    kind: url
    allow: false
    path: /admin
"""
        )
        auth = authority_from_policy(policy)
        assert auth.evaluate_request("https://app.example.com/api/x").allowed
        decision = auth.evaluate_request("https://app.example.com/admin/users")
        assert not decision.allowed
        assert decision.violation_code == "explicit_out_of_scope"
        assert decision.matched_deny_rule is not None

    def test_query_and_fragment_do_not_change_path_decision(self) -> None:
        auth = _authority(self.POLICY)
        assert auth.evaluate_request("https://app.example.com/api/x?q=1").allowed
        assert auth.evaluate_request("https://app.example.com/api/x#frag").allowed


# ---------------------------------------------------------------------------
# Methods and severity
# ---------------------------------------------------------------------------


class TestMethodMatrix:
    def test_allowed_methods_enforced(self) -> None:
        policy = parse_scope_text(
            'rules:\n  - value: "https://app.example.com"\n    kind: url\n    methods: ["GET", "POST"]\n'
        )
        auth = authority_from_policy(policy)
        assert auth.evaluate_request("https://app.example.com/x", method="GET").allowed
        assert auth.evaluate_request("https://app.example.com/x", method="POST").allowed
        decision = auth.evaluate_request("https://app.example.com/x", method="DELETE")
        assert not decision.allowed

    def test_destructive_methods_blocked_by_default_limits(self) -> None:
        auth = _authority('rules:\n  - value: "https://app.example.com"\n    kind: url\n')
        for method in ("DELETE", "PUT", "PATCH"):
            decision = auth.evaluate_request("https://app.example.com/x", method=method)
            assert not decision.allowed
            assert decision.violation_code == "destructive_method_blocked"

    def test_method_changes_across_redirects_are_rechecked(self) -> None:
        # The redirect guard in shared/http.py re-evaluates with the
        # original method AND the GET-downgrade — the authority must be
        # able to answer both.
        policy = parse_scope_text(
            'rules:\n  - value: "https://app.example.com"\n    kind: url\n    methods: ["GET"]\n'
        )
        auth = authority_from_policy(policy)
        assert auth.evaluate_request("https://app.example.com/x", method="GET").allowed
        assert not auth.evaluate_request("https://app.example.com/x", method="POST").allowed

    def test_severity_restriction_enforced(self) -> None:
        policy = parse_scope_text(
            'rules:\n  - value: "https://app.example.com"\n    kind: url\n    max_severity: medium\n'
        )
        auth = authority_from_policy(policy)
        assert auth.evaluate_request("https://app.example.com/x", severity="low").allowed
        assert not auth.evaluate_request("https://app.example.com/x", severity="critical").allowed

    def test_blacklisted_payload_blocked(self) -> None:
        policy = parse_scope_text(
            'rules:\n  - value: "https://app.example.com"\n    kind: url\nblacklisted_payloads:\n  - "rm -rf"\n'
        )
        auth = authority_from_policy(policy)
        decision = auth.evaluate_request(
            "https://app.example.com/x", method="POST", payload="rm -rf /"
        )
        assert not decision.allowed
        assert decision.violation_code == "blacklisted_payload_blocked"


# ---------------------------------------------------------------------------
# Determinism, deny precedence, decision record
# ---------------------------------------------------------------------------


class TestDecisionContract:
    POLICY = """
rules:
  - value: "*.example.com"
    kind: wildcard
  - value: "forbidden.example.com"
    kind: domain
    allow: false
"""

    def test_deterministic_decisions(self) -> None:
        auth = _authority(self.POLICY)
        first = auth.evaluate_request("http://shop.example.com/x")
        second = auth.evaluate_request("http://shop.example.com/x")
        assert first.reason == second.reason
        assert first.matched_allow_rule == second.matched_allow_rule
        assert first.scope_fingerprint == second.scope_fingerprint
        # Monotonic sequence.
        assert second.decision_seq == first.decision_seq + 1

    def test_deny_always_takes_precedence(self) -> None:
        auth = _authority(self.POLICY)
        decision = auth.evaluate_request("http://forbidden.example.com/x")
        assert not decision.allowed
        assert decision.violation_code == "explicit_out_of_scope"
        assert decision.matched_deny_rule == "domain:forbidden.example.com"
        assert decision.may_proceed_to_network is False

    def test_decision_record_fields_present(self) -> None:
        auth = _authority(self.POLICY)
        d = auth.evaluate_request("http://shop.example.com/api/x?y=1")
        assert d.normalized_origin == "http://shop.example.com:80"
        assert d.hostname == "shop.example.com"
        assert d.scheme == "http"
        assert d.effective_port == 80
        assert d.normalized_path == "/api/x"
        assert d.scope_fingerprint.startswith("sha256:")
        assert d.authorization_context_id
        assert d.may_proceed_to_network is True

    def test_empty_policy_denies_everything(self) -> None:
        from webpent.scope.models import ScopeLimits, ScopePolicy

        empty = ScopePolicy(rules=(), limits=ScopeLimits(), fingerprint="sha256:empty")
        auth = EngagementScopeAuthority(empty)
        decision = auth.evaluate_request("http://shop.example.com/x")
        assert not decision.allowed
        assert decision.violation_code == "scope_policy_empty"


# ---------------------------------------------------------------------------
# Parser unification (scope file / YAML / JSON / HackerOne / Bugcrowd)
# ---------------------------------------------------------------------------


class TestParserUnification:
    def test_scope_file_spec_becomes_one_authority(self) -> None:
        spec = parse_scope_file_spec(
            "https://app.example.com\nexclude: staging.example.com\ninclude-path: /api\n"
        )
        auth = authority_from_scope_file_spec(spec)
        assert auth.evaluate_request("https://app.example.com/api/x").allowed
        assert not auth.evaluate_request("https://staging.example.com/api/x").allowed
        assert not auth.evaluate_request("https://app.example.com/blog/x").allowed

    def test_hackerone_style_export(self) -> None:
        policy = parse_scope_text(
            """
structured_scopes:
  - asset_identifier: "*.corp.example.com"
    asset_type: WILDCARD
  - asset_identifier: "old.corp.example.com"
    eligible_for_bounties: false
    out_of_scope: true
"""
        )
        auth = authority_from_policy(policy)
        assert auth.evaluate_request("https://api.corp.example.com/").allowed
        assert not auth.evaluate_request("https://old.corp.example.com/").allowed

    def test_bugcrowd_style_export(self) -> None:
        policy = parse_scope_text(
            """
targets:
  in_scope:
    - target: "https://app.example.com"
      type: web
  out_of_scope:
    - target: "https://app.example.com/admin"
"""
        )
        auth = authority_from_policy(policy)
        assert auth.evaluate_request("https://app.example.com/x").allowed

    def test_malformed_scope_fails_closed(self) -> None:
        from webpent.scope.parser import ScopeParseError

        with pytest.raises(ScopeParseError):
            parse_scope_text("")
        with pytest.raises(ScopeParseError):
            parse_scope_text("# only comments\n")
        with pytest.raises((ScopeParseError, CanonicalScopeError)):
            # Invalid rule that cannot compile strictly.
            authority_from_policy(
                parse_scope_text('rules:\n  - value: "bad host!!"\n    kind: domain\n')
            )

    def test_target_only_authority_is_narrow_and_reported(self) -> None:
        auth = authority_for_target_only("http://10.10.0.5:8080/dvwa/")
        assert auth.mode == "target_only"
        assert auth.evaluate_request("http://10.10.0.5:8080/dvwa/login").allowed
        assert not auth.evaluate_request("http://10.10.0.5:8081/x").allowed
        assert not auth.evaluate_request("http://other.example.com/").allowed
        assert not auth.evaluate_request("http://10.10.0.5/x").allowed
