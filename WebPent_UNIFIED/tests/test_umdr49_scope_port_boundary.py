"""UM-DR-49 P0.3 — the scope-file PORT boundary (the safe-stop
rehearsal's finding) + the fail-closed refusal proof.

The rehearsal (out-of-scope target → refusal with zero requests) found
a REAL engine defect: the scope-file grammar matched HOST only and
ignored PORTS entirely — an allow entry http://127.0.0.1:3000
authorized every port on that host. Fixed: an entry with an explicit
port matches that port only; port-less entries match the scheme's
default port only. These tests pin the boundary.
"""
from __future__ import annotations

import os

os.environ.setdefault("WEBPENT_ENTRYPOINT", "cli")

from webpent.shared.scope_file import (  # noqa: E402
    parse_scope_file,
    target_scope_error,
)

SPEC = parse_scope_file("http://127.0.0.1:3000\n")


class TestScopePortBoundary:
    def test_same_host_same_port_allowed(self):
        assert target_scope_error(
            SPEC, "http://127.0.0.1:3000") is None

    def test_same_host_other_port_refused(self):
        assert target_scope_error(
            SPEC, "http://127.0.0.1:9999") == \
            "scope_file_target_url_not_in_scope"

    def test_portless_entry_matches_default_port_only(self):
        spec = parse_scope_file("http://lab.example\n")
        assert target_scope_error(spec, "http://lab.example") is None
        assert target_scope_error(
            spec, "http://lab.example:8080") == \
            "scope_file_target_url_not_in_scope"

    def test_https_port_not_authorized_by_http_entry(self):
        spec = parse_scope_file("http://lab.example\n")
        assert target_scope_error(
            spec, "https://lab.example") == \
            "scope_file_target_url_not_in_scope"

    def test_wildcard_entry_keeps_host_scope(self):
        # the parser normalizes a bare wildcard to https:// (existing
        # fail-closed behavior) — the test uses the explicit form
        spec = parse_scope_file("https://*.lab.example\n")
        assert target_scope_error(
            spec, "https://app.lab.example") is None
        assert target_scope_error(
            spec, "https://app.lab.example:8443") == \
            "scope_file_target_url_not_in_scope"
        assert target_scope_error(
            spec, "https://other.example") == \
            "scope_file_target_url_not_in_scope"
