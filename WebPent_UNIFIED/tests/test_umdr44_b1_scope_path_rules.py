"""UM-DR-44 B1 — path rules must apply across ALL allow entries.

The scope-file factory bound exclude-path deny rules to
``allow_entries[0]`` only, and constrained allow rules to
``include_paths[0]`` only, while the comment above the code claimed
"apply as constraints on every allow rule".  A scope of
``["a.com", "b.com"]`` with ``exclude_paths: ["/admin"]`` therefore
denied ``a.com/admin`` but ALLOWED ``b.com/admin`` — a real
path-restriction bypass through a second in-scope origin.

Required semantics (deny-first evaluation stays authoritative):

* one deny rule per (allow entry x exclude prefix) — the exclusion
  applies to every in-scope origin, not just the first;
* the include constraint applies per (allow entry x include prefix) —
  a path under ANY declared include prefix passes for that origin;
* scope with no include/exclude paths keeps its exact previous
  behavior (no rule churn).
"""

from __future__ import annotations

from webpent.scope import authority_from_scope_file_spec
from webpent.shared.scope_file import parse_scope_file


def _authority(text: str):
    return authority_from_scope_file_spec(parse_scope_file(text))


MULTI_ORIGIN = """
https://a.example.com
https://b.example.com
exclude-path: /admin
"""


class TestExcludePathAppliesToEveryAllowEntry:
    def test_excluded_path_denied_on_first_origin(self) -> None:
        auth = _authority(MULTI_ORIGIN)
        assert not auth.evaluate_request("https://a.example.com/admin/panel").allowed

    def test_excluded_path_denied_on_second_origin(self) -> None:
        """RED on the current tree: b.example.com/admin was allowed."""
        auth = _authority(MULTI_ORIGIN)
        assert not auth.evaluate_request("https://b.example.com/admin/panel").allowed

    def test_excluded_path_denied_on_every_origin(self) -> None:
        text = "\n".join(
            [f"https://h{i}.example.com" for i in range(5)] + ["exclude-path: /admin"]
        )
        auth = _authority(text)
        for i in range(5):
            assert not auth.evaluate_request(f"https://h{i}.example.com/admin").allowed

    def test_non_excluded_path_still_allowed_on_every_origin(self) -> None:
        auth = _authority(MULTI_ORIGIN)
        assert auth.evaluate_request("https://a.example.com/api/x").allowed
        assert auth.evaluate_request("https://b.example.com/api/x").allowed


class TestIncludePathAnyOf:
    TEXT = """
https://a.example.com
https://b.example.com
include-path: /api
include-path: /graphql
"""

    def test_path_under_first_include_passes(self) -> None:
        auth = _authority(self.TEXT)
        assert auth.evaluate_request("https://a.example.com/api/v1").allowed

    def test_path_under_second_include_passes(self) -> None:
        """RED on the current tree: only include_paths[0] was applied."""
        auth = _authority(self.TEXT)
        assert auth.evaluate_request("https://a.example.com/graphql/q").allowed

    def test_second_include_passes_on_second_origin(self) -> None:
        auth = _authority(self.TEXT)
        assert auth.evaluate_request("https://b.example.com/graphql/q").allowed

    def test_path_outside_all_includes_denied(self) -> None:
        auth = _authority(self.TEXT)
        assert not auth.evaluate_request("https://a.example.com/blog/x").allowed
        assert not auth.evaluate_request("https://b.example.com/blog/x").allowed


class TestMixedEntriesAndPaths:
    TEXT = """
https://a.example.com
https://b.example.com
exclude-path: /admin
exclude-path: /internal
include-path: /api
"""

    def test_exclude_wins_over_include_on_same_origin(self) -> None:
        """Deny-first: /admin stays denied even though includes exist."""
        auth = _authority(self.TEXT)
        assert not auth.evaluate_request("https://b.example.com/admin/x").allowed
        assert not auth.evaluate_request("https://a.example.com/internal/x").allowed

    def test_include_passes_on_all_origins(self) -> None:
        auth = _authority(self.TEXT)
        assert auth.evaluate_request("https://a.example.com/api/x").allowed
        assert auth.evaluate_request("https://b.example.com/api/x").allowed


class TestNoPathConstraintsUnchanged:
    def test_plain_scope_behavior_identical(self) -> None:
        auth = _authority("https://a.example.com\nhttps://b.example.com\n")
        assert auth.evaluate_request("https://a.example.com/anything").allowed
        assert auth.evaluate_request("https://b.example.com/admin").allowed
        assert not auth.evaluate_request("https://c.example.com/api").allowed

    def test_excluded_host_still_denied_with_paths(self) -> None:
        auth = _authority(
            "https://a.example.com\nexclude: evil.example.com\ninclude-path: /api\n"
        )
        assert not auth.evaluate_request("https://evil.example.com/api/x").allowed
