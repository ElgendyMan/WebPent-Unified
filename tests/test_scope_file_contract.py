"""SCENARIO CONTRACT locks: explicit scope file vs URL-inferred scope.

Covers the operator workflow "URL + Credentials (+ Scope sometimes)":
strict scope-file grammar, fail-closed target membership, path rules,
ScopeSource propagation (worker -> initial_state -> report inputs), and
the crawler/scope_enforcer path pruning layers.
"""

from __future__ import annotations

import inspect

import pytest

from webpent.shared.scope_file import (
    SCOPE_SOURCE_FILE,
    SCOPE_SOURCE_INFERRED,
    ScopeFileError,
    ScopeFileSpec,
    evaluate_path_rules,
    inferred_spec,
    parse_scope_entries,
    parse_scope_file,
    prune_endpoints_by_path_rules,
    target_scope_error,
)

SCOPE_TEXT = """
# engagement contract
app.example.com
https://api.example.com
*.cdn.example.com
exclude: staging.example.com
include-path: /api
exclude-path: /admin
"""


def test_scope_file_grammar_parses_all_entry_kinds() -> None:
    spec = parse_scope_file(SCOPE_TEXT)
    assert spec.source == SCOPE_SOURCE_FILE
    assert spec.allow_entries == (
        "https://app.example.com",
        "https://api.example.com",
        "https://*.cdn.example.com",
    )
    assert spec.excluded_hosts == ("https://staging.example.com",)
    assert spec.include_paths == ("/api",)
    assert spec.exclude_paths == ("/admin",)
    assert spec.fingerprint.startswith("sha256:")


def test_scope_file_requires_at_least_one_allow_entry() -> None:
    with pytest.raises(ScopeFileError) as excinfo:
        parse_scope_file("# only comments\n\nexclude: x.example.com\n")
    assert excinfo.value.code == "scope_file_no_allow_entries"


def test_scope_file_rejects_ambiguous_entry_via_strict_compiler() -> None:
    with pytest.raises(ScopeFileError) as excinfo:
        parse_scope_file("https://user:pass@app.example.com\n")
    assert excinfo.value.code == "scope_file_entry_invalid"


def test_scope_file_rejects_wildcard_not_leftmost() -> None:
    with pytest.raises(ScopeFileError):
        parse_scope_file("https://api.*.example.com\n")


def test_scope_file_duplicate_allow_entries_rejected() -> None:
    with pytest.raises(ScopeFileError) as excinfo:
        parse_scope_file("app.example.com\napp.example.com\n")
    assert excinfo.value.code == "scope_file_duplicate_allow_entries"


def test_scope_file_path_rules_must_be_absolute_and_ascii() -> None:
    with pytest.raises(ScopeFileError):
        parse_scope_file("app.example.com\ninclude-path: api\n")
    with pytest.raises(ScopeFileError):
        parse_scope_file("app.example.com\nexclude-path: /admın\n")


def test_target_membership_fail_closed_matrix() -> None:
    spec = parse_scope_file(SCOPE_TEXT)
    # Inside: exact allow entry.
    assert target_scope_error(spec, "https://app.example.com/login") is None
    # Inside: wildcard subdomain.
    assert target_scope_error(spec, "https://img.cdn.example.com/a.png") is None
    # Outside: unknown host.
    assert (
        target_scope_error(spec, "https://other.example.com/")
        == "scope_file_target_url_not_in_scope"
    )
    # Outside: subdomain of an allow entry host is NOT auto-included
    # (only *.wildcard entries expand).
    assert (
        target_scope_error(spec, "https://blog.app.example.com/")
        == "scope_file_target_url_not_in_scope"
    )
    # Excluded host wins even if a wildcard would cover it.
    assert (
        target_scope_error(spec, "https://staging.example.com/")
        == "scope_file_target_url_excluded"
    )
    # Excluded path on an allowed host.
    assert (
        target_scope_error(spec, "https://app.example.com/admin/panel")
        == "scope_file_target_url_path_excluded"
    )
    # Garbage URL.
    assert target_scope_error(spec, "not-a-url") == "scope_file_target_url_invalid"


def test_path_rules_exclude_wins_include_is_allowlist() -> None:
    spec = parse_scope_file(SCOPE_TEXT)
    assert evaluate_path_rules(spec, "https://app.example.com/admin/x") == "denied"
    assert evaluate_path_rules(spec, "https://app.example.com/api/v1/users") == "allowed"
    assert evaluate_path_rules(spec, "https://app.example.com/public") == "denied"
    # No path rules -> not applicable (legacy behaviour).
    no_paths = parse_scope_file("app.example.com\n")
    assert evaluate_path_rules(no_paths, "https://app.example.com/anything") == (
        "not_applicable"
    )


def test_wildcard_root_itself_not_auto_included() -> None:
    spec = parse_scope_file("*.cdn.example.com\n")
    # The apex/root of a wildcard requires its own explicit entry.
    assert (
        target_scope_error(spec, "https://cdn.example.com/")
        == "scope_file_target_url_not_in_scope"
    )
    assert target_scope_error(spec, "https://a.b.cdn.example.com/x") is None


def test_inferred_spec_is_cautious_same_host_only() -> None:
    spec = inferred_spec("http://127.0.0.1:8123/login")
    assert spec.source == SCOPE_SOURCE_INFERRED
    assert spec.allow_entries == ("http://127.0.0.1",)
    assert spec.include_paths == () and spec.exclude_paths == ()
    assert target_scope_error(spec, "http://127.0.0.1/x") is None
    # A different host is NOT in the inferred scope.
    assert target_scope_error(spec, "http://127.0.0.2/x") == (
        "scope_file_target_url_not_in_scope"
    )


def test_parse_scope_entries_is_the_list_form_of_the_file() -> None:
    spec = parse_scope_entries(["app.example.com", "exclude-path: /admin"])
    assert spec.allow_entries == ("https://app.example.com",)
    assert spec.exclude_paths == ("/admin",)


def test_prune_endpoints_handles_string_and_dict_shapes() -> None:
    declaration = {"include_paths": ["/api"], "exclude_paths": ["/admin"]}
    endpoints = [
        "https://app.example.com/api/users",
        "https://app.example.com/admin/panel",
        {"url": "https://app.example.com/api/orders"},
        {"endpoint": "https://app.example.com/logout"},
    ]
    kept, pruned = prune_endpoints_by_path_rules(endpoints, declaration)
    assert pruned == 2
    assert kept == [
        "https://app.example.com/api/users",
        {"url": "https://app.example.com/api/orders"},
    ]
    # No path rules -> byte-identical passthrough.
    same, pruned0 = prune_endpoints_by_path_rules(endpoints, {})
    assert pruned0 == 0 and same == endpoints


def test_scope_enforcer_core_prunes_by_path_rules() -> None:
    from urllib.parse import urlparse

    from webpent.agents.scope_enforcer.agent import _enforce_scope_core
    from webpent.models.targets import Target

    target = Target(url="https://app.example.com")
    endpoints = [
        {"url": "https://app.example.com/api/users"},
        {"url": "https://app.example.com/admin/panel"},
    ]
    kept_findings, kept_data, f_removed, e_removed = _enforce_scope_core(
        target,
        [],
        {"endpoints": endpoints},
        path_rules={"include_paths": ("/api",), "exclude_paths": ()},
    )
    assert f_removed == 0
    assert e_removed == 1
    assert kept_data["endpoints"] == [{"url": "https://app.example.com/api/users"}]
    assert urlparse(kept_data["endpoints"][0]["url"]).path == "/api/users"


def test_initial_state_carries_scope_source_and_declaration() -> None:
    from webpent.models.targets import Target
    from webpent.state.initial_state import build_initial_state

    declaration = {
        "source": SCOPE_SOURCE_FILE,
        "allow_entries": ["https://app.example.com"],
        "excluded_hosts": [],
        "include_paths": ["/api"],
        "exclude_paths": [],
        "fingerprint": "sha256:abc",
    }
    state = build_initial_state(
        Target(url="https://app.example.com"),
        thread_id="scope-src-test",
        raw_scope_entries=["https://app.example.com"],
        scope_source=SCOPE_SOURCE_FILE,
        scope_declaration=declaration,
    )
    assert state["scope_source"] == SCOPE_SOURCE_FILE
    assert state["scope_declaration"]["fingerprint"] == "sha256:abc"
    assert state["raw_scope_entries"] == ["https://app.example.com"]
    # Default (absent) input stays URL-inferred.
    legacy = build_initial_state(
        Target(url="https://app.example.com"), thread_id="scope-src-legacy"
    )
    assert legacy["scope_source"] == SCOPE_SOURCE_INFERRED
    assert legacy["scope_declaration"] == {}


def test_worker_contract_contains_scope_inputs() -> None:
    from webpent.workers.pentest_worker import run_pentest_task

    signature = inspect.signature(run_pentest_task.run)
    assert "scope_file_text" in signature.parameters
    assert "scope_entries" in signature.parameters


def test_worker_fails_closed_when_target_outside_scope_file(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from webpent.workers import pentest_worker

    monkeypatch.setattr(pentest_worker, "sweep_expired", lambda *a, **k: 0)
    from webpent.workers.pentest_worker import run_pentest_task as _bound

    with pytest.raises(RuntimeError, match="scope_file_target_url_not_in_scope"):
        _bound.run(
            target_url="https://elsewhere.example.com/",
            is_portswigger=False,
            thread_id="scope-failclosed-test",
            auto_approve=True,
            skip_recon=True,
            credentials={},
            session_cookies={},
            identity_profiles={},
            scope_entries=["app.example.com", "exclude-path: /admin"],
        )


def test_worker_fails_closed_when_target_path_excluded(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from webpent.workers import pentest_worker

    monkeypatch.setattr(pentest_worker, "sweep_expired", lambda *a, **k: 0)
    from webpent.workers.pentest_worker import run_pentest_task as _bound

    with pytest.raises(RuntimeError, match="scope_file_target_url_path_excluded"):
        _bound.run(
            target_url="https://app.example.com/admin/panel",
            is_portswigger=False,
            thread_id="scope-pathfail-test",
            auto_approve=True,
            skip_recon=True,
            credentials={},
            session_cookies={},
            identity_profiles={},
            scope_entries=["app.example.com", "exclude-path: /admin"],
        )


def test_scope_declaration_projection_is_json_safe() -> None:
    import json

    spec = parse_scope_file(SCOPE_TEXT)
    encoded = json.dumps(spec.as_dict(), sort_keys=True)
    decoded = json.loads(encoded)
    rebuilt = ScopeFileSpec(
        allow_entries=tuple(decoded["allow_entries"]),
        excluded_hosts=tuple(decoded["excluded_hosts"]),
        include_paths=tuple(decoded["include_paths"]),
        exclude_paths=tuple(decoded["exclude_paths"]),
        source=decoded["source"],
    )
    assert rebuilt.allow_entries == spec.allow_entries
    assert rebuilt.source == SCOPE_SOURCE_FILE
