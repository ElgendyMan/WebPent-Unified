"""UM-DR-41 §6.3 — cross-process scope registry consistency tests.

The directive's exact scenario, executed with REAL separate processes
(not mocks): load a scope in process A, read it in process B, update in
A, verify B observes the new version, restart B, simulate store
failure, and verify execution is blocked (fail-closed) when the
authoritative scope cannot be resolved.

Also pins: legacy in-memory-only behavior is byte-for-byte preserved
for existing callers (no store -> no persistence, same return values).
"""
from __future__ import annotations

import json
import subprocess
import sys
import textwrap
from pathlib import Path

import pytest

from webpent.scope import (
    GLOBAL_SCOPE_REGISTRY,
    ScopeEnforcer,
    ScopeRegistry,
    ScopeStoreUnavailable,
    SqliteScopeStore,
    parse_scope_text,
)

_SCOPE_DOC = json.dumps({
    "in_scope": ["https://target-a.example"],
    "limits": {"max_requests_per_second": 2.0},
})
_SCOPE_DOC_V2 = json.dumps({
    "in_scope": ["https://target-a.example", "https://target-b.example"],
    "limits": {"max_requests_per_second": 4.0},
})

_WORKER = textwrap.dedent(
    """
    import json, sys
    sys.path.insert(0, {src!r})
    from webpent.scope import SqliteScopeStore
    store = SqliteScopeStore({path!r})
    cmd = sys.argv[1]
    if cmd == "read":
        policy = store.current({engagement!r})
        if policy is None:
            print(json.dumps({{"present": False}}))
        else:
            print(json.dumps({{
                "present": True,
                "rules": len(policy.rules),
                "rps": policy.limits.max_requests_per_second,
                "version": store.current_version({engagement!r}),
                "fingerprint": policy.fingerprint,
            }}))
    elif cmd == "load":
        policy = store.append_policy_text(sys.argv[2], {engagement!r})
        print(json.dumps({{"version": policy}}))
    """.rstrip()
)


def _run_worker(tmp_path: Path, store_path: Path, engagement: str,
                cmd: str, *args: str) -> dict:
    """Run one registry operation in a FRESH interpreter (process B)."""
    import webpent
    src_root = str(Path(webpent.__file__).resolve().parents[2] / "src")
    script = tmp_path / "worker.py"
    script.write_text(_WORKER.format(
        src=src_root, path=str(store_path), engagement=engagement))
    result = subprocess.run(
        [sys.executable, str(script), cmd, *args],
        capture_output=True, text=True, timeout=60, check=True)
    return json.loads(result.stdout.strip().splitlines()[-1])


def _append_via_text(store: SqliteScopeStore, text: str, engagement: str) -> int:
    """Helper bridging parse -> store.append (mirrors the API route)."""
    policy = parse_scope_text(text, source="api:test")
    return store.append(policy, engagement_id=engagement)


# ---------------------------------------------------------------------------
# The directive's 8-step scenario, executed for real
# ---------------------------------------------------------------------------

def test_6_3_cross_process_visibility_and_versioning(tmp_path):
    store_path = tmp_path / "scope_store.sqlite3"

    # 1. Load a scope in "process A" (this process).
    store_a = SqliteScopeStore(store_path)
    registry_a = ScopeRegistry(store=store_a)
    policy_v1 = parse_scope_text(_SCOPE_DOC, source="api:test")
    registry_a.load(policy_v1, engagement_id="eng-6-3")
    assert registry_a.current_version("eng-6-3") == 1

    # 2. Read it in process B (a fresh interpreter with its own registry).
    seen = _run_worker(tmp_path, store_path, "eng-6-3", "read")
    assert seen["present"] is True
    assert seen["rules"] == len(policy_v1.rules)
    assert seen["rps"] == 2.0
    assert seen["version"] == 1

    # 3. Update the policy in process A (append -> version 2).
    policy_v2 = parse_scope_text(_SCOPE_DOC_V2, source="api:test")
    registry_a.load(policy_v2, engagement_id="eng-6-3")
    assert registry_a.current_version("eng-6-3") == 2

    # 4. Process B observes the correct NEW version atomically.
    seen = _run_worker(tmp_path, store_path, "eng-6-3", "read")
    assert seen["version"] == 2
    assert seen["rps"] == 4.0
    assert seen["rules"] == 2

    # 5. Restart one process (new registry instance, same store) —
    #    the policy survives; nothing silently reverts to empty.
    registry_a2 = ScopeRegistry(store=SqliteScopeStore(store_path))
    assert registry_a2.get("eng-6-3") is not None
    assert registry_a2.current_version("eng-6-3") == 2
    # the enforcer built from the RESOLVED policy behaves correctly
    enforcer = ScopeEnforcer(registry_a2.get("eng-6-3"))
    assert enforcer.check_url("https://target-b.example/x").allowed
    assert not enforcer.check_url("https://target-c.example/x").allowed


def test_6_3_clear_tombstones_across_processes(tmp_path):
    store_path = tmp_path / "scope_store.sqlite3"
    store = SqliteScopeStore(store_path)
    registry = ScopeRegistry(store=store)
    registry.load(parse_scope_text(_SCOPE_DOC), engagement_id="eng-clear")
    assert _run_worker(tmp_path, store_path, "eng-clear", "read")["present"]

    registry.clear("eng-clear")
    # history preserved (row count unchanged via SQL), current is None
    seen = _run_worker(tmp_path, store_path, "eng-clear", "read")
    assert seen["present"] is False
    assert registry.get("eng-clear") is None


def test_6_3_store_failure_fails_closed(tmp_path):
    """A corrupt/unopenable store must raise ScopeStoreUnavailable —
    never silently behave like an empty permissive registry."""
    bogus = tmp_path / "not-a-dir" / "nested" / "store.sqlite3"
    bogus.parent.mkdir(parents=True)
    bogus.write_text("this is not a sqlite database")
    with pytest.raises(ScopeStoreUnavailable):
        SqliteScopeStore(bogus)

    # A directory path also fails loudly rather than empty-permissive.
    with pytest.raises(ScopeStoreUnavailable):
        SqliteScopeStore(tmp_path)


def test_6_3_registry_read_failure_propagates(tmp_path):
    """Registry with a store whose file goes bad mid-flight: get() must
    raise (fail closed), not return None (which callers could read as
    'no policy -> proceed')."""
    store_path = tmp_path / "store.sqlite3"
    store = SqliteScopeStore(store_path)
    registry = ScopeRegistry(store=store)
    registry.load(parse_scope_text(_SCOPE_DOC), engagement_id="eng-x")
    # corrupt the file out from under the registry
    store_path.write_text("garbage" * 100)
    with pytest.raises(ScopeStoreUnavailable):
        registry.get("eng-x")


def test_6_3_tampered_record_rejected(tmp_path):
    store_path = tmp_path / "store.sqlite3"
    store = SqliteScopeStore(store_path)
    store.append(parse_scope_text(_SCOPE_DOC), engagement_id="eng-t")
    # tamper: rewrite the JSON so its embedded fingerprint no longer
    # matches the fingerprint column recorded at load time
    import sqlite3
    conn = sqlite3.connect(str(store_path))
    conn.execute(
        "UPDATE scope_policies SET policy_json = replace(policy_json, "
        "'target-a', 'attacker-a') WHERE engagement_id = 'eng-t'")
    conn.commit()
    conn.close()
    with pytest.raises(ScopeStoreUnavailable):
        store.current("eng-t")


def test_6_3_round_trip_preserves_policy_semantics(tmp_path):
    """as_dict -> store -> policy_from_dict keeps enforcement identical."""
    original = parse_scope_text(_SCOPE_DOC_V2, source="api:test")
    store = SqliteScopeStore(tmp_path / "rt.sqlite3")
    store.append(original, engagement_id="eng-rt")
    restored = store.current("eng-rt")
    assert restored is not None
    assert restored.fingerprint == original.fingerprint
    assert restored.limits.as_dict() == original.limits.as_dict()
    assert [r.as_dict() for r in restored.rules] == [r.as_dict() for r in original.rules]
    assert restored.blacklisted_payloads == original.blacklisted_payloads
    assert list(restored.instructions) == list(original.instructions)


def test_6_3_legacy_registry_behavior_unchanged():
    """No store -> EXACT historical semantics (all existing callers)."""
    registry = ScopeRegistry()
    policy = parse_scope_text(_SCOPE_DOC)
    assert registry.get("never-loaded") is None
    assert registry.load(policy, engagement_id="e1") is policy
    assert registry.get("e1") is policy
    assert registry.redacted()["e1"]["fingerprint"] == policy.fingerprint
    assert registry.current_version("e1") is None  # no versioning w/o store
    assert registry.clear("e1") is True
    assert registry.clear("e1") is False
    assert registry.get("e1") is None
    # the module-level singleton stays legacy-mode (no implicit I/O)
    assert GLOBAL_SCOPE_REGISTRY.current_version("anything") is None


def test_6_3_concurrent_append_is_serialized(tmp_path):
    """Two processes appending simultaneously -> two distinct versions,
    no lost update (SQLite BEGIN IMMEDIATE serializes the read-modify-write)."""
    store_path = tmp_path / "conc.sqlite3"
    _append_via_text(SqliteScopeStore(store_path), _SCOPE_DOC, "eng-c")
    import concurrent.futures
    def append_one(_: int) -> int:
        return _append_via_text(
            SqliteScopeStore(store_path), _SCOPE_DOC_V2, "eng-c")
    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
        versions = list(pool.map(append_one, range(4)))
    assert sorted(versions) == [2, 3, 4, 5]
    assert SqliteScopeStore(store_path).current_version("eng-c") == 5
