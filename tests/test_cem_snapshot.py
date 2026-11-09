"""v83 T1 / U-CEM-1: the CEM snapshot engine."""

from __future__ import annotations

import json
from pathlib import Path

from webpent.autonomous.cem.snapshot import (
    MAX_LIST_ITEMS,
    MAX_SNAPSHOTS_PER_TARGET,
    MAX_TARGETS,
    SECTION_FIELDS,
    SnapshotStore,
    build_snapshot,
)

NOW = 1_700_000_000.0


def _make(tmp_path: Path) -> SnapshotStore:
    return SnapshotStore(tmp_path / "snapshots.json")


def test_build_snapshot_is_deterministic_and_hashed() -> None:
    a = build_snapshot("t1", now=NOW, subdomains=["b", "a"], headers={"Server": "nginx"})
    b = build_snapshot("t1", now=NOW, subdomains=["a", "b"], headers={"Server": "nginx"})
    assert a == b
    assert a["hash"] == b["hash"]
    assert len(a["hash"]) == 16
    # order of list inputs does not change the fingerprint
    c = build_snapshot("t1", now=NOW, subdomains=["a", "b"], headers={"Server": "nginx"})
    assert c["hash"] == a["hash"]


def test_build_snapshot_differs_on_content_change() -> None:
    a = build_snapshot("t1", now=NOW, endpoints=["/login"])
    b = build_snapshot("t1", now=NOW, endpoints=["/login", "/admin"])
    assert a["hash"] != b["hash"]


def test_build_snapshot_redacts_every_persisted_string() -> None:
    snapshot = build_snapshot(
        "t1",
        now=NOW,
        subdomains=["token=abcdef123456"],
        headers={"Authorization": "Bearer sk-9999999999999999"},
        cert_expiry="password=hunter2",
        tech_stack=["api_key=abcd1234efgh5678"],
    )
    blob = json.dumps(snapshot)
    for needle in ("abcdef123456", "sk-9999", "hunter2", "abcd1234"):
        assert needle not in blob
    assert "[REDACTED_SECRET]" in blob
    for field in SECTION_FIELDS:
        assert field in snapshot


def test_build_snapshot_bounded_and_garbage_safe() -> None:
    values = [f"/p{i}" for i in range(MAX_LIST_ITEMS + 50)]
    snapshot = build_snapshot("t1", now=NOW, endpoints=values)
    assert len(snapshot["endpoints"]) == MAX_LIST_ITEMS
    junk = build_snapshot("t1", now=NOW, endpoints=42, headers="nope", js_hashes=["x"])
    assert junk["endpoints"] == []
    assert junk["headers"] == {}
    assert junk["js_hashes"] == {"x": ""} or junk["js_hashes"] == {}
    empty = build_snapshot("", now=NOW)
    assert empty["target_id"] == ""


def test_snapshot_store_roundtrip(tmp_path: Path) -> None:
    store = _make(tmp_path)
    snapshot = build_snapshot("t1", now=NOW, endpoints=["/a"])
    store.append(snapshot)
    store.save()

    reloaded = SnapshotStore(tmp_path / "snapshots.json")
    assert reloaded.latest("t1") == snapshot
    assert reloaded.series("t1") == [snapshot]
    assert reloaded.per_target_counts()["t1"] == 1


def test_snapshot_store_missing_and_corrupt_degrade_to_empty(
    tmp_path: Path,
) -> None:
    assert SnapshotStore(tmp_path / "nope.json").latest("t1") is None
    bad = tmp_path / "broken.json"
    bad.write_text("{not json", encoding="utf-8")
    store = SnapshotStore(bad)
    assert store.series("t1") == []
    # appending on top of a corrupt file works and re-saves cleanly
    store.append(build_snapshot("t1", now=NOW, endpoints=["/a"]))
    store.save()
    assert SnapshotStore(bad).latest("t1") is not None


def test_snapshot_store_per_target_and_store_bounds(tmp_path: Path) -> None:
    store = _make(tmp_path)
    for i in range(MAX_SNAPSHOTS_PER_TARGET + 10):
        store.append(build_snapshot("t1", now=NOW + i, endpoints=[f"/e{i}"]))
    assert len(store.series("t1")) == MAX_SNAPSHOTS_PER_TARGET
    assert store.latest("t1")["endpoints"] == [f"/e{MAX_SNAPSHOTS_PER_TARGET + 9}"]

    for t in range(MAX_TARGETS + 4):
        store.append(build_snapshot(f"t{t}", now=NOW, endpoints=["/x"]))
    assert len(store.per_target_counts()) == MAX_TARGETS
    # the earliest target was evicted; the newest survives
    assert store.latest("t0") is None
    assert store.latest(f"t{MAX_TARGETS + 3}") is not None


def test_snapshot_store_append_garbage_is_noop(tmp_path: Path) -> None:
    store = _make(tmp_path)
    store.append({})  # missing target_id
    store.append("not-a-dict")
    store.append(None)
    assert store.per_target_counts() == {} or dict(store.per_target_counts()) == {}


def test_history_endpoints_is_bounded_union(tmp_path: Path) -> None:
    store = _make(tmp_path)
    store.append(build_snapshot("t1", now=NOW, endpoints=["/a", "/b"]))
    store.append(build_snapshot("t1", now=NOW + 1, endpoints=["/b", "/c"]))
    seen = store.history_endpoints("t1")
    assert seen == {"/a", "/b", "/c"}
    assert store.history_endpoints("missing") == set()


def test_snapshot_save_failure_keeps_memory(tmp_path: Path) -> None:
    store = _make(tmp_path)
    store.append(build_snapshot("t1", now=NOW, endpoints=["/a"]))
    # a directory in the save path makes os.replace fail; memory survives
    (tmp_path / "snapshots.json").mkdir()
    store.save()
    assert store.latest("t1") is not None
