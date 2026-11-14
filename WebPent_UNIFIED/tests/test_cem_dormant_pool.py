"""v83 T10 / U-CEM-10: the dormant hypothesis pool."""

from __future__ import annotations

from pathlib import Path

from webpent.autonomous.cem.dormant_pool import MAX_POOL, DormantPool

NOW = 1_700_000_000.0


def _diff(target="t1", changes=None):
    return {"target_id": target, "changes": changes or []}


def _change(field="endpoints", kind="added", item="/admin"):
    return {"field": field, "kind": kind, "item": item}


def test_add_and_list_dormant_hypotheses(tmp_path: Path) -> None:
    pool = DormantPool(tmp_path / "pool.json")
    out = pool.add(
        target_id="t1", hypothesis="test admin panel for default creds",
        blocked_on_field="endpoints", blocked_on_kind="added", now=NOW,
        vuln_class="auth",
    )
    assert out["blocked_on"] == "endpoints:added"
    assert pool.count() == 1
    assert pool.pool()[0]["target_id"] == "t1"


def test_activation_on_matching_diff_and_removal(tmp_path: Path) -> None:
    pool = DormantPool(tmp_path / "pool.json")
    pool.add(target_id="t1", hypothesis="h1", blocked_on_field="endpoints",
             blocked_on_kind="added", now=NOW)
    quiet = pool.activate_for(_diff(changes=[_change(field="headers", kind="changed")]),
                              now=NOW + 60)
    assert quiet == []
    assert pool.count() == 1
    woken = pool.activate_for(_diff(changes=[_change(item="/admin")]), now=NOW + 120)
    assert len(woken) == 1
    assert woken[0]["hypothesis"] == "h1"
    assert woken[0]["activated_at"] == NOW + 120
    assert pool.count() == 0  # activated hypotheses leave the pool


def test_activation_is_target_scoped(tmp_path: Path) -> None:
    pool = DormantPool(tmp_path / "pool.json")
    pool.add(target_id="t1", hypothesis="h1", blocked_on_field="endpoints",
             blocked_on_kind="added", now=NOW)
    pool.add(target_id="t2", hypothesis="h2", blocked_on_field="endpoints",
             blocked_on_kind="added", now=NOW)
    woken = pool.activate_for(_diff(target="t2", changes=[_change()]), now=NOW + 60)
    assert [w["hypothesis"] for w in woken] == ["h2"]
    assert pool.count() == 1


def test_ttl_reap_after_120_days(tmp_path: Path) -> None:
    pool = DormantPool(tmp_path / "pool.json")
    pool.add(target_id="t1", hypothesis="old", blocked_on_field="endpoints",
             blocked_on_kind="added", now=NOW)
    assert pool.reap(now=NOW + 119 * 86400) == []
    retired = pool.reap(now=NOW + 121 * 86400)
    assert len(retired) == 1
    assert pool.count() == 0


def test_pool_capped_at_32(tmp_path: Path) -> None:
    pool = DormantPool(tmp_path / "pool.json")
    for i in range(MAX_POOL + 5):
        pool.add(target_id=f"t{i}", hypothesis=f"h{i}", blocked_on_field="endpoints",
                 blocked_on_kind="added", now=NOW + i)
    assert pool.count() == MAX_POOL


def test_garbage_adds_and_diffs_never_raise(tmp_path: Path) -> None:
    pool = DormantPool(tmp_path / "pool.json")
    assert pool.add(target_id="", hypothesis="x", blocked_on_field="a",
                    blocked_on_kind="b", now=NOW) == {}
    assert pool.add(target_id="t1", hypothesis="", blocked_on_field="a",
                    blocked_on_kind="b", now=NOW) == {}
    assert pool.activate_for(None, now=NOW) == []
    assert pool.activate_for({}, now=NOW) == []
    assert pool.activate_for(_diff(changes=["junk", 42]), now=NOW) == []
    assert pool.count() == 0


def test_roundtrip_and_corruption(tmp_path: Path) -> None:
    path = tmp_path / "pool.json"
    pool = DormantPool(path)
    pool.add(target_id="t1", hypothesis="keep me", blocked_on_field="endpoints",
             blocked_on_kind="added", now=NOW)
    assert DormantPool(path).count() == 1

    path.write_text("nope", encoding="utf-8")
    assert DormantPool(path).count() == 0
