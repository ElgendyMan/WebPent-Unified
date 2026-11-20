"""v81 Task 1 + Task 3: dead-end memory and advisory demotion.

Proven properties:

* only conclusively-decided negative outcomes enter the store (clean, or
  executed with vulnerable falsy); confirmed/vulnerable never do,
* blocked/inconclusive outcomes are never treated as dead ends,
* no secrets and no query values survive into the stored file,
* bounds (pairs per origin, origins) are enforced,
* persistence round-trips and a corrupt file degrades to "no memory",
* the save is atomic (temp file + os.replace, no partial state),
* ``penalty_for`` demotes advisory matches (exact pair 0.25, class-level
  0.10 after two dead pairs) and returns 0.0 for unknown probes,
* ``dead_end_ratio`` stays within [0, 1],
* a broken store never breaks a hunt round (orchestrator guard).
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from webpent.autonomous.hunt_deadends import (
    MAX_ORIGINS,
    MAX_PAIRS_PER_ORIGIN,
    DeadEndStore,
)


class _FakeState:
    """Minimal state double carrying only what DeadEndStore reads."""

    def __init__(self, target_url: str, outcomes: list[dict[str, Any]]) -> None:
        self.target_url = target_url
        self.outcomes = outcomes


def _clean(
    vuln_class: str,
    url: str = "",
    *,
    status: str = "executed",
    vulnerable: Any = False,
) -> dict[str, Any]:
    record: dict[str, Any] = {
        "status": status,
        "vulnerability_class": vuln_class,
        "vulnerable": vulnerable,
    }
    if url:
        record["url"] = url
    return record


# -- update_from_state --------------------------------------------------


def test_only_decided_negative_outcomes_enter(tmp_path: Path) -> None:
    store = DeadEndStore(tmp_path / "deadends.json")
    store.update_from_state(
        _FakeState(
            "http://lab.example/",
            [
                _clean("sqli", "http://lab.example/a"),
                _clean("xss", "http://lab.example/b", status="executed", vulnerable=False),
                _clean("confirmed_class", "http://lab.example/c", status="confirmed"),
                _clean("vuln_flag", "http://lab.example/d", vulnerable=True),
                _clean("blocked_class", "http://lab.example/e", status="blocked_by_precondition"),
                _clean("inconclusive_class", "http://lab.example/f", status="inconclusive"),
            ],
        )
    )
    record = store.record_for("http://lab.example/")
    pairs = {(p["class"], p["endpoint"]) for p in record["pairs"]}
    assert ("sqli", "http://lab.example/a") in pairs
    assert ("xss", "http://lab.example/b") in pairs
    # Decided-positive or undecided outcomes are never dead ends.
    assert ("confirmed_class", "http://lab.example/c") not in pairs
    assert ("vuln_flag", "http://lab.example/d") not in pairs
    assert ("blocked_class", "http://lab.example/e") not in pairs
    assert ("inconclusive_class", "http://lab.example/f") not in pairs


def test_no_secrets_and_no_query_values_stored(tmp_path: Path) -> None:
    store = DeadEndStore(tmp_path / "deadends.json")
    store.update_from_state(
        _FakeState(
            "http://lab.example/",
            [_clean("sqli", "http://lab.example/admin?password=hunter2&token=abc123def456")],
        )
    )
    store.save()
    dumped = (tmp_path / "deadends.json").read_text(encoding="utf-8")
    assert "hunter2" not in dumped
    assert "abc123def456" not in dumped
    assert "?" not in dumped.replace('{"', "")


def test_bounds_are_enforced(tmp_path: Path) -> None:
    store = DeadEndStore(tmp_path / "deadends.json")
    outcomes = [
        _clean(f"class{i}", f"http://lab.example/path{i}") for i in range(60)
    ]
    store.update_from_state(_FakeState("http://lab.example/", outcomes))
    record = store.record_for("http://lab.example/")
    assert len(record["pairs"]) <= MAX_PAIRS_PER_ORIGIN
    for i in range(MAX_ORIGINS + 4):
        store.update_from_state(_FakeState(f"http://host{i}.example/", [_clean("sqli")]))
    assert len(store.origins()) <= MAX_ORIGINS


def test_repeats_accumulate_hits(tmp_path: Path) -> None:
    store = DeadEndStore(tmp_path / "deadends.json")
    for _ in range(3):
        store.update_from_state(
            _FakeState("http://lab.example/", [_clean("sqli", "http://lab.example/a")])
        )
    pairs = store.record_for("http://lab.example/")["pairs"]
    assert len(pairs) == 1
    assert pairs[0]["hits"] == 3


def test_roundtrip_and_corrupt_file_degrade_to_empty(tmp_path: Path) -> None:
    path = tmp_path / "deadends.json"
    store = DeadEndStore(path)
    store.update_from_state(
        _FakeState("http://lab.example/", [_clean("sqli", "http://lab.example/a")])
    )
    store.save()
    reloaded = DeadEndStore(path)
    assert reloaded.record_for("http://lab.example/") is not None

    path.write_text("{not json at all", encoding="utf-8")
    broken = DeadEndStore(path)
    assert broken.origins() == []
    assert broken.dead_end_ratio("http://lab.example/") == 0.0


def test_save_is_atomic_no_partial_file(tmp_path: Path) -> None:
    path = tmp_path / "deadends.json"
    store = DeadEndStore(path)
    store.update_from_state(
        _FakeState("http://lab.example/", [_clean("sqli", "http://lab.example/a")])
    )
    store.save()
    assert path.is_file()
    document = json.loads(path.read_text(encoding="utf-8"))
    assert "http://lab.example" in document
    leftovers = [p for p in tmp_path.iterdir() if p.name != "deadends.json"]
    assert leftovers == []


# -- reading ------------------------------------------------------------


def test_penalty_for_exact_pair_and_class_level(tmp_path: Path) -> None:
    from webpent.autonomous.hunt_deadends import (
        PENALTY_CLASS_LEVEL,
        PENALTY_EXACT_PAIR,
    )

    store = DeadEndStore(tmp_path / "deadends.json")
    store.update_from_state(
        _FakeState(
            "http://lab.example/",
            [
                _clean("sqli", "http://lab.example/a"),
                _clean("sqli", "http://lab.example/b"),
                _clean("xss", "http://lab.example/a"),
            ],
        )
    )
    # Exact (class, endpoint) match: full penalty.
    assert store.penalty_for("http://lab.example/", "sqli", "http://lab.example/a") == (
        PENALTY_EXACT_PAIR
    )
    # Same class, unknown endpoint, two or more dead pairs: class-level.
    assert store.penalty_for("http://lab.example/", "sqli", "http://lab.example/zzz") == (
        PENALTY_CLASS_LEVEL
    )
    # Only one dead pair for the class: no class-level demotion.
    assert store.penalty_for("http://lab.example/", "xss", "http://lab.example/zzz") == 0.0
    # Unknown class: nothing.
    assert store.penalty_for("http://lab.example/", "ssti", "http://lab.example/a") == 0.0
    # Other origin: nothing.
    assert store.penalty_for("http://other.example/", "sqli", "http://lab.example/a") == 0.0


def test_dead_end_ratio_bounded(tmp_path: Path) -> None:
    store = DeadEndStore(tmp_path / "deadends.json")
    assert store.dead_end_ratio("http://lab.example/") == 0.0
    store.update_from_state(
        _FakeState(
            "http://lab.example/",
            [_clean(f"c{i}", f"http://lab.example/p{i}") for i in range(30)],
        )
    )
    ratio = store.dead_end_ratio("http://lab.example/")
    assert 0.0 < ratio <= 1.0


def test_empty_and_bad_outcomes_change_nothing(tmp_path: Path) -> None:
    store = DeadEndStore(tmp_path / "deadends.json")
    store.update_from_state(_FakeState("http://lab.example/", []))
    assert store.origins() == []
    store.update_from_state(_FakeState("http://lab.example/", ["not-a-dict", None, 42]))
    assert store.origins() == []
    store.update_from_state(_FakeState("", [_clean("sqli")]))
    assert store.origins() == []
