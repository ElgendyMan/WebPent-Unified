"""v83 T7 / U-CEM-7: the wake-up protocol."""

from __future__ import annotations

from pathlib import Path

from webpent.autonomous.cem.wake_up import WakeUpProtocol

NOW = 1_700_000_000.0


def _diff(signal="critical", target="t1"):
    return {
        "target_id": target,
        "top_signal": signal,
        "change_count": 2,
        "changes": [{"field": "subdomains", "kind": "added", "item": "x.example.com"}],
    }


def test_non_critical_diff_is_ignored(tmp_path: Path) -> None:
    wake = WakeUpProtocol(tmp_path / "w.json", daily_budget=1000)
    for signal in ("noise", "signal-low", "signal-high"):
        assert wake.evaluate(_diff(signal=signal), now=NOW, remaining_budget=500) is None
    assert wake.evaluate({}, now=NOW, remaining_budget=500) is None


def test_wake_budget_never_exceeds_remaining_and_never_negative(tmp_path: Path) -> None:
    wake = WakeUpProtocol(tmp_path / "w.json", daily_budget=1000)
    decision = wake.evaluate(_diff(), now=NOW, remaining_budget=300)
    assert decision["budget"] == 300
    assert decision["remaining_after"] == 0

    assert wake.evaluate(_diff(), now=NOW, remaining_budget=0)["refusal"] == "no_remaining_budget"
    assert wake.evaluate(_diff(), now=NOW, remaining_budget=-5)["refusal"] == "no_remaining_budget"

    big = wake.evaluate(_diff(), now=NOW, remaining_budget=5000)
    assert big["budget"] == 1000  # full campaign budget, clipped to daily


def test_apply_records_and_cooldown_blocks_rewake(tmp_path: Path) -> None:
    wake = WakeUpProtocol(tmp_path / "w.json", daily_budget=1000)
    decision = wake.evaluate(_diff(), now=NOW, remaining_budget=800)
    record = wake.apply(decision, now=NOW)
    assert record["budget"] == 800
    again = wake.evaluate(_diff(), now=NOW + 3600, remaining_budget=800)
    assert again["refusal"] == "cooldown"
    after = NOW + 25 * 3600
    assert wake.evaluate(_diff(), now=after, remaining_budget=800)["budget"] == 800


def test_return_to_dormancy_marks_closed(tmp_path: Path) -> None:
    wake = WakeUpProtocol(tmp_path / "w.json", daily_budget=1000)
    decision = wake.evaluate(_diff(), now=NOW, remaining_budget=800)
    wake.apply(decision, now=NOW)
    assert wake.return_to_dormancy("t1", now=NOW + 60) is True
    assert wake.history()[-1]["closed"] is True
    assert wake.return_to_dormancy("t1", now=NOW + 120) is False  # nothing open
    assert wake.return_to_dormancy("ghost", now=NOW) is False


def test_garbage_apply_and_evaluate_never_raise(tmp_path: Path) -> None:
    wake = WakeUpProtocol(tmp_path / "w.json", daily_budget=1000)
    assert wake.apply({}, now=NOW) is None
    assert wake.apply("junk", now=NOW) is None  # type: ignore[arg-type]
    assert wake.apply({"target_id": "t1", "refusal": "cooldown"}, now=NOW) is None
    assert wake.evaluate("junk", now=NOW, remaining_budget=100) is None  # type: ignore[arg-type]


def test_roundtrip_and_corruption(tmp_path: Path) -> None:
    path = tmp_path / "w.json"
    wake = WakeUpProtocol(path, daily_budget=1000)
    wake.apply(wake.evaluate(_diff(), now=NOW, remaining_budget=500), now=NOW)
    reloaded = WakeUpProtocol(path, daily_budget=1000)
    assert reloaded._on_cooldown("t1", NOW + 60)

    path.write_text("{broken", encoding="utf-8")
    broken = WakeUpProtocol(path, daily_budget=1000)
    assert broken.history() == []
    assert broken._on_cooldown("t1", NOW + 60) is False
