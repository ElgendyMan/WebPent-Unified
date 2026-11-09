"""v83 T11 / U-CEM-11: the daily digest (Markdown + JSON twin)."""

from __future__ import annotations

import json
from pathlib import Path

from webpent.autonomous.cem.digest import (
    MAX_LISTED_ITEMS,
    MAX_MARKDOWN_CHARS,
    build_digest,
    write_digest,
)

NOW = 1_700_000_000.0


def _report(**over):
    base = {
        "target_id": "example.com",
        "change_count": 2,
        "spend": 40,
        "changes": {"changes": [
            {"field": "endpoints", "kind": "added", "item": "/admin?token=abcdef123456",
             "classification": "SIGNAL_HIGH"},
        ]},
        "observed": [{"diff": {"changes": [
            {"field": "subdomains", "kind": "added", "item": "app.example.com",
             "classification": "CRITICAL"},
        ]}}],
    }
    base.update(over)
    return base


def test_digest_returns_markdown_and_json_twin() -> None:
    digest = build_digest(now=NOW, cem_state={"cycle_count": 5, "targets": {"t1": {}}},
                          cycle_reports=[_report()])
    assert isinstance(digest["markdown"], str) and digest["markdown"]
    assert digest["advisory"] is True
    assert digest["cycle_count"] == 5
    assert digest["cycles_today"] == 1
    assert digest["changes_total"] == 2
    assert digest["spend_today"] == 40


def test_markdown_has_arabic_sections_and_redacts_secrets() -> None:
    digest = build_digest(
        now=NOW,
        scheduler_status={"kill_switch": True, "kill_reason": "leaked api_key=abcd1234efgh",
                          "active_hours": "08:00-20:00", "spent_today": 5, "daily_cap": 100},
        cycle_reports=[_report()],
        drift_alerts=[{"kind": "scope_drift", "host": "Authorization: Bearer zzzz1111qqqq",
                       "severity": "high", "note": "n"}],
    )
    md = digest["markdown"]
    for heading in ("تقرير CEM اليومي", "الجدولة والحدود", "التغيّرات الأخيرة",
                    "الحملات والانحدارات", "تنبيهات النطاق", "الذاكرة الطولية"):
        assert heading in md
    assert "abcdef123456" not in md and "abcd1234efgh" not in md
    assert "zzzz1111qqqq" not in md
    assert "[REDACTED_SECRET]" in md
    # the JSON twin carries no raw secrets either
    blob = json.dumps({k: v for k, v in digest.items() if k != "markdown"})
    assert "abcdef123456" not in blob and "zzzz1111qqqq" not in blob


def test_sections_bounded() -> None:
    reports = [
        {"target_id": f"t{i}", "change_count": 1, "spend": 1,
         "changes": {"changes": [{"field": "x", "kind": "added", "item": f"/p{i}",
                                  "classification": "SIGNAL_LOW"} for _ in range(3)]},
         "observed": []}
        for i in range(15)
    ]
    digest = build_digest(now=NOW, cycle_reports=reports)
    bullets = [line for line in digest["markdown"].splitlines() if line.startswith("- `")]
    assert len(bullets) <= MAX_LISTED_ITEMS
    assert len(digest["scope_alerts"]) <= MAX_LISTED_ITEMS
    assert digest["cycles_today"] == 15  # counts are not truncated, listings are


def test_garbage_inputs_degrade_to_empty_sections() -> None:
    digest = build_digest(now=NOW, cem_state="nope", cycle_reports=[42, None, "x"],
                          scheduler_status=3.14, reactor_active=None, regressed=None,
                          drift_alerts=[1, "junk"])
    assert digest["cycle_count"] == 0
    assert digest["cycles_today"] == 0
    assert digest["scope_alerts"] == []
    assert "لا تغيّرات تستحق الذكر" in digest["markdown"]


def test_markdown_hard_capped() -> None:
    huge = {"target_id": "t", "change_count": 1, "spend": 1,
            "changes": {"changes": [{"field": "x", "kind": "added",
                                     "item": "y" * 200, "classification": "NOISE"}]},
            "observed": []}
    digest = build_digest(now=NOW, cycle_reports=[huge] * 50)
    assert len(digest["markdown"]) <= MAX_MARKDOWN_CHARS


def test_write_digest_creates_both_files(tmp_path: Path) -> None:
    digest = build_digest(now=NOW)
    written = write_digest(digest, directory=tmp_path / "out")
    assert set(written) == {"digest.json", "digest.md"}
    payload = json.loads((tmp_path / "out" / "digest.json").read_text(encoding="utf-8"))
    assert payload["advisory"] is True
    assert (tmp_path / "out" / "digest.md").read_text(encoding="utf-8") == digest["markdown"]


def test_write_digest_survives_unwritable_directory() -> None:
    written = write_digest({}, directory="/proc/definitely/not/writable")
    assert written == {}


def test_write_digest_survives_unserializable_digest(tmp_path: Path) -> None:
    """RT83-8: a non-JSON-serializable digest degrades to empty, never raises."""
    written = write_digest({"digest": {"bad": object()}}, directory=tmp_path)
    assert written == {}


def test_wake_up_refusal_carries_advisory_flag(tmp_path: Path) -> None:
    """RT83-2: refusal dicts carry the same advisory flag as acceptance dicts."""
    from webpent.autonomous.cem.wake_up import WakeUpProtocol

    wake = WakeUpProtocol(tmp_path / "wake.json", daily_budget=100)
    wake.apply({"target_id": "t.example", "budget": 50}, now=1000.0)
    cooldown = wake.evaluate(
        {"target_id": "t.example", "top_signal": "critical", "changes": []},
        now=2000.0, remaining_budget=10,
    )
    assert cooldown == {"refusal": "cooldown", "target_id": "t.example", "advisory": True}
    budget = wake.evaluate(
        {"target_id": "t.other", "top_signal": "critical", "changes": []},
        now=2000.0, remaining_budget=0,
    )
    assert budget == {
        "refusal": "no_remaining_budget", "target_id": "t.other", "advisory": True,
    }
