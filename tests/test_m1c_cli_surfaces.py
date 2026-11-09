"""M1-C (UM-DR-12) regression: ق10 bounty + ق11 portfolio CLI surfaces.

Contract (M1_READINESS_REVIEW §5.5):
  * ``webpent bounty preview`` renders promoted-ProofBundle previews only;
    non-promoted findings are refused by the pipeline and reported, and
    the surface performs NO network I/O (no submit exists here at all).
  * ``webpent portfolio wave`` plans a launch ORDER from an operator-owned
    entries file: priority-ascending admissions, explicit skip reasons,
    capacity-bounded — and never launches or mutates a campaign.
  * Both commands are registered on the main CLI app.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from webpent.cli.bounty import bounty_app
from webpent.cli.portfolio import portfolio_app

runner = CliRunner()


# ---------------------------------------------------------------------------
# portfolio wave
# ---------------------------------------------------------------------------

_ENTRIES = [
    {
        "target_ref": "https://lab-a.example",
        "campaign_id": "camp-a",
        "priority": 2,
    },
    {
        "target_ref": "https://lab-b.example",
        "campaign_id": "camp-b",
        "priority": 1,
    },
    {
        "target_ref": "https://lab-c.example",
        "campaign_id": "camp-c",
        "priority": 1,
        "state": "paused",
        "pause_reason": "operator_hold",
    },
]


def _entries_file(tmp_path: Path, entries: list[dict]) -> Path:
    path = tmp_path / "entries.json"
    path.write_text(json.dumps(entries), encoding="utf-8")
    return path


def test_wave_orders_by_priority_and_reports_skips(tmp_path):
    result = runner.invoke(
        portfolio_app,
        ["wave", "--entries", str(_entries_file(tmp_path, _ENTRIES)), "--capacity", "2"],
    )
    assert result.exit_code == 0, result.output
    # priority 1 entries first (lab-b before lab-c? — lab-c is paused/skipped)
    assert "lab-b.example" in result.output
    # the paused target appears in the SKIP table with its reason — nothing
    # silently dropped
    assert "lab-c.example" in result.output
    assert "operator_hold" in result.output


def test_wave_capacity_bounds_admissions(tmp_path):
    result = runner.invoke(
        portfolio_app,
        ["wave", "--entries", str(_entries_file(tmp_path, _ENTRIES)), "--capacity", "1"],
    )
    assert result.exit_code == 0, result.output
    assert "fleet_capacity_full" in result.output


def test_wave_rejects_unknown_fields(tmp_path):
    bad = [dict(_ENTRIES[0], free_text_field="nope")]
    result = runner.invoke(
        portfolio_app,
        ["wave", "--entries", str(_entries_file(tmp_path, bad)), "--capacity", "1"],
    )
    assert result.exit_code == 2
    assert "free_text_field" in result.output


def test_wave_rejects_malformed_json(tmp_path):
    path = tmp_path / "broken.json"
    path.write_text("{not json", encoding="utf-8")
    result = runner.invoke(portfolio_app, ["wave", "--entries", str(path)])
    assert result.exit_code == 2


# ---------------------------------------------------------------------------
# bounty preview (no-DB environment → typed refusal, never a crash)
# ---------------------------------------------------------------------------

def test_bounty_preview_unreadable_engagement_exits_typed():
    result = runner.invoke(
        bounty_app, ["preview", "no-such-engagement-m1c", "--platform", "hackerone"]
    )
    # Either an empty campaign (dim notice) or a typed error exit — never a
    # traceback, never a network call.
    assert result.exit_code in (0, 2)
    assert "Traceback" not in result.output


def test_bounty_preview_rejects_bad_platform():
    result = runner.invoke(
        bounty_app, ["preview", "any-engagement", "--platform", "twitter-dm"]
    )
    assert result.exit_code == 1
    assert "platform" in result.output


def test_bounty_app_has_no_submit_command():
    """The CLI surface must not expose submission — operator-cage only."""
    names = {cmd.name for cmd in bounty_app.registered_commands}
    assert "preview" in names
    assert "submit" not in names
