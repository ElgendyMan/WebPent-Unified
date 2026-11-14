"""Retired-alias removal window (v0.32.0) — fail-closed removal gates +
the migrated API-level coverage for the v80 Task 3 mid-hunt recheck.

The 0.30.0 CHANGELOG (item ج.2) declared the removal window v0.32.0 for
the three retired CLI aliases ``scan`` / ``hunt-auto`` / ``hunt-plan``.
This file pins BOTH halves of that contract:

* the aliases are GONE from the CLI app (a silent re-addition fails the
  build — same fail-closed spirit as the frozen-module gate);
* the mid-hunt authorization recheck — whose closure used to live only
  inside the removed ``hunt-auto`` command — survives verbatim as the
  ``webpent.autonomous.make_authorization_recheck`` library API
  (re-reads the file every call; any read/parse failure is a typed
  reason, never a pass: CR-5 fail-closed).
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from typer.main import get_command
from typer.testing import CliRunner

from webpent.autonomous import DeadEndStore, IntelStore, make_authorization_recheck
from webpent.autonomous.hunt_runtime import run_wired_hunt
from webpent.cli import app as cli_app

runner = CliRunner()

RETIRED_ALIASES = ("scan", "hunt-auto", "hunt-plan")


# ---------------------------------------------------------------------------
# Removal gates (fail-closed): the aliases must not come back silently.
# ---------------------------------------------------------------------------


def _click_command_names() -> set[str]:
    click_app = get_command(cli_app)
    return set(click_app.commands)


@pytest.mark.parametrize("alias", RETIRED_ALIASES)
def test_retired_alias_is_not_a_registered_command(alias: str) -> None:
    assert alias not in _click_command_names(), (
        f"RETIRED ALIAS RE-ADDED: {alias!r} was removed by the v0.32.0 "
        "window (declared 2026-11-01, 0.30.0 CHANGELOG item ج.2). Re-adding "
        "it requires a new declared window — this gate fails closed."
    )


@pytest.mark.parametrize("alias", RETIRED_ALIASES)
def test_retired_alias_invocation_fails_closed(alias: str) -> None:
    result = runner.invoke(cli_app, [alias, "--url", "https://example.test/"])
    assert result.exit_code != 0, result.output
    assert "no such command" in result.output.lower()


def test_cli_help_does_not_advertise_retired_aliases() -> None:
    result = runner.invoke(cli_app, ["--help"])
    assert result.exit_code == 0, result.output
    for alias in RETIRED_ALIASES:
        assert f" {alias} " not in result.output


def test_unified_hunt_and_agent_hunt_remain_registered() -> None:
    names = _click_command_names()
    assert "hunt" in names, "the unified entry point must stay registered"
    assert "agent-hunt" in names, "the hunter CLI surface must stay registered"


# ---------------------------------------------------------------------------
# Migrated coverage: the v80 Task 3 mid-hunt recheck, now a library API.
# (The runtime-side "recheck reason stops the hunt BLOCKED" behavior stays
# pinned by tests/test_hunt_intel.py::test_auth_recheck_blocks_mid_hunt_*)
# ---------------------------------------------------------------------------


def _write_authorization(tmp_path: Path, target: str = "https://example.test") -> str:
    document = {
        "target_origin": target,
        "scope": [target],
        "operator": "cli-test",
        "authorization_reference": "AUTH-CLI-1",
    }
    path = tmp_path / "authorization.json"
    path.write_text(json.dumps(document), encoding="utf-8")
    return str(path)


def test_recheck_valid_authorization_returns_none(tmp_path: Path) -> None:
    path = _write_authorization(tmp_path)
    recheck = make_authorization_recheck(path, "https://example.test")
    assert recheck() is None


def test_recheck_replaced_authorization_fails_closed(tmp_path: Path) -> None:
    """v80 Task 3 verbatim: the file is re-read every call, never cached."""
    path = _write_authorization(tmp_path)
    recheck = make_authorization_recheck(path, "https://example.test")
    assert recheck() is None
    Path(path).write_text(
        json.dumps(
            {
                "target_origin": "https://example.test",
                "scope": ["https://example.test"],
                "operator": "someone-else",
                "authorization_reference": "AUTH-REVOKED",
                "expires_at": "2020-01-01T00:00:00Z",
            }
        ),
        encoding="utf-8",
    )
    reason = recheck()
    assert reason is not None
    assert "2020-01-01" in reason or "expired" in reason.lower() or "reason" in reason


def test_recheck_deleted_authorization_fails_closed(tmp_path: Path) -> None:
    """CR-5: the gate fails closed even when the file vanishes entirely."""
    path = _write_authorization(tmp_path)
    recheck = make_authorization_recheck(path, "https://example.test")
    Path(path).unlink()
    reason = recheck()
    assert reason is not None
    assert "unreadable" in reason


def test_recheck_corrupt_authorization_fails_closed(tmp_path: Path) -> None:
    path = tmp_path / "authorization.json"
    path.write_text("{corrupt", encoding="utf-8")
    recheck = make_authorization_recheck(path, "https://example.test")
    reason = recheck()
    assert reason is not None
    assert "unreadable" in reason


def test_recheck_out_of_scope_authorization_returns_reason(tmp_path: Path) -> None:
    path = _write_authorization(tmp_path, target="https://authorized.example")
    recheck = make_authorization_recheck(path, "https://unauthorized.example")
    reason = recheck()
    assert reason is not None


# ---------------------------------------------------------------------------
# Migrated wiring parity: intel + dead-ends stores ride a bounded hunt at
# the API level exactly as they did through the removed CLI flags.
# ---------------------------------------------------------------------------


def test_wired_hunt_with_stores_stops_bounded_and_persists_files(
    tmp_path: Path,
) -> None:
    intel_path = tmp_path / "intel.json"
    deadends_path = tmp_path / "deadends.json"
    authorization = _write_authorization(tmp_path)

    state = run_wired_hunt(
        engagement_id="api-e1",
        campaign_id="api-h1",
        target_url="https://example.test/",
        auth_recheck=make_authorization_recheck(authorization, "https://example.test/"),
        intel=IntelStore(intel_path),
        deadends=DeadEndStore(deadends_path),
    )
    summary = state.summary()
    # No target knowledge and a soft-failed bootstrap on a non-resolving
    # host: bounded inconclusive stop, zero proof bundles, no requests.
    assert summary["outcome"] == "inconclusive"
    assert summary["stop_reason"] == "no_new_ready_task"
    assert summary["counts"]["proof_bundles"] == 0
    # CR-2 / v81 Task 4 parity: a hunt with no proof bundles records
    # nothing — both stores end up saved but empty, never polluting the
    # bounded memory with an empty origin entry.
    assert intel_path.is_file(), "the intel store must be saved after the hunt"
    assert json.loads(intel_path.read_text(encoding="utf-8")) == {}
    assert deadends_path.is_file(), "the dead-end store must be saved after the hunt"
    assert json.loads(deadends_path.read_text(encoding="utf-8")) == {}
