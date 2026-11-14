# tests/test_autonomous_hunt_cli.py
"""The autonomous hunt CLI surface — aligned to the UNIFIED command.

UM-DR-25 (red-team window 2026-11-06) reconciliation: this file
originally drove the retired ``hunt-auto`` command (retired by the
Ultimate plan 2026-10-27 proposal 1: "one command, three modes" —
``scan``/``hunt-auto``/``hunt-plan`` were folded into ``hunt``). The
tests below preserve the ORIGINAL protective intent against the
implemented surface:

  * the retired alias is GONE (clean "No such command", help points
    at the unified ``hunt``) — retirement must not silently resurrect;
  * ``hunt`` is authorization-first: it refuses to construct without
    ``--authorization`` (fail-closed, no runtime, no network);
  * the unified modes are the documented three;
  * a nonexistent mode is refused typed, not defaulted.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest
from typer.testing import CliRunner

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from webpent.cli import app  # noqa: E402

runner = CliRunner()


def _write_authorization(tmp_path, target="https://example.test"):
    document = {
        "target_origin": target,
        "scope": [target],
        "operator": "cli-test",
        "authorization_reference": "AUTH-CLI-1",
    }
    path = Path(tmp_path) / "authorization.json"
    path.write_text(json.dumps(document), encoding="utf-8")
    return str(path)


# ---------------------------------------------------------------------------
# The retirement contract
# ---------------------------------------------------------------------------
def test_retired_hunt_auto_alias_is_gone() -> None:
    result = runner.invoke(app, ["hunt-auto", "--url", "https://example.test/"])
    assert result.exit_code != 0
    assert "No such command" in result.output
    # the error UX points at the surviving unified command
    assert "hunt" in result.output


def test_retired_scan_alias_is_gone() -> None:
    result = runner.invoke(app, ["scan", "--url", "https://example.test/"])
    assert result.exit_code != 0
    assert "No such command" in result.output


def test_unified_hunt_is_registered() -> None:
    result = runner.invoke(app, ["hunt", "--help"])
    assert result.exit_code == 0
    for mode in ("quick", "standard", "deep"):
        assert mode in result.output


# ---------------------------------------------------------------------------
# Authorization-first (the fail-closed core the old suite protected)
# ---------------------------------------------------------------------------
def test_hunt_refuses_without_authorization() -> None:
    result = runner.invoke(app, ["hunt", "--url", "https://example.test/"])
    assert result.exit_code != 0
    assert "--authorization" in result.output


def test_hunt_refuses_unreadable_scope_file(tmp_path) -> None:
    missing = str(Path(tmp_path) / "does-not-exist.scope")
    result = runner.invoke(
        app,
        [
            "hunt",
            "--url", "https://example.test/",
            "--authorization", "AUTH-CLI-1",
            "--scope-file", missing,
        ],
    )
    # fail-closed: never proceeds past an unreadable scope file
    assert result.exit_code != 0


def test_hunt_refuses_unreadable_authorization_manifest(tmp_path) -> None:
    missing = str(Path(tmp_path) / "does-not-exist-manifest.json")
    result = runner.invoke(
        app,
        [
            "hunt",
            "--url", "https://example.test/",
            "--authorization", "AUTH-CLI-1",
            "--authorization-manifest", missing,
        ],
    )
    # fail-closed: never proceeds past an unreadable manifest
    assert result.exit_code != 0


def test_hunt_refuses_out_of_scope_target(tmp_path) -> None:
    # Scope file authorizes a DIFFERENT origin than the requested URL.
    scope = Path(tmp_path) / "other.scope"
    scope.write_text("allow https://other.test\n", encoding="utf-8")
    result = runner.invoke(
        app,
        [
            "hunt",
            "--url", "https://example.test/",
            "--authorization", "AUTH-CLI-1",
            "--scope-file", str(scope),
        ],
    )
    assert result.exit_code != 0


def test_hunt_refuses_invalid_mode(tmp_path) -> None:
    authorization = _write_authorization(tmp_path)
    result = runner.invoke(
        app,
        [
            "hunt",
            "--url", "https://example.test/",
            "--authorization", authorization,
            "--mode", "not-a-real-mode",
        ],
    )
    assert result.exit_code != 0


# ---------------------------------------------------------------------------
# The unified modes are wired and distinct
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("mode", ["quick", "standard", "deep"])
def test_hunt_modes_accepted_at_parse_level(tmp_path, mode) -> None:
    """The three documented modes parse; further execution requires the
    full runtime (network/DB), which unit tests never drive — the dry
    refusal paths above are the CLI-level contract."""
    authorization = _write_authorization(tmp_path)
    result = runner.invoke(
        app,
        [
            "hunt",
            "--url", "https://example.test/",
            "--authorization", authorization,
            "--mode", mode,
        ],
    )
    # Parsing succeeded (not a usage error). Any failure beyond this is a
    # runtime/environment matter, never a "No such option --mode" one.
    assert "No such option" not in result.output
    assert "Invalid value" not in result.output


def test_help_mentions_authorization_requirement() -> None:
    result = runner.invoke(app, ["hunt", "--help"])
    assert result.exit_code == 0
    assert "REQUIRED" in result.output or "authorization" in result.output.lower()
