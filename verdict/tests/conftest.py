"""Fixtures for the Verdict tool test suite."""

from __future__ import annotations

import sys
from pathlib import Path

VERDICT_DIR = Path(__file__).resolve().parents[1]
if str(VERDICT_DIR) not in sys.path:
    sys.path.insert(0, str(VERDICT_DIR))

import pytest  # noqa: E402
from verdict_tool.tracking import Workspace, new_state  # noqa: E402

VALID_TARGET_YAML = """\
target:
  name: {name}
  platform: hackerone
  program_url: https://example.com/security
  program_handle: {handle}

scope:
  in_scope:
    - "*.example.com"
  out_of_scope:
    - "blog.example.com"
  excluded_methods:
    - destructive

policy:
  automation_allowed: true
  max_rate_rps: 5
  safe_harbor: true
  notes: "authorization on file"

credentials:
  has_test_account: false

output:
  run_dir: runs/{name}/
  log_level: INFO

metadata:
  legal_review_completed: true
  reviewed_by: operator
  added_at: "2026-10-18"
"""


def write_target_yaml(directory: Path, name: str = "target_a",
                      handle: str = "handle_a") -> Path:
    path = directory / f"{name}.yaml"
    path.write_text(
        VALID_TARGET_YAML.format(name=name, handle=handle), encoding="utf-8")
    return path


def make_evidence_files(workspace: Workspace) -> None:
    """Create the evidence paths the tests reference (F-4: paths must exist)."""
    for rel in ("e.png", "shots/f.png", "shots/f1.png"):
        path = workspace.root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(b"png")


@pytest.fixture
def ws(tmp_path: Path) -> Workspace:
    """An initialized Verdict workspace."""
    workspace = Workspace(tmp_path / "verdict_ws")
    workspace.ensure_dirs()
    state = new_state()
    workspace.save(state)
    make_evidence_files(workspace)
    return workspace


@pytest.fixture
def target_yaml(tmp_path: Path) -> Path:
    return write_target_yaml(tmp_path)
