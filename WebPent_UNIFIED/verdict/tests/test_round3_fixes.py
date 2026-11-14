"""Round-3 red-team fixes — regression tests (F-1..F-5).

Each test here was written RED first (it failed against the pre-fix
code, reproduced in the Round-3 war games) and must stay green after
the fix:

- F-1  tamper detection on .verdict/state.json (CRITICAL)
- F-2  pre-registration predictions frozen after day 0 (HIGH)
- F-3  pre_registration.md hash recorded at freeze and verified at
       verdict time (HIGH)
- F-4  re-test evidence paths must exist in the workspace (MEDIUM-HIGH)
- F-5  the day-14 selection is immutable once frozen (MEDIUM)
"""

from __future__ import annotations

import hashlib

import pytest
from click.testing import CliRunner
from verdict_tool.classifier import ClassificationError, FindingClassifier
from verdict_tool.cli import cli
from verdict_tool.tracking import Workspace

runner = CliRunner()


def invoke(ws: Workspace, *args: str):
    return runner.invoke(cli, ["--path", str(ws.root), *args])


@pytest.fixture
def classifier(ws: Workspace) -> FindingClassifier:
    return FindingClassifier(ws.load(), ws)


def frozen_ws(ws: Workspace) -> None:
    """Take an initialized workspace to a frozen pre-registration."""
    (ws.root / "pre_registration.md").write_text(
        "# Pre-Registration\n\nPredictions: 5-15 findings, 20-50% "
        "acceptance.\n", encoding="utf-8")
    result = invoke(ws, "pre-registration", "done")
    assert result.exit_code == 0, result.output


def register_confirmed(ws: Workspace, count: int = 5,
                       prefix: str = "f") -> list[str]:
    """Register and confirm `count` findings with real evidence files."""
    evidence_dir = ws.root / "shots"
    evidence_dir.mkdir(parents=True, exist_ok=True)
    (evidence_dir / "evidence.png").write_bytes(b"png")
    state = ws.load()
    classifier = FindingClassifier(state, ws)
    ids = []
    for i in range(count):
        fid = f"{prefix}-{i}"
        classifier.register(fid, "target_a", "sqli", "high", 0.9)
        classifier.classify(fid, "confirmed",
                            re_test_evidence=["shots/evidence.png"],
                            impact_confirmed="data exposure")
        ids.append(fid)
    return ids


# -- F-1: tamper detection on state.json -------------------------------------


def test_tampered_state_detected(ws: Workspace) -> None:
    from verdict_tool.tracking import StateTamperError
    state = ws.load()
    ws.save(state)
    raw = ws.state_path.read_text(encoding="utf-8")
    tampered = raw.replace('"version": 1', '"version": 2')
    assert tampered != raw
    ws.state_path.write_text(tampered, encoding="utf-8")
    with pytest.raises(StateTamperError):
        ws.load()


def test_missing_integrity_record_detected(ws: Workspace) -> None:
    from verdict_tool.tracking import StateTamperError
    state = ws.load()
    ws.save(state)
    (ws.root / ".verdict" / "state.sha256").unlink()
    with pytest.raises(StateTamperError):
        ws.load()


def test_honest_roundtrip_still_works(ws: Workspace) -> None:
    state = ws.load()
    state.selection = ["f-0", "f-1"]
    ws.save(state)
    reloaded = ws.load()
    assert reloaded.selection == ["f-0", "f-1"]


# -- F-2: predictions frozen after day 0 ---------------------------------------


def test_predict_after_freeze_refused(ws: Workspace) -> None:
    invoke(ws, "pre-registration", "predict", "--findings", "5", "15",
           "--acceptance", "0.2", "0.5")
    frozen_ws(ws)
    result = invoke(ws, "pre-registration", "predict",
                    "--findings", "1", "2",
                    "--acceptance", "0.9", "1.0")
    assert result.exit_code != 0
    assert "frozen" in result.output.lower()


def test_prereg_edit_after_freeze_refused(ws: Workspace) -> None:
    frozen_ws(ws)
    result = invoke(ws, "pre-registration", "edit")
    assert result.exit_code != 0
    assert "frozen" in result.output.lower()


# -- F-3: pre_registration.md is hashed and verified ---------------------------


def test_prereg_hash_recorded_at_freeze(ws: Workspace) -> None:
    frozen_ws(ws)
    state = ws.load()
    assert state.pre_registration_sha256, "freeze must record a hash"
    expected = hashlib.sha256(
        (ws.root / "pre_registration.md").read_bytes()).hexdigest()
    assert state.pre_registration_sha256 == expected


def test_verdict_refused_when_prereg_modified(ws: Workspace) -> None:
    frozen_ws(ws)
    pre_reg = ws.root / "pre_registration.md"
    pre_reg.write_text(
        pre_reg.read_text(encoding="utf-8")
        + "\nEdited AFTER the freeze: predicted 100 findings.\n",
        encoding="utf-8",
    )
    result = invoke(ws, "verdict", "final")
    assert result.exit_code != 0
    assert "pre-registration" in result.output.lower()


# -- F-4: evidence paths must exist -----------------------------------------------


def test_nonexistent_evidence_refused(classifier: FindingClassifier) -> None:
    classifier.register("f-1", "target_a", "sqli", "high", 0.9)
    with pytest.raises(ClassificationError, match="do not exist"):
        classifier.classify(
            "f-1", "confirmed",
            re_test_evidence=["runs/was-never-taken.txt"],
            impact_confirmed="i",
        )


def test_existing_evidence_accepted(classifier: FindingClassifier) -> None:
    classifier.register("f-1", "target_a", "sqli", "high", 0.9)
    record = classifier.classify(
        "f-1", "confirmed", re_test_evidence=["e.png"],
        impact_confirmed="i",
    )
    assert record.classification == "confirmed"


# -- F-5: selection is immutable -------------------------------------------------


def test_selection_cannot_be_refrozen(ws: Workspace) -> None:
    invoke(ws, "init")
    ids = register_confirmed(ws)
    first = invoke(ws, "select", *ids)
    assert first.exit_code == 0, first.output
    second = invoke(ws, "select", *reversed(ids))
    assert second.exit_code != 0
    assert "already frozen" in second.output.lower()
    state = ws.load()
    assert state.selection == ids
