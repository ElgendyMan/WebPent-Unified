"""U-DRYRUN-1 — Rehearsal protocol tests (6 tests)."""

from __future__ import annotations

from pathlib import Path

import pytest

from rehearsal import RehearsalProtocol, RehearsalReport

# Local emulator targets only — every rehearsal endpoint is localhost.
EMULATOR_TARGETS = [
    {"name": "juice-shop", "url": "http://localhost:3000",
     "kind": "vulnerable app"},
    {"name": "custom-api", "url": "http://localhost:9000",
     "kind": "training API"},
    {"name": "waf", "url": "http://localhost:80",
     "kind": "waf-fronted app"},
]


class FakeRange:
    """A range stub shaped like the emulator's target list."""

    def __init__(self, targets: list[dict[str, str]]) -> None:
        self._targets = targets

    def targets(self) -> list[dict[str, str]]:
        return self._targets


@pytest.fixture
def range_stub() -> FakeRange:
    return FakeRange(EMULATOR_TARGETS)


def _rehearse_days_one_to_four(ws: Path, protocol: RehearsalProtocol,
                               range_stub: FakeRange) -> None:
    protocol.start(range_stub)
    protocol.set_predictions([3, 6], [0.3, 0.6])
    protocol.complete_day(1, outputs=["pre_registration.md"])
    protocol.run_day(2)
    for target in protocol.state.frozen_targets:
        protocol.record_run(target["name"], hours=8.0)
    protocol.complete_day(2, outputs=["runs/"])
    protocol.run_day(3)
    protocol.register_finding("r-1", "juice-shop", "sqli")
    protocol.register_finding("r-2", "custom-api", "idor")
    protocol.classify_finding("r-1", "confirmed", note="blocker worked")
    protocol.classify_finding("r-2", "false_positive", note="not in scope")
    protocol.complete_day(3, outputs=["analysis.md"])
    protocol.run_day(4)
    protocol.add_lesson(4, "issue", "rate limiter throttled the burst scan")
    protocol.add_lesson(4, "adjustment", "drop to 4 r/s on real targets")
    protocol.complete_day(4, outputs=["refinement_notes.md"])


def test_rehearsal_full_flow(tmp_path: Path, range_stub: FakeRange) -> None:
    protocol = RehearsalProtocol(tmp_path / "rehearsal")
    _rehearse_days_one_to_four(tmp_path, protocol, range_stub)
    protocol.run_day(5)
    protocol.complete_day(5, outputs=["final_analysis.md", "playbook.md"])
    report = protocol.finish()
    assert isinstance(report, RehearsalReport)
    text = report.to_markdown()
    assert "# Verdict Dry Run Report" in text
    assert "Runs: 3" in text
    assert "Findings: 2" in text
    assert "Lessons: 2" in text
    assert "juice-shop, custom-api, waf" in text


def test_daily_runs(tmp_path: Path, range_stub: FakeRange) -> None:
    protocol = RehearsalProtocol(tmp_path / "rehearsal")
    protocol.start(range_stub)
    protocol.set_predictions([3, 6], [0.3, 0.6])
    protocol.complete_day(1, outputs=["pre_registration.md"])
    protocol.run_day(2)
    protocol.record_run("juice-shop", 8.0)
    with pytest.raises(RuntimeError, match="one run per frozen target"):
        protocol.run_day(3)
    protocol.record_run("custom-api", 8.0)
    protocol.record_run("waf", 8.0)
    protocol.complete_day(2, outputs=["runs/"])
    protocol.run_day(3)  # now day 3 opens


def test_analysis_generated(tmp_path: Path, range_stub: FakeRange) -> None:
    protocol = RehearsalProtocol(tmp_path / "rehearsal")
    protocol.start(range_stub)
    protocol.set_predictions([3, 6], [0.3, 0.6])
    protocol.complete_day(1, outputs=["pre_registration.md"])
    protocol.run_day(2)
    for target in protocol.state.frozen_targets:
        protocol.record_run(target["name"], 8.0)
    protocol.complete_day(2, outputs=["runs/"])
    protocol.run_day(3)
    protocol.register_finding("r-1", "juice-shop", "sqli")
    with pytest.raises(RuntimeError, match="classified"):
        protocol.run_day(4)
    protocol.classify_finding("r-1", "inconclusive",
                              note="waf ate the probe")
    with pytest.raises(ValueError, match="immutable"):
        protocol.classify_finding("r-1", "confirmed")
    protocol.complete_day(3, outputs=["analysis.md"])
    protocol.run_day(4)


def test_playbook_produced(tmp_path: Path, range_stub: FakeRange) -> None:
    protocol = RehearsalProtocol(tmp_path / "rehearsal")
    _rehearse_days_one_to_four(tmp_path, protocol, range_stub)
    protocol.run_day(5)
    protocol.complete_day(5, outputs=["final_analysis.md", "playbook.md"])
    protocol.finish()
    playbook = protocol.generate_playbook()
    assert "The Verdict Playbook" in playbook
    assert "4 r/s" in playbook  # a real recorded lesson appears in it


def test_no_real_targets_needed(tmp_path: Path,
                                range_stub: FakeRange) -> None:
    protocol = RehearsalProtocol(tmp_path / "rehearsal")
    protocol.start(range_stub)
    for target in protocol.state.frozen_targets:
        assert target["url"].startswith("http://localhost")
    # nothing in the state references anything outside the emulator range
    text = protocol.state_path.read_text(encoding="utf-8")
    assert "hackerone" not in text and "bugcrowd" not in text
    assert "yeswehack" not in text


def test_emulator_integration(tmp_path: Path) -> None:
    """The protocol consumes the real emulator CLI's target list."""
    import sys
    emulator_dir = tmp_path / "emulator"
    emulator_dir.mkdir()
    (emulator_dir / "emulator_cli.py").write_text(
        "TARGETS = [('juice-shop', 'http://localhost:3000', 'app'),\n"
        "            ('waf', 'http://localhost:80', 'waf')]\n",
        encoding="utf-8")
    sys.path.insert(0, str(emulator_dir))
    try:
        import emulator_cli

        class LiveRange:
            def targets(self) -> list[dict[str, str]]:
                return [{"name": name, "url": url, "kind": note}
                        for name, url, note in emulator_cli.TARGETS]

        protocol = RehearsalProtocol(tmp_path / "rehearsal")
        protocol.start(LiveRange())
        assert [t["name"] for t in protocol.state.frozen_targets] == \
            ["juice-shop", "waf"]
        # day 2 cannot open without day 1's predictions and completion
        with pytest.raises(RuntimeError, match="pre-registration"):
            protocol.run_day(2)
        protocol.set_predictions([2, 4], [0.3, 0.6])
        with pytest.raises(RuntimeError, match="day 1 is not complete"):
            protocol.run_day(2)
    finally:
        sys.path.remove(str(emulator_dir))
