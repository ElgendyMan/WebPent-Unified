"""U-DRYRUN-2 — Playbook generator tests (4 tests)."""

from __future__ import annotations

from pathlib import Path

from playbook import PlaybookGenerator

from rehearsal import RehearsalProtocol, RehearsalState

EMULATOR_TARGETS = [
    {"name": "juice-shop", "url": "http://localhost:3000",
     "kind": "vulnerable app"},
    {"name": "custom-api", "url": "http://localhost:9000",
     "kind": "training API"},
    {"name": "waf", "url": "http://localhost:80",
     "kind": "waf-fronted app"},
]


class StubRange:
    def targets(self) -> list[dict[str, str]]:
        return EMULATOR_TARGETS


def _state_with_lessons() -> RehearsalProtocol:
    protocol = RehearsalProtocol(Path("/tmp") / "playbook-test")
    protocol.state.started_at = "2026-10-01T00:00:00+00:00"
    protocol.state.frozen_targets = EMULATOR_TARGETS
    protocol.add_lesson(1, "lesson", "freeze targets before writing "
                        "predictions")
    protocol.add_lesson(2, "lesson", "waf paranoia 2 blocks the recon "
                        "phase")
    protocol.add_lesson(3, "lesson", "most findings were duplicates of "
                        "the same root cause")
    protocol.add_lesson(4, "issue", "rate limiter throttled the burst "
                        "scan")
    protocol.add_lesson(4, "issue", "one target returned 500s under "
                        "load")
    protocol.add_lesson(4, "adjustment", "drop to 4 r/s on real targets")
    protocol.add_lesson(4, "adjustment", "back off when HTTP 500 appears")
    protocol.add_lesson(5, "lesson", "prediction ranges were too narrow")
    protocol.add_lesson(5, "red_flag", "waf challenges with no audit "
                        "trail")
    protocol.add_lesson(5, "green_flag", "clean 200s on low-rate probes")
    protocol.add_lesson(5, "lesson", "slow pages look like waf blocks "
                        "but are just latency",
                        real_implication="timeouts under 30s are latency, "
                        "not blocking")
    return protocol


def test_playbook_generated(tmp_path: Path) -> None:
    protocol = _state_with_lessons()
    generator = PlaybookGenerator(protocol.state)
    out_path = generator.write(tmp_path / "playbook.md")
    assert out_path.is_file()
    text = out_path.read_text(encoding="utf-8")
    assert text.startswith("# The Verdict Playbook")
    assert "## Lessons from the Dry Run" in text
    assert "Generated" in text


def test_playbook_includes_lessons(tmp_path: Path) -> None:
    protocol = _state_with_lessons()
    text = PlaybookGenerator(protocol.state).generate()
    assert "freeze targets before writing predictions" in text
    assert "drop to 4 r/s on real targets" in text
    assert "waf challenges with no audit trail" in text
    assert "clean 200s on low-rate probes" in text
    # if-dry-run-showed mapping with the recorded implication
    assert ("If the dry run showed slow pages look like waf blocks but "
            "are just latency, then in the real run expect timeouts "
            "under 30s are latency, not blocking.") in text


def test_playbook_has_all_days(tmp_path: Path) -> None:
    protocol = _state_with_lessons()
    text = PlaybookGenerator(protocol.state).generate()
    for header in ("### Before you start", "### Day 1 — Target selection",
                   "### Day 2 — Environment", "### Day 3-4 — Run",
                   "### Day 5 — Analysis", "### Red flags to watch for",
                   "### Green flags"):
        assert header in text, f"missing section: {header}"
    assert "Common issues:" in text
    assert "Recommended adjustments:" in text


def test_playbook_readable(tmp_path: Path) -> None:
    """No template placeholders left once lessons exist."""
    protocol = _state_with_lessons()
    text = PlaybookGenerator(protocol.state).generate()
    assert "{" not in text and "TODO" not in text and "XXX" not in text
    for line in text.splitlines():
        stripped = line.strip()
        if stripped.startswith(("-", "1.", "2.")):
            assert stripped not in ("-", "", "1. ", "2. ")
    # the empty-state fallback wording is only for genuinely empty parts
    empty = PlaybookGenerator(RehearsalState()).generate()
    assert "(none recorded yet)" in empty
