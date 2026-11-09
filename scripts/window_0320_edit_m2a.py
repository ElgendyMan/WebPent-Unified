#!/usr/bin/env python3
"""RETIRED-ALIAS REMOVAL window (v0.32.0) — one-shot surgical edit of
``tests/team1_acceptance/test_m2a_exit_code_honesty.py``.

The exit-code honesty contract for surfaces REMOVED by the window dies
with them; the contract for surviving surfaces stays:

  * delete ``_hunt_args`` + ``TestHuntCliExitCodeHonesty`` (the
    ``hunt-plan --target`` CLI surface was removed by the window; the
    same ``run_hunter_campaign`` gate stays covered through
    ``TestAgentHuntCliExitCodeHonesty``);
  * delete ``TestScanCliExitCodeHonesty`` (the ``scan`` full-graph CLI
    surface was removed by the window);
  * sweep: drop the two scan-source pins, re-pin the honesty-call count
    to the surviving surfaces.

Fail-closed: every deletion range is anchored before writing.
"""
from __future__ import annotations

from pathlib import Path

TARGET = (
    Path(__file__).resolve().parents[1]
    / "tests/team1_acceptance/test_m2a_exit_code_honesty.py"
)

DELETIONS = [
    # def _hunt_args ... TestHuntCliExitCodeHonesty (up to TestAgentHunt)
    (136, 199, "def _hunt_args(scope_file: Path) -> list[str]:"),
    # class TestScanCliExitCodeHonesty (up to the sweep banner comment)
    (228, 316, "class TestScanCliExitCodeHonesty:"),
]

SWEEP_OLD = '''    def test_hunt_target_gate_present(self):
        src = self._source("src/webpent/cli/commands.py")
        assert src.count("_enforce_chain_honesty(") >= 3, (
            "hunt --target and agent-hunt must both enforce chain honesty"
        )

    def test_scan_graph_gate_before_success_panel(self):
        src = self._source("src/webpent/cli/commands.py")
        gate_at = src.find("_chain_honesty_verdict(final_state)")
        panel_at = src.find("Engagement Completed[/bold green]")
        assert gate_at != -1 and panel_at != -1
        assert gate_at < panel_at, (
            "the scan honesty gate must run BEFORE the success panel"
        )

    def test_adapter_free_gate_present(self):
        src = self._source("src/webpent/cli/commands.py")
        assert "SCAN (adapter-free) FAILED" in src
'''

SWEEP_NEW = '''    def test_agent_hunt_gate_present(self):
        src = self._source("src/webpent/cli/commands.py")
        # v0.32.0 retired-alias removal: the scan/hunt-plan surfaces are
        # gone; agent-hunt is the surviving direct-spine surface and must
        # still enforce chain honesty. The unified `hunt` summary path is
        # a declared future-window candidate for its own gate.
        assert src.count("_enforce_chain_honesty(") >= 1, (
            "agent-hunt must enforce chain honesty"
        )
'''

DOCSTRING_OLD = """  * direct-spine surfaces (hunt --target, agent-hunt): incomplete or
    absent trace → non-zero exit + loud operator-visible error naming the
    missing stages and pointing at the trace;
  * graph surfaces (scan full-graph, worker): the research-campaign
    lane's markers are the completeness authority — skip marker or a
    missing executed-marker → non-zero exit / loud non-success status;
"""

DOCSTRING_NEW = """  * direct-spine surfaces (agent-hunt — the scan/hunt-plan surfaces were
    removed by the v0.32.0 retired-alias window): incomplete or absent
    trace → non-zero exit + loud operator-visible error naming the
    missing stages and pointing at the trace;
  * worker: the research-campaign lane's markers are the completeness
    authority — skip marker or a missing executed-marker → loud
    non-success status;
"""


def main() -> int:
    text = TARGET.read_text(encoding="utf-8")
    for marker in ("def _hunt_args(", "class TestScanCliExitCodeHonesty:"):
        if marker not in text:
            print(f"ABORT: {marker!r} missing")
            return 1
    if SWEEP_OLD not in text or DOCSTRING_OLD not in text:
        print("ABORT: sweep/docstring blocks not found verbatim")
        return 1

    lines = text.splitlines(keepends=True)
    for start, end, marker in sorted(DELETIONS, reverse=True):
        chunk = "".join(lines[start - 1 : end])
        if marker not in chunk:
            print(f"ABORT (pre-delete): anchor {marker!r} lost at {start}-{end}")
            return 1
        del lines[start - 1 : end]
    out = "".join(lines)
    out = out.replace(SWEEP_OLD, SWEEP_NEW)
    out = out.replace(DOCSTRING_OLD, DOCSTRING_NEW)

    for gone in ("_hunt_args", "TestScanCliExitCodeHonesty", "TestHuntCliExitCodeHonesty"):
        if gone in out:
            print(f"ABORT (post-check): {gone!r} still present")
            return 1
    for keep in (
        "class TestAgentHuntCliExitCodeHonesty:",
        "class TestSilentZeroExitSweep:",
        "class TestGraphPathVerdict:",
        "class TestWorkerStatusHonesty:",
        "_chain_honesty_verdict",
    ):
        if keep not in out:
            print(f"ABORT (post-check): keeper {keep!r} lost")
            return 1

    TARGET.write_text(out, encoding="utf-8")
    print(f"OK: m2a edited ({len(text.splitlines())} -> {len(out.splitlines())} lines)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
