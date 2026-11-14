"""v85 red-team regression tests (plan: docs/plans/2026-10-16-v85-red-team.md).

One test per confirmed defect, written failing-first, fixed in plan order.
"""

from __future__ import annotations

from datetime import datetime, timezone

from webpent.jc.chamber import CouncilChamber
from webpent.jc.contracts import Argument, Evidence
from webpent.jc.judge import Judge
from webpent.jc.memory import CouncilMemory
from webpent.jc.skeptic import Skeptic

NOW = datetime(2026, 10, 16, 12, 0, 0, tzinfo=timezone.utc)
NOW_TS = 1_760_000_000.0


def test_judge_survives_all_zero_scores():
    """RT-01: hollow argument (evidence=[]) must not crash close()."""
    ch = CouncilChamber(skeptic=Skeptic(), judge=Judge(), now=NOW)
    session = ch.convene("should we escalate?", {"target_id": "lab-01"})
    ch.submit_argument(
        session.session_id,
        Argument(
            advocate_id="tactician",
            claim="do-x",
            evidence=[],
            reasoning="nothing cited",
            confidence=0.5,
            alternatives=["wait"],
            timestamp=NOW,
        ),
    )
    verdict = ch.close(session.session_id)
    assert verdict.escalate is True
    assert verdict.confidence == 0.0


def _recorded_session(tmp_path, question: str = "q?"):
    ch = CouncilChamber(skeptic=Skeptic(), judge=Judge(), now=NOW)
    session = ch.convene(question, {"target_id": "lab-01"})
    for _order, (aid, claim) in enumerate(
        [("tactician", "do-x"), ("historian", "wait")]
    ):
        ch.submit_argument(
            session.session_id,
            Argument(
                advocate_id=aid,
                claim=claim,
                evidence=[
                    Evidence(kind="signal", content=f"e-{aid}",
                             source="scanner-1", observed_at=NOW,
                             confidence=0.8, specificity=0.8)
                ],
                reasoning="because",
                confidence=0.7,
                alternatives=["wait"],
                timestamp=NOW,
            ),
        )
    verdict = ch.close(session.session_id)
    memory = CouncilMemory(tmp_path / "memory.jsonl", now_ts=NOW_TS)
    memory.record(session, verdict, ts=NOW_TS)
    return memory


def test_memory_record_writes_bias_session_log(tmp_path):
    """RT-02: record() feeds the sibling sessions.jsonl consumers read."""
    _recorded_session(tmp_path)
    sessions_path = tmp_path / "sessions.jsonl"
    assert sessions_path.exists()
    import json

    row = json.loads(sessions_path.read_text(encoding="utf-8").splitlines()[0])
    assert row["session_id"]
    assert row["ts"] == NOW_TS
    assert row["question"] == "q?"
    assert "tactician" in row["argue_orders"]
    assert row["scores"]["tactician"]["score"] >= 0.0


def test_bias_detector_consumes_memory_written_log(tmp_path):
    """RT-02: the detector starves no more — recorded sessions are visible."""
    import json as _json

    from webpent.jc.bias_detector import BiasDetector

    _recorded_session(tmp_path)
    sessions_path = tmp_path / "sessions.jsonl"
    line = sessions_path.read_text(encoding="utf-8").splitlines()[0]
    verdict_block = _json.loads(line).get("verdict") or {}
    assert verdict_block.get("advocates_summary")

    detector = BiasDetector(sessions_path, min_sessions=1)
    findings = detector.detect(window_days=30, now_ts=NOW_TS + 10.0)
    assert findings, "the loser of a 2-advocate session must register"


def test_cli_verdicts_filters_then_slices(tmp_path):
    """RT-03: --limit 5 must return 5 verdicts even when non-verdict rows
    sit in the window (slice must follow the filter, not precede it)."""
    import json as _json

    from typer.testing import CliRunner

    def vrow(n: int) -> str:
        return _json.dumps({"session_id": f"s{n}", "ts": NOW_TS + n,
                            "verdict": {"action": f"a{n}", "advisory": True}})

    rows = [vrow(i) for i in range(5)] + [
        _json.dumps({"session_id": "x1", "ts": NOW_TS + 50, "outcome": "correct"}),
        _json.dumps({"session_id": "x2", "ts": NOW_TS + 51, "outcome": "incorrect"}),
    ]
    (tmp_path / "memory.jsonl").write_text("\n".join(rows) + "\n",
                                           encoding="utf-8")
    runner = CliRunner()
    result = runner.invoke(
        __import__("webpent.cli.jc", fromlist=["jc_app"]).jc_app,
        ["verdicts", "--limit", "5"],
        env={"WEBPENT_JC_DIR": str(tmp_path)},
    )
    assert result.exit_code == 0, result.output
    payload = _json.loads(result.output)
    assert payload["count"] == 5, f"expected 5 verdicts, got {payload['count']}"


def test_verdict_rules_inverted_thresholds_are_swapped(tmp_path):
    """RT-04: high < medium must be swapped so tier() and escalation agree."""
    from webpent.jc.verdict import load_verdict_rules

    cfg = tmp_path / "rules.yaml"
    cfg.write_text(
        "verdict:\n  confidence_thresholds:\n    high: 0.3\n    medium: 0.7\n",
        encoding="utf-8",
    )
    rules = load_verdict_rules(cfg)
    assert rules.high >= rules.medium
    tier = rules.tier(0.5)
    escalates = rules.should_escalate(0.5)
    if tier == "low":
        assert escalates
    else:
        assert not escalates


def test_verdict_rules_out_of_range_fall_back(tmp_path):
    """RT-04: thresholds clamp to [0,1]; nonsense epsilon/ratio revert."""
    from webpent.jc.verdict import VERDICT_DEFAULTS, load_verdict_rules

    cfg = tmp_path / "rules.yaml"
    cfg.write_text(
        "verdict:\n"
        "  confidence_thresholds:\n    high: 2.5\n    medium: -1.0\n"
        "  tie_epsilon: -0.5\n"
        "  clear_winner_ratio: 0.2\n",
        encoding="utf-8",
    )
    rules = load_verdict_rules(cfg)
    assert 0.0 <= rules.high <= 1.0
    assert 0.0 <= rules.medium <= 1.0
    assert rules.high >= rules.medium
    assert rules.tie_epsilon == VERDICT_DEFAULTS["tie_epsilon"]
    assert rules.clear_winner_ratio == VERDICT_DEFAULTS["clear_winner_ratio"]


def _arg(evidence_kinds, confidence=0.5, advocate_id="tactician", claim="do-x"):
    return Argument(
        advocate_id=advocate_id,
        claim=claim,
        evidence=[
            Evidence(kind=k, content=f"content-{advocate_id}-{i}",
                     source=f"scanner-{i}", observed_at=NOW,
                     confidence=0.6, specificity=0.6)
            for i, k in enumerate(evidence_kinds)
        ],
        reasoning="because",
        confidence=confidence,
        alternatives=["wait"],
        timestamp=NOW,
    )


def test_skeptic_confirmation_needs_two_items():
    """RT-05: one same-kind citation is thin, not confirmation bias."""
    from webpent.jc.skeptic import Skeptic

    sk = Skeptic(now=NOW)
    context = {"target_id": "lab-01", "now": NOW}
    single = sk.challenge(_arg(["signal"]), context)
    assert "confirmation" not in single.bias_flags

    double = sk.challenge(_arg(["signal", "signal"]), context)
    assert "confirmation" in double.bias_flags


def test_skeptic_flags_are_documented():
    """RT-06: every emitted flag belongs to the documented SKEPTIC_FLAGS set."""
    from webpent.jc.skeptic import SKEPTIC_FLAGS, Skeptic

    sk = Skeptic(now=NOW)
    context = {"target_id": "lab-01", "now": NOW}
    cases = [
        _arg([]),
        _arg(["signal"]),
        _arg(["signal", "signal"], confidence=1.0),
        _arg(["signal", "lesson", "metric"], confidence=0.9),
        _arg(["signal", "lesson"], confidence=0.0),
    ]
    for arg in cases:
        flags = sk.challenge(arg, context).bias_flags
        assert flags, "the skeptic never emits an empty challenge"
        assert set(flags) <= set(SKEPTIC_FLAGS), flags
    assert "general_doubt" in SKEPTIC_FLAGS


def test_memory_temp_files_cleaned_on_io_failure(tmp_path, monkeypatch):
    """RT-07: a failed atomic replace must not leave .tmp files behind."""
    import webpent.jc.memory as memory_mod

    def boom(src, dst):
        raise OSError("disk full")

    monkeypatch.setattr(memory_mod.os, "replace", boom)
    memory = CouncilMemory(tmp_path / "memory.jsonl", now_ts=NOW_TS)
    ch = CouncilChamber(skeptic=Skeptic(), judge=Judge(), now=NOW)
    session = ch.convene("q?", {"target_id": "lab-01"})
    ch.submit_argument(
        session.session_id,
        Argument(advocate_id="a", claim="c", evidence=[], reasoning="r",
                 confidence=0.5, alternatives=["w"], timestamp=NOW),
    )
    verdict = ch.close(session.session_id)

    expected = {"memory.jsonl", "sessions.jsonl"}
    memory.record(session, verdict, ts=NOW_TS)
    after_record = {p.name for p in tmp_path.iterdir()}
    assert after_record <= expected, f"temp files leaked: {after_record - expected}"

    memory.link_outcome(session.session_id, "correct", ts=NOW_TS)
    after_link = {p.name for p in tmp_path.iterdir()}
    assert after_link <= expected, f"temp files leaked: {after_link - expected}"
