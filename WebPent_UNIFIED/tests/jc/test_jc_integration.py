"""Judgment Council integration: one deterministic pipeline, law by law.

Covers the charter end to end: advisory-only envelopes (JC-L-1), no LLM and
no randomness (JC-L-2), transparency (JC-L-3), every voice heard (JC-L-4),
dissent preserved (JC-L-5), zero network from ``webpent.jc``, and a full
convene -> argue -> challenge -> weigh -> judge -> record cycle that is
byte-identical across runs.
"""

from __future__ import annotations

from datetime import datetime, timezone
from unittest.mock import patch

from webpent.jc import (
    ConfidenceCalibrator,
    CouncilChamber,
    DissentRegister,
    VerdictRules,
    all_advocate_ids,
    build_default_advocates,
    context_hash,
    deterministic_id,
)

NOW = datetime(2026, 10, 16, 12, 0, 0, tzinfo=timezone.utc)
CONTEXT = {"target_id": "lab-01", "goal": "assess exposure", "now": NOW}


def build_context(kind: str) -> dict:
    base = dict(CONTEXT)
    if kind == "tactical":
        base["ev_schedule"] = [{"target_id": "lab-01", "ev_per_hour": 12.0},
                               {"target_id": "lab-02", "ev_per_hour": 4.0}]
    elif kind == "observational":
        base["signals"] = [{"endpoint": "/login", "description": "leaks version",
                            "confidence": 0.8}]
    elif kind == "adaptive":
        base["ev_per_hour_now"] = {"lab-01": 3.0}
        base["ev_per_hour_week_ago"] = {"lab-01": 12.0}
    elif kind == "economical":
        base["findings_value"] = [{"finding_id": "f1", "value_usd": 120.0}]
        base["cost_usd"] = 8.0
        base["time_cost_usd"] = 15.0
    elif kind == "historical":
        base["lessons"] = [{"lesson_id": "l1", "confidence": 0.7,
                            "content": "recheck auth before deeper probing"}]
    elif kind == "strategical":
        base["payload_hints"] = ["probe /api/upload for xml entities"]
    elif kind == "resilient":
        base["blocked_paths"] = [{"lane": "/admin", "fallback": "/adminx"}]
    return base


def convene_full() -> tuple:
    """Full council cycle with all seven advocates and the skeptic."""
    context = dict(CONTEXT)
    for kind in ("tactical", "observational", "adaptive", "economical",
                 "historical", "strategical", "resilient"):
        context.update(build_context(kind))
    chamber = CouncilChamber(now=NOW)
    session = chamber.convene("is lab-01 ready for deeper testing?", context)
    for advocate in build_default_advocates():
        argument = advocate.argue(session.context, now=NOW)
        if argument is not None:
            chamber.submit_argument(session.session_id, argument)
    verdict = chamber.close(session.session_id, now=NOW)
    return chamber, session, verdict


def test_every_voice_heard_full_cycle():
    chamber, session, verdict = convene_full()
    argued = {a.advocate_id for a in session.arguments}
    assert argued == set(all_advocate_ids())  # all seven submitted (JC-L-4)
    assert len(session.challenges) == len(session.arguments)  # skeptic on all
    assert verdict.action in {a.claim for a in session.arguments}
    assert verdict.confidence_tier in ("high", "medium", "low")


def test_full_cycle_deterministic_byte_identical():
    _, session_a, verdict_a = convene_full()
    _, session_b, verdict_b = convene_full()
    assert session_a.as_dict() == session_b.as_dict()
    assert verdict_a.as_dict() == verdict_b.as_dict()


def test_every_contract_is_advisory():
    _, session, verdict = convene_full()
    assert verdict.as_dict()["advisory"] is True  # JC-L-1
    assert session.as_dict()["advisory"] is True
    argued_ids = {a.advocate_id for a in session.arguments}
    for argument in session.arguments:
        assert argument.advocate_id in argued_ids
    for challenge in session.challenges:
        assert challenge.target_advocate_id in argued_ids
    for dissent in verdict.dissent:
        assert dissent.advocate_id in argued_ids


def test_no_llm_no_randomness_in_jc_source():
    from pathlib import Path as _Path

    import webpent.jc as jc_pkg

    root = _Path(jc_pkg.__file__).parent
    banned = ("import random", "from random", "uuid4", "Random(",
              "openai", "anthropic", "gpt", "torch", "transformers",
              "import socket", "requests.", "urllib")
    for module_file in root.glob("*.py"):
        text = module_file.read_text(encoding="utf-8")
        for word in banned:
            assert word not in text, f"{module_file.name} contains '{word}'"


def test_zero_network_from_jc_modules():
    import socket

    _, session, verdict = None, None, None
    with patch.object(socket, "socket", side_effect=RuntimeError("network")):
        chamber, session, verdict = convene_full()  # must not touch the wire
    assert verdict.action


def test_session_id_is_deterministic_and_order_free():
    ctx1 = {"a": 1, "b": 2}
    ctx2 = {"b": 2, "a": 1}
    assert context_hash(ctx1) == context_hash(ctx2)
    assert deterministic_id("q", context_hash(ctx1)) == \
        deterministic_id("q", context_hash(ctx2))
    chamber_a = CouncilChamber(now=NOW)
    chamber_b = CouncilChamber(now=NOW)
    assert chamber_a.convene("q", ctx1).session_id == \
        chamber_b.convene("q", ctx2).session_id


def test_dissent_recorded_and_fed_to_memory(tmp_path):
    _, session, verdict = convene_full()
    register = DissentRegister(tmp_path / "dissent.jsonl")
    written = register.record(verdict, now=1_800_000_000.0)
    assert written == len(verdict.dissent)
    register.link_outcome(verdict.session_id, "correct", now=1_800_000_000.0 + 1)
    lessons = register.export_for_lessons()
    assert all(x["lesson_kind"] == "dissent_proved_right" for x in lessons)


def test_calibration_pipeline_to_drift(tmp_path):
    calibrator = ConfidenceCalibrator(tmp_path / "cal.jsonl")
    for i in range(20):
        calibrator.record(0.9, False, ts=1_800_000_000.0 + i)
    report = calibrator.report(now_ts=1_800_000_000.0 + 100)
    assert report.drift_detected
    assert report.n_samples == 20


def test_escalation_and_explainer_end_to_end():
    chamber = CouncilChamber(now=NOW)
    session = chamber.convene("too little context", {"goal": "assess exposure"})
    verdict = chamber.close(session.session_id, now=NOW)
    assert verdict.escalate  # no advocates without context -> escalate
    from webpent.jc.explainer import Explainer
    data = Explainer().explain(verdict, session, level="one-liner")
    assert "escalate" in data["one_liner"]


def test_override_pipeline_end_to_end(tmp_path):
    _, session, verdict = convene_full()
    from webpent.jc.override import OverrideProtocol
    protocol = OverrideProtocol(tmp_path / "ov.jsonl", now_ts=1_800_000_000.0)
    entry = protocol.apply(verdict, "partial",
                           "narrow the action to one port only",
                           final_action="scan-443-only",
                           ts=1_800_000_000.0)
    protocol.link_outcome(verdict.session_id, "correct", ts=1_800_000_000.0 + 1)
    assert protocol.operator_accuracy() == 1.0
    assert entry["council_action"] == verdict.action


def test_dashboard_pipeline_end_to_end(tmp_path):
    _, session, verdict = convene_full()
    from webpent.jc.memory import CouncilMemory
    memory = CouncilMemory(tmp_path / "memory.jsonl", now_ts=1_800_000_000.0)
    memory.record(session, verdict, ts=1_800_000_000.0)
    from webpent.jc.dashboard import CouncilDashboard
    snap = CouncilDashboard(memory_path=tmp_path / "memory.jsonl",
                            dissent_path=tmp_path / "d.jsonl",
                            calibration_path=tmp_path / "c.jsonl",
                            sessions_path=tmp_path / "s.jsonl",
                            override_path=tmp_path / "o.jsonl",
                            ).build(now_ts=1_800_000_000.0 + 100)
    assert snap["n_sessions"] == 1
    assert snap["recent_sessions"][0]["action"] == verdict.action


def test_confidence_never_exceeds_one_and_tiers_match_rules():
    rules = VerdictRules()
    _, _, verdict = convene_full()
    assert 0.0 <= verdict.confidence <= 1.0
    assert verdict.confidence_tier == rules.tier(verdict.confidence)


def test_challenge_severity_capped_and_alternative_always_present():
    _, session, _ = convene_full()
    for challenge in session.challenges:
        assert 0.0 <= challenge.challenge_severity <= 0.9
        assert challenge.alternative_hypothesis
        assert challenge.bias_flags


def test_advocates_abstain_without_context():
    for advocate in build_default_advocates():
        assert advocate.argue({}, now=NOW) is None
