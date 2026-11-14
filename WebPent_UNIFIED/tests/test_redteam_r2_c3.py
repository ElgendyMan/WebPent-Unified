"""RED-TEAM ROUND 2 — C3 batch (remaining Low items), fail-first.

    R2-jc-07      Skeptic.challenge half-guards non-dict contexts then
                  crashes on context.get
    R2-jc-08      DissentRegister.record reports success when the write failed
    R2-jc-09      CouncilMemory.record read-modify-write without a file lock
    R2-prism-06   PriorAdjuster.adjust raises raw KeyError for unknown
                  pattern_type instead of PrismLawError
    R2-prism-07   classifier dies with AttributeError (not PrismLawError)
                  on a non-mapping pattern entry
    R2-graph-06   confirmed-findings counter reads a nonexistent
                  validation_status field (always 0/N)
    R2-graph-07   smart_mode / enable_smart_campaigns never declared in
                  PentestState -> dropped by langgraph channel filtering
"""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
PRISM_CFG = REPO_ROOT / "config" / "prism"
NOW_TS = 1_800_000_000.0
NOW = datetime.fromtimestamp(NOW_TS, tz=timezone.utc)


def _verdict(dissent=None, session_id: str = "s1"):
    from webpent.jc.contracts import Verdict

    return Verdict(
        action="none", reasoning="r", confidence=0.0, confidence_tier="low",
        dissent=list(dissent or []), escalate=True, escalation_reason="r",
        advocates_summary={}, session_id=session_id, timestamp=NOW,
    )


def _session(session_id: str = "s2"):
    from webpent.jc.contracts import CouncilSession

    return CouncilSession(
        session_id=session_id, question="q", context={"k": 1},
        started_at=NOW,
    )


# ---------------------------------------------------------------------------
# R2-jc-07
# ---------------------------------------------------------------------------

def test_r2jc_07_skeptic_tolerates_non_dict_context():
    from webpent.jc.contracts import Argument, Evidence
    from webpent.jc.skeptic import Skeptic

    argument = Argument(
        advocate_id="a1", claim="c",
        evidence=[Evidence(
            kind="metric", content="x", source="t1",
            observed_at=NOW, confidence=0.5, specificity=1.0,
        )],
        reasoning="r", confidence=0.9, alternatives=["x"], timestamp=NOW,
    )
    challenge = Skeptic(now=NOW).challenge(argument, None)
    assert challenge is not None


# ---------------------------------------------------------------------------
# R2-jc-08
# ---------------------------------------------------------------------------

def test_r2jc_08_record_returns_zero_when_write_fails(tmp_path):
    from webpent.jc.contracts import DissentingView
    from webpent.jc.dissent import DissentRegister

    # parent exists as a regular FILE: mkdir(parents=True) raises OSError
    # no matter the effective user, so the append cannot succeed.
    blocker = tmp_path / "blocker"
    blocker.write_text("", encoding="utf-8")
    register = DissentRegister(blocker / "d.jsonl")
    written = register.record(_verdict(
        [DissentingView(advocate_id="d1", claim="c", reasoning="r",
                        confidence=0.4)],
    ))
    assert written == 0, (
        "record must not report success for a write that failed"
    )


def test_r2jc_08_record_returns_lines_written(tmp_path):
    from webpent.jc.contracts import DissentingView
    from webpent.jc.dissent import DissentRegister

    register = DissentRegister(tmp_path / "d.jsonl")
    written = register.record(_verdict([
        DissentingView(advocate_id="d1", claim="c", reasoning="r",
                       confidence=0.4),
        DissentingView(advocate_id="d2", claim="c2", reasoning="r2",
                       confidence=0.3),
    ]))
    assert written == 2


# ---------------------------------------------------------------------------
# R2-jc-09
# ---------------------------------------------------------------------------

def test_r2jc_09_record_takes_an_exclusive_file_lock(tmp_path, monkeypatch):
    import fcntl

    from webpent.jc.memory import CouncilMemory

    calls = []
    real_flock = fcntl.flock

    def spy(fd, operation):
        calls.append(operation)
        return real_flock(fd, operation)

    monkeypatch.setattr(fcntl, "flock", spy)
    memory = CouncilMemory(tmp_path / "m.jsonl", retention_days=30)
    memory.record(_session(), _verdict(), ts=NOW_TS + 60)
    monkeypatch.undo()
    assert fcntl.LOCK_EX in calls, (
        "record must hold an exclusive lock across the read-modify-write"
    )


# ---------------------------------------------------------------------------
# R2-prism-06
# ---------------------------------------------------------------------------

def test_r2prism_06_unknown_pattern_type_is_law_error():
    from webpent.prism.errors import PrismLawError
    from webpent.prism.patterns import Pattern
    from webpent.prism.priors import PriorAdjuster

    pattern = Pattern(
        pattern_id="x" * 16, pattern_type="custom_type", key="k",
        samples=10, successes=8, success_rate=0.8, confidence=0.77,
        updated_at="2026-11-02T00:00:00+00:00", reason="8/10",
    )
    with pytest.raises(PrismLawError):
        PriorAdjuster(PRISM_CFG / "learning_params.yaml").adjust(
            0.5, pattern, {"technique": "k"}
        )


# ---------------------------------------------------------------------------
# R2-prism-07
# ---------------------------------------------------------------------------

def test_r2prism_07_non_dict_pattern_entry_is_law_error(tmp_path):
    import yaml

    from webpent.prism.classifier import EvidenceClassifier
    from webpent.prism.errors import PrismLawError
    from webpent.prism.taxonomy import EvidenceTaxonomy

    data = yaml.safe_load(
        (PRISM_CFG / "classifier_patterns.yaml").read_text(encoding="utf-8")
    )
    data["patterns"][0] = "oops"
    bad = tmp_path / "bad.yaml"
    bad.write_text(yaml.safe_dump(data), encoding="utf-8")
    taxonomy = EvidenceTaxonomy(PRISM_CFG / "taxonomy.yaml")
    with pytest.raises(PrismLawError):
        EvidenceClassifier(bad, taxonomy)


# ---------------------------------------------------------------------------
# R2-graph-06
# ---------------------------------------------------------------------------

def test_r2graph_06_renderer_counts_confirmed_findings():
    from webpent.graph.progress_display import HuntProgressRenderer
    from webpent.models.findings import Finding

    finding = Finding(
        title="Confirmed SQL injection", severity="high", description="d",
        tool_name="x", url="https://a.example", vuln_class="sqli",
        confidence="confirmed", confidence_level="Tool-Confirmed",
        evidence={"tool_confirmed_by": "test.fixture"},
    )
    renderer = HuntProgressRenderer(is_tty=False)
    renderer.observe_findings([finding])
    assert renderer._findings_confirmed == 1


# ---------------------------------------------------------------------------
# R2-graph-07
# ---------------------------------------------------------------------------

def test_r2graph_07_smart_mode_flags_survive_channel_filtering():
    pytest.importorskip("langgraph")
    from langgraph.graph import END, START, StateGraph

    from webpent.state.state import PentestState

    g = StateGraph(PentestState)
    g.add_node("probe", lambda s: {
        "smart_mode": True, "enable_smart_campaigns": True,
    })
    g.add_edge(START, "probe")
    g.add_edge("probe", END)
    out = g.compile().invoke({})
    assert out.get("smart_mode") is True
    assert out.get("enable_smart_campaigns") is True
