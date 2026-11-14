# tests/test_lcs2_sweep_instrument.py
"""TC-3 (Dispatch #041 §1) — the LCS-2 sweep instrument's pure-logic tests.

The instrument (tests/lab/lcs2_sweep_instrument.py) makes the improving-
efficiency threshold measurable.  These tests pin the parts that must NEVER
drift: the brain-replay determinism, the lesson priors mapping, the EV->
selector advisory bridge, the recon-honest construction contract (DR-012),
and the floor theorem constant.
"""
from __future__ import annotations

import copy
import importlib
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

instrument = importlib.import_module("tests.lab.lcs2_sweep_instrument")
_ev = importlib.import_module("webpent.brain.ev_scheduler")


# ---------------------------------------------------------------------------
# Floor theorem
# ---------------------------------------------------------------------------
def test_floor_theorem_constant():
    """FLOOR = causal triple (3) + control triple (3) = 6.  The convergence
    bound of the improving trend — lower is impossible without weakening
    the evidence contract."""
    assert instrument.FLOOR_REQUESTS_PER_FINDING == 6


# ---------------------------------------------------------------------------
# Brain-state replay determinism (the adaptation loop's feed-through)
# ---------------------------------------------------------------------------
def test_outcome_stream_replay_is_deterministic():
    """Replaying the cycle-1 outcome stream twice from the inherited state
    yields IDENTICAL base rates — the learned state is a pure function of
    the recorded streams, never hand-edited."""
    inherited = copy.deepcopy(_ev.FAMILY_BASE_RATES)
    try:
        instrument.reset_brain_to_inherited()
        instrument.apply_outcome_stream(instrument.CYCLE1_OUTCOME_STREAM)
        after_first = copy.deepcopy(_ev.FAMILY_BASE_RATES)
        instrument.reset_brain_to_inherited()
        instrument.apply_outcome_stream(instrument.CYCLE1_OUTCOME_STREAM)
        after_second = copy.deepcopy(_ev.FAMILY_BASE_RATES)
        assert after_first == after_second
        # the feed-through actually moved the priors (IDOR promoted)
        assert after_second["IDOR"] > inherited["IDOR"]
    finally:
        instrument.reset_brain_to_inherited()


def test_only_executed_outcomes_enter_the_stream():
    """Zero false positives applies to lessons: cycle 1 never executed
    XSS/RFI — they must have NO outcome entry (no invented evidence)."""
    families = {e["family"] for e in instrument.CYCLE1_OUTCOME_STREAM}
    assert "XSS" not in families
    assert "RFI" not in families
    assert families == {"IDOR", "SQLI"}


def test_recon_honest_construction_derives_from_surface():
    """DR-012: recon-honest construction derives recon_signal_matches from
    the OBSERVED fixture surface (SQLI/XSS/RFI = 0 signals), while the
    recorded-input replay preserves the cycle-1 EV-leg values verbatim."""
    honest = instrument.build_sweep_hypothesis_set(
        engagement_id="t_rh", recon_honest=True)
    by_id = {h["id"]: h for h in honest}
    assert by_id["t_rh_sqli"]["recon_signal_matches"] == 0
    assert by_id["t_rh_xss"]["recon_signal_matches"] == 0
    assert by_id["t_rh_rfi"]["recon_signal_matches"] == 0
    assert by_id["t_rh_idor"]["recon_signal_matches"] == 2
    recorded = instrument.build_sweep_hypothesis_set(
        engagement_id="t_rh", recon_honest=False,
        recorded_inputs=instrument.CYCLE1_RECORDED_EV_INPUTS)
    rec = {h["id"]: h for h in recorded}
    assert rec["h_sqli"]["recon_signal_matches"] == 2  # the recorded state
    assert rec["h_rfi"]["recon_signal_matches"] == 0


# ---------------------------------------------------------------------------
# Lesson priors mapping + growth rule
# ---------------------------------------------------------------------------
def test_lesson_priors_mapping_and_growth():
    """Positive lesson -> priors > 1; negative -> < 1 (clamped); unknown
    family -> exactly 1.0.  Re-validation grows confidence by +0.1 capped
    at 0.95."""
    book = instrument.LessonBook()
    book.record(lesson_id="L-P", family="IDOR", positive=True,
                statement="IDOR confirms on the invoice family — productive",
                confidence=0.7)
    book.record(lesson_id="L-N", family="SQLI", positive=False,
                statement="no live SQLi lane on the fixture surface",
                confidence=0.6)
    assert book.priors_for("IDOR", current_run=1) > 1.0
    assert book.priors_for("SQLI", current_run=1) < 1.0
    assert book.priors_for("XSS", current_run=1) == 1.0  # no lesson, no claim
    assert book.revalidate("IDOR") is True
    audit = {a["lesson_id"]: a for a in book.audit(current_run=1)}
    assert audit["L-P"]["confidence"] == pytest.approx(0.8)
    for _ in range(5):
        book.revalidate("IDOR")
    audit = {a["lesson_id"]: a for a in book.audit(current_run=1)}
    assert audit["L-P"]["confidence"] == 0.95  # the cap


# ---------------------------------------------------------------------------
# EV -> selector advisory bridge
# ---------------------------------------------------------------------------
def test_ev_to_information_value_bridge():
    """Rank order maps monotonically into information_value for EV>0; EV<=0
    hypotheses are demoted to 0.05 (the structural skip's advisory face)."""
    ranked = [{"id": "a", "ev": 2.0}, {"id": "b", "ev": 1.0},
              {"id": "c", "ev": 0.0}, {"id": "d", "ev": -1.0}]
    iv = instrument.ev_to_information_value(ranked)
    assert iv["a"] > iv["b"] > iv["c"] == iv["d"] == 0.05
    assert iv["a"] == 0.9 and iv["b"] == pytest.approx(0.7)


def test_bridge_never_touches_selector_authority():
    """The bridge is ADVISORY: the selector's final pick stays its own
    deterministic scoring.  A high-iv hypothesis with a lower deterministic
    score cannot jump a registry+iv-superior one — pinned with real
    selector objects."""
    from webpent.production.autonomous_validation_v1 import (
        AutonomousExperimentSelector, EXPERIMENT_REGISTRY,
    )
    assert "IDOR" in EXPERIMENT_REGISTRY
    sel = AutonomousExperimentSelector()
    pick = sel.select([
        {"id": "h_low", "vulnerability_class": "NOT_A_REAL_FAMILY",
         "information_value": 0.9},
        {"id": "h_high", "vulnerability_class": "IDOR", "information_value": 0.7},
    ])
    assert pick["hypothesis_id"] == "h_high"


# ---------------------------------------------------------------------------
# Skip-policy structure
# ---------------------------------------------------------------------------
def test_skip_policy_is_structural():
    """The sweep passes ONLY EV-positive hypotheses to the decision — an
    ev<=0 hypothesis is structurally unselectable (recorded skip, not a
    silent drop)."""
    import inspect
    src = inspect.getsource(instrument.run_sweep)
    assert "hypotheses=active" in src
    assert "ev_le_0_irrational_spend" in src
