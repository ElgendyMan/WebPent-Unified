"""U-17 Mastery Scorecard tests.

Restored after the workspace reset. 4 tests over
``webpent.brain.scorecard.ScorecardEmitter``:

  * Denominators (2 tests):
      - emit() uses ``LAB_DENOMINATORS[lab]`` when ``applicable_items``
        is omitted.
      - emit() uses the operator-supplied ``applicable_items`` when
        provided (override path for non-canonical labs).
  * Scorecard emitter (2 tests):
      - the honesty ratio drops to 0.0 when any false-positive is
        present (honesty is binary — one FP breaks perfect honesty).
      - to_json() serialises all five scorecard sections
        (coverage, honesty, no_dead_ends, efficiency, ev_calibration).
"""
from __future__ import annotations

import json
import os
import sys
from pathlib import Path

import pytest

os.environ.setdefault("WEBPENT_AUDIT_SECRET_KEY", "test_key_32_chars_minimum_required_1234567890")
os.environ.setdefault("CELERY_PAYLOAD_KEY", "test-only-celery-payload-key-not-for-production-use")
os.environ.setdefault("JWT_SECRET_KEY", "test-only-jwt-secret-key-not-for-production-use-000000")
os.environ.setdefault("WEBPENT_ALLOW_DIRECT_ORCHESTRATOR_CONSTRUCTION_TEST_ONLY", "1")
os.environ.setdefault("WEBPENT_ENTRYPOINT", "cli")

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from webpent.brain.scorecard import (  # noqa: E402
    LAB_DENOMINATORS,
    ScorecardEmitter,
)


# ---------------------------------------------------------------------------
# Denominators (2 tests)
# ---------------------------------------------------------------------------
class TestDenominators:
    def test_emit_uses_lab_denominator_when_applicable_omitted(self):
        """When ``applicable_items`` is None, the emitter falls back to
        ``LAB_DENOMINATORS[lab]`` for the coverage ratio's denominator.
        """
        emitter = ScorecardEmitter()
        emission = emitter.emit(
            lab="juice_shop",
            cycle=1,
            full_chain_outcomes=10,
        )
        assert emission.coverage["applicable"] == LAB_DENOMINATORS["juice_shop"]
        assert emission.coverage["full_chain_outcomes"] == 10
        # ratio = 10 / 116
        assert emission.coverage["ratio"] == round(10 / 116, 4)

    def test_emit_uses_explicit_applicable_items_when_supplied(self):
        """When ``applicable_items`` is supplied, it overrides
        LAB_DENOMINATORS — the operator can declare a non-canonical
        lab's denominator.
        """
        emitter = ScorecardEmitter()
        emission = emitter.emit(
            lab="custom_lab",
            cycle=1,
            full_chain_outcomes=5,
            applicable_items=50,
        )
        assert emission.coverage["applicable"] == 50
        assert emission.coverage["ratio"] == round(5 / 50, 4)


# ---------------------------------------------------------------------------
# Scorecard emitter (2 tests)
# ---------------------------------------------------------------------------
class TestScorecardEmitter:
    def test_honesty_ratio_is_zero_when_false_positives_present(self):
        """Honesty is binary — a single false-positive drops the
        honesty ratio to 0.0 (no partial credit for "almost honest").
        """
        emitter = ScorecardEmitter()
        clean = emitter.emit(
            lab="juice_shop",
            cycle=1,
            full_chain_outcomes=10,
            false_positives=0,
        )
        assert clean.honesty["ratio"] == 1.0
        dirty = emitter.emit(
            lab="juice_shop",
            cycle=1,
            full_chain_outcomes=10,
            false_positives=1,
        )
        assert dirty.honesty["ratio"] == 0.0
        assert dirty.honesty["false_positives"] == 1

    def test_to_json_serialises_all_five_scorecard_sections(self):
        """to_json() emits a JSON object with all five sections:
        coverage, honesty, no_dead_ends, efficiency, ev_calibration.
        """
        emitter = ScorecardEmitter()
        emission = emitter.emit(
            lab="dvwa",
            cycle=2,
            full_chain_outcomes=8,
            false_positives=0,
            correct_refutations=3,
            total_refutations=5,
            explained_terminals=4,
            total_terminals=4,
            findings=2,
            cost_usd=1.5,
            total_requests=200,
        )
        blob = emission.to_json()
        parsed = json.loads(blob)
        for section in ("coverage", "honesty", "no_dead_ends", "efficiency", "ev_calibration"):
            assert section in parsed, f"scorecard missing section: {section}"
        # Spot-check a couple of derived metrics.
        assert parsed["no_dead_ends"]["ratio"] == 1.0
        assert parsed["efficiency"]["findings_per_dollar"] == round(2 / 1.5, 6)
        assert parsed["efficiency"]["requests_per_finding"] == round(200 / 2, 2)
        # No EV observations supplied -> honest "no calibration claim" (0.0),
        # NOT an invented correlation.
        assert parsed["ev_calibration"]["rank_outcome_correlation"] == 0.0
        assert parsed["ev_calibration"]["ev_input_count"] == 0


# ---------------------------------------------------------------------------
# EV-Calibration (C1(a) TC-2) — the correlation is COMPUTED, never pinned
# ---------------------------------------------------------------------------
class TestEVCalibration:
    """C1(a): ``rank_outcome_correlation`` must be a real Spearman rank
    correlation between the EV-implied priority order and the observed
    outcome order — the scheduler's honesty metric.  The pre-C1(a) test
    pinned the dead hard-coded 0.0 (green-by-de-scoping); these tests pin
    COMPUTED values instead.
    """

    def test_perfect_agreement_yields_correlation_one(self):
        """EV order and (tie-free) outcome order agree perfectly -> rho == 1.0."""
        emitter = ScorecardEmitter()
        emission = emitter.emit(
            lab="juice_shop", cycle=1, full_chain_outcomes=3,
            ev_ranked=[0.9, 0.5, 0.1],       # EV: H1 > H2 > H3
            ev_outcomes=[1.0, 0.5, 0.0],     # outcomes agree exactly
        )
        assert emission.ev_calibration["rank_outcome_correlation"] == 1.0
        assert emission.ev_calibration["ev_input_count"] == 3

    def test_perfect_inversion_yields_correlation_minus_one(self):
        """EV ranks anti-correlate with outcomes exactly -> rho == -1.0."""
        emitter = ScorecardEmitter()
        emission = emitter.emit(
            lab="juice_shop", cycle=1, full_chain_outcomes=3,
            ev_ranked=[0.9, 0.5, 0.1],       # EV: H1 > H2 > H3
            ev_outcomes=[0.0, 0.5, 1.0],     # strictly inverted
        )
        assert emission.ev_calibration["rank_outcome_correlation"] == -1.0

    def test_partial_agreement_yields_known_rho(self):
        """One transposition in four (tie-free) -> rho == 0.8.

        Spearman: rho = 1 - 6*sum(d^2)/(n(n^2-1)).  EV order [a,b,c,d],
        outcomes swap positions b and c: d = [0,-1,-1,0], sum(d^2) = 2,
        n=4 -> rho = 1 - 12/60 = 0.8.
        """
        emitter = ScorecardEmitter()
        emission = emitter.emit(
            lab="webgoat", cycle=2, full_chain_outcomes=2,
            ev_ranked=[0.8, 0.6, 0.4, 0.2],
            ev_outcomes=[0.9, 0.4, 0.6, 0.2],
        )
        assert emission.ev_calibration["rank_outcome_correlation"] == 0.8

    def test_no_ev_inputs_remains_honest_zero(self):
        """Missing/misaligned EV inputs -> 0.0 with count 0 (no claim)."""
        emitter = ScorecardEmitter()
        no_inputs = emitter.emit(lab="dvwa", cycle=1, full_chain_outcomes=1)
        assert no_inputs.ev_calibration["rank_outcome_correlation"] == 0.0
        assert no_inputs.ev_calibration["ev_input_count"] == 0
        misaligned = emitter.emit(
            lab="dvwa", cycle=1, full_chain_outcomes=1,
            ev_ranked=[0.5, 0.4], ev_outcomes=[1.0],
        )
        assert misaligned.ev_calibration["rank_outcome_correlation"] == 0.0

    def test_ties_use_average_rank_method(self):
        """Tied EV values share the average rank (standard Spearman).

        Ascending-value ranks on BOTH sides (Spearman is invariant to the
        direction convention as long as both sides match).

        EV [0.5, 0.5, 0.1]  -> ev_ranks  = [2.5, 2.5, 1.0]
        outcomes [1.0, 0.0, 0.0] -> out_ranks = [3.0, 1.5, 1.5]
        d = [-0.5, 1.0, -0.5] -> sum(d^2) = 1.5; n=3
        rho = 1 - 9/24 = 0.625.
        """
        emitter = ScorecardEmitter()
        emission = emitter.emit(
            lab="juice_shop", cycle=1, full_chain_outcomes=1,
            ev_ranked=[0.5, 0.5, 0.1],
            ev_outcomes=[1.0, 0.0, 0.0],
        )
        assert emission.ev_calibration["rank_outcome_correlation"] == 0.625
