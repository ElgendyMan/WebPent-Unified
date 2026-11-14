"""U-15 Lessons Ledger tests.

Restored after the workspace reset. 5 tests over
``webpent.brain.lessons.LessonsLedger``:

  * Approval gates (2 tests):
      - run-scoped lessons auto-approve (``scope=="run"``).
      - beyond-lab lessons require the ``owner`` approver.
  * Staleness decay (2 tests):
      - get_influence() decays confidence with runs-since-applied.
      - get_influence() floors at MINIMUM_INFLUENCE (0.0).
  * Advisory-only (1 test):
      - is_advisory_only() is permanently True — the ledger never
        authorizes actions, only advises.
"""

from __future__ import annotations

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

from webpent.brain.lessons import Lesson, LessonsLedger  # noqa: E402


# ---------------------------------------------------------------------------
# Approval gates (2 tests)
# ---------------------------------------------------------------------------
class TestApprovalGates:
    def test_run_scoped_lesson_is_auto_approved(self):
        """A lesson with ``scope=="run"`` is auto-approved on record —
        run-scoped lessons never block on a human approver.
        """
        ledger = LessonsLedger()
        lesson = ledger.record_lesson(
            Lesson(
                lesson_id="L-run-1",
                scope="run",
                statement="refactor endpoint classifier for less bias",
                confidence=0.7,
            )
        )
        assert lesson.is_approved() is True
        assert lesson.approved_by == "auto"

    def test_beyond_lab_lesson_requires_owner_approver(self):
        """A beyond-lab lesson cannot be approved by an arbitrary
        approver — only the ``owner`` role may approve it.
        """
        ledger = LessonsLedger()
        ledger.record_lesson(
            Lesson(
                lesson_id="L-beyond-1",
                scope="beyond-lab",
                statement="do not target external metadata services",
                confidence=0.8,
            )
        )
        # Non-owner approver is rejected.
        assert ledger.approve_lesson("L-beyond-1", "operator") is False
        # Owner approver is accepted.
        assert ledger.approve_lesson("L-beyond-1", "owner") is True
        # Second approval is idempotent (the lesson is already approved).
        assert ledger.approve_lesson("L-beyond-1", "owner") is True


# ---------------------------------------------------------------------------
# Staleness decay (2 tests)
# ---------------------------------------------------------------------------
class TestStalenessDecay:
    def test_influence_decays_with_runs_since_applied(self):
        """get_influence() decays confidence by DECAY_RATE per
        run-since-applied; an unapplied approved lesson at run 0
        returns its full confidence.
        """
        ledger = LessonsLedger()
        lesson = ledger.record_lesson(
            Lesson(
                lesson_id="L-decay-1",
                scope="run",
                statement="param-name prior for id-like fields",
                confidence=0.6,
            )
        )
        # At run 0 (no apply yet): full confidence.
        assert ledger.get_influence(lesson, current_run=0) == pytest.approx(0.6)
        # Apply at run 1, then check at run 2 (1 run since apply).
        ledger.apply_lesson("L-decay-1", run_number=1)
        influence = ledger.get_influence(lesson, current_run=2)
        expected = 0.6 * ((1 - LessonsLedger.DECAY_RATE) ** 1)
        assert influence == pytest.approx(expected)

    def test_influence_floors_at_minimum(self):
        """get_influence() never drops below MINIMUM_INFLUENCE."""
        ledger = LessonsLedger()
        lesson = ledger.record_lesson(
            Lesson(
                lesson_id="L-floor-1",
                scope="run",
                statement="stale lesson that hasn't applied in many runs",
                confidence=0.4,
            )
        )
        ledger.apply_lesson("L-floor-1", run_number=1)
        # Many runs since apply — decay asymptotically approaches 0,
        # but never below MINIMUM_INFLUENCE.
        influence = ledger.get_influence(lesson, current_run=1000)
        assert influence >= LessonsLedger.MINIMUM_INFLUENCE


# ---------------------------------------------------------------------------
# Advisory-only (1 test)
# ---------------------------------------------------------------------------
class TestAdvisoryOnly:
    def test_ledger_is_permanently_advisory_only(self):
        """is_advisory_only() is permanently True — the ledger never
        authorizes actions; it only advises downstream consumers.
        """
        ledger = LessonsLedger()
        assert ledger.is_advisory_only() is True
        # After recording and approving lessons, the advisory-only
        # invariant still holds.
        ledger.record_lesson(
            Lesson(
                lesson_id="L-advisory-1",
                scope="run",
                statement="advisory lesson",
                confidence=0.5,
            )
        )
        assert ledger.is_advisory_only() is True
