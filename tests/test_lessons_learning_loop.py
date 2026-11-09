"""Learning-loop activation tests (2026-10-24, Proposal 1).

Covers the three phases of the lessons-learning loop:

  * Phase 1 — real persistence: a ledger constructed with a
    ``store_path`` writes through to SQLite and a NEW instance over the
    same path reloads the lessons (including still-pending beyond-lab
    HITL state and applied-run decay counters). ``store_path=None``
    stays in-memory only. A corrupt store degrades fail-soft to memory.
  * Phase 2 — bounded scoring influence: ``compute_lesson_adjustment``
    returns 0.0 when the flag is off (zero arithmetical change to
    ``score_hypothesis``), and a bounded bonus/penalty when on, riding
    the novelty channel.
  * Phase 3 — end-of-engagement emission: family outcomes become
    auto-approved run-scoped lessons that persist and then measurably
    (and modestly) tilt the next engagement's score for the same
    family.
"""
from __future__ import annotations

import pytest

pytest.skip(
    "legacy v4 lessons subsystem: the lessons brain module was "
    "deliberately removed in the 0.29.0 G-1 deletion window of the "
    "0.34.0 lineage; this v4-era test is kept for reference and "
    "skipped at collection by UNIFIED MERGE (2026-11-02).",
    allow_module_level=True,
)


import os
import sqlite3
import sys
from pathlib import Path

import pytest

os.environ.setdefault("WEBPENT_AUDIT_SECRET_KEY", "test_key_32_chars_minimum_required_1234567890")
os.environ.setdefault("CELERY_PAYLOAD_KEY", "test-only-celery-payload-key-not-for-production-use")
os.environ.setdefault("JWT_SECRET_KEY", "test-only-jwt-secret-key-not-for-production-use-000000")
os.environ.setdefault("WEBPENT_ALLOW_DIRECT_ORCHESTRATOR_CONSTRUCTION_TEST_ONLY", "1")
os.environ.setdefault("WEBPENT_ENTRYPOINT", "cli")

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from webpent.brain.lessons import Lesson, LessonsLedger, get_lessons_ledger  # noqa: E402
from webpent.brain.lesson_emission import (  # noqa: E402
    emit_run_lessons,
    lesson_from_family_outcomes,
    lessons_from_scorecard_emission,
)
from webpent.brain.scorecard import ScorecardEmitter  # noqa: E402
from webpent.config.settings import get_settings  # noqa: E402
from webpent.models.findings import VulnClass  # noqa: E402
from webpent.shared.prioritization import (  # noqa: E402
    compute_lesson_adjustment,
    score_hypothesis,
)


def _clear_settings_cache() -> None:
    get_settings.cache_clear()


@pytest.fixture(autouse=True)
def _reset_settings():
    _clear_settings_cache()
    yield
    _clear_settings_cache()


def _make_hypothesis(vuln_class, confidence: float = 0.6):
    import uuid

    from webpent.models.hypothesis import Hypothesis

    return Hypothesis(
        id=uuid.uuid4(),
        target_url="https://example.test/api/search",
        statement=f"A {vuln_class} hypothesis built for the lessons tests.",
        vuln_class=vuln_class,
        confidence_score=confidence,
    )


# ---------------------------------------------------------------------------
# Phase 1 — persistence
# ---------------------------------------------------------------------------
class TestPersistence:
    def test_lessons_persist_across_ledger_instances(self, tmp_path):
        """The acceptance test: a lesson recorded and approved in one
        ledger instance is present in a NEW instance over the same
        store path — record, approve, reload, assert."""
        store = str(tmp_path / "lessons.db")
        first = LessonsLedger(store_path=store)
        first.record_lesson(
            Lesson(lesson_id="L-persist-1", scope="beyond-lab",
                   statement="sqli: union payloads work on this stack",
                   confidence=0.7)
        )
        first.record_lesson(
            Lesson(lesson_id="L-persist-2", scope="run",
                   statement="sqli: error-based channel observed",
                   confidence=0.6)
        )
        # The run lesson is auto-approved; the beyond-lab one needs owner.
        assert first.approve_lesson("L-persist-1", "owner") is True

        second = LessonsLedger(store_path=store)
        loaded = {l.lesson_id for l in second.get_all_lessons()}
        assert loaded == {"L-persist-1", "L-persist-2"}
        by_id = {l.lesson_id: l for l in second.get_all_lessons()}
        # Approval state survived.
        assert by_id["L-persist-1"].is_approved() is True
        assert by_id["L-persist-1"].approved_by == "owner"
        assert by_id["L-persist-2"].is_approved() is True
        assert by_id["L-persist-2"].approved_by == "auto"
        # Retrieval sees both approved lessons for the matching family.
        retrieved = second.retrieve_lessons(family="sqli", run_number=1)
        assert {l.lesson_id for l in retrieved} == {"L-persist-1", "L-persist-2"}
        assert second.is_persistent() is True

    def test_beyond_lab_hitl_gate_survives_restart(self, tmp_path):
        """An UNAPPROVED beyond-lab lesson persists too: a non-owner in a
        later instance still cannot approve it, owner still can."""
        store = str(tmp_path / "hitl.db")
        first = LessonsLedger(store_path=store)
        first.record_lesson(
            Lesson(lesson_id="L-hitl-1", scope="beyond-lab",
                   statement="do not target external metadata services")
        )

        second = LessonsLedger(store_path=store)
        # Pending state survived the restart...
        pending = [l for l in second.get_all_lessons() if l.lesson_id == "L-hitl-1"]
        assert len(pending) == 1 and pending[0].is_approved() is False
        # ...and the HITL gate is still enforced in the new instance.
        assert second.approve_lesson("L-hitl-1", "operator") is False
        assert second.approve_lesson("L-hitl-1", "owner") is True
        assert second.retrieve_lessons(family="metadata", run_number=0) != []

    def test_apply_counters_persist(self, tmp_path):
        """apply_lesson bumps survive a reload, so influence decay
        continues across instances instead of resetting."""
        store = str(tmp_path / "apply.db")
        first = LessonsLedger(store_path=store)
        first.record_lesson(
            Lesson(lesson_id="L-apply-1", scope="run",
                   statement="xss: payload family A", confidence=0.6)
        )
        first.apply_lesson("L-apply-1", run_number=3)

        second = LessonsLedger(store_path=store)
        lesson = [l for l in second.get_all_lessons() if l.lesson_id == "L-apply-1"][0]
        assert lesson.applied_runs == 1
        assert lesson.last_applied_run == 3
        # Decay measured from the PERSISTED last-applied run.
        influence = second.get_influence(lesson, current_run=4)
        assert influence == pytest.approx(0.6 * ((1 - LessonsLedger.DECAY_RATE) ** 1))

    def test_store_path_none_stays_in_memory_only(self, tmp_path):
        """No store path -> no DB file anywhere, original behavior."""
        ledger = LessonsLedger()
        ledger.record_lesson(
            Lesson(lesson_id="L-mem-1", scope="run", statement="x"))
        ledger.approve_lesson("L-mem-1", "owner")
        assert ledger.is_persistent() is False
        assert ledger.store_path is None
        # Nothing was created on disk in the tmp dir (nor anywhere).
        assert list(tmp_path.rglob("*.db")) == []

    def test_corrupt_store_degrades_fail_soft(self, tmp_path):
        """A corrupt store file logs and degrades to memory operation —
        the advisory ledger never raises into the engagement."""
        store = tmp_path / "corrupt.db"
        store.write_bytes(b"this is not a sqlite database")
        ledger = LessonsLedger(store_path=str(store))
        lesson = ledger.record_lesson(
            Lesson(lesson_id="L-corr-1", scope="run", statement="x"))
        assert lesson.is_approved() is True  # run scope auto-approves
        assert ledger.get_all_lessons()[0].lesson_id == "L-corr-1"
        assert ledger.is_persistent() is False  # downgraded, not crashed

    def test_sqlite_url_forms_supported(self, tmp_path):
        store = str(tmp_path / "url.db")
        for url in (f"sqlite:///{store}", store):
            ledger = LessonsLedger(store_path=url)
            ledger.record_lesson(
                Lesson(lesson_id="L-url", scope="run", statement="y"))
            assert ledger.is_persistent() is True


# ---------------------------------------------------------------------------
# Phase 2 — bounded scoring influence
# ---------------------------------------------------------------------------
class TestScoringInfluence:
    def test_flag_defaults_off(self):
        assert get_settings().enable_lessons_ledger_influence is False

    def test_flag_off_returns_zero_without_touching_ledger(self, tmp_path, monkeypatch):
        """Flag off -> 0.0 and the store path is never even opened."""
        monkeypatch.delenv("ENABLE_LESSONS_LEDGER_INFLUENCE", raising=False)
        store = tmp_path / "should_not_exist.db"
        monkeypatch.setenv("LESSONS_LEDGER_STORE_PATH", str(store))
        _clear_settings_cache()
        # Point the singleton at a fresh path and confirm it is untouched.
        from webpent.brain import lessons as lessons_mod
        lessons_mod._scoped_singletons.clear()
        try:
            assert compute_lesson_adjustment(_make_hypothesis(VulnClass.SQLI), {}) == 0.0
            assert not store.exists()
        finally:
            lessons_mod._scoped_singletons.clear()

    def test_flag_off_score_identical(self, tmp_path, monkeypatch):
        """With the flag off the score is arithmetically identical to the
        pre-wiring formula, even with lessons present in a store."""
        monkeypatch.delenv("ENABLE_LESSONS_LEDGER_INFLUENCE", raising=False)
        monkeypatch.setenv("LESSONS_LEDGER_STORE_PATH", str(tmp_path / "off.db"))
        _clear_settings_cache()
        # Populate the singleton store (flag off) with a positive lesson.
        from webpent.brain import lessons as lessons_mod
        lessons_mod._singleton = None
        lessons_mod._scoped_singletons.clear()
        try:
            ledger = get_lessons_ledger()
            ledger.record_lesson(
                Lesson(lesson_id="L-off-1", scope="run",
                       statement="sqli: prior family",
                       confidence=0.9))
            h = _make_hypothesis(VulnClass.SQLI)
            baseline = score_hypothesis(h, {"run_number": 1})
            assert compute_lesson_adjustment(h, {"run_number": 1}) == 0.0
            again = score_hypothesis(h, {"run_number": 1})
            assert baseline == again
        finally:
            lessons_mod._singleton = None
            lessons_mod._scoped_singletons.clear()

    def test_flag_on_positive_lesson_bonuses_bounded(self, tmp_path, monkeypatch):
        monkeypatch.setenv("ENABLE_LESSONS_LEDGER_INFLUENCE", "true")
        monkeypatch.setenv("LESSONS_LEDGER_STORE_PATH", str(tmp_path / "s.db"))
        _clear_settings_cache()
        from webpent.brain import lessons as lessons_mod
        lessons_mod._singleton = None
        lessons_mod._scoped_singletons.clear()
        try:
            ledger = get_lessons_ledger()
            h = _make_hypothesis(VulnClass.SQLI)
            # The score moves UP by exactly W_NOVELTY * adj / W_SUM
            # relative to the SAME ledger with no matching lessons yet
            # (baseline scored first, then the lesson is recorded).
            baseline = score_hypothesis(h, {"run_number": 0})
            ledger.record_lesson(
                Lesson(lesson_id="L-bonus-1", scope="run",
                       statement="sqli: family prior", confidence=0.1))
            adj = compute_lesson_adjustment(h, {"run_number": 0})
            with_flag_on = score_hypothesis(h, {"run_number": 0})
            delta = with_flag_on - baseline
            assert delta == pytest.approx(0.10 * adj / (0.25 + 0.20 + 0.10 + 0.15 + 0.10 + 0.20))
        finally:
            lessons_mod._singleton = None
            lessons_mod._scoped_singletons.clear()

    def test_negative_feedback_lesson_penalises(self, tmp_path, monkeypatch):
        monkeypatch.setenv("ENABLE_LESSONS_LEDGER_INFLUENCE", "true")
        monkeypatch.setenv("LESSONS_LEDGER_STORE_PATH", str(tmp_path / "neg.db"))
        _clear_settings_cache()
        from webpent.brain import lessons as lessons_mod
        lessons_mod._singleton = None
        lessons_mod._scoped_singletons.clear()
        try:
            ledger = get_lessons_ledger()
            ledger.record_lesson(
                Lesson(lesson_id="L-neg-1", scope="run",
                       statement="sqli: false-positive prone family",
                       confidence=0.2, outcome_feedback=["negative"]))
            adj = compute_lesson_adjustment(_make_hypothesis(VulnClass.SQLI), {"run_number": 0})
            assert adj == pytest.approx(-0.2)
            # A negative lesson cannot push novelty below zero overall.
            assert adj >= -0.25 - 1e-9
        finally:
            lessons_mod._singleton = None
            lessons_mod._scoped_singletons.clear()

    def test_family_mismatch_is_neutral(self, tmp_path, monkeypatch):
        monkeypatch.setenv("ENABLE_LESSONS_LEDGER_INFLUENCE", "true")
        monkeypatch.setenv("LESSONS_LEDGER_STORE_PATH", str(tmp_path / "mis.db"))
        _clear_settings_cache()
        from webpent.brain import lessons as lessons_mod
        lessons_mod._singleton = None
        lessons_mod._scoped_singletons.clear()
        try:
            ledger = get_lessons_ledger()
            ledger.record_lesson(
                Lesson(lesson_id="L-mis-1", scope="run",
                       statement="xss: unrelated family", confidence=0.9))
            assert compute_lesson_adjustment(
                _make_hypothesis(VulnClass.SQLI), {"run_number": 0}
            ) == 0.0
        finally:
            lessons_mod._singleton = None
            lessons_mod._scoped_singletons.clear()

    def test_adjacent_engagement_score_delta_is_small(self, tmp_path, monkeypatch):
        """Acceptance criterion: two consecutive engagements on the same
        tech stack — a same-family hypothesis scores slightly higher in
        the second (a small documented delta, not a leap)."""
        monkeypatch.setenv("ENABLE_LESSONS_LEDGER_INFLUENCE", "true")
        monkeypatch.setenv("LESSONS_LEDGER_STORE_PATH", str(tmp_path / "loop.db"))
        _clear_settings_cache()
        from webpent.brain import lessons as lessons_mod
        lessons_mod._singleton = None
        lessons_mod._scoped_singletons.clear()
        try:
            ledger = get_lessons_ledger()
            h = _make_hypothesis(VulnClass.SQLI)
            state = {"run_number": 0}
            score_first = score_hypothesis(h, state)
            # Engagement 1 ends; its outcome becomes a run lesson...
            emit_run_lessons(
                ledger,
                confirmed_by_family={"sqli": 2},
                false_positives_by_family={"sqli": 0},
                run_number=1,
            )
            ledger.apply_lesson(
                [l.lesson_id for l in ledger.retrieve_lessons(
                    family="sqli", run_number=2)][0], run_number=1)
            # ...and engagement 2 scores the same hypothesis slightly higher.
            state_next = {"run_number": 2}
            score_second = score_hypothesis(h, state_next)
            delta = score_second - score_first
            assert 0.0 < delta <= 0.10  # small, bounded by the novelty channel
            # And the flag-off twin shows zero delta for the same story.
            monkeypatch.delenv("ENABLE_LESSONS_LEDGER_INFLUENCE", raising=False)
            _clear_settings_cache()
            assert score_hypothesis(h, state_next) == score_first
        finally:
            lessons_mod._singleton = None
            lessons_mod._scoped_singletons.clear()


# ---------------------------------------------------------------------------
# Phase 3 — end-of-engagement emission
# ---------------------------------------------------------------------------
class TestLessonEmission:
    def test_family_outcomes_become_auto_approved_run_lessons(self, tmp_path):
        ledger = LessonsLedger(store_path=str(tmp_path / "emit.db"))
        recorded = emit_run_lessons(
            ledger,
            confirmed_by_family={"sqli": 3, "xss": 1},
            false_positives_by_family={"sqli": 1, "xss": 2},
            run_number=7, cycle=2, lab="juice_shop",
        )
        assert len(recorded) == 2
        for lesson in recorded:
            assert lesson.scope == "run"
            assert lesson.is_approved() is True
            assert lesson.approved_by == "auto"
            assert lesson.proposed_by == "scorecard"
        by_id = {l.lesson_id: l for l in recorded}
        # Deterministic ids.
        assert set(by_id) == {"L-run-7-cycle-2-sqli",
                              "L-run-7-cycle-2-xss"}
        # Precision drives confidence and polarity.
        assert by_id["L-run-7-cycle-2-sqli"].confidence == pytest.approx(0.75)
        assert by_id["L-run-7-cycle-2-sqli"].outcome_feedback == []
        assert by_id["L-run-7-cycle-2-xss"].confidence == pytest.approx(0.3333)
        assert by_id["L-run-7-cycle-2-xss"].outcome_feedback == ["negative"]

    def test_emission_is_idempotent(self, tmp_path):
        """Re-emitting the same engagement summary upserts, never
        duplicates (deterministic lesson ids)."""
        store = str(tmp_path / "idem.db")
        ledger = LessonsLedger(store_path=store)
        kwargs = dict(
            confirmed_by_family={"idor": 1}, false_positives_by_family={},
            run_number=1,
        )
        first = emit_run_lessons(ledger, **kwargs)
        second = emit_run_lessons(ledger, **kwargs)
        assert [l.lesson_id for l in first] == [l.lesson_id for l in second]
        assert len(ledger.get_all_lessons()) == 1

    def test_emission_persists_and_feeds_scoring(self, tmp_path, monkeypatch):
        """The full loop across instances: engagement 1 emits lessons
        into a persistent store; a NEW ledger instance loads them; with
        the flag on the same-family hypothesis scores higher."""
        store = str(tmp_path / "feed.db")
        first = LessonsLedger(store_path=store)
        emit_run_lessons(
            first,
            confirmed_by_family={"idor": 4},
            false_positives_by_family={"idor": 0},
            run_number=1,
        )

        monkeypatch.setenv("ENABLE_LESSONS_LEDGER_INFLUENCE", "true")
        monkeypatch.setenv("LESSONS_LEDGER_STORE_PATH", store)
        _clear_settings_cache()
        second = LessonsLedger(store_path=store)
        lessons = second.retrieve_lessons(family="idor", run_number=2)
        assert len(lessons) == 1
        assert lessons[0].is_approved() is True
        from webpent.brain import lessons as lessons_mod
        lessons_mod._singleton = None
        lessons_mod._scoped_singletons.clear()
        try:
            adj = compute_lesson_adjustment(_make_hypothesis(VulnClass.IDOR), {"run_number": 2})
            assert adj > 0.0
        finally:
            lessons_mod._singleton = None
            lessons_mod._scoped_singletons.clear()

    def test_scorecard_emission_bridge(self, tmp_path):
        """The ScorecardEmission bridge: family breakdowns win when given;
        otherwise a single aggregate engagement lesson from confirmed_total
        plus the emission's honesty false-positive count (no invented
        per-family attribution); a zero-outcome emission emits nothing."""
        ledger = LessonsLedger(store_path=str(tmp_path / "bridge.db"))
        emitter = ScorecardEmitter()
        emission = emitter.emit(
            lab="juice_shop", cycle=1, full_chain_outcomes=2,
            false_positives=1, findings=3, cost_usd=1.0, total_requests=10,
        )
        # Aggregate-only path: one engagement-family lesson with both counts.
        recorded = lessons_from_scorecard_emission(
            ledger, emission, run_number=1, confirmed_total=3)
        assert len(recorded) == 1
        lesson = recorded[0]
        assert lesson.lesson_id == "L-run-1-cycle-1-engagement"
        assert "confirmed=3" in lesson.statement
        assert "false_positive=1" in lesson.statement
        assert lesson.is_approved() is True

        # Family breakdown path: emission-level lab/cycle flow through.
        recorded2 = lessons_from_scorecard_emission(
            ledger, emission, run_number=1,
            confirmed_by_family={"ssrf": 2},
            false_positives_by_family={"ssrf": 0},
        )
        assert [l.lesson_id for l in recorded2] == ["L-run-1-cycle-1-ssrf"]

        # Zero outcomes -> nothing emitted (no empty lesson).
        empty = emitter.emit(lab="x", cycle=1, full_chain_outcomes=0)
        assert lessons_from_scorecard_emission(
            ledger, empty, run_number=9, confirmed_total=0) == []

    def test_zero_outcome_family_teaches_nothing(self, tmp_path):
        ledger = LessonsLedger(store_path=str(tmp_path / "zero.db"))
        assert emit_run_lessons(
            ledger, confirmed_by_family={}, false_positives_by_family={},
            run_number=1,
        ) == []


# ---------------------------------------------------------------------------
# Invariants
# ---------------------------------------------------------------------------
class TestInvariants:
    def test_ledger_still_advisory_only_after_activation(self, tmp_path):
        ledger = LessonsLedger(store_path=str(tmp_path / "adv.db"))
        ledger.record_lesson(
            Lesson(lesson_id="L-adv", scope="run", statement="x"))
        assert ledger.is_advisory_only() is True

    def test_new_settings_fields_exist(self):
        settings = get_settings()
        assert settings.enable_lessons_ledger_influence is False
        assert settings.lessons_ledger_store_path
