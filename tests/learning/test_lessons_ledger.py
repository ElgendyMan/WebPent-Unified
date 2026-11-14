"""ق3 — safe lessons ledger contract tests.

Anti-fabrication, engagement isolation, decay, the ranking-only
influence cap and the signed replayable chain.
"""
from __future__ import annotations

import hashlib
import json
import time

import pytest

from webpent.learning.lessons_ledger import (
    DECAY_FLOOR,
    INFLUENCE_CAP,
    Lesson,
    LessonRejected,
    LessonsLedger,
    influence_of,
)


EVIDENCE = {"kind": "proof_bundle", "finding": "idor-1", "verdict": "confirmed"}


def _ledger(tmp_path, **kwargs) -> LessonsLedger:
    return LessonsLedger(tmp_path / "lessons.jsonl", **kwargs)


def _record(ledger: LessonsLedger, engagement="eng-1", kind="technique_worked",
            statement="the /api/items/{id} enumeration needs a second id",
            evidence=None):
    return ledger.record_lesson(
        client_id="client-a",
        engagement_id=engagement,
        kind=kind,
        statement=statement,
        evidence_record=evidence if evidence is not None else EVIDENCE,
    )


def _json_bytes(record) -> bytes:
    return json.dumps(record, sort_keys=True, default=str).encode("utf-8")


# -- anti-fabrication ------------------------------------------------

def test_lesson_requires_wellformed_evidence_digest():
    with pytest.raises(LessonRejected):
        Lesson(
            lesson_id="l1", client_id="c", engagement_id="e",
            kind="technique_worked", statement="s",
            evidence_digest="deadbeef", created_at=0.0,
        )


def test_lesson_kind_is_whitelisted():
    with pytest.raises(LessonRejected):
        Lesson(
            lesson_id="l1", client_id="c", engagement_id="e",
            kind="free_text_opinion", statement="s",
            evidence_digest="a" * 64, created_at=0.0,
        )


def test_lessons_without_scope_are_rejected(tmp_path):
    ledger = _ledger(tmp_path)
    with pytest.raises(LessonRejected):
        ledger.record_lesson(
            client_id=" ", engagement_id="eng-1",
            kind="technique_worked", statement="s",
            evidence_record=EVIDENCE,
        )


def test_digest_must_exist_in_the_evidence_store_when_reader_is_set(tmp_path):
    store: dict[str, dict] = {}

    ledger = _ledger(tmp_path, evidence_reader=lambda digest: store.get(digest))
    with pytest.raises(LessonRejected):
        _record(ledger)
    store[hashlib.sha256(_json_bytes(EVIDENCE)).hexdigest()] = EVIDENCE
    lesson = _record(ledger)
    assert lesson.lesson_id


def test_digest_is_computed_from_the_presented_record(tmp_path):
    ledger = _ledger(tmp_path)
    lesson = _record(ledger, evidence={"a": 1})
    assert lesson.evidence_digest == hashlib.sha256(
        _json_bytes({"a": 1})
    ).hexdigest()


def test_duplicate_lesson_for_same_evidence_is_rejected(tmp_path):
    ledger = _ledger(tmp_path)
    _record(ledger)
    with pytest.raises(LessonRejected):
        _record(ledger, statement="a different statement, same evidence")


# -- engagement isolation --------------------------------------------

def test_reads_never_leak_across_engagements_or_clients(tmp_path):
    ledger = _ledger(tmp_path)
    _record(ledger, engagement="eng-1")
    _record(ledger, engagement="eng-2")
    seen_1 = ledger.lessons_for(client_id="client-a", engagement_id="eng-1")
    seen_2 = ledger.lessons_for(client_id="client-a", engagement_id="eng-2")
    assert len(seen_1) == 1 and len(seen_2) == 1
    assert seen_1[0][0].engagement_id == "eng-1"
    # a different client sees nothing — scope is in the API
    assert ledger.lessons_for(
        client_id="client-b", engagement_id="eng-1") == []


def test_mutation_apis_are_scoped_too(tmp_path):
    ledger = _ledger(tmp_path)
    lesson = _record(ledger, engagement="eng-1")
    assert ledger.confirm_retrieval(
        lesson.lesson_id, "eng-OTHER", "client-a") is False
    assert ledger.confirm_retrieval(
        lesson.lesson_id, "eng-1", "client-b") is False
    assert ledger.confirm_retrieval(
        lesson.lesson_id, "eng-1", "client-a") is True


# -- decay and the influence cap ---------------------------------------

def test_influence_is_capped_regardless_of_reinforcement(tmp_path):
    ledger = _ledger(tmp_path)
    lesson = _record(ledger)
    for _ in range(50):
        ledger.confirm_retrieval(
            lesson.lesson_id, "eng-1", "client-a")
    fresh = ledger.lessons_for(
        client_id="client-a", engagement_id="eng-1")[0][0]
    assert influence_of(fresh) <= INFLUENCE_CAP


def test_age_and_unconfirmed_retrievals_decay_influence(tmp_path):
    now = time.time()
    old = Lesson(
        lesson_id="old", client_id="c", engagement_id="e",
        kind="technique_worked", statement="s", evidence_digest="a" * 64,
        created_at=now - 120 * 86400.0,  # ~8.5 half-lives
    )
    assert influence_of(old, now=now) == pytest.approx(
        INFLUENCE_CAP * DECAY_FLOOR)
    decayed_by_use = Lesson(
        lesson_id="used", client_id="c", engagement_id="e",
        kind="technique_worked", statement="s", evidence_digest="b" * 64,
        created_at=now, unconfirmed_retrievals=3,
    )
    fresh = Lesson(
        lesson_id="new", client_id="c", engagement_id="e",
        kind="technique_worked", statement="s", evidence_digest="c" * 64,
        created_at=now,
    )
    assert influence_of(decayed_by_use, now=now) < influence_of(
        fresh, now=now)


def test_unconfirmed_retrieval_decays_the_live_lesson(tmp_path):
    ledger = _ledger(tmp_path)
    lesson = _record(ledger)
    base = ledger.lessons_for(
        client_id="client-a", engagement_id="eng-1")[0][1]
    for _ in range(4):
        ledger.mark_unconfirmed_retrieval(
            lesson.lesson_id, "eng-1", "client-a")
    after = ledger.lessons_for(
        client_id="client-a", engagement_id="eng-1")[0][1]
    assert after < base


def test_fresh_lesson_outranks_a_stale_one(tmp_path):
    ledger = _ledger(tmp_path)
    now = time.time()
    ledger.record_lesson(
        client_id="client-a", engagement_id="eng-1",
        kind="technique_worked", statement="fresh",
        evidence_record={"n": 1}, created_at=now,
    )
    ledger.record_lesson(
        client_id="client-a", engagement_id="eng-1",
        kind="surface_shape", statement="stale",
        evidence_record={"n": 2}, created_at=now - 90 * 86400.0,
    )
    ranked = ledger.lessons_for(
        client_id="client-a", engagement_id="eng-1", now=now)
    assert ranked[0][0].statement == "fresh"


# -- chain integrity ---------------------------------------------------

def test_chain_is_signed_and_replayable(tmp_path):
    ledger = _ledger(tmp_path)
    _record(ledger)
    _record(ledger, engagement="eng-2", evidence={"other": True})
    ok, detail = ledger.verify_chain()
    assert ok is True, detail


def test_chain_tampering_is_detected(tmp_path):
    path = tmp_path / "lessons.jsonl"
    ledger = _ledger(tmp_path)
    _record(ledger)
    lines = path.read_text(encoding="utf-8").splitlines()
    forged = json.loads(lines[-1])
    forged["event"]["lesson"]["statement"] = "tampered"
    lines[-1] = json.dumps(forged)
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    ok, detail = LessonsLedger(path).verify_chain()
    assert ok is False and "chain" in detail
