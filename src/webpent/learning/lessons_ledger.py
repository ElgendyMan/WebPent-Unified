"""webpent.learning.lessons_ledger — evidence-bound campaign memory (ق3).

The lessons subsystem was deliberately removed in the 0.29.0 G-1 window
because the original implementation inflated unbounded scores and leaked
knowledge ACROSS campaigns (the R2-dojo-01 repeat of the same failure
shape). This ledger is the corrected re-introduction, with the failure
modes designed OUT:

  - every lesson is BOUND to an evidence digest (sha256 of the proof
    bundle / finding record it was learned from); a lesson without a
    verifiable digest cannot be recorded — anti-fabrication by
    construction;
  - ISOLATION: records carry ``client_id`` + ``engagement_id`` and every
    read is scoped to one engagement; cross-client reads are impossible
    through the API (the 0.29.0 leak);
  - DECAY: every lesson carries a decay weight that shrinks with
    (a) age in days and (b) every retrieval that was NOT followed by a
    confirmation; a floor keeps the lesson addressable but its numeric
    influence decays toward it — stale knowledge cannot dominate;
  - CAP: lessons influence RANKING only, through a bounded additive term
    (``influence_cap``); they can NEVER move a verification outcome, a
    verdict, or a score above the cap — the oracle stays sovereign;
  - the store is append-only JSONL with per-record digests and a
    chain, so memory is replayable and tampering is detectable (same
    property as the audit log in autonomy_tiers).
"""
from __future__ import annotations

import hashlib
import hmac
import json
import math
import os
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

__all__ = [
    "LessonsLedger",
    "Lesson",
    "LessonRejected",
    "LESSON_KINDS",
    "influence_of",
]

LESSON_KINDS = frozenset({
    "technique_worked",
    "technique_failed",
    "surface_shape",
    "tool_misuse",
})

#: A lesson's numeric influence on RANKING never exceeds this.
INFLUENCE_CAP = 0.15
#: Decay floor: the lesson stays addressable; its influence decays to this.
DECAY_FLOOR = 0.05
#: Half-life in days for the time decay.
HALF_LIFE_DAYS = 14.0
#: Confidence weight a fresh lesson carries.
FRESH_WEIGHT = 1.0


class LessonRejected(Exception):
    """A lesson failed the anti-fabrication or schema gate."""


@dataclass(frozen=True)
class Lesson:
    """One evidence-bound lesson, scoped to one engagement."""

    lesson_id: str
    client_id: str
    engagement_id: str
    kind: str
    statement: str
    evidence_digest: str
    created_at: float
    weight: float = FRESH_WEIGHT
    retrievals: int = 0
    unconfirmed_retrievals: int = 0

    def __post_init__(self) -> None:
        if self.kind not in LESSON_KINDS:
            raise LessonRejected(
                f"unknown lesson kind: {self.kind!r} "
                f"(one of {sorted(LESSON_KINDS)})"
            )
        if not self.statement.strip():
            raise LessonRejected("empty lesson statement")
        if len(self.evidence_digest) != 64:
            raise LessonRejected(
                "a lesson must carry the sha256 evidence digest it was "
                "learned from"
            )

    def to_dict(self) -> dict[str, Any]:
        return {
            "lesson_id": self.lesson_id,
            "client_id": self.client_id,
            "engagement_id": self.engagement_id,
            "kind": self.kind,
            "statement": self.statement,
            "evidence_digest": self.evidence_digest,
            "created_at": self.created_at,
            "weight": self.weight,
            "retrievals": self.retrievals,
            "unconfirmed_retrievals": self.unconfirmed_retrievals,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Lesson":
        return cls(
            lesson_id=data["lesson_id"],
            client_id=data["client_id"],
            engagement_id=data["engagement_id"],
            kind=data["kind"],
            statement=data["statement"],
            evidence_digest=data["evidence_digest"],
            created_at=float(data["created_at"]),
            weight=float(data.get("weight", FRESH_WEIGHT)),
            retrievals=int(data.get("retrievals", 0)),
            unconfirmed_retrievals=int(
                data.get("unconfirmed_retrievals", 0)
            ),
        )


def influence_of(
    lesson: Lesson, *, now: float | None = None
) -> float:
    """Bounded ranking influence: decayed weight, capped.

    influence = cap × decayed_weight, where
      decayed_weight = weight × 0.5 ** (age_days / half_life)
                      × 0.5 ** unconfirmed_retrievals
    floored at DECAY_FLOOR (never zero — the lesson stays addressable).
    The value NEVER exceeds INFLUENCE_CAP regardless of history.
    """
    now = now if now is not None else time.time()
    age_days = max(0.0, (now - lesson.created_at) / 86400.0)
    time_factor = math.pow(0.5, age_days / HALF_LIFE_DAYS)
    unconfirmed_factor = math.pow(
        0.5, max(0, lesson.unconfirmed_retrievals)
    )
    decayed = lesson.weight * time_factor * unconfirmed_factor
    decayed = max(decayed, DECAY_FLOOR)
    return min(INFLUENCE_CAP, INFLUENCE_CAP * decayed)


def digest_record(record: dict[str, Any]) -> str:
    """The evidence digest a lesson must be bound to."""
    return hashlib.sha256(
        json.dumps(record, sort_keys=True, default=str).encode("utf-8")
    ).hexdigest()


class LessonsLedger:
    """Append-only, chain-signed, engagement-scoped lesson store."""

    def __init__(
        self,
        path: str | Path,
        *,
        secret: str = "",
        evidence_reader: Any = None,
    ) -> None:
        self.path = Path(path) if path else None
        self._secret = secret or os.environ.get(
            "WEBPENT_AUDIT_SECRET", "dev-chain"
        )
        self._lessons: list[Lesson] = []
        self._prev_digest = ""
        # evidence_reader: optional callable(digest) -> record, used to
        # VERIFY that a bound digest actually exists in the evidence
        # store (anti-fabrication beyond well-formedness).
        self._evidence_reader = evidence_reader

    # -- write path ----------------------------------------------------

    def record_lesson(
        self,
        *,
        client_id: str,
        engagement_id: str,
        kind: str,
        statement: str,
        evidence_record: dict[str, Any],
        created_at: float | None = None,
    ) -> Lesson:
        """Record one lesson bound to the digest of its evidence.

        The digest is COMPUTED here from the caller-supplied evidence
        record — a caller cannot claim a digest it did not present the
        record for. When an evidence_reader is configured, the record
        must also be present in the evidence store.
        """
        if not client_id.strip() or not engagement_id.strip():
            raise LessonRejected(
                "lessons are engagement-scoped: client_id and "
                "engagement_id are required"
            )
        digest = digest_record(evidence_record)
        if self._evidence_reader is not None:
            stored = self._evidence_reader(digest)
            if stored is None:
                raise LessonRejected(
                    "evidence digest not found in the evidence store: "
                    "no lesson without verifiable evidence"
                )
        lesson_id = digest[:16]
        if any(
            existing.lesson_id == lesson_id
            and existing.engagement_id == engagement_id
            for existing in self._lessons
        ):
            raise LessonRejected(
                f"duplicate lesson for the same evidence in engagement "
                f"{engagement_id!r}"
            )
        lesson = Lesson(
            lesson_id=lesson_id,
            client_id=client_id,
            engagement_id=engagement_id,
            kind=kind,
            statement=statement,
            evidence_digest=digest,
            created_at=created_at if created_at is not None else time.time(),
        )
        self._lessons.append(lesson)
        self._append(
            {
                "event": "lesson_recorded",
                "lesson": lesson.to_dict(),
            }
        )
        return lesson

    def confirm_retrieval(self, lesson_id: str, engagement_id: str,
                          client_id: str) -> bool:
        """A retrieval WAS followed by a confirmation: reinforce."""
        lesson = self._scoped_lesson(lesson_id, engagement_id, client_id)
        if lesson is None:
            return False
        replacement = Lesson(
            lesson_id=lesson.lesson_id,
            client_id=lesson.client_id,
            engagement_id=lesson.engagement_id,
            kind=lesson.kind,
            statement=lesson.statement,
            evidence_digest=lesson.evidence_digest,
            created_at=lesson.created_at,
            weight=min(2.0, lesson.weight * 1.25),
            retrievals=lesson.retrievals + 1,
            unconfirmed_retrievals=lesson.unconfirmed_retrievals,
        )
        self._replace(replacement)
        self._append({"event": "lesson_confirmed",
                      "lesson_id": lesson_id,
                      "engagement_id": engagement_id})
        return True

    def mark_unconfirmed_retrieval(
            self, lesson_id: str, engagement_id: str,
            client_id: str) -> bool:
        """A retrieval NOT followed by a confirmation: decay harder."""
        lesson = self._scoped_lesson(lesson_id, engagement_id, client_id)
        if lesson is None:
            return False
        replacement = Lesson(
            lesson_id=lesson.lesson_id,
            client_id=lesson.client_id,
            engagement_id=lesson.engagement_id,
            kind=lesson.kind,
            statement=lesson.statement,
            evidence_digest=lesson.evidence_digest,
            created_at=lesson.created_at,
            weight=lesson.weight,
            retrievals=lesson.retrievals + 1,
            unconfirmed_retrievals=lesson.unconfirmed_retrievals + 1,
        )
        self._replace(replacement)
        self._append({"event": "lesson_unconfirmed",
                      "lesson_id": lesson_id,
                      "engagement_id": engagement_id})
        return True

    # -- read path (scoped) ---------------------------------------------

    def lessons_for(
        self, *, client_id: str, engagement_id: str,
        kind: str | None = None, now: float | None = None,
    ) -> list[tuple[Lesson, float]]:
        """Lessons of ONE engagement, ranked by bounded influence.

        There is no cross-engagement or cross-client read: the scope is
        part of the API, not a filter the caller can forget.
        """
        scoped = [
            lesson
            for lesson in self._lessons
            if lesson.client_id == client_id
            and lesson.engagement_id == engagement_id
            and (kind is None or lesson.kind == kind)
        ]
        ranked = sorted(
            scoped,
            key=lambda lesson: (
                -influence_of(lesson, now=now),
                lesson.lesson_id,
            ),
        )
        return [(lesson, influence_of(lesson, now=now))
                for lesson in ranked]

    def verify_chain(self) -> tuple[bool, str]:
        if self.path is None or not self.path.exists():
            return True, "empty"
        prev = ""
        with self.path.open("r", encoding="utf-8") as fh:
            for lineno, line in enumerate(fh, 1):
                line = line.strip()
                if not line:
                    continue
                try:
                    record = json.loads(line)
                except json.JSONDecodeError as exc:
                    return False, f"line {lineno}: bad json ({exc})"
                event = record.get("event") or {}
                expected = hmac.new(
                    self._secret.encode("utf-8"),
                    json.dumps(event, sort_keys=True, default=str).encode(
                        "utf-8"
                    ),
                    hashlib.sha256,
                ).hexdigest()
                if record.get("sig") != expected or event.get("prev") != prev:
                    return False, f"line {lineno}: chain break"
                prev = record["sig"]
        return True, "ok"

    # -- internals -------------------------------------------------------

    def _scoped_lesson(
            self, lesson_id: str, engagement_id: str,
            client_id: str) -> Lesson | None:
        for lesson in self._lessons:
            if (
                lesson.lesson_id == lesson_id
                and lesson.engagement_id == engagement_id
                and lesson.client_id == client_id
            ):
                return lesson
        return None

    def _replace(self, replacement: Lesson) -> None:
        for index, lesson in enumerate(self._lessons):
            if (
                lesson.lesson_id == replacement.lesson_id
                and lesson.engagement_id == replacement.engagement_id
                and lesson.client_id == replacement.client_id
            ):
                self._lessons[index] = replacement
                return

    def _append(self, event: dict[str, Any]) -> None:
        event = dict(event)
        event["prev"] = self._prev_digest
        payload = json.dumps(event, sort_keys=True, default=str)
        digest = hmac.new(
            self._secret.encode("utf-8"),
            payload.encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()
        if self.path is not None:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            with self.path.open("a", encoding="utf-8") as fh:
                fh.write(
                    json.dumps(
                        {"sig": digest, "event": event},
                        sort_keys=True,
                        default=str,
                    )
                    + "\n"
                )
        self._prev_digest = digest
