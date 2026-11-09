"""Judgment Council — U-JC-6: the Dissent Register.

Minority opinions are never thrown away (JC-L-5). The register is an
append-only JSONL store: every ``record`` and every ``link_outcome``
appends a line, so history is never rewritten. Reads resolve the latest
state per (session_id, advocate_id). From the linked outcomes the register
computes per-advocate accuracy, detects a persistent minority whose
dissent keeps proving right, and exports lesson candidates for the
lessons ledger.
"""

from __future__ import annotations

import json
import logging
import time
from contextlib import suppress
from pathlib import Path
from typing import Any

from webpent.jc.contracts import Verdict, clamp01

_LOG = logging.getLogger(__name__)

MIN_ENTRIES_FOR_PERSISTENCE = 3
PERSISTENT_ACCURACY = 0.6


class DissentRegister:
    """Append-only store of minority opinions and their outcomes."""

    def __init__(self, path: Any) -> None:
        self.path = Path(str(path))

    # ------------------------------------------------------------- record
    def record(self, verdict: Verdict, *, now: float | None = None) -> int:
        """Append every dissenting view of a verdict. Returns lines written."""
        stamp = time.time() if now is None else float(now)
        rows = []
        for d in verdict.dissent:
            rows.append({
                "session_id": verdict.session_id,
                "advocate_id": d.advocate_id,
                "claim": d.claim,
                "reasoning": d.reasoning,
                "confidence": round(clamp01(d.confidence), 4),
                "outcome": None,
                "recorded_at": stamp,
            })
        # R2-jc-08: return the number of rows actually written.
        return self._append(rows)

    def link_outcome(self, session_id: str, outcome: str, *,
                     now: float | None = None) -> int:
        """Append an outcome update for every dissent of one session.

        Returns the number of rows actually written (R2-jc-08): a failed
        write must not be reported as persisted dissent.
        """
        stamp = time.time() if now is None else float(now)
        rows = [
            {
                "session_id": str(session_id),
                "advocate_id": row["advocate_id"],
                "outcome": str(outcome)[:20],
                "linked_at": stamp,
            }
            for row in self._resolve().values()
            if row["session_id"] == str(session_id)
        ]
        # R2-jc-08: return the number of rows actually written.
        return self._append(rows)

    # -------------------------------------------------------------- reads
    def _resolve(self) -> dict[tuple[str, str], dict]:
        """Latest state per (session_id, advocate_id) from the whole log."""
        state: dict[tuple[str, str], dict] = {}
        try:
            lines = self.path.read_text(encoding="utf-8").splitlines()
        except OSError:
            return state
        for line in lines:
            row = None
            with suppress(ValueError):
                row = json.loads(line)
            if not isinstance(row, dict):
                continue
            key = (str(row.get("session_id") or ""), str(row.get("advocate_id") or ""))
            if key == ("", ""):
                continue
            entry = state.setdefault(key, {"session_id": key[0], "advocate_id": key[1],
                                           "claim": "", "confidence": 0.0,
                                           "outcome": None})
            if "claim" in row and row["claim"]:
                entry["claim"] = row["claim"]
            if "confidence" in row:
                entry["confidence"] = clamp01(row["confidence"])
            if "outcome" in row:
                entry["outcome"] = row["outcome"]
        return state

    def get_dissent_accuracy(self, advocate_id: str) -> float | None:
        """accuracy = correct / (correct + incorrect); None without data."""
        resolved = [
            r for r in self._resolve().values()
            if r["advocate_id"] == str(advocate_id)
            and r["outcome"] in ("correct", "incorrect")
        ]
        if not resolved:
            return None
        correct = sum(1 for r in resolved if r["outcome"] == "correct")
        return correct / len(resolved)

    def get_persistent_minority(self) -> list[str]:
        """Advocates whose dissent proved right at least 60% of >=3 votes."""
        accuracies: dict[str, list[float | None]] = {}
        for r in self._resolve().values():
            if r["outcome"] in ("correct", "incorrect"):
                accuracies.setdefault(r["advocate_id"], []).append(
                    1.0 if r["outcome"] == "correct" else 0.0
                )
        return sorted(
            aid for aid, marks in accuracies.items()
            if len(marks) >= MIN_ENTRIES_FOR_PERSISTENCE
            and sum(marks) / len(marks) >= PERSISTENT_ACCURACY
        )

    def export_for_lessons(self) -> list[dict[str, Any]]:
        """Lesson candidates: dissenting views that turned out correct."""
        lessons = []
        for r in self._resolve().values():
            if r["outcome"] == "correct" and r["claim"]:
                lessons.append({
                    "lesson_kind": "dissent_proved_right",
                    "advocate_id": r["advocate_id"],
                    "claim": r["claim"],
                    "session_id": r["session_id"],
                    "confidence": r["confidence"],
                    "advisory": True,
                })
        return lessons

    # -------------------------------------------------------------- write
    def _append(self, rows: list[dict[str, Any]]) -> int:
        """Append rows; returns the number actually written (R2-jc-08)."""
        if not rows:
            return 0
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            text = "".join(json.dumps(r, ensure_ascii=False) + "\n" for r in rows)
            with self.path.open("a", encoding="utf-8") as handle:
                handle.write(text)
            return len(rows)
        except OSError as exc:
            _LOG.warning("dissent register write failed: %s", exc)
            return 0


__all__ = ["DissentRegister"]
