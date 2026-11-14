"""Judgment Council — U-JC-9: the Council Memory.

The council remembers its own decisions (JC-L-5, L-3):

    context_hash   sha256 of the canonical context (deterministic)
    exact match    same hash -> "we did this before"
    similar match  top-k by shared context keys with equal values
    pattern        >= 5 similar decisions with the same action

Storage is a JSONL log bounded by a retention policy (default 180 days):
``record`` compacts the file atomically, dropping entries past retention.
Every recorded decision also appends a compact bias-compatible row to the
sibling ``sessions.jsonl``, the log the bias detector (U-JC-8), the
dashboard and the CLI ``jc sessions`` command read.
"""

from __future__ import annotations

import fcntl
import json
import logging
import os
import tempfile
import time
from contextlib import suppress
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from webpent.jc.contracts import CouncilSession, Verdict, context_hash

_LOG = logging.getLogger(__name__)

DEFAULT_RETENTION_DAYS = 180
PATTERN_MIN_SAMPLES = 5
#: sibling log the bias detector, dashboard and CLI read (RT-02)
SESSIONS_LOG_NAME = "sessions.jsonl"


@dataclass
class Pattern:
    """A repeated decision pattern detected by the memory."""

    context_hash_prefix: str
    action: str
    count: int
    outcome: str | None = None
    session_ids: list[str] = field(default_factory=list)

    def as_dict(self) -> dict[str, Any]:
        return {
            "context_hash_prefix": self.context_hash_prefix,
            "action": self.action,
            "count": self.count,
            "outcome": self.outcome,
            "session_ids": self.session_ids,
            "advisory": True,
        }


class CouncilMemory:
    """Bounded, deterministic memory of council decisions."""

    def __init__(self, path: Any, *, retention_days: int = DEFAULT_RETENTION_DAYS,
                 now_ts: float | None = None) -> None:
        self.path = Path(str(path))
        self.retention_days = int(retention_days)
        self._now_ts = time.time() if now_ts is None else float(now_ts)

    # ------------------------------------------------------------- record
    def record(self, session: CouncilSession, verdict: Verdict, *,
               ts: float | None = None) -> None:
        """Append one decision, then compact the file to the retention window."""
        stamp = self._now_ts if ts is None else float(ts)
        row = {
            "session_id": session.session_id,
            "question": session.question,
            "context_hash": context_hash(session.context),
            "context_keys": sorted(session.context),
            "verdict": verdict.as_dict(),
            "outcome": None,
            "outcome_link_at": None,
            "ts": stamp,
        }
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            # R2-jc-09: record is a read-modify-write of the whole file;
            # without an exclusive lock two concurrent writers snapshot the
            # same baseline and the second os.replace erases the first
            # writer's row. Hold flock across the whole cycle.
            lock_fd = os.open(str(self.path), os.O_RDWR | os.O_CREAT, 0o600)
            try:
                fcntl.flock(lock_fd, fcntl.LOCK_EX)
                rows = [json.dumps(r, ensure_ascii=False)
                        for r in self._all_rows()]
                rows.append(json.dumps(row, ensure_ascii=False))
                cutoff = stamp - self.retention_days * 86400.0
                kept = []
                for r in rows:
                    # R2-jc-05: a row with a corrupt "ts" cannot be
                    # time-filtered; drop it from the retention rewrite
                    # instead of crashing.
                    try:
                        row_ts = float(json.loads(r).get("ts", 0.0) or 0.0)
                    except (TypeError, ValueError):
                        continue
                    if row_ts >= cutoff:
                        kept.append(r)
                fd, tmp_name = tempfile.mkstemp(dir=str(self.path.parent))
                try:
                    with os.fdopen(fd, "w", encoding="utf-8") as handle:
                        handle.write("\n".join(kept) + ("\n" if kept else ""))
                    os.replace(tmp_name, self.path)
                finally:
                    with suppress(OSError):
                        os.unlink(tmp_name)
            finally:
                with suppress(OSError):
                    fcntl.flock(lock_fd, fcntl.LOCK_UN)
                    os.close(lock_fd)
        except OSError as exc:
            _LOG.warning("council memory write failed: %s", exc)
        self._append_session_log(session, verdict, stamp)

    @staticmethod
    def _bias_row(session: CouncilSession, verdict: Verdict,
                  stamp: float) -> dict[str, Any]:
        """Compact bias-compatible row for sessions.jsonl (U-JC-8 consumers).

        Carries both the flat view (scores / argue_orders) and the
        verdict-shaped summary the BiasDetector consumes.
        """
        summary = {
            aid: {
                "claim": str(data.get("claim") or ""),
                "score": float(data.get("score") or 0.0),
                "argue_order": int(data.get("argue_order", 0)),
            }
            for aid, data in (verdict.advocates_summary or {}).items()
            if isinstance(data, dict)
        }
        return {
            "session_id": session.session_id,
            "ts": stamp,
            "question": session.question,
            "scores": {
                aid: {"score": data["score"], "claim": data["claim"]}
                for aid, data in summary.items()
            },
            "argue_orders": {
                aid: data["argue_order"] for aid, data in summary.items()
            },
            "verdict": {"advocates_summary": summary},
        }

    def _append_session_log(self, session: CouncilSession, verdict: Verdict,
                            stamp: float) -> None:
        try:
            target = self.path.with_name(SESSIONS_LOG_NAME)
            target.parent.mkdir(parents=True, exist_ok=True)
            row = self._bias_row(session, verdict, stamp)
            with target.open("a", encoding="utf-8") as handle:
                handle.write(json.dumps(row, ensure_ascii=False) + "\n")
        except OSError as exc:
            _LOG.warning("council session log write failed: %s", exc)

    def link_outcome(self, session_id: str, outcome: str, *,
                     ts: float | None = None) -> int:
        """Set the outcome on every entry of a session (rewrite, not append)."""
        stamp = self._now_ts if ts is None else float(ts)
        changed = 0
        # R2-jc-09: same exclusive lock as record() — link_outcome is a
        # read-modify-write racing the very same file.
        self.path.parent.mkdir(parents=True, exist_ok=True)
        lock_fd = os.open(str(self.path), os.O_RDWR | os.O_CREAT, 0o600)
        try:
            fcntl.flock(lock_fd, fcntl.LOCK_EX)
            rows = self._all_rows()
            for row in rows:
                if row.get("session_id") == str(session_id):
                    row["outcome"] = str(outcome)[:20]
                    row["outcome_link_at"] = stamp
                    changed += 1
            if changed:
                self._rewrite(rows)
        finally:
            with suppress(OSError):
                fcntl.flock(lock_fd, fcntl.LOCK_UN)
                os.close(lock_fd)
        return changed

    # -------------------------------------------------------------- reads
    def _all_rows(self) -> list[dict[str, Any]]:
        try:
            lines = self.path.read_text(encoding="utf-8").splitlines()
        except OSError:
            return []
        rows = []
        for line in lines:
            row = None
            with suppress(ValueError):
                row = json.loads(line)
            if isinstance(row, dict):
                rows.append(row)
        return rows

    def _rewrite(self, rows: list[dict[str, Any]]) -> None:
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            fd, tmp_name = tempfile.mkstemp(dir=str(self.path.parent))
            try:
                with os.fdopen(fd, "w", encoding="utf-8") as handle:
                    handle.write("\n".join(
                        json.dumps(r, ensure_ascii=False) for r in rows
                    ) + ("\n" if rows else ""))
                os.replace(tmp_name, self.path)
            finally:
                with suppress(OSError):
                    os.unlink(tmp_name)
        except OSError as exc:
            _LOG.warning("council memory rewrite failed: %s", exc)

    def all_entries(self) -> list[dict[str, Any]]:
        """Every remembered decision (oldest first)."""
        return self._all_rows()

    def find_similar(self, context: dict, k: int = 5) -> list[dict[str, Any]]:
        """Exact hash matches first, then best key-overlap similarity."""
        target = context_hash(dict(context or {}))
        scored = []
        for row in self._all_rows():
            if row.get("context_hash") == target:
                score = 1.0
            else:
                keys = set(row.get("context_keys") or [])
                wanted = set(context or {})
                union = keys | wanted
                # similarity from key overlap only (values are not stored raw)
                shared_equal = len(keys & wanted)
                score = (shared_equal / len(union)) if union else 0.0
            scored.append((score, row))
        scored.sort(key=lambda pair: (-pair[0], str(pair[1].get("session_id"))))
        return [row for score, row in scored if score > 0.0][: max(0, int(k))]

    def find_pattern(self, context_hash_prefix: str) -> Pattern | None:
        """>= 5 decisions with the same hash prefix and same action."""
        prefix = str(context_hash_prefix or "")
        rows = [r for r in self._all_rows()
                if str(r.get("context_hash", "")).startswith(prefix)]
        if len(rows) < PATTERN_MIN_SAMPLES:
            return None
        actions = {str((r.get("verdict") or {}).get("action") or "") for r in rows}
        if len(actions) != 1 or "" in actions:
            return None
        outcomes = {r.get("outcome") for r in rows}
        outcome = outcomes.pop() if len(outcomes) == 1 else None
        return Pattern(
            context_hash_prefix=prefix,
            action=next(iter(actions)),
            count=len(rows),
            outcome=None if outcome is None else str(outcome),
            session_ids=[str(r.get("session_id") or "") for r in rows],
        )

    def feed_lessons(self) -> list[dict[str, Any]]:
        """Lesson candidates from decisions whose outcome was 'incorrect'."""
        lessons = []
        for row in self._all_rows():
            if row.get("outcome") == "incorrect":
                verdict = row.get("verdict") or {}
                lessons.append({
                    "lesson_kind": "council_decision_failed",
                    "session_id": row.get("session_id"),
                    "question": row.get("question"),
                    "action": verdict.get("action"),
                    "confidence": verdict.get("confidence"),
                    "advisory": True,
                })
        return lessons


__all__ = ["DEFAULT_RETENTION_DAYS", "PATTERN_MIN_SAMPLES", "SESSIONS_LOG_NAME",
           "CouncilMemory", "Pattern"]
