"""False-positive autopsy system (v82, Layer 2 / Task 8).

When a finding is rejected (by the triager prediction, a self-refuted
skeptic verdict, or an operator decision recorded in the hunt state),
this module dissects *why* and files a lesson in a persistent knowledge
base: pattern -> lesson count. Later, hypothesis generation can ask the
autopsy store for an advisory demotion for that pattern's class — the
same contract as dead-end memory: re-rank, never drop, never suppress
fresh evidence.

Persistence mirrors IntelStore/DeadEndStore: atomic save, corrupt file
degrades to an empty base, redaction on everything stored, bounded.
"""

from __future__ import annotations

import contextlib
import json
import logging
import os
import tempfile
from pathlib import Path
from typing import Any

from webpent.autonomous.hunt_contracts import redact

_LOG = logging.getLogger(__name__)

MAX_LESSONS = 48
MAX_REJECTED_BEFORE = 3


def autopsy_key(rejection: dict[str, Any]) -> str:
    """Derive a stable lesson key from one rejection record.

    The key is (vuln_class, source_of_rejection): the coarsest fact that
    generalizes. Secret values, URLs and query strings never enter it.
    """
    vuln_class = redact(str(rejection.get("vuln_class") or "").strip().lower())[:64]
    if not vuln_class:
        return ""
    source = redact(str(rejection.get("rejected_by") or "unknown").strip().lower())[:32]
    return f"{vuln_class}::{source}"


class FPAutopsyStore:
    """Persistent advisory lessons from rejected findings."""

    def __init__(self, persist_path: Path | str) -> None:
        self.path = Path(persist_path)
        self._lessons: dict[str, dict[str, Any]] = {}
        self.load()

    def load(self) -> None:
        self._lessons = {}
        try:
            raw = json.loads(self.path.read_text(encoding="utf-8"))
        except FileNotFoundError:
            return
        except (OSError, ValueError):
            _LOG.warning("autopsy file unreadable; starting with no memory: %s", self.path)
            return
        if not isinstance(raw, dict):
            _LOG.warning("autopsy file wrong type; starting with no memory: %s", self.path)
            return
        for key, entry in raw.items():
            if isinstance(key, str) and isinstance(entry, dict) and "count" in entry:
                count = entry.get("count")
                if isinstance(count, int) and count > 0:
                    self._lessons[key[:96]] = {
                        "count": count,
                        "reason": str(entry.get("reason", ""))[:200],
                    }
            if len(self._lessons) >= MAX_LESSONS:
                break

    def save(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        payload = json.dumps(self._lessons, indent=2, ensure_ascii=False)
        try:
            fd, tmp_name = tempfile.mkstemp(dir=str(self.path.parent))
            try:
                with os.fdopen(fd, "w", encoding="utf-8") as handle:
                    handle.write(payload)
                os.replace(tmp_name, self.path)
            except BaseException:
                with contextlib.suppress(OSError):
                    os.unlink(tmp_name)
                raise
        except OSError as exc:
            _LOG.warning("autopsy save failed (memory stays in-process): %s", exc)

    def record_rejection(self, rejection: dict[str, Any]) -> str:
        """File one rejection; returns the lesson key (or "" for noise)."""
        key = autopsy_key(rejection)
        if not key:
            return ""
        entry = self._lessons.setdefault(key, {"count": 0, "reason": ""})
        entry["count"] += 1
        entry["reason"] = redact(str(rejection.get("reason") or entry["reason"]))[:200]
        if len(self._lessons) > MAX_LESSONS:
            # Evict the least-count lesson.
            least = min(self._lessons, key=lambda k: self._lessons[k]["count"])
            del self._lessons[least]
        return key

    def demotion_for(self, vuln_class: str, rejected_by: str) -> float:
        """Advisory demotion in [0, 0.20]; 0 until a pattern repeats."""
        key = autopsy_key({"vuln_class": vuln_class, "rejected_by": rejected_by})
        entry = self._lessons.get(key)
        if not entry:
            return 0.0
        # Scale with repeats: 1 rejection -> 0.05, 3+ -> 0.20 cap.
        return min(0.20, 0.05 * entry["count"])

    def has_history(self, vuln_class: str, rejected_by: str) -> bool:
        key = autopsy_key({"vuln_class": vuln_class, "rejected_by": rejected_by})
        return key in self._lessons

    def lesson_count(self, vuln_class: str, rejected_by: str) -> int:
        key = autopsy_key({"vuln_class": vuln_class, "rejected_by": rejected_by})
        return self._lessons.get(key, {}).get("count", 0)


def summarize_autopsy(lessons: dict[str, dict[str, Any]]) -> list[str]:
    """Human-readable one-liners: 'pattern X rejects findings of type Y'."""
    lines: list[str] = []
    for key, entry in sorted(lessons.items(), key=lambda kv: -kv[1]["count"]):
        if entry["count"] < MAX_REJECTED_BEFORE and entry["count"] < 1:
            continue
        lines.append(
            f"{key}: {entry['count']} rejections — {entry['reason'] or 'no reason recorded'}"
        )
    return lines[:MAX_LESSONS]
