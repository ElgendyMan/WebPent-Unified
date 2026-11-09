"""U-DOJO-12: the progress ledger — every session leaves a measured trail.

Laws honored here:
- L-2 ISOLATED STATE: the ledger lives only inside the Dojo directory,
  resolved from WEBPENT_DOJO_DIR (default download/dojo).
- L-4 DETERMINISTIC: trends are computed from recorded numbers only.
- L-5 MEASURED IMPROVEMENT: the trend reports what was measured, never
  what was hoped; empty or flat history reports exactly that.
- L-10 NO IMPACT ON REAL CAMPAIGNS: nothing here reads campaign state.
"""

from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path

#: the audit log keeps at most this many lines (bounded state)
MAX_AUDIT_LINES = 1000

#: the history ledger keeps at most this many lines (bounded state, RT-09)
MAX_HISTORY_LINES = 5000


class ProgressTracker:
    """Append-only JSONL ledger of dojo sessions, with trend reporting."""

    def __init__(self, dojo_dir: str | Path | None = None) -> None:
        if dojo_dir is not None:
            self.dojo_dir = Path(dojo_dir)
        else:
            env = os.environ.get("WEBPENT_DOJO_DIR")
            self.dojo_dir = Path(env) if env else Path("download") / "dojo"
        self.dojo_dir.mkdir(parents=True, exist_ok=True)

    @property
    def history_path(self) -> Path:
        return self.dojo_dir / "history.jsonl"

    @property
    def audit_path(self) -> Path:
        return self.dojo_dir / "audit_log.jsonl"

    # -- the ledger -----------------------------------------------------------

    def record(self, entry: dict) -> None:
        line = json.dumps(entry, sort_keys=True)
        self._append_line(self.history_path, line, cap=MAX_HISTORY_LINES)

    def history(self) -> list[dict]:
        if not self.history_path.exists():
            return []
        entries: list[dict] = []
        for line in self.history_path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if line:
                entries.append(json.loads(line))
        return entries

    # -- trends (L-5) -----------------------------------------------------------

    def trend(self, history: list[dict] | None = None) -> str:
        """improving / declining / flat, comparing the two halves by score.

        Entries whose score is not numeric (a stray "n/a", a null) are kept
        in the ledger but excluded from the arithmetic (RT-10): one bad
        value must not crash every command that reads history (L-5 keeps
        the trend measured, L-4 keeps it deterministic).
        """
        entries = history if history is not None else self.history()
        scores = [
            e["score"] for e in entries
            if "score" in e and isinstance(e["score"], (int, float))
            and not isinstance(e["score"], bool)
        ]
        if len(scores) < 2:
            return "flat"
        half = len(scores) // 2
        first = sum(scores[:half]) / half
        second = sum(scores[half:]) / (len(scores) - half)
        if second > first:
            return "improving"
        if second < first:
            return "declining"
        return "flat"

    def summary(self) -> dict:
        history = self.history()
        return {
            "entries": len(history),
            "trend": self.trend(history),
            "dojo_dir": str(self.dojo_dir),
        }

    # -- audit log (capped) ------------------------------------------------------

    def audit(self, command: str, detail: str = "") -> None:
        line = json.dumps(
            {"command": command, "detail": detail}, sort_keys=True
        )
        self._append_line(self.audit_path, line, cap=MAX_AUDIT_LINES)

    # -- bounded, atomic append ------------------------------------------------------

    @staticmethod
    def _append_line(path: Path, line: str, cap: int | None = None) -> None:
        lines: list[str] = []
        if path.exists():
            lines = path.read_text(encoding="utf-8").splitlines()
        if cap is not None and len(lines) >= cap:
            # R2-dojo-08: cap=1 used to slice lines[-0:], which keeps every
            # line (a negative index of zero is the whole list); clamp the
            # keep window so the cap always trims
            keep = max(cap - 1, 0)
            lines = lines[-keep:] if keep else []
        lines.append(line)
        handle, tmp_name = tempfile.mkstemp(
            dir=str(path.parent), prefix=path.name, suffix=".tmp"
        )
        with os.fdopen(handle, "w", encoding="utf-8") as tmp:
            tmp.write("\n".join(lines) + "\n")
        os.replace(tmp_name, path)


__all__ = ["MAX_AUDIT_LINES", "MAX_HISTORY_LINES", "ProgressTracker"]
