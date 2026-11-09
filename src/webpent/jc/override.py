"""Judgment Council — U-JC-11: the Override Protocol (JC-L-7).

The operator is sovereign. The council advises; the operator may accept,
partially accept, or fully override any verdict — and every override is
recorded with a mandatory reason in an append-only JSONL log, then linked
to its outcome so operator accuracy is measured by exactly the same
method as every other voice in the council.
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

ALLOWED_MODES = ("full", "partial", "advisory")
DEFAULT_MIN_REASON_CHARS = 10
OPERATOR_ID = "operator"


class OverrideProtocol:
    """Records operator overrides and tracks their accuracy."""

    def __init__(self, path: Any, *, min_reason_chars: int = DEFAULT_MIN_REASON_CHARS,
                 now_ts: float | None = None) -> None:
        self.path = Path(str(path))
        self.min_reason_chars = max(0, int(min_reason_chars))
        self._now_ts = time.time() if now_ts is None else float(now_ts)

    # ------------------------------------------------------------- apply
    def apply(
        self,
        verdict: Verdict,
        mode: str,
        reason: str,
        *,
        final_action: str | None = None,
        operator_id: str = OPERATOR_ID,
        ts: float | None = None,
    ) -> dict[str, Any]:
        """Record one override; returns the logged entry.

        ``full``      the operator replaced the council's action entirely
                      (``final_action`` required).
        ``partial``   the operator kept the action but changed its scope
                      (``final_action`` records the narrowed action).
        ``advisory``  the operator noted the verdict without acting on it.
        """
        mode = str(mode or "").lower()
        if mode not in ALLOWED_MODES:
            raise ValueError(f"mode must be one of {ALLOWED_MODES}, got {mode!r}")
        reason = str(reason or "").strip()
        if len(reason) < self.min_reason_chars:
            raise ValueError(
                f"a reason of at least {self.min_reason_chars} characters is required"
            )
        if mode == "full" and not str(final_action or "").strip():
            raise ValueError("a full override requires final_action")
        final = str(final_action).strip() if final_action else (
            verdict.action if mode in ("partial", "advisory") else ""
        )
        stamp = self._now_ts if ts is None else float(ts)
        entry = {
            "ts": round(stamp, 3),
            "session_id": verdict.session_id,
            "council_action": verdict.action,
            "council_confidence": round(clamp01(verdict.confidence), 4),
            "council_escalated": verdict.escalate,
            "mode": mode,
            "final_action": final,
            "reason": reason[:500],
            "operator_id": str(operator_id)[:60],
            "outcome": None,
            "advisory": True,
        }
        self._append([entry])
        return entry

    # ------------------------------------------------------------ outcomes
    def link_outcome(self, session_id: str, outcome: str, *,
                     ts: float | None = None) -> int:
        """Append outcome updates for every override of one session."""
        stamp = self._now_ts if ts is None else float(ts)
        session_id = str(session_id)
        targets = [r for r in self._resolve().values()
                   if r["session_id"] == session_id]
        rows = [
            {
                "ts": round(stamp, 3),
                "session_id": session_id,
                "mode": r["mode"],
                "final_action": r["final_action"],
                "reason": r["reason"],
                "operator_id": r["operator_id"],
                "outcome": str(outcome)[:20],
                "link_only": True,
            }
            for r in targets
        ]
        self._append(rows)
        return len(rows)

    def operator_accuracy(self, operator_id: str = OPERATOR_ID) -> float | None:
        """accuracy = correct / (correct + incorrect) of linked overrides."""
        resolved = [
            r for r in self._resolve().values()
            if r["operator_id"] == str(operator_id)
            and r["outcome"] in ("correct", "incorrect")
        ]
        if not resolved:
            return None
        correct = sum(1 for r in resolved if r["outcome"] == "correct")
        return correct / len(resolved)

    # -------------------------------------------------------------- reads
    def entries(self) -> list[dict[str, Any]]:
        """Resolved override state, oldest first."""
        return list(self._resolve().values())

    def _resolve(self) -> dict[tuple[str, str], dict[str, Any]]:
        """Latest state per (session_id, mode+final_action)."""
        state: dict[tuple[str, str], dict[str, Any]] = {}
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
            session_id = str(row.get("session_id") or "")
            if not session_id:
                continue
            if row.get("link_only"):
                for key, entry in state.items():
                    if key[0] == session_id:
                        entry["outcome"] = row.get("outcome")
                continue
            key = (session_id,
                   f"{row.get('mode', '')}\x1f{row.get('final_action', '')}")
            state[key] = {
                "session_id": session_id,
                "council_action": row.get("council_action"),
                "council_confidence": row.get("council_confidence"),
                "mode": row.get("mode"),
                "final_action": row.get("final_action"),
                "reason": row.get("reason"),
                "operator_id": row.get("operator_id"),
                "outcome": row.get("outcome"),
            }
        return state

    def _append(self, rows: list[dict[str, Any]]) -> None:
        if not rows:
            return
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            text = "".join(json.dumps(r, ensure_ascii=False) + "\n" for r in rows)
            with self.path.open("a", encoding="utf-8") as handle:
                handle.write(text)
        except OSError as exc:
            _LOG.warning("override log write failed: %s", exc)


__all__ = ["ALLOWED_MODES", "DEFAULT_MIN_REASON_CHARS", "OverrideProtocol"]
