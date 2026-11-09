"""Unified campaign ledger — one JSONL audit trail for a VIP campaign.

Before this module, a campaign's evidence was scattered across seven
advisory surfaces (AttackMemory entries, optimizer counters, a
postmortem store, red-vs-blue reports, drift reports, CVE
correlations, influence graphs). Answering "what did the campaign do
and why" meant re-deriving the story from each store separately. The
ledger gives the VIP Orchestrator (and any human reading its output)
a single append-only record: one JSON object per line, one line per
orchestrator step.

Design constraints:

  * Append-only JSON Lines: one ``{"step": ..., "cycle": ..., ...}``
    object per line. Trivially tail-able with ``jq``/``grep``; no
    schema migration, no database.
  * Fail-soft writes: a full disk, a bad path, or a permission error
    degrades to "ledger disabled" (``enabled=False``) and never
    raises into the orchestrator — losing an audit line must not
    abort a campaign loop.
  * Bounded reads: ``read_steps`` caps lines returned so a long
    campaign can't blow up a caller's memory.
  * No sensitive payloads: callers pass labels, scenario ids, and
    counts. The ledger never stores raw attack payloads (same
    posture as ``feed_escapes_to_postmortem``, which persists
    technique names without the raw payload).
"""
from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

_MAX_READ_STEPS = 5000
_MAX_LINE_BYTES = 1_000_000


class CampaignLedger:
    """Append-only JSONL ledger. Fail-soft: never raises on write."""

    def __init__(self, path: str | Path | None = None) -> None:
        self._path = Path(path) if path else None
        self.enabled = self._path is not None
        self._write_failed = False
        if self._path is not None:
            try:
                self._path.parent.mkdir(parents=True, exist_ok=True)
            except OSError:
                self.enabled = False

    @property
    def path(self) -> Path | None:
        return self._path

    def record(self, step: str, cycle: int, **fields: Any) -> None:
        """Append one step record. Silently no-ops when disabled or
        after a write has failed once (fail-soft latch)."""
        if not self.enabled or self._write_failed or self._path is None:
            return
        entry: dict[str, Any] = {
            "ts": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "step": step,
            "cycle": cycle,
        }
        entry.update(fields)
        try:
            line = json.dumps(entry, ensure_ascii=False, default=str)
            if len(line.encode("utf-8")) > _MAX_LINE_BYTES:
                line = json.dumps(
                    {**entry, "truncated": True, "note": "step payload exceeded ledger line cap"},
                    ensure_ascii=False,
                    default=str,
                )
            with self._path.open("a", encoding="utf-8") as fh:
                fh.write(line + "\n")
        except OSError:
            self._write_failed = True
            self.enabled = False

    def read_steps(self, *, limit: int = _MAX_READ_STEPS) -> list[dict[str, Any]]:
        """Read back ledger entries (bounded). Empty list on any problem."""
        if self._path is None:
            return []
        try:
            lines = self._path.read_text(encoding="utf-8").splitlines()
        except (OSError, ValueError):
            return []
        steps: list[dict[str, Any]] = []
        for line in lines[-limit:]:
            try:
                parsed = json.loads(line)
            except ValueError:
                continue
            if isinstance(parsed, dict):
                steps.append(parsed)
        return steps


__all__ = ["CampaignLedger"]
