"""CEM Longitudinal Memory — the dormant hypothesis pool (v83, U-CEM-10).

Some hypotheses are right but premature: "if an admin panel appears, test
it for default credentials". The pool stores them as dormant, each with a
``blocked_on`` condition of the form ``"<field>:<kind>"`` (for example
``endpoints:added``). When a later diff report for the same target
contains a matching change, the hypothesis wakes and is returned to the
caller as an advisory seed. Hypotheses retire after 120 days; the pool is
capped; every text field is redacted and bounded; corrupt files degrade
to an empty pool. Nothing here executes anything: activation only hands
the idea back to the cycle.
"""

from __future__ import annotations

import contextlib
import json
import logging
import os
import tempfile
from typing import Any

from webpent.autonomous.hunt_contracts import redact

_LOG = logging.getLogger(__name__)

RETIRE_DAYS = 120.0
MAX_POOL = 32
MAX_TEXT = 200


def _condition_key(field: str, kind: str) -> str:
    return f"{field}:{kind}"


class DormantPool:
    """Bounded, condition-gated hypothesis pool. Advisory only."""

    def __init__(self, persist_path: Any) -> None:
        self._path = persist_path
        self._pool: dict[str, dict[str, Any]] = {}
        self.load()

    def load(self) -> None:
        try:
            raw = json.loads(self._path.read_text(encoding="utf-8"))
        except (FileNotFoundError, OSError, ValueError, AttributeError):
            self._pool = {}
            return
        if not isinstance(raw, dict):
            self._pool = {}
            return
        kept: dict[str, dict[str, Any]] = {}
        for key, record in list(raw.items())[:MAX_POOL]:
            if isinstance(key, str) and isinstance(record, dict):
                kept[key[:160]] = record
        self._pool = kept

    def save(self) -> None:
        try:
            self._path.parent.mkdir(parents=True, exist_ok=True)
            fd, tmp_name = tempfile.mkstemp(dir=str(self._path.parent))
            try:
                with os.fdopen(fd, "w", encoding="utf-8") as handle:
                    json.dump(self._pool, handle, indent=2, ensure_ascii=False)
                os.replace(tmp_name, self._path)
            except BaseException:
                with contextlib.suppress(OSError):
                    os.unlink(tmp_name)
                raise
        except (OSError, AttributeError) as exc:
            _LOG.warning("dormant pool save failed (memory stays in-process): %s", exc)

    def add(
        self,
        *,
        target_id: str,
        hypothesis: str,
        blocked_on_field: str,
        blocked_on_kind: str,
        now: float,
        vuln_class: str = "",
    ) -> dict[str, Any]:
        """Park a hypothesis until a change of field:kind shows up."""
        target_id = redact(str(target_id or ""))[:120]
        text = redact(str(hypothesis or ""))[:MAX_TEXT]
        field = redact(str(blocked_on_field or ""))[:60]
        kind = redact(str(blocked_on_kind or ""))[:20]
        if not (target_id and text and field and kind):
            return {}
        key = f"{target_id}::{_condition_key(field, kind)}::{text[:40]}"
        record = {
            "target_id": target_id,
            "hypothesis": text,
            "vuln_class": redact(str(vuln_class or ""))[:80],
            "blocked_on": _condition_key(field, kind),
            "parked_at": float(now),
        }
        self._pool[key[:160]] = record
        if len(self._pool) > MAX_POOL:
            oldest = min(self._pool, key=lambda k: self._pool[k].get("parked_at", 0))
            self._pool.pop(oldest)
        self.save()
        return dict(record)

    def reap(self, *, now: float) -> list[str]:
        """Retire hypotheses older than the TTL; returns their keys."""
        now = float(now)
        retired = [
            key
            for key, record in self._pool.items()
            if now - float(record.get("parked_at") or now) > RETIRE_DAYS * 86400.0
        ]
        for key in retired:
            self._pool.pop(key)
        if retired:
            self.save()
        return retired

    def activate_for(self, diff: dict[str, Any], *, now: float) -> list[dict[str, Any]]:
        """Wake every hypothesis whose condition appears in this diff."""
        now = float(now)
        if not isinstance(diff, dict):
            return []
        target_id = redact(str(diff.get("target_id") or ""))[:120]
        if not target_id:
            return []
        observed = {
            _condition_key(str(c.get("field") or ""), str(c.get("kind") or ""))
            for c in diff.get("changes", [])
            if isinstance(c, dict)
        }
        activated: list[dict[str, Any]] = []
        for key, record in list(self._pool.items()):
            if record.get("target_id") != target_id:
                continue
            if record.get("blocked_on") in observed:
                woken = dict(record)
                woken["activated_at"] = now
                woken["advisory"] = True
                activated.append(woken)
                self._pool.pop(key)
        if activated:
            self.save()
        return activated[:MAX_POOL]

    def pool(self) -> list[dict[str, Any]]:
        return [dict(r) for r in self._pool.values()]

    def count(self) -> int:
        return len(self._pool)


__all__ = ["MAX_POOL", "RETIRE_DAYS", "DormantPool"]
