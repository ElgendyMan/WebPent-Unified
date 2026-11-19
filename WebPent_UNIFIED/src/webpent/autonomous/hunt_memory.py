"""Engagement-scoped learning memory for the autonomous hunt (Phase 4).

``ScopedHuntMemory`` is the orchestrator's ``memory`` slot. It stores what
each hunt observed (which pattern was vulnerable, which was clean) and
produces advisory reordering hints for the *next* hunt. Governance it
inherits and re-states:

* **Hint-only.** It can reorder hypotheses; it can never promote a
  finding. The orchestrator re-caps every hint at 0.75 at the point of
  use, and this module returns hints already capped there as well.
* **Isolated by ``engagement_id:target_id``.** A hint learned on one
  engagement's target can never influence another engagement's hunt: the
  scope key is part of every store, query and hint lookup.
* **Tamper-evident.** Entries carry deterministic SHA-256 signatures (the
  same scheme as ``SmartMemory``); a corrupted or hand-forged entry is
  refused on store and on read.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from webpent.smart.memory_engine import MemoryEntry

_HINT_CAP = 0.75
_MAX_ENTRIES = 512


def scope_key(engagement_id: str, target_id: str) -> str:
    """The isolation key for learned entries."""
    return f"{engagement_id}:{target_id}"


class ScopedHuntMemory:
    """Per-engagement:target memory of pattern outcomes.

    ``update(state)`` is the orchestrator's callback: it ingests the hunt's
    outcome records and returns ``{pattern_id: hint}`` for the *same*
    scope only. Hints are already clamped to ``_HINT_CAP``.
    """

    def __init__(self, persist_path: str | None = None) -> None:
        self._entries: dict[str, MemoryEntry] = {}
        self.persist_path = persist_path
        if persist_path:
            self._load()

    def _load(self) -> None:
        """Load signed entries from a JSON snapshot; corrupt ones are dropped."""
        import json
        from pathlib import Path

        path = Path(self.persist_path)
        if not path.exists():
            return
        try:
            raw = json.loads(path.read_text(encoding="utf-8"))
        except Exception:
            return
        if not isinstance(raw, list):
            return
        for item in raw[:_MAX_ENTRIES]:
            if not isinstance(item, dict):
                continue
            try:
                entry = MemoryEntry(
                    pattern_id=str(item.get("pattern_id") or ""),
                    pattern_type=str(item.get("pattern_type") or "hunt_pattern"),
                    features=dict(item.get("features") or {}),
                    outcome=str(item.get("outcome") or ""),
                    confidence=float(item.get("confidence", 0.0)),
                    source=str(item.get("source") or "autonomous_hunt"),
                    signature=str(item.get("signature") or ""),
                )
                # P1-06 (0.33.0): the module contract says a hand-forged or
                # corrupted entry is refused on store AND on read — but
                # _load() never verified signatures, so a forged on-disk
                # entry loaded fine and hint() served it. Skip unverifiable
                # entries exactly like store() refuses them.
                if not entry.verify_signature():
                    continue
                self._entries[str(item.get("_key") or "")] = entry
            except (TypeError, ValueError):
                continue

    def save(self) -> None:
        """Write the entry snapshot (including keys) to the persist path."""
        import json
        from dataclasses import asdict
        from pathlib import Path

        if not self.persist_path:
            return
        payload = []
        for key, entry in self._entries.items():
            item = asdict(entry)
            item["_key"] = key
            payload.append(item)
        Path(self.persist_path).write_text(
            json.dumps(payload, indent=2, sort_keys=True) + chr(10), encoding="utf-8"
        )

    def store(
        self,
        *,
        engagement_id: str,
        target_id: str,
        entry: MemoryEntry,
    ) -> None:
        if not entry.verify_signature():
            raise ValueError("memory entry signature invalid - possible tampering")
        key = f"{scope_key(engagement_id, target_id)}::{entry.pattern_id}"
        # P1-07 (0.33.0): the cap check used to run BEFORE the upsert, so
        # once the store was full even UPDATES to existing patterns were
        # silently dropped — a corrected outcome (vulnerable -> clean)
        # could never overwrite a stale one. Existing keys always upsert;
        # only genuinely NEW entries are bounded by the cap.
        if key not in self._entries and len(self._entries) >= _MAX_ENTRIES:
            return
        self._entries[key] = entry

    def entries_for(self, engagement_id: str, target_id: str) -> list[MemoryEntry]:
        prefix = f"{scope_key(engagement_id, target_id)}::"
        return [e for k, e in self._entries.items() if k.startswith(prefix)]

    def hint(
        self,
        *,
        engagement_id: str,
        target_id: str,
        features: Mapping[str, Any] | None = None,
    ) -> dict[str, float]:
        """Advisory hints for one scope, capped, keyed by pattern id.

        A pattern is hinted toward the top when past runs on *this*
        engagement and target saw it vulnerable, and toward the bottom
        when they saw it clean. Unknown scopes return no hints at all.
        """
        entries = self.entries_for(engagement_id, target_id)
        if not entries:
            return {}
        features = dict(features or {})
        hints: dict[str, float] = {}
        for entry in entries:
            # Exact feature match is a full-strength signal; anything else
            # contributes at half strength so cross-pattern bleed stays weak.
            if features and entry.features and all(
                features.get(k) == entry.features.get(k)
                for k in entry.features
            ):
                strength = 1.0
            else:
                strength = 0.5
            direction = 1.0 if entry.outcome == "vulnerable" else -1.0
            contribution = direction * strength * max(0.0, min(1.0, entry.confidence))
            hints[entry.pattern_id] = hints.get(entry.pattern_id, 0.0)
            hints[entry.pattern_id] = max(hints[entry.pattern_id], contribution)
        return {
            pattern: max(-_HINT_CAP, min(_HINT_CAP, value))
            for pattern, value in hints.items()
        }

    def update(self, state: Any) -> dict[str, float]:
        """Orchestrator callback: learn from this hunt, hint for this hunt.

        Ingests ``state.outcomes`` (records with ``vulnerability_class``
        and ``status``) into this hunt's scope, then returns hints for the
        remaining hypotheses. Negative-control contradictions are ignored:
        only executed, decided outcomes are learned from.
        """
        engagement_id = str(getattr(state, "engagement_id", "") or "")
        target_id = str(
            getattr(state, "target_id", "")
            or getattr(state, "target_url", "")
            or engagement_id
        )
        for record in getattr(state, "outcomes", []) or []:
            if not isinstance(record, Mapping):
                continue
            status = str(record.get("status") or "")
            if status not in {"executed", "confirmed"}:
                continue
            pattern = str(
                record.get("vulnerability_class")
                or record.get("pattern_id")
                or record.get("hypothesis_id")
                or ""
            )
            if not pattern:
                continue
            is_vulnerable = status == "confirmed" or bool(record.get("vulnerable"))
            outcome = "vulnerable" if is_vulnerable else "clean"
            entry = MemoryEntry(
                pattern_id=pattern,
                pattern_type="hunt_pattern",
                features={"vulnerability_class": pattern},
                outcome=outcome,
                confidence=0.75,
                source="autonomous_hunt",
            )
            try:
                self.store(
                    engagement_id=engagement_id, target_id=target_id, entry=entry
                )
            except ValueError:
                continue
        hints = self.hint(engagement_id=engagement_id, target_id=target_id)
        # Positive hints only: reordering toward patterns that worked.
        return {k: v for k, v in hints.items() if v > 0}


__all__ = ["ScopedHuntMemory", "scope_key"]
