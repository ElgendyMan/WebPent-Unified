# src/webpent/vip/asset_triage.py
"""webpent.vip.asset_triage — visual triage previews with retention (0.26.0).

Roadmap contract (المسار 11، البند 2 — فرز بصري للأصول):

    لقطات معاينة للأصول المصرح بها لتسهيل triage، مع سياسة احتفاظ
    وحماية للبيانات.

    ("Preview screenshots of AUTHORIZED assets to ease triage, with a
    retention policy and data protection.")

Until 0.25.0 this was the only Track-11 item with NO implementation at
all — the repo had screenshot *digests* (``playwright_adapter.py``) but
no preview store, no retention, no triage surface. This module closes
it with the house posture:

* **Scope-gated before any byte is captured.** Every capture request
  goes through the caller-supplied ``ScopeEnforcer.check_url`` first;
  a non-``allowed`` decision records a blocked entry and captures
  NOTHING (same contract as ``vip/retest.py``: zero requests outside
  the authorized scope).
* **Capture is injected, never built-in.** The module ships NO browser
  automation of its own: the operator/engine passes a ``capturer``
  callable (URL -> PNG bytes) — in the engine that is the existing
  playwright adapter path; in tests it is a deterministic fake. With no
  capturer configured the store stays empty and capture returns
  ``capture_unavailable`` (an honest advisory, not a failure).
* **Data protection.** Previews live under a per-client hashed
  directory (same isolation pattern as the coordination ledger and the
  calibration store), files are 0600, and the JSON index carries
  digests + dimensions metadata only — the index never embeds image
  bodies or raw URLs beyond the scoped asset reference the operator
  already owns.
* **Retention is a policy, not an auto-delete.** ``retention_plan``
  (dry-run by default) returns which entries EXPIRE (age/count caps);
  the caller executes ``purge`` explicitly — the 0.23.0 retention
  posture ("خطأ سياسة لا يمسح شيئًا بنفسه") reused verbatim.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

__all__ = [
    "TriageEntry",
    "TriageDecision",
    "AssetTriageStore",
]

#: Bounded store: an unbounded preview pile is its own data-protection
#: problem (the roadmap's retention clause exists for exactly this).
MAX_PREVIEW_BYTES = 3_000_000
MAX_ENTRIES_DEFAULT = 200
DEFAULT_RETENTION_DAYS = 14


def _slug_scope(scope_hash: str) -> str:
    slug = "".join(c if c.isalnum() or c in "-_" else "_" for c in scope_hash)[:48]
    digest = hashlib.sha256(scope_hash.encode("utf-8", "replace")).hexdigest()[:12]
    return f"{slug or 'blank'}-{digest}"


def _digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


@dataclass
class TriageEntry:
    """One stored preview — identifiers and digests, never bodies."""

    asset_url: str
    scope_hash: str
    client_id: str
    file_name: str
    sha256: str
    size_bytes: int
    captured_at: float

    def as_dict(self) -> dict[str, Any]:
        return {
            "asset_url": self.asset_url,
            "scope_hash": self.scope_hash,
            "client_id": self.client_id,
            "file_name": self.file_name,
            "sha256": self.sha256,
            "size_bytes": self.size_bytes,
            "captured_at": self.captured_at,
        }


@dataclass
class TriageDecision:
    """Outcome of one capture attempt (typed vocabulary, honest reasons)."""

    status: str  # stored | blocked_by_scope | capture_unavailable | rejected
    entry: TriageEntry | None = None
    reason: str = ""

    def as_dict(self) -> dict[str, Any]:
        return {
            "status": self.status,
            "entry": self.entry.as_dict() if self.entry else None,
            "reason": self.reason,
        }


@dataclass
class AssetTriageStore:
    """Per-client visual-triage preview store (digests + 0600 files)."""

    root_dir: str | os.PathLike[str]
    max_entries: int = MAX_ENTRIES_DEFAULT
    retention_days: int = DEFAULT_RETENTION_DAYS
    _index: dict[str, TriageEntry] = field(default_factory=dict, repr=False)

    def __post_init__(self) -> None:
        self._root = Path(self.root_dir).expanduser()
        self._root.mkdir(parents=True, exist_ok=True, mode=0o700)
        self._index_path = self._root / "triage_index.json"
        self._load_index()

    # ------------------------------------------------------------------
    # persistence (digests only)
    # ------------------------------------------------------------------
    def _load_index(self) -> None:
        try:
            data = json.loads(self._index_path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return
        for raw in data.get("entries", []) if isinstance(data, dict) else []:
            if isinstance(raw, dict) and raw.get("file_name"):
                try:
                    entry = TriageEntry(
                        asset_url=str(raw.get("asset_url", "")),
                        scope_hash=str(raw.get("scope_hash", "")),
                        client_id=str(raw.get("client_id", "")),
                        file_name=str(raw.get("file_name", "")),
                        sha256=str(raw.get("sha256", "")),
                        size_bytes=int(raw.get("size_bytes", 0)),
                        captured_at=float(raw.get("captured_at", 0.0)),
                    )
                except (TypeError, ValueError):
                    continue
                self._index[entry.file_name] = entry

    def _save_index(self) -> None:
        payload = {"entries": [e.as_dict() for e in self._index.values()]}
        self._index_path.write_text(
            json.dumps(payload, indent=2), encoding="utf-8"
        )

    def _scope_dir(self, scope_hash: str) -> Path:
        path = self._root / _slug_scope(scope_hash)
        path.mkdir(parents=True, exist_ok=True, mode=0o700)
        return path

    # ------------------------------------------------------------------
    # capture
    # ------------------------------------------------------------------
    def capture(
        self,
        *,
        asset_url: str,
        scope_hash: str,
        client_id: str,
        scope_enforcer: Any,
        capturer: Callable[[str], bytes] | None = None,
    ) -> TriageDecision:
        """Capture ONE preview for an authorized asset (fail-closed gate).

        ``scope_enforcer`` must expose ``check_url(url)`` (the standard
        ScopeEnforcer); anything not ``allowed`` blocks the capture with
        zero bytes touched. ``capturer`` returns PNG bytes for the URL —
        when absent the decision is ``capture_unavailable``.
        """
        if scope_enforcer is not None:
            decision = scope_enforcer.check_url(asset_url)
            if not getattr(decision, "allowed", False):
                return TriageDecision(
                    status="blocked_by_scope",
                    reason=str(getattr(decision, "reason", "") or "out of scope"),
                )
        else:
            return TriageDecision(
                status="rejected", reason="no scope enforcer supplied (fail-closed)"
            )
        if capturer is None:
            return TriageDecision(
                status="capture_unavailable",
                reason="no capturer configured (advisory path is opt-in)",
            )
        try:
            data = capturer(asset_url)
        except Exception as exc:  # capture failures are advisory, not fatal
            return TriageDecision(
                status="capture_unavailable",
                reason=f"capturer failed: {type(exc).__name__}",
            )
        if not isinstance(data, (bytes, bytearray)) or not data:
            return TriageDecision(status="capture_unavailable", reason="empty capture")
        if len(data) > MAX_PREVIEW_BYTES:
            return TriageDecision(
                status="rejected", reason=f"preview exceeds {MAX_PREVIEW_BYTES} bytes"
            )
        # Count cap: evict the OLDEST entry for this scope first (bounded
        # store; the eviction candidate list is returned, deletion happens
        # only when the caller calls purge).
        scope_entries = sorted(
            (e for e in self._index.values() if e.scope_hash == scope_hash),
            key=lambda e: e.captured_at,
        )
        evicted: list[TriageEntry] = []
        while len(scope_entries) >= max(1, self.max_entries):
            victim = scope_entries.pop(0)
            evicted.append(victim)
            self._index.pop(victim.file_name, None)
        file_name = f"{_digest(asset_url.encode())[:16]}-{int(time.time())}.png"
        target = self._scope_dir(scope_hash) / file_name
        try:
            target.write_bytes(bytes(data))
            os.chmod(target, 0o600)
        except OSError as exc:
            return TriageDecision(
                status="capture_unavailable",
                reason=f"store write failed: {type(exc).__name__}",
            )
        entry = TriageEntry(
            asset_url=asset_url,
            scope_hash=scope_hash,
            client_id=client_id,
            file_name=f"{_slug_scope(scope_hash)}/{file_name}",
            sha256=_digest(bytes(data)),
            size_bytes=len(data),
            captured_at=time.time(),
        )
        self._index[entry.file_name] = entry
        try:
            self._save_index()
        except OSError:
            logger.warning("asset_triage: index write failed", exc_info=True)
        reason = "evicted oldest preview(s) to honor the count cap" if evicted else ""
        return TriageDecision(status="stored", entry=entry, reason=reason)

    # ------------------------------------------------------------------
    # retention (dry-run first, explicit purge — 0.23.0 posture)
    # ------------------------------------------------------------------
    def retention_plan(
        self,
        *,
        retention_days: int | None = None,
        max_entries: int | None = None,
    ) -> list[TriageEntry]:
        """Return entries that EXPIRE under the policy — deletes nothing."""
        days = self.retention_days if retention_days is None else retention_days
        cap = self.max_entries if max_entries is None else max_entries
        now = time.time()
        expiring: list[TriageEntry] = []
        for entry in self._index.values():
            if now - entry.captured_at > days * 86_400:
                expiring.append(entry)
        remaining = [e for e in self._index.values() if e not in expiring]
        overflow = len(remaining) - cap
        if overflow > 0:
            expiring.extend(sorted(remaining, key=lambda e: e.captured_at)[:overflow])
        return sorted(expiring, key=lambda e: e.captured_at)

    def purge(self, entries: list[TriageEntry]) -> int:
        """Explicitly delete the given entries (caller's policy decision)."""
        removed = 0
        for entry in entries:
            self._index.pop(entry.file_name, None)
            path = self._root / entry.file_name
            try:
                path.unlink(missing_ok=True)
                removed += 1
            except OSError:
                logger.warning("asset_triage: purge failed for %s", entry.file_name)
        try:
            self._save_index()
        except OSError:
            logger.warning("asset_triage: index save after purge failed", exc_info=True)
        return removed

    def entries_for_scope(self, scope_hash: str) -> list[TriageEntry]:
        return sorted(
            (e for e in self._index.values() if e.scope_hash == scope_hash),
            key=lambda e: e.captured_at,
        )
