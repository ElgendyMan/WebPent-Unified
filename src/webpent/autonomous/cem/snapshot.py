"""CEM Watchtower — the snapshot engine (v83, U-CEM-1).

A snapshot is a bounded, redacted picture of a target's observable state:
subdomains, endpoints, response headers, certificate expiry, JS file
hashes, response shapes of sensitive endpoints, and the technology-stack
fingerprint. Snapshots are advisory observations only: nothing here probes
anything by itself, and every external observation arrives through
operator-injected data, never through this module's own network calls.

Persistence follows the store discipline used across the autonomous
package: atomic replace, corrupt or missing file degrades to empty memory,
hard per-target bounds, redaction on every persisted string.
"""

from __future__ import annotations

import contextlib
import hashlib
import json
import logging
import os
import tempfile
from typing import Any

from webpent.autonomous.hunt_contracts import redact

_LOG = logging.getLogger(__name__)

MAX_SNAPSHOTS_PER_TARGET = 64
MAX_LIST_ITEMS = 128
MAX_TARGETS = 16
SECTION_FIELDS = (
    "subdomains",
    "endpoints",
    "headers",
    "cert_expiry",
    "js_hashes",
    "tech_stack",
    "response_shapes",
)


def _clean_list(values: Any) -> list[str]:
    if not isinstance(values, (list, tuple, set)):
        return []
    cleaned = sorted(
        {
            redact(str(value)).strip()[:200]
            for value in values
            if str(value or "").strip()
        }
    )
    return cleaned[:MAX_LIST_ITEMS]


def _clean_mapping(mapping: Any) -> dict[str, str]:
    if not isinstance(mapping, dict):
        return {}
    cleaned: dict[str, str] = {}
    for key, value in list(mapping.items())[:MAX_LIST_ITEMS]:
        entry = redact(str(value or ""))[:200]
        if entry:
            cleaned[redact(str(key))[:100]] = entry
    return cleaned


def _snapshot_hash(snapshot: dict[str, Any]) -> str:
    canonical = json.dumps(
        {k: snapshot.get(k) for k in SECTION_FIELDS},
        sort_keys=True,
        ensure_ascii=False,
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()[:16]


def build_snapshot(
    target_id: str,
    *,
    now: float,
    subdomains: Any = None,
    endpoints: Any = None,
    headers: Any = None,
    cert_expiry: Any = None,
    js_hashes: Any = None,
    tech_stack: Any = None,
    response_shapes: Any = None,
) -> dict[str, Any]:
    """Build one bounded, redacted snapshot; pure and deterministic."""
    snapshot: dict[str, Any] = {
        "target_id": redact(str(target_id or ""))[:120],
        "ts": float(now),
        "subdomains": _clean_list(subdomains),
        "endpoints": _clean_list(endpoints),
        "headers": _clean_mapping(headers),
        "cert_expiry": redact(str(cert_expiry or ""))[:60],
        "js_hashes": _clean_mapping(js_hashes),
        "tech_stack": _clean_list(tech_stack),
        "response_shapes": _clean_mapping(response_shapes),
    }
    snapshot["hash"] = _snapshot_hash(snapshot)
    return snapshot


class SnapshotStore:
    """Bounded per-target snapshot history with atomic persistence."""

    def __init__(self, persist_path: Any) -> None:
        self._path = persist_path
        self._snapshots: dict[str, list[dict[str, Any]]] = {}
        self.load()

    def load(self) -> None:
        self._snapshots = {}
        try:
            raw = json.loads(self._path.read_text(encoding="utf-8"))
        except FileNotFoundError:
            return
        except (OSError, ValueError):
            _LOG.warning("snapshot file unreadable; starting empty: %s", self._path)
            return
        if not isinstance(raw, dict):
            return
        for target_id, series in list(raw.items())[:MAX_TARGETS]:
            if not isinstance(target_id, str) or not isinstance(series, list):
                continue
            kept = [s for s in series if isinstance(s, dict)]
            self._snapshots[target_id[:120]] = kept[-MAX_SNAPSHOTS_PER_TARGET:]

    def save(self) -> None:
        path = self._path
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            payload = json.dumps(self._snapshots, indent=2, ensure_ascii=False)
            fd, tmp_name = tempfile.mkstemp(dir=str(path.parent))
            try:
                with os.fdopen(fd, "w", encoding="utf-8") as handle:
                    handle.write(payload)
                os.replace(tmp_name, path)
            except BaseException:
                with contextlib.suppress(OSError):
                    os.unlink(tmp_name)
                raise
        except OSError as exc:
            _LOG.warning("snapshot save failed (memory stays in-process): %s", exc)

    def append(self, snapshot: dict[str, Any]) -> None:
        if not isinstance(snapshot, dict) or not snapshot.get("target_id"):
            return
        target_id = str(snapshot["target_id"])[:120]
        series = self._snapshots.setdefault(target_id, [])
        series.append(dict(snapshot))
        self._snapshots[target_id] = series[-MAX_SNAPSHOTS_PER_TARGET:]
        if len(self._snapshots) > MAX_TARGETS:
            # Keep the most recently appended targets.
            oldest = next(iter(self._snapshots))
            self._snapshots.pop(oldest)

    def latest(self, target_id: str) -> dict[str, Any] | None:
        series = self._snapshots.get(redact(str(target_id or ""))[:120], [])
        return series[-1] if series else None

    def series(self, target_id: str) -> list[dict[str, Any]]:
        return list(self._snapshots.get(redact(str(target_id or ""))[:120], []))

    def history_endpoints(self, target_id: str) -> set[str]:
        """Every endpoint ever observed for the target (bounded union)."""
        seen: set[str] = set()
        for snapshot in self.series(target_id):
            for endpoint in snapshot.get("endpoints", []):
                seen.add(str(endpoint))
                if len(seen) >= MAX_LIST_ITEMS:
                    return seen
        return seen

    def per_target_counts(self) -> dict[str, int]:
        return {k: len(v) for k, v in self._snapshots.items()}
