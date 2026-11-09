"""Cross-session dead-end memory (v81, Task 1).

The counterpart to ``hunt_intel.IntelStore``: where intel remembers what a
target has *proven* vulnerable, this store remembers what has been
*conclusively decided negative* — a real executed outcome that came back
clean for a (vuln_class, endpoint) pair. Future rounds use it as an
advisory signal only: matching advisory seeds are demoted (re-ranked, never
dropped), and the round-budget allocator reads the dead-end ratio to stop
spending quiet rounds on a mostly-mapped target.

Only decisive negative outcomes enter: ``clean`` status, or ``executed``
with a falsy ``vulnerable`` flag. Confirmed/vulnerable outcomes, blocked
or inconclusive outcomes never enter — a blocked probe is a gap, not a
dead end. The store never creates findings, never claims coverage, and
never stores secrets or query values.
"""

from __future__ import annotations

import contextlib
import json
import logging
import os
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from webpent.autonomous.hunt_contracts import redact

_LOG = logging.getLogger(__name__)

MAX_ORIGINS = 64
MAX_PAIRS_PER_ORIGIN = 48
# Demotion penalties, advisory only: re-rank, never drop (v81 design).
PENALTY_EXACT_PAIR = 0.25
PENALTY_CLASS_LEVEL = 0.10
# Class-level demotion needs more than one dead pair: one dead endpoint is
# not a dead class.
CLASS_LEVEL_MIN_PAIRS = 2
# dead_end_ratio saturates at this many recorded pairs per origin.
RATIO_SATURATION_PAIRS = 16


def _normalize_url(value: object) -> str:
    """Origin + path only: no query, no fragment, no credentials."""
    text = redact(str(value or ""))
    parts = urlsplit(text)
    if not parts.scheme or not parts.netloc:
        return ""
    host = parts.netloc.rpartition("@")[2].lower()
    if not host:
        return ""
    path = parts.path.split("?", 1)[0].split("#", 1)[0]
    if len(path) > 256:
        path = path[:256]
    return f"{parts.scheme.lower()}://{host}{path}"


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _is_decided_negative(record: dict[str, Any]) -> bool:
    status = str(record.get("status") or "").strip().lower()
    if status == "clean":
        return True
    if status != "executed":
        return False
    return not bool(record.get("vulnerable"))


class DeadEndStore:
    """Per-target-origin negative intelligence persisted to one JSON file.

    Only conclusively-decided negative outcomes enter the store. Corrupt or
    wrong-typed files are discarded (logged, never raised): a broken
    dead-end file must degrade to "no memory", never crash a hunt.
    """

    def __init__(self, persist_path: Path | str) -> None:
        self.path = Path(persist_path)
        self._origins: dict[str, dict[str, Any]] = {}
        self.load()

    # -- persistence -------------------------------------------------

    def load(self) -> None:
        self._origins = {}
        try:
            raw = json.loads(self.path.read_text(encoding="utf-8"))
        except FileNotFoundError:
            return
        except (OSError, ValueError):
            _LOG.warning("dead-end file unreadable; starting with no memory: %s", self.path)
            return
        if not isinstance(raw, dict):
            _LOG.warning("dead-end file wrong type; starting with no memory: %s", self.path)
            return
        for origin, record in raw.items():
            if isinstance(origin, str) and isinstance(record, dict):
                self._origins[origin] = self._sanitize_record(record)
            if len(self._origins) >= MAX_ORIGINS:
                break

    def save(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        payload = json.dumps(self._origins, indent=2, ensure_ascii=False)
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
            _LOG.warning("dead-end save failed (memory stays in-process): %s", exc)

    @staticmethod
    def _sanitize_record(record: dict[str, Any]) -> dict[str, Any]:
        pairs: list[dict[str, Any]] = []
        raw_pairs = record.get("pairs")
        if isinstance(raw_pairs, list):
            for entry in raw_pairs:
                if not isinstance(entry, dict) or len(pairs) >= MAX_PAIRS_PER_ORIGIN:
                    break
                vuln_class = str(entry.get("class") or "").strip()[:64]
                if not vuln_class:
                    continue
                endpoint = _normalize_url(entry.get("endpoint") or "")
                hits = entry.get("hits")
                if not isinstance(hits, int) or hits <= 0:
                    hits = 1
                pairs.append(
                    {"class": vuln_class, "endpoint": endpoint, "hits": hits}
                )
        updated = record.get("updated_at")
        return {
            "pairs": pairs,
            "updated_at": updated if isinstance(updated, str) else "",
        }

    # -- updating ----------------------------------------------------

    def update_from_state(self, state: Any) -> None:
        """Feed the store from decisively-negative outcome records only.

        Outcomes without a vulnerability class, confirmed/vulnerable
        outcomes, and blocked/inconclusive ones are ignored: this memory
        records dead ends, not gaps and not wins.
        """
        target = _normalize_url(getattr(state, "target_url", "") or "")
        if not target:
            return
        parts = urlsplit(target)
        origin = f"{parts.scheme}://{parts.netloc}"
        outcomes = getattr(state, "outcomes", None)
        if not isinstance(outcomes, list) or not outcomes:
            return
        for outcome in outcomes:
            if not isinstance(outcome, dict) or not _is_decided_negative(outcome):
                continue
            vuln_class = str(outcome.get("vulnerability_class") or "").strip()
            if not vuln_class:
                continue
            raw_url = (
                outcome.get("url")
                or outcome.get("path")
                or (outcome.get("task") or {}).get("target_url")
                if isinstance(outcome.get("task"), dict)
                else outcome.get("url")
                or outcome.get("path")
            )
            endpoint = _normalize_url(raw_url)
            # Per-origin guard (mirrors intel CR-4): a URL belonging to
            # another origin never enters this origin's record.
            if endpoint and not endpoint.startswith(f"{origin}/"):
                endpoint = ""
            self._record(origin, vuln_class, endpoint)
        record = self._origins.get(origin)
        if record is not None:
            record["updated_at"] = _now_iso()
            record["pairs"] = record["pairs"][:MAX_PAIRS_PER_ORIGIN]
            while len(self._origins) > MAX_ORIGINS:
                oldest = min(
                    (o for o in self._origins if o != origin),
                    key=lambda o: self._origins[o].get("updated_at", ""),
                    default=None,
                )
                if oldest is None:
                    break
                del self._origins[oldest]

    def _record(self, origin: str, vuln_class: str, endpoint: str) -> None:
        record = self._origins.setdefault(origin, {"pairs": [], "updated_at": ""})
        for pair in record["pairs"]:
            if pair["class"] == vuln_class and pair["endpoint"] == endpoint:
                pair["hits"] += 1
                return
        if len(record["pairs"]) >= MAX_PAIRS_PER_ORIGIN:
            # Drop the least-hit pair to make room: repeated dead ends are
            # the stronger memory.
            record["pairs"] = sorted(
                record["pairs"], key=lambda p: -p["hits"]
            )[: MAX_PAIRS_PER_ORIGIN - 1]
        record["pairs"].append(
            {"class": vuln_class, "endpoint": endpoint, "hits": 1}
        )

    # -- reading -----------------------------------------------------

    def penalty_for(self, target_url: str, vuln_class: str, endpoint: str = "") -> float:
        """Advisory demotion penalty in [0, 0.25]; re-ranks, never drops.

        Exact (class, endpoint) match gets the full penalty; a class with
        two or more dead pairs gets the class-level penalty even on an
        unknown endpoint. Unknown probes and other origins get 0.
        """
        target = _normalize_url(target_url or "")
        parts = urlsplit(target)
        if not parts.scheme or not parts.netloc:
            return 0.0
        record = self._origins.get(f"{parts.scheme}://{parts.netloc}")
        if not record:
            return 0.0
        wanted_class = str(vuln_class or "").strip()
        wanted_endpoint = _normalize_url(endpoint or "")
        dead_pairs = [p for p in record["pairs"] if p["class"] == wanted_class]
        if not dead_pairs:
            return 0.0
        for pair in dead_pairs:
            if pair["endpoint"] == wanted_endpoint and wanted_endpoint:
                return PENALTY_EXACT_PAIR
        if len(dead_pairs) >= CLASS_LEVEL_MIN_PAIRS:
            return PENALTY_CLASS_LEVEL
        return 0.0

    def dead_end_ratio(self, target_url: str) -> float:
        """Saturating dead-end density in [0, 1] for the budget allocator."""
        target = _normalize_url(target_url or "")
        parts = urlsplit(target)
        if not parts.scheme or not parts.netloc:
            return 0.0
        record = self._origins.get(f"{parts.scheme}://{parts.netloc}")
        if not record:
            return 0.0
        return min(1.0, len(record["pairs"]) / RATIO_SATURATION_PAIRS)

    def origins(self) -> list[str]:
        return sorted(self._origins)

    def record_for(self, target_url: str) -> dict[str, Any] | None:
        target = _normalize_url(target_url or "")
        parts = urlsplit(target)
        if not parts.scheme or not parts.netloc:
            return None
        return self._origins.get(f"{parts.scheme}://{parts.netloc}")
