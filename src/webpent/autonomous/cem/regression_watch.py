"""CEM Reactor — the regression watch (v83, U-CEM-6).

Every confirmed finding gets a lifecycle the watch keeps, advisory only:

    active -> fixed -> regressed -> (re-fix cycles...)
    active -> deferred   (endpoint disappeared; nothing to retest)

The watch decides *when* a retest is due (configurable interval, capped
retest count) and notices *when the surface under test disappeared*
(auto-defer instead of blind retesting). A regression — a finding that
was fixed and came back — is an alert. Nothing here executes a retest:
the cycle picks up ``due_for_retest`` and runs the audited verification
path if the operator's runtime allows it.

Configurable via ``config/regression_watch.yaml``; corrupt/missing file
degrades to the built-in defaults.
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

ACTIVE = "active"
FIXED = "fixed"
REGRESSED = "regressed"
DEFERRED = "deferred"

MAX_FINDINGS = 256
#: One cycle never queues more than this many retests; the rest wait for
#: the next cycle, so a bloated store cannot blow a single scheduler slot.
MAX_DUE_PER_CYCLE = 32

DEFAULTS: dict[str, Any] = {
    "retest_interval_hours": 168.0,  # weekly by default
    "max_retests_per_finding": 8,
    "defer_after_missed_retests": 2,
}


def load_regression_config(path: Any) -> dict[str, Any]:
    """Load regression_watch.yaml; corrupt/missing -> defaults."""
    config = dict(DEFAULTS)
    if path is None:
        return config
    try:
        import yaml

        raw = yaml.safe_load(Path(path).read_text(encoding="utf-8"))
    except FileNotFoundError:
        return config
    except Exception as exc:
        _LOG.warning("regression config unreadable; using defaults: %s", exc)
        return config
    if not isinstance(raw, dict):
        return config
    for key in DEFAULTS:
        value = raw.get(key)
        if isinstance(value, (int, float)) and value >= 0:
            config[key] = value
    return config


class RegressionWatch:
    """Finding lifecycle store. Advisory, bounded, fail-soft."""

    def __init__(self, persist_path: Any, *, config_path: Any = None) -> None:
        self._path = persist_path
        self.config = load_regression_config(config_path)
        self._findings: dict[str, dict[str, Any]] = {}
        self.load()

    def load(self) -> None:
        try:
            raw = json.loads(self._path.read_text(encoding="utf-8"))
        except (FileNotFoundError, OSError, ValueError, AttributeError):
            self._findings = {}
            return
        if not isinstance(raw, dict):
            self._findings = {}
            return
        kept: dict[str, dict[str, Any]] = {}
        for finding_id, record in list(raw.items())[:MAX_FINDINGS]:
            if isinstance(finding_id, str) and isinstance(record, dict):
                kept[finding_id[:120]] = record
        self._findings = kept

    def save(self) -> None:
        try:
            self._path.parent.mkdir(parents=True, exist_ok=True)
            fd, tmp_name = tempfile.mkstemp(dir=str(self._path.parent))
            try:
                with os.fdopen(fd, "w", encoding="utf-8") as handle:
                    json.dump(self._findings, handle, indent=2)
                os.replace(tmp_name, self._path)
            except BaseException:
                with contextlib.suppress(OSError):
                    os.unlink(tmp_name)
                raise
        except (OSError, AttributeError) as exc:
            _LOG.warning("regression watch save failed (memory stays in-process): %s", exc)

    def record_finding(
        self,
        finding_id: str,
        *,
        endpoint: str = "",
        vuln_class: str = "",
        now: float,
    ) -> dict[str, Any]:
        """Register (or idempotently refresh) a finding under watch."""
        finding_id = redact(str(finding_id or ""))[:120]
        if not finding_id:
            return {}
        existing = self._findings.get(finding_id)
        if existing is None:
            record = {
                "finding_id": finding_id,
                "endpoint": redact(str(endpoint or ""))[:200],
                "vuln_class": redact(str(vuln_class or ""))[:80],
                "state": ACTIVE,
                "first_seen": float(now),
                "last_transition": float(now),
                "retest_count": 0,
                "missed_retests": 0,
            }
            self._findings[finding_id] = record
            if len(self._findings) > MAX_FINDINGS:
                oldest = min(self._findings, key=lambda k: self._findings[k].get("first_seen", 0))
                self._findings.pop(oldest)
            self.save()
            return dict(record)
        if endpoint and not existing.get("endpoint"):
            existing["endpoint"] = redact(str(endpoint))[:200]
            self.save()
        return dict(existing)

    def note_result(
        self, finding_id: str, *, still_vulnerable: bool, now: float
    ) -> dict[str, Any] | None:
        """Record a retest outcome; a fixed->present result regresses."""
        record = self._findings.get(redact(str(finding_id or ""))[:120])
        if record is None:
            return None
        now = float(now)
        record["retest_count"] = int(record.get("retest_count") or 0) + 1
        record["missed_retests"] = 0
        record["last_transition"] = now
        was = record["state"]
        if still_vulnerable and was in (FIXED,):
            record["state"] = REGRESSED
        elif still_vulnerable:
            record["state"] = ACTIVE
        else:
            record["state"] = FIXED
        self.save()
        out = dict(record)
        out["regressed"] = record["state"] == REGRESSED and was != REGRESSED
        return out

    def note_endpoint_gone(self, finding_id: str, *, now: float) -> dict[str, Any] | None:
        """The endpoint under test disappeared: defer, do not blind-retest."""
        record = self._findings.get(redact(str(finding_id or ""))[:120])
        if record is None:
            return None
        record["state"] = DEFERRED
        record["last_transition"] = float(now)
        self.save()
        return dict(record)

    def note_retest_blocked(self, finding_id: str) -> dict[str, Any] | None:
        """A scheduled retest could not run this cycle (endpoint missing)."""
        record = self._findings.get(redact(str(finding_id or ""))[:120])
        if record is None:
            return None
        record["missed_retests"] = int(record.get("missed_retests") or 0) + 1
        if record["missed_retests"] >= int(self.config["defer_after_missed_retests"]):
            record["state"] = DEFERRED
        self.save()
        return dict(record)

    def due_for_retest(self, now: float) -> list[str]:
        """Finding IDs whose retest window has arrived, capped and honest.

        Deferred findings never come back automatically; reactivating one
        is the operator's (or a fresh diff's) decision.
        """
        now = float(now)
        interval = float(self.config["retest_interval_hours"]) * 3600.0
        cap = int(self.config["max_retests_per_finding"])
        due: list[tuple[float, str]] = []
        for finding_id, record in self._findings.items():
            if record.get("state") not in (ACTIVE, FIXED, REGRESSED):
                continue
            if int(record.get("retest_count") or 0) >= cap:
                continue
            if now - float(record.get("last_transition") or 0) >= interval:
                due.append((float(record.get("last_transition") or 0), finding_id))
        due.sort()
        return [finding_id for _, finding_id in due[:MAX_DUE_PER_CYCLE]]

    def regressed(self) -> list[dict[str, Any]]:
        return [dict(r) for r in self._findings.values() if r.get("state") == REGRESSED]

    def status(self) -> dict[str, int]:
        counts = {ACTIVE: 0, FIXED: 0, REGRESSED: 0, DEFERRED: 0}
        for record in self._findings.values():
            state = str(record.get("state") or "")
            if state in counts:
                counts[state] += 1
        return counts


__all__ = [
    "ACTIVE",
    "DEFAULTS",
    "DEFERRED",
    "FIXED",
    "MAX_DUE_PER_CYCLE",
    "MAX_FINDINGS",
    "REGRESSED",
    "RegressionWatch",
    "load_regression_config",
]
