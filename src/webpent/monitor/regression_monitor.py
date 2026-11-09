# src/webpent/monitor/regression_monitor.py
"""Regression monitor (PROPOSALS_ULTIMATE_V3 §10, 2026-11-01).

Watches previously-CONFIRMED findings for regressions: a fix that
reverts is a high-value new report, and the hunter who notices it wins
twice on the same class.

Honesty contracts, stated up front:
- RECHECK-ONLY. The monitor re-tests what was already confirmed, using
  the reference payload recorded at watch time. It NEVER explores: no
  new payloads, no new endpoints, no enumeration. A finding that was
  never confirmed cannot be watched.
- State vocabulary is exactly {vulnerable, fixed, unverifiable} and is
  fail-closed: an unknown state from the injected verifier is an
  error, never silently mapped.
- Every recheck passes a MANDATORY scope check on the recorded
  endpoint BEFORE the verifier runs and is recorded in the request
  ledger BEFORE it is issued; a ledger refusal fails closed.
- The verifier is INJECTED (one callable). The module owns no network
  transport; tests pass fakes. JSONL storage is local and atomic-
  append; corrupt lines refuse to load.
- Flag-gated via ``enable_regression_monitor`` (default False); the
  watch store path is ``regression_watch_path`` (empty = refusal).

Deterministic for the same records and verifier (timestamps are
injected for tests).
"""

from __future__ import annotations

import hashlib
import json
import os
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Callable, Mapping, Sequence

__all__ = [
    "STATES",
    "RegressionMonitorError",
    "WatchRecord",
    "WatchStore",
    "finding_fingerprint",
    "recheck",
    "diff_report",
    "regression_refusal",
]

STATES = ("vulnerable", "fixed", "unverifiable")


class RegressionMonitorError(ValueError):
    """Raised when a watch cannot proceed within its contracts."""


def regression_refusal() -> str | None:
    """Refusal code when the operator's flag is off, else None."""
    from webpent.config.settings import get_settings

    if not get_settings().enable_regression_monitor:
        return "regression_monitor_flag_off"
    return None


def _require_flag() -> None:
    if regression_refusal() is not None:
        raise RegressionMonitorError("regression_monitor_flag_off")


@dataclass(frozen=True)
class WatchRecord:
    """One watched finding and its latest known state."""

    finding_ref: str
    vuln_class: str
    endpoint: str
    fingerprint: str
    last_state: str
    last_checked_at: str
    reference_payload: dict = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self.finding_ref or not self.finding_ref.strip():
            raise RegressionMonitorError("regression_bad_finding_ref")
        if not self.endpoint or not self.endpoint.strip():
            raise RegressionMonitorError("regression_bad_endpoint")
        if not self.fingerprint:
            raise RegressionMonitorError("regression_bad_fingerprint")
        if self.last_state not in STATES:
            raise RegressionMonitorError("regression_unknown_state")

    def to_json(self) -> str:
        return json.dumps(
            {
                "finding_ref": self.finding_ref,
                "vuln_class": self.vuln_class,
                "endpoint": self.endpoint,
                "fingerprint": self.fingerprint,
                "last_state": self.last_state,
                "last_checked_at": self.last_checked_at,
                "reference_payload": self.reference_payload,
            },
            sort_keys=True,
            separators=(",", ":"),
        )

    @classmethod
    def from_json(cls, line: str) -> "WatchRecord":
        try:
            raw = json.loads(line)
        except ValueError as exc:
            raise RegressionMonitorError(
                "regression_corrupt_line"
            ) from exc
        if not isinstance(raw, dict):
            raise RegressionMonitorError("regression_corrupt_line")
        return cls(
            finding_ref=str(raw.get("finding_ref", "")),
            vuln_class=str(raw.get("vuln_class", "")),
            endpoint=str(raw.get("endpoint", "")),
            fingerprint=str(raw.get("fingerprint", "")),
            last_state=str(raw.get("last_state", "")),
            last_checked_at=str(raw.get("last_checked_at", "")),
            reference_payload=dict(raw.get("reference_payload") or {}),
        )


def _finding_mapping(finding) -> Mapping:
    if isinstance(finding, Mapping):
        return finding
    dump = getattr(finding, "model_dump", None)
    if callable(dump):
        return dump()
    raise RegressionMonitorError("regression_bad_finding")


def finding_fingerprint(finding) -> str:
    """Recheckable fingerprint: class + path + key params, canonical.

    Order-independent over request parameters, so equivalent states
    hash identically; any material change hashes differently.
    """
    data = dict(_finding_mapping(finding))
    params = data.get("request_data")
    if isinstance(params, Mapping):
        data["request_data"] = {
            str(k): params[k] for k in sorted(params, key=str)
        }
    canonical = {
        "vuln_class": str(data.get("vuln_class", "")),
        "endpoint": str(data.get("endpoint", data.get("url", ""))),
        "target_param": str(data.get("target_param", "")),
        "request_data": data.get("request_data") or {},
    }
    blob = json.dumps(canonical, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()


class WatchStore:
    """Append-only local JSONL of WatchRecords; corrupt lines refuse."""

    def __init__(self, path: str):
        if not path or not path.strip():
            raise RegressionMonitorError("regression_watch_path_required")
        self.path = path

    def add(self, record: WatchRecord) -> None:
        with open(self.path, "a", encoding="utf-8") as fh:
            fh.write(record.to_json() + "\n")
            fh.flush()
            os.fsync(fh.fileno())

    def load(self) -> list[WatchRecord]:
        if not os.path.exists(self.path):
            return []
        records: list[WatchRecord] = []
        with open(self.path, encoding="utf-8") as fh:
            for line in fh:
                if not line.strip():
                    continue
                records.append(WatchRecord.from_json(line))
        return records

    def load_latest(self) -> list[WatchRecord]:
        """Latest record per fingerprint, in first-seen order."""
        latest: dict[str, WatchRecord] = {}
        order: list[str] = []
        for rec in self.load():
            if rec.fingerprint not in latest:
                order.append(rec.fingerprint)
            latest[rec.fingerprint] = rec
        return [latest[f] for f in order]


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def recheck(
    record: WatchRecord,
    *,
    verifier: Callable[[WatchRecord], str],
    scope_checker: Callable[[str], bool] | None,
    ledger,
    now: Callable[[], str] | None = None,
) -> WatchRecord:
    """Re-test ONLY the recorded reference payload; update the state.

    ``verifier(record) -> state`` is injected and receives nothing the
    watch did not already hold — no exploration is possible through
    this path. Scope and ledger gates are mandatory and fail closed.
    """
    _require_flag()
    if verifier is None:
        raise RegressionMonitorError("regression_verifier_required")
    if scope_checker is None:
        raise RegressionMonitorError("regression_scope_checker_required")
    if ledger is None:
        raise RegressionMonitorError("regression_ledger_required")
    if not scope_checker(record.endpoint):
        raise RegressionMonitorError("regression_out_of_scope")
    recorded = ledger.record(
        "GET", record.endpoint, flags="regression_monitor"
    )
    if not recorded:
        raise RegressionMonitorError("regression_ledger_refused")
    state = verifier(record)
    if state not in STATES:
        raise RegressionMonitorError("regression_unknown_state")
    timestamp = (now or _now_iso)()
    return WatchRecord(
        finding_ref=record.finding_ref,
        vuln_class=record.vuln_class,
        endpoint=record.endpoint,
        fingerprint=record.fingerprint,
        last_state=state,
        last_checked_at=timestamp,
        reference_payload=dict(record.reference_payload),
    )


def diff_report(records: Sequence[WatchRecord]) -> list[WatchRecord]:
    """Latest state per fingerprint; return what came BACK (vulnerable)."""
    _require_flag()
    latest: dict[str, WatchRecord] = {}
    order: list[str] = []
    for rec in records:
        if rec.fingerprint not in latest:
            order.append(rec.fingerprint)
        latest[rec.fingerprint] = rec
    return [latest[f] for f in order if latest[f].last_state == "vulnerable"]
