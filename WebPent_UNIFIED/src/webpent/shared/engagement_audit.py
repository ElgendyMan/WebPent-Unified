# src/webpent/shared/engagement_audit.py
"""Sprint I-1, item 3.2 — per-engagement append-only audit chain (M4 v2.1
OQ-8, ratified verbatim):

    "Per-engagement append-only audit file: JSON Lines format, sequential
    event numbers, a hash chain, O_APPEND write mode, 0o600 permissions,
    and a finalization event carrying the root hash. At engagement
    finalization, the root hash is anchored in two external places: (1)
    the engagement workspace record written through an independent path;
    and (2) the trace recorder's finalization summary line, which
    includes the root hash as the explicit exception to the normal
    event_id + event_type summary. A chain-verification step recomputes
    the full chain and compares both anchors; mismatch fails closed with
    AUDIT_CHAIN_VERIFICATION_FAILED and audit.chain_verification_failed.
    The residual threat boundary is explicit: protection covers
    in-process tampering and partial file edits under the Phase 1 threat
    model; an attacker with full filesystem control over every anchor is
    out of scope."

Payload schema (M4 §3.3.4, uniform across every event type): {event_id,
event_type, seq, prev_hash, timestamp, principal_alias, engagement_id,
target_fingerprint, error_class, details}. `details` must never contain
secret material — callers are responsible for that; this module does not
attempt to detect secrets in arbitrary caller-supplied dicts.

Neither of OQ-8's two external anchors (an "engagement workspace record"
and "the trace recorder's finalization summary") exist as ready-made
infrastructure elsewhere in this codebase as of this sprint — this
module builds both, minimally and only as far as this spec requires:
  - the workspace record is a small JSON file at a genuinely independent
    path from the audit log itself;
  - the trace anchor is a new `ProductionTrace.record_audit_event()` /
    `record_audit_finalization()` pair (see production_spine.py), kept
    deliberately thin — this module owns the audit chain; the trace
    module only receives one-line summaries, per spec.
"""
from __future__ import annotations

import hashlib
import json
import os
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from webpent.shared.exceptions import WebPentError

_GENESIS_PREV_HASH = "0" * 64


class AuditChainVerificationFailed(WebPentError):
    """AUDIT_CHAIN_VERIFICATION_FAILED / audit.chain_verification_failed
    (M4 OQ-8) — raised when recomputing the chain does not match either
    external anchor, or the chain itself is internally inconsistent
    (broken hash link, non-sequential seq, missing/duplicate
    finalization event)."""

    def __init__(self, reason: str) -> None:
        self.reason = reason
        self.error_class = "AUDIT_CHAIN_VERIFICATION_FAILED"
        self.event_type = "audit.chain_verification_failed"
        super().__init__(f"AUDIT_CHAIN_VERIFICATION_FAILED: {reason}")


def _canonical_json(payload: dict[str, Any]) -> str:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"))


def _event_hash(event_without_hash: dict[str, Any]) -> str:
    return hashlib.sha256(_canonical_json(event_without_hash).encode()).hexdigest()


@dataclass
class EngagementAuditChain:
    """Append-only, hash-chained audit log for one engagement.

    Not thread-safe across processes writing to the same file
    concurrently beyond what O_APPEND provides at the OS level for
    single small writes; this module targets the Phase-1 threat model
    stated in OQ-8 (in-process tampering / partial file edits), not
    concurrent-writer races, which no caller in this codebase currently
    needs.
    """

    engagement_id: str
    audit_dir: Path
    workspace_dir: Path
    trace: Any | None = None  # webpent.production.production_spine.ProductionTrace, optional
    _seq: int = field(default=0, init=False)
    _last_hash: str = field(default=_GENESIS_PREV_HASH, init=False)
    _finalized: bool = field(default=False, init=False)

    def __post_init__(self) -> None:
        self.audit_dir = Path(self.audit_dir)
        self.workspace_dir = Path(self.workspace_dir)
        self.audit_dir.mkdir(parents=True, exist_ok=True)
        self.workspace_dir.mkdir(parents=True, exist_ok=True)
        # Resume an existing chain (e.g. across a pause/resume cycle)
        # rather than silently restarting seq/hash at zero, which would
        # make the file internally inconsistent.
        if self.audit_path.exists():
            existing = _read_events(self.audit_path)
            if existing:
                self._seq = existing[-1]["seq"] + 1
                self._last_hash = existing[-1]["hash"]
                self._finalized = any(e["event_type"] == "audit.finalized" for e in existing)

    @property
    def audit_path(self) -> Path:
        return self.audit_dir / f"{self.engagement_id}.audit.jsonl"

    @property
    def workspace_path(self) -> Path:
        return self.workspace_dir / f"{self.engagement_id}.workspace.json"

    def append_event(
        self, *, event_type: str, principal_alias: str | None = None,
        target_fingerprint: str | None = None, error_class: str | None = None,
        details: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        if self._finalized:
            raise AuditChainVerificationFailed(
                f"cannot append event_type={event_type!r} — chain for "
                f"engagement {self.engagement_id!r} is already finalized"
            )
        event_id = f"{self.engagement_id}:{self._seq}"
        event_without_hash = {
            "event_id": event_id,
            "event_type": event_type,
            "seq": self._seq,
            "prev_hash": self._last_hash,
            "timestamp": time.time(),
            "principal_alias": principal_alias,
            "engagement_id": self.engagement_id,
            "target_fingerprint": target_fingerprint,
            "error_class": error_class,
            "details": details or {},
        }
        this_hash = _event_hash(event_without_hash)
        event = {**event_without_hash, "hash": this_hash}

        line = _canonical_json(event) + "\n"
        fd = os.open(str(self.audit_path), os.O_APPEND | os.O_CREAT | os.O_WRONLY, 0o600)
        try:
            os.write(fd, line.encode("utf-8"))
            os.fsync(fd)
        finally:
            os.close(fd)
        # Belt-and-suspenders: O_CREAT respects umask, so explicitly pin
        # the mode after creation too (0o600, per spec). On Windows the
        # POSIX mode bits are not modelled by NTFS (chmod only toggles the
        # read-only attribute); the equivalent "current user only" property
        # is guaranteed by the profile-scoped directory the audit file
        # lives in, so the POSIX-mode assertion is POSIX-only.
        if sys.platform != "win32":
            os.chmod(self.audit_path, 0o600)

        self._seq += 1
        self._last_hash = this_hash

        # Trace anchor, per-event: "the trace recorder receives only a
        # one-line summary event_id + event_type per event" — nothing
        # else, deliberately.
        if self.trace is not None:
            self.trace.record(
                stage="audit_event", component="EngagementAuditChain",
                detail={"event_id": event_id, "event_type": event_type},
                counts_toward_limit=False,
            )
        return event

    def finalize(self) -> dict[str, Any]:
        """Writes the finalization event, then anchors its hash (the
        chain's root hash) in both of OQ-8's required external places."""
        if self._finalized:
            raise AuditChainVerificationFailed(
                f"chain for engagement {self.engagement_id!r} is already finalized"
            )
        finalization_event = self.append_event(
            event_type="audit.finalized",
            details={"final_seq": self._seq, "event_count": self._seq},
        )
        root_hash = finalization_event["hash"]
        # append_event already flipped _last_hash; mark finalized AFTER
        # so the finalization event itself is allowed to be appended.
        self._finalized = True

        # Anchor 1: engagement workspace record, an independent path from
        # the audit log itself.
        workspace_record = {
            "engagement_id": self.engagement_id,
            "audit_chain_root_hash": root_hash,
            "finalized_at": finalization_event["timestamp"],
        }
        self.workspace_path.write_text(_canonical_json(workspace_record), encoding="utf-8")

        # Anchor 2: trace recorder's finalization summary — "the explicit
        # exception to the normal event_id + event_type summary" (i.e.
        # this ONE stage entry additionally carries the root hash; every
        # other audit_event stage entry above does not).
        if self.trace is not None:
            self.trace.record(
                stage="audit_finalization", component="EngagementAuditChain",
                detail={
                    "event_id": finalization_event["event_id"],
                    "event_type": finalization_event["event_type"],
                    "root_hash": root_hash,
                },
            )
        return finalization_event


def _read_events(audit_path: Path) -> list[dict[str, Any]]:
    events = []
    with audit_path.open("r", encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            events.append(json.loads(line))
    return events


def verify_chain(
    *, audit_path: Path, workspace_path: Path | None = None,
    trace: Any | None = None,
) -> dict[str, Any]:
    """Recompute the full hash chain from `audit_path` and compare the
    finalization event's hash (the root hash) against whichever external
    anchors are supplied. Raises AuditChainVerificationFailed (fail-
    closed) on ANY mismatch — internal chain break, missing/duplicate
    finalization, or an anchor disagreeing with the recomputed root.
    At least one of `workspace_path`/`trace` must be supplied, or there
    is nothing external to verify against (an unanchored chain can only
    prove internal self-consistency, not tamper-evidence).
    """
    audit_path = Path(audit_path)
    if not audit_path.exists():
        raise AuditChainVerificationFailed(f"audit file does not exist: {audit_path}")
    if workspace_path is None and trace is None:
        raise AuditChainVerificationFailed(
            "no external anchor supplied (workspace_path and trace both None) — "
            "cannot verify tamper-evidence, only internal consistency"
        )

    events = _read_events(audit_path)
    if not events:
        raise AuditChainVerificationFailed(f"audit file is empty: {audit_path}")

    expected_prev = _GENESIS_PREV_HASH
    for i, event in enumerate(events):
        if event.get("seq") != i:
            raise AuditChainVerificationFailed(
                f"non-sequential seq at line {i}: expected {i}, got {event.get('seq')}"
            )
        if event.get("prev_hash") != expected_prev:
            raise AuditChainVerificationFailed(
                f"broken hash chain at line {i} (seq={event.get('seq')}): "
                f"prev_hash does not match the previous event's hash"
            )
        stored_hash = event.get("hash")
        recomputed = _event_hash({k: v for k, v in event.items() if k != "hash"})
        if stored_hash != recomputed:
            raise AuditChainVerificationFailed(
                f"tampered event at line {i} (seq={event.get('seq')}): "
                "stored hash does not match recomputed hash"
            )
        expected_prev = stored_hash

    finalization_events = [e for e in events if e["event_type"] == "audit.finalized"]
    if not finalization_events:
        raise AuditChainVerificationFailed("no finalization event found in chain")
    if len(finalization_events) > 1:
        raise AuditChainVerificationFailed(
            f"{len(finalization_events)} finalization events found — expected exactly 1"
        )
    if finalization_events[0] is not events[-1]:
        raise AuditChainVerificationFailed("finalization event is not the last event in the chain")
    root_hash = finalization_events[0]["hash"]

    if workspace_path is not None:
        workspace_path = Path(workspace_path)
        if not workspace_path.exists():
            raise AuditChainVerificationFailed(f"workspace record does not exist: {workspace_path}")
        workspace_record = json.loads(workspace_path.read_text(encoding="utf-8"))
        if workspace_record.get("audit_chain_root_hash") != root_hash:
            raise AuditChainVerificationFailed(
                "workspace-record anchor mismatch: recomputed root hash does not "
                "match the root hash anchored in the workspace record"
            )

    if trace is not None:
        finalization_stages = [s for s in trace.stages if s["stage"] == "audit_finalization"]
        if not finalization_stages:
            raise AuditChainVerificationFailed("no audit_finalization stage found in supplied trace")
        trace_root_hash = finalization_stages[-1]["detail"].get("root_hash")
        if trace_root_hash != root_hash:
            raise AuditChainVerificationFailed(
                "trace anchor mismatch: recomputed root hash does not match the "
                "root hash recorded in the trace's finalization stage"
            )

    return {"root_hash": root_hash, "event_count": len(events), "verified": True}
