# src/webpent/production/worker_coordination.py
"""webpent.production.worker_coordination — Track 12, item 3.

Roadmap contract (المسار 12، البند 3 — تنسيق عدة عمال):

    تنسيق عدة عمال: مشاركة حالة ونتائج منقحة ومنع التكرار، ضمن حدود
    العميل والنطاق، مع سجل واضح للتغييرات.

    ("Multi-worker coordination: share state and sanitized results and
    prevent duplication, within CLIENT and SCOPE bounds, with a clear
    change log.")

Design
------
``WorkerCoordinator`` is a small, dependency-free coordination layer for
several worker processes operating on the same platform install:

1. **Work-claim ledger** — atomic first-wins claims on work units
   (campaigns, retests, ...) guarded by ``fcntl.flock`` so two workers
   can never hold the same work unit. Claims carry a TTL; an expired
   claim may be taken over (recorded as ``TAKEOVER``), which keeps a
   crashed worker from blocking work forever.
2. **Cross-worker result dedup** — an ``O_CREAT|O_EXCL`` fingerprint
   ledger: the first worker to register a result fingerprint reports it;
   later registrations are ``DUPLICATE``. This is the multi-worker
   counterpart of the Track 11 dedup gate (same logical identity, but
   shared ACROSS worker processes, not just across campaigns).
3. **Change log** — every claim/renew/release/takeover/dedup event is
   appended as one JSON line to ``changes.jsonl``: the roadmap's "سجل
   واضح للتغييرات".

Isolation bounds (non-negotiable):

* Every entry point is client-scoped: state lives under a per-client
  subdirectory derived from a hash of the client id. Cross-client reads
  are impossible by construction; the platform privacy rule (raw data
  never shared across clients) is preserved.
* Claims carry the scope hash they were made under. A claim attempt on
  an already-claimed unit with a DIFFERENT scope hash returns
  ``SCOPE_CONFLICT`` and never takes over — coordination must not become
  a channel to widen targeting.

Failure semantics: coordination is an efficiency guard, not a safety
boundary. Ledger failures never crash the caller: claims degrade to
``DENIED_ERROR`` (do the work is allowed; the caller decides), dedup
degrades to ``INDETERMINATE`` (report rather than silently suppress —
the same fail-safe rule as the dedup gate). Everything is logged.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import time
import uuid
from contextlib import suppress
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

__all__ = [
    "ClaimDecision",
    "ClaimOutcome",
    "DedupVerdict",
    "WorkerCoordinator",
]


class ClaimOutcome(str, Enum):
    """Outcome vocabulary for work-claim attempts."""

    ACQUIRED = "acquired"
    RENEWED = "renewed"
    TAKEOVER = "takeover"
    BUSY = "busy"
    SCOPE_CONFLICT = "scope_conflict"
    DENIED_ERROR = "denied_error"


class DedupVerdict(str, Enum):
    """Outcome vocabulary for cross-worker result dedup."""

    FIRST_SEEN = "first_seen"
    DUPLICATE = "duplicate"
    INDETERMINATE = "indeterminate"


@dataclass
class ClaimDecision:
    """Result of one claim/renew/release attempt (auditable)."""

    outcome: ClaimOutcome
    work_unit_id: str
    client_id: str
    holder_worker_id: str | None = None
    expires_at: float | None = None
    note: str = ""

    def as_dict(self) -> dict[str, Any]:
        return {
            "outcome": self.outcome.value
            if isinstance(self.outcome, ClaimOutcome)
            else str(self.outcome),
            "work_unit_id": self.work_unit_id,
            "client_id": self.client_id,
            "holder_worker_id": self.holder_worker_id,
            "expires_at": self.expires_at,
            "note": self.note,
        }


def _slug(value: str) -> str:
    """Filesystem-safe namespace key (hash when non-trivial)."""
    cleaned = "".join(c if c.isalnum() or c in "-_" else "_" for c in value.strip())
    cleaned = cleaned[:48]
    digest = hashlib.sha256(value.encode("utf-8", "replace")).hexdigest()[:12]
    return f"{cleaned or 'blank'}-{digest}"


class WorkerCoordinator:
    """Client-scoped multi-worker coordination (claims + dedup + log)."""

    def __init__(
        self,
        coord_dir: str | os.PathLike[str],
        *,
        worker_id: str | None = None,
        claim_ttl_seconds: float = 300.0,
    ) -> None:
        self._root = Path(coord_dir).expanduser()
        self._worker_id = worker_id or f"worker-{os.getpid()}-{uuid.uuid4().hex[:8]}"
        self._ttl = max(1.0, float(claim_ttl_seconds))
        self._root.mkdir(parents=True, exist_ok=True, mode=0o700)
        (self._root / "clients").mkdir(exist_ok=True, mode=0o700)

    # ------------------------------------------------------------------
    # properties / paths
    # ------------------------------------------------------------------
    @property
    def worker_id(self) -> str:
        return self._worker_id

    @property
    def coord_dir(self) -> Path:
        return self._root

    @property
    def claim_ttl_seconds(self) -> float:
        return self._ttl

    def _client_dir(self, client_id: str) -> Path:
        return self._root / "clients" / _slug(client_id or "unassigned")

    def _claims_dir(self, client_id: str) -> Path:
        path = self._client_dir(client_id) / "claims"
        path.mkdir(parents=True, exist_ok=True, mode=0o700)
        return path

    def _fingerprints_dir(self, client_id: str) -> Path:
        path = self._client_dir(client_id) / "fingerprints"
        path.mkdir(parents=True, exist_ok=True, mode=0o700)
        return path

    @property
    def change_log_path(self) -> Path:
        return self._root / "changes.jsonl"

    # ------------------------------------------------------------------
    # change log (the roadmap's "سجل واضح للتغييرات")
    # ------------------------------------------------------------------
    def _log(self, event: str, **fields: Any) -> None:
        record = {
            "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "worker_id": self._worker_id,
            "event": event,
            **fields,
        }
        try:
            with open(self.change_log_path, "a", encoding="utf-8") as fh:
                fh.write(json.dumps(record, separators=(",", ":"), default=str) + "\n")
        except OSError:
            logger.warning(
                "worker_coordination: change log write failed (%s)", event, exc_info=True
            )

    def read_change_log(self, *, limit: int = 500) -> list[dict[str, Any]]:
        """Read the last ``limit`` change-log records (for dashboards)."""
        try:
            with open(self.change_log_path, encoding="utf-8") as fh:
                lines = fh.readlines()
        except OSError:
            return []
        records: list[dict[str, Any]] = []
        for line in lines[-max(1, limit) :]:
            try:
                data = json.loads(line)
                if isinstance(data, dict):
                    records.append(data)
            except ValueError:
                continue
        return records

    # ------------------------------------------------------------------
    # work-claim ledger
    # ------------------------------------------------------------------
    def _claim_path(self, client_id: str, work_unit_id: str) -> Path:
        return self._claims_dir(client_id) / f"{_slug(work_unit_id)}.json"

    def claim_work(
        self,
        client_id: str,
        scope_hash: str,
        work_unit_id: str,
        *,
        work_kind: str = "campaign",
    ) -> ClaimDecision:
        """Atomically claim a work unit for this worker (first wins).

        ``ACQUIRED`` on success; ``RENEWED`` when this worker already
        holds it; ``TAKEOVER`` when the previous holder's TTL expired;
        ``BUSY`` when another live worker holds it; ``SCOPE_CONFLICT``
        when the unit is held under a different scope hash (never taken
        over); ``DENIED_ERROR`` when the ledger itself fails.
        """
        import fcntl

        try:
            path = self._claim_path(client_id, work_unit_id)
        except OSError as exc:
            self._log(
                "claim_error",
                client_id=client_id,
                work_unit_id=work_unit_id,
                detail=type(exc).__name__,
            )
            return ClaimDecision(
                ClaimOutcome.DENIED_ERROR,
                work_unit_id,
                client_id,
                note=f"ledger unavailable: {type(exc).__name__}",
            )
        now = time.time()
        try:
            fd = os.open(str(path), os.O_RDWR | os.O_CREAT, 0o600)
        except OSError as exc:
            self._log(
                "claim_error",
                client_id=client_id,
                work_unit_id=work_unit_id,
                detail=type(exc).__name__,
            )
            return ClaimDecision(
                ClaimOutcome.DENIED_ERROR,
                work_unit_id,
                client_id,
                note=f"ledger unavailable: {type(exc).__name__}",
            )
        try:
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except OSError:
                # Contended flock: the other process is mid-claim. Busy.
                self._log(
                    "claim_contended",
                    client_id=client_id,
                    work_unit_id=work_unit_id,
                )
                return ClaimDecision(
                    ClaimOutcome.BUSY, work_unit_id, client_id, note="claim in flight"
                )
            raw = os.read(fd, 4096)
            prior: dict[str, Any] = {}
            if raw.strip():
                try:
                    loaded = json.loads(raw.decode("utf-8", "replace"))
                    if isinstance(loaded, dict):
                        prior = loaded
                except ValueError:
                    prior = {}
            if prior:
                prior_scope = str(prior.get("scope_hash") or "")
                prior_worker = str(prior.get("worker_id") or "")
                prior_expiry = float(prior.get("expires_at") or 0.0)
                if prior_scope and scope_hash and prior_scope != scope_hash:
                    self._log(
                        "claim_scope_conflict",
                        client_id=client_id,
                        work_unit_id=work_unit_id,
                    )
                    return ClaimDecision(
                        ClaimOutcome.SCOPE_CONFLICT,
                        work_unit_id,
                        client_id,
                        holder_worker_id=prior_worker or None,
                        expires_at=prior_expiry or None,
                        note="held under a different scope hash",
                    )
                if prior_worker == self._worker_id and prior_expiry > now:
                    meta = self._claim_meta(
                        client_id, scope_hash, work_unit_id, work_kind
                    )
                    os.lseek(fd, 0, os.SEEK_SET)
                    os.ftruncate(fd, 0)
                    os.write(fd, json.dumps(meta, separators=(",", ":")).encode())
                    self._log("claim_renewed", client_id=client_id, work_unit_id=work_unit_id)
                    return ClaimDecision(
                        ClaimOutcome.RENEWED,
                        work_unit_id,
                        client_id,
                        holder_worker_id=self._worker_id,
                        expires_at=meta["expires_at"],
                    )
                if prior_expiry > now:
                    self._log(
                        "claim_busy",
                        client_id=client_id,
                        work_unit_id=work_unit_id,
                        holder=prior_worker,
                    )
                    return ClaimDecision(
                        ClaimOutcome.BUSY,
                        work_unit_id,
                        client_id,
                        holder_worker_id=prior_worker,
                        expires_at=prior_expiry,
                    )
                # Expired → takeover falls through to the write below.
                self._log(
                    "claim_takeover",
                    client_id=client_id,
                    work_unit_id=work_unit_id,
                    previous_holder=prior_worker,
                )
            meta = self._claim_meta(client_id, scope_hash, work_unit_id, work_kind)
            os.lseek(fd, 0, os.SEEK_SET)
            os.ftruncate(fd, 0)
            os.write(fd, json.dumps(meta, separators=(",", ":")).encode())
            outcome = (
                ClaimOutcome.TAKEOVER if prior else ClaimOutcome.ACQUIRED
            )
            if outcome is ClaimOutcome.ACQUIRED:
                self._log("claim_acquired", client_id=client_id, work_unit_id=work_unit_id)
            return ClaimDecision(
                outcome,
                work_unit_id,
                client_id,
                holder_worker_id=self._worker_id,
                expires_at=meta["expires_at"],
            )
        except OSError as exc:
            self._log(
                "claim_error",
                client_id=client_id,
                work_unit_id=work_unit_id,
                detail=type(exc).__name__,
            )
            return ClaimDecision(
                ClaimOutcome.DENIED_ERROR,
                work_unit_id,
                client_id,
                note=f"ledger error: {type(exc).__name__}",
            )
        finally:
            with suppress(OSError):
                os.close(fd)

    def _claim_meta(
        self, client_id: str, scope_hash: str, work_unit_id: str, work_kind: str
    ) -> dict[str, Any]:
        now = time.time()
        return {
            "work_unit_id": work_unit_id,
            "work_kind": work_kind,
            "client_id": client_id,
            "scope_hash": scope_hash,
            "worker_id": self._worker_id,
            "pid": os.getpid(),
            "acquired_at": now,
            "expires_at": now + self._ttl,
        }

    def release_claim(self, client_id: str, work_unit_id: str, *, note: str = "") -> bool:
        """Release this worker's claim (best-effort; false if not held)."""
        import fcntl

        path = self._claim_path(client_id, work_unit_id)
        try:
            if not path.exists():
                return False
            fd = os.open(str(path), os.O_RDWR, 0o600)
        except OSError:
            return False
        try:
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except OSError:
                return False
            raw = os.read(fd, 4096)
            try:
                meta = json.loads(raw.decode("utf-8", "replace")) if raw.strip() else {}
            except ValueError:
                meta = {}
            if not isinstance(meta, dict) or meta.get("worker_id") not in (
                self._worker_id,
                None,
                "",
            ):
                return False  # someone else's claim — never release it
            os.lseek(fd, 0, os.SEEK_SET)
            os.ftruncate(fd, 0)
            with suppress(OSError):
                path.unlink()
            self._log(
                "claim_released",
                client_id=client_id,
                work_unit_id=work_unit_id,
                note=note,
            )
            return True
        except OSError:
            return False
        finally:
            with suppress(OSError):
                os.close(fd)

    def claim_status(self, client_id: str, work_unit_id: str) -> dict[str, Any] | None:
        """Read a claim's metadata (expired claims report ``expired=True``)."""
        try:
            raw = self._claim_path(client_id, work_unit_id).read_bytes()
        except OSError:
            return None
        try:
            meta = json.loads(raw.decode("utf-8", "replace"))
        except ValueError:
            return None
        if not isinstance(meta, dict):
            return None
        meta = dict(meta)
        meta["expired"] = float(meta.get("expires_at") or 0.0) <= time.time()
        return meta

    # ------------------------------------------------------------------
    # cross-worker result dedup (O_CREAT|O_EXCL — atomic first wins)
    # ------------------------------------------------------------------
    def register_result(
        self,
        client_id: str,
        scope_hash: str,
        fingerprint: str,
        *,
        finding_id: str = "",
        kind: str = "finding",
    ) -> DedupVerdict:
        """Register a result fingerprint; FIRST_SEEN wins, rest DUPLICATE.

        ``INDETERMINATE`` on ledger failure — callers must NOT silently
        suppress a result because coordination infrastructure failed
        (same fail-safe rule as the Track 11 dedup gate).
        """
        if not str(fingerprint or "").strip():
            return DedupVerdict.INDETERMINATE
        try:
            path = self._fingerprints_dir(client_id) / f"{_slug(fingerprint)}.json"
        except OSError as exc:
            self._log(
                "result_dedup_error",
                client_id=client_id,
                detail=type(exc).__name__,
            )
            return DedupVerdict.INDETERMINATE
        record = {
            "fingerprint": fingerprint,
            "kind": kind,
            "client_id": client_id,
            "scope_hash": scope_hash,
            "worker_id": self._worker_id,
            "finding_id": finding_id,
            "registered_at": time.time(),
        }
        try:
            fd = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        except FileExistsError:
            owner = ""
            try:
                raw = path.read_bytes()
                data = json.loads(raw.decode("utf-8", "replace"))
                if isinstance(data, dict):
                    owner = str(data.get("worker_id") or "")
            except (OSError, ValueError):
                pass
            self._log(
                "result_duplicate",
                client_id=client_id,
                fingerprint=fingerprint,
                first_owner=owner,
            )
            return DedupVerdict.DUPLICATE
        except OSError as exc:
            self._log(
                "result_dedup_error",
                client_id=client_id,
                detail=type(exc).__name__,
            )
            return DedupVerdict.INDETERMINATE
        try:
            os.write(fd, json.dumps(record, separators=(",", ":")).encode())
        finally:
            os.close(fd)
        self._log("result_first_seen", client_id=client_id, fingerprint=fingerprint)
        return DedupVerdict.FIRST_SEEN

    # ------------------------------------------------------------------
    # monitoring
    # ------------------------------------------------------------------
    def snapshot(self, client_id: str = "") -> dict[str, Any]:
        """Live view: active (non-expired) claims and fingerprint count.

        Scoped to one client when given; otherwise aggregate counts only
        (never cross-client record contents).
        """
        now = time.time()
        clients_root = self._root / "clients"
        active_claims = 0
        total_claims = 0
        fingerprints = 0
        active_records: list[dict[str, Any]] = []
        if client_id:
            dirs: list[Path] = [self._client_dir(client_id)]
        elif clients_root.exists():
            dirs = [p for p in clients_root.iterdir() if p.is_dir()]
        else:
            dirs = []
        for cdir in dirs:
            claims_dir = cdir / "claims"
            if claims_dir.exists():
                for path in claims_dir.glob("*.json"):
                    total_claims += 1
                    try:
                        meta = json.loads(path.read_text(encoding="utf-8"))
                    except (OSError, ValueError):
                        continue
                    if not isinstance(meta, dict):
                        continue
                    if float(meta.get("expires_at") or 0.0) > now:
                        active_claims += 1
                        if client_id:
                            active_records.append(
                                {
                                    "work_unit_id": meta.get("work_unit_id"),
                                    "worker_id": meta.get("worker_id"),
                                    "expires_at": meta.get("expires_at"),
                                }
                            )
            fp_dir = cdir / "fingerprints"
            if fp_dir.exists():
                fingerprints += sum(1 for _ in fp_dir.glob("*.json"))
        snapshot: dict[str, Any] = {
            "worker_id": self._worker_id,
            "coord_dir": str(self._root),
            "claim_ttl_seconds": self._ttl,
            "active_claims": active_claims,
            "total_claim_files": total_claims,
            "registered_fingerprints": fingerprints,
        }
        if client_id:
            snapshot["active_claim_records"] = active_records
        return snapshot
