"""WebPent Milestone 5 — fixture quarantine content store + operator admission path.

Remediation (Team-Red audit):
  D5  — approved_target_origins passed to the loopback/foreign-origin scanner.
  D12 — quarantine_path recovered from manifest on restart (was None).
  D14 — source_type derived from content; operator declaration mismatch rejects.
"""
from __future__ import annotations

import json
import os
import tempfile
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Optional

from .fixture_registry import (
    DECLARED_NON_PROOF, MAX_SOURCE_BYTES, REASON_BUDGET, REASON_CATCHER_UNKNOWN,
    REASON_DUPLICATE_BINDING, REASON_FOREIGN_ORIGIN, REASON_LOOPBACK,
    REASON_OVERSIZE, REASON_RESCAN_UNCLEAN, REASON_SECRET_AMBIGUOUS,
    REASON_SECRET_LIVE, REASON_UNKNOWN_SOURCE, REASON_WINDOW,
    SOURCE_RESERVED_CATCHER, SOURCE_STATIC_HAR, SOURCE_STATIC_JSON,
    FixtureManifestChain, content_digest, detect_source_type, mint_fixture_id,
    scan_fixture_bytes,
)

MAX_FIXTURES_PER_ENGAGEMENT = int(os.environ.get("WEBPENT_MAX_FIXTURES_PER_ENGAGEMENT", "100"))
assert 1 <= MAX_FIXTURES_PER_ENGAGEMENT <= 1000, "M5 OQ-5.3: 1-1000 only"
MAX_FIXTURE_TOTAL_BYTES = int(os.environ.get("WEBPENT_MAX_FIXTURE_TOTAL_BYTES", str(1610612736)))
STALENESS_CAP_SECONDS = int(os.environ.get("WEBPENT_FIXTURE_STALENESS_CAP_HOURS", "72")) * 3600
QUARANTINE_MODE = 0o440  # M5 FIX-9


@dataclass
class AdmissionResult:
    admitted: bool
    fixture_id: Optional[str] = None
    content_digest: Optional[str] = None
    quarantine_path: Optional[str] = None
    manifest_event: Optional[dict[str, Any]] = None
    rejection_reason: Optional[str] = None
    rejection_detail: Optional[str] = None
    duplicate_of: Optional[str] = None
    stale: bool = False
    secret_scan_result: Optional[dict[str, Any]] = None
    source_type: Optional[str] = None

    def value_free_record(self) -> dict[str, Any]:
        return {
            "admitted": self.admitted, "fixture_id": self.fixture_id,
            "content_digest": self.content_digest, "source_type": self.source_type,
            "rejection_reason": self.rejection_reason, "duplicate_of": self.duplicate_of,
            "stale": self.stale, "secret_scan_result": self.secret_scan_result,
            "engagement_instance_id": None, "target_fingerprint": None,
        }


class CorruptionAlarm(Exception):
    pass


class FixtureStore:
    def __init__(
        self, workspace: str, engagement_id: str, engagement_instance_id: str,
        target_fingerprint: str, engagement_window_start: Optional[datetime] = None,
        engagement_window_end: Optional[datetime] = None,
        fixture_readers_gid: Optional[int] = None,
        approved_target_origins: Optional[frozenset] = None,
    ):
        self.workspace = workspace
        self.engagement_id = engagement_id
        self.engagement_instance_id = engagement_instance_id
        self.target_fingerprint = target_fingerprint
        self.window_start = engagement_window_start
        self.window_end = engagement_window_end
        self.fixture_readers_gid = fixture_readers_gid
        self.approved_origins = approved_target_origins  # None = skip foreign-origin check
        self.incoming_dir = os.path.join(workspace, "fixtures", "incoming")
        self.quarantine_dir = os.path.join(workspace, "fixtures", "quarantine")
        self.manifest_path = os.path.join(workspace, "fixtures", "fixture_manifest.jsonl")
        os.makedirs(self.incoming_dir, exist_ok=True)
        os.makedirs(self.quarantine_dir, exist_ok=True)
        self.manifest = FixtureManifestChain(self.manifest_path)
        self._known_digests: dict[str, dict[str, Any]] = {}
        self._total_bytes = 0
        self._fixture_count = 0
        self._recover_registry()

    def _recover_registry(self) -> None:
        if not os.path.exists(self.manifest_path):
            return
        with open(self.manifest_path, "r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                evt = json.loads(line)
                payload = evt.get("payload", {})
                meta = payload.get("admission_metadata", {})
                if payload.get("content_digest") and meta.get("status") == "admitted":
                    # D12 FIX: recover quarantine_path too.
                    self._known_digests[payload["content_digest"]] = {
                        "fixture_id": payload.get("fixture_id"),
                        "target_fingerprint": payload.get("target_fingerprint"),
                        "engagement_instance_id": payload.get("engagement_instance_id"),
                        "byte_size": meta.get("byte_size", 0),
                        "quarantine_path": meta.get("quarantine_path"),
                    }
                    self._fixture_count += 1
                    self._total_bytes += meta.get("byte_size", 0)

    def admit_incoming(
        self, filename: str, declared_source_type: Optional[str] = None,
        capture_timestamp: Optional[datetime] = None, capturer_tool: str = "unknown",
        capturer_version: str = "unknown", lab_session_authorization_ref: str = "",
        operator_alias: str = "",
    ) -> AdmissionResult:
        src = os.path.join(self.incoming_dir, filename)
        if not os.path.isfile(src):
            return AdmissionResult(False, rejection_reason="fixture_file_not_found")

        size = os.path.getsize(src)
        if size > MAX_SOURCE_BYTES:
            return AdmissionResult(False, rejection_reason=REASON_OVERSIZE,
                                   rejection_detail=f"{size} > {MAX_SOURCE_BYTES}")
        if self._fixture_count + 1 > MAX_FIXTURES_PER_ENGAGEMENT:
            return AdmissionResult(False, rejection_reason=REASON_BUDGET,
                                   rejection_detail="max_fixtures_per_engagement")
        if self._total_bytes + size > MAX_FIXTURE_TOTAL_BYTES:
            return AdmissionResult(False, rejection_reason=REASON_BUDGET,
                                   rejection_detail="max_fixture_total_bytes")

        with open(src, "rb") as fh:
            raw = fh.read()

        # D14 FIX: source_type derived from content; catcher RESERVED hard-rejects.
        derived = detect_source_type(raw)
        if declared_source_type == SOURCE_RESERVED_CATCHER or derived == SOURCE_RESERVED_CATCHER:
            return AdmissionResult(False, rejection_reason=REASON_CATCHER_UNKNOWN)
        if derived is None:
            return AdmissionResult(False, rejection_reason=REASON_UNKNOWN_SOURCE,
                                   rejection_detail="unparseable")
        if declared_source_type and declared_source_type != derived:
            return AdmissionResult(False, rejection_reason=REASON_UNKNOWN_SOURCE,
                                   rejection_detail=f"declared={declared_source_type} derived={derived}")
        source_type = derived

        # D5: scan with approved_origins for loopback/foreign-origin check.
        scan = scan_fixture_bytes(raw, approved_origins=self.approved_origins)
        scan_summary = scan.value_free_summary()
        if not scan.clean:
            return AdmissionResult(False, rejection_reason=scan.disposition,
                                   secret_scan_result=scan_summary, source_type=source_type)
        rescan = scan_fixture_bytes(raw, approved_origins=self.approved_origins)
        if not rescan.clean:
            return AdmissionResult(False, rejection_reason=REASON_RESCAN_UNCLEAN,
                                   secret_scan_result=rescan.value_free_summary())

        digest = content_digest(raw)
        digest_hex = digest.split(":", 1)[1]
        fixture_id = mint_fixture_id(digest_hex)

        if digest in self._known_digests:
            prior = self._known_digests[digest]
            if (prior["target_fingerprint"] != self.target_fingerprint
                    or prior["engagement_instance_id"] != self.engagement_instance_id):
                return AdmissionResult(False, rejection_reason=REASON_DUPLICATE_BINDING,
                                       source_type=source_type)
            evt = self.manifest.append_event({
                "fixture_id": fixture_id, "content_digest": digest, "source_type": source_type,
                "engagement_id": self.engagement_id,
                "engagement_instance_id": self.engagement_instance_id,
                "target_fingerprint": self.target_fingerprint,
                "declared_non_proof": DECLARED_NON_PROOF, "secret_scan_result": scan_summary,
                "admission_metadata": {"status": "duplicate_reference",
                                       "duplicate_of": prior["fixture_id"]},
            })
            return AdmissionResult(True, fixture_id=fixture_id, content_digest=digest,
                                   quarantine_path=prior.get("quarantine_path"),
                                   manifest_event=evt, duplicate_of=prior["fixture_id"],
                                   secret_scan_result=scan_summary, source_type=source_type)

        stale = False
        if capture_timestamp is not None:
            if self.window_end and capture_timestamp > self.window_end:
                return AdmissionResult(False, rejection_reason=REASON_WINDOW,
                                       rejection_detail="after_window_end")
            if self.window_start and capture_timestamp < self.window_start:
                return AdmissionResult(False, rejection_reason=REASON_WINDOW,
                                       rejection_detail="before_window_start")
            stale = (datetime.now(timezone.utc) - capture_timestamp).total_seconds() > STALENESS_CAP_SECONDS

        qdir = os.path.join(self.quarantine_dir, digest_hex[:2])
        os.makedirs(qdir, exist_ok=True)
        qpath = os.path.join(qdir, digest_hex[2:])
        if not os.path.exists(qpath):
            fd, tmp = tempfile.mkstemp(dir=qdir)
            try:
                os.write(fd, raw)
                os.fsync(fd)
                os.fchmod(fd, QUARANTINE_MODE)
                if self.fixture_readers_gid is not None:
                    try:
                        os.fchown(fd, -1, self.fixture_readers_gid)
                    except (PermissionError, OSError):
                        pass
            finally:
                os.close(fd)
            os.replace(tmp, qpath)
        else:
            try:
                os.chmod(qpath, QUARANTINE_MODE)
            except OSError:
                pass

        redaction_manifest = {"values_retained": False,
                              "categories": scan_summary["categories"],
                              "counts": {c: sum(f["count"] for f in scan_summary["findings"]
                                                if f["category"] == c)
                                         for c in scan_summary["categories"]}}
        evt = self.manifest.append_event({
            "manifest_schema_version": 1, "fixture_id": fixture_id, "content_digest": digest,
            "source_type": source_type, "engagement_id": self.engagement_id,
            "engagement_instance_id": self.engagement_instance_id,
            "target_fingerprint": self.target_fingerprint,
            "capture_timestamp": capture_timestamp.isoformat() if capture_timestamp else None,
            "capture_context": {"capturer_tool": capturer_tool, "capturer_version": capturer_version,
                                "lab_session_authorization_ref": lab_session_authorization_ref,
                                "operator_alias": operator_alias},
            "declared_non_proof": DECLARED_NON_PROOF, "secret_scan_result": scan_summary,
            "redaction_manifest": redaction_manifest,
            "fixture_format_version": "har/v1.2" if source_type == SOURCE_STATIC_HAR else "static_json/v1",
            "staleness_bound": {"stale": stale, "cap_seconds": STALENESS_CAP_SECONDS},
            "admission_metadata": {"status": "admitted", "byte_size": size, "quarantine_path": qpath},
        })
        self._known_digests[digest] = {"fixture_id": fixture_id,
                                       "target_fingerprint": self.target_fingerprint,
                                       "engagement_instance_id": self.engagement_instance_id,
                                       "byte_size": size, "quarantine_path": qpath}
        self._fixture_count += 1
        self._total_bytes += size
        return AdmissionResult(True, fixture_id=fixture_id, content_digest=digest,
                               quarantine_path=qpath, manifest_event=evt, stale=stale,
                               secret_scan_result=scan_summary, source_type=source_type)

    def read_quarantined_bytes(self, digest: str) -> bytes:
        digest_hex = digest.split(":", 1)[1] if digest.startswith("sha256:") else digest
        qpath = os.path.join(self.quarantine_dir, digest_hex[:2], digest_hex[2:])
        with open(qpath, "rb") as fh:
            raw = fh.read()
        if content_digest(raw) != ("sha256:" + digest_hex):
            raise CorruptionAlarm(f"quarantine digest mismatch for {digest_hex[:12]}")
        return raw
