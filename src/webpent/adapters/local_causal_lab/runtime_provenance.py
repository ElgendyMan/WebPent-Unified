"""Immutable local runtime/source provenance for the Option B readiness gate.

The values in this module are target-local evidence pins.  They do not authorize
network execution, authentication, state mutation, or scoring promotion.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from hashlib import sha256
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class RuntimeProvenance:
    target_id: str
    source_revision: str
    source_files: tuple[tuple[str, str, str], ...]
    runtime_digest_status: str
    runtime_digest: str | None
    toolchain_digest: str | None = None
    service_alignment_status: str = "not_attested"
    image_digests: tuple[tuple[str, str], ...] = ()

    def validate(self) -> tuple[str, ...]:
        errors: list[str] = []
        if len(self.source_revision) != 40:
            errors.append("source_revision_must_be_git_sha1")
        if not self.source_files:
            errors.append("source_files_required")
        for name, path, digest in self.source_files:
            if not name or not path or len(digest) != 64:
                errors.append("source_file_pin_invalid")
        if self.runtime_digest_status == "pinned":
            if not self.runtime_digest or len(self.runtime_digest) != 64:
                errors.append("pinned_runtime_digest_required")
        elif self.runtime_digest is not None:
            errors.append("runtime_digest_must_be_empty_when_unpinned")
        if self.toolchain_digest is not None and len(self.toolchain_digest) != 64:
            errors.append("toolchain_digest_must_be_sha256")
        if self.service_alignment_status not in {"attested", "not_attested"}:
            errors.append("service_alignment_status_invalid")
        for image, digest in self.image_digests:
            if not image or not digest.startswith("sha256:") or len(digest) != 71:
                errors.append("image_digest_pin_invalid")
        return tuple(errors)

    def as_dict(self) -> dict[str, Any]:
        return {
            "target_id": self.target_id,
            "source_revision": self.source_revision,
            "source_files": [
                {"name": name, "path": path, "sha256": digest}
                for name, path, digest in self.source_files
            ],
            "runtime_digest_status": self.runtime_digest_status,
            "runtime_digest": self.runtime_digest,
            "toolchain_digest": self.toolchain_digest,
            "service_alignment_status": self.service_alignment_status,
            "image_digests": [
                {"image": image, "repo_digest": digest}
                for image, digest in self.image_digests
            ],
        }

    def manifest_hash(self) -> str:
        payload = json.dumps(self.as_dict(), sort_keys=True, separators=(",", ":"))
        return sha256(payload.encode("utf-8")).hexdigest()


def source_digest_check(
    provenance: RuntimeProvenance, source_root: Path
) -> dict[str, Any]:
    entries: list[dict[str, Any]] = []
    for name, relative_path, expected in provenance.source_files:
        path = source_root / relative_path
        try:
            actual = sha256(path.read_bytes()).hexdigest()
        except OSError:
            actual = None
        entries.append(
            {
                "name": name,
                "path": relative_path,
                "expected_sha256": expected,
                "actual_sha256": actual,
                "matches": actual == expected,
            }
        )
    return {
        "source_revision": provenance.source_revision,
        "files": entries,
        "all_match": bool(entries) and all(item["matches"] for item in entries),
    }


def readiness_check(
    provenance: RuntimeProvenance, source_root: Path
) -> dict[str, Any]:
    source = source_digest_check(provenance, source_root)
    errors = list(provenance.validate())
    if not source["all_match"]:
        errors.append("source_digest_drift")
    if provenance.runtime_digest_status != "pinned":
        errors.append("runtime_digest_not_pinned")
    if provenance.service_alignment_status != "attested":
        errors.append("service_artifact_alignment_not_attested")
    return {
        "status": "ready" if not errors else "blocked",
        "target_id": provenance.target_id,
        "provenance_manifest_hash": provenance.manifest_hash(),
        "source": source,
        "runtime_digest_status": provenance.runtime_digest_status,
        "runtime_digest": provenance.runtime_digest,
        "service_alignment_status": provenance.service_alignment_status,
        "errors": errors,
    }
