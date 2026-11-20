"""Build a reproducible release manifest without treating a checksum as a signature."""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

PROJECT_ROOT = Path(__file__).resolve().parents[1]
OUTPUT = PROJECT_ROOT / "docs" / "release_manifest.json"
# R-03/R-09 (TEAM-2 residuals): the manifest must describe the tracked
# source tree — not run artifacts, sandbox caches, or nested snapshot
# material. A manifest that hashes ``webpent.db`` / ``memory/global/*``
# (a) certifies files that a fresh checkout neither needs nor should
# receive, and (b) changes on every test run, defeating reproducibility.
EXCLUDED_PARTS = {
    ".git", ".venv", "__pycache__", ".pytest_cache", ".ruff_cache",
    ".mypy_cache", ".idea", ".vscode", "node_modules",
    # Runtime artifacts (rebuilt per run / via scripts/ingest_payloads.py).
    "memory", "output", "chroma_db",
    # Nested historical snapshot directories shipped with the audit archive.
    "goed_v1_8", "goed_v1_8_1", "goed_v1_8_2", "goed_v1_8_3", "goed_v1_8_4",
}
EXCLUDED_NAMES = {
    ".env", "webpent.db", "action_ledger.db", ".coverage",
    "webpent.db-wal", "webpent.db-shm", "webpent.db.migration.lock",
}
EXCLUDED_SUFFIXES = {".pyc", ".pyo", ".db", ".db-wal", ".db-shm", ".log"}


def _tracked_commit() -> str | None:
    try:
        result = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=PROJECT_ROOT,
            capture_output=True,
            text=True,
            check=False,
        )
    except OSError:
        return None
    return result.stdout.strip() if result.returncode == 0 else None


def _included(path: Path) -> bool:
    relative = path.relative_to(PROJECT_ROOT)
    if any(part in EXCLUDED_PARTS for part in relative.parts):
        return False
    if path.name in EXCLUDED_NAMES or path.suffix in EXCLUDED_SUFFIXES:
        return False
    if path.name.endswith(".zip"):
        return False
    return path.is_file()


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _artifact_hashes() -> dict[str, str]:
    artifacts = [
        "docs/vip_quality_gate.json",
        "docs/waptlab_regression.json",
        "docs/waptlab_coverage_ledger.json",
        "docs/waptlab_mock_reproducibility.json",
        "docs/bandit_release.json",
        "docs/pip_audit_release.json",
        "docs/sbom.cdx.json",
    ]
    return {
        relative: _sha256(PROJECT_ROOT / relative)
        for relative in artifacts
        if (PROJECT_ROOT / relative).is_file()
    }


def _qualification() -> dict[str, Any]:
    path = PROJECT_ROOT / "docs" / "waptlab_regression.json"
    if not path.is_file():
        return {
            "live_qualification": False,
            "target_contacted": None,
            "waptlab_modified": None,
            "status": "missing_artifact",
        }
    payload = json.loads(path.read_text(encoding="utf-8"))
    return {
        "live_qualification": bool(payload.get("live_qualification", False)),
        "target_contacted": payload.get("target_contacted"),
        "waptlab_modified": payload.get("waptlab_modified"),
        "campaign_count": payload.get("campaign_count"),
        "summary": payload.get("summary", {}),
        "status": "live" if payload.get("live_qualification") else "contract_only",
    }


def _security_status() -> dict[str, Any]:
    path = PROJECT_ROOT / "docs" / "vip_quality_gate.json"
    if not path.is_file():
        return {"gate_present": False, "gate_passed": False}
    payload = json.loads(path.read_text(encoding="utf-8"))
    return {
        "gate_present": True,
        "gate_passed": bool(payload.get("passed", False)),
        "schema_version": payload.get("schema_version"),
        "known_blockers": payload.get("known_blockers", []),
        "checks": {
            item.get("name", "unknown"): bool(item.get("passed", False))
            for item in payload.get("checks", [])
        },
    }


def _signature_status() -> dict[str, Any]:
    """Sign only when an explicit private key is supplied by the release operator."""
    key_path = os.environ.get("WEBPENT_SIGNING_KEY")
    if not key_path:
        return {
            "status": "not_configured",
            "algorithm": None,
            "signature_path": None,
            "note": "A SHA-256 manifest is integrity evidence, not a cryptographic signature.",
        }
    return {
        "status": "operator_required",
        "algorithm": "external-signing-key",
        "signature_path": None,
        "key_path_present": bool(Path(key_path).is_file()),
        "note": "The release must be signed by the operator outside this sandbox.",
    }


def main() -> int:
    files = sorted(
        {
            str(path.relative_to(PROJECT_ROOT)): _sha256(path)
            for path in PROJECT_ROOT.rglob("*")
            if _included(path) and path != OUTPUT
        }.items()
    )
    payload = {
        "schema_version": "webpent-release-manifest-v1",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "project": "WebPent",
        "git_commit": _tracked_commit(),
        "file_count": len(files),
        "files": dict(files),
        "artifact_hashes": _artifact_hashes(),
        "qualification": _qualification(),
        "security": _security_status(),
        "signature": _signature_status(),
        "release_decision": "blocked" if not _security_status()["gate_passed"] else "candidate",
    }
    OUTPUT.write_text(
        json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    print(json.dumps({"output": str(OUTPUT), "file_count": len(files)}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
