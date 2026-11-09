"""Capture a deterministic, report-safe VIP baseline for a WebPent release.

The script does not contact targets and does not execute security probes. It records
only local project metadata, test-function count, and the declarative WAPTLab campaign
ledger. Any campaign without executor evidence remains ``not_observed`` or
``missing-validator``; the output never promotes inventory into a finding.
"""

from __future__ import annotations

import hashlib
import json
import platform
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from webpent.benchmark.waptlab_campaign_profile import (
    build_waptlab_campaign_ledger,
)

PROJECT_ROOT = Path(__file__).resolve().parents[1]
OUTPUT_PATH = PROJECT_ROOT / "docs" / "vip_baseline.json"


def _sha256(path: Path) -> str | None:
    if not path.is_file():
        return None
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _version(command: list[str]) -> str | None:
    try:
        completed = subprocess.run(
            command,
            cwd=PROJECT_ROOT,
            check=True,
            capture_output=True,
            text=True,
            timeout=10,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    return completed.stdout.strip().splitlines()[0] if completed.stdout.strip() else None


def _test_function_count() -> int | None:
    verifier = PROJECT_ROOT / "scripts" / "verify_test_count.py"
    if not verifier.is_file():
        return None
    try:
        completed = subprocess.run(
            [sys.executable, str(verifier)],
            cwd=PROJECT_ROOT,
            check=True,
            capture_output=True,
            text=True,
            timeout=120,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    json_output, _separator, _status_line = completed.stdout.partition("\nOK:")
    try:
        payload = json.loads(json_output)
    except json.JSONDecodeError:
        return None
    value = payload.get("pytest_collected_count", payload.get("total_test_functions"))
    return int(value) if isinstance(value, int) else None


def capture() -> dict[str, Any]:
    root_files = {name: _sha256(PROJECT_ROOT / name) for name in ("pyproject.toml", "uv.lock")}
    return {
        "schema_version": "vip-baseline-v1",
        "captured_at": datetime.now(timezone.utc).isoformat(),
        "project": "WebPent v60",
        "project_root": str(PROJECT_ROOT),
        "python": sys.version.split()[0],
        "platform": platform.platform(),
        "pytest": _version([sys.executable, "-m", "pytest", "--version"]),
        "ruff": _version([str(PROJECT_ROOT / ".venv" / "bin" / "ruff"), "--version"]),
        "test_function_count": _test_function_count(),
        "root_file_sha256": root_files,
        "waptlab_fixture": {
            "available": False,
            "reason": (
                "No local WAPTLab fixture directory is present; no remote target was contacted."
            ),
        },
        "campaign_ledger": build_waptlab_campaign_ledger(),
        "safety_statement": (
            "This baseline is inventory/evidence accounting only. It does not claim that "
            "unobserved campaigns are negative or confirmed."
        ),
    }


def main() -> int:
    payload = capture()
    OUTPUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT_PATH.write_text(
        json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    print(OUTPUT_PATH)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
