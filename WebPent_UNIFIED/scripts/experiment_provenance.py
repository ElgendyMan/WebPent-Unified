#!/usr/bin/env python3
"""UM-DR-32 §3.2 — experiment provenance contract.

The UM-DR-31 ablation artifact recorded a single ambiguous ``git_head``
obtained via ``git rev-parse HEAD`` while the results were actually
produced by a (possibly dirty) working tree, and the artifact was later
committed at a DIFFERENT commit — three distinct identities collapsed
into one field. This module enforces the corrected contract:

  source_provenance / capture_source_provenance()
      exact source commit, tree SHA, branch, dirty status, and — only
      when dirty execution is EXPLICITLY permitted — the sha256 of the
      working-tree diff. Default behavior REJECTS a dirty tree for
      release-grade measurement (fail-closed).

  artifact_provenance / capture_artifact_provenance()
      the record every experiment artifact must carry: source identity,
      generator-script revision, fixture content hash, exact command,
      python version, dependency-lock identity, UTC start/completion
      timestamps, request budget, requests actually issued, and the
      ground-truth manifest identity.

A report generated from modified-but-uncommitted files can no longer
claim the committed HEAD alone represents the tested source.
"""
from __future__ import annotations

import datetime as _dt
import hashlib
import json
import subprocess
import sys
from pathlib import Path
from typing import Any


def _git(repo: Path, *args: str) -> str:
    out = subprocess.run(
        ["git", *args], cwd=repo, capture_output=True, text=True, timeout=30,
    )
    return out.stdout.strip() if out.returncode == 0 else ""


def _file_sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def capture_source_provenance(
    repo: Path, *, allow_dirty: bool = False,
) -> dict[str, Any]:
    """Exact source identity for a measurement run.

    Raises SystemExit when the tree is dirty and allow_dirty is False
    (release-grade default: reject).
    """
    head = _git(repo, "rev-parse", "HEAD")
    if not head:
        raise SystemExit(
            "ABORT: no git HEAD — release-grade measurements require a "
            "committed source revision"
        )
    dirty = bool(_git(repo, "status", "--porcelain"))
    record: dict[str, Any] = {
        "source_commit": head,
        "source_tree_sha": _git(repo, "rev-parse", "HEAD^{tree}"),
        "branch": _git(repo, "rev-parse", "--abbrev-ref", "HEAD"),
        "dirty_tree": dirty,
    }
    if dirty:
        if not allow_dirty:
            raise SystemExit(
                "ABORT: dirty working tree — commit or stash before "
                "release-grade measurement (or pass --allow-dirty to "
                "record an explicitly-dirty engineering run; the artifact "
                "will then carry the source-diff hash and can never be "
                "confused with a clean-release result)"
            )
        diff = subprocess.run(
            ["git", "diff", "HEAD"], cwd=repo,
            capture_output=True, timeout=60,
        ).stdout
        record["source_diff_sha256"] = hashlib.sha256(diff).hexdigest()
        record["dirty_execution"] = "explicitly_permitted"
    return record


def capture_artifact_provenance(
    repo: Path,
    *,
    generator_script: Path,
    fixture_files: list[Path] | None = None,
    lock_file: Path | None = None,
    command: list[str] | None = None,
    started_utc: str | None = None,
    completed_utc: str | None = None,
    request_budget: int | None = None,
    requests_issued: int | None = None,
    ground_truth_manifest: Any = None,
    allow_dirty: bool = False,
) -> dict[str, Any]:
    """The full provenance block every experiment artifact must carry."""
    record: dict[str, Any] = {
        "provenance_contract": "UM-DR-32 §3.2 (v1)",
        "source": capture_source_provenance(repo, allow_dirty=allow_dirty),
        "generator_script": generator_script.name,
        "generator_revision_sha256": _file_sha256(generator_script),
        "python_version": sys.version.split()[0],
        "python_executable": sys.executable,
    }
    if fixture_files:
        record["fixtures"] = [
            {"path": f.relative_to(repo).as_posix()
             if f.is_relative_to(repo) else f.name,
             "content_sha256": _file_sha256(f)}
            for f in fixture_files
        ]
    if lock_file is not None and lock_file.exists():
        record["dependency_lock"] = {
            "path": lock_file.name,
            "sha256": _file_sha256(lock_file),
        }
    record["command"] = command or list(sys.argv)
    record["started_utc"] = started_utc or _dt.datetime.now(
        _dt.timezone.utc).isoformat()
    record["completed_utc"] = completed_utc or _dt.datetime.now(
        _dt.timezone.utc).isoformat()
    if request_budget is not None:
        record["request_budget"] = request_budget
    if requests_issued is not None:
        record["requests_issued"] = requests_issued
    if ground_truth_manifest is not None:
        # UM-DR-33 §3.6: single canonical JSON identity contract
        # (webpent.shared.canonical_json). Import is deferred so the
        # module docstring stays accurate for callers that only need
        # source provenance; the repository's generator scripts always
        # put src/ on sys.path before importing this module.
        try:
            from webpent.shared.canonical_json import (  # noqa: PLC0415
                CANONICAL_JSON_CONTRACT_ID,
                canonical_json_sha256,
            )
        except ImportError as exc:  # pragma: no cover - explicit contract
            raise RuntimeError(
                "capture_artifact_provenance(ground_truth_manifest=...) "
                "requires src/ on sys.path: the canonical JSON contract "
                "lives in webpent.shared.canonical_json (UM-DR-33 §3.6)"
            ) from exc
        record["ground_truth_manifest"] = {
            "identity": canonical_json_sha256(ground_truth_manifest),
            "contract": CANONICAL_JSON_CONTRACT_ID,
        }
    return record
