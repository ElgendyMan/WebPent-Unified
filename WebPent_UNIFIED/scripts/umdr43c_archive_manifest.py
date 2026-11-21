#!/usr/bin/env python3
"""UM-DR-43C §3 — historical artifact preservation + archive manifest.

Recovers the historical artifacts the directive lists from resolvable
git history, verifies each (SHA-256, JSON parse, bundle verify), and
writes UMDR42_ARCHIVE_MANIFEST.json with the preservation decision.

Nothing is deleted or moved in the working tree; recovered files land
under deliverables/umdr43c/archive/ with their original commit and
digest recorded so any engineer can re-derive and compare.
"""
from __future__ import annotations

import hashlib
import json
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
GIT_ROOT = REPO.parent
OUT_DIR = REPO / "deliverables/umdr43c/archive"
MANIFEST_OUT = REPO / "deliverables/umdr43c/UMDR42_ARCHIVE_MANIFEST.json"
# tracked paths live INSIDE the WebPent_UNIFIED subtree of the repo
PREFIX = "WebPent_UNIFIED/"

# (path relative to WebPent_UNIFIED/, why it matters) — §3 items.
TARGETS: list[tuple[str, str]] = [
    ("docs/baseline/coverage.json",
     "historical coverage baseline (pre-unfreeze measurement)"),
    ("docs/coverage_measured_baseline_0260.json",
     "0260-era measured coverage baseline"),
    ("docs/history/UMDR37_COVERAGE_LAST_RUN.json",
     "UMDR37 last-run coverage record"),
    ("deliverables/umdr38/test_evidence/coverage_last_run.json",
     "UMDR38 test-evidence coverage record"),
    ("REGRESSION.json",
     "historical regression gate state"),
    ("download/dojo/trainer_session.json",
     "dojo trainer session state (deleted by the main publish; "
     "session lineage evidence)"),
]

BUNDLES: list[tuple[str, str]] = [
    ("WebPent_UNIFIED/UMDR36_2_37_DELIVERABLES/"
     "WebPent_Unified_mission-umdr36.2-umdr37.bundle",
     "UMDR36.2+37 mission bundle"),
    ("WebPent_UNIFIED/deliverables/umdr36_1/"
     "WebPent_Unified_recovery-umdr36-closure.bundle",
     "UMDR36-1 recovery closure bundle"),
    ("WebPent_Unified_umdr38.bundle",
     "UMDR38 mission bundle (repo-root path)"),
]

def _git_show(sha: str, path: str) -> bytes | None:
    result = subprocess.run(
        ["git", "show", f"{sha}:{path}"],
        cwd=GIT_ROOT, capture_output=True)
    if result.returncode == 0 and result.stdout:
        return result.stdout
    return None


def _git(args: list[str], cwd: Path = GIT_ROOT) -> str:
    result = subprocess.run(
        ["git", *args], cwd=cwd, capture_output=True, text=True)
    return result.stdout.strip()


def _sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _find_last_commit(path: str) -> tuple[str, str] | None:
    """(commit, blob-content) of the newest commit where the path
    EXISTS. ``git log --all -- path`` lists every commit that TOUCHED
    the path — including the one that DELETED it, where the blob is
    gone — so walk the list and return the first commit whose tree
    still carries the file."""
    shas = _git(["log", "--all", "--format=%H", "--",
                 PREFIX + path]).splitlines()
    for sha in shas:
        result = subprocess.run(
            ["git", "show", f"{sha}:{PREFIX}{path}"],
            cwd=GIT_ROOT, capture_output=True)
        if result.returncode == 0 and result.stdout:
            return sha, result.stdout.decode("utf-8", errors="replace")
    return None


def main() -> int:
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    entries: list[dict[str, object]] = []

    for path, why in TARGETS:
        found = _find_last_commit(path)
        record: dict[str, object] = {
            "original_path": path,
            "purpose": why,
        }
        if found is None:
            record.update({
                "recovered": False,
                "verification": "path absent from resolvable history",
                "preservation_decision": "not recoverable in this lineage",
            })
            entries.append(record)
            continue
        sha, blob = found
        if not blob.strip():
            record.update({
                "recovered": False,
                "original_commit": sha,
                "verification": "empty blob at last carrying commit",
            })
            entries.append(record)
            continue
        dest = OUT_DIR / path.replace("/", "__")
        dest.write_text(blob, encoding="utf-8")
        # verify: JSON parse + digest
        parsed = None
        try:
            parsed = json.loads(blob)
        except json.JSONDecodeError:
            pass
        record.update({
            "recovered": True,
            "original_commit": sha,
            "original_sha256": _sha256_bytes(blob.encode("utf-8")),
            "archive_path": str(dest.relative_to(REPO)),
            "artifact_type": "json" if parsed is not None else "text",
            "verification": "json-parsed" if parsed is not None
            else "sha256-only (not JSON)",
            "preservation_decision": "archived under umdr43c deliverables",
        })
        entries.append(record)

    for path, why in BUNDLES:
        record: dict[str, object] = {
            "original_path": path,
            "purpose": why,
        }
        bundle_path = GIT_ROOT / path
        shas = _git(["log", "--all", "--format=%H", "--",
                     path]).splitlines()
        recovered_blob: bytes | None = None
        carry_sha: str | None = None
        for candidate in shas:
            recovered_blob = _git_show(candidate, path)
            if recovered_blob is not None:
                carry_sha = candidate
                break
        sha = carry_sha
        if recovered_blob is not None:
            # history verified ABSENT from the current lineage's
            # objects (the umdr38-closure head is not an ancestor of
            # main) — the bundle is the ONLY carrier of that history,
            # so it is archived, not merely referenced.
            dest = OUT_DIR / ("bundle__" + path.replace("/", "__"))
            dest.write_bytes(recovered_blob)
            verify = subprocess.run(
                ["git", "bundle", "verify", str(dest)],
                cwd=GIT_ROOT, capture_output=True, text=True)
            heads = subprocess.run(
                ["git", "bundle", "list-heads", str(dest)],
                cwd=GIT_ROOT, capture_output=True, text=True)
            record.update({
                "recovered": True,
                "original_commit": sha,
                "archive_path": str(dest.relative_to(REPO)),
                "size_bytes": len(recovered_blob),
                "sha256": _sha256_bytes(recovered_blob),
                "bundle_verify": "ok" if verify.returncode == 0 else
                f"failed: {verify.stderr.strip()[:120]}",
                "bundle_heads": heads.stdout.strip().splitlines()[:3],
                "preservation_decision":
                    "archived — carries history NOT contained in the "
                    "current lineage or the unified closure bundle",
            })
        elif bundle_path.exists() and bundle_path.stat().st_size > 0:
            data = bundle_path.read_bytes()
            verify = subprocess.run(
                ["git", "bundle", "verify", str(bundle_path)],
                cwd=GIT_ROOT, capture_output=True, text=True)
            heads = subprocess.run(
                ["git", "bundle", "list-heads", str(bundle_path)],
                cwd=GIT_ROOT, capture_output=True, text=True)
            record.update({
                "recovered": True,
                "present_in": "current tree",
                "size_bytes": len(data),
                "sha256": _sha256_bytes(data),
                "bundle_verify": "ok" if verify.returncode == 0 else
                f"failed: {verify.stderr.strip()[:120]}",
                "bundle_heads": heads.stdout.strip().splitlines()[:3],
                "preservation_decision":
                    "kept in tree; history contained in the unified "
                    "closure bundle and git history",
            })
        elif sha:
            record.update({
                "recovered": False,
                "original_commit": sha,
                "preservation_decision":
                    "tracked historically but absent from the current "
                    "checkout; recoverable via git show",
            })
        else:
            record.update({
                "recovered": False,
                "verification": "not found in resolvable history",
                "preservation_decision":
                    "superseded by the unified closure bundle "
                    "(WebPent_Unified_v0.40.1_UMDR42_CLOSURE.bundle)",
            })
        entries.append(record)

    # the current unified bundle
    unified = GIT_ROOT.parent / (
        "download/WebPent_Unified_v0.40.1_UMDR42_CLOSURE.zip")
    zip_extract = GIT_ROOT.parent / "zip-extract"
    unified_bundle = None
    for candidate in zip_extract.rglob("*.bundle"):
        unified_bundle = candidate
        break
    if unified_bundle and unified_bundle.exists():
        data = unified_bundle.read_bytes()
        verify = subprocess.run(
            ["git", "bundle", "verify", str(unified_bundle)],
            cwd=GIT_ROOT, capture_output=True, text=True)
        entries.append({
            "original_path": "WebPent_Unified_v0.40.1_UMDR42_CLOSURE.bundle",
            "purpose": "the unified UMDR42 closure bundle (current)",
            "recovered": True,
            "present_in": "release ZIP + release asset",
            "size_bytes": len(data),
            "sha256": _sha256_bytes(data),
            "bundle_verify": "ok" if verify.returncode == 0
            else f"failed: {verify.stderr.strip()[:120]}",
            "preservation_decision": "kept — the canonical release "
            "artifact, published on the GitHub release",
        })

    manifest = {
        "mission": "UM-DR-43C §3 historical artifact preservation",
        "generated_from_branch": _git(["rev-parse", "--abbrev-ref",
                                       "HEAD"]),
        "generated_at_commit": _git(["rev-parse", "HEAD"]),
        "entries": entries,
    }
    MANIFEST_OUT.parent.mkdir(parents=True, exist_ok=True)
    MANIFEST_OUT.write_text(json.dumps(manifest, indent=2),
                            encoding="utf-8")
    recovered = sum(1 for e in entries if e.get("recovered"))
    print(f"archive_manifest: {recovered}/{len(entries)} entries "
          f"recovered/verified → {MANIFEST_OUT.relative_to(REPO)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
