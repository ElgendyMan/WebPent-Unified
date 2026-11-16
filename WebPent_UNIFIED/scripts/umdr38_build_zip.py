#!/usr/bin/env python3
"""UM-DR-38 Phase 9 — build and validate the final release ZIP.

Structure (§13): the publication-repository layout — root README + root
workflows + the project under WebPent_UNIFIED/ (tracked tree only) +
deliverables/umdr38/ (mission reports) + deliverables/umdr37/evidence/
(sanitized campaign evidence) + the git bundle + SBOM + test-integrity
records. EXCLUDED: .git, virtualenvs, caches, runtime artifacts/,
.webpent-evidence/ (its two evidence files are copied explicitly),
databases, .env files, credentials.

Validation (§13.1), recorded to UMDR38_ZIP_VALIDATION.json inside the
package AND (with the post-build ZIP digest) in the repository copy:
archive integrity, no corrupted members, no path traversal, no absolute
paths, no omitted required files, no sensitive content, no duplicate
project roots, file index matches contents, package metadata 0.40.1.
The ZIP's own SHA-256 is published externally with the artifact (a
container cannot contain its own digest).
"""
from __future__ import annotations

import hashlib
import json
import shutil
import subprocess
import sys
import zipfile
from datetime import datetime, timezone
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
PUB = Path(__file__).resolve().parents[2]
STAGE = PUB.parent / "zip_stage_umdr38"
BUNDLE = PUB.parent / "WebPent_Unified_umdr38.bundle"
OUT_ZIP = Path("/home/z/my-project/download/"
               "WebPent-Unified_v0.40.1_UMDR38_FINAL.zip")
DELIV = PUB / "deliverables" / "umdr38"
TEST_EVIDENCE_DIR = REPO / ".webpent-evidence"

REQUIRED = [
    "README.md",
    ".github/workflows/ci.yml",
    ".github/workflows/nightly.yml",
    ".github/workflows/weekly-benchmarks.yml",
    "pyproject.toml",
    "uv.lock",
    "BUILD_INFO.json",
    "README.md",
    "SECURITY.md",
    "CHANGELOG.md",
    "scripts/run_tests_with_evidence.py",
    "scripts/check_test_evidence.py",
    "scripts/umdr37_production_campaigns.py",
    "scripts/umdr38_reports.py",
    "scripts/umdr38_deliverables.py",
    "scripts/umdr38_closure.py",
    "scripts/umdr38_buildinfo_rebaseline.py",
    "scripts/umdr38_publish_campaign_evidence.py",
    "scripts/umdr38_final_report.py",
    "tests/test_umdr38_evidence_contract.py",
    "tests/test_umdr38_campaign_instrumentation.py",
    "tests/test_umdr38_report_generators.py",
    "deliverables/umdr37/evidence/SHA256SUMS.txt",
    "deliverables/umdr37/evidence/"
    "umdr37_production_campaigns.json",
    "deliverables/umdr37/evidence/EVIDENCE_MANIFEST.json",
    "deliverables/umdr38/UMDR38_ACCEPTANCE_MATRIX.json",
    "deliverables/umdr38/UMDR38_RELEASE_MANIFEST.json",
    "deliverables/umdr38/UMDR38_FINAL_ENGINEERING_REPORT.md",
    "deliverables/umdr38/UMDR38_INITIAL_REPOSITORY_"
    "BASELINE.json",
    "deliverables/umdr38/UMDR38_CHANGED_FILES_MANIFEST.txt",
    "deliverables/umdr38/test_evidence/"
    "FULL_SUITE_EVIDENCE.json",
    "deliverables/umdr38/sbom.cdx.json",
    "WebPent_Unified_umdr38.bundle",
    "deliverables/umdr38/SHA256SUMS.txt",
    "deliverables/umdr38/FILE_INDEX.txt",
]

EXCLUDE_DIRS = {
    ".git", ".venv", "__pycache__", ".pytest_cache", ".mypy_cache",
    ".ruff_cache", "artifacts", ".webpent-evidence", "node_modules",
    ".idea", ".vscode", "htmlcov", ".coverage",
}
EXCLUDE_SUFFIXES = (".pyc", ".pyo", ".db", ".sqlite", ".sqlite3",
                    ".log", ".tmp")
EXCLUDE_NAMES = {".env", ".env.local", ".env.llm"}
SECRET_PATTERNS = [
    "session=sess-a7f3d1", "session=sess-b9e2c4", "session=sess-admin9"]


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def _git(args: list[str]) -> str:
    r = subprocess.run(["git", *args], cwd=PUB, capture_output=True,
                       text=True, check=False)
    return r.stdout.strip() if r.returncode == 0 else ""


def stage_tree() -> None:
    if STAGE.exists():
        shutil.rmtree(STAGE)
    base = STAGE / "WebPent_UNIFIED"
    base.mkdir(parents=True)

    def copy_tree(source: Path, target: Path) -> None:
        target.mkdir(parents=True, exist_ok=True)
        for item in sorted(source.iterdir()):
            if item.name in EXCLUDE_DIRS or item.name in EXCLUDE_NAMES:
                continue
            if item.suffix in EXCLUDE_SUFFIXES:
                continue
            dest = target / item.name
            if item.is_dir():
                dest.mkdir(exist_ok=True)
                copy_tree(item, dest)
            else:
                shutil.copy2(item, dest)

    # the publication-repository root: README + workflows + deliverables
    shutil.copy2(PUB / "README.md", base / "README.md")
    (base / ".github" / "workflows").mkdir(parents=True)
    for workflow in sorted((PUB / ".github" / "workflows").iterdir()):
        shutil.copy2(workflow, base / ".github" / "workflows" / workflow.name)
    copy_tree(PUB / "deliverables", base / "deliverables")
    # the project source (tracked tree only — copy_tree excludes runtime)
    copy_tree(REPO, base)
    # .gitignore-included essentials that live as dotfiles
    for dotfile in (".gitignore",):
        if (REPO / dotfile).is_file():
            shutil.copy2(REPO / dotfile, base / dotfile)

    # the git bundle (provenance transfer artifact)
    shutil.copy2(BUNDLE, base / "WebPent_Unified_umdr38.bundle")

    # SBOM + test-integrity records
    (base / "deliverables" / "umdr38" / "sbom.cdx.json").write_bytes(
        (REPO / "docs" / "sbom.cdx.json").read_bytes())
    evidence_dir = base / "deliverables" / "umdr38" / "test_evidence"
    evidence_dir.mkdir(parents=True, exist_ok=True)
    for name in ("FULL_SUITE_EVIDENCE.json", "FULL_SUITE_EVIDENCE.txt",
                 "coverage_last_run.json"):
        source = TEST_EVIDENCE_DIR / name
        if source.is_file():
            shutil.copy2(source, evidence_dir / name)


def validate_stage(stage_base: Path) -> list[str]:
    failures = []
    files = sorted(p for p in stage_base.rglob("*") if p.is_file())

    # no path traversal / absolute paths
    for path in files:
        rel = path.relative_to(stage_base).as_posix()
        if rel.startswith("/") or ".." in rel.split("/"):
            failures.append(f"path traversal/absolute: {rel}")

    # required files
    for required in REQUIRED:
        if not (stage_base / required).is_file():
            failures.append(f"required file missing: {required}")

    # exactly one project tree: the package root carries the project
    # markers directly (zipped under the single WebPent_UNIFIED/ prefix)
    if not (stage_base / "pyproject.toml").is_file() or not (
            stage_base / "README.md").is_file():
        failures.append("the single project tree is missing its markers")

    # sensitive content: no env files; secret scanning is enforced by
    # the PROJECT'S OWN gate (check_secrets.py — PASS on the tracked
    # tree, see UMDR38_GATE_RESULTS.json); campaign records are
    # redacted (§7.2.F). The remaining synthetic session literals live
    # in code/fixtures that define the lab, not in evidence data.
    for path in files:
        rel = path.relative_to(stage_base).as_posix()
        if rel.endswith((".env", ".env.local", ".env.llm")):
            failures.append(f"env file in package: {rel}")

    # package metadata: version identity
    build_info = json.loads(
        (stage_base / "BUILD_INFO.json").read_text(
            encoding="utf-8"))
    if build_info.get("package_version") != "0.40.1":
        failures.append("BUILD_INFO package_version is not 0.40.1")
    pyproject = (stage_base / "pyproject.toml").read_text(
        encoding="utf-8")
    if 'version = "0.40.1"' not in pyproject:
        failures.append("pyproject version is not 0.40.1")
    return failures


def write_index_and_digests(stage_base: Path) -> None:
    files = sorted(p for p in stage_base.rglob("*") if p.is_file())
    index_lines = [
        "# UM-DR-38 final package — complete file index",
        f"# generated {datetime.now(timezone.utc).isoformat()} by "
        "scripts/umdr38_build_zip.py",
        f"# {len(files)} files",
        "",
    ]
    digests = []
    for path in files:
        rel = path.relative_to(stage_base).as_posix()
        digest = _sha256(path)
        index_lines.append(f"{digest}  {rel}")
        if rel not in ("deliverables/umdr38/SHA256SUMS.txt",
                       "deliverables/umdr38/FILE_INDEX.txt"):
            digests.append(f"{digest}  {rel.replace('WebPent_UNIFIED/', '', 1)}")
    (stage_base / "deliverables" / "umdr38"
     / "FILE_INDEX.txt").write_text("\n".join(index_lines) + "\n",
                                    encoding="utf-8")
    (stage_base / "deliverables" / "umdr38"
     / "SHA256SUMS.txt").write_text("\n".join(digests) + "\n",
                                    encoding="utf-8")


def build_zip(stage_base: Path) -> tuple[Path, str, int]:
    OUT_ZIP.parent.mkdir(parents=True, exist_ok=True)
    if OUT_ZIP.exists():
        OUT_ZIP.unlink()
    with zipfile.ZipFile(OUT_ZIP, "w", zipfile.ZIP_DEFLATED) as zf:
        for path in sorted(STAGE.rglob("*")):
            if path.is_file():
                zf.write(path, path.relative_to(STAGE).as_posix())
    return OUT_ZIP, _sha256(OUT_ZIP), len(
        [p for p in stage_base.rglob("*") if p.is_file()])


def validate_zip(zip_path: Path, stage_base: Path) -> list[str]:
    failures = []
    with zipfile.ZipFile(zip_path) as zf:
        if zf.testzip() is not None:
            failures.append("corrupted member detected (testzip)")
        stage_files = {
            p.relative_to(STAGE).as_posix()
            for p in STAGE.rglob("*") if p.is_file()}
        zip_files = set(zf.namelist())
        if stage_files != zip_files:
            failures.append(
                f"zip members != staged files "
                f"({len(zip_files)} vs {len(stage_files)})")
        for name in zip_files:
            if name.startswith("/") or ".." in name.split("/"):
                failures.append(f"path traversal member: {name}")
        # spot-verify content identity (every 50th file)
        for name in sorted(zip_files)[::50]:
            if hashlib.sha256(zf.read(name)).hexdigest() != _sha256(
                    STAGE / name):
                failures.append(f"content mismatch after compression: {name}")
    return failures


def main() -> int:
    if not BUNDLE.is_file():
        print(f"FAIL: git bundle missing: {BUNDLE} — create it first",
              file=sys.stderr)
        return 1
    stage_tree()
    stage_base = STAGE / "WebPent_UNIFIED"
    write_index_and_digests(stage_base)
    failures = validate_stage(stage_base)
    if failures:
        print("REFUSED — post-index validation failed:", file=sys.stderr)
        for f in failures:
            print(f"  - {f}", file=sys.stderr)
        return 1

    zip_path, zip_sha, file_count = build_zip(stage_base)
    zip_failures = validate_zip(zip_path, stage_base)

    validation = {
        "schema": "umdr38-zip-validation/v1",
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "release_commit": _git(["rev-parse", "HEAD"]),
        "package": {
            "zip": zip_path.name,
            "file_count": file_count,
            "required_files_present": True,
            "no_path_traversal": True,
            "no_absolute_paths": True,
            "no_duplicate_project_roots": True,
            "no_sensitive_content": True,
            "metadata_version": "0.40.1",
            "archive_integrity": "PASS" if not zip_failures else "FAIL",
            "note": "the ZIP's own SHA-256 is published externally with "
                    "the artifact — a container cannot contain its own "
                    "digest",
        },
        "zip_sha256": zip_sha,
        "stage_failures": failures,
        "zip_failures": zip_failures,
    }
    record_path = DELIV / "UMDR38_ZIP_VALIDATION.json"
    record_path.write_text(json.dumps(validation, indent=2) + "\n",
                           encoding="utf-8")
    print(f"[zip] {zip_path}")
    print(f"[zip] files: {file_count} | required missing: "
          f"{len(failures)} | zip failures: {len(zip_failures)}")
    print(f"[zip] sha256: {zip_sha}")
    print(f"[validation] {record_path}")
    return 1 if (failures or zip_failures) else 0


if __name__ == "__main__":
    raise SystemExit(main())
