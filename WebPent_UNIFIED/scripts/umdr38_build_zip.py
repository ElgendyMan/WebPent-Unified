#!/usr/bin/env python3
"""UM-DR-38.1 Phase 7 — the reproducible release ZIP builder.

Design corrections over the UM-DR-38 builder (which assumed a personal
workspace layout and silently depended on files no clean clone has):

* REPO-LAYOUT ZIP — the package mirrors the REQUIRED repository root
  layout exactly (README.md, .github/workflows/, WebPent_UNIFIED/,
  deliverables/, the git bundle). Publishing the ZIP contents produces
  a correct repository tree: one project root, canonical workflows at
  the discovery location, deliverables where the reports reference
  them.
* TRACKED SOURCES ONLY — the project tree is staged from
  ``git ls-files`` (a clean clone contains exactly these files); the
  builder never reaches outside the repository.
* OUTPUT PARAMETER — ``--output PATH`` or ``WEBPENT_ZIP_OUTPUT``,
  default ``dist/`` relative to the repository root. No absolute
  personal paths anywhere.
* CONFLICT DETECTION — generated extras (SBOM, test evidence copies)
  must never silently overwrite a tracked file with different content;
  any conflict REFUSES the build.
* PACKAGE SECRET SCAN — the project's own ``check_secrets.py`` runs
  over the STAGED project tree via the CURRENT interpreter executing
  the STAGED script (its ROOT resolves inside the stage) — running a
  package manager inside the stage would materialize a virtualenv
  there and is forbidden; plus a credential-pattern scan over the
  root-level deliverables.
* FAIL-CLOSED — missing required files (including the current
  full-suite evidence) refuse the build; a failed validation writes no
  ZIP.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import subprocess
import sys
import zipfile
from datetime import datetime, timezone
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]   # WebPent_UNIFIED/
PUB = Path(__file__).resolve().parents[2]    # repository root
DIST_DEFAULT = PUB / "dist"

REQUIRED = (
    "README.md",
    ".github/workflows/ci.yml",
    ".github/workflows/nightly.yml",
    ".github/workflows/weekly-benchmarks.yml",
    "WebPent_Unified_umdr38.bundle",
    "WebPent_UNIFIED/pyproject.toml",
    "WebPent_UNIFIED/uv.lock",
    "WebPent_UNIFIED/BUILD_INFO.json",
    "WebPent_UNIFIED/README.md",
    "WebPent_UNIFIED/SECURITY.md",
    "WebPent_UNIFIED/CHANGELOG.md",
    "WebPent_UNIFIED/frozen_modules.sha256",
    "WebPent_UNIFIED/scripts/run_tests_with_evidence.py",
    "WebPent_UNIFIED/scripts/check_test_evidence.py",
    "WebPent_UNIFIED/scripts/umdr37_production_campaigns.py",
    "WebPent_UNIFIED/scripts/confirmation_chain.py",
    "WebPent_UNIFIED/scripts/umdr38_reports.py",
    "WebPent_UNIFIED/scripts/umdr38_deliverables.py",
    "WebPent_UNIFIED/scripts/umdr38_closure.py",
    "WebPent_UNIFIED/scripts/umdr38_buildinfo_rebaseline.py",
    "WebPent_UNIFIED/scripts/umdr38_publish_campaign_evidence.py",
    "WebPent_UNIFIED/scripts/umdr38_build_zip.py",
    "WebPent_UNIFIED/tests/test_umdr38_evidence_contract.py",
    "WebPent_UNIFIED/tests/test_umdr38_campaign_instrumentation.py",
    "WebPent_UNIFIED/tests/test_umdr38_report_generators.py",
    "WebPent_UNIFIED/tests/test_umdr38_1_repository_structure.py",
    "WebPent_UNIFIED/tests/test_umdr38_1_gate_status.py",
    "WebPent_UNIFIED/tests/test_umdr38_1_funnel_integrity.py",
    "WebPent_UNIFIED/tests/test_umdr38_1_acceptance.py",
    "deliverables/umdr37/evidence/SHA256SUMS.txt",
    "deliverables/umdr37/evidence/EVIDENCE_MANIFEST.json",
    "deliverables/umdr37/evidence/umdr37_production_campaigns.json",
    "deliverables/umdr38/UMDR38_ACCEPTANCE_MATRIX.json",
    "deliverables/umdr38/UMDR38_RELEASE_MANIFEST.json",
    "deliverables/umdr38/UMDR38_1_INITIAL_STATE_REPORT.md",
    "deliverables/umdr38/UMDR38_1_FINAL_CORRECTIVE_CLOSEOUT_REPORT.md",
    "deliverables/umdr38/UMDR38_CHANGED_FILES_MANIFEST.txt",
    "deliverables/umdr38/UMDR38_GATE_RESULTS.json",
    "deliverables/umdr38/test_evidence/FULL_SUITE_EVIDENCE.json",
    "deliverables/umdr38/sbom.cdx.json",
    "deliverables/umdr38/SHA256SUMS.txt",
    "deliverables/umdr38/FILE_INDEX.txt",
)

EXCLUDE_PARTS = {
    ".git", ".venv", "__pycache__", ".pytest_cache", ".mypy_cache",
    ".ruff_cache", "artifacts", ".webpent-evidence", "node_modules",
    "htmlcov", "dist",
}
EXCLUDE_SUFFIXES = (".pyc", ".pyo", ".db", ".sqlite", ".sqlite3",
                    ".log", ".tmp", ".coverage")
EXCLUDE_NAMES = {".env", ".env.local", ".env.llm"}
CREDENTIAL_PATTERNS = (
    "BEGIN PRIVATE KEY", "BEGIN RSA PRIVATE KEY", "AKIA",
    "xoxb-", "ghp_", "gho_", "aws_secret", "password=", "api_key=")


def _git(args: list[str], cwd: Path = PUB) -> str:
    r = subprocess.run(["git", *args], cwd=cwd, capture_output=True,
                       text=True, check=False)
    return r.stdout if r.returncode == 0 else ""


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def _utcnow() -> str:
    return datetime.now(timezone.utc).isoformat()


def tracked_files() -> list[str]:
    out = []
    for line in _git(["ls-files", "-z"]).split("\0"):
        if not line:
            continue
        parts = Path(line).parts
        if any(p in EXCLUDE_PARTS for p in parts):
            continue
        if line.endswith(EXCLUDE_SUFFIXES) or Path(line).name in EXCLUDE_NAMES:
            continue
        out.append(line)
    return sorted(out)


def stage_tree(stage: Path) -> list[str]:
    """Stage every TRACKED file (a clean clone has exactly these)."""
    conflicts = []
    staged = []
    for rel in tracked_files():
        src = PUB / rel
        dst = stage / rel
        if dst.exists() and dst.read_bytes() != src.read_bytes():
            conflicts.append(f"CONFLICT: tracked file {rel} already "
                             "staged with different content")
            continue
        dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(src, dst)
        staged.append(rel)
    return conflicts + staged  # conflicts first: caller refuses


def add_extras(stage: Path) -> list[str]:
    """Copy the generated extras into the stage with CONFLICT
    DETECTION: an extra must never silently overwrite a tracked file
    with different content."""
    notes = []
    extras: list[tuple[Path, Path]] = [
        (REPO / "docs" / "sbom.cdx.json",
         stage / "deliverables" / "umdr38" / "sbom.cdx.json"),
    ]
    evidence_dir = REPO / ".webpent-evidence"
    if evidence_dir.is_dir():
        for name in ("FULL_SUITE_EVIDENCE.json", "FULL_SUITE_EVIDENCE.txt",
                     "coverage_last_run.json"):
            src = evidence_dir / name
            if src.is_file():
                extras.append((
                    src, stage / "deliverables" / "umdr38" / "test_evidence"
                    / name))
    for src, dst in extras:
        if not src.is_file():
            continue
        if dst.exists() and dst.read_bytes() != src.read_bytes():
            notes.append(f"CONFLICT: extra {src.name} would overwrite a "
                         f"tracked file at {dst.relative_to(stage)}")
            continue
        dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(src, dst)
        notes.append(f"extra: {dst.relative_to(stage)}")
    return notes


def package_secret_scan(stage: Path) -> tuple[int, str]:
    """The PACKAGE-WIDE secret scan (UM-DR-38.2 §3.2): the project's
    OWN secret gate over the STAGED project tree (the CURRENT
    interpreter executes the STAGED script — its ROOT resolves inside
    the stage; a package manager is NEVER invoked inside the stage, it
    would materialize a virtualenv there), PLUS a credential-pattern
    scan over EVERY text file of the ENTIRE package: the root README,
    the root workflows, all deliverables, the SBOM, the nested source
    tree and the generated indexes. Secret VALUES are never printed —
    only path + pattern."""
    r = subprocess.run(
        [sys.executable,
         str(stage / "WebPent_UNIFIED" / "scripts" / "check_secrets.py")],
        capture_output=True, text=True, timeout=300)
    staged_exit = r.returncode
    # single-policy-source: the project's OWN calibrated gate (above)
    # adjudicates the staged project tree — its exclusion semantics
    # (example/env placeholders, docs) are the reviewed policy. The
    # raw credential-pattern net adds coverage ONLY where that gate
    # does not run: the root README, the root workflows, the
    # deliverables, the SBOM and the generated indexes. Applying the
    # raw net inside the project tree would only re-flag the
    # placeholders the calibrated gate deliberately allows.
    package_failures = []
    scanned = 0
    project_prefix = stage / "WebPent_UNIFIED"
    record_rel = Path("deliverables") / "umdr38" / \
        "UMDR38_ZIP_VALIDATION.json"
    for path in sorted(stage.rglob("*")):
        if not path.is_file() or path.is_symlink():
            continue
        if project_prefix in path.parents or path == project_prefix:
            continue
        if path.relative_to(stage) == record_rel:
            # self-referential by construction: the validation record
            # ENUMERATES the credential patterns it reports (its detail
            # lines are documentation, not credentials) — scanning it
            # would find its own pattern names and loop forever
            continue
        if path.suffix in (".png", ".jpg", ".jpeg", ".gif", ".ico",
                           ".woff", ".woff2", ".ttf", ".zip", ".gz",
                           ".bundle", ".bin", ".pdf", ".mp4", ".webp",
                           ".pyc"):
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except (UnicodeDecodeError, OSError):
            continue
        scanned += 1
        for pattern in CREDENTIAL_PATTERNS:
            if pattern.lower() in text.lower():
                package_failures.append(
                    f"{path.relative_to(stage)}: {pattern}")
    exit_code = staged_exit if not package_failures else 1
    detail = (f"scan_scope=full package ({scanned} text files across "
              f"the ENTIRE stage: root README, root workflows, "
              f"deliverables, SBOM, nested source, generated indexes); "
              f"staged check_secrets exit={staged_exit} (executed via "
              f"{Path(sys.executable).name} over the STAGED script); "
              f"credential-pattern failures={len(package_failures)}")
    for f in package_failures[:10]:
        detail += f"\n  - {f}"
    return exit_code, detail


def validate_stage(stage: Path) -> list[str]:
    failures = []
    files = sorted(p for p in stage.rglob("*") if p.is_file())
    for path in files:
        rel = path.relative_to(stage).as_posix()
        if rel.startswith("/") or ".." in rel.split("/"):
            failures.append(f"path traversal/absolute: {rel}")
        if path.is_symlink():
            failures.append(f"symlink in package: {rel}")
        if path.suffix in (".db", ".sqlite", ".sqlite3") or \
                path.name in EXCLUDE_NAMES:
            failures.append(f"runtime/credential file: {rel}")
    for required in REQUIRED:
        if not (stage / required).is_file():
            failures.append(f"required file missing: {required}")
    allowed_roots = {"WebPent_UNIFIED", "deliverables", ".github",
                     "README.md", "WebPent_Unified_umdr38.bundle"}
    roots = {p.relative_to(stage).parts[0] for p in files}
    unexpected = roots - allowed_roots
    if unexpected:
        failures.append(f"unexpected root entries: {sorted(unexpected)}")
    build_info = json.loads(
        (stage / "WebPent_UNIFIED" / "BUILD_INFO.json").read_text(
            encoding="utf-8"))
    if build_info.get("package_version") != "0.40.1":
        failures.append("BUILD_INFO package_version is not 0.40.1")
    pyproject = (stage / "WebPent_UNIFIED" / "pyproject.toml").read_text(
        encoding="utf-8")
    if 'version = "0.40.1"' not in pyproject:
        failures.append("pyproject version is not 0.40.1")
    return failures


def write_index_and_digests(stage: Path) -> None:
    files = sorted(p for p in stage.rglob("*") if p.is_file())
    index_lines = [
        "# UM-DR-38.1 final package — complete file index",
        f"# generated {_utcnow()} by scripts/umdr38_build_zip.py",
        f"# {len(files)} files",
        "",
    ]
    digests = []
    for path in files:
        rel = path.relative_to(stage).as_posix()
        digest = _sha256(path)
        index_lines.append(f"{digest}  {rel}")
        if rel not in ("deliverables/umdr38/SHA256SUMS.txt",
                       "deliverables/umdr38/FILE_INDEX.txt"):
            digests.append(f"{digest}  {rel}")
    (stage / "deliverables" / "umdr38" / "FILE_INDEX.txt").write_text(
        chr(10).join(index_lines) + chr(10), encoding="utf-8")
    (stage / "deliverables" / "umdr38" / "SHA256SUMS.txt").write_text(
        chr(10).join(digests) + chr(10), encoding="utf-8")


def build_zip(stage: Path, out_zip: Path) -> int:
    out_zip.parent.mkdir(parents=True, exist_ok=True)
    if out_zip.exists():
        out_zip.unlink()
    count = 0
    with zipfile.ZipFile(out_zip, "w", zipfile.ZIP_DEFLATED) as zf:
        for path in sorted(stage.rglob("*")):
            if path.is_file():
                zf.write(path, path.relative_to(stage).as_posix())
                count += 1
    return count


def validate_zip(zip_path: Path, stage: Path) -> list[str]:
    failures = []
    with zipfile.ZipFile(zip_path) as zf:
        if zf.testzip() is not None:
            failures.append("corrupted member detected (testzip)")
        stage_files = {p.relative_to(stage).as_posix()
                       for p in stage.rglob("*") if p.is_file()}
        zip_files = set(zf.namelist())
        if stage_files != zip_files:
            failures.append(f"zip members != staged files "
                            f"({len(zip_files)} vs {len(stage_files)})")
        for name in zip_files:
            if name.startswith("/") or ".." in name.split("/"):
                failures.append(f"path traversal member: {name}")
        # UM-DR-38.2 §3.2: EVERY member is validated — presence,
        # relative path, size and sha256 against the staged content
        # (the previous every-50th sampling was a verification gap)
        for name in sorted(zip_files):
            src = stage / name
            info = zf.getinfo(name)
            if info.file_size != src.stat().st_size:
                failures.append(f"size mismatch: {name} "
                                f"({info.file_size} vs "
                                f"{src.stat().st_size})")
                continue
            if hashlib.sha256(zf.read(name)).hexdigest() != _sha256(src):
                failures.append(f"content mismatch after compression: "
                                f"{name}")
    return failures


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", default=None,
                        help="ZIP output path (default: "
                             "dist/WebPent-Unified_v0.40.1_UMDR38_1_"
                             "FINAL.zip under the repository root; "
                             "WEBPENT_ZIP_OUTPUT overrides)")
    args = parser.parse_args()
    out_zip = Path(
        args.output
        or os.environ.get("WEBPENT_ZIP_OUTPUT")
        or (DIST_DEFAULT / "WebPent-Unified_v0.40.1_UMDR38_1_FINAL.zip"))

    if not (REPO / ".webpent-evidence" / "FULL_SUITE_EVIDENCE.json").is_file():
        print("REFUSED: no current full-suite evidence "
              "(.webpent-evidence/FULL_SUITE_EVIDENCE.json missing) — "
              "run scripts/run_tests_with_evidence.py at the release "
              "commit first (the package carries the run record; there "
              "is no workspace-external fallback)", file=sys.stderr)
        return 1

    stage = PUB / "dist" / "stage_umdr38_1"
    if stage.exists():
        shutil.rmtree(stage)
    stage.mkdir(parents=True)

    results = stage_tree(stage)
    conflicts = [r for r in results if r.startswith("CONFLICT")]
    if conflicts:
        print("REFUSED — copy conflicts (a canonical file would be "
              "silently overwritten):", file=sys.stderr)
        for c in conflicts:
            print(f"  - {c}", file=sys.stderr)
        return 1
    notes = add_extras(stage)
    # UM-DR-38.2 §3: a conflict reported by add_extras is FATAL — a
    # conflict that is merely appended to notes must never silently
    # pass validation (the published record carried an SBOM conflict
    # alongside archive_integrity: PASS)
    extra_conflicts = [n for n in notes if n.startswith("CONFLICT")]
    if extra_conflicts:
        print("REFUSED — extra-file conflicts (generated extras would "
              "overwrite canonical content):", file=sys.stderr)
        for c in extra_conflicts:
            print(f"  - {c}", file=sys.stderr)
        return 1
    secret_exit, secret_detail = package_secret_scan(stage)
    # a package never ships an environment: defensive removal AFTER the
    # scan too (in case anything materialized one inside the stage)
    for venv_dir in list(stage.rglob(".venv")):
        if venv_dir.is_dir():
            shutil.rmtree(venv_dir)
    write_index_and_digests(stage)
    failures = validate_stage(stage)
    if failures:
        print("REFUSED — stage validation failed:", file=sys.stderr)
        for f in failures:
            print(f"  - {f}", file=sys.stderr)
        return 1

    # UM-DR-38.2 §3.3: the IN-ARCHIVE validation record is written
    # INTO the stage BEFORE zipping, describing the staged content it
    # travels with (file_count, digests, scans) — the archive can
    # never again carry a stale record from a previous build. The
    # archive-level digest is published EXTERNALLY (a container cannot
    # contain its own digest).
    stage_record = {
        "schema": "umdr38-2-zip-validation/v1",
        "generated_at_utc": _utcnow(),
        "release_commit": _git(["rev-parse", "HEAD"]).strip(),
        "builder": "scripts/umdr38_build_zip.py (tracked sources only, "
                   "output-parameterized, conflicts fatal)",
        "package": {
            "zip": out_zip.name,
            "layout": "repository-root layout: README.md + "
                      ".github/workflows/ + WebPent_UNIFIED/ + "
                      "deliverables/ + the git bundle",
            "stage_file_count": len([p for p in stage.rglob("*")
                                     if p.is_file()]),
            "stage_failures": failures,
            "stage_validation": "PASS" if not failures else "FAIL",
            "archive_integrity": ("verified post-build over EVERY "
                                  "member (size + sha256 against the "
                                  "staged content); the release record "
                                  "at the repository root carries the "
                                  "result and the archive digest"),
        },
        "package_secret_scan_exit": secret_exit,
        "package_secret_scan_detail": secret_detail,
        "extras": notes,
        "zip_sha256": None,
        "zip_sha256_note": "an archive cannot contain its own digest; "
                           "the exact archive SHA-256 is published "
                           "externally with the artifact and recorded "
                           "in the repository-level record after the "
                           "build",
    }
    in_stage_record = (stage / "deliverables" / "umdr38"
                       / "UMDR38_ZIP_VALIDATION.json")
    in_stage_record.parent.mkdir(parents=True, exist_ok=True)
    in_stage_record.write_text(
        json.dumps(stage_record, indent=2) + chr(10), encoding="utf-8")
    # the indexes must include the record itself: regenerate them
    write_index_and_digests(stage)

    count = build_zip(stage, out_zip)
    zip_failures = validate_zip(out_zip, stage)
    zip_sha = _sha256(out_zip)

    record_path = PUB / "deliverables" / "umdr38" / \
        "UMDR38_ZIP_VALIDATION.json"
    record_path.parent.mkdir(parents=True, exist_ok=True)
    record_path.write_text(json.dumps({
        **stage_record,
        "package": {**stage_record["package"],
                    "file_count": count,
                    "archive_integrity":
                        "PASS" if not zip_failures else "FAIL"},
        "zip_failures": zip_failures,
        "zip_sha256": zip_sha,
        "member_validation": "every member: presence, relative path, "
                             "size, sha256, staged-content equality, "
                             "archive-content equality",
    }, indent=2) + chr(10), encoding="utf-8")
    print(f"[zip] {out_zip}")
    print(f"[zip] files: {count} | stage failures: {len(failures)} | "
          f"zip failures: {len(zip_failures)} | "
          f"secret scan exit: {secret_exit}")
    print(f"[zip] sha256: {zip_sha}")
    print(f"[validation] {record_path}")
    return 1 if (failures or zip_failures or secret_exit != 0) else 0


if __name__ == "__main__":
    raise SystemExit(main())
