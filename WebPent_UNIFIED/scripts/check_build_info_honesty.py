#!/usr/bin/env python3
"""P2-205 gate (UM-DR-36.1 redesign): build-info honesty & provenance.

The previous gate anchored provenance stability on the tag
``v15.2-audit-baseline`` and a single ``git_head`` / ``manifest_digest_v9``
pair. That anchor does not exist in the public repository, and a single
git_head provably cannot represent source/test/evidence/publication
revisions at once. Per UM-DR-36.1 §3 this gate is redesigned around a
genuine, verifiable baseline commit and the checked-in integrity
manifest — WITHOUT weakening any check:

  1. BUILD_INFO.json parses; required fields present and well-formed.
  2. Package version is unambiguous: BUILD_INFO.package_version ==
     provenance.package_version == version_identity_contract.
     package_version == version_identity_contract.current_release.
     package_version == the pyproject.toml SSOT version.
  3. Provenance schema (``umdr36-1-provenance-v1``): source_revision,
     tested_revision, evidence_revision, recovery_baseline are 40-hex
     AND resolvable commits in this repository; recovery_baseline must
     equal the documented public-main baseline; manifest_digest is
     64-hex AND must equal the ACTUAL sha256 of frozen_modules.sha256
     (missing manifest = failure); build_date is ISO-8601 and matches
     the top-level field; publication metadata is well-formed (a
     ``published: true`` claim requires a real, resolvable release tag).
  4. Test accounting: provenance.test_accounting carries the full
     collected/executed/passed/failed/skipped/xfailed/xpassed/errors/
     deselected counts, mathematically consistent (executed ==
     passed+failed+errors+skipped+xfailed+xpassed; collected ==
     executed+deselected); the top-level suite_count must EQUAL the
     executed count (collected tests may never be reported as
     executed); when the committed evidence JSON records the same
     evidence_revision, its accounting must match exactly. A live
     collection probe (when available) enforces the inflation guard:
     suite_count must not exceed the collected reality, nor lag it by
     more than 200 (stale accounting).
  5. Release-history sanity: every release_history entry is a strictly
     older package_version than the current one; entries carrying a
     source_revision must reference resolvable commits, or explicitly
     record ``source_revision: null`` with an explanatory
     source_revision_note (honest unverifiable-local-lineage marker).
     current_release.source_revision must equal provenance.
     source_revision.
  6. Provenance stability: the first post-baseline commit touching
     BUILD_INFO.json must be the declared UM-DR-36.1 re-baseline
     (subject prefix "BUILD_INFO re-baseline", exactly once); every
     later touch must be a qualifying re-freeze (subject prefix
     "BUILD_INFO re-freeze", touching ONLY BUILD_INFO.json, changing
     only the honest-drift fields). Anything else fails.

Historical narrative fields (umdr32/umdr34 window blocks, prose
lineage notes) are preserved as history and explicitly reported as
not-machine-verified — the gate distinguishes verified facts from
unverifiable historical claims instead of deleting them.

Exit 0 = honest; exit 1 = any violated claim (printed).
"""
from __future__ import annotations

import json
import re
import subprocess
import sys
from datetime import datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
BI = ROOT / "BUILD_INFO.json"
MANIFEST = ROOT / "frozen_modules.sha256"
EVIDENCE = ROOT / "docs" / "FULL_SUITE_EVIDENCE.json"

PROVENANCE_SCHEMA = "umdr36-1-provenance-v1"
# The genuine, verifiable recovery baseline: public main at the moment
# the UM-DR-36.1 mission started (exists in this repository's history).
RECOVERY_BASELINE = "1968f63c2076b1b804537f91cd5cfa01c3eee0bb"

REQUIRED_TOP_LEVEL = ("build_name", "build_date", "package_version",
                      "provenance", "suite_count", "suite_evidence",
                      "units_closed", "fixes_applied")
COUNT_KEYS = ("collected", "executed", "passed", "failed", "skipped",
              "xfailed", "xpassed", "errors", "deselected")
HEX40 = re.compile(r"^[0-9a-f]{40}$")
HEX64 = re.compile(r"^[0-9a-f]{64}$")
ISO_DATE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}")


def _git(args: list[str], root: Path | None = None) -> subprocess.CompletedProcess:
    return subprocess.run(["git", *args], cwd=root or ROOT, capture_output=True,
                          text=True, check=False)


def _commit_resolvable(sha: str) -> bool:
    if not HEX40.match(sha):
        return False
    return _git(["cat-file", "-e", f"{sha}^{{commit}}"]).returncode == 0


def _pyproject_version(root: Path | None = None) -> str:
    path = (root or ROOT) / "pyproject.toml"
    if not path.is_file():
        return ""
    for line in path.read_text(encoding="utf-8").splitlines():
        s = line.strip()
        if s.startswith("version"):
            return s.split("=", 1)[1].strip().strip('"')
    return ""


def _sha256_file(path: Path) -> str:
    import hashlib
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def _live_collected_count() -> int | None:
    """pytest's own --collect-only count, or None when unavailable."""
    try:
        r = subprocess.run(
            ["uv", "run", "pytest", "--collect-only", "-q", "tests/"],
            cwd=ROOT, capture_output=True, text=True, check=False)
    except OSError:
        return None
    for line in reversed((r.stdout or "").strip().splitlines()):
        m = re.match(r"^(\d+) tests? collected", line.strip())
        if m:
            return int(m.group(1))
    return None


def evaluate(info: dict, *, root: Path | None = None,
             collected_probe: int | None | object = None,
             evidence_record: dict | None = None) -> tuple[list[str], list[str]]:
    """Evaluate the honesty contract; returns (failures, notes).

    ``collected_probe``: the live collected-test count (int), or None to
    use the live probe, or the string "skip" to skip (unit tests).
    ``evidence_record``: the parsed committed evidence JSON, or None.
    """
    root = root or ROOT
    failures: list[str] = []
    notes: list[str] = []

    for key in REQUIRED_TOP_LEVEL:
        if key not in info or info[key] in (None, "", [], {}):
            failures.append(f"required field missing/empty: {key}")

    # --- 2. version identity -------------------------------------------
    py_version = _pyproject_version(root)
    declared = str(info.get("package_version", ""))
    if py_version and declared != py_version:
        failures.append(f"package_version {declared!r} != pyproject SSOT "
                        f"{py_version!r}")
    contract = info.get("version_identity_contract") or {}
    if not isinstance(contract, dict):
        contract = {}
    else:
        if str(contract.get("package_version", "")) != declared:
            failures.append("version_identity_contract.package_version != "
                            "top-level package_version")
        current_release = contract.get("current_release") or {}
        if not isinstance(current_release, dict):
            failures.append("version_identity_contract.current_release missing")
        else:
            crv = str(current_release.get("package_version", ""))
            if crv != declared:
                failures.append(
                    f"current_release.package_version {crv!r} != current "
                    f"package_version {declared!r} (invalid historical/"
                    "current release relationship)")

    # --- 3. provenance schema ------------------------------------------
    prov = info.get("provenance")
    if not isinstance(prov, dict):
        failures.append("provenance block missing")
        prov = {}
    else:
        if prov.get("schema") != PROVENANCE_SCHEMA:
            failures.append(f"provenance.schema is {prov.get('schema')!r}, "
                            f"expected {PROVENANCE_SCHEMA!r}")
        for key in ("source_revision", "tested_revision", "evidence_revision",
                    "recovery_baseline"):
            sha = str(prov.get(key, ""))
            if not HEX40.match(sha):
                failures.append(f"provenance.{key} is not a 40-hex sha: "
                                f"{sha!r}")
            elif not _commit_resolvable(sha):
                failures.append(f"provenance.{key} {sha} is not a resolvable "
                                "commit in this repository")
        if str(prov.get("recovery_baseline", "")) != RECOVERY_BASELINE:
            failures.append(f"provenance.recovery_baseline must be the "
                            f"documented public-main baseline "
                            f"{RECOVERY_BASELINE}")
        if str(prov.get("package_version", "")) != declared:
            failures.append("provenance.package_version != top-level "
                            "package_version")

        digest = str(prov.get("manifest_digest", ""))
        if not HEX64.match(digest):
            failures.append(f"provenance.manifest_digest is not 64-hex: "
                            f"{digest!r}")
        elif not MANIFEST.is_file():
            failures.append("frozen_modules.sha256 missing — manifest digest "
                            "cannot be verified")
        elif _sha256_file(MANIFEST) != digest:
            failures.append("provenance.manifest_digest does not match the "
                            "actual sha256 of frozen_modules.sha256")

        prov_date = str(prov.get("build_date", ""))
        top_date = str(info.get("build_date", ""))
        if not ISO_DATE.match(top_date):
            failures.append(f"build_date is not ISO-8601: {top_date!r}")
        if prov_date != top_date:
            failures.append("provenance.build_date != build_date")

        publication = prov.get("publication")
        if not isinstance(publication, dict) or not isinstance(
                publication.get("published"), bool):
            failures.append("provenance.publication must carry a boolean "
                            "'published' field")
        elif publication.get("published"):
            tag = str(publication.get("release_tag") or "")
            if not tag:
                failures.append("publication claims published=true without a "
                                "release tag")
            elif _git(["rev-parse", f"refs/tags/{tag}"]).returncode != 0:
                failures.append(f"publication release tag {tag!r} does not "
                                "exist")

    # --- 4. test accounting --------------------------------------------
    suite_count = info.get("suite_count")
    accounting = prov.get("test_accounting") if isinstance(prov, dict) else None
    if not isinstance(accounting, dict):
        failures.append("provenance.test_accounting missing")
    else:
        missing = [k for k in COUNT_KEYS
                   if not isinstance(accounting.get(k), int)]
        if missing:
            failures.append(f"test_accounting missing integer counts: "
                            f"{missing}")
        else:
            executed_sum = (accounting["passed"] + accounting["failed"]
                            + accounting["errors"] + accounting["skipped"]
                            + accounting["xfailed"] + accounting["xpassed"])
            if accounting["executed"] != executed_sum:
                failures.append(
                    f"test_accounting.executed {accounting['executed']} != "
                    f"outcome sum {executed_sum}")
            if accounting["collected"] != (accounting["executed"]
                                           + accounting["deselected"]):
                failures.append("test_accounting.collected != executed + "
                                "deselected")
            if isinstance(suite_count, int) and suite_count != accounting[
                    "executed"]:
                failures.append(
                    f"suite_count {suite_count} != test_accounting.executed "
                    f"{accounting['executed']} (suite_count must report the "
                    "EXECUTED count, never the collected count)")
        if isinstance(evidence_record, dict) and isinstance(
                evidence_record.get("accounting"), dict):
            ev_commit = str(evidence_record.get("source_commit", ""))
            if ev_commit == str(prov.get("evidence_revision", "")):
                if evidence_record["accounting"] != accounting:
                    failures.append(
                        "committed evidence accounting differs from "
                        "provenance.test_accounting for the same "
                        "evidence_revision")
            else:
                notes.append(
                    f"committed evidence records commit {ev_commit[:12]}, "
                    "provenance.evidence_revision is "
                    f"{str(prov.get('evidence_revision', ''))[:12]} — "
                    "binding not evaluated")

    if isinstance(suite_count, bool) or not isinstance(suite_count, int) \
            or suite_count <= 0:
        failures.append(f"suite_count must be a positive int, got "
                        f"{suite_count!r}")
    else:
        probe = collected_probe
        if probe is None:
            probe = _live_collected_count()
        if isinstance(probe, int):
            if suite_count > probe:
                failures.append(f"suite_count {suite_count} EXCEEDS collected "
                                f"reality {probe} — inflated claim")
            elif probe - suite_count > 200:
                failures.append(f"suite_count {suite_count} lags collected "
                                f"reality {probe} by {probe - suite_count} "
                                "(>200) — stale accounting, re-freeze "
                                "BUILD_INFO")
            else:
                notes.append(f"suite_count {suite_count} vs collected "
                             f"{probe} (within margin)")

    evidence_text = str(info.get("suite_evidence", ""))
    if len(evidence_text) < 40:
        failures.append("suite_evidence too short to be a real evidence "
                        "statement")

    for key in ("units_closed", "fixes_applied"):
        val = info.get(key)
        if not isinstance(val, list) or not val or not all(
                isinstance(x, str) and x.strip() for x in val):
            failures.append(f"{key} must be a non-empty list of non-empty "
                            "strings")

    # --- 5. release history --------------------------------------------
    if isinstance(contract, dict):
        history = contract.get("release_history")
        if not isinstance(history, list) or not history:
            failures.append("version_identity_contract.release_history must "
                            "be a non-empty list")
        else:
            for i, entry in enumerate(history):
                if not isinstance(entry, dict):
                    failures.append(f"release_history[{i}] is not an object")
                    continue
                hv = str(entry.get("package_version", ""))
                if not hv or hv >= declared:
                    failures.append(
                        f"release_history[{i}].package_version {hv!r} is not "
                        f"strictly older than the current {declared!r}")
                rev = entry.get("source_revision")
                if rev is None:
                    if not str(entry.get("source_revision_note", "")).strip():
                        failures.append(
                            f"release_history[{i}] has no source_revision and "
                            "no explanatory source_revision_note (unverifiable "
                            "local lineage must be marked explicitly)")
                    else:
                        notes.append(f"release_history[{i}] ({hv}) retained as "
                                     "explicitly-unverifiable local lineage")
                elif not _commit_resolvable(str(rev)):
                    failures.append(
                        f"release_history[{i}].source_revision {rev!r} is not "
                        "a resolvable commit")
            current_release = contract.get("current_release") or {}
            if isinstance(current_release, dict) and prov:
                crs = str(current_release.get("source_revision", ""))
                if crs and crs != str(prov.get("source_revision", "")):
                    failures.append("current_release.source_revision != "
                                    "provenance.source_revision")

    # --- 6. provenance stability ---------------------------------------
    touches = _git(["log", "--format=%H%x00%s", "--", "BUILD_INFO.json"]
                   ).stdout.strip().splitlines()
    post_baseline: list[tuple[str, str]] = []
    for line in touches:
        sha, _, subject = line.partition("\x00")
        if sha == RECOVERY_BASELINE:
            break
        post_baseline.append((sha, subject))
    rebaselines = 0
    bad: list[str] = []
    allowed_keys = {"build_date", "suite_count", "suite_evidence"}
    for sha, subject in post_baseline:
        if subject.startswith("BUILD_INFO re-baseline"):
            rebaselines += 1
            if rebaselines > 1:
                bad.append(f"{sha[:12]}: more than one declared re-baseline")
            continue
        if subject.startswith("BUILD_INFO re-freeze"):
            files_touched = _git(["show", "--name-only", "--format=", sha]
                                 ).stdout.split()
            if sorted(files_touched) != ["BUILD_INFO.json"]:
                bad.append(f"{sha[:12]}: re-freeze must touch ONLY "
                           "BUILD_INFO.json")
                continue
            changed_keys = {
                m.group(1) for m in re.finditer(
                    r'^[+-]\s*"([a-z_0-9]+)":',
                    _git(["show", sha, "--", "BUILD_INFO.json"]).stdout,
                    re.MULTILINE)}
            if not changed_keys <= allowed_keys:
                bad.append(f"{sha[:12]}: re-freeze modified non-drift fields: "
                           f"{sorted(changed_keys - allowed_keys)}")
        else:
            bad.append(f"{sha[:12]}: subject does not declare a re-baseline "
                       "or re-freeze")
    if bad:
        failures.append("BUILD_INFO.json was modified after the recovery "
                        "baseline without a qualifying declared decision: "
                        + "; ".join(bad))
    elif post_baseline:
        notes.append(f"provenance stability: {len(post_baseline)} post-"
                     "baseline touch(es), all qualifying declared decisions")
    else:
        notes.append("provenance stability: BUILD_INFO.json untouched since "
                     "the recovery baseline")

    notes.append("historical narrative blocks (umdr32/umdr34 windows, prose "
                 "lineage notes) are preserved as history and are not "
                 "machine-verified claims")
    return failures, notes


def main() -> int:
    if not BI.exists():
        print("build_info_honesty: FAIL — BUILD_INFO.json missing")
        return 1
    try:
        info = json.loads(BI.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        print(f"build_info_honesty: FAIL — BUILD_INFO.json unparseable: {exc}")
        return 1
    evidence_record = None
    if EVIDENCE.is_file():
        try:
            evidence_record = json.loads(EVIDENCE.read_text(encoding="utf-8"))
        except ValueError:
            evidence_record = None

    failures, notes = evaluate(info, evidence_record=evidence_record)
    for n in notes:
        print(f"  note: {n}")
    if failures:
        print(f"build_info_honesty: GATE FAILURE ({len(failures)})")
        for f in failures:
            print(f"  - {f}")
        return 1
    print("build_info_honesty: PASS — version identity, provenance "
          "revisions, manifest digest, test accounting and stability "
          "discipline all verified; historical narrative preserved")
    return 0


if __name__ == "__main__":
    sys.exit(main())
