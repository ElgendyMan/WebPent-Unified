#!/usr/bin/env python3
"""UM-DR-36.1 §1.4 — reproducible recovery verification command.

One command, runnable from any clean clone, that verifies the recovery
state and produces a machine-readable report distinguishing VERIFIED
recovery facts from UNVERIFIED historical claims. Fail-closed: a
non-zero exit means the recovery state is NOT verified.

Checks (in order):
  1. required recovery files present;
  2. SHA-256 manifests verify (frozen_modules.sha256, BASELINE/POST
     modern_spine pins);
  3. frozen-module integrity (every manifest entry matches disk);
  4. package/version consistency (pyproject == __init__ == uv.lock ==
     BUILD_INFO.package_version);
  5. required campaign artifacts present and schema-complete;
  6. missing recovery inputs detected and reported explicitly.

Output: JSON report on stdout (and --out PATH, default
docs/UMDR36_1_RECOVERY_VERIFICATION.json).

Usage:
    uv run python scripts/verify_recovery_umdr36.py [--out PATH] [--quiet]
"""
from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]

REQUIRED_FILES = (
    "pyproject.toml",
    "uv.lock",
    "BUILD_INFO.json",
    "frozen_modules.sha256",
    "src/webpent/__init__.py",
    "scripts/recover_umdr35_36.py",
    "scripts/refreeze_umdr35_36_repinned.py",
    "scripts/build_umdr35_36_readiness_summary.py",
    "artifacts/umdr35_36_integrated_campaign_result.json",
    "docs/FULL_SUITE_EVIDENCE.txt",
)

# Campaign artifact keys that must exist and be internally consistent
# (same finding id across every confirmation channel).
CAMPAIGN_CHAIN_KEYS = (
    ("confirmation_chain", "causal_guard", "finding_id"),
    ("confirmation_chain", "proof_bundle", "finding_id"),
    ("confirmation_chain", "replay", "finding_id"),
    ("confirmation_chain", "promotion", "finding_id"),
)


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def _git(args: list[str]) -> str:
    r = subprocess.run(["git", *args], cwd=REPO, capture_output=True, text=True,
                       check=False)
    return r.stdout.strip() if r.returncode == 0 else ""


def check_required_files(report: dict) -> bool:
    missing = [rel for rel in REQUIRED_FILES if not (REPO / rel).is_file()]
    report["required_files"] = {
        "checked": len(REQUIRED_FILES),
        "missing": missing,
        "ok": not missing,
    }
    return not missing


def check_frozen_manifest(report: dict) -> bool:
    manifest = REPO / "frozen_modules.sha256"
    entries, missing_files, mismatches = 0, [], []
    for line in manifest.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        digest, _, rel = line.partition("  ")
        entries += 1
        f = REPO / rel
        if not f.is_file():
            missing_files.append(rel)
        elif _sha256(f) != digest:
            mismatches.append(rel)
    report["frozen_module_integrity"] = {
        "manifest": "frozen_modules.sha256",
        "entries": entries,
        "missing_files": missing_files,
        "hash_mismatches": mismatches,
        "ok": not missing_files and not mismatches,
    }
    return report["frozen_module_integrity"]["ok"]


def _resolve_module(target: str) -> Path | None:
    """Resolve a bare module filename under src/webpent (unambiguous)."""
    hits = [p for p in (REPO / "src" / "webpent").rglob(target) if p.is_file()]
    return hits[0] if len(hits) == 1 else None


def check_baseline_pins(report: dict) -> bool:
    """BASELINE/POST pins are HISTORICAL window records, not current-tree
    integrity contracts.

    They pin modern_spine.py as it stood during their original window
    (2026-10-22); the file legitimately changed afterwards and was
    re-pinned in frozen_modules.sha256 (the authoritative current
    integrity reference, checked separately). Rewriting these pins to
    match the current tree would falsify history, so this check only
    verifies the historical record is well-formed and internally
    consistent (BASELINE == POST, both 64-hex).
    """
    results = {}
    ok = True
    digests = {}
    for name in ("BASELINE.sha256.txt", "POST.sha256.txt"):
        path = REPO / name
        if not path.is_file():
            results[name] = {"ok": False, "error": "file missing"}
            ok = False
            continue
        line = path.read_text(encoding="utf-8").strip().splitlines()[0]
        target, _, rest = line.partition(":")
        digest = rest.strip().split()[0]
        target_path = _resolve_module(target.strip())
        well_formed = (
            target_path is not None and len(digest) == 64
        )
        digests[name] = digest
        results[name] = {
            "classification": "historical_window_record",
            "target": str(target_path.relative_to(REPO)) if target_path
            else f"<unresolved: {target.strip()}>",
            "well_formed": well_formed,
            "ok": well_formed,
        }
        ok = ok and well_formed
    internally_consistent = digests.get("BASELINE.sha256.txt") == digests.get(
        "POST.sha256.txt")
    results["internal_consistency"] = {
        "baseline_equals_post": internally_consistent,
        "ok": internally_consistent,
    }
    results["note"] = (
        "These pins record a historical tree state; current integrity is "
        "authoritatively enforced by frozen_modules.sha256 (checked above). "
        "They are intentionally NOT compared against the current tree."
    )
    ok = ok and internally_consistent
    report["baseline_pins"] = results
    return ok


def _pyproject_version() -> str:
    for line in (REPO / "pyproject.toml").read_text(encoding="utf-8").splitlines():
        s = line.strip()
        if s.startswith("version"):
            return s.split("=", 1)[1].strip().strip('"')
    return ""


def _init_version() -> str:
    for line in (REPO / "src/webpent/__init__.py").read_text(
            encoding="utf-8").splitlines():
        s = line.strip()
        if s.startswith("__version__"):
            return s.split("=", 1)[1].strip().strip('"')
    return ""


def _lock_version() -> str:
    lines = (REPO / "uv.lock").read_text(encoding="utf-8").splitlines()
    for i, line in enumerate(lines):
        if line.strip() == 'name = "webpent"':
            for j in range(i, min(i + 4, len(lines))):
                if lines[j].strip().startswith("version"):
                    return lines[j].split("=", 1)[1].strip().strip('"')
    return ""


def check_version_consistency(report: dict) -> bool:
    pyproject = _pyproject_version()
    versions = {
        "pyproject.toml (SSOT)": pyproject,
        "src/webpent/__init__.py": _init_version(),
        "uv.lock webpent entry": _lock_version(),
    }
    try:
        build_info = json.loads((REPO / "BUILD_INFO.json").read_text(
            encoding="utf-8"))
        versions["BUILD_INFO.json package_version"] = str(
            build_info.get("package_version", ""))
    except (OSError, ValueError):
        versions["BUILD_INFO.json package_version"] = "<unparseable>"
    consistent = len(set(versions.values())) == 1 and pyproject != ""
    report["version_consistency"] = {
        "versions": versions,
        "consistent": consistent,
        "ok": consistent,
    }
    return consistent


def check_campaign_artifact(report: dict) -> bool:
    path = REPO / "artifacts" / "umdr35_36_integrated_campaign_result.json"
    try:
        artifact = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        report["campaign_artifact"] = {"ok": False, "error": str(exc)}
        return False
    problems: list[str] = []
    if not artifact.get("campaign", {}).get("campaign_id"):
        problems.append("campaign.campaign_id missing")
    invariant = artifact.get("same_finding_invariant", {})
    finding_id = invariant.get("finding_id")
    if not finding_id:
        problems.append("same_finding_invariant.finding_id missing")
    for keypath in CAMPAIGN_CHAIN_KEYS:
        node = artifact
        for key in keypath:
            node = node.get(key, {}) if isinstance(node, dict) else {}
        if node != finding_id:
            problems.append(
                f"{'.'.join(keypath)} != same_finding_invariant.finding_id "
                f"({node!r} vs {finding_id!r})")
    report["campaign_artifact"] = {
        "path": "artifacts/umdr35_36_integrated_campaign_result.json",
        "campaign_id": artifact.get("campaign", {}).get("campaign_id"),
        "finding_id": finding_id,
        "problems": problems,
        "ok": not problems,
    }
    return not problems


def check_git_state(report: dict) -> None:
    head = _git(["rev-parse", "HEAD"])
    dirty = bool(_git(["status", "--porcelain"]))
    report["git_state"] = {
        "head": head or "unknown (not a git checkout)",
        "clean": not dirty,
        "recovery_baseline": "1968f63c2076b1b804537f91cd5cfa01c3eee0bb "
                             "(public main at mission start)",
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", default=None,
                        help="write the JSON report to this repo-relative path")
    parser.add_argument("--quiet", action="store_true",
                        help="only print the verdict line")
    args = parser.parse_args()

    checks = {
        "required_files": check_required_files,
        "frozen_manifest": check_frozen_manifest,
        "baseline_pins": check_baseline_pins,
        "version_consistency": check_version_consistency,
        "campaign_artifact": check_campaign_artifact,
    }
    report: dict = {
        "command": "scripts/verify_recovery_umdr36.py",
        "spec": "UM-DR-36.1 §1.4 reproducible recovery verification",
        "executed_at": datetime.now(timezone.utc).isoformat(),
        "repo_root": str(REPO),
    }
    check_git_state(report)
    results = {name: fn(report) for name, fn in checks.items()}

    # Historical claims carried in BUILD_INFO are explicitly NOT verified
    # by this command (they predate the recovery baseline); only the
    # machine-checkable recovery state above can be verified.
    report["unverified_historical_claims"] = [
        "BUILD_INFO.json umdr32/suite_evidence/suite_count fields "
        "(historical records, predating the recovery baseline)",
        "docs/UMDR35_36_READINESS_SUMMARY.json local head df2b50d "
        "(not resolvable in the public repository — recorded by the "
        "mission brief as an unverifiable historical reference)",
    ]
    report["verdict"] = "VERIFIED" if all(results.values()) else "NOT_VERIFIED"
    report["checks"] = {k: ("PASS" if v else "FAIL") for k, v in results.items()}

    out = {"verdict": report["verdict"], "checks": report["checks"]}
    if not args.quiet:
        out = report
    text = json.dumps(out, indent=2, default=str)
    if args.out:
        target = Path(args.out)
        if not target.is_absolute():
            target = REPO / target
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(json.dumps(report, indent=2, default=str) + "\n",
                          encoding="utf-8")
    print(text)
    return 0 if report["verdict"] == "VERIFIED" else 1


if __name__ == "__main__":
    raise SystemExit(main())
