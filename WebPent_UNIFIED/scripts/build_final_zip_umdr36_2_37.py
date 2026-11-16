#!/usr/bin/env python3
"""Build the FINAL UM-DR-36.2/37 ZIP: the whole project + all mission
deliverables + a complete FILE_INDEX of every path inside the archive."""
from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

REPO = Path("/home/z/my-project/work/repo")
DL = Path("/home/z/my-project/download")
DELIV = DL / "UMDR36_2_37_DELIVERABLES"
STAGE = Path("/home/z/my-project/work/zip_stage2")
ROOT = STAGE / "WebPent_UNIFIED"
ZIP_OUT = DL / "WebPent_UNIFIED_v0.40.1_UMDR36_2_37_FINAL.zip"

EXCLUDES = [".git", ".venv", "__pycache__", ".pytest_cache",
            ".ruff_cache", ".mypy_cache", ".coverage", "htmlcov",
            "node_modules", ".tox", "*.pyc", "*.pyo", ".DS_Store"]


def main() -> int:
    if STAGE.exists():
        shutil.rmtree(STAGE)
    ROOT.mkdir(parents=True)

    rsync = ["rsync", "-a"]
    for exc in EXCLUDES:
        rsync += [f"--exclude={exc}"]
    rsync += [f"{REPO}/", str(ROOT) + "/"]
    subprocess.run(rsync, check=True)

    # deliverables live inside the archive too
    dest = ROOT / "UMDR36_2_37_DELIVERABLES"
    if not dest.exists():
        dest.mkdir()
    for item in DELIV.iterdir():
        if item.is_file():
            shutil.copy2(item, dest / item.name)

    # ---- FILE_INDEX: every path inside the archive --------------------
    index_lines = [
        "WebPent UNIFIED v0.40.1 — UM-DR-36.2 + UM-DR-37 FINAL ARCHIVE",
        "=" * 68,
        f"Generated from branch mission/umdr36.2-umdr37",
        "",
        "COMPLETE FILE INDEX (all paths inside this archive):",
        "",
    ]
    all_files = sorted(
        p.relative_to(STAGE).as_posix()
        for p in STAGE.rglob("*") if p.is_file())
    for i, rel in enumerate(all_files, 1):
        index_lines.append(f"{i:5d}. {rel}")
    index_lines += [
        "",
        f"TOTAL: {len(all_files)} files",
        "",
        "KEY PATHS:",
        "  WebPent_UNIFIED/                                  the full project",
        "  WebPent_UNIFIED/docs/UMDR36_2_*.md|json           36.2 deliverables",
        "  WebPent_UNIFIED/docs/UMDR37_*.md|json             37 deliverables",
        "  WebPent_UNIFIED/docs/FULL_SUITE_EVIDENCE.json     v3 full-suite evidence",
        "  WebPent_UNIFIED/artifacts/umdr37_*.json           campaign/trace artifacts",
        "  WebPent_UNIFIED/UMDR36_2_37_DELIVERABLES/         deliverable copies + git bundle",
        "  WebPent_UNIFIED/UMDR36_2_37_DELIVERABLES/FILE_INDEX.txt   this index",
        "  WebPent_UNIFIED/UMDR36_2_37_DELIVERABLES/"
        "WebPent_Unified_mission-umdr36.2-umdr37.bundle   pushable git bundle",
        "",
        "Honest state: PARTIALLY_VERIFIED — production discovery chain",
        "verified 3/3 (genuine IDOR confirmations through CausalGuard ->",
        "ProofBundle -> Replay); decoy + out-of-scope invariants green;",
        "full-loop learning proven; seven failures closed this round;",
        "remote CI unverified (no credentials — bundle provided).",
    ]
    (dest / "FILE_INDEX.txt").write_text("\n".join(index_lines),
                                         encoding="utf-8")

    if ZIP_OUT.exists():
        ZIP_OUT.unlink()
    subprocess.run(["zip", "-r", "-q", str(ZIP_OUT), "WebPent_UNIFIED"],
                   cwd=STAGE, check=True)

    listing = subprocess.run(["unzip", "-l", str(ZIP_OUT)],
                             capture_output=True, text=True,
                             check=True).stdout
    # NOTE: the summary line filter must match "N files" COUNT lines
    # only — a naive `"files" not in line` also excluded every path
    # containing "pro*files*" (e.g. family_profiles.py), producing
    # false MISSING reports.
    import re as _re
    names = [line.split()[-1] for line in listing.splitlines()
             if line.strip() and not line.startswith("Archive")
             and not _re.match(r"^\s*[\d,]+\s+files?\b", line)]
    files = [n for n in names if not n.endswith("/")]
    size = ZIP_OUT.stat().st_size
    required = [
        "WebPent_UNIFIED/pyproject.toml",
        "WebPent_UNIFIED/BUILD_INFO.json",
        "WebPent_UNIFIED/src/webpent/shared/http_discovery.py",
        "WebPent_UNIFIED/src/webpent/agents/access_control/agent.py",
        "WebPent_UNIFIED/src/webpent/cli/unified_hunt.py",
        "WebPent_UNIFIED/src/webpent/appmodel/models.py",
        "WebPent_UNIFIED/src/webpent/research/lifecycle_view.py",
        "WebPent_UNIFIED/src/webpent/research/hypothesis_lifecycle.py",
        "WebPent_UNIFIED/src/webpent/research/failure_taxonomy.py",
        "WebPent_UNIFIED/src/webpent/research/family_profiles.py",
        "WebPent_UNIFIED/scripts/pytest_accounting_plugin.py",
        "WebPent_UNIFIED/scripts/umdr37_production_campaigns.py",
        "WebPent_UNIFIED/scripts/umdr37_learning_ablation.py",
        "WebPent_UNIFIED/scripts/umdr37_full_loop_learning.py",
        "WebPent_UNIFIED/scripts/umdr37_discovery_efficiency.py",
        "WebPent_UNIFIED/scripts/regen_direct_io_inventory_umdr36_2_37.py",
        "WebPent_UNIFIED/tests/test_umdr37_root_cause_fixes.py",
        "WebPent_UNIFIED/tests/test_umdr37_learning_ablation.py",
        "WebPent_UNIFIED/tests/test_umdr36_2_accounting_plugin.py",
        "WebPent_UNIFIED/tests/test_umdr37_lifecycle_registry.py",
        "WebPent_UNIFIED/tests/test_umdr37_failure_taxonomy.py",
        "WebPent_UNIFIED/tests/test_umdr37_family_profiles.py",
        "WebPent_UNIFIED/tests/test_umdr37_component_influence.py",
        "WebPent_UNIFIED/tests/test_umdr37_decoy_closure.py",
        "WebPent_UNIFIED/docs/UMDR37_ROOT_CAUSE_REPORT.md",
        "WebPent_UNIFIED/docs/UMDR37_PRODUCTION_E2E_REPORT.md",
        "WebPent_UNIFIED/docs/UMDR37_VERIFICATION_REPORT.md",
        "WebPent_UNIFIED/docs/UMDR37_FAILURE_CLOSURE.json",
        "WebPent_UNIFIED/docs/UMDR37_DECOY_CLOSURE.json",
        "WebPent_UNIFIED/docs/UMDR37_FULL_LOOP_LEARNING.json",
        "WebPent_UNIFIED/docs/UMDR37_DISCOVERY_EFFICIENCY.json",
        "WebPent_UNIFIED/docs/UMDR37_READINESS.json",
        "WebPent_UNIFIED/docs/UMDR36_2_READINESS.json",
        "WebPent_UNIFIED/docs/FULL_SUITE_EVIDENCE.json",
        "WebPent_UNIFIED/artifacts/umdr37_production_campaigns.json",
        "WebPent_UNIFIED/artifacts/umdr37_decoy_exposure.json",
        "WebPent_UNIFIED/artifacts/umdr37_full_loop_learning.json",
        "WebPent_UNIFIED/UMDR36_2_37_DELIVERABLES/"
        "WebPent_Unified_mission-umdr36.2-umdr37.bundle",
        "WebPent_UNIFIED/UMDR36_2_37_DELIVERABLES/FILE_INDEX.txt",
    ]
    missing = [r for r in required if r not in files]
    leaked = [f for f in files if ".venv/" in f or "__pycache__/" in f]
    integrity = subprocess.run(
        ["unzip", "-t", str(ZIP_OUT)], capture_output=True, text=True,
        check=False).returncode
    print(f"zip: {ZIP_OUT.name}")
    print(f"size: {size:,} bytes ({size / 1e6:.1f} MB)")
    print(f"files: {len(files)} | required missing: {len(missing)} "
          f"| cache leaks: {len(leaked)} | integrity exit: {integrity}")
    if missing:
        print("MISSING:", missing)
        return 1
    if leaked or integrity != 0:
        return 1
    # copy the file index next to the zip for immediate reading
    shutil.copy2(dest / "FILE_INDEX.txt",
                 DL / "UMDR36_2_37_FILE_INDEX.txt")
    print("VERIFIED OK — index copied to download/UMDR36_2_37_FILE_INDEX.txt")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
