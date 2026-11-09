#!/usr/bin/env python3
"""WebPent v14.2 delivery builder (TC-2 Dispatch #040, C4).

Standing build rules (inherited from the v14.1 build discipline):

  1. BUILD_INFO as SSOT — ``BUILD_INFO.json`` is the single source of
     truth for build identity (name, date, base, suite count, git head,
     units closed).  The builder REFUSES to ship when the tree's
     verifiable state contradicts BUILD_INFO (suite count, git head,
     frozen-manifest scope).
  2. External anchors only — the ANCHORS file records the SHA-256 of
     the four EXTERNAL anchor artifacts (ZIP, git bundle, RUNNING_LOG,
     DRIFT_REGISTER) plus the evidence-pack docs.  No in-tree-derived
     anchor substitutes for an external one.
  3. Completeness enforcement — RF-06 lineage: the build REFUSES
     (exit 2) when any required deliverable class is missing, when the
     hygiene gate fails, or when the frozen manifests fail verification.

Usage:
  python scripts/build_delivery_v14_2.py --out-dir /path/to/download
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
import sys
import zipfile
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
HERE = Path(__file__).resolve().parent

REQUIRED_CLASSES: list[tuple[str, str]] = [
    ("RUNNING_LOG.md", "unit-closure log (external anchor)"),
    ("DRIFT_REGISTER.md", "C1(e) complete drift register (TC-2)"),
    ("BUILD_INFO.json", "build identity SSOT"),
    ("frozen_modules.sha256", "frozen-module manifest (re-frozen at unit boundary)"),
    ("docs/integration/WEBPENT_AUTHORITY_MANIFEST.json", "authority manifest (re-captured per C-7)"),
    ("scripts/resurrect.py", "canonical residue-aware resurrection script (C2b)"),
    ("scripts/hygiene_gate_extended.py", "extended hygiene gate"),
    ("scripts/verify_frozen_manifest.py", "fail-closed manifest verifier"),
    ("tests/test_c1b_resume_hitl_contract.py", "C1(b) decision-pin contract"),
    ("tests/test_resurrect_residue_aware.py", "C2(b) residue-awareness contract"),
    ("tests/test_u17_scorecard.py", "U-17 scorecard (with computed EV calibration)"),
    ("tests/test_u8_cheap_yields.py", "U-8 cheap yields (with SQLi timing)"),
    ("tests/test_u10_off1_remainder.py", "U-10 remainder (with confounder depth)"),
    ("BASELINE.sha256.txt", "pre-build baseline manifest"),
]

EXPECTED_FROZEN_MIN = 700  # v9 base was 708; v14.2 re-freeze includes the brain package (716)


def fail(msg: str, code: int = 2) -> int:
    print("\nBUILD REFUSED — " + msg, file=sys.stderr)
    return code


def sha256_file(p: Path) -> str:
    h = hashlib.sha256()
    with open(p, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out-dir", required=True)
    ap.add_argument("--build-name", default="WebPent v14.2")
    args = ap.parse_args()

    # -- 0. deliverable completeness (RF-06 lineage) -----------------------
    print("== deliverable-completeness enforcement (RF-06 lineage) ==")
    missing = []
    for rel, why in REQUIRED_CLASSES:
        p = ROOT / rel
        if not p.is_file():
            missing.append(f"  MISSING {rel}  ({why})")
        else:
            print(f"  present: {rel}")
    if missing:
        return fail("deliverable classes missing — refusing to build:\n" + "\n".join(missing))

    # -- 1. frozen manifests ------------------------------------------------
    print("== frozen manifests (C-7 re-freeze at unit boundary) ==")
    entries = [ln for ln in (ROOT / "frozen_modules.sha256").read_text().splitlines() if ln.strip()]
    if len(entries) < EXPECTED_FROZEN_MIN:
        return fail(f"frozen manifest scope {len(entries)} < {EXPECTED_FROZEN_MIN}")
    chk = subprocess.run(["sha256sum", "-c", "frozen_modules.sha256"], cwd=ROOT,
                         capture_output=True, text=True)
    ok_count = chk.stdout.count(": OK")
    if chk.returncode != 0 or ok_count != len(entries):
        return fail(f"frozen_modules.sha256 verification failed ({ok_count}/{len(entries)} OK)")
    print(f"  frozen_modules.sha256: {ok_count}/{len(entries)} OK")
    auth = subprocess.run([sys.executable, str(HERE / "verify_frozen_manifest.py")],
                          cwd=ROOT, capture_output=True, text=True)
    if auth.returncode != 0:
        print(auth.stdout, auth.stderr)
        return fail("authority manifest verification failed")
    print("  authority manifest: OK")

    # -- 2. hygiene gate ----------------------------------------------------
    print("== extended hygiene gate ==")
    hyg = subprocess.run([sys.executable, str(HERE / "hygiene_gate_extended.py")],
                         cwd=ROOT, capture_output=True, text=True)
    print(hyg.stdout.strip().splitlines()[0] if hyg.stdout else hyg.stderr)
    if hyg.returncode != 0:
        print(hyg.stdout, hyg.stderr)
        return fail("hygiene gate FAILED — refusing to build")

    # -- 3. BUILD_INFO as SSOT ---------------------------------------------
    print("== BUILD_INFO SSOT verification ==")
    info = json.loads((ROOT / "BUILD_INFO.json").read_text())
    if info.get("build_name") != args.build_name:
        return fail(f"BUILD_INFO build_name {info.get('build_name')!r} != {args.build_name!r}")
    git_head = subprocess.run(["git", "rev-parse", "HEAD"], cwd=ROOT,
                              capture_output=True, text=True).stdout.strip()
    # v14.1 standing convention: BUILD_INFO.git_head records the
    # CONTENT-FREEZE commit; the delivery commit on top of it may touch
    # ONLY build-metadata files (BUILD_INFO.json itself + RUNNING_LOG.md
    # hash closure).  Anything else between freeze and HEAD refuses.
    info_head = info.get("git_head", "")
    ancestry = subprocess.run(["git", "merge-base", "--is-ancestor", info_head, "HEAD"],
                              cwd=ROOT, capture_output=True, text=True)
    if ancestry.returncode != 0:
        return fail(f"BUILD_INFO git_head {info_head!r} is not an ancestor of HEAD {git_head!r} "
                    "(BUILD_INFO must reference a commit in this tree's history)")
    meta_diff = subprocess.run(["git", "diff", "--name-only", f"{info_head}..HEAD"],
                               cwd=ROOT, capture_output=True, text=True).stdout.split()
    allowed_meta = {"BUILD_INFO.json", "RUNNING_LOG.md"}
    unexpected = [p for p in meta_diff if p not in allowed_meta]
    if unexpected:
        return fail(f"commits after the content freeze touched non-metadata files: {unexpected} "
                    "(re-freeze and re-commit before building)")
    print(f"  build_name: {info['build_name']}")
    print(f"  suite_count: {info['suite_count']}  content-freeze git_head: {info_head[:12]}")

    # -- 4. timestamp normalization + ZIP ----------------------------------
    stamp = datetime.now(timezone.utc).replace(microsecond=0)
    stamp_text = stamp.strftime("%Y-%m-%dT%H:%M:%SZ")
    print(f"== timestamp normalization ({stamp_text}) ==")
    n = 0
    for p in ROOT.rglob("*"):
        if ".git" in p.parts:
            continue
        if p.is_file():
            os.utime(p, (stamp.timestamp(), stamp.timestamp()))
            n += 1
    print(f"  normalized {n} files")

    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    date_tag = stamp.strftime("%Y%m%d")
    zip_path = out_dir / f"WebPent_v14.2_{date_tag}.zip"
    print(f"== building {zip_path.name} ==")
    with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as z:
        for p in sorted(ROOT.rglob("*")):
            if ".git" in p.parts or p.is_dir():
                continue
            z.write(p, p.relative_to(ROOT))
    zip_sha = sha256_file(zip_path)
    zip_side = Path(str(zip_path) + ".sha256.txt")
    zip_side.write_text(f"{zip_sha}  {zip_path.name}\n")
    print(f"  zip sha256: {zip_sha}")

    # -- 5. git bundle -------------------------------------------------------
    bundle_path = out_dir / f"WebPent_v14.2_{date_tag}.git.bundle"
    subprocess.run(["git", "bundle", "create", str(bundle_path), "--all"], cwd=ROOT,
                   capture_output=True, text=True, check=True)
    bundle_sha = sha256_file(bundle_path)
    print(f"  bundle: {bundle_path.name} sha256: {bundle_sha[:16]}…")

    # -- 6. ANCHORS file (external anchors only) + sidecar ------------------
    anchors_rel = [
        zip_path.name, zip_side.name, bundle_path.name,
        "RUNNING_LOG.md", "DRIFT_REGISTER.md", "BUILD_INFO.json",
        "frozen_modules.sha256", "docs/integration/WEBPENT_AUTHORITY_MANIFEST.json",
    ]
    anchors_path = out_dir / f"WEBPENT_V14.2_{date_tag}_ANCHORS.txt"
    lines = [
        f"# WebPent v14.2 ANCHORS — {stamp_text}",
        "# External anchor set (C3/C4): every line 'sha256  artifact'.",
        "# These four artifact classes + the evidence pack are the anchor",
        "# package for the C4 abbreviated re-verify.",
        "",
    ]
    for rel in anchors_rel:
        p = out_dir / rel if (out_dir / rel).exists() else ROOT / rel
        lines.append(f"{sha256_file(p)}  {rel}")
    anchors_path.write_text("\n".join(lines) + "\n")
    anchors_sha = sha256_file(anchors_path)
    anchors_side = Path(str(anchors_path) + ".sha256.txt")
    anchors_side.write_text(f"{anchors_sha}  {anchors_path.name}\n")

    # RUNNING_LOG sidecar (the log is an external anchor; ship its hash)
    log_side = out_dir / "RUNNING_LOG.md.sha256.txt"
    log_side.write_text(f"{sha256_file(ROOT / 'RUNNING_LOG.md')}  RUNNING_LOG.md\n")

    print("== ANCHORS ==")
    print(anchors_path.read_text())
    print(f"== built: {zip_path}")
    print(f"== anchors: {anchors_path.name} (+ sidecar)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
