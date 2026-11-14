#!/usr/bin/env python3
"""M2 STANDING GATES (Dispatch #009, G2 rider R3 — manifest-vs-HEAD).

Permanent drift detector, carried from the RED-2 P-7 advisory. Two checks,
both fail-closed:

  manifest-vs-head   the frozen manifest committed at HEAD must be
                     byte-identical to the working-tree manifest, AND every
                     manifest-pinned file must be byte-identical between
                     HEAD's committed tree and the working tree. Any
                     uncommitted drift to a frozen file, or any manifest
                     regeneration not paired with a commit, is RED.

  anchor             the working-tree manifest digest must equal the anchor
                     recorded in scripts/m2_anchor_record.json (written at
                     re-freeze; before re-freeze the record holds the v7
                     baseline digest, so any mid-window manifest edit is
                     caught immediately).

Usage:
  python scripts/m2_standing_gates.py manifest-vs-head
  python scripts/m2_standing_gates.py anchor

Exit 0 = green; exit 1 = RED (STOP and escalate). This gate is STANDING:
it runs after the window (via CI/battery composition) and never disabled.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "frozen_modules.sha256"
ANCHOR_RECORD = ROOT / "scripts" / "m2_anchor_record.json"

V7_MANIFEST_SHA256 = "33885034a9da3d945c66ff67c00fcec23d8aaede778414dd74281adda32b2a33"


def _fail(msg: str) -> int:
    print("\nSTANDING GATE RED\n" + "=" * 72)
    print(msg)
    return 1


def _git(*args: str) -> str:
    return subprocess.run(
        ["git", *args], cwd=ROOT, capture_output=True, text=True, check=True
    ).stdout


def check_manifest_vs_head() -> int:
    if not MANIFEST.exists():
        return _fail("frozen_modules.sha256 missing from working tree")
    worktree_manifest = MANIFEST.read_bytes()
    try:
        head_manifest = subprocess.run(
            ["git", "show", f"HEAD:{MANIFEST.relative_to(ROOT).as_posix()}"],
            cwd=ROOT, capture_output=True, check=True,
        ).stdout
    except subprocess.CalledProcessError:
        return _fail("frozen_modules.sha256 is NOT committed at HEAD — "
                     "commit the manifest so drift is detectable")
    if head_manifest != worktree_manifest:
        return _fail("manifest drift: working-tree frozen_modules.sha256 "
                     "differs from HEAD. Regeneration must be paired with a "
                     "documented re-freeze commit, never left uncommitted.")
    entries = [
        ln for ln in worktree_manifest.decode("utf-8", "replace").splitlines()
        if ln.strip()
    ]
    drifted = []
    missing = []
    for ln in entries:
        sha, _, relpath = ln.partition("  ")
        if not relpath:
            sha, _, relpath = ln.partition(" *")
        relpath = relpath.strip()
        try:
            head_bytes = subprocess.run(
                ["git", "show", f"HEAD:{relpath}"],
                cwd=ROOT, capture_output=True, check=True,
            ).stdout
        except subprocess.CalledProcessError:
            missing.append(relpath)
            continue
        disk = (ROOT / relpath).read_bytes() if (ROOT / relpath).exists() else b""
        if hashlib.sha256(disk).hexdigest() != sha:
            if hashlib.sha256(head_bytes).hexdigest() != sha:
                drifted.append(relpath + " (HEAD AND worktree differ from pin)")
            else:
                drifted.append(relpath + " (worktree differs from pin; uncommitted)")
        elif hashlib.sha256(head_bytes).hexdigest() != sha:
            drifted.append(relpath + " (HEAD differs from pin)")
    if missing:
        return _fail(f"{len(missing)} manifest-pinned files missing on disk "
                     f"(first 5: {missing[:5]})")
    if drifted:
        return _fail(f"{len(drifted)} frozen files drifted from their pin "
                     f"(first 5: {drifted[:5]})")
    print(f"[manifest-vs-head] OK — {len(entries)} pinned files byte-identical "
          "HEAD<->worktree<->pin")
    return 0


def check_anchor() -> int:
    if not MANIFEST.exists():
        return _fail("frozen_modules.sha256 missing")
    digest = hashlib.sha256(MANIFEST.read_bytes()).hexdigest()
    # Dispatch #009-A (reopened window): the v9 re-freeze anchor lives in
    # scripts/m2a_anchor_record.json. It takes precedence when the manifest
    # matches it; otherwise the original record governs.
    reopen_record_path = ROOT / "scripts" / "m2a_anchor_record.json"
    if reopen_record_path.exists():
        reopen = json.loads(reopen_record_path.read_text())
        v9 = reopen.get("v9_refreeze_manifest_sha256")
        if v9 and digest == v9:
            print(f"[anchor] OK — manifest digest == reopened-window v9 anchor "
                  f"({digest[:16]}…, Dispatch #009-A)")
            return 0
    if not ANCHOR_RECORD.exists():
        # Pre-refreeze: the record file is written at G2; if absent, assert
        # the v7 baseline anchor directly.
        if digest != V7_MANIFEST_SHA256:
            return _fail(f"manifest digest {digest} != v7 baseline anchor "
                         f"{V7_MANIFEST_SHA256} (and no re-freeze record exists)")
        print(f"[anchor] OK — manifest digest == v7 baseline anchor "
              f"({digest[:16]}…)")
        return 0
    record = json.loads(ANCHOR_RECORD.read_text())
    expected = record.get("manifest_sha256")
    if digest != expected:
        return _fail(f"manifest digest {digest} != recorded anchor {expected}")
    print(f"[anchor] OK — manifest digest == recorded anchor ({digest[:16]}…, "
          f"recorded {record.get('recorded_at', '?')})")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("gate", choices=["manifest-vs-head", "anchor"])
    args = ap.parse_args()
    if args.gate == "manifest-vs-head":
        return check_manifest_vs_head()
    return check_anchor()


if __name__ == "__main__":
    sys.exit(main())
