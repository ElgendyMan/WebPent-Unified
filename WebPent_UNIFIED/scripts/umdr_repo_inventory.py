#!/usr/bin/env python3
"""Repository rationalization — the measured inventory (UM-DR Phase B).

Read-only: measures the actual checkout, the tracked tree, the git
object database, exact duplicates, bundles, and the known size
contributors. Every cleanup candidate carries its evidence.
"""
from __future__ import annotations

import hashlib
import json
import subprocess
import sys
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
PUB = Path(__file__).resolve().parents[2]
DELIV = PUB / "deliverables" / "repository-rationalization"


def _git(args: list[str], cwd: Path = PUB) -> str:
    r = subprocess.run(["git", *args], cwd=cwd, capture_output=True,
                       text=True)
    return r.stdout.strip() if r.returncode == 0 else ""


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def _du(path: Path) -> int:
    try:
        return int(subprocess.run(["du", "-sb", str(path)],
                                  capture_output=True, text=True)
                   .stdout.split()[0])
    except Exception:
        return 0


def main() -> int:
    now = datetime.now(timezone.utc).isoformat()
    tracked = [PUB / p for p in
               _git(["ls-files"]).splitlines() if p]
    total_tracked = sum(p.stat().st_size for p in tracked
                        if p.is_file())
    by_ext = Counter(p.suffix or "(none)" for p in tracked)
    largest = sorted(
        ({"path": str(p), "bytes": p.stat().st_size}
         for p in tracked if p.is_file()),
        key=lambda x: -x["bytes"])[:100]

    dir_sizes: dict[str, int] = defaultdict(int)
    for p in tracked:
        if p.is_file():
            dir_sizes[str(p.parent)] += p.stat().st_size
    largest_dirs = sorted(
        ({"dir": d, "tracked_bytes": b} for d, b in
         dir_sizes.items()),
        key=lambda x: -x["tracked_bytes"])[:25]

    # exact duplicates among tracked files (grouped by size+digest)
    hash_groups: dict[str, list[str]] = defaultdict(list)
    size_groups: dict[int, list[str]] = defaultdict(list)
    for p in tracked:
        if p.is_file() and p.stat().st_size > 4096:
            size_groups[p.stat().st_size].append(str(p))
    dup_sets = []
    for size, paths in size_groups.items():
        if len(paths) < 2:
            continue
        for path in paths:
            hash_groups[_sha256(Path(path))].append(path)
    for digest, paths in hash_groups.items():
        if len(paths) > 1:
            dup_sets.append({"sha256": digest, "bytes": size,
                             "paths": sorted(paths)})

    # bundles
    bundles = []
    for b in sorted(PUB.rglob("*.bundle")):
        rel = b.relative_to(PUB)
        verify = subprocess.run(
            ["git", "bundle", "verify", str(b)], cwd=PUB,
            capture_output=True, text=True)
        heads = _git(["bundle", "list-heads", str(b)])
        # which bundle commits are reachable from the current clone?
        unique = []
        if verify.returncode == 0:
            head_shas = [line.split()[0] for line in
                         heads.splitlines() if line]
            for hs in head_shas:
                rc = subprocess.run(
                    ["git", "cat-file", "-e", f"{hs}^{{commit}}"],
                    cwd=PUB, capture_output=True).returncode
                if rc != 0:
                    unique.append(hs)
        bundles.append({
            "path": str(rel), "bytes": b.stat().st_size,
            "sha256": _sha256(b),
            "verify_rc": verify.returncode,
            "heads": heads,
            "head_commits_unreachable_in_clone": unique,
        })

    empty_dirs = [str(d.relative_to(PUB)) for d in PUB.rglob("*")
                  if d.is_dir() and not any(d.iterdir())
                  and ".git" not in d.parts]

    # the known named contributors, measured
    named = {}
    for rel in [
        "deliverables/umdr38/test_evidence/coverage_last_run.json",
        "WebPent_UNIFIED/docs/history/UMDR37_COVERAGE_LAST_RUN.json",
        "WebPent_UNIFIED/docs/coverage_measured_baseline_0260.json",
        "WebPent_UNIFIED/UMDR36_2_37_DELIVERABLES/"
        "WebPent_Unified_mission-umdr36.2-umdr37.bundle",
        "WebPent_Unified_umdr38.bundle",
    ]:
        p = PUB / rel
        named[rel] = ({"bytes": p.stat().st_size,
                       "sha256": _sha256(p)} if p.is_file()
                      else "MISSING")

    # duplicate candidate groups by name (across the tree)
    by_name = defaultdict(list)
    for p in tracked:
        by_name[p.name].append(str(p))
    name_dupes = {name: sorted(paths) for name, paths in
                  by_name.items()
                  if len(paths) > 1 and name in {
                      "TEAM1_AVI_V1_2_100_DECISION_RUNTIME.json",
                      "payload_library.json", "wstg_catalog.json",
                      "FULL_SUITE_POSTFIX_RESULT.txt",
                      "hunter_state.json", "SHA256SUMS"}}

    # big files > 1MB
    big = [{"path": str(p), "bytes": p.stat().st_size}
           for p in tracked if p.is_file()
           and p.stat().st_size > 1_000_000]

    inventory = {
        "schema": "repository-rationalization-inventory/v1",
        "generated_at_utc": now,
        "generated_at_revision": _git(["rev-parse", "HEAD"]),
        "checkout_bytes": _du(PUB),
        "checkout_bytes_note":
            "includes the gitignored local build environment "
            "(.venv ~6.2 GB) — see tracked_bytes for the tracked "
            "payload",
        "git_dir_bytes": _du(PUB / ".git"),
        "local_venv_bytes": _du(REPO / ".venv"),
        "tracked_file_count": len(tracked),
        "tracked_bytes": total_tracked,
        "files_by_extension_top20":
            dict(by_ext.most_common(20)),
        "largest_100_files": largest,
        "largest_directories_top25": largest_dirs,
        "exact_duplicate_sets": dup_sets,
        "exact_duplicate_wasted_bytes":
            sum(d["bytes"] * (len(d["paths"]) - 1)
                for d in dup_sets),
        "bundles": bundles,
        "empty_directories": empty_dirs,
        "files_over_1MB": big,
        "named_contributors": named,
        "duplicate_candidate_groups_by_name": name_dupes,
        "count_objects": _git(["count-objects", "-vH"]).replace(
            "\n", "; "),
    }
    DELIV.mkdir(parents=True, exist_ok=True)
    out = DELIV / "REPOSITORY_INVENTORY.json"
    out.write_text(json.dumps(inventory, indent=2) + "\n",
                   encoding="utf-8")
    print(f"[inventory] {out}")

    dup_wasted = inventory["exact_duplicate_wasted_bytes"]
    lines = [
        "# Repository Inventory (measured)",
        "",
        f"Generated {now} at `{inventory['generated_at_revision'][:12]}`.",
        "",
        f"* Tracked files: **{len(tracked):,}** "
        f"({total_tracked / 1e6:.1f} MB tracked payload).",
        f"* Checkout (du): {inventory['checkout_bytes'] / 1e6:.0f} MB; "
        f"git object DB: {inventory['git_dir_bytes'] / 1e6:.0f} MB.",
        f"* Exact-duplicate sets: **{len(dup_sets)}** "
        f"({dup_wasted / 1e6:.1f} MB redundant copies in the tree).",
        f"* Files > 1 MB: {len(big)}.",
        f"* Empty directories: {len(empty_dirs)}.",
        "",
        "## Largest directories (tracked bytes)",
        "",
        "| dir | tracked MB |",
        "|---|---|",
    ]
    for d in largest_dirs[:12]:
        lines.append(f"| {d['dir']} | {d['tracked_bytes'] / 1e6:.1f} |")
    lines += ["", "## Bundles", ""]
    for b in bundles:
        lines.append(
            f"* `{b['path']}` — {b['bytes'] / 1e6:.1f} MB, "
            f"verify rc={b['verify_rc']}, heads: "
            f"`{b['heads'].replace(chr(10), ' · ')[:120]}`, "
            f"unreachable-in-clone heads: "
            f"{b['head_commits_unreachable_in_clone'] or 'NONE'}")
    lines += ["", "## Exact duplicate sets (top 15 by waste)", ""]
    for d in sorted(dup_sets, key=lambda x: -x["bytes"])[:15]:
        lines.append(f"* **{d['bytes'] / 1e6:.2f} MB** ×"
                     f"{len(d['paths'])} — " +
                     "; ".join(f"`{p}`" for p in d["paths"][:4]))
    lines += ["", "## Named duplicate-candidate groups", ""]
    for name, paths in name_dupes.items():
        lines.append(f"* `{name}`: {len(paths)} copies")
    (DELIV / "REPOSITORY_INVENTORY.md").write_text(
        chr(10).join(lines) + "\n", encoding="utf-8")
    print(f"[inventory] {DELIV / 'REPOSITORY_INVENTORY.md'}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
