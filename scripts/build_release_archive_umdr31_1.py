#!/usr/bin/env python3
"""UM-DR-31.1 R1 — deterministic release-archive builder.

Builds the release candidate archive from the CURRENT git tree (not the
working dir) with reproducible output:
  * entries sorted by path;
  * fixed timestamps (1980-01-01 00:00:00 — the zip epoch);
  * explicit exclusions (nothing outside the tracked tree is included —
    the archive IS the git tree);
  * the same tree therefore always yields the same SHA-256.

Historical note (F01): the original v0.37.0 announcement digest
(607e17fa…) could never be independently verified because the archive
file was absent; a reconstructed archive (git archive of 2d7b928,
live-mtime packaging) necessarily hashes differently. A deterministic
builder makes this class of gap impossible going forward: the digest is
reproducible from the tagged commit.

Usage: python3 scripts/build_release_archive_umdr31_1.py [--output PATH]
"""
from __future__ import annotations

import argparse
import hashlib
import io
import subprocess
import sys
import zipfile
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
GIT_ROOT = Path(subprocess.run(
    ["git", "rev-parse", "--show-toplevel"],
    cwd=REPO, capture_output=True, text=True, check=True,
).stdout.strip())
SUBDIR = str(REPO.relative_to(GIT_ROOT)).replace("\\", "/") + "/"
PREFIX = "WebPent_UNIFIED/"
ZIP_EPOCH = (1980, 1, 1, 0, 0, 0)


def git_tree_files(rev: str) -> list[str]:
    out = subprocess.run(
        ["git", "ls-tree", "-r", "--name-only", "-z", rev],
        cwd=GIT_ROOT, capture_output=True, text=False, check=True,
    ).stdout
    return sorted(p.decode("utf-8") for p in out.split(b"\0") if p)


def build(rev: str, output: Path) -> tuple[str, int, int]:
    files = git_tree_files(rev)
    # the tracked tree of the deliverable subdirectory, re-rooted
    subdir = SUBDIR
    payload = [f for f in files if f.startswith(subdir)]
    if not payload:
        print(f"ABORT: no files under {subdir} at {rev}", file=sys.stderr)
        raise SystemExit(1)
    blobs: list[tuple[str, bytes]] = []
    for rel in payload:
        data = subprocess.run(
            ["git", "cat-file", "blob", f"{rev}:{rel}"],
            cwd=GIT_ROOT, capture_output=True, check=True,
        ).stdout
        blobs.append((rel[len(subdir):], data))

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED, compresslevel=9) as zf:
        for name, data in blobs:  # sorted by path
            info = zipfile.ZipInfo(PREFIX + name, date_time=ZIP_EPOCH)
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = 0o644 << 16
            zf.writestr(info, data)
    output.write_bytes(buf.getvalue())
    digest = hashlib.sha256(buf.getvalue()).hexdigest()
    return digest, len(blobs), len(buf.getvalue())


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--rev", default="HEAD", help="git rev to package")
    parser.add_argument("--output", default=str(REPO / "download" / "WebPent_UNIFIED_v0.37.1_UMDR31_1.zip"))
    args = parser.parse_args()
    out = Path(args.output)
    out.parent.mkdir(parents=True, exist_ok=True)
    digest, files, size = build(args.rev, out)
    print(f"archive: {out}")
    print(f"entries: {files} files (tracked tree at {args.rev}, sorted, fixed timestamps)")
    print(f"bytes:   {size}")
    print(f"sha256:  {digest}")
    (out.parent / (out.name + ".sha256")).write_text(f"{digest}  {out.name}\n")
    print(f"digest file: {out.name}.sha256")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
