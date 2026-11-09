#!/usr/bin/env python3
"""UM-DR-32 — canonical portable deterministic release-archive builder.

Supersedes and corrects ``scripts/build_release_archive_umdr31_1.py``
(the UM-DR-32 §3.1 portability remediation). The previous implementation
computed the project prefix as ``str(REPO.relative_to(GIT_ROOT)) + "/"``,
which yields ``"./"`` when the project root IS the Git root; ``git
ls-tree`` paths never start with ``./`` so the payload filter matched
nothing (the abort check caught it, but the builder was unusable for
root layouts).

Correctness contract (UM-DR-32 §3.1):

  * supports a project that IS the Git root AND a project nested inside
    a larger repository (the exact repo-relative prefix is computed
    from the resolved script location against ``git rev-parse``);
  * every payload byte is read from the selected immutable Git revision
    (``git ls-tree`` + ``git cat-file``), never from the working tree;
  * explicit, documented exclusion policy (below) — nothing is dropped
    silently, and any exclusion that would touch production source
    (src/scripts/tests) is a hard error, not an omission;
  * deterministic output: entries sorted by path, fixed 1980-01-01 zip
    epoch timestamps, deflate level 9, fixed 0644 attributes — the same
    tree at the same revision always yields the same SHA-256;
  * full post-build verification: re-opened, CRC-checked (testzip),
    entry count/order/duplicates checked, prefix checked, and the
    archive never contains itself.

Exclusion policy (tracked-tree categories, each with its reason):

  EX-1  generated release archives and checksum sidecars
        (``*.zip`` outside docs/, ``*.sha256``, ``*.sha256.txt`` except
        the load-bearing ``frozen_modules.sha256`` and the anchored
        evidence digests that ship with the tree) — a release archive
        must not contain itself or a stale digest of a different tree;
  EX-2  operational state (``webpent.db*``, ``*.sqlite3*``, lock files,
        ``output/``, ``artifacts/``, ``memory/global/``, ``.suite_state/``)
        — runtime/user data never belongs in a public archive;
  EX-3  private credentials (``.env.llm``, ``.llm_keys*.json``,
        ``.webpent_credentials*.json``, ``operator_credentials*.json``
        except the documented example) — secret safety;
  EX-4  local caches (``__pycache__``, ``.pytest_cache``,
        ``.ruff_cache``, ``.venv``) — machine-local, never shipped;
  EX-5  builder state (``.suite_state/``) — test-runner scratch.

Usage:
    python3 scripts/build_release_archive.py [--rev HEAD] [--output PATH]
"""
from __future__ import annotations

import argparse
import hashlib
import io
import subprocess
import zipfile
from pathlib import Path, PurePosixPath

REPO = Path(__file__).resolve().parent.parent
ZIP_EPOCH = (1980, 1, 1, 0, 0, 0)


def git_root(repo: Path | None = None) -> Path:
    out = subprocess.run(
        ["git", "rev-parse", "--show-toplevel"],
        cwd=repo or REPO, capture_output=True, text=True, check=True,
    )
    return Path(out.stdout.strip())


def project_prefix(repo: Path | None = None) -> str:
    """Exact repository-relative prefix for the project.

    ``""`` when the project IS the Git root; ``"sub/dir/"`` when the
    project is nested inside a larger repository. Never ``"./"``
    (the UM-DR-31.1 defect).
    """
    root = git_root(repo)
    repo = repo or REPO
    try:
        rel = repo.resolve().relative_to(root.resolve())
    except ValueError:  # script outside the repository — unusable
        raise SystemExit(f"ABORT: {repo} is not inside the git root {root}")
    if rel == Path("."):
        return ""
    return rel.as_posix().rstrip("/") + "/"


def git_tree_files(rev: str, repo: Path | None = None) -> list[str]:
    out = subprocess.run(
        ["git", "ls-tree", "-r", "--name-only", "-z", rev],
        cwd=git_root(repo), capture_output=True, text=False, check=True,
    ).stdout
    return sorted(p.decode("utf-8") for p in out.split(b"\0") if p)


# --- exclusion policy ------------------------------------------------------

# Anchored paths that MUST ship despite matching a checksum/archive pattern
# (the .gitignore mirrors this list; these are the documented exceptions).
_SHIP_ANYWAY = {
    "frozen_modules.sha256",
    "BASELINE.sha256.txt",
    "POST.sha256.txt",
    "TEAM1_AVI_V1_2_SOURCE_HASH.sha256.txt",
    "verification/evidence/BASELINE_AUTHORITY.sha256.txt",
}


def _exclusion_reason(rel: str) -> str | None:
    """Return the policy code for a tracked path, or None to include it.

    ``rel`` is the path relative to the PROJECT root (prefix stripped).
    """
    p = PurePosixPath(rel)
    name = p.name
    parts = p.parts
    # EX-1 generated archives + checksum sidecars
    if name.endswith((".sha256", ".sha256.txt")) and rel not in _SHIP_ANYWAY:
        return "EX-1 checksum sidecar"
    if name.endswith(".zip") and parts and parts[0] != "docs":
        return "EX-1 generated archive"
    # EX-2 operational state
    if name.startswith("webpent.db") or name.endswith((".sqlite3", ".sqlite3-wal", ".sqlite3-shm")):
        return "EX-2 operational database"
    if name.endswith(".lock") and name != "uv.lock":
        return "EX-2 runtime lock"
    if parts and parts[0] in {"output", "artifacts", ".suite_state"}:
        return "EX-2 runtime directory"
    if rel.startswith("memory/global/"):
        return "EX-2 derived global memory"
    # EX-3 private credentials
    if name.startswith((".llm_keys", ".webpent_credentials")):
        return "EX-3 private credential"
    if name == ".env.llm" or (name.startswith("operator_credentials") and name.endswith(".json")):
        return "EX-3 private credential"
    # EX-4 caches
    if "__pycache__" in parts or name in {".pytest_cache", ".ruff_cache", ".venv"}:
        return "EX-4 local cache"
    if ".venv" in parts:
        return "EX-4 local cache"
    return None


def select_payload(tree_files: list[str], prefix: str) -> list[tuple[str, str]]:
    """Map project-relative path -> exclusion reason (or None = include).

    Fails closed when an exclusion would touch production source.
    """
    payload: list[tuple[str, str]] = []
    production_violations: list[str] = []
    for f in tree_files:
        if not f.startswith(prefix):
            continue
        rel = f[len(prefix):]
        reason = _exclusion_reason(rel)
        if reason and (
            rel.startswith(("src/", "scripts/", "tests/"))
            and rel.endswith(".py")
        ):
            production_violations.append(f"{rel} ({reason})")
        payload.append((rel, reason or ""))
    if production_violations:
        raise SystemExit(
            "ABORT: exclusion policy would drop production source:\n  "
            + "\n  ".join(production_violations)
        )
    included = [rel for rel, why in payload if not why]
    if not included:
        raise SystemExit(
            f"ABORT: no project files included (prefix={prefix!r}, "
            f"tree={len(tree_files)} files) — refusing to emit an empty archive"
        )
    return payload


def read_blob(rev: str, git_path: str, repo: Path | None = None) -> bytes:
    return subprocess.run(
        ["git", "cat-file", "blob", f"{rev}:{git_path}"],
        cwd=git_root(repo), capture_output=True, check=True,
    ).stdout


def build(
    rev: str, output: Path, prefix: str | None = None, repo: Path | None = None,
    archive_prefix: str = "WebPent_UNIFIED/",
) -> tuple[str, int, int, list[dict]]:
    """Build the deterministic archive. Returns (sha256, entries, size, manifest)."""
    repo = repo or REPO
    prefix = project_prefix(repo) if prefix is None else prefix
    files = git_tree_files(rev, repo)
    payload = select_payload(files, prefix)
    included = [(rel, read_blob(rev, prefix + rel, repo)) for rel, why in payload if not why]

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED, compresslevel=9) as zf:
        for name, data in included:  # already sorted by path
            info = zipfile.ZipInfo(archive_prefix + name, date_time=ZIP_EPOCH)
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = 0o644 << 16
            zf.writestr(info, data)
    blob = buf.getvalue()
    output.write_bytes(blob)

    # Full post-build verification (§3.1 "verify the complete archive
    # contents"): CRC, order, duplicates, prefix, self-containment.
    with zipfile.ZipFile(output) as zf:
        bad = zf.testzip()
        if bad is not None:
            raise SystemExit(f"ABORT: CRC failure inside archive: {bad}")
        names = zf.namelist()
        if len(names) != len(included):
            raise SystemExit(
                f"ABORT: entry count mismatch {len(names)} != {len(included)}"
            )
        if names != sorted(names):
            raise SystemExit("ABORT: entries not in deterministic sorted order")
        if len(set(names)) != len(names):
            raise SystemExit("ABORT: duplicate entries in archive")
        for n in names:
            if not n.startswith(archive_prefix):
                raise SystemExit(f"ABORT: entry outside prefix: {n}")
        if str(output.resolve()) in {
            str((Path.cwd() / n).resolve()) for n in names
        }:
            raise SystemExit("ABORT: archive contains itself")
        manifest = [
            {"name": n, "size": i.file_size, "crc": hex(i.CRC)}
            for n, i in zip(names, zf.infolist())
        ]
    digest = hashlib.sha256(blob).hexdigest()
    return digest, len(included), len(blob), manifest


def main() -> int:
    parser = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--rev", default="HEAD", help="git revision to package")
    parser.add_argument(
        "--output", default=None,
        help="archive output path (default: download/WebPent_UNIFIED_<version>.zip)",
    )
    parser.add_argument(
        "--archive-prefix", default="WebPent_UNIFIED/",
        help="top-level directory inside the archive",
    )
    parser.add_argument(
        "--manifest", default=None,
        help="write the full entry manifest (JSON) to this path",
    )
    args = parser.parse_args()

    prefix = project_prefix()
    if args.output is None:
        import re
        pyproject = (REPO / "pyproject.toml").read_text(encoding="utf-8")
        m = re.search(r'^version\s*=\s*"([^"]+)"', pyproject, re.M)
        version = m.group(1) if m else "unknown"
        out = REPO / "download" / f"WebPent_UNIFIED_v{version}_UMDR32.zip"
    else:
        out = Path(args.output)
    out.parent.mkdir(parents=True, exist_ok=True)

    excluded_count = 0
    files = git_tree_files(args.rev)
    payload = select_payload(files, prefix)
    excluded_count = sum(1 for _, why in payload if why)

    digest, entries, size, manifest = build(
        args.rev, out, prefix=prefix, archive_prefix=args.archive_prefix,
    )
    if args.manifest:
        import json
        Path(args.manifest).write_text(
            json.dumps(manifest, indent=2), encoding="utf-8",
        )
    tree_sha = subprocess.run(
        ["git", "rev-parse", f"{args.rev}^{{tree}}"],
        cwd=git_root(), capture_output=True, text=True, check=True,
    ).stdout.strip()
    print(f"archive:          {out}")
    print(f"source rev:       {args.rev}")
    print(f"source tree sha:  {tree_sha}")
    print(f"project prefix:   {prefix or '(git root)'}")
    print(f"entries:          {entries} files (sorted, fixed timestamps)")
    print(f"excluded (policy):{excluded_count} tracked files")
    print(f"bytes:            {size}")
    print(f"sha256:           {digest}")
    (out.parent / (out.name + ".sha256")).write_text(
        f"{digest}  {out.name}\n", encoding="utf-8",
    )
    print(f"digest file:      {out.name}.sha256")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
