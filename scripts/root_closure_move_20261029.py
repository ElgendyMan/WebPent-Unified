#!/usr/bin/env python3
"""Root-closure move (Track 0.1/7.2/7.4, RESIDUAL CLOSURE 2026-10-29).

Moves historical report/artifact files out of the project root into
``docs/archive/2026-10-28-root-artifacts/`` with an INDEX.md provenance
note, moves the legacy goed_v1_8* freeze dirs next to their documented
provenance (docs/archive/goed-v1.8.x already exists), and archives the
three legacy one-off scripts. Reference-checked: any file referenced by
tests/src/Makefile/CI/README with a load-bearing dependency stays (the
per-file reference scan runs before every move and aborts that move).
"""
from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DEST = ROOT / "docs" / "archive" / "2026-10-28-root-artifacts"

KEEP = {
    # active identity/config/tooling
    "README.md", "CHANGELOG.md", "DRIFT_REGISTER.md", "worklog.md",
    "pyproject.toml", "uv.lock", "Makefile", "install.sh", "entrypoint.sh",
    "webpent-cli.sh", "main.py", "server.py", "worker.py", "verify_all.py",
    "Dockerfile", "Dockerfile.base", "alembic.ini", ".gitignore",
    "requirements-runtime.txt", "credentials_template.json",
    "scope_template.yaml", "knowledge_sources.yaml", "BUILD_INFO.json",
    "invoice_route_static.json",
    # frozen-manifest machinery (gate reads baseline + orig)
    "frozen_modules.sha256", "frozen_modules.sha256.baseline_pre_unfreeze",
    "frozen_modules.sha256.orig",
}
KEEP_SUFFIXES = (".env.example", ".env.llm.example", ".env.minimal.example")

LEGACY_SCRIPTS = ["demo_refactor.py", "build_sprint_a_zip.py", "viewer.py"]
GOED_DIRS = ["goed_v1_8", "goed_v1_8_1", "goed_v1_8_2", "goed_v1_8_3", "goed_v1_8_4"]

SCAN_TARGETS = ["tests", "src", "scripts", "Makefile", ".github", "README.md", "docs/CURRENT_RELEASE.md"]


def referenced_elsewhere(name: str) -> list[str]:
    hits = []
    for target in SCAN_TARGETS:
        path = ROOT / target
        if path.is_file():
            args = ["grep", "-l", "-F", name, str(path)]
        else:
            args = ["grep", "-r", "-l", "-F", "--exclude-dir=__pycache__",
                    "--exclude-dir=.venv", "--exclude-dir=.ruff_cache",
                    name, str(path)]
        try:
            proc = subprocess.run(args, capture_output=True, text=True, timeout=120)
        except subprocess.TimeoutExpired:
            hits.append(target)
            continue
        if proc.returncode == 0 and proc.stdout.strip():
            for line in proc.stdout.strip().splitlines():
                rel = Path(line).resolve().relative_to(ROOT).as_posix()
                # references from inside the destination itself don't count
                if not rel.startswith("docs/archive/"):
                    hits.append(rel)
    return hits


def main() -> int:
    DEST.mkdir(parents=True, exist_ok=True)
    moved: list[str] = []
    held_back: list[tuple[str, str]] = []

    candidates = sorted(
        p.name for p in ROOT.iterdir()
        if p.is_file() and p.name not in KEEP
        and not p.name.startswith(".env")
        and p.suffix in {".md", ".json", ".txt"}
    )
    for name in candidates:
        refs = referenced_elsewhere(name)
        load_bearing = [
            r for r in refs
            if r.startswith("tests/") or r.startswith("src/") or r == "Makefile"
            or r.startswith(".github/")
        ]
        if load_bearing:
            held_back.append((name, ", ".join(load_bearing[:3])))
            continue
        shutil.move(str(ROOT / name), str(DEST / name))
        moved.append(name)

    for script in LEGACY_SCRIPTS:
        src = ROOT / script
        if src.is_file():
            refs = referenced_elsewhere(script)
            if any(r.startswith(("tests/", "src/")) or r == "Makefile" for r in refs):
                held_back.append((script, "referenced by active surface"))
                continue
            shutil.move(str(src), str(DEST / script))
            moved.append(script)

    goed_dest = ROOT / "docs" / "archive" / "2026-10-28-goed-v1.8-root-dirs"
    goed_dest.mkdir(parents=True, exist_ok=True)
    goed_moved = []
    for d in GOED_DIRS:
        src = ROOT / d
        if src.is_dir():
            refs = referenced_elsewhere(d)
            load_bearing = [r for r in refs if r.startswith(("tests/", "src/"))]
            if load_bearing:
                held_back.append((d, ", ".join(load_bearing[:2])))
                continue
            shutil.move(str(src), str(goed_dest / d))
            goed_moved.append(d)

    index_lines = [
        "# Root artifacts archive — moved 2026-10-29",
        "",
        "Track 0.1 (Repository organization) of WEBPENT_UNIFIED_MASTER_ROADMAP:",
        "the project root was carrying ~95 historical report/artifact files",
        "alongside the active tree. They were reference-checked (tests, src,",
        "Makefile, CI, README) and moved here UNMODIFIED; their findings and",
        "numbers are snapshots of their dates and are superseded by",
        "CHANGELOG.md (the single active release log) and DRIFT_REGISTER.md",
        "(the single active deviations register).",
        "",
        f"## Files ({len(moved)})",
        "",
    ]
    index_lines += [f"- `{name}`" for name in moved]
    index_lines += ["", f"## Legacy root dirs ({len(goed_moved)})", ""]
    index_lines += [
        "- `goed_v1_8*` moved to `docs/archive/2026-10-28-goed-v1.8-root-dirs/` — "
        "provenance freeze dirs of the GOED v1.8.x line; their canonical "
        "manifests already live under docs/archive/goed-v1.8.*/."
    ]
    if held_back:
        index_lines += ["", "## Held back (referenced by an active surface)", ""]
        index_lines += [f"- `{name}` — {why}" for name, why in held_back]
    (DEST / "INDEX.md").write_text("\n".join(index_lines) + "\n", encoding="utf-8")

    (goed_dest / "README.md").write_text(
        "\n".join(
            [
                "# goed_v1_8* — root freeze dirs (archived 2026-10-29)",
                "",
                "Track 7.2: legacy model-eval/freeze directories that still sat in",
                "the project root after their canonical provenance was already",
                "archived under `docs/archive/goed-v1.8.*/`. Excluded from the",
                "package build by construction (src/-scoped packaging) and now out",
                "of the lint surface too. No source file imports them (verified by",
                "the same reference scan that performed this move).",
                "",
            ]
        ),
        encoding="utf-8",
    )
    print(f"moved files: {len(moved)}; goed dirs: {len(goed_moved)}; held back: {len(held_back)}")
    for name, why in held_back:
        print(f"  HELD BACK {name}: {why}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
