"""UM-DR-38.1 Phase 1.3 — workflow discovery tests.

These tests pin the ROOT git-tree paths and explicitly FORBID the
nested-location fallback: a workflow that exists ONLY under
WebPent_UNIFIED/.github/workflows/ does NOT satisfy discovery (GitHub
discovers workflows only at the repository root), and the nested copy
must not shadow the canonical one.
"""
from __future__ import annotations

import subprocess
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]          # WebPent_UNIFIED
PUB = REPO.parent                                    # repository root


def _git(args: list[str]) -> str:
    r = subprocess.run(["git", *args], cwd=PUB, capture_output=True,
                       text=True, check=False)
    return r.stdout if r.returncode == 0 else ""


def _tree_has(path: str) -> bool:
    return bool(_git(["ls-tree", "--name-only", "HEAD", "--", path]).strip())


def test_root_readme_exists_in_git_tree() -> None:
    assert _tree_has("README.md"), (
        "the repository root must carry a real README.md in the GIT "
        "TREE — not only inside WebPent_UNIFIED/")


def test_root_workflows_exist_in_git_tree() -> None:
    for name in ("ci.yml", "nightly.yml", "weekly-benchmarks.yml"):
        assert _tree_has(f".github/workflows/{name}"), (
            f".github/workflows/{name} must exist at the REPOSITORY "
            "ROOT in the git tree — the only location GitHub discovers")


def test_nested_workflows_do_not_shadow_the_canonical_ones() -> None:
    nested = _git(["ls-tree", "-r", "--name-only", "HEAD", "--",
                   "WebPent_UNIFIED/.github/"])
    assert not nested.strip(), (
        "WebPent_UNIFIED/.github must not carry workflow copies that "
        "shadow the canonical root workflows — the published tree had "
        "them nested where GitHub cannot discover them")


def test_working_tree_matches_the_tree_for_root_artifacts() -> None:
    for path in ("README.md", ".github/workflows/ci.yml",
                 ".github/workflows/nightly.yml",
                 ".github/workflows/weekly-benchmarks.yml"):
        assert (PUB / path).is_file(), (
            f"the checked-out working tree must contain {path} at the "
            "repository root")


def test_root_readme_is_not_the_project_readme() -> None:
    root = (PUB / "README.md").read_text(encoding="utf-8")
    project = (REPO / "README.md").read_text(encoding="utf-8")
    assert root != project, (
        "the root README must be a repository entrypoint, not a silent "
        "copy of the project README")
    assert "WebPent_UNIFIED/" in root, (
        "the root README must state that the actual code lives inside "
        "WebPent_UNIFIED/")
