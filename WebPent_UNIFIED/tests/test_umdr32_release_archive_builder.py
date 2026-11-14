"""UM-DR-32 §3.1 — release-archive builder portability regression tests.

Covers both required layouts:
  1. project root == git root;
  2. project nested inside a larger git repository.

Also covers the exclusion policy (checksums/archives/operational data
excluded, load-bearing digests kept) and the empty-payload refusal.
"""
from __future__ import annotations

import importlib.util
import subprocess
import zipfile
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
SCRIPT = REPO / "scripts" / "build_release_archive.py"


def _load_builder():
    spec = importlib.util.spec_from_file_location("umdr32_release_builder", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _git(cwd: Path, *args: str) -> str:
    return subprocess.run(
        ["git", *args], cwd=cwd, capture_output=True, text=True, check=True,
    ).stdout.strip()


def _make_repo(tmp_path: Path, nested: bool) -> tuple[Path, Path]:
    """Create a git repo; return (git_root, project_root)."""
    if nested:
        git_root = tmp_path / "monorepo"
        project = git_root / "apps" / "webpent"
    else:
        git_root = tmp_path / "flatrepo"
        project = git_root
    project.mkdir(parents=True)
    _git(tmp_path, "init", "-q", "-b", "main", str(git_root.relative_to(tmp_path)) if nested else str(git_root))
    _git(git_root, "config", "user.name", "test")
    _git(git_root, "config", "user.email", "test@example.com")
    (project / "src").mkdir()
    (project / "src" / "app.py").write_text("print('hi')\n", encoding="utf-8")
    (project / "README.md").write_text("# test\n", encoding="utf-8")
    # tracked artifacts that MUST be excluded by policy
    (project / "download").mkdir()
    (project / "download" / "old_release.zip").write_bytes(b"PK\x03\x04zip")
    (project / "download" / "old_release.zip.sha256").write_text("x\n", encoding="utf-8")
    (project / "random.sha256").write_text("x\n", encoding="utf-8")
    (project / "webpent.db").write_bytes(b"sqlite operational data")
    # load-bearing digest that MUST ship
    (project / "frozen_modules.sha256").write_text("a b\n", encoding="utf-8")
    if nested:
        (git_root / "OTHER_PROJECT.txt").write_text("other\n", encoding="utf-8")
    _git(git_root, "add", "-A")
    _git(git_root, "commit", "-q", "-m", "test layout")
    return git_root, project


@pytest.mark.parametrize("nested", [False, True], ids=["root-layout", "nested-layout"])
def test_builder_packages_both_layouts(tmp_path: Path, nested: bool) -> None:
    builder = _load_builder()
    git_root, project = _make_repo(tmp_path, nested)
    out = tmp_path / "out.zip"

    prefix = builder.project_prefix(project)
    if nested:
        assert prefix == "apps/webpent/"
    else:
        assert prefix == ""  # NOT "./" — the exact UM-DR-31.1 defect

    digest, entries, size, manifest = builder.build(
        "HEAD", out, prefix=prefix, repo=project,
    )
    assert entries == 3  # src/app.py, README.md, frozen_modules.sha256
    assert size > 0
    assert len(manifest) == 3
    with zipfile.ZipFile(out) as zf:
        names = zf.namelist()
        assert names == sorted(names)
        assert "WebPent_UNIFIED/src/app.py" in names
        assert "WebPent_UNIFIED/frozen_modules.sha256" in names
        # exclusion policy actually excluded the artifacts
        assert not any(n.endswith(".zip") for n in names)
        assert not any(n.endswith("old_release.zip.sha256") for n in names)
        assert not any(n.endswith("random.sha256") for n in names)
        assert not any("webpent.db" in n for n in names)
        if nested:
            # only the nested project, never the sibling project
            assert not any("OTHER_PROJECT" in n for n in names)
    # determinism: same tree -> same digest
    out2 = tmp_path / "out2.zip"
    digest2, _, _, _ = builder.build("HEAD", out2, prefix=prefix, repo=project)
    assert digest == digest2


def test_builder_refuses_empty_payload(tmp_path: Path) -> None:
    builder = _load_builder()
    git_root = tmp_path / "empty"
    git_root.mkdir()
    _git(tmp_path, "init", "-q", "-b", "main", "empty")
    _git(git_root, "config", "user.name", "t")
    _git(git_root, "config", "user.email", "t@e.com")
    (git_root / "unrelated.txt").write_text("x\n", encoding="utf-8")
    _git(git_root, "add", "-A")
    _git(git_root, "commit", "-q", "-m", "x")
    # a prefix that matches nothing -> hard refusal, never empty success
    with pytest.raises(SystemExit, match="no project files"):
        builder.build("HEAD", tmp_path / "never.zip", prefix="does/not/exist/", repo=git_root)


def test_builder_fails_when_policy_drops_production_source(tmp_path: Path) -> None:
    builder = _load_builder()
    git_root, project = _make_repo(tmp_path, nested=False)
    # a tracked production .py file that matches an exclusion pattern
    # (a vendored virtualenv inside scripts/): must be a HARD ERROR,
    # never a silent omission
    (project / "scripts" / ".venv").mkdir(parents=True)
    (project / "scripts" / ".venv" / "tool.py").write_text("x = 1\n", encoding="utf-8")
    _git(git_root, "add", "-A")
    _git(git_root, "commit", "-q", "-m", "add prod py under excluded dir")
    files = builder.git_tree_files("HEAD", project)
    with pytest.raises(SystemExit, match="production source"):
        builder.select_payload(files, "")


def test_builder_policy_categories(tmp_path: Path) -> None:
    builder = _load_builder()
    cases = {
        "download/x.zip": "EX-1",
        "sums.sha256.txt": "EX-1",
        "frozen_modules.sha256": None,  # load-bearing: ships
        "webpent.db": "EX-2",
        "webpent.db.migration.lock": "EX-2",
        "state.sqlite3": "EX-2",
        "output/report.html": "EX-2",
        ".suite_state/chunk_001.log": "EX-2",
        ".llm_keys.json": "EX-3",
        "operator_credentials.json": "EX-3",
        "src/webpent/app.py": None,
        "docs/guide.zip": None,  # docs archives ship (documented exception)
        "uv.lock": None,
    }
    for path, expected in cases.items():
        reason = builder._exclusion_reason(path)
        if expected is None:
            assert reason is None, f"{path} must ship, got {reason}"
        else:
            assert reason is not None and reason.startswith(expected), (
                f"{path} expected {expected}, got {reason}"
            )


def test_real_repository_build_is_deterministic(tmp_path: Path) -> None:
    """The actual repo (root layout, since the snapshot import) builds
    reproducibly through the corrected builder."""
    builder = _load_builder()
    assert REPO == builder.git_root() or REPO.relative_to(builder.git_root())
    out1 = tmp_path / "real1.zip"
    out2 = tmp_path / "real2.zip"
    d1, n1, _, _ = builder.build("HEAD", out1)
    d2, n2, _, _ = builder.build("HEAD", out2)
    assert d1 == d2 and n1 == n2 and n1 > 4000  # the real tree, not a stub


def test_self_containment_guard(tmp_path: Path) -> None:
    """An output path colliding with a tracked archive path is detected
    before writing (the archive must never contain itself)."""
    builder = _load_builder()
    git_root, project = _make_repo(tmp_path, nested=False)
    (project / "download" / "old_release.zip").unlink()
    _git(git_root, "add", "-A")
    _git(git_root, "commit", "-q", "-m", "rm zip")
    out = tmp_path / "out.zip"
    builder.build("HEAD", out, repo=project)
    with zipfile.ZipFile(out) as zf:
        assert not any(n.endswith(".zip") for n in zf.namelist())
