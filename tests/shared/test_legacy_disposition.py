"""FEATURE_PROPOSALS ق9 — legacy disposition (absorb or archive, no gray zone).

Pins:
  * exactly THREE dispositions per module — absorbed / archive / review
    — and review ALWAYS carries a deadline release, so the gray zone
    cannot become permanent,
  * absorption evidence is an AST scan of the ACTIVE tree only
    (tests/docs/archive/scripts/benchmarks never count as importers;
    the module is never its own importer; relative imports resolve),
  * the two-release rule runs on RECORDED history (LegacyRegistry):
    a module with no active importer for >= grace (2) recorded releases
    is archived; unknown provenance starts the clock at review, never a
    surprise archive,
  * the registry persists atomically, refuses invalid shapes on load,
    and records each release in which an import was observed,
  * archive_plan() computes move targets only — no import-time side
    effects, no silent deletions.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from webpent.shared.legacy_disposition import (
    LegacyRegistry,
    archive_plan,
    classify,
    find_importers,
)

RELEASES = ["0.33.0", "0.34.0", "0.35.0"]


@pytest.fixture()
def tree(tmp_path: Path) -> Path:
    """A miniature src/ tree: webpent package with three legacy modules."""
    src = tmp_path / "src"
    pkg = src / "webpent"
    (pkg / "shared").mkdir(parents=True)
    (pkg / "legacy_a.py").write_text("X = 1\n", encoding="utf-8")
    (pkg / "legacy_b.py").write_text("Y = 2\n", encoding="utf-8")
    (pkg / "legacy_c.py").write_text("Z = 3\n", encoding="utf-8")
    (pkg / "shared" / "__init__.py").write_text("", encoding="utf-8")
    # active code imports legacy_a only (absorbed)
    (pkg / "engine.py").write_text(
        "from webpent.legacy_a import X\n", encoding="utf-8"
    )
    # tests/ import legacy_b — but tests are NOT active code
    tests = tmp_path / "tests"
    tests.mkdir()
    (tests / "test_b.py").write_text(
        "import webpent.legacy_b\n", encoding="utf-8"
    )
    return src


def _registry(tmp_path: Path, **seed) -> LegacyRegistry:
    registry = LegacyRegistry(tmp_path / "legacy_registry.json")
    for module, releases in seed.items():
        for release in releases:
            registry.record_import(module, release)
    return registry


# ---------------------------------------------------------------------------
# find_importers — the absorption evidence
# ---------------------------------------------------------------------------


def test_active_importer_found_but_not_tests_or_self(tree) -> None:
    assert find_importers("webpent.legacy_a", src_root=tree) == [
        "src/webpent/engine.py"
    ]
    # legacy_b is imported ONLY from tests/ → no ACTIVE importers
    assert find_importers("webpent.legacy_b", src_root=tree) == []
    assert find_importers("webpent.legacy_c", src_root=tree) == []


def test_path_and_parent_package_forms_match(tree) -> None:
    # path form and parent-package import form resolve to the same verdict
    (tree / "webpent" / "engine2.py").write_text(
        "from webpent import legacy_a\n", encoding="utf-8"
    )
    importers = find_importers("src/webpent/legacy_a.py", src_root=tree)
    assert "src/webpent/engine.py" in importers
    assert "src/webpent/engine2.py" in importers


def test_relative_imports_resolve(tree) -> None:
    (tree / "webpent" / "shared" / "user.py").write_text(
        "from ..legacy_c import Z\n", encoding="utf-8"
    )
    assert "src/webpent/shared/user.py" in find_importers(
        "webpent.legacy_c", src_root=tree
    )


def test_empty_and_foreign_names_match_nothing(tree) -> None:
    assert find_importers("", src_root=tree) == []
    assert find_importers("otherpkg.module", src_root=tree) == []


# ---------------------------------------------------------------------------
# classify — the three dispositions
# ---------------------------------------------------------------------------


def test_absorbed_module_records_current_release(tree, tmp_path) -> None:
    registry = _registry(tmp_path)
    dispositions = classify(
        legacy_modules=["webpent.legacy_a"],
        src_root=tree,
        releases=RELEASES,
        registry=registry,
    )
    assert dispositions[0].disposition == "absorbed"
    assert dispositions[0].importers
    assert registry.imported_releases("webpent.legacy_a") == ["0.35.0"]
    registry.save()
    saved = json.loads((tmp_path / "legacy_registry.json").read_text(encoding="utf-8"))
    assert saved["webpent.legacy_a"] == ["0.35.0"]


def test_two_releases_unimported_archives(tree, tmp_path) -> None:
    # legacy_c was imported in 0.33.0 only; two releases have passed
    registry = _registry(tmp_path, **{"webpent.legacy_c": ["0.33.0"]})
    dispositions = classify(
        legacy_modules=["webpent.legacy_c"],
        src_root=tree,
        releases=RELEASES,
        registry=registry,
    )
    assert dispositions[0].disposition == "archive"
    assert dispositions[0].releases_since_import == 2
    assert "grace=2" in dispositions[0].rule


def test_one_release_unimported_is_review_with_deadline(tree, tmp_path) -> None:
    registry = _registry(tmp_path, **{"webpent.legacy_c": ["0.34.0"]})
    dispositions = classify(
        legacy_modules=["webpent.legacy_c"],
        src_root=tree,
        releases=RELEASES,
        registry=registry,
    )
    assert dispositions[0].disposition == "review"
    assert dispositions[0].releases_since_import == 1
    # deadline is projected one release beyond the current lineage end
    assert dispositions[0].deadline_release == "0.35.1"


def test_unknown_provenance_starts_at_review_not_archive(tree, tmp_path) -> None:
    registry = _registry(tmp_path)
    dispositions = classify(
        legacy_modules=["webpent.legacy_b"],
        src_root=tree,
        releases=RELEASES,
        registry=registry,
    )
    assert dispositions[0].disposition == "review"
    assert dispositions[0].releases_since_import == 0


def test_grace_releases_configurable(tree, tmp_path) -> None:
    registry = _registry(tmp_path, **{"webpent.legacy_c": ["0.34.0"]})
    dispositions = classify(
        legacy_modules=["webpent.legacy_c"],
        src_root=tree,
        releases=RELEASES,
        registry=registry,
        grace_releases=3,
    )
    assert dispositions[0].disposition == "review"
    assert dispositions[0].deadline_release == "0.35.2"


def test_absorption_later_in_history_persists(tree, tmp_path) -> None:
    # imported in 0.33.0 AND now: the registry accumulates, verdict absorbed
    registry = _registry(tmp_path, **{"webpent.legacy_a": ["0.33.0"]})
    classify(
        legacy_modules=["webpent.legacy_a"],
        src_root=tree,
        releases=RELEASES,
        registry=registry,
    )
    assert registry.imported_releases("webpent.legacy_a") == ["0.33.0", "0.35.0"]


def test_classify_requires_lineage(tree, tmp_path) -> None:
    registry = _registry(tmp_path)
    with pytest.raises(ValueError):
        classify(
            legacy_modules=["webpent.legacy_a"],
            src_root=tree,
            releases=[],
            registry=registry,
        )


# ---------------------------------------------------------------------------
# registry — persistence + fail-closed load
# ---------------------------------------------------------------------------


def test_registry_round_trip_and_atomic_write(tmp_path) -> None:
    path = tmp_path / "reg" / "legacy_registry.json"
    registry = LegacyRegistry(path)
    registry.record_import("webpent.x", "0.33.0")
    registry.record_import("webpent.x", "0.34.0")
    registry.record_import("webpent.x", "0.34.0")  # dedup
    registry.save()
    again = LegacyRegistry(path)
    assert again.imported_releases("webpent.x") == ["0.33.0", "0.34.0"]
    assert again.modules() == ["webpent.x"]
    assert not list(path.parent.glob("*.tmp"))  # atomic rename, no residue


def test_registry_refuses_invalid_shape(tmp_path) -> None:
    path = tmp_path / "legacy_registry.json"
    path.write_text(json.dumps({"webpent.x": "not-a-list"}), encoding="utf-8")
    with pytest.raises(ValueError):
        LegacyRegistry(path)
    path.write_text("[1,2,3]", encoding="utf-8")
    with pytest.raises(ValueError):
        LegacyRegistry(path)
    path.write_text("{broken", encoding="utf-8")
    with pytest.raises(ValueError):
        LegacyRegistry(path)


def test_missing_registry_file_is_empty(tmp_path) -> None:
    registry = LegacyRegistry(tmp_path / "absent.json")
    assert registry.modules() == []
    assert registry.imported_releases("webpent.x") == []


# ---------------------------------------------------------------------------
# archive_plan — computed moves only
# ---------------------------------------------------------------------------


def test_archive_plan_targets_only_archived_modules(tree, tmp_path) -> None:
    registry = _registry(
        tmp_path, **{"webpent.legacy_c": ["0.33.0"], "webpent.legacy_b": ["0.34.0"]}
    )
    dispositions = classify(
        legacy_modules=["webpent.legacy_a", "webpent.legacy_b", "webpent.legacy_c"],
        src_root=tree,
        releases=RELEASES,
        registry=registry,
    )
    plan = archive_plan(dispositions, window="2026-11-04")
    assert len(plan) == 1
    entry = plan[0]
    assert entry["module"] == "webpent.legacy_c"
    assert entry["source"] == "src/webpent/legacy_c.py"
    assert entry["destination"] == "docs/archive/2026-11-04-legacy/src/webpent/legacy_c.py"
    # the plan never touches the tree
    assert (tree / "webpent" / "legacy_c.py").exists()


def test_archive_plan_accepts_path_form_modules(tmp_path) -> None:
    from webpent.shared.legacy_disposition import LegacyDisposition

    disposition = LegacyDisposition(
        module="src/webpent/old_thing.py",
        disposition="archive",
        rule="two releases unimported",
    )
    plan = archive_plan([disposition], window="w1")
    assert plan[0]["source"] == "src/webpent/old_thing.py"
    assert plan[0]["destination"].endswith("src/webpent/old_thing.py")
