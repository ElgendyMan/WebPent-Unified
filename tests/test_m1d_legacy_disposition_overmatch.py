"""M1-D (UM-DR-12) regression: ق9 legacy-disposition engine over-match fix.

The first documented operator run of the ق9 engine over the M0-verified
dead clusters classified EVERY module ``absorbed`` on fabricated evidence:
``_module_variants("webpent.shared.cve_advisory")`` returned the parent
prefix ``webpent.shared`` as a FULL match variant, so every
``from webpent.shared import <anything>`` in the tree (~190 files)
counted as an importer. The module also scanned itself (the sorted
variants put the parent first, breaking self-file detection).

Contract pinned here:
  * a parent prefix NEVER satisfies a bare/prefix import match — only
    the full dotted name does;
  * the parent prefix still completes a name:
    ``from webpent.auth import identity_orchestrator`` IS an importer of
    ``webpent.auth.identity_orchestrator``;
  * the module's own file is never its own importer (3-segment names);
  * a relative import from a sibling package resolves correctly and
    does NOT over-match a same-leaf module in another package.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from webpent.shared.legacy_disposition import (
    _module_variants,
    find_importers,
)


@pytest.fixture()
def tree(tmp_path: Path) -> Path:
    """A src/ tree exercising the 3-segment over-match cases."""
    src = tmp_path / "src"
    pkg = src / "webpent"
    (pkg / "shared").mkdir(parents=True)
    (pkg / "auth").mkdir(parents=True)
    (pkg / "otherpkg").mkdir(parents=True)
    (pkg / "shared" / "__init__.py").write_text("", encoding="utf-8")
    (pkg / "auth" / "__init__.py").write_text("", encoding="utf-8")
    (pkg / "otherpkg" / "__init__.py").write_text("", encoding="utf-8")
    # the module under test
    (pkg / "shared" / "cve_advisory.py").write_text("X = 1\n", encoding="utf-8")
    # sibling module with the SAME leaf name in another package
    (pkg / "otherpkg" / "cve_advisory.py").write_text("Y = 2\n", encoding="utf-8")
    # NOT importers: from-package imports of OTHER names (the over-match)
    (pkg / "engine.py").write_text(
        "from webpent.shared import differential_workflow\n",
        encoding="utf-8",
    )
    (pkg / "engine2.py").write_text(
        "import webpent.shared.anything_else\n",
        encoding="utf-8",
    )
    # importers: full dotted + parent-completed name + relative sibling
    (pkg / "real_user.py").write_text(
        "from webpent.shared.cve_advisory import X\n",
        encoding="utf-8",
    )
    (pkg / "name_completion.py").write_text(
        "from webpent.shared import cve_advisory\n",
        encoding="utf-8",
    )
    # a same-leaf module in ANOTHER package imported relatively must not
    # count for the shared one
    (pkg / "otherpkg" / "user.py").write_text(
        "from webpent.otherpkg.cve_advisory import Y\n",
        encoding="utf-8",
    )
    return src


def test_full_name_is_the_only_variant(tree):
    variants = _module_variants("webpent.shared.cve_advisory")
    # M1-D contract: the tuple is EXACTLY the full dotted name — the old
    # parent prefix ("webpent.shared") used to join the equality set.
    assert variants == ("webpent.shared.cve_advisory",)


def test_from_package_import_of_other_name_is_no_importer(tree):
    importers = find_importers("webpent.shared.cve_advisory", src_root=tree)
    assert "src/webpent/engine.py" not in importers
    assert "src/webpent/engine2.py" not in importers


def test_real_importers_still_found(tree):
    importers = find_importers("webpent.shared.cve_advisory", src_root=tree)
    assert "src/webpent/real_user.py" in importers
    assert "src/webpent/name_completion.py" in importers


def test_module_never_imports_itself(tree):
    importers = find_importers("webpent.shared.cve_advisory", src_root=tree)
    assert "src/webpent/shared/cve_advisory.py" not in importers


def test_same_leaf_other_package_not_confused(tree):
    importers = find_importers("webpent.shared.cve_advisory", src_root=tree)
    assert "src/webpent/otherpkg/user.py" not in importers
    assert "src/webpent/otherpkg/cve_advisory.py" not in importers


def test_two_segment_name_completion_still_matches(tree):
    """The HEAD-era pinned case: from webpent import legacy_a matches."""
    (tree / "webpent" / "legacy_a.py").write_text("X = 1\n", encoding="utf-8")
    (tree / "webpent" / "engine3.py").write_text(
        "from webpent import legacy_a\n", encoding="utf-8"
    )
    importers = find_importers("webpent.legacy_a", src_root=tree)
    assert "src/webpent/engine3.py" in importers
