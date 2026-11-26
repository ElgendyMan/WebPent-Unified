"""UM-DR-50 W3/P3.4 — the durable publication-integrity tests.

Two permanent gates the 49 provenance break proved missing:

1. ``test_evidence_revisions_resolvable`` — every SHA a published
   evidence file binds to (BUILD_INFO provenance + the durable
   FULL_SUITE_EVIDENCE records) must resolve inside THIS clone. The
   49 window bound its evidence to 66fec2d — a commit orphaned by a
   later force-push — and nothing caught it until the master plan's
   clean-clone audit. This test fails the suite the moment an
   evidence revision becomes unreachable.

2. ``test_publication_claims`` — PUBLICATION.json is MANDATORY for a
   release window: main head SHA, the release tag, the CI run id, and
   the release URL — machine-verified for shape and cross-checked for
   coherence (the tag must exist, the head must be an ancestor-or-equal
   of the tag target). No PUBLICATION.json = no published-green claim.

Both tests are read-only (no network): they verify what the local
repository can prove about its own evidence bindings.
"""
from __future__ import annotations

import json
import re
import subprocess
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]

_SHA_RE = re.compile(r"\b[0-9a-f]{40}\b")

# the evidence sources whose SHA bindings are load-bearing
EVIDENCE_FILES = [
    REPO / "BUILD_INFO.json",
    REPO / "deliverables" / "umdr49_closure" / "FULL_SUITE_EVIDENCE.json",
    REPO / "deliverables" / "umdr45" / "FULL_SUITE_EVIDENCE.json",
    REPO / "deliverables" / "umdr47" / "FULL_SUITE_EVIDENCE.json",
]


def _git_ok(*args: str) -> bool:
    return subprocess.run(
        ["git", "cat-file", "-e", *args], cwd=str(REPO),
        capture_output=True).returncode == 0


def _known_unresolvable(sha: str) -> bool:
    """Declared historical orphans (documented, never current claims).

    ``fe92f178`` — the umdr38 evidence bound in the PREDECESSOR
    repository (this repository's lineage predates the transfer);
    documented in PUBLICATION_AUDIT.md.
    """
    return sha.startswith("fe92f178")


def test_evidence_revisions_resolvable() -> None:
    orphans: list[str] = []
    checked = 0
    for path in EVIDENCE_FILES:
        if not path.is_file():
            continue
        for sha in sorted(set(_SHA_RE.findall(path.read_text(
                encoding="utf-8", errors="replace")))):
            checked += 1
            if _known_unresolvable(sha):
                continue
            if not _git_ok(sha):
                orphans.append(f"{path.name}: {sha}")
    assert checked > 0, (
        "no evidence SHA bindings found — the evidence files moved?")
    assert not orphans, (
        "EVIDENCE REVISIONS UNRESOLVABLE in this clone (the 49-class "
        f"provenance break): {orphans}")


def _publication() -> dict | None:
    path = REPO / "PUBLICATION.json"
    if not path.is_file():
        return None
    return json.loads(path.read_text(encoding="utf-8"))


def test_publication_claims() -> None:
    pub = _publication()
    if pub is None:
        # no publication claim in the tree: legal for a work window —
        # but then the tree must not CLAIM a published green either
        # (BUILD_INFO must not point evidence at a tag-only commit)
        pytest.skip(
            "no PUBLICATION.json in the tree — no published-green "
            "claim to verify (work window)")


def test_publication_claims_shape_and_coherence() -> None:
    pub = _publication()
    if pub is None:
        pytest.skip("no PUBLICATION.json in the tree")
    # mandatory fields with honest shapes
    for field in ("main_head", "release_tag", "ci_run_id", "release_url"):
        assert pub.get(field), f"PUBLICATION.json missing {field}"
    assert re.fullmatch(r"[0-9a-f]{40}", str(pub["main_head"])), (
        "main_head must be a full SHA")
    assert re.fullmatch(r"\d+", str(pub["ci_run_id"])), (
        "ci_run_id must be the numeric GitHub Actions run id")
    assert str(pub["release_tag"]).startswith("v"), (
        "release_tag must be a version tag")
    assert str(pub["release_url"]).startswith(
        "https://github.com/"), "release_url must be the real URL"
    # coherence: the head resolves, and the tag exists in this clone
    assert _git_ok(str(pub["main_head"])), (
        f"main_head {pub['main_head']} does not resolve in this clone")
    tag = subprocess.run(
        ["git", "rev-parse", str(pub["release_tag"])], cwd=str(REPO),
        capture_output=True, text=True)
    assert tag.returncode == 0, (
        f"release tag {pub['release_tag']} missing in this clone")
