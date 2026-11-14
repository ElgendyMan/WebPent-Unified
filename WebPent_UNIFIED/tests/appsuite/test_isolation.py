"""L8 §2 — implementation-independence evidence for the appsuite.

These tests assert the independence claims mechanically rather than
leaving them as docstring prose. They check what can be checked:

1. the external vocabulary (route segments, ids, field names) drawn
   from the shared WORDS pool is disjoint from BOTH prior corpora's
   vocabularies (the L5/L6 canonical fixture and the L7 labsuite),
   so no appsuite instance can collide with a fixture-lab deployment
   on names the engine could memorize;
2. no appsuite module imports fixture or labsuite implementation
   modules: an independently implemented application cannot share
   its vulnerability or fixture-generation logic by import;
3. the appsuite never imports the benchmark ground truth (the
   detector must learn from observations alone; so must an app that
   is measured against that ground truth).
"""

from __future__ import annotations

import importlib
import sys
from pathlib import Path

import pytest

APPSUITE = importlib.import_module("webpent.appsuite")
# Import the corpus so every app submodule registers as a package
# attribute: the assertions below must not depend on which other
# test modules happened to run first.
importlib.import_module("webpent.appsuite.corpus")
_APPS = ("docvault", "market", "slots", "ticketflow",
         "requisitions", "ledgerflow", "berth",
         "consign", "permit")

_LABSUITE_WORDLIST = [
    "atlas", "bramble", "cinder", "dovetail", "esparto", "flint",
    "garnet", "hollow", "ibex", "jetty", "kiln", "lumen", "mesa",
    "nutmeg", "onyx", "pilaster", "quiver", "roan", "sable",
    "tundra", "umbel", "vestry", "wicket", "yarrow", "zephyr",
]

# The generation-2 apps share ONE word pool by design (the L8
# suite's own landscape draw); each generation-3 app must be
# disjoint from every EARLIER app's pool so no cross-corpus name
# collision is possible.
_EARLIER_APPS = ("docvault", "market", "slots", "ticketflow",
                 "requisitions", "ledgerflow", "berth")
_L10_APPS = ("consign", "permit")

# The canonical wire vocabulary the L5/L6 fixture declares (the same
# set test_blind_discovery asserts the labsuite is disjoint from).
_CANONICAL = {
    "resources", "operations", "workflows", "resource", "amount",
    "account", "actor", "idem",
}


def test_appsuite_words_disjoint_from_labsuite_wordlist() -> None:
    labsuite = set(_LABSUITE_WORDLIST)
    for name in _APPS:
        words = set(getattr(APPSUITE, name).WORDS)
        assert words.isdisjoint(labsuite), (
            f"{name}.WORDS collides with the L7 labsuite wordlist: "
            f"{sorted(words & labsuite)}")


def test_appsuite_words_disjoint_from_canonical_wire_names() -> None:
    for name in _APPS:
        words = set(getattr(APPSUITE, name).WORDS)
        assert words.isdisjoint(_CANONICAL), (
            f"{name}.WORDS collides with the canonical fixture wire "
            f"vocabulary: {sorted(words & _CANONICAL)}")


def test_l10_apps_disjoint_from_every_earlier_app_wordlist() -> None:
    earlier = {name: set(getattr(APPSUITE, name).WORDS)
               for name in _EARLIER_APPS}
    for name in _L10_APPS:
        words = set(getattr(APPSUITE, name).WORDS)
        for other, pool in earlier.items():
            assert words.isdisjoint(pool), (
                f"{name}.WORDS collides with {other}.WORDS: "
                f"{sorted(words & pool)}")


@pytest.mark.parametrize("name", _APPS)
def test_appsuite_module_imports_no_fixture_or_lab_implementation(
        name: str,
) -> None:
    module = getattr(APPSUITE, name)
    file = Path(sys.modules[module.__name__].__file__ or "")
    text = file.read_text(encoding="utf-8")
    for forbidden in (
            "discovery_target", "http_target", "labsuite",
            "lab_target", "discovery_ground_truth", "differential"):
        assert f"import {forbidden}" not in text, (
            f"{name} imports {forbidden}: implementation not "
            "independent")
        assert "from webpent.egaie" not in text, (
            f"{name} imports from the detector package (webpent.egaie): "
            "implementation not independent")


@pytest.mark.parametrize("probe", (
        "discovery_target", "http_target", "differential"))
def test_detector_package_never_references_the_appsuite(
        probe: str) -> None:
    """Independence runs in both directions: the fixture, the
    labsuite and the detector must not know the appsuite exists."""
    path = Path(importlib.import_module(
        f"webpent.egaie.{probe}").__file__ or "")
    assert "appsuite" not in path.read_text(encoding="utf-8"), (
        f"webpent.egaie.{probe} references the appsuite")
