"""UM-DR-51 P4 — GT-integrity: the truth cannot change after measurement.

The owner's word (window 51, law of the meters): "add a GT-integrity
test that fails at any GT modification after the first measurement of
the same run."

WHAT THIS PINS (measured live this window):
  * the ORIGINAL ground truth fingerprints to f46511e1... — any edit
    to FAMILY_GROUND_TRUTH after the recorded measurement (an anchor
    added, a defect renamed, a must_not entry dropped) fails here.
  * importing scripts/umdr48_battery_v2 MUTATES the shared GT at
    import time (appends the mirror defect GT-TEN-1-MIRROR AND
    removes its must_not entry — measured: fingerprint f46511e1 ->
    a30a9c2f). That mutation is the live demonstration of "changing
    the truth after seeing the results": any measurement taken after
    the import silently scores against the expanded truth. This test
    pins the mutation EXACTLY — the declared expansion only; any
    additional in-place GT change (another defect, another must_not
    removal) fails here.

ORDER MATTERS (live-measured twice this window): the battery-import
mutation test runs LAST — after it, the shared base GT stays mutated
for the rest of the process, so any purity-sensitive assertion must
come before it.
"""
from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "scripts"))
sys.path.insert(0, str(REPO / "src"))

PINNED_ORIGINAL = "f46511e1a3c31b222cbd7fa0a186b373a4e19f8b5e99c398a7785762d95881b6"
PINNED_POST_BATTERY_IMPORT = (
    "a30a9c2f11a4e6cacbd638e5461fb125ccf34a463ad159849a590345de82c482")

# The recorded measurement this test protects (first measurement of
# the 36 raw window-48 campaigns against the ORIGINAL truth).
MEASUREMENT_RECORD = (
    REPO / "deliverables/umdr51/METER_CORRECTION.json")


def _fingerprint(gt: dict) -> str:
    blob = json.dumps(
        {fam: {
            "defects": [sorted(d["anchor_paths"]) for d in g["defects"]],
            "must_not": sorted(g["must_not_confirm"]),
        } for fam, g in sorted(gt.items())},
        sort_keys=True, ensure_ascii=False)
    return hashlib.sha256(blob.encode()).hexdigest()


def test_original_truth_matches_the_recorded_measurement() -> None:
    import umdr46_baseline_battery as base
    fp = _fingerprint(base.FAMILY_GROUND_TRUTH)
    assert fp == PINNED_ORIGINAL, (
        "the ORIGINAL ground truth changed after the recorded "
        "measurement (METER_CORRECTION.json pins "
        f"{PINNED_ORIGINAL[:16]}; live GT is {fp[:16]}) — re-measure "
        "and re-pin deliberately, never silently"
    )


def test_measurement_record_carries_the_original_fingerprint() -> None:
    record = json.loads(MEASUREMENT_RECORD.read_text())
    assert record["ground_truth_fingerprint_sha256"] == PINNED_ORIGINAL, (
        "the meter-correction record and this test pin different "
        "truths — one of them changed after the measurement"
    )


def test_meter_correction_scores_against_the_snapshot_not_the_live_gt() -> None:
    """The meter-correction script's own defense: it snapshots the
    original truth BEFORE importing the battery (the live-measured
    hazard) — its correction must never be scoreable against the
    post-import truth.

    Runs in a FRESH SUBPROCESS (the exact way the meter-correction
    script itself runs: `python scripts/umdr51_meter_correction.py`)
    — in-process the shared base GT may already be mutated by an
    earlier import (the very order hazard this module documents), so
    the snapshot defense is verified where it lives: a clean process.
    """
    import subprocess
    import sys as _sys

    code = (
        "import sys; sys.path.insert(0, 'scripts'); "
        "sys.path.insert(0, 'src')\n"
        "import umdr51_meter_correction as mc\n"
        "tenant = mc.ORIGINAL_GT['tenant_confusion']\n"
        "anchors = {a for d in tenant['defects'] "
        "for a in d['anchor_paths']}\n"
        "assert anchors == {'/api/tenant/profiles/PROF-T2-55'}, anchors\n"
        "assert '/api/tenant/profiles/PROF-T1-11' in "
        "tenant['must_not_confirm']\n"
        "assert mc.EXPANDED_MIRRORS.get('tenant_confusion') == "
        "['/api/tenant/profiles/PROF-T1-11']\n"
        "assert mc.gt_fingerprint() == " + repr(PINNED_ORIGINAL) + "\n"
        "print('SNAPSHOT-OK')"
    )
    r = subprocess.run(
        [_sys.executable, "-c", code], cwd=str(REPO),
        capture_output=True, text=True, timeout=120)
    assert "SNAPSHOT-OK" in r.stdout, (
        f"the meter-correction snapshot is not the original truth in a "
        f"fresh process:\n{r.stdout[-400:]}\n{r.stderr[-400:]}"
    )


def test_battery_import_mutation_is_exactly_the_declared_expansion() -> None:
    """The known, declared hazard — pinned so it cannot grow silently.

    ORDER-INDEPENDENT (the module-level lesson this window taught twice:
    importing the battery anywhere in the process mutates the shared
    GT for everything after): the LIVE truth must be EXACTLY one of
    the two pinned states — the original (battery not yet imported)
    or the declared post-expansion truth (imported exactly once with
    exactly the mirror defect + the single must_not removal). Any
    third state (another defect, another must_not edit, any drift
    beyond the declared expansion) fails here.
    """
    import umdr46_baseline_battery as base
    import umdr48_battery_v2 as battery  # noqa: F401 — the mutation under test

    fp = _fingerprint(base.FAMILY_GROUND_TRUTH)
    assert fp in (PINNED_ORIGINAL, PINNED_POST_BATTERY_IMPORT), (
        f"the live ground truth is NEITHER the original "
        f"({PINNED_ORIGINAL[:16]}) NOR the declared post-battery "
        f"expansion ({PINNED_POST_BATTERY_IMPORT[:16]}) — live is "
        f"{fp[:16]}: an in-place GT modification beyond the declared "
        "expansion happened after the first measurement"
    )

    # the declared expansion, read from the battery itself, is exactly
    # ONE mirror defect + its single must_not removal — nothing else
    expansion = battery._ANCHOR_EXPANSION
    assert set(expansion) == {"tenant_confusion"}, (
        f"the declared expansion grew beyond tenant_confusion: "
        f"{sorted(expansion)}")
    exp_defects = expansion["tenant_confusion"]["defects"]
    assert [d["id"] for d in exp_defects] == ["GT-TEN-1-MIRROR"], (
        "the declared expansion is not exactly the single mirror defect")
    mirror = exp_defects[0]["anchor_paths"][0]
    assert mirror == "/api/tenant/profiles/PROF-T1-11"

    # and the live tenant truth carries exactly ONE extra defect vs the
    # original pin (the mirror), with exactly its must_not entry removed
    live_tenant = base.FAMILY_GROUND_TRUTH["tenant_confusion"]
    anchor_sets = [set(d["anchor_paths"]) for d in live_tenant["defects"]]
    assert {"/api/tenant/profiles/PROF-T2-55"} in anchor_sets
    assert {mirror} in anchor_sets
    assert len(live_tenant["defects"]) == 2, (
        "more than the original + the mirror defect in the live truth")
    assert mirror not in set(live_tenant["must_not_confirm"]), (
        "the mirror path must not be in must_not after the declared "
        "expansion (the battery removes exactly it)")
    _ORIGINAL_MUST_NOT = {
        "/api/tenant/profiles/PROF-T1-11", "/api/tenants",
        "/api/tenant-docs", "/api/session",
    }
    assert set(live_tenant["must_not_confirm"]) == (
        _ORIGINAL_MUST_NOT - {mirror}), (
        "the must_not set changed beyond the single declared removal"
    )
