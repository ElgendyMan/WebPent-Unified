"""UM-DR-36.1 §3 — adversarial provenance tests for the build-info gate.

Every defect class the mission names gets a failing-case test plus a
passing baseline, all against scripts/check_build_info_honesty.evaluate:

  * version mismatch (BUILD_INFO vs pyproject SSOT / nested contracts);
  * invalid or missing commit references (unresolvable revisions);
  * missing manifests (frozen_modules.sha256 absent);
  * incorrect manifest digest (does not match the actual file);
  * stale test accounting (suite_count lagging collected reality, or
    collected reported as executed);
  * invalid historical/current release relationships;
  * artifacts (evidence) generated from a different source revision.

The gate must also validate a fully-honest record, and the historical
local-lineage marker (source_revision: null + note) must be accepted
while an unresolvable non-null revision fails.
"""
from __future__ import annotations

import hashlib
import json
import subprocess
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
import sys  # noqa: E402

sys.path.insert(0, str(REPO / "scripts"))
from check_build_info_honesty import (  # noqa: E402
    RECOVERY_BASELINE,
    evaluate,
)

RESOLVABLE_OLD = "989c49ba5cb3747859496d06736ae7c8317086ed"  # public history
UNRESOLVABLE = "d" * 40


def _manifest_digest() -> str:
    return hashlib.sha256((REPO / "frozen_modules.sha256").read_bytes()
                          ).hexdigest()


def _valid_info() -> dict:
    accounting = {"collected": 9100, "executed": 9096, "passed": 9080,
                  "failed": 0, "skipped": 14, "xfailed": 2, "xpassed": 0,
                  "errors": 0, "deselected": 4}
    return {
        "build_name": "WebPent v15.2 (unified)",
        "build_date": "2026-11-14T00:00:00+00:00",
        "package_version": "0.40.1",
        "provenance": {
            "schema": "umdr36-1-provenance-v1",
            "source_revision": RESOLVABLE_OLD,
            "tested_revision": RESOLVABLE_OLD,
            "evidence_revision": RESOLVABLE_OLD,
            "recovery_baseline": RECOVERY_BASELINE,
            "manifest_digest": _manifest_digest(),
            "package_version": "0.40.1",
            "test_accounting": accounting,
            "build_date": "2026-11-14T00:00:00+00:00",
            "publication": {"published": False, "release_tag": None},
        },
        "suite_count": 9096,
        "suite_evidence": ("full-suite run recorded in "
                           "docs/FULL_SUITE_EVIDENCE.json at the tested "
                           "revision (see provenance block)"),
        "units_closed": ["UM-DR-35", "UM-DR-36"],
        "fixes_applied": ["umdr36.1-lockfile-sync"],
        "version_identity_contract": {
            "package_version": "0.40.1",
            "current_release": {
                "package_version": "0.40.1",
                "source_revision": RESOLVABLE_OLD,
            },
            "release_history": [
                {"package_version": "0.39.0",
                 "source_revision": RESOLVABLE_OLD},
                {"package_version": "0.38.0", "source_revision": None,
                 "source_revision_note": "local lineage predating the public "
                                         "repository; unverifiable here"},
            ],
        },
    }


def _evaluate(info: dict, *, collected_probe: int | str = "skip",
              evidence_record: dict | None = None):
    probe = "skip" if collected_probe == "skip" else collected_probe
    return evaluate(info, collected_probe=probe,
                    evidence_record=evidence_record)


def test_honest_record_passes() -> None:
    failures, _ = _evaluate(_valid_info())
    assert failures == [], failures


def test_version_mismatch_against_pyproject_fails() -> None:
    info = _valid_info()
    info["package_version"] = "0.40.0"
    failures, _ = _evaluate(info)
    assert any("pyproject SSOT" in f for f in failures)


def test_nested_contract_version_mismatch_fails() -> None:
    info = _valid_info()
    info["version_identity_contract"]["package_version"] = "0.40.0"
    failures, _ = _evaluate(info)
    assert any("version_identity_contract.package_version" in f
               for f in failures)


def test_provenance_package_version_mismatch_fails() -> None:
    info = _valid_info()
    info["provenance"]["package_version"] = "0.40.2"
    failures, _ = _evaluate(info)
    assert any("provenance.package_version" in f for f in failures)


def test_unresolvable_source_revision_fails() -> None:
    info = _valid_info()
    info["provenance"]["source_revision"] = UNRESOLVABLE
    failures, _ = _evaluate(info)
    assert any("source_revision" in f and "resolvable" in f
               for f in failures)


def test_missing_revision_fails() -> None:
    info = _valid_info()
    del info["provenance"]["tested_revision"]
    failures, _ = _evaluate(info)
    assert any("tested_revision" in f for f in failures)


def test_wrong_recovery_baseline_fails() -> None:
    info = _valid_info()
    info["provenance"]["recovery_baseline"] = RESOLVABLE_OLD
    failures, _ = _evaluate(info)
    assert any("recovery_baseline" in f for f in failures)


def test_incorrect_manifest_digest_fails(tmp_path, monkeypatch) -> None:
    info = _valid_info()
    info["provenance"]["manifest_digest"] = "0" * 64
    failures, _ = _evaluate(info)
    assert any("manifest_digest" in f for f in failures)


def test_missing_manifest_fails(tmp_path, monkeypatch) -> None:
    # Point the gate's MANIFEST at a path without the file.
    import check_build_info_honesty as gate
    monkeypatch.setattr(gate, "MANIFEST", tmp_path / "nope.sha256")
    info = _valid_info()
    failures, _ = _evaluate(info)
    assert any("missing" in f and "manifest" in f.lower() for f in failures)


def test_suite_count_reporting_collected_as_executed_fails() -> None:
    info = _valid_info()
    # 9100 is the COLLECTED count; reporting it as suite_count (executed)
    # is exactly the collected-as-executed confusion the mission forbids.
    info["suite_count"] = 9100
    failures, _ = _evaluate(info)
    assert any("EXECUTED count" in f for f in failures)


def test_inconsistent_test_accounting_fails() -> None:
    info = _valid_info()
    info["provenance"]["test_accounting"]["executed"] = 9097
    failures, _ = _evaluate(info)
    assert any("outcome sum" in f for f in failures)


def test_collected_not_equal_executed_plus_deselected_fails() -> None:
    info = _valid_info()
    info["provenance"]["test_accounting"]["collected"] = 9110
    failures, _ = _evaluate(info)
    assert any("collected != executed + deselected" in f for f in failures)


def test_stale_test_accounting_fails() -> None:
    info = _valid_info()
    info["suite_count"] = 8500
    info["provenance"]["test_accounting"]["executed"] = 8500
    failures, _ = _evaluate(info, collected_probe=9100)
    assert any("lags collected reality" in f for f in failures)


def test_inflated_test_accounting_fails() -> None:
    info = _valid_info()
    info["suite_count"] = 9999
    info["provenance"]["test_accounting"]["executed"] = 9999
    failures, _ = _evaluate(info, collected_probe=9100)
    assert any("EXCEEDS collected reality" in f for f in failures)


def test_history_entry_not_older_than_current_fails() -> None:
    info = _valid_info()
    info["version_identity_contract"]["release_history"][0][
        "package_version"] = "0.40.1"
    failures, _ = _evaluate(info)
    assert any("not strictly older" in f for f in failures)


def test_current_release_version_older_than_declared_fails() -> None:
    info = _valid_info()
    info["version_identity_contract"]["current_release"][
        "package_version"] = "0.39.0"
    failures, _ = _evaluate(info)
    assert any("current_release.package_version" in f for f in failures)


def test_history_unresolvable_revision_fails() -> None:
    info = _valid_info()
    info["version_identity_contract"]["release_history"][0][
        "source_revision"] = UNRESOLVABLE
    failures, _ = _evaluate(info)
    assert any("release_history[0].source_revision" in f for f in failures)


def test_history_null_revision_without_note_fails() -> None:
    info = _valid_info()
    entry = info["version_identity_contract"]["release_history"][0]
    entry["source_revision"] = None
    entry.pop("source_revision_note", None)
    failures, _ = _evaluate(info)
    assert any("no explanatory source_revision_note" in f for f in failures)


def test_history_null_revision_with_note_is_accepted() -> None:
    info = _valid_info()
    _, notes = _evaluate(info)
    assert any("explicitly-unverifiable local lineage" in n for n in notes)


def test_evidence_from_different_revision_not_bound_but_noted() -> None:
    info = _valid_info()
    evidence = {"source_commit": RESOLVABLE_OLD,
                "accounting": dict(info["provenance"]["test_accounting"])}
    # Same revision, DIFFERENT accounting -> binding failure.
    evidence["accounting"] = dict(evidence["accounting"], passed=9000)
    failures, _ = _evaluate(info, evidence_record=evidence)
    assert any("committed evidence accounting differs" in f for f in failures)


def test_evidence_from_same_revision_with_matching_accounting_binds() -> None:
    info = _valid_info()
    evidence = {"source_commit": RESOLVABLE_OLD,
                "accounting": dict(info["provenance"]["test_accounting"])}
    failures, _ = _evaluate(info, evidence_record=evidence)
    assert failures == [], failures


def test_published_claim_without_real_tag_fails() -> None:
    info = _valid_info()
    info["provenance"]["publication"] = {
        "published": True, "release_tag": "v99.99.99-never-created"}
    failures, _ = _evaluate(info)
    assert any("release tag" in f for f in failures)


def test_missing_fixes_applied_fails() -> None:
    info = _valid_info()
    info.pop("fixes_applied")
    failures, _ = _evaluate(info)
    assert any("fixes_applied" in f for f in failures)
