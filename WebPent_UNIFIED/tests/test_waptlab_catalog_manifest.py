"""Regression tests for the strict WAPTLab catalog and baseline manifest."""

from __future__ import annotations

import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CATALOG = ROOT / "docs" / "waptlab_vulnerability_catalog.yml"
MANIFEST = ROOT / "docs" / "waptlab_baseline_manifest.json"


def test_catalog_has_twenty_unique_entries_and_required_fields() -> None:
    text = CATALOG.read_text(encoding="utf-8")
    ids = [int(value) for value in re.findall(r"^  - id: (\d+)$", text, re.MULTILINE)]
    keys = re.findall(r"^    key: ([a-z0-9_]+)$", text, re.MULTILINE)
    assert ids == list(range(1, 21))
    assert len(keys) == 20
    assert len(set(keys)) == 20
    for field in ("category", "surfaces", "validator", "evidence_required", "negative_control"):
        assert text.count(f"    {field}:") == 20


def test_catalog_requires_replay_and_cleanup_evidence() -> None:
    text = CATALOG.read_text(encoding="utf-8")
    assert text.count("replay") >= 20
    assert text.count("cleanup:") == 20
    assert "confirmation_policy:" in text


def test_manifest_is_explicitly_non_live_and_references_catalog() -> None:
    manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
    assert manifest["catalog_version"] == "waptlab-v1"
    assert manifest["target_contacted"] is False
    assert manifest["waptlab_modified"] is False
    assert manifest["live_runtime"]["status"] == "blocked"
    assert manifest["acceptance"]["current_vip_ready"] is False


def test_manifest_records_mock_measurement_without_live_confirmation() -> None:
    manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
    mock_runs = [run for run in manifest["runs"] if run["mode"].endswith("mock-detector-coverage")]
    assert len(mock_runs) == 1
    run = mock_runs[0]
    assert run["confirmed"] == 5
    assert run["false_positive_candidates"] == 15
    assert run["target_contacted"] is False
    assert run["artifact"] == "docs/waptlab_mock_matrix.json"


def test_mock_reproducibility_artifact_is_stable() -> None:
    artifact = ROOT / "docs" / "waptlab_mock_reproducibility.json"
    report = json.loads(artifact.read_text(encoding="utf-8"))
    assert report["stable"] is True
    assert len(report["runs"]) == 3
    assert report["summary"] == {"candidate-or-review": 15, "tool-confirmed": 5}


def test_coverage_ledger_has_all_campaigns_and_safe_dispositions() -> None:
    ledger_path = ROOT / "docs" / "waptlab_coverage_ledger.json"
    ledger = json.loads(ledger_path.read_text(encoding="utf-8"))
    assert len(ledger["entries"]) == 20
    assert ledger["summary"] == {"candidate_or_review": 15, "tested": 5}
    assert ledger["live_qualification"] is False
    assert ledger["target_contacted"] is False
    assert ledger["waptlab_modified"] is False
