"""Reproducible local baseline contracts for the VIP plan."""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
_SCRIPT_PATH = PROJECT_ROOT / "scripts" / "capture_vip_baseline.py"
_SPEC = importlib.util.spec_from_file_location("capture_vip_baseline", _SCRIPT_PATH)
assert _SPEC is not None and _SPEC.loader is not None
_MODULE = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(_MODULE)
capture = _MODULE.capture


def test_vip_baseline_is_local_and_report_safe() -> None:
    payload = capture()
    assert payload["schema_version"] == "vip-baseline-v1"
    assert payload["waptlab_fixture"]["available"] is False
    assert payload["test_function_count"] >= 498
    ledger = payload["campaign_ledger"]
    assert len(ledger["entries"]) == 20
    assert all(
        entry["status"] in {"not_observed", "missing-validator"}
        for entry in ledger["entries"]
    )
    assert not any(entry["evidence_complete"] for entry in ledger["entries"])


def test_checked_in_baseline_is_valid_json() -> None:
    baseline = PROJECT_ROOT / "docs" / "vip_baseline.json"
    payload = json.loads(baseline.read_text(encoding="utf-8"))
    assert payload["schema_version"] == "vip-baseline-v1"
    assert payload["campaign_ledger"]["summary"]["not_observed"] >= 1
