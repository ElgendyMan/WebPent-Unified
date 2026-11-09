from __future__ import annotations

import importlib.util
from pathlib import Path
from types import ModuleType

_HARNESS_PATH = Path(__file__).resolve().parents[1] / "scripts" / "run_waptlab_regression.py"


def _load_harness() -> ModuleType:
    spec = importlib.util.spec_from_file_location("waptlab_regression", _HARNESS_PATH)
    if spec is None or spec.loader is None:
        raise RuntimeError("unable to load WAPTLab regression harness")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_local_waptlab_regression_is_target_free_and_complete() -> None:
    report = _load_harness().run_regression()

    assert report["campaign_count"] == 20
    assert report["target_contacted"] is False
    assert report["waptlab_modified"] is False
    # GOED closed 5 of the original 7 validator gaps (see
    # test_vip_validator_plugins.py) — only 2 campaigns remain without a
    # deterministic or offline-fixture validator now.
    assert report["summary"] == {"inconclusive": 18, "missing-validator": 2}
    assert all(not item["evidence_complete"] for item in report["campaigns"])


def test_synthetic_contracts_replan_on_missing_evidence() -> None:
    report = _load_harness().run_regression()

    assert len(report["synthetic_contract_checks"]) == 4
    assert all(check["synthetic_contract_only"] for check in report["synthetic_contract_checks"])
    assert all(check["changes_plan_on_gap"] for check in report["synthetic_contract_checks"])
    assert all(check["gap_fixture_types"] for check in report["synthetic_contract_checks"])
