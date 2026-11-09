"""Option-B local causal-lab runner tests (R-10, hermetic).

These tests used to call ``build_result()`` with the shipped default import,
which requires the external owner-approval artifact at a hard-coded
author-machine path. On any other machine the artifact is absent and the
run correctly fails closed — but the test then reported that fail-closed
abort as a failure. The tests now build a synthetic-but-consistent approval
environment (see test_local_causal_lab_option_b_approval.py) and pass it
through the ``approval_source`` seam added to ``build_result``. The
boundary laws asserted below (loopback-only, GET-only, zero confirmations,
zero sealed bundles, no network, no sensitive material) are unchanged.
"""

from __future__ import annotations

from pathlib import Path

from scripts.run_option_b_local_causal_lab import build_result
from tests.test_local_causal_lab_option_b_approval import (
    _build_synthetic_approval_env,
)


def test_option_b_runner_emits_only_redacted_blocked_records(tmp_path: Path) -> None:
    approval_path, import_path = _build_synthetic_approval_env(tmp_path)
    result = build_result(import_path=import_path, approval_source=approval_path)
    assert result["scope"]["loopback_only"] is True
    assert result["scope"]["methods"] == ["GET"]
    assert result["scope"]["official_isolated_p10_runs_authorized"] is False
    assert result["summary"]["target_backed_causal_confirmations"] == 0
    assert result["summary"]["proof_bundles_sealed"] == 0
    assert result["summary"]["quality_metrics"] == "WITHHELD"
    assert len(result["cases"]) == 6
    assert all(case["final_classification"] == "BLOCKED" for case in result["cases"])
    assert all(
        case["runnable_precondition"]["network_attempted"] is False for case in result["cases"]
    )
    assert all(case["baseline"]["status"] == "not_run" for case in result["cases"])
    assert all(case["proof_bundle"]["seal"] == "not_created" for case in result["cases"])
    assert all(case["cleanup"]["status"] == "verified_no_mutation" for case in result["cases"])


def test_option_b_runner_records_runtime_digest_blockers_without_sensitive_material(
    tmp_path: Path,
) -> None:
    approval_path, import_path = _build_synthetic_approval_env(tmp_path)
    result = build_result(import_path=import_path, approval_source=approval_path)
    for target in result["target_provenance"].values():
        assert target["runtime"]["runtime_digest"] is None
    serialized = str(result)
    for forbidden in ("Cookie:", "Set-Cookie:", "Bearer ", "password=", "token="):
        assert forbidden not in serialized
    for case in result["cases"]:
        assert case["cleanup"]["network_attempted"] is False
        assert case["identity_model"].startswith("opaque synthetic")


def test_option_b_runner_still_fails_closed_without_approval(tmp_path: Path) -> None:
    """R-10 law: with no approval artifact, build_result must still abort."""
    import pytest

    with pytest.raises(ValueError) as excinfo:
        build_result(approval_source=tmp_path / "missing.txt")
    assert "approval_boundary_failed" in str(excinfo.value)
    assert "approval_source_missing" in str(excinfo.value)
