"""Option-B approval-import boundary tests (R-10, hermetic).

History / root cause (TEAM-2 residual R-10): these tests originally pointed
``APPROVAL`` at a hard-coded author-machine path
(``/home/ubuntu/upload/pasted_content.txt``). The approval content is
deliberately NOT persisted in the repo (``raw_content_persisted_in_repo``
must be false), so on any other machine the artifact simply does not exist
and the tests failed with ``approval_source_missing`` /
``FileNotFoundError`` for three-plus rounds.

The fix keeps EVERY validation law intact and instead builds a synthetic
but internally consistent approval environment: the test writes its own
approval artifact, recomputes ``source_artifact.sha256`` for it, and runs
the validator against that pair. The validator still fails closed when the
artifact is missing or its content changes — the final test in this file
pins that law.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from scripts.check_local_causal_lab_option_b_approval import (
    APPROVAL_SOURCE,
    IMPORT,
    INVENTORY,
    PACKET,
    validate,
)

ROOT = Path(__file__).resolve().parents[1]
SYNTHETIC_APPROVAL_CONTENT = (
    "owner-approval-option-b:test synthetic artifact for hermetic validation "
    "runs — NOT a real owner signature\n"
)


def _sha256_of(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _build_synthetic_approval_env(tmp_path: Path) -> tuple[Path, Path]:
    """Create (approval_file, import_json) whose hash fields agree.

    The returned import record is a copy of the shipped IMPORT with only the
    ``source_artifact`` fields updated to reference the synthetic artifact.
    Every other boundary field (network boundary, fixture boundary,
    invariants, exclusions, import effects) stays exactly as shipped, so the
    validator exercises the same rules as in production.
    """
    approval_path = tmp_path / "approval_source.txt"
    approval_path.write_text(SYNTHETIC_APPROVAL_CONTENT, encoding="utf-8")

    record = json.loads(IMPORT.read_text(encoding="utf-8"))
    source_artifact = record.get("source_artifact") or {}
    source_artifact["path"] = str(approval_path)
    source_artifact["sha256"] = _sha256_of(approval_path)
    # Policy invariant preserved: raw approval content never enters the repo.
    source_artifact["raw_content_persisted_in_repo"] = False
    record["source_artifact"] = source_artifact

    import_path = tmp_path / "import.json"
    import_path.write_text(json.dumps(record), encoding="utf-8")
    return approval_path, import_path


def _copy_json(tmp_path: Path, source: Path, name: str) -> Path:
    target = tmp_path / name
    target.write_text(source.read_text(encoding="utf-8"), encoding="utf-8")
    return target


def test_option_b_import_validates_and_original_packet_stays_pending(tmp_path: Path) -> None:
    approval_path, import_path = _build_synthetic_approval_env(tmp_path)
    assert validate(import_path, PACKET, INVENTORY, approval_path) == []
    packet = json.loads(PACKET.read_text(encoding="utf-8"))
    assert packet["status"] == "PENDING_OWNER_APPROVAL"
    assert packet["owner_decision"]["decision"] is None
    assert packet["current_governance_state"]["official_isolated_p10_runs_authorized"] is False


@pytest.mark.parametrize(
    ("path", "mutation", "expected"),
    [
        (
            "network_boundary",
            lambda value: value.update(host_allowlist=["0.0.0.0"]),
            "host_allowlist_must_be_loopback_only",
        ),
        (
            "record",
            lambda value: value.update(approved_methods=["POST"]),
            "approved_methods_must_be_get_only",
        ),
        (
            "record",
            lambda value: value.update(approved_case_ids=["webgoat.stored_xss.comments.v1"]),
            "case_allowlist_mismatch",
        ),
        (
            "fixture",
            lambda value: value.update(login_or_session_bootstrap_allowed=True),
            "fixture_boundary_forbidden:login_or_session_bootstrap_allowed",
        ),
        (
            "invariants",
            lambda value: value.update(official_isolated_p10_runs_authorized=True),
            "official_run_gate_must_be_false",
        ),
    ],
)
def test_option_b_import_rejects_scope_expansion(
    tmp_path: Path, path: str, mutation, expected: str
) -> None:
    approval_path, import_path = _build_synthetic_approval_env(tmp_path)
    data = json.loads(import_path.read_text(encoding="utf-8"))
    field_map = {
        "record": data,
        "network_boundary": data["network_boundary"],
        "fixture": data["fixture_and_identity_boundary"],
        "invariants": data["global_invariants"],
    }
    mutation(field_map[path])
    import_path.write_text(json.dumps(data), encoding="utf-8")
    assert expected in validate(import_path, PACKET, INVENTORY, approval_path)


def test_option_b_import_rejects_prefilled_original_packet(tmp_path: Path) -> None:
    approval_path, import_path = _build_synthetic_approval_env(tmp_path)
    packet_path = _copy_json(tmp_path, PACKET, "packet.json")
    packet = json.loads(packet_path.read_text(encoding="utf-8"))
    packet["owner_decision"]["decision"] = "B"
    packet_path.write_text(json.dumps(packet), encoding="utf-8")
    assert "original_packet_contains_prefilled_approval" in validate(
        import_path, packet_path, INVENTORY, approval_path
    )


def test_option_b_import_rejects_changed_approval_source(tmp_path: Path) -> None:
    approval_path, import_path = _build_synthetic_approval_env(tmp_path)
    changed_path = tmp_path / "approval_changed.txt"
    changed_path.write_text(
        approval_path.read_text(encoding="utf-8") + "\nchanged", encoding="utf-8"
    )
    assert "approval_source_hash_mismatch" in validate(
        import_path, PACKET, INVENTORY, changed_path
    )


def test_option_b_approval_boundary_stays_fail_closed_when_missing(tmp_path: Path) -> None:
    """Pin the R-10 law: relocating the artifact must NOT weaken the boundary.

    With the approval artifact absent, validation must still report
    ``approval_source_missing`` — and the shipped import's recorded sha256
    must never be accepted without the matching external file.
    """
    missing_path = tmp_path / "does_not_exist.txt"
    assert "approval_source_missing" in validate(IMPORT, PACKET, INVENTORY, missing_path)
    # An attachment with the historical path may exist in a review sandbox;
    # either absence or a content mismatch must remain fail-closed.
    errors = validate(IMPORT, PACKET, INVENTORY, APPROVAL_SOURCE)
    assert {"approval_source_missing", "approval_source_hash_mismatch"}.intersection(errors)


def test_option_b_import_has_no_human_signoff_or_promotion_effect() -> None:
    record = json.loads(IMPORT.read_text(encoding="utf-8"))
    assert record["authority"]["human_independent_signoff_obtained"] is False
    assert record["global_invariants"]["official_isolated_p10_runs_authorized"] is False
    assert record["global_invariants"]["scoring_promotion_allowed"] is False
    assert all(value is False for value in record["import_effect"].values())
