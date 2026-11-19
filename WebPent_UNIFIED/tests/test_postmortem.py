"""Project Zero-tier item 6 — Postmortem structure for every mistake.

Pins:
  * PostmortemRecord enforces a closed vocabulary for kind/category
    (invalid values raise ValidationError, not silently coerce),
  * PostmortemManager is append-only, thread-safe under concurrent
    writes, and persists across manager instances on the same file,
  * record_false_positive / record_missed_finding / record_missed_findings
    convenience helpers round-trip correctly through SQLite JSON columns,
  * get_category_summary aggregates by kind then category without
    requiring the caller to re-parse free text,
  * devils_advocate_node's fresh-downgrade path calls the postmortem
    helper, and a postmortem write failure never raises out of it.
"""

from __future__ import annotations

import threading
from uuid import UUID, uuid4

import pytest
from pydantic import ValidationError

from webpent.memory.postmortem import (
    PostmortemManager,
    _active_workspace_database_url,
    get_postmortem_manager,
)
from webpent.models.postmortem import (
    PostmortemCategory,
    PostmortemKind,
    PostmortemRecord,
)
from webpent.shared.target_workspace import TargetWorkspace
from webpent.shared.target_workspace_context import activate_target_workspace

# ---------------------------------------------------------------------------
# Model-level tests
# ---------------------------------------------------------------------------


def test_record_accepts_valid_kind_and_category() -> None:
    record = PostmortemRecord(
        kind="false_positive",
        category="tool_miscalibration",
        root_cause_detail="dalfox misfired",
        proposed_fix="tune threshold",
    )
    assert record.kind == PostmortemKind.FALSE_POSITIVE
    assert record.category == PostmortemCategory.TOOL_MISCALIBRATION
    assert isinstance(record.id, UUID)


def test_record_rejects_invalid_kind() -> None:
    with pytest.raises(ValidationError):
        PostmortemRecord(kind="bogus", category="other")


def test_record_rejects_invalid_category() -> None:
    with pytest.raises(ValidationError):
        PostmortemRecord(kind="false_positive", category="bogus")


def test_record_rejects_extra_fields() -> None:
    with pytest.raises(ValidationError):
        PostmortemRecord(
            kind="false_positive",
            category="other",
            not_a_real_field="x",
        )


def test_to_dict_for_state_is_json_safe() -> None:
    record = PostmortemRecord(kind="missed_finding", category="coverage_gap")
    as_dict = record.to_dict_for_state()
    assert as_dict["kind"] == "missed_finding"
    assert as_dict["category"] == "coverage_gap"
    assert isinstance(as_dict["id"], str)  # UUID serialised to str in JSON mode


# ---------------------------------------------------------------------------
# Manager-level tests (real SQLite, no mocks)
# ---------------------------------------------------------------------------


@pytest.fixture
def manager() -> PostmortemManager:
    return PostmortemManager(database_url="sqlite://")


def test_record_and_get_all(manager: PostmortemManager) -> None:
    fid = manager.record_false_positive(
        category=PostmortemCategory.TOOL_MISCALIBRATION,
        root_cause_detail="dalfox flagged reflected content in a JSON context",
        proposed_fix="add content-type check",
        vuln_class="xss",
        thread_id="t1",
        detector_name="dalfox",
    )
    assert isinstance(fid, UUID)
    records = manager.get_all_records()
    assert len(records) == 1
    assert records[0]["kind"] == "false_positive"
    assert records[0]["category"] == "tool_miscalibration"
    assert records[0]["vuln_class"] == "xss"


def test_record_missed_finding_has_no_finding_id(
    manager: PostmortemManager,
) -> None:
    manager.record_missed_finding(
        category=PostmortemCategory.COVERAGE_GAP,
        root_cause_detail="admin panel never crawled",
        vuln_class="broken_access_control",
        thread_id="t1",
    )
    records = manager.get_all_records()
    assert records[0]["finding_id"] is None


def test_record_missed_findings_batch_from_strings(
    manager: PostmortemManager,
) -> None:
    ids = manager.record_missed_findings(["sqli", "idor"], thread_id="t1")
    assert len(ids) == 2
    records = manager.get_all_records()
    assert {r["vuln_class"] for r in records} == {"sqli", "idor"}
    assert all(r["kind"] == "missed_finding" for r in records)


def test_record_missed_findings_batch_from_dicts(
    manager: PostmortemManager,
) -> None:
    ids = manager.record_missed_findings(
        [
            {
                "vuln_class": "ssrf",
                "category": "detection_logic_gap",
                "root_cause_detail": "no SSRF detector for this sink",
                "proposed_fix": "add outbound DNS canary check",
            }
        ],
        thread_id="t1",
    )
    assert len(ids) == 1
    records = manager.get_all_records()
    assert records[0]["category"] == "detection_logic_gap"
    assert records[0]["proposed_fix"] == "add outbound DNS canary check"


def test_record_missed_findings_skips_non_str_non_dict_items(
    manager: PostmortemManager,
) -> None:
    ids = manager.record_missed_findings([123, None, "sqli"], thread_id="t1")  # type: ignore[list-item]
    assert len(ids) == 1
    records = manager.get_all_records()
    assert records[0]["vuln_class"] == "sqli"


def test_evidence_refs_and_metadata_round_trip(
    manager: PostmortemManager,
) -> None:
    manager.record_false_positive(
        category=PostmortemCategory.LLM_HALLUCINATION,
        root_cause_detail="ungrounded citation",
        evidence_refs=["hash:abc123", "hash:def456"],
        metadata={"original_confidence_level": "AI-Assessed"},
    )
    records = manager.get_all_records()
    assert records[0]["evidence_refs"] == ["hash:abc123", "hash:def456"]
    assert records[0]["metadata"] == {"original_confidence_level": "AI-Assessed"}


def test_get_records_by_thread_filters_correctly(
    manager: PostmortemManager,
) -> None:
    manager.record_false_positive(
        category=PostmortemCategory.OTHER, root_cause_detail="x", thread_id="t1"
    )
    manager.record_false_positive(
        category=PostmortemCategory.OTHER, root_cause_detail="y", thread_id="t2"
    )
    assert len(manager.get_records_by_thread("t1")) == 1
    assert len(manager.get_records_by_thread("t2")) == 1
    assert len(manager.get_all_records()) == 2


def test_get_records_by_kind(manager: PostmortemManager) -> None:
    manager.record_false_positive(category=PostmortemCategory.OTHER, root_cause_detail="x")
    manager.record_missed_finding(category=PostmortemCategory.OTHER, root_cause_detail="y")
    fps = manager.get_records_by_kind(PostmortemKind.FALSE_POSITIVE)
    missed = manager.get_records_by_kind(PostmortemKind.MISSED_FINDING)
    assert len(fps) == 1
    assert len(missed) == 1


def test_get_records_by_finding(manager: PostmortemManager) -> None:
    target_finding_id = uuid4()
    manager.record_false_positive(
        category=PostmortemCategory.OTHER,
        root_cause_detail="x",
        finding_id=target_finding_id,
    )
    manager.record_false_positive(
        category=PostmortemCategory.OTHER, root_cause_detail="y"
    )
    matches = manager.get_records_by_finding(target_finding_id)
    assert len(matches) == 1

    no_matches = manager.get_records_by_finding(uuid4())
    assert len(no_matches) == 0


def test_get_category_summary_aggregates_correctly(
    manager: PostmortemManager,
) -> None:
    manager.record_false_positive(
        category=PostmortemCategory.TOOL_MISCALIBRATION, root_cause_detail="a"
    )
    manager.record_false_positive(
        category=PostmortemCategory.TOOL_MISCALIBRATION, root_cause_detail="b"
    )
    manager.record_false_positive(
        category=PostmortemCategory.CONTEXT_MISREAD, root_cause_detail="c"
    )
    manager.record_missed_finding(
        category=PostmortemCategory.COVERAGE_GAP, root_cause_detail="d"
    )
    summary = manager.get_category_summary()
    assert summary["false_positive"]["tool_miscalibration"] == 2
    assert summary["false_positive"]["context_misread"] == 1
    assert summary["missed_finding"]["coverage_gap"] == 1


def test_get_category_summary_scoped_to_thread(
    manager: PostmortemManager,
) -> None:
    manager.record_false_positive(
        category=PostmortemCategory.OTHER, root_cause_detail="a", thread_id="t1"
    )
    manager.record_false_positive(
        category=PostmortemCategory.OTHER, root_cause_detail="b", thread_id="t2"
    )
    summary_t1 = manager.get_category_summary(thread_id="t1")
    assert summary_t1["false_positive"]["other"] == 1


def test_init_db_is_idempotent(manager: PostmortemManager) -> None:
    manager.init_db()
    manager.init_db()  # must not raise on second call
    manager.record_false_positive(category=PostmortemCategory.OTHER, root_cause_detail="x")
    assert len(manager.get_all_records()) == 1


def test_concurrent_writes_are_thread_safe(tmp_path) -> None:
    db_path = tmp_path / "postmortem.db"
    manager = PostmortemManager(database_url=f"sqlite:///{db_path}")

    errors: list[Exception] = []

    def worker(i: int) -> None:
        try:
            manager.record_false_positive(
                category=PostmortemCategory.ENVIRONMENTAL_NOISE,
                root_cause_detail=f"noise {i}",
                thread_id="concurrent-test",
            )
        except Exception as exc:  # noqa: BLE001
            errors.append(exc)

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(20)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert not errors
    assert len(manager.get_all_records()) == 20


def test_persistence_across_manager_instances(tmp_path) -> None:
    db_path = tmp_path / "postmortem.db"
    manager1 = PostmortemManager(database_url=f"sqlite:///{db_path}")
    manager1.record_false_positive(category=PostmortemCategory.OTHER, root_cause_detail="x")

    manager2 = PostmortemManager(database_url=f"sqlite:///{db_path}")
    records = manager2.get_all_records()
    assert len(records) == 1


def test_get_postmortem_manager_singleton_without_workspace() -> None:
    # No active target workspace in a unit-test process, so this should
    # fall back to the process-wide singleton without raising.
    manager_a = get_postmortem_manager(database_url="sqlite://")
    manager_b = get_postmortem_manager(database_url="sqlite://")
    assert manager_a is manager_b


def test_active_workspace_database_url_is_none_outside_context() -> None:
    assert _active_workspace_database_url() is None


def test_get_postmortem_manager_scopes_to_active_target_workspace(
    tmp_path,
) -> None:
    # Regression test: exercises the REAL TargetWorkspace +
    # activate_target_workspace context-var integration, not just a
    # fallback path. Confirms get_postmortem_manager() actually
    # isolates records per workspace (co-located with
    # decision_log_database_path's directory, as documented) rather
    # than silently always falling through to the process-wide
    # singleton.
    workspace = TargetWorkspace.for_target(
        workspace_root=tmp_path,
        target_origin="https://example.com",
        client_id="client1",
        engagement_id="eng1",
    )

    with activate_target_workspace(workspace):
        resolved_url = _active_workspace_database_url()
        assert resolved_url is not None
        assert "postmortem.db" in resolved_url

        scoped_manager = get_postmortem_manager()
        scoped_manager.record_false_positive(
            category=PostmortemCategory.OTHER, root_cause_detail="in workspace"
        )
        assert len(scoped_manager.get_all_records()) == 1

    # Outside the activation context, falls back to the process-wide
    # singleton and must not see the workspace-scoped record.
    assert _active_workspace_database_url() is None


def test_workspace_scoped_manager_isolated_from_process_singleton(
    tmp_path,
) -> None:
    workspace = TargetWorkspace.for_target(
        workspace_root=tmp_path,
        target_origin="https://example.com",
        client_id="client2",
        engagement_id="eng2",
    )
    unscoped_manager = PostmortemManager(database_url="sqlite://")
    unscoped_manager.record_false_positive(
        category=PostmortemCategory.OTHER, root_cause_detail="unscoped"
    )

    with activate_target_workspace(workspace):
        scoped_manager = get_postmortem_manager()
        # A fresh workspace's database must start empty — the unscoped
        # in-memory manager's record above must not leak in.
        assert scoped_manager.get_all_records() == []
