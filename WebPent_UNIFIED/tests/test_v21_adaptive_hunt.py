from __future__ import annotations

from webpent.models.adaptive_hunt import (
    BranchBudget,
    RevisitOutcome,
    RevisitStatus,
    RevisitSurface,
    RevisitTask,
)
from webpent.models.findings import Confidence, Severity, VulnClass
from webpent.shared import adaptive_hunt
from webpent.shared.adaptive_hunt import (
    apply_revisit_outcome,
    build_adaptive_hunt_update,
    build_targeted_revisit_tasks,
    prioritize_revisit_tasks,
    score_revisit_task,
)


def _finding(
    *,
    finding_id: str,
    url: str = "https://example.test/items?id=1",
    severity: Severity = Severity.HIGH,
    confidence_level: str = "Tool-Confirmed",
    vuln_class: VulnClass = VulnClass.IDOR,
    evidence: dict | None = None,
) -> dict:
    # Return a dict deliberately: checkpoints and LangGraph branches commonly
    # carry serialized records, and the scheduler must accept that shape.
    return {
        "id": finding_id,
        "url": url,
        "severity": severity.value,
        "confidence_level": confidence_level,
        "confidence": Confidence.CONFIRMED.value,
        "vuln_class": vuln_class.value,
        "evidence": evidence or {"auth_pattern": "role:user", "object_family": "invoice"},
        "evidence_refs": [f"evidence:{finding_id}"],
    }


def test_targeted_revisits_are_related_and_deduplicated():
    finding = _finding(finding_id="f-1")
    tasks = build_targeted_revisit_tasks(findings=[finding])

    surfaces = {str(task.surface) for task in tasks}
    assert RevisitSurface.ENDPOINT.value in surfaces
    assert RevisitSurface.AUTH_PATTERN.value in surfaces
    assert RevisitSurface.OBJECT_FAMILY.value in surfaces
    assert all(task.target_url == "https://example.test/items?id=1" for task in tasks)
    assert len({task.surface_key for task in tasks}) == len(tasks)

    repeated = build_targeted_revisit_tasks(
        findings=[finding],
        existing_tasks={task.id: task.model_dump(mode="json") for task in tasks},
    )
    assert repeated == []


def test_priority_ordering_is_deterministic_and_bounded():
    finding = _finding(finding_id="f-2", severity=Severity.CRITICAL, vuln_class=VulnClass.SSRF)
    tasks = build_targeted_revisit_tasks(findings=[finding])
    ordered_a = prioritize_revisit_tasks(tasks, findings=[finding], max_tasks=2)
    ordered_b = prioritize_revisit_tasks(tasks, findings=[finding], max_tasks=2)

    assert [task.surface_key for task in ordered_a] == [task.surface_key for task in ordered_b]
    assert len(ordered_a) == 2
    assert ordered_a[0].score.score >= ordered_a[1].score.score
    assert ordered_a[0].score.rule


def test_score_penalizes_repeated_surface_without_discarding_new_chain_lead():
    finding = _finding(finding_id="f-3")
    task = build_targeted_revisit_tasks(findings=[finding])[0]
    fresh = score_revisit_task(task, finding=finding, prior_surface_counts={})
    repeated = score_revisit_task(task, finding=finding, prior_surface_counts={task.surface_key: 3})

    assert fresh.score.score > repeated.score.score
    assert repeated.score.repetition_penalty == 1.0
    assert "repetition=1.00" in repeated.score.rule


def test_outcome_closes_branch_and_exhausts_budget():
    task = RevisitTask(
        target_url="https://example.test/items?id=1",
        surface=RevisitSurface.ENDPOINT,
        surface_key="endpoint-key",
        task_type="endpoint_revalidation",
        reason="bounded revalidation",
        budget=BranchBudget(max_attempts=1, max_requests=1, max_time_seconds=5),
    )
    outcome = RevisitOutcome(
        task_id=task.id,
        status=RevisitStatus.PENDING,
        requests_used=1,
        time_seconds_used=5,
        note="executor returned no new evidence",
    )
    updated = apply_revisit_outcome(task, outcome)

    assert updated.status == RevisitStatus.BUDGET_EXHAUSTED
    assert updated.budget.requests_used == 1
    assert updated.budget.attempts_used == 1
    assert updated.outcome_note == "executor returned no new evidence"


def test_adaptive_update_is_empty_when_flag_disabled(monkeypatch):
    monkeypatch.setattr(adaptive_hunt, "adaptive_hunt_enabled", lambda: False)
    update = build_adaptive_hunt_update({"findings": [_finding(finding_id="f-4")]})
    assert update == {}


def test_adaptive_update_emits_tasks_and_decision_log_when_enabled(monkeypatch):
    monkeypatch.setattr(adaptive_hunt, "adaptive_hunt_enabled", lambda: True)
    update = build_adaptive_hunt_update({"findings": [_finding(finding_id="f-5")]})

    assert update["adaptive_revisit_tasks"]
    assert update["adaptive_revisit_ledger"]
    assert update["adaptive_hunt"]["selected_count"] >= 1
    assert update["decision_log"]
    assert all(
        entry["decision_type"] == "adaptive_revisit_scheduled" for entry in update["decision_log"]
    )


def test_relational_revisit_is_scoped_to_relation_target():
    finding = _finding(finding_id="f-6")
    tasks = build_targeted_revisit_tasks(
        findings=[finding],
        relational_evidence=[
            {
                "id": "rel-1",
                "source_finding_id": "f-6",
                "relation_type": "same_object_family",
                "target_url": "https://example.test/invoices?id=2",
            }
        ],
    )
    relation_tasks = [task for task in tasks if str(task.surface) == RevisitSurface.RELATION.value]
    assert len(relation_tasks) == 1
    assert relation_tasks[0].target_url == "https://example.test/invoices?id=2"
    assert relation_tasks[0].source_relation_id == "rel-1"
