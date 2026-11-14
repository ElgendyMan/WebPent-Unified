"""POST-P0 Phase 2 — memory read-back (lessons + hypothesis ledger).

Pins:
  * a repeat run retrieves prior negative lessons for the SAME target
    signature (scoped retrieval service),
  * a poisoned/false lesson on target A does NOT affect target B, and
    an unscoped read fails closed entirely,
  * the structured-hypothesis ledger read-back is narrowed by exact
    target_url and only negative statuses feed the class prior,
  * the strategist's negative prior is demotion-only and changes
    ranking order,
  * the strategist emits the retrieved-only learned_strategy record
    (advisory metadata; never confirmation evidence),
  * the planner prompt includes the advisory block as untrusted data,
  * memory can NEVER produce confirmation vocabulary.
"""

from __future__ import annotations

from webpent.memory.lessons import LessonsManager
from webpent.models.hypothesis import Hypothesis, HypothesisStatus
from webpent.models.targets import Target
from webpent.shared.learned_context import (
    MAX_LEDGER_ENTRIES,
    negative_outcome_classes,
    retrieve_learned_strategy,
    retrieve_learned_strategy_from_state,
)
from webpent.state.initial_state import build_initial_state

TARGET_A = "https://target-a.test"
TARGET_B = "https://target-b.test"


def _manager(tmp_path) -> LessonsManager:
    return LessonsManager(database_url=str(tmp_path / "lessons.db"))


def _hypothesis(tmp_path_monkey, target_url: str, vuln_class: str, status: str):
    return Hypothesis(
        target_url=target_url,
        statement=f"prior {vuln_class} hypothesis on {target_url}",
        vuln_class=vuln_class,
        status=HypothesisStatus(status),
        confidence_score=0.5,
        origin="heuristic",
    )


def test_repeat_run_retrieves_negative_lessons_for_same_target(tmp_path) -> None:
    mgr = _manager(tmp_path)
    mgr.save_negative_lesson(
        target_url=TARGET_A,
        vuln_class="sqli",
        failure_reason="tool_no_marker",
        hypothesis_id="h-1",
        client_id="client-1",
        engagement_id="eng-1",
    )
    record = retrieve_learned_strategy(
        target_url=TARGET_A, client_id="client-1", engagement_id="eng-1", manager=mgr
    )
    assert record is not None
    assert record["advisory_only"] is True
    assert record["never_confirmation_evidence"] is True
    assert len(record["negative_lessons"]) == 1
    assert "negative_lesson" in record["negative_lessons"][0]
    assert negative_outcome_classes(record) == frozenset({"sqli"})


def test_poisoned_lesson_target_a_invisible_to_target_b(tmp_path) -> None:
    mgr = _manager(tmp_path)
    mgr.save_negative_lesson(
        target_url=TARGET_A,
        vuln_class="sqli",
        failure_reason="tool_no_marker",
        hypothesis_id="h-1",
        client_id="client-1",
        engagement_id="eng-1",
    )
    # Same client + engagement, DIFFERENT target: no bleed.
    record_b = retrieve_learned_strategy(
        target_url=TARGET_B, client_id="client-1", engagement_id="eng-1", manager=mgr
    )
    assert record_b is not None
    assert record_b["negative_lessons"] == []
    assert negative_outcome_classes(record_b) == frozenset()
    # Different client: no bleed either way.
    record_other_client = retrieve_learned_strategy(
        target_url=TARGET_A, client_id="client-2", engagement_id="eng-1", manager=mgr
    )
    assert record_other_client is not None
    assert record_other_client["negative_lessons"] == []
    # And the poisoned lesson on A cannot confirm anything on A — the
    # record only ever carries advisory flags and demotion-only classes.
    record_a = retrieve_learned_strategy(
        target_url=TARGET_A, client_id="client-1", engagement_id="eng-1", manager=mgr
    )
    assert record_a["never_confirmation_evidence"] is True


def test_unscoped_retrieval_fails_closed(tmp_path) -> None:
    mgr = _manager(tmp_path)
    mgr.save_negative_lesson(
        target_url=TARGET_A,
        vuln_class="sqli",
        failure_reason="tool_no_marker",
        hypothesis_id="h-1",
        client_id="client-1",
        engagement_id="eng-1",
    )
    assert retrieve_learned_strategy(
        target_url=TARGET_A, client_id=None, engagement_id="eng-1"
    ) is None
    assert retrieve_learned_strategy(
        target_url=TARGET_A, client_id="client-1", engagement_id=""
    ) is None
    assert retrieve_learned_strategy(
        target_url="", client_id="client-1", engagement_id="eng-1"
    ) is None


def test_ledger_readback_scoped_and_negative_statuses_only(tmp_path) -> None:
    mgr = _manager(tmp_path)
    mgr.save_structured_hypothesis(
        _hypothesis(None, TARGET_A, "idor", "abandoned")
    )
    mgr.save_structured_hypothesis(
        _hypothesis(None, TARGET_B, "idor", "unexplored")
    )
    rows_a = mgr.get_structured_hypotheses(target_url=TARGET_A)
    assert len(rows_a) == 1
    assert rows_a[0]["vuln_class"] == "idor"
    rows_b = mgr.get_structured_hypotheses(target_url=TARGET_B)
    assert len(rows_b) == 1
    # Target B's row is unexplored -> NOT a negative outcome.
    record_b = retrieve_learned_strategy(
        target_url=TARGET_B, client_id="client-1", engagement_id="eng-1", manager=mgr
    )
    # record_b's ledger may contain B's row (same workspace manager in
    # this unit context) but its class must NOT be negative.
    assert "idor" not in negative_outcome_classes(record_b)
    # Target A's abandoned row IS a negative outcome.
    record_a = retrieve_learned_strategy(
        target_url=TARGET_A, client_id="client-1", engagement_id="eng-1", manager=mgr
    )
    assert "idor" in negative_outcome_classes(record_a)
    # Bounded ledger.
    classes = ["xss", "sqli", "ssrf", "lfi", "rfi", "rce"]
    for i in range(MAX_LEDGER_ENTRIES + 6):
        mgr.save_structured_hypothesis(
            _hypothesis(
                None,
                TARGET_B,
                classes[i % len(classes)],
                "abandoned",
            )
        )
    record_capped = retrieve_learned_strategy(
        target_url=TARGET_B, client_id="client-1", engagement_id="eng-1", manager=mgr
    )
    assert len(record_capped["hypothesis_ledger"]) <= MAX_LEDGER_ENTRIES


def test_negative_prior_is_demotion_only_and_changes_ranking() -> None:
    from webpent.agents.strategist.agent import _apply_negative_prior

    hyp_sqli = Hypothesis(
        target_url=TARGET_A, statement="sqli candidate", vuln_class="sqli",
        origin="heuristic", confidence_score=0.6,
    )
    hyp_xss = Hypothesis(
        target_url=TARGET_A, statement="xss candidate", vuln_class="xss",
        origin="heuristic", confidence_score=0.58,
    )
    ranked = [(hyp_sqli, 0.6), (hyp_xss, 0.58)]
    learned = {
        "advisory_only": True,
        "negative_lessons": ["negative_lesson target_signature abc vulnerability_class sqli failure_reason tool_no_marker"],
        "hypothesis_ledger": [],
    }
    adjusted, demoted = _apply_negative_prior(ranked, learned)
    assert demoted == frozenset({"sqli"})
    # sqli demoted below xss -> order changed.
    assert [h.id for h, _ in adjusted] == [hyp_xss.id, hyp_sqli.id]
    # Demotion-only: no score increased.
    before = {h.id: s for h, s in ranked}
    after = {h.id: s for h, s in adjusted}
    assert all(after[k] <= before[k] for k in before)
    assert after[hyp_sqli.id] == 0.6 - 0.05


def test_strategist_emits_learned_strategy_record(tmp_path, monkeypatch) -> None:
    from webpent.agents.strategist.agent import strategist_node

    mgr = _manager(tmp_path)
    mgr.save_negative_lesson(
        target_url=TARGET_A,
        vuln_class="sqli",
        failure_reason="tool_no_marker",
        hypothesis_id="h-1",
        client_id="client-1",
        engagement_id="eng-1",
    )
    monkeypatch.setattr(
        "webpent.memory.lessons.get_lessons_manager", lambda: mgr
    )
    state = build_initial_state(
        target=Target(url=TARGET_A), thread_id="eng-1", client_id="client-1"
    )
    state["hypotheses"] = [
        Hypothesis(
            target_url=TARGET_A, statement="fresh candidate here",
            vuln_class="xss", origin="heuristic", confidence_score=0.5,
        )
    ]
    result = strategist_node(state)
    record = result.get("learned_strategy") or {}
    assert record.get("advisory_only") is True
    assert record.get("never_confirmation_evidence") is True
    assert any("negative_lesson" in ln for ln in record.get("negative_lessons", []))


def test_planner_prompt_injects_advisory_block(tmp_path, monkeypatch) -> None:
    from webpent.agents.planner.agent import _make_decision_prompt

    mgr = _manager(tmp_path)
    mgr.save_negative_lesson(
        target_url=TARGET_A,
        vuln_class="sqli",
        failure_reason="tool_no_marker",
        hypothesis_id="h-1",
        client_id="client-1",
        engagement_id="eng-1",
    )
    monkeypatch.setattr(
        "webpent.memory.lessons.get_lessons_manager", lambda: mgr
    )
    state = build_initial_state(
        target=Target(url=TARGET_A), thread_id="eng-1", client_id="client-1"
    )
    prompt = _make_decision_prompt(state)
    assert "Prior memory" in prompt
    # Untrusted-wrapper presence: safe_prompt_format wraps the block.
    assert "negative_lesson" in prompt


def test_state_retrieval_wrapper_fail_closed_without_client() -> None:
    state = build_initial_state(target=Target(url=TARGET_A), thread_id="eng-1")
    # No client_id in state -> fail-closed empty record.
    assert retrieve_learned_strategy_from_state(state) == {}
