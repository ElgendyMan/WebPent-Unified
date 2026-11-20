"""UM-DR-37 §6 — hypothesis lifecycle registry tests (adversarial)."""

from __future__ import annotations

from webpent.research.hypothesis_lifecycle import (
    STAGE_TRANSITIONS,
    HypothesisLifecycle,
    LifecycleStage,
)


def test_all_twelve_stages_exist_and_are_covered() -> None:
    expected = {
        "GENERATED", "NORMALIZED", "DEDUPLICATED", "RANKED", "SELECTED",
        "EXECUTED", "SUPPORTED", "REFUTED", "INCONCLUSIVE", "SUPERSEDED",
        "REOPENED", "CLOSED",
    }
    assert {stage.value for stage in LifecycleStage} == expected
    # every stage appears in the transition graph as a source, and every
    # stage except the entry state GENERATED appears as a target
    targets = {target for targets in STAGE_TRANSITIONS.values()
               for target in targets}
    assert set(STAGE_TRANSITIONS) == set(LifecycleStage)
    assert targets == set(LifecycleStage) - {LifecycleStage.GENERATED}


def test_full_supported_path_records_reasoned_history() -> None:
    life = HypothesisLifecycle(hypothesis_id="h-1")
    for target, code in (
        (LifecycleStage.NORMALIZED, "normalized"),
        (LifecycleStage.DEDUPLICATED, "survivor_of_dedup"),
        (LifecycleStage.RANKED, "info_gain_ranked"),
        (LifecycleStage.SELECTED, "selected_next"),
        (LifecycleStage.EXECUTED, "experiment_executed"),
        (LifecycleStage.SUPPORTED, "evidence_supported"),
    ):
        assert life.transition(target, reason_code=code,
                               reason=f"{code} — test")
    assert life.stage is LifecycleStage.SUPPORTED
    assert life.is_terminal
    assert [event.reason_code for event in life.history] == [
        "normalized", "survivor_of_dedup", "info_gain_ranked",
        "selected_next", "experiment_executed", "evidence_supported",
    ]
    assert all(event.at for event in life.history)


def test_invalid_transitions_are_rejected() -> None:
    life = HypothesisLifecycle(hypothesis_id="h-2")
    # no shortcuts: GENERATED cannot jump to selection or resolution
    assert not life.transition(LifecycleStage.SUPPORTED,
                               reason_code="shortcuts",
                               reason="attempted shortcut")
    assert not life.transition(LifecycleStage.SELECTED,
                               reason_code="shortcuts",
                               reason="attempted shortcut")
    assert life.stage is LifecycleStage.GENERATED
    # no reason, no transition
    assert not life.transition(LifecycleStage.NORMALIZED,
                               reason_code="", reason="")
    # REFUTED is terminal: only evidence-gated reopening leaves it
    life.transition(LifecycleStage.NORMALIZED, reason_code="n",
                    reason="n")
    life.transition(LifecycleStage.CLOSED, reason_code="closed",
                    reason="closed without execution")
    assert not life.transition(LifecycleStage.SELECTED,
                               reason_code="resurrect",
                               reason="attempted resurrection")
    assert life.stage is LifecycleStage.CLOSED


def test_reopening_requires_new_evidence() -> None:
    life = HypothesisLifecycle(hypothesis_id="h-3")
    life.transition(LifecycleStage.NORMALIZED, reason_code="n", reason="n")
    life.transition(LifecycleStage.CLOSED, reason_code="closed",
                    reason="closed")
    # without evidence: refused
    assert not life.reopen(new_evidence_refs=[])
    assert life.stage is LifecycleStage.CLOSED
    # with new evidence: reopened, and the refs are recorded
    assert life.reopen(new_evidence_refs=["obs:new-evidence-1"])
    assert life.stage is LifecycleStage.REOPENED
    assert life.history[-1].evidence_refs == ("obs:new-evidence-1",)
    # REOPENED re-enters the pool at NORMALIZED — never straight to
    # SELECTED
    assert not life.transition(LifecycleStage.SELECTED,
                               reason_code="jump", reason="jump")
    assert life.transition(LifecycleStage.NORMALIZED,
                           reason_code="renormalized", reason="re-enter")


def test_inconclusive_never_auto_refutes() -> None:
    life = HypothesisLifecycle(hypothesis_id="h-4")
    for target, code in (
        (LifecycleStage.NORMALIZED, "n"),
        (LifecycleStage.DEDUPLICATED, "d"),
        (LifecycleStage.RANKED, "r"),
        (LifecycleStage.SELECTED, "s"),
        (LifecycleStage.EXECUTED, "e"),
    ):
        assert life.transition(target, reason_code=code, reason=code)
    assert life.transition(LifecycleStage.INCONCLUSIVE,
                           reason_code="experiment_inconclusive",
                           reason="probe could not discriminate")
    # automatic refutation from inconclusive: REFUSED (no evidence)
    assert not life.transition(LifecycleStage.REFUTED,
                               reason_code="auto_refute",
                               reason="treated absence of evidence as "
                                      "refutation")
    assert life.stage is LifecycleStage.INCONCLUSIVE
    # explicit refutation WITH new discriminating evidence: allowed
    assert life.transition(
        LifecycleStage.REFUTED, reason_code="refuted_with_evidence",
        reason="follow-up discriminated against the hypothesis",
        evidence_refs=["obs:decisive-1"])
    assert life.stage is LifecycleStage.REFUTED
    # an inconclusive result may instead generate a follow-up experiment
    other = HypothesisLifecycle(hypothesis_id="h-4b")
    for target, code in (
        (LifecycleStage.NORMALIZED, "n"), (LifecycleStage.RANKED, "r"),
        (LifecycleStage.SELECTED, "s"), (LifecycleStage.EXECUTED, "e"),
    ):
        assert other.transition(target, reason_code=code, reason=code)
    assert other.transition(LifecycleStage.INCONCLUSIVE,
                            reason_code="experiment_inconclusive",
                            reason="undiscriminating")
    assert other.transition(LifecycleStage.SELECTED,
                            reason_code="follow_up_selected",
                            reason="more discriminating follow-up")


def test_duplicate_merge_bookkeeping_is_bidirectional() -> None:
    canonical = HypothesisLifecycle(hypothesis_id="h-canonical")
    canonical.transition(LifecycleStage.NORMALIZED, reason_code="n",
                         reason="n")
    duplicate = HypothesisLifecycle(hypothesis_id="h-duplicate")
    duplicate.transition(LifecycleStage.NORMALIZED, reason_code="n",
                         reason="n")
    duplicate.transition(LifecycleStage.DEDUPLICATED,
                         reason_code="duplicate_detected",
                         reason="same target entity + invariant as "
                                "h-canonical")
    assert duplicate.mark_duplicate_of(canonical)
    assert duplicate.stage is LifecycleStage.CLOSED
    assert duplicate.merged_into == "h-canonical"
    assert canonical.merged_ids == ["h-duplicate"]
    assert canonical.children == ["h-duplicate"]
    assert duplicate.parents == ["h-canonical"]
    # merging is only valid from the DEDUPLICATED gate
    early = HypothesisLifecycle(hypothesis_id="h-early")
    assert not early.mark_duplicate_of(canonical)


def test_supersession_bookkeeping_is_bidirectional() -> None:
    original = HypothesisLifecycle(hypothesis_id="h-v1")
    original.transition(LifecycleStage.NORMALIZED, reason_code="n",
                        reason="n")
    successor = HypothesisLifecycle(hypothesis_id="h-v2-sharper")
    assert original.supersede(
        successor, reason_code="sharper_reformulation",
        reason="h-v2 names the exact alternate endpoint; h-v1 is its "
               "coarser form")
    assert original.stage is LifecycleStage.SUPERSEDED
    assert original.superseded_by == "h-v2-sharper"
    assert successor.superseded_ids == ["h-v1"]
    assert successor.parents == ["h-v1"]
    assert original.children == ["h-v2-sharper"]
    # a superseded hypothesis can return ONLY with new evidence
    assert not original.reopen(new_evidence_refs=[])
    assert original.reopen(new_evidence_refs=["obs:changed-app-behavior"])


def test_competing_relations_are_symmetric_explicit() -> None:
    a = HypothesisLifecycle(hypothesis_id="h-alternate-endpoint")
    b = HypothesisLifecycle(hypothesis_id="h-parameter-influence")
    a.competes_with(b.hypothesis_id)
    b.competes_with(a.hypothesis_id)
    assert a.competing_with == ["h-parameter-influence"]
    assert b.competing_with == ["h-alternate-endpoint"]
    # self-competition is refused
    a.competes_with(a.hypothesis_id)
    assert a.competing_with == ["h-parameter-influence"]


def test_to_dict_carries_the_full_auditable_record() -> None:
    life = HypothesisLifecycle(hypothesis_id="h-dict")
    life.transition(LifecycleStage.NORMALIZED, reason_code="n", reason="n")
    dump = life.to_dict()
    assert dump["hypothesis_id"] == "h-dict"
    assert dump["stage"] == "NORMALIZED"
    assert dump["history"][0]["reason_code"] == "n"
    assert dump["is_terminal"] is False
