"""UM-DR-46 Phase C — the adaptive hypothesis engine (evolution).

The mission's Phase C: mutation of refuted hypotheses, decomposition
of compound hypotheses, SKG-grounded competing hypotheses, negative-
evidence learning and information-gain selection — ALL deterministic
pure functions (no LLM) feeding the ordinary hypothesis pool (the
strategist's ``rank_open_hypotheses`` ranks whatever the pool holds).

Lab fixture: a small pool with ONE resolved-false (refuted) parent
hypothesis plus related/compound hypotheses; ground truth declared.
"""

from __future__ import annotations

from typing import Any

from webpent.researcher.evolution import (
    competing_hypotheses,
    decompose_hypothesis,
    learn_from_negative_evidence,
    mutate_hypothesis,
    select_by_info_gain,
)

BASE = "https://shop.example"
PARENT_ID = "11111111-1111-4111-8111-111111111111"
RELATED_ID = "22222222-2222-4222-8222-222222222222"
UNRELATED_ID = "33333333-3333-4333-8333-333333333333"


def _hypothesis(hyp_id: str, **overrides: Any) -> Any:
    from webpent.production.hypothesis_adapter import canonical_hypothesis

    fields: dict[str, Any] = {
        "id": hyp_id,
        "statement": "orders:123 readable by bob without ownership",
        "vuln_class": "idor",
        "origin": "researcher_brain",
        "origin_detail": "SKG lab",
        "target_url": BASE,
        "expected_behavior": "denied for non-owner",
        "negative_control": "owner replay succeeds",
    }
    fields.update(overrides)
    return canonical_hypothesis(**fields)


def _pool() -> list[Any]:
    parent = _hypothesis(
        PARENT_ID,
        status="resolved_false",
        deterministic_match=True,
        info_gain=0.8,
        evidence_contract={"evidence_refs": ["ev-1"], "kind": "idor"},
    )
    related = _hypothesis(
        RELATED_ID,
        statement="orders:456 readable by bob without ownership",
        info_gain=0.6,
        deterministic_match=True,
        evidence_contract={"evidence_refs": ["ev-2"], "kind": "idor"},
    )
    unrelated = _hypothesis(
        UNRELATED_ID,
        statement="ssti in the search template",
        vuln_class="ssti",
        info_gain=0.9,
    )
    return [parent, related, unrelated]


def _model_of(state: dict[str, Any]) -> Any:
    from webpent.appmodel.skg import build_security_knowledge_graph

    return build_security_knowledge_graph(state)


def _skg_state() -> dict[str, Any]:
    """Compact SKG fixture (same lab pattern as Phase A/B)."""
    return {
        "engagement_id": "umdr46-evolution-lab",
        "target_url": BASE,
        "base_url": BASE,
        "crawled_data": {"openapi_routes": [
            {"method": "GET", "path": "/api/orders/123"},
        ]},
        "object_identity_observations": [
            {"endpoint": "/api/orders/123", "resource_type": "orders",
             "object_id": "123", "tenant": "t1", "observation_ref": "ob-1"},
        ],
        "authorization_observations": [
            {"finding_id": "f-1", "vuln_class": "idor", "source_node": "test",
             "guard_verdict": "confirmed", "actor_id": "bob",
             "resource_id": "orders:123", "resource_owner": "alice",
             "ownership_basis": "lab"},
        ],
    }


class TestMutation:
    """تعديل الفرضيات المرفوضة — deterministic templates per class."""

    def test_idor_refuted_yields_three_mutations(self) -> None:
        parent = _pool()[0]
        mutations = mutate_hypothesis(parent)
        assert len(mutations) == 3
        for m in mutations:
            assert m.origin == "researcher_brain" or str(m.origin) == (
                "HypothesisOrigin.RESEARCHER_BRAIN")
            assert m.deterministic_match is True
            assert m.vuln_class == "idor"
            assert m.evidence_contract.get("parent_hypothesis_id") == PARENT_ID
            assert m.info_gain <= parent.info_gain  # decayed
            assert m.statement != parent.statement

    def test_mutations_are_deterministic_and_deduplicable(self) -> None:
        parent = _pool()[0]
        one = mutate_hypothesis(parent)
        two = mutate_hypothesis(parent)
        assert [str(m.id) for m in one] == [str(m.id) for m in two]
        # re-emission dedupes through the pool reducer (same ids)
        from webpent.state.reducers import merge_hypotheses

        first = merge_hypotheses([], one)
        second = merge_hypotheses(first, two)
        assert len(second) == 3

    def test_only_refuted_parents_mutate(self) -> None:
        from webpent.models.hypothesis import HypothesisStatus

        open_hyp = _hypothesis(UNRELATED_ID)
        assert open_hyp.status == HypothesisStatus.UNEXPLORED
        assert mutate_hypothesis(open_hyp) == []

    def test_unrelated_class_uses_fallback_templates(self) -> None:
        parent = _hypothesis(
            PARENT_ID, vuln_class="ssti", status="resolved_false",
            statement="template engine evaluates operator input")
        mutations = mutate_hypothesis(parent)
        assert 1 <= len(mutations) <= 3
        assert all(m.vuln_class == "ssti" for m in mutations)


class TestDecomposition:
    """تقسيم الفرضيات المركّبة — deterministic step split."""

    def test_compound_hypothesis_decomposes(self) -> None:
        compound = _hypothesis(
            PARENT_ID,
            statement=(
                "orders:123 readable by bob without ownership then the "
                "same bypass applies to orders:456"
            ),
        )
        steps = decompose_hypothesis(compound)
        assert len(steps) == 2
        for index, step in enumerate(steps):
            assert step.evidence_contract.get("parent_hypothesis_id") == PARENT_ID
            assert step.evidence_contract.get("step_index") == index
            assert step.evidence_contract.get("step_count") == 2
            assert step.statement

    def test_atomic_hypothesis_stays_whole(self) -> None:
        atomic = _hypothesis(UNRELATED_ID, statement="no chaining phrase here")
        assert decompose_hypothesis(atomic) == []


class TestCompetingHypotheses:
    """الفرضيات المنافسة — SKG-grounded alternatives."""

    def test_competitors_are_skg_grounded(self) -> None:
        model = _model_of(_skg_state())
        parent = _pool()[0]
        competitors = competing_hypotheses(parent, model)
        assert competitors, "the lab SKG must ground competitors"
        assert len(competitors) <= 3
        for c in competitors:
            assert c.id != parent.id
            assert c.evidence_contract.get("parent_hypothesis_id") == PARENT_ID
            assert c.evidence_contract.get("competitor_basis")
            assert c.negative_control

    def test_competitors_deterministic(self) -> None:
        model = _model_of(_skg_state())
        parent = _pool()[0]
        one = [str(c.id) for c in competing_hypotheses(parent, model)]
        two = [str(c.id) for c in competing_hypotheses(parent, model)]
        assert one == two


class TestNegativeEvidenceLearning:
    """التعلم من الدليل السلبي — related decay + deterministic lesson."""

    def test_related_hypotheses_decay_and_lesson_recorded(self) -> None:
        pool = _pool()
        parent = pool[0]
        updated, lesson = learn_from_negative_evidence(pool, parent)
        # parent untouched, related DECAYED, unrelated untouched
        related = next(h for h in updated if str(h.id) == RELATED_ID)
        unrelated = next(h for h in updated if str(h.id) == UNRELATED_ID)
        assert related.info_gain < 0.6
        assert related.evidence_contract.get("negative_lesson_id") == lesson[
            "lesson_id"]
        assert unrelated.info_gain == 0.9
        assert lesson["refuted_hypothesis_id"] == PARENT_ID
        assert lesson["vuln_class"] == "idor"
        assert RELATED_ID in lesson["related_hypothesis_ids"]
        assert UNRELATED_ID not in lesson["related_hypothesis_ids"]
        assert lesson["evidence_refs"] == ["ev-1"]

    def test_learning_is_pure(self) -> None:
        pool = _pool()
        before = [str(h.id) + str(h.info_gain) for h in pool]
        learn_from_negative_evidence(pool, pool[0])
        after = [str(h.id) + str(h.info_gain) for h in pool]
        assert before == after


class TestInfoGainSelection:
    """اختيار عالي المعلومات — deterministic ordering."""

    def test_order_and_open_filter(self) -> None:
        pool = _pool()  # parent is resolved_false → excluded
        selected = select_by_info_gain(pool, limit=3)
        ids = [str(h.id) for h in selected]
        assert PARENT_ID not in ids
        assert len(selected) == 2
        # repo convention (rank_open_hypotheses): deterministic-match
        # hypotheses first, then info_gain desc — related (0.6,
        # deterministic) outranks unrelated (0.9, non-deterministic)
        assert ids[0] == RELATED_ID
        one = [str(h.id) for h in select_by_info_gain(pool, limit=3)]
        assert one == ids

    def test_limit_respected(self) -> None:
        pool = _pool()
        assert len(select_by_info_gain(pool, limit=1)) == 1


class TestEvolutionNode:
    """The production node: pool additions + lessons + priorities."""

    def test_node_emits_pool_additions_and_lessons(self) -> None:
        from webpent.production.hypothesis_evolution import (
            hypothesis_evolution_node,
        )

        state = _skg_state()
        state["hypotheses"] = _pool()
        update = hypothesis_evolution_node(state)
        assert update["researcher_evolution"]["built"] is True
        assert update["researcher_evolution"]["advisory_only"] is True
        hyps = update["hypotheses"]
        ids = {str(h.id) for h in hyps}
        assert len(ids) == len(hyps), "ids must be unique within one emission"
        assert len(update["research_lessons"]) == 1
        assert update["researcher_priorities"]["advisory_only"] is True
        assert update["researcher_priorities"]["selected_count"] >= 1
        for hyp in hyps:
            for field in ("statement", "vuln_class", "origin",
                          "origin_detail", "expected_behavior",
                          "negative_control", "target_url"):
                assert str(getattr(hyp, field) or "").strip(), field

    def test_node_output_json_safe_and_deterministic(self) -> None:
        import json

        from webpent.production.hypothesis_evolution import (
            hypothesis_evolution_node,
        )

        state = _skg_state()
        state["hypotheses"] = _pool()
        one = hypothesis_evolution_node(state)
        two = hypothesis_evolution_node(state)
        assert [str(h.id) for h in one["hypotheses"]] == [
            str(h.id) for h in two["hypotheses"]]
        json.dumps(one["researcher_evolution"])
        json.dumps(one["research_lessons"])

    def test_empty_pool_yields_noop(self) -> None:
        from webpent.production.hypothesis_evolution import (
            hypothesis_evolution_node,
        )

        update = hypothesis_evolution_node(_skg_state())
        assert update["hypotheses"] == []
        assert update["research_lessons"] == []
