"""UM-DR-46 Phase I — autonomous QC over the research artifacts.

Deterministic quality checks (no LLM, no I/O) over what the researcher
brain produced:

* per-hypothesis QC — canonical fields complete, evidence contract
  present, origin registered (a HypothesisOrigin member),
  deterministic_match declared;
* per-lesson QC — the Phase C lesson records carry their required
  keys;
* per-plan QC — experiment plans keep their complete observed
  principal matrices (the planner's contract, verified here).

A QC record is a DEFICIENCY REPORT, never a fix, never a deletion —
deficient artifacts stay in the pool flagged for the operator.
"""

from __future__ import annotations

from typing import Any

from webpent.researcher.qc import qc_channel_report

BASE = "https://shop.example"


def _hypothesis(hyp_id: str, **overrides: Any) -> Any:
    from webpent.production.hypothesis_adapter import canonical_hypothesis

    fields: dict[str, Any] = {
        "id": hyp_id,
        "statement": "orders:123 differential",
        "vuln_class": "idor",
        "origin": "researcher_brain",
        "origin_detail": "lab",
        "target_url": BASE,
        "expected_behavior": "denied",
        "negative_control": "owner succeeds",
        "deterministic_match": True,
        "evidence_contract": {"evidence_refs": ["ev-1"]},
    }
    fields.update(overrides)
    return canonical_hypothesis(**fields)


def _pool() -> list[Any]:
    return [
        _hypothesis("11111111-1111-4111-8111-111111111111"),
        _hypothesis("22222222-2222-4222-8222-222222222222",
                    evidence_contract=None),
        _hypothesis("33333333-3333-4333-8333-333333333333",
                    deterministic_match=False),
    ]


class TestHypothesisQc:
    def test_well_formed_hypothesis_passes(self) -> None:
        from webpent.researcher.qc import qc_hypothesis_pool

        records = qc_hypothesis_pool(_pool())
        first = records[0]
        assert first["qc_verdict"] == "pass"
        assert first["deficiencies"] == []
        assert first["checks"]["canonical_fields_complete"] is True
        assert first["checks"]["evidence_contract_present"] is True

    def test_missing_contract_flagged_not_removed(self) -> None:
        from webpent.researcher.qc import qc_hypothesis_pool

        records = qc_hypothesis_pool(_pool())
        second = records[1]
        assert second["qc_verdict"] == "deficient"
        assert "evidence_contract_present" in second["deficiencies"]
        # the artifact STAYS (QC never deletes)
        assert len(records) == 3

    def test_undeterministic_match_flagged(self) -> None:
        from webpent.researcher.qc import qc_hypothesis_pool

        records = qc_hypothesis_pool(_pool())
        third = records[2]
        assert third["checks"]["deterministic_match_declared"] is False
        assert third["qc_verdict"] == "deficient"

    def test_qc_deterministic(self) -> None:
        from webpent.researcher.qc import qc_hypothesis_pool

        assert qc_hypothesis_pool(_pool()) == qc_hypothesis_pool(_pool())


class TestChannelQc:
    def test_lessons_and_plans_checked(self) -> None:
        state = {
            "hypotheses": _pool(),
            "research_lessons": [{
                "lesson_id": "aaaa", "vuln_class": "idor",
                "refuted_hypothesis_id": "1111", "evidence_refs": ["e"],
            }],
            "experiment_plans": [{
                "plan_id": "p1",
                "principal_matrix": {"primary": "alice",
                                     "secondary": "bob"},
            }],
        }
        report = qc_channel_report(state)
        assert report["built"] is True
        assert report["hypothesis_deficient_count"] == 2
        assert report["lesson_deficient_count"] == 0
        assert report["plan_deficient_count"] == 0
        assert report["advisory_only"] is True

    def test_malformed_records_flagged(self) -> None:
        state = {
            "hypotheses": [],
            "research_lessons": [{"lesson_id": "only"}],
            "experiment_plans": [{"plan_id": "p2"}],
        }
        report = qc_channel_report(state)
        assert report["lesson_deficient_count"] == 1
        assert report["plan_deficient_count"] == 1


class TestQcNode:
    def test_node_emits_channel(self) -> None:
        import json

        from webpent.production.research_qc_node import research_qc_node

        state = {"hypotheses": _pool()}
        update = research_qc_node(state)
        assert update["research_qc"]["built"] is True
        assert update["research_qc"]["advisory_only"] is True
        assert update["research_qc"]["hypothesis_deficient_count"] == 2
        json.dumps(update["research_qc"])
