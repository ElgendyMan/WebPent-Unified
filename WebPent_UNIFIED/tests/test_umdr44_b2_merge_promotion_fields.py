"""UM-DR-44 B2 — merging must not silently zero promotion-critical fields.

``_merge_hypothesis_records`` built its ``base`` dict from a fixed field
list that did NOT include any of the five promotion-critical fields:
``deterministic_match``, ``evidence_contract``, ``novelty_score``,
``preconditions_satisfied``, ``info_gain``.  After any re-emission merge,
``Hypothesis.model_validate(base)`` therefore reset those fields to their
model defaults (``deterministic_match=False`` etc.) — and that flag is
what gates probabilistic promotion.  A hypothesis silently lost its
promotion eligibility after every merge.

Per-field preservation policy (documented in the engineering report):

* ``deterministic_match``: sticky True — once deterministic, always
  deterministic (False can never come back after a merge);
* ``evidence_contract``: dict merge, new keys win on collision;
* ``novelty_score`` / ``info_gain``: keep the last declared value
  (existing if present, else the new record's) — never a silent zero;
* ``preconditions_satisfied``: keep the non-None value from either side.
"""

from __future__ import annotations

from uuid import uuid4

from webpent.models.hypothesis import Hypothesis
from webpent.state.reducers import merge_hypotheses

HYP_ID = str(uuid4())


def _full() -> Hypothesis:
    return Hypothesis(
        id=HYP_ID,
        target_url="https://target.example.com/orders",
        statement="object-level authorization is missing on order lookup",
        vuln_class="idor",
        status="investigating",
        confidence_score=0.7,
        deterministic_match=True,
        evidence_contract={
            "required_evidence": ["http_response_diff"],
            "replay_required": True,
        },
        novelty_score=0.42,
        info_gain=0.75,
        preconditions_satisfied=True,
        evidence_refs=["obs://first"],
    )


def _reemission() -> Hypothesis:
    """A re-emission that carries NONE of the promotion fields."""
    return Hypothesis(
        id=HYP_ID,
        target_url="https://target.example.com/orders",
        statement="object-level authorization is missing on order lookup",
        vuln_class="idor",
        status="investigating",
        evidence_refs=["obs://second"],
    )


def _merged() -> Hypothesis:
    pool = merge_hypotheses([], [_full()])
    pool = merge_hypotheses(pool, [_reemission()])
    assert len(pool) == 1
    out = pool[0]
    return out if isinstance(out, Hypothesis) else Hypothesis.model_validate(out)


class TestPromotionFieldsSurviveMerge:
    def test_deterministic_match_is_sticky_true(self) -> None:
        """RED on the current tree: reset to False by model_validate."""
        assert _merged().deterministic_match is True

    def test_evidence_contract_dict_merged(self) -> None:
        merged = _merged()
        assert merged.evidence_contract is not None
        assert merged.evidence_contract.get("required_evidence") == ["http_response_diff"]
        assert merged.evidence_contract.get("replay_required") is True

    def test_novelty_score_preserved(self) -> None:
        assert _merged().novelty_score == 0.42

    def test_info_gain_preserved(self) -> None:
        assert _merged().info_gain == 0.75

    def test_preconditions_satisfied_preserved(self) -> None:
        assert _merged().preconditions_satisfied is True

    def test_new_evidence_refs_accumulate(self) -> None:
        merged = _merged()
        refs = [str(r) for r in (merged.evidence_refs or [])]
        assert "obs://first" in refs and "obs://second" in refs


class TestMergeDirectionPolicies:
    def test_new_record_can_supply_first_contract_and_scores(self) -> None:
        """Existing lacks the fields; the re-emission carries them."""
        rich = _reemission().model_copy(update={
            "deterministic_match": True,
            "evidence_contract": {"replay_required": False},
            "novelty_score": 0.9,
            "info_gain": 0.5,
            "preconditions_satisfied": False,
        })
        pool = merge_hypotheses([], [_reemission()])
        pool = merge_hypotheses(pool, [rich])
        merged = pool[0]
        merged = merged if isinstance(merged, Hypothesis) else Hypothesis.model_validate(merged)
        assert merged.deterministic_match is True
        assert merged.evidence_contract == {"replay_required": False}
        assert merged.novelty_score == 0.9
        assert merged.info_gain == 0.5
        assert merged.preconditions_satisfied is False

    def test_contract_new_keys_added_existing_keys_kept(self) -> None:
        updated = _reemission().model_copy(update={
            "evidence_contract": {"negative_control_required": True},
        })
        pool = merge_hypotheses([], [_full()])
        pool = merge_hypotheses(pool, [updated])
        merged = pool[0]
        merged = merged if isinstance(merged, Hypothesis) else Hypothesis.model_validate(merged)
        contract = merged.evidence_contract or {}
        assert contract.get("required_evidence") == ["http_response_diff"]
        assert contract.get("negative_control_required") is True
