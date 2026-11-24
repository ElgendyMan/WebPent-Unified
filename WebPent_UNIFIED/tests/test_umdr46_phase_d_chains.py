"""UM-DR-46 Phase D — cross-feature attack reasoning (SKG chains).

The mission's Phase D: compose the SKG's evidence-backed facts into
multi-step attack-chain candidates BEFORE any finding exists
(pre-finding reasoning — the findings-level analogue already lives in
production/chain_composer.py). ALL deterministic, advisory, evidence-
carrying; each step names its causal-guard validation contract.

Lab fixture (derived from the Phase B brain fixture): the planted
composition is invoices:900 carrying BOTH an unmarked read (info leg)
AND an unmarked ownership change (authz leg) → the composed
info+authz chain; plus the workflow-skip chain and the cross-surface
chain. Ground truth declared: exactly 3 chains.
"""

from __future__ import annotations

from typing import Any

from webpent.researcher.attack_chains import (
    compose_attack_chains,
    summarize_chains,
)

BASE = "https://shop.example"


def _chain_state() -> dict[str, Any]:
    """Phase D fixture = Phase B fixture verbatim (the compositions are
    derivable from the same evidence)."""
    from tests.test_umdr46_phase_b_brain import _brain_state

    return _brain_state()


def _model_of(state: dict[str, Any]) -> Any:
    from webpent.appmodel.skg import build_security_knowledge_graph

    return build_security_knowledge_graph(state)


class TestChainComposition:
    """سلاسل الهجوم المركبة — evidence-backed multi-step candidates."""

    def test_exactly_three_chains_of_expected_kinds(self) -> None:
        model = _model_of(_chain_state())
        chains = compose_attack_chains(model)
        kinds = sorted(c["kind"] for c in chains)
        assert kinds == [
            "cross_surface_chain",
            "info_authz_composition",
            "workflow_bypass_chain",
        ]
        for chain in chains:
            assert chain["advisory_only"] is True
            assert chain["required_validation"] == "causal-guard differential"
            assert len(chain["steps"]) >= 2
            for step in chain["steps"]:
                assert step["evidence_refs"], f"step without evidence: {step}"

    def test_info_authz_chain_on_invoices_900(self) -> None:
        model = _model_of(_chain_state())
        chains = compose_attack_chains(model)
        info_authz = next(
            c for c in chains if c["kind"] == "info_authz_composition")
        paths = {step.get("path") or "" for step in info_authz["steps"]}
        assert "/api/admin/invoices/900" in paths
        assert any("invoices:900" in str(step) for step in info_authz["steps"])
        assert "ev-acc-1" in info_authz["evidence_refs"]
        assert "ev-own-2" in info_authz["evidence_refs"]

    def test_workflow_bypass_chain_names_the_gated_target(self) -> None:
        model = _model_of(_chain_state())
        chains = compose_attack_chains(model)
        wf = next(c for c in chains if c["kind"] == "workflow_bypass_chain")
        steps_text = " | ".join(str(step) for step in wf["steps"])
        assert "pending" in steps_text and "approved" in steps_text
        assert "review" in steps_text  # the skipped state is named
        assert "role_scoped" in steps_text or any(
            step.get("role_scoped") for step in wf["steps"])

    def test_cross_surface_chain_pairs_diff_with_parameter(self) -> None:
        model = _model_of(_chain_state())
        chains = compose_attack_chains(model)
        surface = next(c for c in chains if c["kind"] == "cross_surface_chain")
        steps_text = " ".join(str(step) for step in surface["steps"])
        assert "/orders" in steps_text and "/api/v1/orders" in steps_text

    def test_marked_endpoints_never_compose(self) -> None:
        # the transfer ownership change is MARKED (openapi security) and
        # orders:789 has no unmarked read — no chain must form for it
        model = _model_of(_chain_state())
        chains = compose_attack_chains(model)
        for chain in chains:
            paths = {step.get("path") or "" for step in chain["steps"]}
            assert "/api/orders/789/transfer" not in paths

    def test_clean_model_composes_nothing(self) -> None:
        state = _chain_state()
        state["skg_evidence"] = [
            e for e in state["skg_evidence"]
            if e.get("evidence_refs") not in (["ev-own-2"], ["ev-acc-1"])
        ]
        state["workflow_observations"] = [
            w for w in state["workflow_observations"]
            if w["transition_key"] != "fasttrack"
        ]
        state["crawled_data"]["openapi_routes"] = [
            r for r in state["crawled_data"]["openapi_routes"]
            if r["path"] not in ("/orders", "/api/v1/orders")
        ]
        model = _model_of(state)
        assert compose_attack_chains(model) == []

    def test_composition_is_deterministic(self) -> None:
        model = _model_of(_chain_state())
        one = compose_attack_chains(model)
        two = compose_attack_chains(model)
        assert one == two


class TestChainHypotheses:
    """One canonical hypothesis per chain, deterministic ids."""

    def test_hypotheses_canonical_and_deduplicable(self) -> None:
        from webpent.researcher.attack_chains import chain_hypotheses
        from webpent.state.reducers import merge_hypotheses

        model = _model_of(_chain_state())
        hyps = chain_hypotheses(model, BASE)
        assert len(hyps) == 3
        for hyp in hyps:
            for field in ("statement", "vuln_class", "origin",
                          "origin_detail", "expected_behavior",
                          "negative_control", "target_url"):
                assert str(getattr(hyp, field) or "").strip(), field
        first = merge_hypotheses([], hyps)
        second = merge_hypotheses(first, chain_hypotheses(model, BASE))
        assert len(second) == 3, "re-emission must dedupe"


class TestChainNode:
    """The production node: channels + canonical pool additions."""

    def test_node_emits_channels(self) -> None:
        from webpent.production.attack_chains_node import attack_chain_node

        update = attack_chain_node(_chain_state())
        assert update["attack_chain_summary"]["built"] is True
        assert update["attack_chain_summary"]["advisory_only"] is True
        assert update["attack_chain_summary"]["chain_count"] == 3
        assert len(update["attack_chains"]) == 3
        assert len(update["hypotheses"]) == 3

    def test_node_output_json_safe(self) -> None:
        import json

        from webpent.production.attack_chains_node import attack_chain_node

        update = attack_chain_node(_chain_state())
        json.dumps(update["attack_chains"])
        json.dumps(update["attack_chain_summary"])

    def test_empty_state_yields_noop(self) -> None:
        from webpent.production.attack_chains_node import attack_chain_node

        update = attack_chain_node({"engagement_id": "empty"})
        assert update["attack_chains"] == []
        assert update["hypotheses"] == []


class TestSummarize:
    def test_summary_counts(self) -> None:
        model = _model_of(_chain_state())
        summary = summarize_chains(model)
        assert summary["chain_count"] == 3
        assert summary["advisory_only"] is True
