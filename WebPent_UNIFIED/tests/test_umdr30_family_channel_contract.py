"""UM-DR-30 Workstream A §3.3 — family execution spine channel contract.

Regression class: the family_execution node has produced nine ``family_*``
output keys since the spine landed, but none was declared as a PentestState
channel, so LangGraph channel filtering silently dropped every one of them
(the exact R2-graph-03 miss class, now closed for the whole family at once).
Only ``findings`` (declared) survived to the campaign report. This suite
pins the closed contract at three levels:

1. SOURCE CONTRACT — every ``family_*`` key the node can emit is a declared
   PentestState channel (the scan is mechanical: a future analyzer key that
   forgets its declaration fails this gate, not a live campaign).
2. LANGGRAPH RUNTIME — the REAL wiring function inside a compiled
   StateGraph over the real PentestState: the keys survive channel
   filtering into the final state, both on the ``no_input_surface`` early
   return and on the full execution return (executor disabled — plans
   pending, never faked).
3. SEMANTICS — last-write-wins (no reducer): the spine is wired exactly
   once per campaign pass (EXECUTION_SANDBOX → FAMILY_EXECUTION →
   VALIDATOR), matching the dedup_report precedent; the channels are
   optional (total=False) so legacy checkpoints load unchanged.

Honesty boundary: these channels are advisory/auditable data only. None of
them grants confirmation authority — cqa_v2/causal_guard.py stays the sole
confirmation authority; ``family_findings_merged`` counts findings the
guard already confirmed.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
NODE_SRC = ROOT / "src" / "webpent" / "families" / "execution_node.py"

#: The nine spine output keys documented in the UM-DR-30 channel contract.
NINE_CHANNELS = (
    "family_execution_status",
    "family_observed_capabilities",
    "family_candidates",
    "family_execution_plans",
    "family_executed_plans",
    "family_validation_results",
    "family_proof_bundles",
    "family_findings_merged",
    "family_feeds_derived",
)

#: Eleven more advisory keys emitted by the SAME return statement — the
#: chained-exploit projections, adversarial-review downgrades, creative
#: horizon hypotheses, expanded surface, adaptive-defense state, and the
#: self-verify quality summary (same miss class, declared together).
EXTENDED_CHANNELS = (
    "attack_graph_chains_total",
    "attack_graph_chains_confirmed",
    "attack_graph_findings_promoted",
    "goed_feedback_hypotheses",
    "adversarial_review_downgraded",
    "creative_hybrid_hypotheses",
    "expanded_attack_surface",
    "adaptive_defense",
    "self_verify_quality",
    "self_verify_needs_review",
    "self_verify_learned_rules",
)

ALL_SPINE_CHANNELS = NINE_CHANNELS + EXTENDED_CHANNELS


def _declared_channels() -> dict[str, object]:
    from webpent.state.state import PentestState

    return dict(PentestState.__annotations__)


def _emitted_family_keys() -> set[str]:
    """Mechanically scan the node source for emitted ``family_*`` keys."""
    source = NODE_SRC.read_text(encoding="utf-8")
    return set(re.findall(r"[\"'](family_[a-z0-9_]+)[\"']\s*:", source))


# ---------------------------------------------------------------------------
# 1. the source-level contract
# ---------------------------------------------------------------------------


class TestSpineSourceContract:
    def test_every_emitted_family_key_is_a_declared_channel(self) -> None:
        declared = _declared_channels()
        emitted = _emitted_family_keys()
        assert emitted, "source scan found no family_* keys — scan is broken"
        missing = sorted(emitted - set(declared))
        assert not missing, (
            "family_execution_node emits keys that are NOT declared "
            f"PentestState channels (LangGraph drops them silently): {missing}"
        )

    def test_the_nine_documented_channels_are_declared(self) -> None:
        declared = _declared_channels()
        missing = [name for name in ALL_SPINE_CHANNELS if name not in declared]
        assert not missing, f"documented channels missing from PentestState: {missing}"

    def test_channels_are_last_write_wins_no_reducer(self) -> None:
        """The spine writes once per campaign pass → plain (non-Annotated)
        declarations, exactly like the dedup_report precedent. A reducer
        here would be a semantic change that must be re-justified."""
        declared = _declared_channels()
        for name in ALL_SPINE_CHANNELS:
            annotation = declared[name]
            assert not hasattr(annotation, "__metadata__"), (
                f"{name} gained reducer metadata {annotation!r} — "
                "last-write-wins is the documented contract"
            )

    def test_stateful_discovery_summary_stays_declared(self) -> None:
        """UM-DR-28's adjacent channel must not regress in this window."""
        assert "stateful_discovery" in _declared_channels()


# ---------------------------------------------------------------------------
# 2. the LangGraph runtime level (the real wiring function)
# ---------------------------------------------------------------------------


class TestLangGraphRuntimeSurvival:
    def _run_spine(self, campaign_state: dict) -> dict:
        from langgraph.graph import END, START, StateGraph

        from webpent.families.execution_node import wire_family_execution
        from webpent.state.state import PentestState

        graph = StateGraph(PentestState)
        graph.add_node("execution_sandbox", lambda s: {})
        graph.add_node("validator", lambda s: {})
        graph.add_edge(START, "execution_sandbox")
        graph.add_edge("validator", END)
        wire_family_execution(graph)  # the REAL production wiring
        compiled = graph.compile()
        return compiled.invoke(campaign_state, config={"recursion_limit": 50})

    def test_no_input_surface_outputs_survive_channel_filtering(self) -> None:
        """Empty state → the early return. Before UM-DR-30 these five keys
        were dropped by channel filtering; the final state never saw them."""
        result = self._run_spine({})
        assert result.get("family_execution_status") == "no_input_surface"
        assert result.get("family_candidates") == []
        assert result.get("family_execution_plans") == []
        assert result.get("family_validation_results") == []
        assert result.get("family_findings_merged") == 0

    def test_full_return_all_nine_keys_survive(self, monkeypatch) -> None:
        """A minimal surface drives the FULL return path through the REAL
        production data route: LangGraph drops undeclared input keys
        (``endpoint_inventory`` is the documented direct-invocation-only
        injection seam), so the inventory must arrive via the declared
        ``crawled_data`` channel exactly like a live campaign — the
        family_feeds adapter then derives the analyzer inventory from
        ``openapi_routes``. The executor is disabled (no httpx client) —
        the node's documented behavior is to emit plans pending
        execution, never to fake replays."""
        from webpent.families import execution_node as spine

        monkeypatch.setattr(spine, "get_default_http_executor", lambda: None)
        result = self._run_spine(
            {
                "crawled_data": {
                    "openapi_routes": [
                        {
                            "method": "POST",
                            "path": "/api/orders",
                            "params": ["quantity"],
                        },
                        {
                            "method": "POST",
                            "path": "/api/admin/transfer",
                            "params": ["amount"],
                        },
                    ]
                },
                "engagement_id": "umdr30-channel-contract",
            }
        )
        # all twenty keys survived LangGraph channel filtering
        for name in ALL_SPINE_CHANNELS:
            assert name in result, f"{name} was dropped by channel filtering"
        # and the semantics are honest: no executor → nothing faked
        assert result["family_execution_status"] in {
            "ok",
            "plans_pending_execution",
            "executed_and_validated",
        }
        assert result["family_executed_plans"] == 0
        assert isinstance(result["family_candidates"], list)
        assert isinstance(result["family_observed_capabilities"], list)
        assert "mutating_endpoint" in result["family_observed_capabilities"]
        assert isinstance(result["family_findings_merged"], int)
        assert isinstance(result["family_feeds_derived"], bool)
        assert result["family_feeds_derived"] is True  # family_feeds derived it

    def test_legacy_checkpoint_shape_stays_valid(self) -> None:
        """total=False: a state dict that predates the nine channels loads
        and runs through the graph unchanged (no KeyError, no default
        mutation)."""
        result = self._run_spine({"target_id": "legacy-checkpoint-shape"})
        assert result.get("family_execution_status") == "no_input_surface"


# ---------------------------------------------------------------------------
# 3. honesty pins — the channels never become confirmation authority
# ---------------------------------------------------------------------------


class TestAdvisoryOnlyPins:
    def test_channels_carry_no_confirmation_vocabulary(self) -> None:
        """The spine channels are advisory: the node's confirmed findings
        ride the (already-declared) ``findings`` merge channel; the spine
        block must never carry its own confirmed-findings list."""
        source = NODE_SRC.read_text(encoding="utf-8")
        for name in ALL_SPINE_CHANNELS:
            assert f'"{name}_confirmed"' not in source
        assert '"family_confirmed_findings"' not in source

    @pytest.mark.parametrize("name", ALL_SPINE_CHANNELS)
    def test_channel_documented_in_state_contract(self, name: str) -> None:
        """The declaration block in state.py carries the UM-DR-30 window
        marker so the refreeze provenance is traceable from the schema."""
        state_src = (
            ROOT / "src" / "webpent" / "state" / "state.py"
        ).read_text(encoding="utf-8")
        assert "UM-DR-30" in state_src
        assert name in state_src
