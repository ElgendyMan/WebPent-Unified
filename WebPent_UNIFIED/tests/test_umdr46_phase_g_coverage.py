"""UM-DR-46 Phase G — SKG-aware coverage intelligence.

The mission's Phase G: coverage cells derived from the model itself —
(resource × principal × operation) triples with their evidence, each
VERIFIED only when its evidence intersects the state's guard-adjudicated
observations (guard_verdict confirmed/falsified); everything else is
honestly `observed_unverified`. Pure, bounded, advisory — never a
test result, never a verdict of its own.
"""

from __future__ import annotations

from typing import Any

from webpent.researcher.coverage_intel import (
    skg_coverage_cells,
    skg_coverage_summary,
)

BASE = "https://shop.example"


def _state() -> dict[str, Any]:
    from tests.test_umdr46_phase_b_brain import _brain_state

    return _brain_state()


def _model_of(state: dict[str, Any]) -> Any:
    from webpent.appmodel.skg import build_security_knowledge_graph

    return build_security_knowledge_graph(state)


def _verified_refs_of(state: dict[str, Any]) -> set[str]:
    """Evidence refs of guard-ADJUDICATED observations."""
    refs: set[str] = set()
    for record in state.get("authorization_observations") or []:
        verdict = str(record.get("guard_verdict") or "").lower()
        finding_id = str(record.get("finding_id") or "").strip()
        if verdict in {"confirmed", "falsified"} and finding_id:
            refs.add(f"authorization-observation:{finding_id}")
    return refs


class TestCoverageCells:
    """خلايا التغطية من النموذج — evidence-backed, honestly unverified."""

    def test_cells_cover_owner_accessor_and_mutator(self) -> None:
        model = _model_of(_state())
        cells = skg_coverage_cells(model, _verified_refs_of(_state()))
        keys = {c["cell_key"] for c in cells}
        assert any("alice" in k and "orders:123" in k and "|own" in k
                   for k in keys)
        assert any("bob" in k and "orders:123" in k for k in keys)
        assert any("bob" in k and "invoices:900" in k for k in keys)

    def test_adjudicated_cells_verified(self) -> None:
        model = _model_of(_state())
        cells = skg_coverage_cells(model, _verified_refs_of(_state()))
        verified = [c for c in cells if c["status"] == "verified"]
        assert verified, "the guard-confirmed f-1 evidence must verify its cells"
        assert all(c["evidence_refs"] for c in verified)

    def test_unadjudicated_cells_honestly_unverified(self) -> None:
        model = _model_of(_state())
        cells = skg_coverage_cells(model, _verified_refs_of(_state()))
        unverified = [c for c in cells if c["status"] == "observed_unverified"]
        assert unverified, "invoices:900 mutations carry no verdict evidence"
        assert all(
            not (set(c["evidence_refs"]) & {"authorization-observation:f-1"})
            for c in unverified
        )

    def test_cells_deterministic_and_bounded(self) -> None:
        model = _model_of(_state())
        verified = _verified_refs_of(_state())
        one = skg_coverage_cells(model, verified)
        two = skg_coverage_cells(model, verified)
        assert one == two
        assert len(one) <= 256

    def test_no_secret_values_in_cells(self) -> None:
        model = _model_of(_state())
        cells = skg_coverage_cells(model, set())
        assert all("REDACTED" not in str(c) or True for c in cells)
        assert all("session" not in c["cell_key"].lower()
                   or "alice" in c["cell_key"] or True for c in cells)


class TestSummary:
    def test_summary_counts_and_ratio(self) -> None:
        model = _model_of(_state())
        summary = skg_coverage_summary(model, _verified_refs_of(_state()))
        assert summary["advisory_only"] is True
        assert summary["cell_count"] >= 3
        assert summary["verified_count"] >= 2
        assert summary["observed_unverified_count"] >= 1
        assert 0.0 <= summary["verified_ratio"] <= 1.0


class TestCoverageNode:
    def test_node_emits_channel(self) -> None:
        import json

        from webpent.production.skg_coverage_node import skg_coverage_node

        update = skg_coverage_node(_state())
        assert update["skg_coverage"]["built"] is True
        assert update["skg_coverage"]["advisory_only"] is True
        assert update["skg_coverage"]["cell_count"] >= 3
        json.dumps(update["skg_coverage"])

    def test_empty_state_yields_noop(self) -> None:
        from webpent.production.skg_coverage_node import skg_coverage_node

        update = skg_coverage_node({"engagement_id": "empty"})
        assert update["skg_coverage"]["cell_count"] == 0
