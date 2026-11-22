"""UM-DR-44 A2 — contract tests for the Canonical Hypothesis Adapter.

Part 1 (behavior): the adapter enforces the required contract fields
and bounds the documented string limits exactly once.

Part 2 (structural): the three principal production emitters —
identity workflow, adaptive research, rabbit hole — construct their
hypotheses THROUGH the adapter (no direct ``Hypothesis(``
construction left in those modules).
"""

from __future__ import annotations

import inspect
from pathlib import Path

import pytest

from webpent.models.hypothesis import Hypothesis
from webpent.production.hypothesis_adapter import (
    CanonicalHypothesisAdapter,
    HypothesisContractError,
    canonical_hypothesis,
)

REPO_ROOT = Path(__file__).resolve().parents[1]

_FULL = dict(
    target_url="https://t.example.com/api/orders/1",
    statement="foreign principal can read a protected order",
    vuln_class="privilege_differential",
    status="unexplored",
    origin="invariant",
    origin_detail="umdr44_adapter_test fp=abc",
    expected_behavior="foreign request succeeds while control is denied",
    negative_control="control request on restricted object is denied",
    confidence_score=0.5,
    preconditions=["observed-owner-allowed-operation"],
)


class TestAdapterBehavior:
    def test_full_fields_build(self) -> None:
        hyp = canonical_hypothesis(**_FULL)
        assert isinstance(hyp, Hypothesis)
        assert hyp.vuln_class == "privilege_differential"
        assert hyp.preconditions == ["observed-owner-allowed-operation"]

    def test_missing_required_field_rejected(self) -> None:
        for field in ("statement", "vuln_class", "origin", "origin_detail",
                      "expected_behavior", "negative_control"):
            broken = {k: v for k, v in _FULL.items() if k != field}
            with pytest.raises(HypothesisContractError, match=field):
                canonical_hypothesis(**broken)

    def test_bounded_strings_truncated_once(self) -> None:
        long = "x" * 2000
        hyp = canonical_hypothesis(**{**_FULL, "statement": long,
                                      "origin_detail": long})
        assert len(hyp.statement) == 500
        assert len(hyp.origin_detail) == 500

    def test_blank_required_field_rejected(self) -> None:
        with pytest.raises(HypothesisContractError, match="statement"):
            canonical_hypothesis(**{**_FULL, "statement": "   "})

    def test_adapter_never_invents_content(self) -> None:
        hyp = canonical_hypothesis(**_FULL)
        # nothing the producer did not declare appears
        assert hyp.evidence_refs in (None, [], ())


class TestEmittersAreCanonical:
    """Structural: the three named emitters route through the adapter."""

    @pytest.mark.parametrize("module_path", [
        "src/webpent/production/identity_workflow.py",
        "src/webpent/production/adaptive_research.py",
        "src/webpent/agents/rabbit_hole/agent.py",
    ])
    def test_module_imports_adapter(self, module_path: str) -> None:
        source = (REPO_ROOT / module_path).read_text(encoding="utf-8")
        assert "hypothesis_adapter" in source, (
            f"{module_path} does not import the canonical adapter"
        )

    @pytest.mark.parametrize("module_path", [
        "src/webpent/production/identity_workflow.py",
        "src/webpent/production/adaptive_research.py",
        "src/webpent/agents/rabbit_hole/agent.py",
    ])
    def test_module_has_no_direct_construction(self, module_path: str) -> None:
        """RED on the current tree: all three construct Hypothesis(
        directly."""
        source = (REPO_ROOT / module_path).read_text(encoding="utf-8")
        # strip the import lines themselves
        lines = [
            ln for ln in source.splitlines()
            if not ln.strip().startswith(("import ", "from ", "#"))
        ]
        body = "\n".join(lines)
        assert "Hypothesis(" not in body, (
            f"{module_path} still constructs Hypothesis( directly — "
            "emission must go through canonical_hypothesis()"
        )
