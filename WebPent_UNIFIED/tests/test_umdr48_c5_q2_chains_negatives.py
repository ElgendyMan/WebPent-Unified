"""UM-DR-48 — C5 chains + Q2 negatives: the machine-proof tests.

C5 (chain ignition): each declared chain confirms EVERY step with its
recorded signal AND end-to-end (the composition is real, not two
unrelated defects); the NEGATIVE control (the secure variant of the
same chain fixture) confirms nothing.

Q2 (negative suite): >= 12 near-miss fixtures — zero confirmations
under the same lane pressure that lights up the vulnerable labs.
"""
from __future__ import annotations

import os
import threading
from http.server import HTTPServer

os.environ.setdefault("WEBPENT_ENTRYPOINT", "cli")

import pytest  # noqa: E402

import sys  # noqa: E402
from pathlib import Path  # noqa: E402

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "scripts"))

from umdr48_chain_labs import (  # noqa: E402
    CHAIN_GROUND_TRUTH,
    run_chain_campaign,
)
from umdr48_negative_labs import (  # noqa: E402
    NEGATIVE_FIXTURES,
    run_negative_campaign,
)


class TestC5Chains:
    @pytest.mark.parametrize("chain_id", list(CHAIN_GROUND_TRUTH))
    def test_chain_confirms_every_step_end_to_end(self, chain_id):
        record = run_chain_campaign(chain_id, run_index=1)
        spec = CHAIN_GROUND_TRUTH[chain_id]
        assert record["chain_steps_confirmed"] == len(spec["steps"]), (
            record["notes"])
        assert record["chain_end_to_end"] is True
        # every step's evidence carries its recorded signal
        assert len(record["step_evidence"]) == len(spec["steps"])
        for ev, declared in zip(record["step_evidence"], spec["steps"]):
            assert ev["step"] == declared["n"]
            assert ev["anchor"] == declared["anchor"]
            assert ev["signal"]
        # scope discipline held
        assert record["invariants"][
            "out_of_scope_origin_zero_requests"] is True

    @pytest.mark.parametrize("chain_id", list(CHAIN_GROUND_TRUTH))
    def test_chain_secure_variant_confirms_nothing(self, chain_id):
        """The honesty control: the same fixture with BOTH gates
        enforced must yield zero confirmed steps."""
        record = run_chain_campaign(chain_id, run_index=1, secure=True)
        assert record["chain_steps_confirmed"] == 0, (
            record["step_evidence"])
        assert record["chain_end_to_end"] is False

    def test_two_chains_declared(self):
        assert len(CHAIN_GROUND_TRUTH) >= 2


class TestQ2Negatives:
    @pytest.mark.parametrize("fixture_id", list(NEGATIVE_FIXTURES))
    def test_near_miss_confirms_nothing(self, fixture_id):
        record = run_negative_campaign(fixture_id)
        assert record["findings_confirmed"] == 0, (
            record["confirmed_detail"])
        assert record["invariants"][
            "out_of_scope_origin_zero_requests"] is True

    def test_at_least_twelve_fixtures(self):
        assert len(NEGATIVE_FIXTURES) >= 12

    def test_every_family_covered(self):
        families = {spec["family"] for spec in NEGATIVE_FIXTURES.values()}
        assert families == {
            "workflow_abuse", "request_smuggling", "graphql_oracle",
            "tenant_confusion", "redirect_scope_bypass"}
