# tests/test_chain_v3.py
"""Proposal 7 (2026-10-25) test suite: chain v3 replay + impact escalation.

Covers the default-off flag contract, deterministic chain construction
from a confirmed findings inventory, the empty-inventory no-op, the
impact ranking, and that every emitted PoC is syntactically valid bash.
"""
from __future__ import annotations

import subprocess
from typing import Any

import pytest

from webpent.chained_exploits.graph_v3 import (
    MAX_CHAIN_DEPTH,
    build_and_emit_chains,
    build_chain_edges,
    build_chains_from_findings,
    impact_of,
    prioritize_chains,
    render_curl_poc,
)
from webpent.config.settings import Settings, activate_settings


def _f(fid: str, vc: str, sev: str = "high", status: str = "confirmed") -> dict[str, Any]:
    return {
        "finding_id": fid,
        "vuln_class": vc,
        "severity": sev,
        "status": status,
        "method": "GET",
        "url": f"https://target/{fid}",
    }


FINDINGS = [
    _f("F1", "ssrf", "high"),
    _f("F2", "idor", "high"),
    _f("F3", "xss", "medium"),
    _f("F4", "xss", "low", status="unconfirmed"),  # never enters the graph
]


class TestDefaultOffFlag:
    def test_enable_chain_v3_defaults_false(self) -> None:
        assert Settings().enable_chain_v3 is False

    def test_emit_returns_empty_when_flag_off(self) -> None:
        out = build_and_emit_chains(FINDINGS)
        assert out == {"chains": [], "pocs": {}}

    def test_emit_returns_empty_when_settings_unavailable(self) -> None:
        # build_and_emit_chains resolves the flag through get_settings();
        # with no activation and default singleton settings it is off.
        out = build_and_emit_chains(FINDINGS)
        assert out["chains"] == []


class TestChainConstruction:
    def test_three_confirmed_findings_build_chains(self) -> None:
        chains = build_chains_from_findings(FINDINGS)
        assert chains, "expected chains from 3 confirmed findings"
        for c in chains:
            assert len(c["steps"]) >= 2
            assert len(set(c["steps"])) == len(c["steps"]), "simple paths only"
            assert len(c["steps"]) <= MAX_CHAIN_DEPTH

    def test_edges_only_between_confirmed_findings(self) -> None:
        edges = build_chain_edges(FINDINGS)
        ids = {e["from"] for e in edges} | {e["to"] for e in edges}
        assert "F4" not in ids, "unconfirmed finding must never join a chain"

    def test_empty_inventory_yields_nothing(self) -> None:
        assert build_chains_from_findings([]) == []
        assert build_chain_edges([]) == []
        assert build_and_emit_chains([]) == {"chains": [], "pocs": {}}
        single = build_chains_from_findings([FINDINGS[0]])
        assert single == []

    def test_deterministic_ordering(self) -> None:
        a = build_chains_from_findings(FINDINGS)
        b = build_chains_from_findings(FINDINGS)
        assert a == b
        deltas = [c["impact_delta"] for c in a]
        assert deltas == sorted(deltas, reverse=True)

    def test_top_k_bounds_output(self) -> None:
        chains = build_chains_from_findings(FINDINGS)
        assert len(prioritize_chains(chains, top_k=2)) == 2
        assert prioritize_chains(chains, top_k=0) == []


class TestImpactRanking:
    def test_rce_outranks_everything(self) -> None:
        assert impact_of("rce") > impact_of("ssrf") > impact_of("sql_injection")
        assert impact_of("rce") > impact_of("xss") > impact_of("open_redirect")

    def test_unknown_class_gets_default_rank(self) -> None:
        assert impact_of("totally_unknown_class") == 25

    def test_severity_bonus_is_monotonic(self) -> None:
        assert impact_of("xss", "critical") > impact_of("xss", "high")
        assert impact_of("xss", "high") > impact_of("xss", "low")


class TestPocRendering:
    def test_poc_is_syntactically_valid_bash(self) -> None:
        with activate_settings(Settings(enable_chain_v3=True)):
            out = build_and_emit_chains(FINDINGS, top_k=3)
        assert out["pocs"], "flag-on emit must include PoCs"
        for chain_id, poc in out["pocs"].items():
            proc = subprocess.run(
                ["bash", "-n"], input=poc, capture_output=True, text=True
            )
            assert proc.returncode == 0, (
                f"PoC for {chain_id} is not valid bash: {proc.stderr}"
            )

    def test_poc_deterministic(self) -> None:
        chains = build_chains_from_findings(FINDINGS)
        p1 = render_curl_poc(chains[0], FINDINGS)
        p2 = render_curl_poc(chains[0], FINDINGS)
        assert p1 == p2

    def test_poc_references_every_chain_step(self) -> None:
        chains = build_chains_from_findings(FINDINGS)
        poc = render_curl_poc(chains[0], FINDINGS)
        for i in range(1, len(chains[0]["steps"]) + 1):
            assert f"resp_{i}=" in poc


class TestEdgeRejectionV3Fixes:
    """The v3.1 fixes: consumer-side matching, deterministic ids, PoC
    artifact consumption."""

    def test_non_intersecting_producer_consumer_rejected(self) -> None:
        # open_redirect produces only AUTHORIZATION_CODE; ssrf consumes
        # INTERNAL_URL/LEAKED_TOKEN/LEAKED_SECRET — no intersection in
        # either direction, so the pair must yield NO edge (v3.0's
        # producer-only matching would have connected them).
        pair = [
            _f("A", "open_redirect", "high"),
            _f("B", "ssrf", "high"),
        ]
        assert build_chain_edges(pair) == []

    def test_intersecting_producer_consumer_kept(self) -> None:
        # xss produces LEAKED_TOKEN; ssrf consumes LEAKED_TOKEN.
        edges = build_chain_edges([_f("X", "xss"), _f("S", "ssrf")])
        assert len(edges) == 1
        assert edges[0]["from"] == "X"
        assert edges[0]["to"] == "S"
        assert edges[0]["artifact_types"] == ["leaked_token"]

    def test_unknown_consumer_family_fails_closed(self) -> None:
        # Unknown vuln families consume nothing: no edges INTO them.
        edges = build_chain_edges([_f("X", "xss"), _f("U", "brand_new_class")])
        assert edges == []

    def test_finding_id_fallback_is_deterministic(self) -> None:
        from webpent.chained_exploits.graph_v3 import _fid

        # Two SEPARATE dict objects with identical content must get the
        # same fallback id (id() was a memory address — run-variant).
        a = {"vuln_class": "idor", "url": "https://t/x", "method": "GET"}
        b = dict(a)
        assert _fid(a) == _fid(b)

    def test_poc_later_steps_consume_artifacts(self) -> None:
        # The v3.0 PoC exported ART_* but never used them (decorative).
        # Every step after the first must reference the predecessor's
        # shared artifact variables.
        chains = build_chains_from_findings(FINDINGS)
        assert chains, "fixture must still produce at least one chain"
        for chain in chains:
            if len(chain["steps"]) < 2:
                continue
            poc = render_curl_poc(chain, FINDINGS)
            assert "${ART_" in poc, (
                f"chain {chain['chain_id']}: no artifact consumption in PoC"
            )


class TestFlagGatedEmit:
    def test_flag_on_emits_chains_and_pocs(self) -> None:
        with activate_settings(Settings(enable_chain_v3=True)):
            out = build_and_emit_chains(FINDINGS, top_k=3)
        assert out["chains"]
        assert set(out["pocs"]) == {c["chain_id"] for c in out["chains"]}
        # chains carry escalation impact metadata
        for c in out["chains"]:
            assert {"impact_first", "impact_last", "impact_delta"} <= set(c)
