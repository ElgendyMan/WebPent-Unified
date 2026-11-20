"""UM-DR-38 §7.2.A + Phase 5 — campaign instrumentation regression tests.

§7.2.A: the instrumentation installed by the three-campaign script must
be REVERSIBLE and must never accumulate across sequential campaigns in
one process. Before UM-DR-38 the script patched production functions
(build_graph, adjudicate_with_causal_guard, verify_replay_evidence) and
never restored them: campaign 2 wrapped campaign 1's wrappers, counts
inflated, and tracing leaked between runs. These tests pin the fixed
contract:

* inside the context manager exactly ONE observation layer is active —
  the installed wrapper's captured original IS the true module original
  (no previous layer underneath);
* on exit EVERY original function is restored by identity;
* a second campaign installs its layer over the ORIGINALS again.

Phase 5 (§9): the lab version is ONE authoritative constant used by the
HTTP response — pinned by serving a real lab instance.
"""
from __future__ import annotations

import importlib.util
import json
import threading
import urllib.request
from http.server import HTTPServer
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
SCRIPTS = REPO / "scripts"


def _load_campaigns_module():
    spec = importlib.util.spec_from_file_location(
        "umdr38_campaigns", str(SCRIPTS / "umdr37_production_campaigns.py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _production_modules():
    import webpent.agents.access_control.agent as ac_agent
    import webpent.graph.builder as gb
    import webpent.production.confirmation_adapter as ca
    import webpent.shared.verifier as verifier_mod

    return gb, ca, verifier_mod, ac_agent


def test_instrumentation_is_reversible_and_never_accumulates() -> None:
    campaigns = _load_campaigns_module()
    gb, ca, verifier_mod, ac_agent = _production_modules()

    original_build = gb.build_graph
    original_adjudicate = ca.adjudicate_with_causal_guard
    original_verify = verifier_mod.verify_replay_evidence
    original_ac_verify = ac_agent.verify_replay_evidence

    sink = {"stages": [], "guard_calls": [], "verifications": [],
            "raw_state": {}, "graphs": [],
            "authoritative_final_state": None,
            "authoritative_final_state_error": None}

    with campaigns.campaign_instrumentation(sink):
        assert gb.build_graph is not original_build
        # exactly ONE layer: the installed wrapper captured the TRUE
        # original as its underlying function — no previous campaign's
        # wrapper underneath
        closure = gb.build_graph.__closure__ or ()
        assert any(cell.cell_contents is original_build
                   for cell in closure), (
            "the instrumentation layer must wrap the ORIGINAL function "
            "(a wrapped wrapper means accumulation)")
        assert ca.adjudicate_with_causal_guard is not original_adjudicate
        assert verifier_mod.verify_replay_evidence is not original_verify
        assert ac_agent.verify_replay_evidence is not original_ac_verify

    # STRICT restoration by identity
    assert gb.build_graph is original_build
    assert ca.adjudicate_with_causal_guard is original_adjudicate
    assert verifier_mod.verify_replay_evidence is original_verify
    assert ac_agent.verify_replay_evidence is original_ac_verify

    # a SECOND campaign (sequential run in the same process) installs
    # its layer over the ORIGINALS again — never over the first layer
    sink2 = {"stages": [], "guard_calls": [], "verifications": [],
             "raw_state": {}, "graphs": [],
             "authoritative_final_state": None,
             "authoritative_final_state_error": None}
    with campaigns.campaign_instrumentation(sink2):
        closure = gb.build_graph.__closure__ or ()
        assert any(cell.cell_contents is original_build
                   for cell in closure), (
            "sequential campaigns must not stack wrappers")
    assert gb.build_graph is original_build
    assert ca.adjudicate_with_causal_guard is original_adjudicate
    assert verifier_mod.verify_replay_evidence is original_verify
    assert ac_agent.verify_replay_evidence is original_ac_verify


def test_lab_version_constant_is_served_by_the_lab() -> None:
    """Phase 5: the single authoritative lab version constant must be
    exactly what the lab's HTTP responses and records carry — served
    from a REAL lab instance, not asserted from source text."""
    campaigns = _load_campaigns_module()
    assert campaigns.LAB_VERSION == "1.6.0"

    out_of_scope = campaigns._OutOfScopeOrigin()
    server = HTTPServer(("127.0.0.1", 0), campaigns._IdorLab)
    server.out_of_scope_origin = out_of_scope.origin
    campaigns._IdorLab.request_log = []
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        origin = f"http://127.0.0.1:{server.server_address[1]}"
        with urllib.request.urlopen(f"{origin}/", timeout=10) as response:
            body = json.loads(response.read().decode("utf-8"))
        assert body["version"] == campaigns.LAB_VERSION
    finally:
        out_of_scope.shutdown()
        server.shutdown()
