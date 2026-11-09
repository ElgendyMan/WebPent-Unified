# tests/team1_acceptance/test_m2_transport_contract.py
"""M2-impl CONTRACT TESTS (Dispatch #009) — WP-A/WP-B/WP-C/WP-D/WP-F.

Covers the substrate/audit fix, the declared-key transport, rehydration,
type discipline, and the spine-flag consumers. The graph-level EXIT GATE
lives in test_m2_graph_chain_gate.py.
"""
from __future__ import annotations

import json
import logging
import os

import pytest


# ---------------------------------------------------------------------------
# WP-A — audit seam (NF-R2-04): the REAL chain fires through the seam
# ---------------------------------------------------------------------------

def _admitted_fixture(fixture_id: str = "fx_ct", *, engagement_id: str = "e_ct",
                      engagement_instance_id: str = "inst_ct",
                      target_fingerprint: str = "tgtfp_ct") -> dict:
    """Admitted-fixture template. The fixture's binding fields MUST match the
    active state binding (the adapter rejects mismatched bindings by design)."""
    return {
        "fixture_id": fixture_id,
        "content_digest": "sha256:" + "a" * 64,
        "source_type": "static_json",
        "engagement_id": engagement_id,
        "engagement_instance_id": engagement_instance_id,
        "target_fingerprint": target_fingerprint,
        "secret_scan_result": {"categories": []},
        "route_shape": {
            "endpoint_template": "/api/invoices/{id}",
            "method": "GET",
            "parameter_names": ["id"],
            "response_shape": "redacted",
            "authorization_hints": "pb",
            "candidate_rationale": "adv",
            "defect_family_hint": "IDOR",
        },
        "object_reference_plan": {
            "owner_object_ref": "INV-B-204",
            "candidate_object_ref": "INV-B-204",
            "negative_control_object_ref": "INV-X-000",
        },
        "baseline_candidate_control_plan": {},
    }


def _flag_env(monkeypatch) -> None:
    """Operator authorization posture for fixture-scheduling tests (WP-F)."""
    monkeypatch.setenv("WEBPENT_EXPLORATION_INGRESS_ENABLED", "true")
    monkeypatch.setenv("WEBPENT_STATIC_FIXTURE_SOURCE_ENABLED", "true")
    monkeypatch.setenv("WEBPENT_MULTI_PRINCIPAL_EXECUTION_ENABLED", "true")


def test_audit_chain_events_fire_through_seam(monkeypatch, tmp_path):
    """NF-R2-04 fix: the seam produces a REAL EngagementAuditChain and the
    D8 fail-closed audit events land in the hash-chained file."""
    _flag_env(monkeypatch)
    from webpent.production.modern_spine_integration import modern_spine_recon_node

    state = {
        "engagement_id": "e_audit_ct", "target_url": "http://127.0.0.1:9101",
        "engagement_instance_id": "inst_audit_ct",
        "target_fingerprint": "tgtfp_audit_ct",
        "admitted_fixtures": [_admitted_fixture("fx_audit", engagement_id="e_audit_ct",
                            engagement_instance_id="inst_audit_ct",
                            target_fingerprint="tgtfp_audit_ct")],
        "campaign_budget_remaining": 20,
    }
    out = modern_spine_recon_node(state)
    descriptor = out.get("_audit_chain")
    assert isinstance(descriptor, dict) and descriptor.get("chain_live") is True
    audit_path = descriptor["audit_path"]
    assert os.path.exists(audit_path)
    events = [json.loads(line) for line in open(audit_path) if line.strip()]
    types = [e["event_type"] for e in events]
    assert "intake.queued" in types  # registration audited
    assert "intake.executed" in types  # publication audited
    # hash-chained append-only shape: seq increments, prev_hash links
    seqs = [e["seq"] for e in events]
    assert seqs == list(range(len(events)))
    assert all(e["prev_hash"] for e in events)


def test_audit_fail_closed_on_chain_failure(tmp_path):
    """D8: a chain-side failure propagates (no silent audit drop). A
    finalized chain refuses appends — the failure reaches the caller
    instead of being swallowed into a silent no-audit path."""
    from webpent.shared.engagement_audit import EngagementAuditChain
    from webpent.production import advisory_registration as ar

    chain = EngagementAuditChain(
        engagement_id="e_fc", audit_dir=tmp_path / "a",
        workspace_dir=tmp_path / "w", trace=None)
    # Force the chain-side failure state directly (test-scoped dirs — no
    # cross-run contamination).
    chain._finalized = True
    with pytest.raises(Exception):
        ar._audit(chain, "intake.queued", {"intake_id": "x"})


def test_spine_caller_guard_refuses_without_token(monkeypatch):
    """NF-R2-06: object-identity token required; filename-substring spoofing
    is dead. Without the token and outside the contained escape, REFUSED."""
    monkeypatch.delenv("WEBPENT_ALLOW_DIRECT_ADVISORY_REGISTRATION_TEST_ONLY",
                       raising=False)
    from webpent.production.advisory_registration import (
        register_advisory_candidates_inline,
    )
    with pytest.raises(RuntimeError, match="object-identity token"):
        register_advisory_candidates_inline({}, [])


def test_spine_caller_guard_escape_contained_to_pytest(monkeypatch):
    """NF-R2-06 containment: the escape env is honored only inside a pytest
    process — simulating a non-pytest process refuses even with env set."""
    import sys
    monkeypatch.setenv("WEBPENT_ALLOW_DIRECT_ADVISORY_REGISTRATION_TEST_ONLY", "1")
    monkeypatch.delenv("PYTEST_CURRENT_TEST", raising=False)
    from webpent.production import advisory_registration as ar
    had_pytest = "pytest" in sys.modules
    saved = sys.modules.pop("pytest", None)
    try:
        with pytest.raises(RuntimeError):
            ar._assert_spine_caller(None)
    finally:
        if had_pytest and saved is not None:
            sys.modules["pytest"] = saved


def test_durable_dedupe_blocks_reacross_invocations(monkeypatch, tmp_path):
    """NF-R2-07: the same dedupe key is rejected across seam invocations
    (durable per-engagement registry), with duplicate telemetry."""
    _flag_env(monkeypatch)
    monkeypatch.setenv("WEBPENT_AUDIT_ROOT", str(tmp_path / "dur"))
    from webpent.production.modern_spine_integration import modern_spine_recon_node

    def state():
        return {"engagement_id": "e_dur_ct", "target_url": "http://127.0.0.1:9102",
                "engagement_instance_id": "inst_dur_ct",
                "target_fingerprint": "tgtfp_dur_ct",
                "admitted_fixtures": [_admitted_fixture("fx_dur_ct", engagement_id="e_dur_ct",
                            engagement_instance_id="inst_dur_ct",
                            target_fingerprint="tgtfp_dur_ct")],
                "campaign_budget_remaining": 20}
    out1 = modern_spine_recon_node(state())
    assert out1.get("advisory_registered_count") == 1
    out2 = modern_spine_recon_node(state())
    assert out2.get("advisory_registered_count") == 0
    assert out2.get("advisory_telemetry", {}).get("advisory.intake.duplicate") == 1


def test_bounds_recheck_rejects_oversized_fixture(monkeypatch):
    """NF-M2-06 disposition: the seam re-checks bounds — an oversized
    fixture is REJECTED with the frozen layer's oversize reason, not
    admitted unbounded (RED-2 P-4: 5 MiB field admitted verbatim)."""
    from webpent.production.modern_spine_integration import _recheck_fixture_bounds
    from webpent.production.fixture_intake import RejectionRegister
    from webpent.shared.fixture_registry import (
        REASON_OVERSIZE,
        REASON_STRUCTURE,
    )

    # structure-cap path: the free-text candidate_rationale cap rejects a
    # 5 MiB field exactly like RED-2 P-4's admitted-verbatim payload
    fixture = _admitted_fixture("fx_big")
    fixture["route_shape"]["candidate_rationale"] = "x" * (5 * 1024 * 1024)
    reg = RejectionRegister()
    assert _recheck_fixture_bounds(fixture, reg) is False
    assert any(r["reason"] == REASON_STRUCTURE for r in reg.rejections)
    # oversize path: a fixture whose serialized payload exceeds the frozen
    # MAX_SOURCE_BYTES constant is rejected with the frozen oversize reason
    from webpent.shared.fixture_registry import MAX_SOURCE_BYTES
    fixture2 = _admitted_fixture("fx_huge")
    fixture2["raw"] = {"blob": "y" * (MAX_SOURCE_BYTES + 1)}
    reg2 = RejectionRegister()
    assert _recheck_fixture_bounds(fixture2, reg2) is False
    assert any(r["reason"] == REASON_OVERSIZE for r in reg2.rejections)


def test_noncanonical_record_rejected_not_crashed(monkeypatch):
    """WP-D/R4: a hostile record with dict identity fields is REJECTED
    (counted) — the previous code crashed with TypeError: unhashable."""
    monkeypatch.setenv("WEBPENT_ALLOW_DIRECT_ADVISORY_REGISTRATION_TEST_ONLY", "1")
    from webpent.production.advisory_registration import (
        register_advisory_candidates_inline,
    )
    state = {}
    records = [{"intake_id": "ok1", "dedupe_key": "sha256:ok"},
               {"intake_id": {"hostile": 1}, "dedupe_key": "sha256:x"},
               {"intake_id": "ok2", "dedupe_key": ["not", "a", "str"]}]
    registered, counters = register_advisory_candidates_inline(state, records)
    assert len(registered) == 1
    assert counters["advisory.intake.noncanonical_record"] == 2


# ---------------------------------------------------------------------------
# WP-B — declared-key transport + R2 prohibition
# ---------------------------------------------------------------------------

def test_target_derivation_ladder_from_declared_state():
    from webpent.production.modern_spine_integration import _derive_target_url
    from webpent.models.targets import Target

    assert _derive_target_url({"target_url": "http://a"}) == "http://a"
    assert _derive_target_url({"target": Target(url="http://b")}) == "http://b"
    assert _derive_target_url({"url": "http://c"}) == "http://c"
    assert _derive_target_url({}) == ""  # fail-closed empty -> factory raises


def test_resolve_spine_orchestrator_fails_closed_without_target():
    from webpent.production.modern_spine_integration import resolve_spine_orchestrator
    from webpent.production.production_spine import ProductionSpineError
    with pytest.raises(ProductionSpineError):
        resolve_spine_orchestrator({"engagement_id": "e_no_tgt"})


def test_state_schema_extension_additive_sqlite_roundtrip(tmp_path):
    """C10/P-2.2: the extended schema round-trips through a REAL SqliteSaver
    checkpoint — every new declared key carries serializable values, and the
    descriptor/projection shapes survive a resume unchanged."""
    import pytest as _pytest
    from langgraph.checkpoint.sqlite import SqliteSaver
    from langgraph.graph import StateGraph, START, END
    from webpent.state.state import PentestState

    payload = {
        "engagement_id": "e_c10",
        "target_url": "http://127.0.0.1:9106",
        "modern_spine_active": True,
        "modern_spine_mode": "PRODUCTION_MODERN",
        "modern_spine_version": "modern_spine_v1",
        "_audit_chain": {"engagement_id": "e_c10", "audit_path": "/x/a.jsonl",
                         "workspace_path": "/x/w.json", "chain_live": True},
        "advisory_registered": [{"intake_id": "i1", "dedupe_key": "sha256:k",
                                 "terminal_state": "intake.queued"}],
        "advisory_telemetry": {"advisory.intake.duplicate": 1},
        "_modern_spine_trace": {"spine_version": "modern_spine_v1",
                                "stages_seen": ["deep_recon"]},
        "research_campaign_skipped": "no_hypotheses",
        "research_loop_rehydrated": 1,
        "legacy_authority_blocked": False,
    }
    db_path = tmp_path / "c10.sqlite"

    def _echo(state: dict) -> dict:
        return {"research_loop_rehydrated": state.get("research_loop_rehydrated", 0) + 1}

    with SqliteSaver.from_conn_string(str(db_path)) as saver:
        g = StateGraph(PentestState)
        g.add_node("echo", _echo)
        g.add_edge(START, "echo")
        g.add_edge("echo", END)
        app = g.compile(checkpointer=saver)
        cfg = {"configurable": {"thread_id": "c10-thread"}}
        final = app.invoke(payload, config=cfg)
        assert final["research_loop_rehydrated"] == 2  # payload + node bump
        resumed = app.get_state(cfg)
        values = resumed.values
        for key, expected in payload.items():
            assert key in values, f"declared key {key} lost at checkpoint"
            if key != "research_loop_rehydrated":
                assert values[key] == expected, key
        # additive-compat: a resume with an EMPTY update (old-shape caller)
        # must not crash the channel layer
        app.invoke({}, config=cfg)
        assert app.get_state(cfg).values["modern_spine_active"] is True


def test_prohibited_object_transport_absent_from_pentest_state():
    """R2: `_modern_orchestrator` must NEVER be declared in PentestState."""
    import ast
    from pathlib import Path
    src = Path("src/webpent/state/state.py").read_text()
    tree = ast.parse(src)
    declared = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.ClassDef) and node.name == "PentestState":
            for st in node.body:
                if isinstance(st, ast.AnnAssign) and isinstance(st.target, ast.Name):
                    declared.add(st.target.id)
    assert "_modern_orchestrator" not in declared
    assert "_tool_boundary" not in declared  # live-object conveniences stay out
    assert "_advisory_memory" not in declared
    # The corrected-census keys ARE declared (R1 baseline):
    for key in ("target_url", "entrypoint", "modern_spine_active",
                "_modern_spine_trace", "advisory_registered", "_audit_chain",
                "avi_version", "research_loop_rehydrated"):
        assert key in declared, key


# ---------------------------------------------------------------------------
# WP-C — rehydration
# ---------------------------------------------------------------------------

def test_rehydration_equivalence_registered_equals_recovered(monkeypatch, tmp_path):
    """R3: registered == recovered. Candidates registered at the seam are
    recovered from the durable CampaignState and re-registered into a fresh
    factory-derived loop; the loop's candidate set matches."""
    _flag_env(monkeypatch)
    monkeypatch.setenv("WEBPENT_AUDIT_ROOT", str(tmp_path / "eq"))
    from webpent.production.modern_spine_integration import (
        _load_or_create_campaign_state,
        modern_spine_recon_node,
        resolve_spine_orchestrator,
    )
    state = {"engagement_id": "e_eq", "target_url": "http://127.0.0.1:9103",
             "engagement_instance_id": "inst_eq", "target_fingerprint": "tgtfp_eq",
             "admitted_fixtures": [_admitted_fixture("fx_eq", engagement_id="e_eq",
                            engagement_instance_id="inst_eq",
                            target_fingerprint="tgtfp_eq")],
             "campaign_budget_remaining": 20}
    out = modern_spine_recon_node(state)
    assert out.get("advisory_registered_count") == 1

    cs, path = _load_or_create_campaign_state("inst_eq", "http://127.0.0.1:9103")
    registered = {r["candidate_id"]: (tuple(r["hypothesis_ids"]), r["experiment_signature"])
                  for r in cs.registered_candidates}
    assert len(registered) == 1

    orch2, _trace, _cfg, _ep = resolve_spine_orchestrator(state)  # fresh factory
    assert len(orch2.research_loop._candidates) == 0  # empty before rehydration
    for cid, (hids, sig) in registered.items():
        orch2.research_loop.register_candidate(candidate_id=cid, hypothesis_ids=hids,
                                               experiment_signature=sig)
    recovered = {cid: (c["hypothesis_ids"], c["signature"])
                 for cid, c in orch2.research_loop._candidates.items()}
    assert recovered == registered  # EQUIVALENCE


def test_campaign_state_version_bump_fails_safe_on_v1(tmp_path):
    """CampaignState v2 rejects v1 payloads loudly (no silent reinterpretation)."""
    from webpent.production.campaign_state import (
        CAMPAIGN_STATE_VERSION,
        CampaignStateError,
        load_campaign_state,
    )
    assert CAMPAIGN_STATE_VERSION == "campaign_state_v2"
    v1_file = tmp_path / "v1.json"
    v1_file.write_text(json.dumps({
        "engagement_id": "e", "target_url": "http://x",
        "state_version": "campaign_state_v1"}))
    with pytest.raises(CampaignStateError, match="Incompatible campaign state version"):
        load_campaign_state(str(v1_file))


# ---------------------------------------------------------------------------
# WP-D — canonical dispatch forms
# ---------------------------------------------------------------------------

def test_canonicalizer_accepts_canonical_and_rejects_hostile():
    from webpent.production.advisory_registration import (
        canonicalize_campaign_hypothesis,
    )
    good, why = canonicalize_campaign_hypothesis(
        {"id": "h1", "vulnerability_class": "idor", "path": "/x"})
    assert why is None and good["id"] == "h1"
    assert good["vulnerability_class"] == "IDOR" and good["method"] == "GET"

    for hostile in ("string", 42, None, [], {}):
        out, why = canonicalize_campaign_hypothesis(hostile)
        assert out is None and why
    out, why = canonicalize_campaign_hypothesis({"id": {"d": 1}})
    assert out is None
    out, why = canonicalize_campaign_hypothesis(
        {"id": "h2", "path": "/x", "injected_payload": "DROP TABLE"})
    assert out is not None and "injected_payload" not in out  # extras dropped


# ---------------------------------------------------------------------------
# WP-F — flag consumers
# ---------------------------------------------------------------------------

def _config_for(monkeypatch, tmp_path, **env):
    for k, v in env.items():
        monkeypatch.setenv(k, v)
    from webpent.production.production_spine import (
        ProductionSpineConfig,
        resolve_production_spine,
    )
    cfg = ProductionSpineConfig(engagement_id="e_flags", target_url="http://127.0.0.1:9104",
                                entrypoint="direct_invoke")
    orch, trace = resolve_production_spine(cfg)
    return cfg, orch, trace


def test_flags_default_deny_nothing_schedulable(monkeypatch, tmp_path):
    monkeypatch.delenv("WEBPENT_EXPLORATION_INGRESS_ENABLED", raising=False)
    monkeypatch.delenv("WEBPENT_STATIC_FIXTURE_SOURCE_ENABLED", raising=False)
    monkeypatch.delenv("WEBPENT_MULTI_PRINCIPAL_EXECUTION_ENABLED", raising=False)
    cfg, _orch, _trace = _config_for(monkeypatch, tmp_path)
    from webpent.production.spine_flag_gates import (
        DENY,
        SpineFlagSnapshot,
        evaluate_all,
    )
    snap = SpineFlagSnapshot.from_config(cfg)
    decisions = evaluate_all(snap, engagement_instance_id="inst_flags",
                             target_fingerprint="tgtfp_flags")
    assert all(d.decision == DENY for d in decisions.values())
    assert decisions["live_proxy_source"].reason == "phase1_hardwired_off"


def test_flags_env_enabled_allow_and_bound(monkeypatch, tmp_path):
    cfg, _orch, _trace = _config_for(
        monkeypatch, tmp_path,
        WEBPENT_EXPLORATION_INGRESS_ENABLED="true",
        WEBPENT_STATIC_FIXTURE_SOURCE_ENABLED="true",
        WEBPENT_MULTI_PRINCIPAL_EXECUTION_ENABLED="true")
    from webpent.production.spine_flag_gates import (
        ALLOW,
        SpineFlagSnapshot,
        gate_static_fixture_source,
    )
    snap = SpineFlagSnapshot.from_config(cfg)
    d = gate_static_fixture_source(snap, engagement_instance_id="inst_flags",
                                   target_fingerprint="tgtfp_flags")
    assert d.decision == ALLOW and d.target_binding_digest


def test_flag_gate_denies_placeholder_binding(monkeypatch, tmp_path):
    """NF-M2-04 placeholder class: 'target_unknown' bindings never schedule."""
    cfg, _orch, _trace = _config_for(
        monkeypatch, tmp_path, WEBPENT_STATIC_FIXTURE_SOURCE_ENABLED="true")
    from webpent.production.spine_flag_gates import (
        DENY,
        SpineFlagSnapshot,
        gate_static_fixture_source,
    )
    snap = SpineFlagSnapshot.from_config(cfg)
    d = gate_static_fixture_source(snap, engagement_instance_id="inst",
                                   target_fingerprint="target_unknown")
    assert d.decision == DENY and d.reason == "binding_placeholder_target_fingerprint"


def test_fixture_cannot_set_flags(monkeypatch, tmp_path):
    """R6: fixtures/artifacts are DATA — flag-like fixture keys schedule
    nothing when the operator flags are off."""
    monkeypatch.delenv("WEBPENT_EXPLORATION_INGRESS_ENABLED", raising=False)
    monkeypatch.delenv("WEBPENT_STATIC_FIXTURE_SOURCE_ENABLED", raising=False)
    from webpent.production.modern_spine_integration import modern_spine_recon_node

    fixture = _admitted_fixture("fx_flagattack", engagement_id="e_flagattack",
                            engagement_instance_id="inst_flagattack",
                            target_fingerprint="tgtfp_flagattack")
    fixture["static_fixture_source_enabled"] = True
    fixture["exploration_ingress_enabled"] = True
    fixture["multi_principal_execution_enabled"] = True
    state = {"engagement_id": "e_flagattack", "target_url": "http://127.0.0.1:9105",
             "engagement_instance_id": "inst_flagattack",
             "target_fingerprint": "tgtfp_flagattack",
             "admitted_fixtures": [fixture], "campaign_budget_remaining": 20}
    out = modern_spine_recon_node(state)
    assert out.get("advisory_registered_count") == 0
    reasons = " ".join(r.get("detail", "") for r in out.get("advisory_intake_rejections", []))
    assert "flag_disabled_nothing_schedulable" in reasons


def test_e2_composition_spine_disabled_refuses_composition(monkeypatch):
    """WP-F/R6 composition: E-2's builder-level rejection is independent and
    stands — flags consumers never run on a refused composition."""
    import webpent.graph.builder as builder_mod
    from webpent.shared.exceptions import UnsupportedLegacyOnlyModeError
    # MODERN_SPINE_ENABLED is an import-time constant (E-2 documented); the
    # established test seam patches the builder attribute (see
    # test_r3_e2_builder_rejection.py) — env alone cannot flip it, which is
    # exactly the fail-closed property under test.
    monkeypatch.setattr(builder_mod, "MODERN_SPINE_ENABLED", False)
    with pytest.raises(UnsupportedLegacyOnlyModeError):
        builder_mod.build_graph()
