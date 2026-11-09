"""UM-DR-31 — the evidence-driven adaptive research loop: unit contract.

This suite pins the research loop core (production/adaptive_research.py)
at the unit level:

1. SIGNAL INVENTORY — the UM-DR-31 six-way classification: observed-
   not-tested and inconclusive surface as actionable; a confirmed
   negative (clean) and a confirmed vulnerability (tool_confirmed) do
   NOT; policy/human/validator blocks are non-actionable; unmapped
   ledger classes are recorded, never guessed; scope-denied invariant
   results generate NO hypothesis.
2. FINGERPRINTS — stable across calls; security-relevant differences
   (principal, state keys, objective) NEVER merge; cosmetic differences
   DO merge.
3. GENERATION + DEDUP — deterministic mapping to ordinary Hypothesis
   citizens (new origins coverage_gap / invariant); equivalent
   hypotheses dedup by deterministic id; conclusively-rejected and
   promoted pool entries are never repeated; open pool entries are not
   duplicated.
4. BOUNDS — iteration cap and per-iteration cap are hard, reported,
   never silently exceeded.
5. FAIL-CLOSED — flag off / settings failure / invalid mandatory
   limits all degrade to a no-op.
6. HONESTY — the node NEVER emits finding vocabulary, never promotes,
   never confirms; telemetry names the unchanged confirmation
   authority.
"""

from __future__ import annotations

from typing import Any

import pytest


# ---------------------------------------------------------------------------
# fixtures
# ---------------------------------------------------------------------------

def _state(**overrides: Any) -> dict[str, Any]:
    state: dict[str, Any] = {
        "base_url": "https://shop.example.com",
        "engagement_id": "eng-123",
        "campaign_ledger": {"entries": []},
        "invariant_review": [],
        "workflow_observations": [],
        "hypotheses": [],
    }
    state.update(overrides)
    return state


def _ledger_state() -> dict[str, Any]:
    """One cell per coverage classification (the six-way distinction)."""
    return _state(
        campaign_ledger={"entries": [
            {"key": "idor:profile", "status": "not_scanned"},
            {"key": "sqli:search", "status": "tool_confirmed"},
            {"key": "xss:comment", "status": "clean"},
            {"key": "cmdi:ping", "status": "policy_block"},
            {"key": "ssti:template", "status": "missing-validator"},
            {"key": "privilege_differential:admin", "status": "inconclusive"},
            {"key": "csrf:logout", "status": "blocked_by_precondition"},
            {"key": "totally_unknown_class:thing", "status": "not_scanned"},
        ]},
    )


@pytest.fixture()
def loop_on(monkeypatch):
    from webpent.config.settings import get_settings

    monkeypatch.setattr(get_settings(), "enable_adaptive_research_loop", True)
    monkeypatch.setattr(get_settings(), "max_research_iterations", 3)
    monkeypatch.setattr(get_settings(), "max_research_hypotheses_per_iteration", 12)


# ---------------------------------------------------------------------------
# 1. signal inventory — the six-way classification
# ---------------------------------------------------------------------------

class TestSignalInventory:
    def test_six_way_classification(self) -> None:
        from webpent.production.adaptive_research import research_signal_inventory

        inventory = research_signal_inventory(_ledger_state())
        keys = {signal["key"]: signal["classification"] for signal in inventory["coverage"]}
        # observed-but-not-tested: actionable
        assert keys["idor:profile"] == "observed_not_tested"
        # tested-but-inconclusive: actionable (lower prior)
        assert keys["privilege_differential:admin"] == "tested_inconclusive"
        # blocked-operational: actionable (lowest prior)
        assert keys["csrf:logout"] == "blocked_operational"
        # confirmed negative + confirmed vulnerability: NOT signals
        assert "xss:comment" not in keys
        assert "sqli:search" not in keys
        # policy block + missing-validator: non-actionable
        assert "cmdi:ping" not in keys
        assert "ssti:template" not in keys
        assert inventory["counts"]["non_actionable"] >= 2
        # unmapped class recorded honestly, never guessed
        assert inventory["unmapped_ledger_classes"] == ["totally_unknown_class:thing"]

    def test_not_scanned_with_attempts_is_inconclusive(self) -> None:
        from webpent.production.adaptive_research import research_signal_inventory

        state = _state(campaign_ledger={"entries": [
            {"key": "idor:profile", "status": "not_scanned"},
        ]}, proof_outcomes=[{"campaign_key": "idor:profile", "status": "executed"}])
        inventory = research_signal_inventory(state)
        # the executed outcome maps to inconclusive, not to a fresh
        # untested cell — attempts were spent
        assert inventory["coverage"][0]["attempts"] == 1

    def test_invariant_scope_violation_never_becomes_a_hypothesis(self) -> None:
        from webpent.production.adaptive_research import research_signal_inventory

        state = _state(invariant_review=[{
            "invariant": "out_of_scope_transition_must_not_be_processed",
            "observation_fingerprint": "f" * 16,
            "reason": "denied by scope policy",
            "evidence_refs": [],
        }])
        inventory = research_signal_inventory(state)
        assert inventory["invariants"] == []
        assert len(inventory["scope_violations"]) == 1

    def test_workflow_boundary_requires_allowed_scope_and_context(self) -> None:
        from webpent.production.adaptive_research import research_signal_inventory

        state = _state(workflow_observations=[
            # allowed cross-identity transition: actionable
            {"fingerprint": "a" * 16, "endpoint": "/api/orders/1", "method": "POST",
             "authorization_boundary": "cross_identity", "scope_decision": "allowed",
             "from_state": "pending", "to_state": "shipped"},
            # denied: never a signal
            {"fingerprint": "b" * 16, "endpoint": "/api/admin/1", "method": "POST",
             "authorization_boundary": "cross_identity", "scope_decision": "denied"},
            # unknown boundary: not a signal
            {"fingerprint": "c" * 16, "endpoint": "/api/x/1", "method": "GET",
             "authorization_boundary": "unknown", "scope_decision": "allowed"},
        ])
        inventory = research_signal_inventory(state)
        assert len(inventory["workflow_boundaries"]) == 1
        assert inventory["workflow_boundaries"][0]["endpoint"].startswith("https://shop.example.com/")

    def test_no_base_url_fails_closed_to_no_workflow_signal(self) -> None:
        from webpent.production.adaptive_research import research_signal_inventory

        state = _state(base_url="", workflow_observations=[
            {"fingerprint": "a" * 16, "endpoint": "/api/orders/1", "method": "POST",
             "authorization_boundary": "cross_identity", "scope_decision": "allowed"},
        ])
        inventory = research_signal_inventory(state)
        assert inventory["workflow_boundaries"] == []


# ---------------------------------------------------------------------------
# 2. fingerprints
# ---------------------------------------------------------------------------

class TestFingerprints:
    def test_stable_across_calls(self) -> None:
        from webpent.production.adaptive_research import hypothesis_fingerprint

        a = hypothesis_fingerprint(
            target_url="https://x.com/api/", vuln_class="idor",
            objective_key="boundary:cross_identity",
        )
        b = hypothesis_fingerprint(
            target_url="https://x.com/api", vuln_class="idor",
            objective_key="boundary:cross_identity",
        )
        assert a == b  # trailing-slash normalization

    def test_security_relevant_differences_never_merge(self) -> None:
        from webpent.production.adaptive_research import hypothesis_fingerprint

        base = dict(
            target_url="https://x.com/api/orders/1", vuln_class="idor",
            objective_key="boundary:cross_identity",
        )
        fp = hypothesis_fingerprint(**base)
        # different principal
        assert hypothesis_fingerprint(**base, principal_refs=["user:a"]) != fp
        # different state keys
        assert hypothesis_fingerprint(**base, state_keys=["pending"]) != fp
        # different objective
        assert hypothesis_fingerprint(**{**base, "objective_key": "boundary:role_scoped"}) != fp
        # different class
        assert hypothesis_fingerprint(**{**base, "vuln_class": "business_logic"}) != fp

    def test_principal_order_does_not_matter(self) -> None:
        from webpent.production.adaptive_research import hypothesis_fingerprint

        assert (
            hypothesis_fingerprint(target_url="https://x.com", vuln_class="idor",
                                   objective_key="o", principal_refs=["a", "b"])
            == hypothesis_fingerprint(target_url="https://x.com", vuln_class="idor",
                                      objective_key="o", principal_refs=["b", "a"])
        )


# ---------------------------------------------------------------------------
# 3. generation + dedup
# ---------------------------------------------------------------------------

class TestGenerationAndDedup:
    def test_generated_hypotheses_are_ordinary_pool_citizens(self, loop_on) -> None:
        from webpent.models.hypothesis import HypothesisOrigin
        from webpent.production.adaptive_research import generate_research_hypotheses

        hypotheses, detail = generate_research_hypotheses(_ledger_state(), max_new=12)
        assert detail["generated"] == 3  # idor + privilege_differential + csrf
        origins = {h.origin for h in hypotheses}
        assert origins == {HypothesisOrigin.COVERAGE_GAP.value}
        for h in hypotheses:
            # the research contract fields are populated
            assert h.preconditions and h.expected_behavior and h.negative_control
            assert h.info_gain is not None and 0.0 <= h.info_gain <= 1.0
            assert h.estimated_cost is not None
            # traceable provenance
            assert h.origin_detail.startswith("umdr31_research_loop fp=")
            assert h.evidence_refs
            # NOT a finding, NOT deterministic-match (no promotion bypass)
            assert h.status == "unexplored"
            assert h.deterministic_match is False

    def test_info_gain_prior_order_is_explainable(self, loop_on) -> None:
        from webpent.production.adaptive_research import generate_research_hypotheses

        hypotheses, _ = generate_research_hypotheses(_ledger_state(), max_new=12)
        priors = {h.vuln_class: h.info_gain for h in hypotheses}
        assert priors["idor"] == 0.60          # observed_not_tested
        assert priors["privilege_differential"] == 0.45  # tested_inconclusive
        assert priors["csrf"] == 0.30          # blocked_operational

    def test_equivalent_signals_dedup_across_passes(self, loop_on) -> None:
        from webpent.production.adaptive_research import generate_research_hypotheses

        state = _ledger_state()
        first, detail1 = generate_research_hypotheses(state, max_new=12)
        # simulate the pool merge (the node's output became state)
        state["hypotheses"] = list(first)
        second, detail2 = generate_research_hypotheses(state, max_new=12)
        assert detail2["generated"] == 0
        assert detail2["suppressed_open"] == 3

    def test_conclusively_rejected_never_repeated(self, loop_on) -> None:
        from webpent.production.adaptive_research import generate_research_hypotheses

        state = _ledger_state()
        first, _ = generate_research_hypotheses(state, max_new=12)
        # the idor hypothesis was conclusively rejected downstream
        rejected = [
            {**h.model_dump(mode="json"), "status": "resolved_false"}
            if hasattr(h, "model_dump") else dict(h)
            for h in first
        ]
        state["hypotheses"] = rejected
        second, detail = generate_research_hypotheses(state, max_new=12)
        assert detail["generated"] == 0
        assert detail["suppressed_closed"] == 3

    def test_promoted_never_regenerated(self, loop_on) -> None:
        from webpent.production.adaptive_research import generate_research_hypotheses

        state = _ledger_state()
        first, _ = generate_research_hypotheses(state, max_new=12)
        promoted = [
            {**h.model_dump(mode="json"), "status": "promoted"}
            if hasattr(h, "model_dump") else dict(h)
            for h in first
        ]
        state["hypotheses"] = promoted
        _, detail = generate_research_hypotheses(state, max_new=12)
        assert detail["generated"] == 0

    def test_invariant_signal_maps_to_idor_class(self, loop_on) -> None:
        from webpent.production.adaptive_research import generate_research_hypotheses

        state = _state(invariant_review=[{
            "invariant": "authorization_context_must_be_present",
            "observation_fingerprint": "f" * 16,
            "reason": "role transition lacks identity context",
            "evidence_refs": ["wf:1", "wf:2"],
        }])
        hypotheses, detail = generate_research_hypotheses(state, max_new=12)
        assert detail["generated"] == 1
        assert hypotheses[0].vuln_class == "idor"
        assert hypotheses[0].origin == "invariant"

    def test_replay_invariant_maps_to_business_logic(self, loop_on) -> None:
        from webpent.production.adaptive_research import generate_research_hypotheses

        state = _state(invariant_review=[{
            "invariant": "state_must_progress_or_reject_replay",
            "observation_fingerprint": "f" * 16,
            "reason": "destructive op reports same source and target state",
            "evidence_refs": [],
        }])
        hypotheses, _ = generate_research_hypotheses(state, max_new=12)
        assert hypotheses[0].vuln_class == "business_logic"

    def test_per_iteration_cap_is_hard_and_reported(self, loop_on) -> None:
        from webpent.production.adaptive_research import generate_research_hypotheses

        big = _state(campaign_ledger={"entries": [
            {"key": f"idor:cell{i}", "status": "not_scanned"} for i in range(40)
        ]})
        hypotheses, detail = generate_research_hypotheses(big, max_new=5)
        assert len(hypotheses) == 5
        assert detail["capped"] is True

    def test_no_target_context_fails_closed(self, loop_on) -> None:
        from webpent.production.adaptive_research import generate_research_hypotheses

        hypotheses, detail = generate_research_hypotheses(
            _state(base_url=""), max_new=12
        )
        assert hypotheses == []
        assert detail["reason"] == "no_target_context"


# ---------------------------------------------------------------------------
# 4 + 5. the node: bounds + fail-closed
# ---------------------------------------------------------------------------

class TestNodeBoundsAndFailClosed:
    def test_flag_off_is_a_no_op(self, monkeypatch) -> None:
        from webpent.config.settings import get_settings
        from webpent.production.adaptive_research import research_loop_node

        monkeypatch.setattr(get_settings(), "enable_adaptive_research_loop", False)
        assert research_loop_node(_ledger_state()) == {}

    def test_flag_on_writes_pool_and_telemetry(self, loop_on) -> None:
        from webpent.production.adaptive_research import research_loop_node

        update = research_loop_node(_ledger_state())
        assert set(update) <= {"hypotheses", "research_loop"}
        assert len(update["hypotheses"]) == 3
        telemetry = update["research_loop"]
        assert telemetry["window"] == "UM-DR-31"
        assert telemetry["iterations_used"] == 1
        assert telemetry["hypotheses_generated_total"] == 3
        assert telemetry["last_status"] == "ok"
        # the confirmation authority is named and unchanged
        assert telemetry["confirmation_authority"].startswith(
            "cqa_v2.guarded_causal_evaluate"
        )
        # honesty: no finding vocabulary anywhere in the update
        assert "findings" not in update

    def test_iteration_cap_is_hard(self, loop_on) -> None:
        from webpent.production.adaptive_research import research_loop_node

        state = _ledger_state()
        for _ in range(3):
            update = research_loop_node(state)
            state["hypotheses"] = list(update.get("hypotheses", state["hypotheses"]))
            state["research_loop"] = update["research_loop"]
        # 4th invocation: capped pass-through, no work
        update = research_loop_node(state)
        assert "hypotheses" not in update
        assert update["research_loop"]["last_status"] == "capped"
        assert update["research_loop"]["iterations_used"] == 3

    def test_settings_failure_fails_closed(self, monkeypatch) -> None:
        import webpent.config.settings as settings_module
        from webpent.production.adaptive_research import research_loop_node

        def _boom():
            raise RuntimeError("settings unavailable")

        monkeypatch.setattr(settings_module, "get_settings", _boom)
        assert research_loop_node(_ledger_state()) == {}

    def test_invalid_mandatory_limits_fail_closed(self, monkeypatch) -> None:
        from webpent.config.settings import get_settings
        from webpent.production.adaptive_research import research_loop_node

        monkeypatch.setattr(get_settings(), "enable_adaptive_research_loop", True)
        monkeypatch.setattr(get_settings(), "max_research_iterations", 0)
        assert research_loop_node(_ledger_state()) == {}

    def test_internal_failure_fails_soft(self, loop_on, monkeypatch) -> None:
        import webpent.production.adaptive_research as module
        from webpent.production.adaptive_research import research_loop_node

        def _boom(state, *, max_new):
            raise RuntimeError("inventory exploded")

        monkeypatch.setattr(module, "generate_research_hypotheses", _boom)
        update = research_loop_node(_ledger_state())
        assert update["research_loop"]["last_status"] == "error"
        assert "hypotheses" not in update


# ---------------------------------------------------------------------------
# 6. honesty pins — no authority, no findings, ever
# ---------------------------------------------------------------------------

class TestAuthorityPins:
    def test_node_output_carries_no_finding_vocabulary(self, loop_on) -> None:
        from webpent.production.adaptive_research import research_loop_node

        update = research_loop_node(_ledger_state())
        assert "findings" not in update
        for key in update.get("hypotheses", []):
            assert key.status == "unexplored"  # beliefs, not results

    def test_loop_hypotheses_rank_under_the_real_strategist_formula(self, loop_on) -> None:
        from webpent.production.adaptive_research import generate_research_hypotheses
        from webpent.shared.prioritization import rank_open_hypotheses

        state = _ledger_state()
        hypotheses, _ = generate_research_hypotheses(state, max_new=12)
        state["hypotheses"] = list(hypotheses)
        ranked = rank_open_hypotheses(state["hypotheses"], state)
        # every research hypothesis is ranked by the UNCHANGED formula
        assert len(ranked) == 3
        assert all(0.0 <= score <= 1.0 for _h, score in ranked)
        # deterministic: the same pool ranks identically on a second pass
        assert [(str(h.id)) for h, _ in ranked] == [
            str(h.id) for h, _ in rank_open_hypotheses(state["hypotheses"], state)
        ]


# ---------------------------------------------------------------------------
# stateful hints
# ---------------------------------------------------------------------------

def _probed_dirs(summary: dict) -> list[str]:
    """Directories of the PROBED cases, in probe order (per_case records
    only probed cases, keyed by candidate path)."""
    return [
        "/".join(str(c.get("candidate")).strip("/").split("/")[:-1])
        for c in summary["per_case"]
    ]


class TestStatefulHints:
    def test_hints_derive_only_from_observed_stateful_boundaries(self) -> None:
        from webpent.production.adaptive_research import stateful_research_hints

        state = _state(workflow_observations=[
            {"fingerprint": "a" * 16, "endpoint": "/api/orders/1", "method": "POST",
             "authorization_boundary": "cross_identity", "scope_decision": "allowed"},
            # GET boundary: no stateful hint
            {"fingerprint": "b" * 16, "endpoint": "/api/users/2", "method": "GET",
             "authorization_boundary": "object_scoped", "scope_decision": "allowed"},
            # out-of-scope: no hint
            {"fingerprint": "c" * 16, "endpoint": "/api/admin/3", "method": "DELETE",
             "authorization_boundary": "cross_identity", "scope_decision": "denied"},
        ])
        hints = stateful_research_hints(state)
        assert hints == {"api/orders": 1.0}

    def test_hints_reorder_stateful_cases_within_same_budget(self) -> None:
        from webpent.production.stateful_discovery import run_stateful_discovery

        inventory = []
        for i in range(1, 4):
            inventory.append({"method": "GET", "path": f"/api/aaa/items/{i}"})
            inventory.append({"method": "GET", "path": f"/api/zzz/items/{i}"})
        inventory.append({"method": "POST", "path": "/api/zzz/items/1"})

        class _Executor:
            def __call__(self, plan):
                class _R:
                    status_code = 200
                    text = "{}"
                    headers = {}
                return _R()

        # without hints: sorted-directory order — aaa first
        # a small real budget so per_case records the probed order;
        # 3 reads per directory mine 2 candidate cases each — both
        # directories are present within max_cases=4)
        plain = run_stateful_discovery(
            _state(), executor=_Executor(), base_url="https://x.com",
            inventory=inventory, max_cases=4, max_requests=8,
        )

        # with hints (the REAL mined-case directory vocabulary — no
        # leading slash): the zzz cases must come first. R5/F06: the
        # assertion is the resulting case ORDER, not an internal flag.
        hinted = run_stateful_discovery(
            _state(), executor=_Executor(), base_url="https://x.com",
            inventory=inventory, max_cases=4, max_requests=8,
            research_hints={"api/zzz/items": 1.0},
        )
        assert hinted["research_hints_applied"] is True
        assert hinted["research_hints_matched_cases"] >= 1
        hinted_dirs = _probed_dirs(hinted)
        assert hinted_dirs, "per_case must record the mined case order"
        assert hinted_dirs[0] == "api/zzz/items"
        assert "api/aaa/items" in hinted_dirs
        assert hinted_dirs.index("api/zzz/items") < hinted_dirs.index("api/aaa/items")
        # the plain (unhinted) run kept the alphabetical order
        plain_dirs = _probed_dirs(plain)
        assert plain_dirs[0] == "api/aaa/items"
        # identical MINED population — hints reorder, never add/remove
        # (the probed subset may legitimately differ: prioritized
        # coverage under the same budget is the mechanism's purpose)
        assert hinted["cases_mined"] == plain["cases_mined"]
        assert plain["research_hints_applied"] is False

    def test_hint_with_mismatched_vocabulary_is_reported_not_applied(self) -> None:
        """R5/F06: a hint that matches no executable case must NOT be
        reported as applied (the historical bug: a leading-slash key
        matched nothing yet the flag said True)."""
        from webpent.production.stateful_discovery import run_stateful_discovery

        inventory = [{"method": "GET", "path": f"/api/aaa/items/{i}"} for i in range(1, 6)]

        class _Executor:
            def __call__(self, plan):
                class _R:
                    status_code = 200
                    text = "{}"
                    headers = {}
                return _R()

        # leading-slash key: wrong vocabulary, matches no mined directory
        mismatched = run_stateful_discovery(
            _state(), executor=_Executor(), base_url="https://x.com",
            inventory=inventory, max_cases=4, max_requests=8,
            research_hints={"/api/aaa": 1.0},
        )
        assert mismatched["research_hints_applied"] is False
        assert mismatched["research_hints_matched_cases"] == 0
        # order unchanged (alphabetical) — the mismatched hint reordered nothing
        dirs = _probed_dirs(mismatched)
        assert dirs == sorted(dirs)

    def test_hint_matching_is_case_exact_but_order_deterministic(self) -> None:
        from webpent.production.stateful_discovery import run_stateful_discovery

        inventory = []
        for i in range(1, 4):
            inventory.append({"method": "GET", "path": f"/api/aaa/items/{i}"})
            inventory.append({"method": "GET", "path": f"/api/zzz/items/{i}"})

        class _Executor:
            def __call__(self, plan):
                class _R:
                    status_code = 200
                    text = "{}"
                    headers = {}
                return _R()

        runs = [
            run_stateful_discovery(
                _state(), executor=_Executor(), base_url="https://x.com",
                inventory=inventory, max_cases=4, max_requests=8,
                research_hints={"api/zzz/items": 1.0, "api/aaa/items": 0.5},
            )
            for _ in range(3)
        ]
        orders = [
            [str(c.get("candidate")) for c in run["per_case"]] for run in runs
        ]
        assert orders[0] == orders[1] == orders[2]
        assert runs[0]["research_hints_applied"] is True


# ---------------------------------------------------------------------------
# UM-DR-31.1 — R3 hypothesis-admission scope filter (F05)
# ---------------------------------------------------------------------------

class TestHypothesisAdmissionScopeFilter:
    """R3: a foreign host, a non-http(s) scheme, or a malformed URL must
    never become an executable research candidate. The execution-time
    scope gate stays the authoritative gate — this is defense in depth
    at hypothesis ADMISSION."""

    def _wf(self, endpoint: str, **extra: Any) -> dict[str, Any]:
        return {
            "fingerprint": "f" * 16,
            "endpoint": endpoint,
            "method": "POST",
            "authorization_boundary": "cross_identity",
            "scope_decision": "allowed",
            **extra,
        }

    def test_same_authorized_host_http_accepted(self) -> None:
        from webpent.production.adaptive_research import research_signal_inventory

        inventory = research_signal_inventory(_state(
            base_url="http://lab.example:8080",
            workflow_observations=[self._wf("http://lab.example:8080/api/vaults/vlt_1")],
        ))
        assert len(inventory["workflow_boundaries"]) == 1
        assert inventory["scope_violations"] == []

    def test_same_authorized_host_https_accepted(self) -> None:
        from webpent.production.adaptive_research import research_signal_inventory

        inventory = research_signal_inventory(_state(
            base_url="https://lab.example",
            workflow_observations=[self._wf("https://lab.example/api/vaults/vlt_1")],
        ))
        assert len(inventory["workflow_boundaries"]) == 1

    def test_relative_endpoint_joined_to_campaign_base(self) -> None:
        from webpent.production.adaptive_research import research_signal_inventory

        inventory = research_signal_inventory(_state(
            workflow_observations=[self._wf("/api/vaults/vlt_1")],
        ))
        assert len(inventory["workflow_boundaries"]) == 1
        assert inventory["workflow_boundaries"][0]["endpoint"].startswith(
            "https://shop.example.com/api/vaults/"
        )

    def test_foreign_host_rejected_before_hypothesis_pool(self) -> None:
        from webpent.production.adaptive_research import (
            generate_research_hypotheses,
            research_signal_inventory,
        )

        state = _state(workflow_observations=[
            self._wf("https://evil.example.com/api/vaults/vlt_1"),
        ])
        inventory = research_signal_inventory(state)
        assert inventory["workflow_boundaries"] == []
        assert len(inventory["scope_violations"]) == 1
        assert inventory["scope_violations"][0]["reason"] == "foreign_host"
        assert inventory["scope_violations"][0]["stage"] == "hypothesis_admission"
        new, _detail = generate_research_hypotheses(state, max_new=12)
        assert new == []  # nothing entered the pool

    def test_non_http_scheme_rejected(self) -> None:
        from webpent.production.adaptive_research import research_signal_inventory

        for endpoint in (
            "ftp://shop.example.com/api/vaults/vlt_1",
            "file:///etc/passwd",
            "gopher://shop.example.com/x",
        ):
            inventory = research_signal_inventory(_state(
                workflow_observations=[self._wf(endpoint)],
            ))
            assert inventory["workflow_boundaries"] == [], endpoint
            assert inventory["scope_violations"], endpoint
            assert inventory["scope_violations"][0]["reason"].startswith(
                "scheme_not_http_s"
            ), endpoint

    def test_malformed_url_rejected(self) -> None:
        from webpent.production.adaptive_research import research_signal_inventory

        inventory = research_signal_inventory(_state(
            workflow_observations=[self._wf("https://[::1:not-a-port/x")],
        ))
        assert inventory["workflow_boundaries"] == []
        assert inventory["scope_violations"][0]["reason"] in {
            "malformed_url", "malformed_url_no_host",
        }

    def test_host_case_normalized_for_comparison(self) -> None:
        from webpent.production.adaptive_research import research_signal_inventory

        inventory = research_signal_inventory(_state(
            workflow_observations=[self._wf("https://SHOP.Example.COM/api/vaults/vlt_1")],
        ))
        assert len(inventory["workflow_boundaries"]) == 1
        # the admitted endpoint is canonically lower-cased (R4)
        assert inventory["workflow_boundaries"][0]["endpoint"].startswith(
            "https://shop.example.com/"
        )

    def test_port_behavior_is_deliberate(self) -> None:
        from webpent.production.adaptive_research import research_signal_inventory

        # same origin with explicit port equal to the origin's: admitted
        ok = research_signal_inventory(_state(
            base_url="http://lab.example:8080",
            workflow_observations=[self._wf("http://lab.example:8080/api/x/1")],
        ))
        assert len(ok["workflow_boundaries"]) == 1
        # same host, DIFFERENT port: a different service — rejected
        diff = research_signal_inventory(_state(
            base_url="http://lab.example:8080",
            workflow_observations=[self._wf("http://lab.example:9090/api/x/1")],
        ))
        assert diff["workflow_boundaries"] == []
        assert diff["scope_violations"][0]["reason"] == "port_mismatch"
        # same host, scheme default port vs the origin's explicit port: rejected
        default = research_signal_inventory(_state(
            base_url="http://lab.example:8080",
            workflow_observations=[self._wf("http://lab.example/api/x/1")],
        ))
        assert default["workflow_boundaries"] == []
        assert default["scope_violations"][0]["reason"] == "port_mismatch"

    def test_no_campaign_origin_fails_closed(self) -> None:
        from webpent.production.adaptive_research import research_signal_inventory

        state = _state()
        state["base_url"] = ""
        state["target_url"] = ""
        inventory = research_signal_inventory(_state(
            base_url="", target_url="",
            workflow_observations=[self._wf("https://shop.example.com/api/x/1")],
        ))
        assert inventory["workflow_boundaries"] == []
        assert inventory["scope_violations"][0]["reason"] == "no_campaign_origin"


# ---------------------------------------------------------------------------
# UM-DR-31.1 — R4 fingerprint canonicalization (F10/F11)
# ---------------------------------------------------------------------------

class TestFingerprintCanonicalization:
    def test_query_order_equivalence(self) -> None:
        from webpent.production.adaptive_research import hypothesis_fingerprint

        base = dict(vuln_class="idor", objective_key="boundary:cross_identity")
        a = hypothesis_fingerprint(target_url="https://x.com/api/o/1?b=2&a=1", **base)
        b = hypothesis_fingerprint(target_url="https://x.com/api/o/1?a=1&b=2", **base)
        assert a == b

    def test_query_value_distinction(self) -> None:
        from webpent.production.adaptive_research import hypothesis_fingerprint

        base = dict(vuln_class="idor", objective_key="boundary:cross_identity")
        a = hypothesis_fingerprint(target_url="https://x.com/api/o/1?account=1", **base)
        b = hypothesis_fingerprint(target_url="https://x.com/api/o/1?account=2", **base)
        assert a != b  # F10: the over-merge that used to suppress this probe

    def test_duplicate_query_parameters_preserved(self) -> None:
        from webpent.production.adaptive_research import hypothesis_fingerprint

        base = dict(vuln_class="idor", objective_key="k")
        single = hypothesis_fingerprint(target_url="https://x.com/o?id=1", **base)
        dup = hypothesis_fingerprint(target_url="https://x.com/o?id=1&id=2", **base)
        reordered = hypothesis_fingerprint(target_url="https://x.com/o?id=2&id=1", **base)
        assert dup != single
        assert dup == reordered  # deterministic without losing duplicates

    def test_host_case_equivalence(self) -> None:
        from webpent.production.adaptive_research import hypothesis_fingerprint

        base = dict(vuln_class="idor", objective_key="k")
        a = hypothesis_fingerprint(target_url="https://X.com/o/1", **base)
        b = hypothesis_fingerprint(target_url="https://x.com/o/1", **base)
        assert a == b  # F11: the cosmetic false split

    def test_path_distinction_preserved(self) -> None:
        from webpent.production.adaptive_research import hypothesis_fingerprint

        base = dict(vuln_class="idor", objective_key="k")
        a = hypothesis_fingerprint(target_url="https://x.com/api/orders/1", **base)
        b = hypothesis_fingerprint(target_url="https://x.com/api/orders/2", **base)
        assert a != b

    def test_fragment_stripped(self) -> None:
        from webpent.production.adaptive_research import hypothesis_fingerprint

        base = dict(vuln_class="idor", objective_key="k")
        a = hypothesis_fingerprint(target_url="https://x.com/o/1", **base)
        b = hypothesis_fingerprint(target_url="https://x.com/o/1#fragment", **base)
        assert a == b

    def test_normalize_url_idempotent_and_deterministic(self) -> None:
        from webpent.production.adaptive_research import _normalize_url

        once = _normalize_url("HTTPS://X.com:443/a/?b=2&a=1&a=1#frag")
        twice = _normalize_url(once)
        assert once == twice
        assert once == "https://x.com:443/a/?a=1&a=1&b=2"

    def test_principal_and_state_distinctions_preserved(self) -> None:
        from webpent.production.adaptive_research import hypothesis_fingerprint

        base = dict(target_url="https://x.com/o/1", vuln_class="idor", objective_key="k")
        a = hypothesis_fingerprint(**base, principal_refs=["user_a"])
        b = hypothesis_fingerprint(**base, principal_refs=["user_b"])
        c = hypothesis_fingerprint(**base, state_keys=["state:open"])
        d = hypothesis_fingerprint(**base, preconditions=["sealed"])
        assert len({a, b, c, d}) == 4


# ---------------------------------------------------------------------------
# UM-DR-31.1 — R6 the classification contract (F08/F12/F20)
# ---------------------------------------------------------------------------

class TestClassificationContract:
    def test_full_vocabulary_is_pure_and_total(self) -> None:
        from webpent.production.adaptive_research import (
            CLASSIFICATION_VOCABULARY,
            classify_coverage_status,
        )

        statuses = [
            "not_scanned", "inconclusive", "blocked_by_precondition",
            "infrastructure_failure", "policy_block", "human_review_only",
            "missing-validator", "clean", "tool_confirmed", "candidate",
            "unknown_status",
        ]
        for status in statuses:
            for attempts in (0, 1, 5):
                result = classify_coverage_status(status, attempts)
                assert result in CLASSIFICATION_VOCABULARY, (status, attempts)

    def test_actionable_group(self) -> None:
        from webpent.production.adaptive_research import classify_coverage_status

        assert classify_coverage_status("not_scanned", 0) == "observed_not_tested"
        assert classify_coverage_status("inconclusive", 0) == "tested_inconclusive"
        assert classify_coverage_status("blocked_by_precondition", 0) == "blocked_operational"
        assert classify_coverage_status("infrastructure_failure", 0) == "blocked_operational"
        # not_scanned WITH attempts: executed but no recognized outcome
        assert classify_coverage_status("not_scanned", 3) == "tested_inconclusive"

    def test_non_actionable_group(self) -> None:
        from webpent.production.adaptive_research import classify_coverage_status

        assert classify_coverage_status("policy_block", 0) == "blocked_policy"
        assert classify_coverage_status("human_review_only", 0) == "non_actionable"
        assert classify_coverage_status("missing-validator", 0) == "non_actionable"
        assert classify_coverage_status("clean", 0) == "tested_rejected"
        assert classify_coverage_status("tool_confirmed", 0) == "confirmed_vulnerability"

    def test_candidate_is_non_actionable_f08(self) -> None:
        from webpent.production.adaptive_research import classify_coverage_status

        # F08: a candidate cell is owned by the causal/human pipeline —
        # never silently an actionable coverage gap
        assert classify_coverage_status("candidate", 0) == "non_actionable"
        assert classify_coverage_status("candidate", 4) == "non_actionable"

    def test_unknown_and_malformed_fail_closed_f20(self) -> None:
        from webpent.production.adaptive_research import (
            CLASSIFICATION_VOCABULARY,
            classify_coverage_status,
        )

        for garbage in ("future_status", "GARBAGE", "some_new_thing", "0", "-", " "):
            result = classify_coverage_status(garbage, 0)
            assert result == "unknown_status", garbage
            assert result in CLASSIFICATION_VOCABULARY
        # attempts DO change the honest reading of an unrecognized
        # label: with backing attempts the cell was EXECUTED and only
        # its outcome label is unrecognized — tested_inconclusive
        # (actionable at the lower 0.45 prior), never "unexplored";
        # with NO attempts the cell is fail-closed unknown_status
        assert classify_coverage_status("future_status", 9) == "tested_inconclusive"
        # the projection guarantees the real path never produces
        # (unrecognized, attempts>0): the outcome status overrides the
        # raw status whenever an outcome exists — this branch is the
        # direct-call second gate only
        # empty/None status with no attempts: honest unobserved, not unknown
        assert classify_coverage_status("", 0) == "observed_not_tested"

    def test_unknown_status_never_becomes_a_research_opportunity(self) -> None:
        """F20 end to end: the projection marks it unknown_status; the
        detector does not emit it; the inventory would record it as
        non-actionable even if it leaked through."""
        from webpent.coverage.gap_detector import CoverageGapDetector
        from webpent.production.adaptive_research import research_signal_inventory
        from webpent.shared.coverage_ledger import project_coverage_ledger

        state = _state(
            campaign_ledger={"entries": [
                {"key": "idor:vaults", "status": "operator_hold"},
            ]},
        )
        projected = project_coverage_ledger(state)
        entry = projected["entries"][0]
        assert entry["status"] == "unknown_status"
        assert "unrecognized-status" in entry["gaps"]
        assert CoverageGapDetector().detect(state) == []  # no gap emitted
        inventory = research_signal_inventory(state)
        assert inventory["coverage"] == []

    def test_producer_aliases_still_reconcile(self) -> None:
        from webpent.shared.coverage_ledger import project_coverage_ledger

        state = _state(
            campaign_ledger={"entries": [
                {"key": "idor:vaults", "status": "not_observed"},
                {"key": "sqli:search", "status": "tested"},
                # the fixture-pinned claimed-but-unbacked spelling: the
                # honest downgrade makes it an open gap (the pinned
                # test_umdr30_coverage_gap_report contract)
                {"key": "xss:comment", "status": "tool_unconfirmed"},
            ]},
        )
        projected = project_coverage_ledger(state)
        statuses = {e["key"]: e["status"] for e in projected["entries"]}
        assert statuses["idor:vaults"] == "not_scanned"
        assert statuses["sqli:search"] == "not_scanned"
        assert statuses["xss:comment"] == "not_scanned"


# ---------------------------------------------------------------------------
# UM-DR-31.1 — R7 corrupted research-loop channel (F18)
# ---------------------------------------------------------------------------

class TestCorruptedChannelFailClosed:
    # every test runs with the research loop flag + mandatory limits ON
    # (the node is double-gated; a flag-off no-op would prove nothing)
    def _corrupt(self, value: Any, loop_on) -> None:
        from webpent.production.adaptive_research import research_loop_node

        update = research_loop_node(_state(research_loop=value))
        telemetry = update.get("research_loop") or {}
        assert telemetry.get("last_status") == "state_invalid_fail_closed"
        assert telemetry.get("state_invalid") is True
        assert telemetry.get("reason") == "research_loop_channel_not_mapping"
        # fail-closed: corruption consumed the remaining budget, never
        # granted more — the counter is flooded to the cap
        assert telemetry.get("iterations_used") == 3
        assert "hypotheses" not in update

    def test_string_channel(self, loop_on) -> None:
        self._corrupt("garbage", loop_on)

    def test_list_channel(self, loop_on) -> None:
        self._corrupt([1, 2, 3], loop_on)

    def test_int_channel(self, loop_on) -> None:
        self._corrupt(12345, loop_on)

    def test_bool_channel(self, loop_on) -> None:
        self._corrupt(True, loop_on)

    def test_corrupted_channel_cannot_re_arm_on_the_next_pass(self, loop_on) -> None:
        from webpent.production.adaptive_research import research_loop_node

        state = _state(research_loop="garbage", campaign_ledger={"entries": [
            {"key": "idor:vaults", "status": "not_scanned"},
        ]})
        first = research_loop_node(state)
        assert first["research_loop"]["last_status"] == "state_invalid_fail_closed"
        # the flooded counter lands in the state; the next pass is capped
        state["research_loop"] = first["research_loop"]
        second = research_loop_node(state)
        assert second["research_loop"].get("capped") is True
        assert second["research_loop"].get("last_status") == "capped"
        assert "hypotheses" not in second

    def test_missing_and_none_channels_still_work(self, loop_on) -> None:
        from webpent.production.adaptive_research import research_loop_node

        for channel in (None, {},):
            state = _state(research_loop=channel, campaign_ledger={"entries": [
                {"key": "idor:vaults", "status": "not_scanned"},
            ]})
            update = research_loop_node(state)
            assert update["research_loop"]["last_status"] == "ok"
            assert update.get("hypotheses")

    def test_non_integer_counter_degrades_without_re_arm(self, loop_on) -> None:
        from webpent.production.adaptive_research import research_loop_node

        state = _state(research_loop={"iterations_used": "not-a-number"})
        update = research_loop_node(state)
        telemetry = update.get("research_loop") or {}
        assert telemetry.get("last_status") in {"error", "state_invalid_fail_closed"}
        assert "hypotheses" not in update
