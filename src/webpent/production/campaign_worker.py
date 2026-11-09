#!/usr/bin/env python3
"""TEAM-1 — Subprocess entry point for process-boundary campaign continuity.

Usage: python3 -m webpent.production.campaign_worker <state_file> <cycle>

Runs ONE research cycle in a fresh process: loads CampaignState, runs one
bounded experiment cycle via ModernOrchestrator, persists updated state.
This crosses a REAL process boundary (not same-process object references).
"""
from __future__ import annotations

import json
import sys


def main():
    # Sprint I-1, item 1.3: fail-closed startup gate — refuses to start
    # when WEBPENT_ALLOW_DIRECT_ORCHESTRATOR_CONSTRUCTION_TEST_ONLY is set
    # in a qualification/staging/production deployment.
    from webpent.shared.preflight import enforce_construction_escape_gate
    enforce_construction_escape_gate()

    if len(sys.argv) < 3:
        print(json.dumps({"error": "usage: campaign_worker <state_file> <cycle>"}))
        sys.exit(2)
    state_file = sys.argv[1]
    cycle = int(sys.argv[2])

    from webpent.production.campaign_state import (
        load_campaign_state,
        persist_campaign_state,
    )

    try:
        state = load_campaign_state(state_file)
    except Exception as exc:
        print(json.dumps({"error": f"load_failed: {exc}"}))
        sys.exit(1)

    if state.is_terminal():
        print(json.dumps({"cycle": cycle, "skipped": True, "reason": state.terminal_state}))
        return

    # Budget/control checkpoint — halt is cooperative: any action already
    # running is allowed to finish, and this next cycle stops before dispatch.
    exhausted, reason = state.budget_exhausted()
    if exhausted:
        state.mark_terminal(reason)
        persist_campaign_state(state, state_file)
        print(json.dumps({"cycle": cycle, "terminal": reason}))
        return

    state.cycle = cycle

    # FIX 1: construct via the single authoritative factory instead of
    # hand-building an AuthorizedLabProfile/ScopeLaw and instantiating
    # ModernOrchestrator directly. The explicit "127.0.0.1"/"localhost"
    # entries below were already a no-op: AuthorizedLabProfile.is_target_
    # authorized() unconditionally allows those hosts regardless of
    # authorized_targets (see live_hunter/profile.py), so routing through
    # resolve_production_spine() (which derives authorized_targets=(host,)
    # from target_url) changes no authorization outcome for this worker.
    from webpent.production.production_spine import ProductionSpineConfig, resolve_production_spine
    spine_config = ProductionSpineConfig(
        engagement_id=state.engagement_id,
        target_url=state.target_url,
        entrypoint="worker",
    )
    orch, _production_trace = resolve_production_spine(spine_config)

    # Reconstruct research state from persisted agenda.
    hypotheses = [h for h in state.agenda.get("follow_up_actions", [])] or [
        f"hyp_cycle_{cycle}_a", f"hyp_cycle_{cycle}_b",
    ]
    orch.run_deep_recon(
        target_url=state.target_url,
        observed=[{"path": f"/api/endpoint_{cycle}", "method": "GET",
                   "status_code": 200, "body": "{}", "headers": {}}],
    )
    selected = hypotheses[0] if hypotheses else f"hyp_cycle_{cycle}"
    orch.research_loop.register_candidate(f"cand_{cycle}", (selected,), f"exp_{cycle}")
    decision = orch.research_step()

    # Bounded experiment (deterministic — no network in subprocess test).
    result = orch.run_bounded_experiment(
        candidate_id=f"cand_{cycle}", hypothesis_id=selected,
        tool_name="httpx_bounded",
        target_url=f"{state.target_url}/api/endpoint_{cycle}",
    )

    # Record decision + outcome.
    import hashlib
    obs_digest = hashlib.sha256(json.dumps(result.get("observation", {}), sort_keys=True).encode()).hexdigest()[:16]
    state.record_decision(
        cycle=cycle, selected_hypothesis=selected, selected_experiment=f"exp_{cycle}",
        agenda_digest=hashlib.sha256(json.dumps(state.agenda, sort_keys=True).encode()).hexdigest()[:16],
        memory_inputs=list(state.memory_refs),
    )
    info_val = result.get("observation", {}).get("information_value", 0.5)
    outcome_class = "high_information" if info_val > 0.6 else "low_information"
    state.record_outcome(
        cycle=cycle, experiment_id=f"exp_{cycle}", outcome_class=outcome_class,
        information_value=info_val, observation_digest=obs_digest,
    )

    # Update agenda from observation (organic — depends on outcome).
    if outcome_class == "high_information":
        state.agenda["confirmed_facts"].append(f"cycle_{cycle}: endpoint responsive")
        state.agenda["promising_relationships"].append(f"cycle_{cycle}: high-value target")
        state.agenda["follow_up_actions"].append(f"hyp_deepen_{cycle}")
    else:
        state.agenda["rejected_hypotheses"].append(selected)
        state.agenda["unresolved_questions"].append(f"cycle_{cycle}: low-info revisit")

    state.world_model_digest = orch.world_model.entity_count and str(orch.world_model.entity_count)

    # Check if promotable finding exists → terminal.
    if any(f.get("state") == "supported" for f in state.findings.values()):
        state.mark_terminal("promotable_finding_found")
    elif cycle >= state.budget.get("max_cycles", 5) - 1:
        state.mark_terminal("max_cycles_reached")

    persist_campaign_state(state, state_file)
    print(json.dumps({
        "cycle": cycle, "selected": selected, "outcome": outcome_class,
        "info_value": info_val, "decisions_total": len(state.decisions),
        "outcomes_total": len(state.outcomes), "terminal": state.terminal_state,
        "process_pid": __import__("os").getpid(),
    }))


if __name__ == "__main__":
    main()
