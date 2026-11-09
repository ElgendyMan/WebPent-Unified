"""TEAM-2 PHASE 4 — Independent 100-decision campaign (fresh runtime evidence).

4 real HTTP targets (2 REST + 2 GraphQL), 6 vulnerability families as ground
truth, multiple actors, ownership boundaries, negative controls on every
hypothesis, 25 decisions per target through the PRODUCTION dispatch path
(ModernOrchestrator.run_autonomous_validation_campaign). Every decision is
recorded individually — no summary-only numbers.
"""
from __future__ import annotations

import json
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from team2_common import (  # noqa: E402
    T2_TARGETS,
    run_t2_target_campaign,
    save_json,
    utc,
)


def outcome_signature(dec: dict) -> dict:
    """Logical, reproducible outcome vector for one decision (timestamps/UUIDs
    and seal digests excluded)."""
    prom = dec.get("promotion", {})
    sel = dec.get("selection", {})
    rr = dec.get("replay_result", {})
    wm = dec.get("world_model_delta") or {}
    otu = dec.get("outcome_tracker_update") or {}
    return {
        "hypothesis_id": dec.get("hypothesis_id"),
        "vulnerability_class": dec.get("vulnerability_class"),
        "api_type": dec.get("api_type"),
        "real_http_executed": dec.get("real_http_executed"),
        "validator_outcome": dec.get("validator_outcome"),
        "evidence_quality": dec.get("evidence_quality"),
        "identity_bound": dec.get("identity_bound"),
        "identity_bound_reason": dec.get("identity_bound_reason"),
        "actor_id": dec.get("actor_id"),
        "resource_id": dec.get("resource_id"),
        "promotion_decision": prom.get("decision"),
        "promotion_reason": prom.get("reason"),
        "gates_passed": sorted(prom.get("gates_passed") or []),
        "gates_failed": sorted(prom.get("gates_failed") or []),
        "replay_verified": dec.get("replay_verified"),
        "replay_digests_match": rr.get("digests_match"),
        "replay_outcome_match": rr.get("outcome_match"),
        "replay_seal_verified": rr.get("seal_verified"),
        "replay_semantic_match": rr.get("semantic_match"),
        "selection_selected": sel.get("selected"),
        "selection_score": sel.get("selected_candidate_score"),
        "runner_up_ids": [r.get("hypothesis_id") for r in (sel.get("rejected_candidates") or [])],
        "runner_up_scores": [r.get("score") for r in (sel.get("rejected_candidates") or [])],
        "proof_bundle_created": (dec.get("proof_result") or {}).get("bundle_created"),
        "proof_sealed": (dec.get("proof_result") or {}).get("sealed"),
        "world_model_updated": bool(wm.get("updated")),
        "world_model_entities_delta": wm.get("entities_delta"),
        "world_model_relations_delta": wm.get("relations_delta"),
        "outcome_tracker_recorded": bool(otu),
        "outcome_tracker_class": otu.get("outcome_class"),
        "t2_expected_promotable": (dec.get("t2_ground_truth") or {}).get("t2_expected_promotable"),
        "family_in_target_vulnerable_set": (dec.get("t2_ground_truth") or {}).get(
            "family_in_target_vulnerable_set"),
    }


def main() -> dict:
    started = time.time()
    ev = {
        "phase": "PHASE_4_100_DECISION_CAMPAIGN",
        "captured_at": utc(),
        "validator": "TEAM-2 independent validation",
        "production_dispatch": "ModernOrchestrator.run_autonomous_validation_campaign",
        "campaign_design": {
            "targets": [
                {"target_id": t["target_id"], "api_type": t["api_type"],
                 "vulnerable_families_ground_truth": sorted(t["vulnerable"])}
                for t in T2_TARGETS
            ],
            "decisions_per_target": 25,
            "decision_target": 100,
            "coverage": {
                "rest_targets": 2, "graphql_targets": 2,
                "families_as_ground_truth": ["IDOR", "SSRF", "AUTH_BYPASS",
                                             "OPEN_REDIRECT", "INFO_DISCLOSURE",
                                             "MASS_ASSIGNMENT"],
                "multiple_actors": ["alice", "bob", "mallory", "eve", "trudy", "oscar"],
                "ownership_boundaries": "cross-actor order/profile access specs",
                "negative_controls": "every hypothesis carries an explicit negative_control request",
            },
            "independence_note": ("target mixes, actor rotation and hypothesis variants are "
                                  "TEAM-2's own design, independent of TEAM-1's campaign"),
        },
        "targets": [],
    }

    all_decisions = []
    for spec in T2_TARGETS:
        t0 = time.time()
        camp = run_t2_target_campaign(spec, run_tag="t2run1", max_decisions=25)
        dur = round(time.time() - t0, 2)
        sr = camp.get("security_report", {})
        # Verify every promoted finding carries the complete trace contract.
        missing = []
        for f in sr.get("promoted_findings", []):
            tr = f.get("proof_trace") or {}
            for field in ("actor_identity", "resource_identity", "authorization_context",
                          "baseline_result", "candidate_result", "negative_control",
                          "causal_difference", "proof_seal", "replay_verification"):
                if field not in tr:
                    missing.append({"finding_id": f.get("finding_id"), "missing": field})
        ev["targets"].append({
            "target_id": camp["target_id"],
            "api_type": camp["api_type"],
            "vulnerable_families_ground_truth": camp["vulnerable_families_ground_truth"],
            "decisions_executed": camp["decisions_executed"],
            "promoted_count": camp["promoted_count"],
            "rejected_count": camp["rejected_count"],
            "trace_full_coverage": (camp.get("trace") or {}).get("full_coverage"),
            "trace_chain_verified": (camp.get("trace") or {}).get("chain_verified"),
            "security_report_promoted": sr.get("promoted_count"),
            "security_report_trace_contract": sr.get("trace_contract"),
            "all_promoted_have_complete_trace": not missing,
            "duration_seconds": dur,
        })
        all_decisions.extend(camp["decisions"])

    ev["decisions"] = all_decisions
    ev["outcome_signatures"] = [
        {"decision_index": i, **outcome_signature(d)} for i, d in enumerate(all_decisions)]

    # ---- Aggregate honesty metrics ----
    promoted = [d for d in all_decisions if d.get("promotion", {}).get("decision") == "PROMOTED"]
    per_family = {}
    for d in all_decisions:
        fam = d.get("vulnerability_class")
        pf = per_family.setdefault(fam, {"decisions": 0, "promoted": 0, "identity_bound": 0})
        pf["decisions"] += 1
        pf["promoted"] += int(d.get("promotion", {}).get("decision") == "PROMOTED")
        pf["identity_bound"] += int(bool(d.get("identity_bound")))
    gt_vuln_promoted = sum(1 for d in promoted
                           if (d.get("t2_ground_truth") or {}).get("family_in_target_vulnerable_set"))
    gt_patched_promoted = len(promoted) - gt_vuln_promoted
    ev["totals"] = {
        "decisions_executed": len(all_decisions),
        "promoted_count": len(promoted),
        "rejected_count": sum(1 for d in all_decisions
                              if d.get("promotion", {}).get("decision") == "REJECTED"),
        "identity_bound_true": sum(1 for d in all_decisions if d.get("identity_bound")),
        "replay_verified_true": sum(1 for d in all_decisions if d.get("replay_verified")),
        "real_http_executed_true": sum(1 for d in all_decisions if d.get("real_http_executed")),
        "world_model_updated": sum(1 for d in all_decisions
                                   if (d.get("world_model_delta") or {}).get("updated")),
        "outcome_tracker_updates": sum(1 for d in all_decisions if d.get("outcome_tracker_update")),
        "promotions_on_vulnerable_families": gt_vuln_promoted,
        "promotions_on_patched_families_FALSE_POSITIVES": gt_patched_promoted,
        "validator_outcomes": {
            k: sum(1 for d in all_decisions if d.get("validator_outcome") == k)
            for k in ("CONFIRMED", "REFUTED", "INCONCLUSIVE")},
        "per_family": per_family,
    }
    ev["trace_contract_audit"] = {
        "contract": "security_report_trace_contract_v1_2",
        "all_targets_all_promoted_have_complete_trace":
            all(t["all_promoted_have_complete_trace"] for t in ev["targets"]),
        "all_campaigns_full_trace_coverage":
            all(t["trace_full_coverage"] for t in ev["targets"]),
        "all_chains_verified": all(t["trace_chain_verified"] for t in ev["targets"]),
    }
    dur = time.time() - started
    ev["wall_clock_seconds"] = round(dur, 1)
    path = save_json("team2_phase4_campaign_run1.json", ev)
    print(json.dumps({
        "decisions": ev["totals"]["decisions_executed"],
        "promoted": ev["totals"]["promoted_count"],
        "rejected": ev["totals"]["rejected_count"],
        "false_positives": ev["totals"]["promotions_on_patched_families_FALSE_POSITIVES"],
        "identity_bound": ev["totals"]["identity_bound_true"],
        "per_family": ev["totals"]["per_family"],
        "trace_audit": ev["trace_contract_audit"],
        "seconds": ev["wall_clock_seconds"],
        "saved": path}, indent=1))
    return ev


if __name__ == "__main__":
    main()
