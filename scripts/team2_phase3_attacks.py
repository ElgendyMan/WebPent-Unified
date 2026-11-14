"""TEAM-2 PHASE 3 — TEAM-3 regression attack replay (independent re-implementation).

 1. False IDOR on healthy target     -> REFUTED / NOT PROMOTED
 2. Real IDOR                        -> identity_bound=true, PROMOTED
 3. Synthetic observation            -> identity_bound=false, NOT PROMOTED
 4. Missing negative control         -> REJECTED
 5. Replay tampering                 -> REJECTED
 6. Proof tampering                  -> seal verification failure
"""
from __future__ import annotations

import copy
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from team2_common import (  # noqa: E402
    AutonomousValidationIntelligence,
    PromotionPipeline,
    ReplayVerifier,
    SecurityReport,
    build_proof_trace,
    build_t2_hypotheses,
    execute_real_triple,
    make_orchestrator,
    normalize_and_validate,
    save_json,
    start_t2_target,
    utc,
)


def run_one(spec, hyp_filter=None, max_decisions=25):
    srv, url = start_t2_target(spec)
    try:
        orch = make_orchestrator(f"t2_p3_{spec['target_id']}")
        hyps = build_t2_hypotheses(url, spec["api_type"], spec["target_id"])
        if hyp_filter:
            hyps = [h for h in hyps if hyp_filter(h)]
        res = orch.run_autonomous_validation_campaign(
            target_url=url, hypotheses=hyps, max_decisions=max_decisions)
        return res, url, orch
    finally:
        try:
            srv.shutdown()
        except Exception:
            pass


def main() -> dict:
    ev = {"phase": "PHASE_3_REGRESSION_ATTACK_REPLAY", "captured_at": utc(), "attacks": {}}

    # ---- Attack 1: False IDOR on healthy target (IDOR patched) -------------
    spec1 = {"target_id": "rest_healthy", "api_type": "rest", "app": "rest",
             "vulnerable": set()}  # NOTHING vulnerable — healthy target
    res1, _, _ = run_one(spec1, hyp_filter=lambda h: h["vulnerability_class"] == "IDOR")
    idor_decs = [d for d in res1["decisions"] if d.get("vulnerability_class") == "IDOR"]
    a1_promoted = [d for d in idor_decs if d.get("promotion", {}).get("decision") == "PROMOTED"]
    ev["attacks"]["attack_1_false_idor_healthy_target"] = {
        "id": 1, "decisions": len(idor_decs),
        "validator_outcomes": sorted({d.get("validator_outcome") for d in idor_decs}),
        "promoted_count": len(a1_promoted),
        "expected": "REFUTED and NOT PROMOTED",
        "result": "PASS" if (idor_decs and not a1_promoted
                             and all(d.get("validator_outcome") == "REFUTED" for d in idor_decs)) else "FAIL",
    }

    # ---- Attack 2: Real IDOR (vulnerable target) ---------------------------
    spec2 = {"target_id": "rest_idor", "api_type": "rest", "app": "rest",
             "vulnerable": {"IDOR"}}
    res2, _, _ = run_one(spec2, hyp_filter=lambda h: h["vulnerability_class"] == "IDOR")
    idor2 = [d for d in res2["decisions"] if d.get("vulnerability_class") == "IDOR"]
    a2_promoted = [d for d in idor2
                   if d.get("promotion", {}).get("decision") == "PROMOTED"
                   and d.get("identity_bound") is True]
    ev["attacks"]["attack_2_real_idor"] = {
        "id": 2, "decisions": len(idor2),
        "promoted_with_identity_bound": len(a2_promoted),
        "sample_causal_difference": (a2_promoted[0].get("causal_difference") if a2_promoted else None),
        "expected": "identity_bound=true and PROMOTED",
        "result": "PASS" if a2_promoted else "FAIL",
    }

    # ---- Attack 3: Synthetic observation ------------------------------------
    pipeline = PromotionPipeline()
    pr_synth = pipeline.evaluate(
        baseline_obs={"body_fingerprint": "fp", "synthetic": True},
        candidate_obs={"body_fingerprint": "fp2", "synthetic": True},
        negative_control_obs={"body_fingerprint": "fp3", "synthetic": True},
        evidence_origin="synthetic_lab", validator_outcome="CONFIRMED",
        evidence_quality=5, proof_bundle=None, replay_verified=True,
        finding_id="f_synth", vulnerability_class="IDOR")
    # 3b. End-to-end: hypothesis WITHOUT explicit request specs -> identity cannot bind.
    spec3 = {"target_id": "rest_idor_nospec", "api_type": "rest", "app": "rest",
             "vulnerable": {"IDOR"}}
    srv, url3 = start_t2_target(spec3)
    try:
        orch3 = make_orchestrator("t2_p3_nospec")
        hyps3 = build_t2_hypotheses(url3, "rest", spec3["target_id"])
        for h in hyps3:
            h.pop("requests", None)  # strip explicit specs -> synthetic-style observation
        res3 = orch3.run_autonomous_validation_campaign(
            target_url=url3, hypotheses=hyps3, max_decisions=3)
        nospec = res3["decisions"]
    finally:
        try:
            srv.shutdown()
        except Exception:
            pass
    ev["attacks"]["attack_3_synthetic_observation"] = {
        "id": 3,
        "gate_test_decision": pr_synth.decision.value,
        "gate_test_failed_gates": pr_synth.gates_failed,
        "end_to_end_identity_bound": sorted({d.get("identity_bound") for d in nospec}),
        "end_to_end_promoted": sum(1 for d in nospec
                                   if d.get("promotion", {}).get("decision") == "PROMOTED"),
        "identity_bound_reasons": sorted({d.get("identity_bound_reason") for d in nospec
                                          if d.get("identity_bound") is False})[:3],
        "expected": "identity_bound=false and NOT PROMOTED",
        "result": "PASS" if (pr_synth.decision.value == "REJECTED"
                             and "real_runtime_observations" in pr_synth.gates_failed
                             and not any(d.get("promotion", {}).get("decision") == "PROMOTED"
                                         for d in nospec)
                             and all(d.get("identity_bound") is False for d in nospec)) else "FAIL",
    }

    # ---- Attacks 4-6 need a REAL sealed bundle from the production path ----
    spec4 = {"target_id": "rest_idor2", "api_type": "rest", "app": "rest",
             "vulnerable": {"IDOR"}}
    srv, url4 = start_t2_target(spec4)
    try:
        orch4 = make_orchestrator("t2_p3_tamper")
        hyps4 = build_t2_hypotheses(url4, "rest", spec4["target_id"])
        hyp = next(h for h in hyps4 if h["id"] == "t2_rest_idor2_idor_v1")
        raw = execute_real_triple(orch4, base_url=url4, requests=hyp["requests"],
                                  hypothesis_id=hyp["id"])
        b_obs, c_obs, nc_obs, vr = normalize_and_validate(
            orch4, vuln_class="IDOR", raw_triple=raw, hypothesis=hyp, experiment_id="exp_idor")
        avi = AutonomousValidationIntelligence(orch4)
        ib = avi._compute_identity_binding(hypothesis=hyp, vuln_class="IDOR", raw_triple=raw)
        import hashlib
        bundle = avi._build_and_seal_proof(
            hypothesis_id=hyp["id"], vuln_class="IDOR", experiment_id="exp_idor",
            validator_result=vr, baseline_digest=b_obs.digest(),
            candidate_digest=c_obs.digest(), negative_control_digest=nc_obs.digest(),
            target_fingerprint=hashlib.sha256(url4.encode()).hexdigest()[:16],
            identity_binding=ib)

        # ---- Attack 4: Missing negative control -> REJECTED ----
        pr4 = pipeline.evaluate(
            baseline_obs=b_obs, candidate_obs=c_obs, negative_control_obs=None,
            evidence_origin="target_runtime", validator_outcome=vr.outcome.value,
            evidence_quality=int(vr.evidence_quality), proof_bundle=bundle,
            replay_verified=True, finding_id="f_nc", vulnerability_class="IDOR")
        ev["attacks"]["attack_4_missing_negative_control"] = {
            "id": 4, "decision": pr4.decision.value,
            "gates_failed": pr4.gates_failed,
            "expected": "REJECTED via negative_control_present gate",
            "result": "PASS" if (pr4.decision.value == "REJECTED"
                                 and "negative_control_present" in pr4.gates_failed) else "FAIL",
        }

        # ---- Attack 5: Replay tampering -> REJECTED ----
        raw_t = copy.deepcopy(raw)
        raw_t["candidate"]["response_body"] += " TAMPERED"
        rv5 = ReplayVerifier.verify(
            experiment_id="exp_idor", baseline_raw=raw_t["baseline"],
            candidate_raw=raw_t["candidate"], negative_control_raw=raw_t["negative_control"],
            vulnerability_class="IDOR", expected_outcome=vr.outcome.value,
            expected_baseline_digest=b_obs.digest(), expected_candidate_digest=c_obs.digest(),
            expected_negative_control_digest=nc_obs.digest(), proof_bundle=bundle)
        pr5 = pipeline.evaluate(
            baseline_obs=b_obs, candidate_obs=c_obs, negative_control_obs=nc_obs,
            evidence_origin="target_runtime", validator_outcome=vr.outcome.value,
            evidence_quality=int(vr.evidence_quality), proof_bundle=bundle,
            replay_verified=rv5["replay_verified"], finding_id="f_rt",
            vulnerability_class="IDOR")
        ev["attacks"]["attack_5_replay_tampering"] = {
            "id": 5, "replay_verified_after_tamper": rv5["replay_verified"],
            "digests_match": rv5["digests_match"],
            "decision": pr5.decision.value, "gates_failed": pr5.gates_failed,
            "expected": "replay_verified=False and REJECTED",
            "result": "PASS" if (not rv5["replay_verified"]
                                 and pr5.decision.value == "REJECTED") else "FAIL",
        }

        # ---- Attack 6: Proof tampering -> seal verification failure ----
        tampered = copy.deepcopy(bundle)
        tampered.causal_oracle["causal_difference"] = "forged difference"
        seal_ok = bool(tampered.verify_seal())
        pr6 = pipeline.evaluate(
            baseline_obs=b_obs, candidate_obs=c_obs, negative_control_obs=nc_obs,
            evidence_origin="target_runtime", validator_outcome=vr.outcome.value,
            evidence_quality=int(vr.evidence_quality), proof_bundle=tampered,
            replay_verified=True, finding_id="f_pt", vulnerability_class="IDOR")
        trace6 = build_proof_trace(proof_bundle=tampered, replay_result={
            "replay_verified": True, "digests_match": True, "outcome_match": True,
            "seal_verified": True, "semantic_match": True, "replayed_outcome": "CONFIRMED",
            "replay_component": "ReplayVerifier_v1_2_semantic"},
            promotion={"decision": "PROMOTED", "gates_passed": pipeline.GATES,
                       "pipeline": "PromotionPipeline_v1"})
        rep6 = SecurityReport(engagement_id="t2_p3_proof_tamper")
        rep6.add_promoted({"finding_id": "f_pt", "vulnerability_class": "IDOR",
                           "promotion": {"decision": "PROMOTED", "gates_passed": pipeline.GATES,
                                         "gates_failed": [], "pipeline": "PromotionPipeline_v1"},
                           "replay_verified": True, "identity_bound": True,
                           "proof_seal_verified": False, "proof_trace": trace6})
        ev["attacks"]["attack_6_proof_tampering"] = {
            "id": 6, "verify_seal_after_tamper": seal_ok,
            "decision": pr6.decision.value, "gates_failed": pr6.gates_failed,
            "trace_seal_verified": trace6["proof_seal"]["seal_verified"],
            "report_rejected": any("proof_seal" in (f.get("trace_contract_missing") or [])
                                   for f in rep6.rejected_findings),
            "expected": "seal verification failure and REJECTED",
            "result": "PASS" if (not seal_ok and pr6.decision.value == "REJECTED"
                                 and not trace6["proof_seal"]["seal_verified"]) else "FAIL",
        }
    finally:
        try:
            srv.shutdown()
        except Exception:
            pass

    ev["summary"] = {k: v["result"] for k, v in ev["attacks"].items()}
    ev["all_pass"] = all(v == "PASS" for v in ev["summary"].values())
    path = save_json("team2_phase3_regression_attacks.json", ev)
    print(json.dumps({"summary": ev["summary"], "all_pass": ev["all_pass"], "saved": path},
                     indent=1))
    return ev


if __name__ == "__main__":
    main()
