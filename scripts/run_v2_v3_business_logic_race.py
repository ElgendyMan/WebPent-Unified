#!/usr/bin/env python3
"""V-2 + V-3 — THE BUSINESS LOGIC ENGINE + THE RACE CONDITION ENGINE
(TC-3, Dispatch #041 §2).  DoD runner.

V-2 (the State Machine Inferrer):
  * the inferrer probes the checkout flow through AUTHORIZED spine
    requests, builds the state diagram
    (START->CART->COUPON_APPLIED->PAID) and re-runs the expected flow on
    an independent cart (the SEQUENTIAL CONTROL).
  * the generated hypotheses (R2 value-manipulation: client-trusted
    price; R1 transition-replay: coupon stacking) go through the FULL
    spine (fresh engagement per leg) -> CONFIRMED -> PROMOTED.
  * the patched lane REFUTES both (price table enforced / single-use
    coupon) — the honest negatives.

V-3 (the Parallel Request Orchestrator):
  * the barrier-synchronized single-packet burst vs the sequential
    control against the genuinely racy single-use redemption surface —
    the differential IS the evidence.
  * a RACE_CONDITION hypothesis through the FULL spine (the AVI's bounded
    burst path — concurrency at the caller layer, never bypassing the
    boundary) -> CONFIRMED -> PROMOTED; the patched lane (atomic lock)
    REFUTES it.
"""
from __future__ import annotations

import json
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT))

from tests.lab.lcs2_sweep_support import ensure_runtime_env  # noqa: E402

ensure_runtime_env()

from webpent.shared.engagement_scope import (  # noqa: E402
    clear_engagement_target_hosts,
)

OUT = ROOT.parent / "download" / "vision_v2_v3"
OUT.mkdir(parents=True, exist_ok=True)
NOW = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
log_lines: list[str] = []


def log(msg: str) -> None:
    print(msg)
    log_lines.append(msg)


def _run_decision(engagement_id: str, url: str, hyp: dict) -> dict:
    """One AVI decision through the AUTHORIZED factory path."""
    from tests.lab.lcs2_sweep_support import (
        make_orchestrator, seal_principals, stages_delta,
    )
    from webpent.production.autonomous_validation_v1 import (
        AutonomousValidationIntelligence,
    )

    orch = make_orchestrator(engagement_id, url)
    seal_principals(engagement_id, url)
    orch.run_deep_recon(target_url=url, observed=[
        {"path": "/api/", "method": "POST", "status_code": 200,
         "body": "{}", "headers": {}}])
    avi = AutonomousValidationIntelligence(orch)
    cursor = len(avi.trace.stages)
    avi._run_one_decision(target_url=url, hypotheses=[hyp], decision_number=1)
    v_proof, p_proof = stages_delta(avi.trace.stages[cursor:])
    return {"validator_outcome": (v_proof or {}).get("outcome"),
            "promotion_decision": ((p_proof or {}).get("decision") or "").upper(),
            "gates_failed": (p_proof or {}).get("gates_failed") or [],
            "discriminating_signal": (v_proof or {}).get("discriminating_signal")}


def run_v2(vulnerable_url: str, patched_url: str) -> dict:
    from webpent.production.business_logic_inferrer import BusinessLogicInferrer
    from tests.lab.lcs2_sweep_support import allow_loopback, make_orchestrator

    tok = allow_loopback()
    try:
        orch = make_orchestrator("v2_probe", vulnerable_url)
        inferrer = BusinessLogicInferrer(orchestrator=orch)
        diagram = inferrer.observe_flow(vulnerable_url)
        log(f"  [V2] diagram: {json.dumps(diagram.to_dict())}")
        log(f"  [V2] sequential control: {json.dumps(inferrer.sequential_control)}")
        hyps = inferrer.generate_hypotheses(engagement_id="v2")
        log(f"  [V2] hypotheses generated: "
            f"{[h['id'] + ':' + h['business_logic_metadata']['rule'] for h in hyps]}")
        results = {}
        for hyp in hyps:
            eng = f"v2_{hyp['business_logic_metadata']['rule'][:2].lower()}"
            res = _run_decision(eng, vulnerable_url, hyp)
            results[hyp["id"]] = res
            log(f"  [V2] {hyp['id']}: validator={res['validator_outcome']} "
                f"promotion={res['promotion_decision']} "
                f"gates_failed={res['gates_failed']} "
                f"signal={res['discriminating_signal']}")
        # the honest negatives: the SAME hypotheses on the PATCHED lane
        neg = {}
        for hyp in hyps:
            neg_hyp = json.loads(json.dumps(hyp))
            neg_hyp["engagement_id"] = "v2_neg"
            res = _run_decision("v2_neg", patched_url, neg_hyp)
            neg[hyp["id"]] = res
            log(f"  [V2-neg] {hyp['id']} on PATCHED lane: "
                f"validator={res['validator_outcome']} "
                f"promotion={res['promotion_decision']}")
        return {"diagram": diagram.to_dict(),
                "sequential_control": inferrer.sequential_control,
                "hypotheses": [h["id"] for h in hyps],
                "results": results, "patched_lane_results": neg}
    finally:
        clear_engagement_target_hosts(tok)


def run_v3(vulnerable_url: str, patched_url: str) -> dict:
    from webpent.production.parallel_orchestrator import (
        ParallelRequestOrchestrator,
    )
    from tests.lab.lcs2_sweep_support import allow_loopback, make_orchestrator

    tok = allow_loopback()
    try:
        # -- the single-packet differential (the evidence) -------------------
        orch = make_orchestrator("v3_orch", vulnerable_url)
        pro = ParallelRequestOrchestrator(orch.execute_real_request)
        headers = {"Content-Type": "application/json"}
        seq_body = json.dumps({"code": "RACE-SEQ-1"}, sort_keys=True)
        seq = pro.sequential(n=5, url=f"{vulnerable_url}/api/redeem",
                             method="POST", headers=headers, body=seq_body)
        seq_ok = sum(1 for r in seq
                     if 200 <= int(r.get("status_code") or 0) < 300)
        par_body = json.dumps({"code": "RACE-PAR-1"}, sort_keys=True)
        par = pro.burst(n=5, url=f"{vulnerable_url}/api/redeem",
                        method="POST", headers=headers, body=par_body)
        par_ok = sum(1 for r in par
                     if 200 <= int(r.get("status_code") or 0) < 300)
        differential = {"sequential_attempts": len(seq),
                        "sequential_successes": seq_ok,
                        "parallel_attempts": len(par),
                        "parallel_successes": par_ok,
                        "over_accepted_under_parallelism": par_ok > 1,
                        "bound_honoured_sequentially": seq_ok == 1,
                        "note": "the sequential run is the control; the "
                                "differential under parallelism is the "
                                "evidence"}
        log(f"  [V3] single-packet differential: {json.dumps(differential)}")

        # -- the FULL-CHAIN leg: RACE_CONDITION through the spine ------------
        def _race_hyp(code_base: str, code_cand: str, code_ctrl: str,
                      engagement_id: str) -> dict:
            return {
                "id": f"{engagement_id}_race", "vulnerability_class":
                    "RACE_CONDITION", "api_type": "rest",
                "path": "/api/redeem", "information_value": 0.9,
                "engagement_id": engagement_id,
                "race_metadata": {
                    "pattern": "single_use_redemption",
                    "evidence_contract": "parallel over-acceptance vs the "
                                         "sequential control",
                },
                "requests": {
                    "baseline": {"method": "POST", "path": "/api/redeem",
                                 "headers": headers,
                                 "body": {"code": code_base}},
                    "candidate": {"method": "POST", "path": "/api/redeem",
                                  "headers": headers, "concurrent": True,
                                  "concurrency": 5, "expected_successes": 1,
                                  "body": {"code": code_cand}},
                    "negative_control": {"method": "POST", "path": "/api/redeem",
                                         "headers": headers, "concurrent": True,
                                         "concurrency": 5,
                                         "body": {"code": code_ctrl}},
                }}
        res = _run_decision("v3_race", vulnerable_url,
                            _race_hyp("RACE-BASE-1", "RACE-CAND-1",
                                      "BAD-CTRL-1", "v3_race"))
        log(f"  [V3] FULL CHAIN: validator={res['validator_outcome']} "
            f"promotion={res['promotion_decision']} "
            f"signal={res['discriminating_signal']}")
        neg = _run_decision("v3_race_neg", patched_url,
                            _race_hyp("RACE-BASE-NEG", "RACE-CAND-NEG",
                                      "BAD-CTRL-NEG", "v3_race_neg"))
        log(f"  [V3-neg] PATCHED lane (atomic lock): validator="
            f"{neg['validator_outcome']} promotion={neg['promotion_decision']}")
        return {"differential": differential, "full_chain": res,
                "patched_lane": neg}
    finally:
        clear_engagement_target_hosts(tok)


def main() -> int:
    from tests.lab.business_logic_lab_target import start_business_logic_server

    log(f"=== V-2/V-3 — {NOW} — mode: LAB-FIXTURE (business-logic lane) ===")
    server_v, url_v = start_business_logic_server(vulnerable=True)
    server_p, url_p = start_business_logic_server(vulnerable=False)
    try:
        v2 = run_v2(url_v, url_p)
        v3 = run_v3(url_v, url_p)
    finally:
        server_v.should_exit = True
        server_p.should_exit = True

    v2_confirmed = all(r["promotion_decision"] == "PROMOTED"
                       for r in v2["results"].values())
    v2_refuted = all(r["promotion_decision"] != "PROMOTED"
                     for r in v2["patched_lane_results"].values())
    v3_proven = (v3["full_chain"]["promotion_decision"] == "PROMOTED"
                 and v3["differential"]["over_accepted_under_parallelism"]
                 and v3["differential"]["bound_honoured_sequentially"])
    v3_refuted = v3["patched_lane"]["promotion_decision"] != "PROMOTED"
    verdict = {
        "items": {"V-2": "Business Logic State Machine Inferrer",
                  "V-3": "Parallel Request Orchestrator"},
        "mode": "LAB-FIXTURE (business-logic lane)", "emitted_at": NOW,
        "engagement_ids": ["v2_probe", "v2_r2", "v2_r1", "v2_neg",
                           "v3_orch", "v3_race", "v3_race_neg"],
        "v2": v2, "v3": v3, "cycle_log": log_lines,
        "dod": {
            "v2_inferrer_plus_hypothesis_through_full_chain": v2_confirmed,
            "v2_patched_lane_refutes": v2_refuted,
            "v3_orchestrator_plus_race_through_full_chain": v3_proven,
            "v3_patched_lane_refutes": v3_refuted,
            "v2_satisfied": v2_confirmed and v2_refuted,
            "v3_satisfied": v3_proven and v3_refuted,
        },
    }
    (OUT / "vision_v2_v3_verdict.json").write_text(json.dumps(verdict, indent=2))
    log(f"=== V-2 DoD: {'SATISFIED' if verdict['dod']['v2_satisfied'] else 'NOT SATISFIED'} "
        f"| V-3 DoD: {'SATISFIED' if verdict['dod']['v3_satisfied'] else 'NOT SATISFIED'} ===")
    return 0 if (verdict["dod"]["v2_satisfied"]
                 and verdict["dod"]["v3_satisfied"]) else 1


if __name__ == "__main__":
    raise SystemExit(main())
