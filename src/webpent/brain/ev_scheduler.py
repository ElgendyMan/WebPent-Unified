"""webpent.brain.ev_scheduler — U-11 S-1 The Expected-Value Scheduler."""
from __future__ import annotations
from typing import Any
FAMILY_BASE_RATES = {"IDOR":0.35,"BOLA":0.30,"XSS":0.45,"SQLI":0.40,"SSRF":0.25,"SSTI":0.20,"LFI":0.15,"PATH_TRAVERSAL":0.15,"COMMAND_INJECTION":0.10,"XXE":0.10,"RFI":0.08,"OPEN_REDIRECT":0.20,"INFO_DISCLOSURE":0.30}
FAMILY_IMPACT = {"IDOR":7.5,"BOLA":7.5,"XSS":6.1,"SQLI":9.8,"SSRF":9.1,"SSTI":9.8,"LFI":7.5,"PATH_TRAVERSAL":7.5,"COMMAND_INJECTION":9.8,"XXE":9.1,"RFI":9.8,"OPEN_REDIRECT":4.3,"INFO_DISCLOSURE":5.3}
CHAIN_STANDALONE = 1.0; REQUEST_WEIGHT = 1.0; LLM_WEIGHT = 5.0; STARVATION_FLOOR = 5
class EVScheduler:
    STARVATION_FLOOR = STARVATION_FLOOR
    def _compute_ev(self, h):
        vc = h.get("vulnerability_class","INFO_DISCLOSURE").upper()
        p = FAMILY_BASE_RATES.get(vc,0.1) * h.get("recon_signal_matches",1) * h.get("lesson_priors",1.0)
        impact = FAMILY_IMPACT.get(vc,5.0); chain = h.get("chain_potential",CHAIN_STANDALONE)
        cost = h.get("estimated_cost",10)*REQUEST_WEIGHT + h.get("estimated_llm_calls",0)*LLM_WEIGHT
        return (p*impact*chain)/max(cost,1)
    def rank(self, hypotheses):
        ranked = [{**h, "ev": self._compute_ev(h)} for h in hypotheses]
        ranked.sort(key=lambda x: (-x["ev"], x.get("id","")))
        return ranked
    def allocate_budget(self, ranked, total_budget):
        if not ranked: return []
        n = len(ranked); floor_total = n*self.STARVATION_FLOOR
        if floor_total >= total_budget:
            # P1-05 (0.33.0): the floor path used to grant the floor (or 1)
            # to EVERY hypothesis, over-allocating past the caller's cap
            # (total_budget=3 across 10 hypotheses granted a sum of 10).
            # Honest triage instead: the top total_budget // STARVATION_FLOOR
            # EV-ranked hypotheses (at least one, capped at the budget) get
            # the floor; the rest get zero and simply do not run this round.
            winners = max(1, total_budget // self.STARVATION_FLOOR)
            grant = min(self.STARVATION_FLOOR, total_budget)
            return [{"hypothesis_id": h["id"],
                     "budget": grant if i < winners else 0,
                     "ev": h["ev"]} for i, h in enumerate(ranked)]
        remaining = total_budget - floor_total; total_ev = sum(h["ev"] for h in ranked) or 1.0
        return [{"hypothesis_id":h["id"],"budget":self.STARVATION_FLOOR+int(remaining*(h["ev"]/total_ev)),"ev":h["ev"]} for h in ranked]
    def update_base_rate(self, vuln_class, outcomes, successes):
        vc = vuln_class.upper(); old = FAMILY_BASE_RATES.get(vc,0.1)
        if outcomes == 0: return old
        observed = successes/outcomes; weight = min(0.3, 0.1*outcomes)
        new = old*(1-weight) + observed*weight; FAMILY_BASE_RATES[vc] = new; return new
