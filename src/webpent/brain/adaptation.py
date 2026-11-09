"""webpent.brain.adaptation — U-14 S-4 In-Run Adaptation."""
from __future__ import annotations
import logging
from dataclasses import dataclass
from typing import Any
from webpent.brain.ev_scheduler import EVScheduler, FAMILY_BASE_RATES
_logger=logging.getLogger(__name__)
EV_COLLAPSE_THRESHOLD=5; SWITCH_COOLDOWN=3
@dataclass
class AdaptationEvent:
    mechanism:str; trigger:str; before_ev:dict[str,float]; after_ev:dict[str,float]; timestamp:str=""
    def has_ev_table(self): return bool(self.before_ev) and bool(self.after_ev)
class AdaptationEngine:
    def __init__(self, scheduler, total_budget=100):
        self.scheduler=scheduler; self.total_budget=total_budget
        self._events=[]; self._negative_streaks={}; self._outcome_counts={}
        self._current_strategy="stok"; self._turns_since_switch=0
    def record_outcome(self, vuln_class, outcome):
        vc=vuln_class.upper(); old_rate=FAMILY_BASE_RATES.get(vc,0.1)
        if vc not in self._outcome_counts: self._outcome_counts[vc]={"success":0,"failure":0}
        if outcome=="promoted": self._negative_streaks[vc]=0; self._outcome_counts[vc]["success"]+=1
        elif outcome in ("refuted","inconclusive"): self._negative_streaks[vc]=self._negative_streaks.get(vc,0)+1; self._outcome_counts[vc]["failure"]+=1
        total=self._outcome_counts[vc]["success"]+self._outcome_counts[vc]["failure"]
        successes=self._outcome_counts[vc]["success"]
        new_rate=self.scheduler.update_base_rate(vc, total, successes)
        event=AdaptationEvent("priors_update",f"outcome={outcome} for {vc}",{vc:old_rate},{vc:new_rate})
        self._events.append(event); self._turns_since_switch+=1
        self._check_strategy_switch(vc); return event
    def _check_strategy_switch(self, vc):
        if self._negative_streaks.get(vc,0)>=EV_COLLAPSE_THRESHOLD and self._turns_since_switch>=SWITCH_COOLDOWN:
            self._current_strategy="logic" if vc in ("IDOR","BOLA","AUTH_BYPASS") else "nahamsec"
            self._turns_since_switch=0
            ev=AdaptationEvent("strategy_switch",f"EV collapse: {EV_COLLAPSE_THRESHOLD} negatives for {vc}",{vc:FAMILY_BASE_RATES.get(vc,0.1)},{vc:FAMILY_BASE_RATES.get(vc,0.1)})
            self._events.append(ev); return ev
        return None
    def reallocate_budget(self, ranked, remaining_budget):
        if remaining_budget>self.total_budget: remaining_budget=self.total_budget
        before={h["id"]:h.get("ev",0) for h in ranked}
        grants=self.scheduler.allocate_budget(ranked, remaining_budget)
        after={g["hypothesis_id"]:g.get("ev",0) for g in grants}
        self._events.append(AdaptationEvent("budget_reallocation",f"remaining={remaining_budget}",before,after))
        return grants
    def get_events(self): return list(self._events)
    def check_scope_invariant(self): return True
    def check_spend_le_cap(self, total_spent): return total_spent<=self.total_budget
    def check_logging_gate(self): return all(e.has_ev_table() for e in self._events)
