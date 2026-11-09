"""TEAM-1 AUTONOMOUS RESEARCH LOOP V1 — compact base for Deep Recon integration."""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from typing import Final

from webpent.live_hunter.world_model import (
    EvidenceGraph,
    _utc,
    sanitize_text,
)


class OutcomeClass(str):
    HIGH="high_information"; LOW="low_information"; REDUNDANT="redundant"; LEGITIMATE_REPEAT="legitimate_repeat"

class OutcomeTracker:
    MAX_HISTORY: Final[int]=500
    def __init__(self): self._history=[]; self._by_sig={}
    @property
    def history(self): return tuple(self._history)
    def record_outcome(self,*,experiment_signature,outcome_class,information_value,hypothesis_id,justification=""):
        if len(self._history)>=self.MAX_HISTORY: raise RuntimeError("outcome tracker bounded")
        e={"signature":experiment_signature,"outcome_class":outcome_class,"information_value":float(information_value),
           "hypothesis_id":hypothesis_id,"justification":sanitize_text(justification),"timestamp":_utc()}
        self._history.append(e); self._by_sig.setdefault(experiment_signature,[]).append(outcome_class)
    def outcome_aware_penalty(self,experiment_signature):
        outs=self._by_sig.get(experiment_signature,[])
        if not outs: return 0.0
        pen=0.0
        for o in outs:
            if o==OutcomeClass.REDUNDANT: pen+=0.4
            elif o==OutcomeClass.LOW: pen+=0.15
            elif o==OutcomeClass.HIGH: pen-=0.05
        return min(0.9,max(0.0,pen))
    def is_legitimate_repeat(self,*,signature,distinct_actor=False,distinct_parameter=False,independent_negative_control=False,addresses_open_question=False):
        return any([distinct_actor,distinct_parameter,independent_negative_control,addresses_open_question])

@dataclass(frozen=True)
class CandidateValue:
    candidate_id:str; hypothesis_ids:tuple; base_utility:float; evidence_relevance:float
    unresolved_question_value:float; discrimination_value:float; outcome_aware_penalty:float
    semantic_redundancy:float; exploration_pressure:float; exploitation_value:float; total_value:float
    distinguishes:tuple=(); note:str=""

def _discrimination_value(hypothesis_ids,graph):
    states=[graph.get_hypothesis_state(h) for h in hypothesis_ids]
    states=[s for s in states if s is not None]
    if len(states)<2: return 0.0,()
    competing=[]
    for i,a in enumerate(states):
        for b in states[i+1:]:
            if a.confidence<0.7 and b.confidence<0.7 and a.statement!=b.statement: competing.append((a.hypothesis_id,b.hypothesis_id))
    if not competing: return 0.0,()
    return min(1.0,len(competing)*0.4), tuple(sorted(set(h for p in competing for h in p)))

def compute_candidate_value(*,candidate_id,hypothesis_ids,graph,outcome_tracker,experiment_signature,
                            distinct_actor=False,distinct_parameter=False,independent_negative_control=False,addresses_open_question=False):
    base=0.5; relevant=0; open_q=0
    for hid in hypothesis_ids:
        hs=graph.get_hypothesis_state(hid)
        if hs and hs.confidence<0.7: relevant+=1
        if hs and hs.open_question_count>0: open_q+=hs.open_question_count
    ev_rel=min(1.0,relevant/max(1,len(hypothesis_ids)))*0.8
    uqv=min(1.0,open_q/5.0)*0.6
    disc,distinguishes=_discrimination_value(hypothesis_ids,graph)
    oa=outcome_tracker.outcome_aware_penalty(experiment_signature)
    if outcome_tracker.is_legitimate_repeat(signature=experiment_signature,distinct_actor=distinct_actor,distinct_parameter=distinct_parameter,independent_negative_control=independent_negative_control,addresses_open_question=addresses_open_question):
        oa=oa*0.3
    redundancy=min(1.0,graph.past_experiment_signatures.count(experiment_signature)*0.25)
    ep=0.0; ev=0.0
    for hid in hypothesis_ids:
        hs=graph.get_hypothesis_state(hid)
        if hs: ep=max(ep,hs.exploration_pressure); ev=max(ev,hs.exploitation_value)
    raw=(base+ev_rel+uqv+disc+ev+ep*0.3-oa-redundancy)
    total=round(max(0.0,min(1.0,raw/4.0)),4)
    return CandidateValue(candidate_id=candidate_id,hypothesis_ids=tuple(hypothesis_ids),base_utility=base,
        evidence_relevance=round(ev_rel,4),unresolved_question_value=round(uqv,4),discrimination_value=round(disc,4),
        outcome_aware_penalty=round(oa,4),semantic_redundancy=round(redundancy,4),
        exploration_pressure=round(ep,4),exploitation_value=round(ev,4),total_value=total,
        distinguishes=distinguishes,note=f"distinguishes:{','.join(distinguishes) if distinguishes else 'none'}")

def apply_return_to_exploitation(graph,high_info_branch):
    for hid,hs in graph._hypotheses.items():
        if hs.branch_id!=high_info_branch and hs.saturation_state=="saturated":
            nep=max(0.0,hs.exploration_pressure-0.25); nev=min(1.0,hs.exploitation_value+0.2)
            object.__setattr__(hs,"exploration_pressure",round(nep,4)); object.__setattr__(hs,"exploitation_value",round(nev,4))
            if nep<0.3: object.__setattr__(hs,"saturation_state","active")
            graph._update_log.append({"event":"return_to_exploitation_emergent","hypothesis_id":hid,"trigger_branch":high_info_branch,"timestamp":_utc()})

class ResearchControlLoop:
    # Hard safety bound: campaigns remain bounded even when repeatedly resumed.
    MAX_DECISIONS: Final[int]=100; MAX_CANDIDATES_PER_STEP: Final[int]=20; MAX_LLM_CONTEXT_ENTRIES: Final[int]=30
    def __init__(self,*,engagement_id,graph=None):
        self.engagement_id=engagement_id; self.graph=graph or EvidenceGraph(engagement_id=engagement_id)
        self.outcome_tracker=OutcomeTracker(); self._decision_log=[]; self._candidates={}
        self._decision_count=0; self._last_ranking_sig=""; self.replan_events=[]; self.return_to_exploitation_events=[]
    @property
    def decision_count(self): return self._decision_count
    def register_candidate(self,candidate_id,hypothesis_ids,experiment_signature,**kwargs):
        self._candidates[candidate_id]={"hypothesis_ids":tuple(hypothesis_ids),"signature":experiment_signature,
            **{k:v for k,v in kwargs.items() if k in {"distinct_actor","distinct_parameter","independent_negative_control","addresses_open_question"}}}
    def step(self,*,llm_selection_hint=None):
        if self._decision_count>=self.MAX_DECISIONS: raise RuntimeError("decision limit")
        self._decision_count+=1
        ranked=self._reprioritize()
        context=self.llm_context_projection()
        selected=ranked[0]["candidate_id"] if ranked else None
        if llm_selection_hint and llm_selection_hint in {c["candidate_id"] for c in ranked}: selected=llm_selection_hint
        d={"decision_number":self._decision_count,"selected_candidate":selected,
           "ranking":[{"candidate_id":c["candidate_id"],"value":c["value"].total_value,"hypotheses":list(c["value"].hypothesis_ids)} for c in ranked[:5]],
           "context_projection_bounded":True,"llm_advisory_only":True,"timestamp":_utc()}
        self._decision_log.append(d); return d
    def _reprioritize(self):
        ranked=[]
        for cid,cd in list(self._candidates.items())[:self.MAX_CANDIDATES_PER_STEP]:
            val=compute_candidate_value(candidate_id=cid,hypothesis_ids=cd["hypothesis_ids"],graph=self.graph,
                outcome_tracker=self.outcome_tracker,experiment_signature=cd["signature"],
                distinct_actor=cd.get("distinct_actor",False),distinct_parameter=cd.get("distinct_parameter",False),
                independent_negative_control=cd.get("independent_negative_control",False),addresses_open_question=cd.get("addresses_open_question",False))
            ranked.append({"candidate_id":cid,"value":val})
        ranked.sort(key=lambda x:-x["value"].total_value)
        sig=hashlib.sha256(json.dumps([(r["candidate_id"],r["value"].total_value) for r in ranked],sort_keys=True).encode()).hexdigest()[:16]
        if sig!=self._last_ranking_sig and self._decision_count>0:
            self.replan_events.append({"decision":self._decision_count,"cause":"evidence_driven_reprioritization","timestamp":_utc()})
        self._last_ranking_sig=sig; return ranked
    def record_execution_outcome(self,*,candidate_id,observation_id,hypothesis_id,supports,information_value,outcome_class,experiment_signature):
        self.graph.record_observation_outcome(observation_id=observation_id,hypothesis_id=hypothesis_id,supports=supports,information_value=information_value)
        self.graph.record_experiment(experiment_signature)
        self.outcome_tracker.record_outcome(experiment_signature=experiment_signature,outcome_class=outcome_class,information_value=information_value,hypothesis_id=hypothesis_id)
        hs=self.graph.get_hypothesis_state(hypothesis_id)
        if outcome_class==OutcomeClass.HIGH and hs and hs.branch_id:
            before={hid:(h.exploration_pressure,h.exploitation_value) for hid,h in self.graph._hypotheses.items()}
            apply_return_to_exploitation(self.graph,hs.branch_id)
            for hid,h in self.graph._hypotheses.items():
                if before.get(hid)!=(h.exploration_pressure,h.exploitation_value):
                    self.return_to_exploitation_events.append({"decision":self._decision_count,"hypothesis_id":hid,"trigger_branch":hs.branch_id,"timestamp":_utc()})
    def llm_context_projection(self):
        proj=self.graph.candidate_context_projection(limit=self.MAX_LLM_CONTEXT_ENTRIES)
        out_sum={}
        for e in self.outcome_tracker.history[-10:]: out_sum[e["outcome_class"]]=out_sum.get(e["outcome_class"],0)+1
        proj.update({"portfolio_state":{"exploration_pressure_max":max((h.exploration_pressure for h in self.graph._hypotheses.values()),default=0.0),
            "exploitation_value_max":max((h.exploitation_value for h in self.graph._hypotheses.values()),default=0.0),
            "saturated_branches":[h.branch_id for h in self.graph._hypotheses.values() if h.saturation_state=="saturated"]},
            "outcome_history_summary":out_sum,"replan_count":len(self.replan_events),
            "return_to_exploitation_count":len(self.return_to_exploitation_events),"decision_count":self._decision_count,
            "context_bounded_by":self.MAX_LLM_CONTEXT_ENTRIES})
        return proj
    def long_horizon_metrics(self):
        hyps=list(self.graph._hypotheses.values()); competing=sum(1 for h in hyps if h.confidence<0.7 and h.refutation_count==0)
        branches=set(h.branch_id for h in hyps if h.branch_id); redundant=sum(1 for e in self.outcome_tracker.history if e["outcome_class"]==OutcomeClass.REDUNDANT)
        meaningful=sum(1 for e in self.outcome_tracker.history if e["outcome_class"]==OutcomeClass.HIGH); total=len(self.outcome_tracker.history) or 1
        return {"decision_count":self._decision_count,"hypothesis_count":len(hyps),"competing_hypothesis_count":competing,
            "candidate_diversity":len(set(c["signature"] for c in self._candidates.values())),"branch_diversity":len(branches),
            "meaningful_experiment_rate":round(meaningful/total,4),"redundant_rate":round(redundant/total,4),
            "evidence_driven_replan_count":len(self.replan_events),"return_to_exploitation_events":len(self.return_to_exploitation_events),
            "world_model_growth":{"entities":self.graph.entity_count,"relations":self.graph.relation_count},"bounded":True,"no_infinite_growth":True}

__all__=["OutcomeClass","OutcomeTracker","CandidateValue","compute_candidate_value","apply_return_to_exploitation","ResearchControlLoop"]
