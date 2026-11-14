"""TEAM-1 WORLD MODEL & EVIDENCE GRAPH V1 — compact base."""
from __future__ import annotations

import hashlib
import json
import re
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Final
from uuid import uuid4

SECRET_PATTERNS: Final[tuple]=tuple(re.compile(p,re.IGNORECASE) for p in [
    r"cookie[\"']?\s*[:=]\s*\S+",r"authorization[\"']?\s*[:=]\s*\S+",r"set-cookie[\"']?\s*[:=]\s*\S+",
    r"session[_-]?token[\"']?\s*[:=]\s*\S+",r"session[_-]?id[\"']?\s*[:=]\s*\S+",
    r"password[\"']?\s*[:=]\s*\S+",r"api[_-]?key[\"']?\s*[:=]\s*\S+",
    r"bearer\s+\S+",r"basic\s+[A-Za-z0-9+/=]+",r"token[\"']?\s*[:=]\s*\S+",r"secret[\"']?\s*[:=]\s*\S+",
    r"jwt[\"']?\s*[:=]\s*[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+"])
REDACTED: Final[str]="[REDACTED]"

def sanitize_text(text:str)->str:
    out=str(text or "")
    for p in SECRET_PATTERNS: out=p.sub(REDACTED,out)
    return out
def _sha(t:str)->str: return hashlib.sha256(t.encode()).hexdigest()
def _utc()->str: return datetime.now(timezone.utc).isoformat()
def _uid(p:str)->str: return f"{p}_{uuid4().hex[:12]}"

class EntityType(str,Enum):
    PRINCIPAL="principal";RESOURCE="resource";ACTION="action";PARAMETER="parameter"
    OBSERVATION="observation";HYPOTHESIS="hypothesis";EXPERIMENT="experiment";EVIDENCE="evidence"
class RelationType(str,Enum):
    PRINCIPAL_PERFORMED_ACTION="principal_performed_action";ACTION_TARGETED_RESOURCE="action_targeted_resource"
    ACTION_USED_PARAMETER="action_used_parameter";ACTION_PRODUCED_OBSERVATION="action_produced_observation"
    OBSERVATION_SUPPORTED_HYPOTHESIS="observation_supported_hypothesis";OBSERVATION_REFUTED_HYPOTHESIS="observation_refuted_hypothesis"
    HYPOTHESIS_GENERATED_EXPERIMENT="hypothesis_generated_experiment";EXPERIMENT_PRODUCED_EVIDENCE="experiment_produced_evidence"
    EVIDENCE_CHANGED_PRIORITY="evidence_changed_priority"

@dataclass(frozen=True)
class Entity:
    entity_id:str; entity_type:EntityType; attributes:dict=field(default_factory=dict)
    provenance:str=""; created_at:str=field(default_factory=_utc)
    def digest(self): return _sha(json.dumps({"id":self.entity_id,"t":self.entity_type.value,"a":self.attributes,"p":self.provenance},sort_keys=True))
    def to_sanitized_dict(self):
        return {"entity_id":self.entity_id,"entity_type":self.entity_type.value,
                "attributes":{k:sanitize_text(str(v)) for k,v in self.attributes.items()},"provenance":self.provenance}

@dataclass(frozen=True)
class Relation:
    relation_id:str; relation_type:RelationType; source_id:str; target_id:str
    attributes:dict=field(default_factory=dict); provenance:str="deterministic_recorder"; created_at:str=field(default_factory=_utc)

@dataclass
class HypothesisState:
    hypothesis_id:str; statement:str; support_count:int=0; refutation_count:int=0
    observation_refs:tuple=(); open_question_count:int=0; last_information_value:float=0.0
    confidence:float=0.0; priority:float=0.5; branch_id:str=""
    exploration_pressure:float=0.0; exploitation_value:float=0.5; saturation_state:str="active"
    recent_information_value:float=0.0; last_decision:str=""; created_at:str=field(default_factory=_utc); last_updated_at:str=field(default_factory=_utc)
    def record_support(self,obs_id,info_val):
        if obs_id in self.observation_refs: return
        object.__setattr__(self,"support_count",self.support_count+1)
        object.__setattr__(self,"observation_refs",(*self.observation_refs,obs_id))
        object.__setattr__(self,"last_information_value",float(info_val))
        object.__setattr__(self,"recent_information_value",float(info_val))
        self._recompute()
    def record_refutation(self,obs_id,info_val):
        if obs_id in self.observation_refs: return
        object.__setattr__(self,"refutation_count",self.refutation_count+1)
        object.__setattr__(self,"observation_refs",(*self.observation_refs,obs_id))
        object.__setattr__(self,"last_information_value",float(info_val))
        object.__setattr__(self,"recent_information_value",float(info_val))
        self._recompute()
    def _recompute(self):
        total=self.support_count+self.refutation_count
        conf=self.support_count/total if total else 0.0
        pri=0.2+0.6*(self.support_count/total) if total else 0.5
        object.__setattr__(self,"confidence",round(conf,4)); object.__setattr__(self,"priority",round(pri,4))
        if total>=3 and self.recent_information_value<0.3:
            object.__setattr__(self,"saturation_state","saturated")
            object.__setattr__(self,"exploration_pressure",min(1.0,self.exploration_pressure+0.3))
            object.__setattr__(self,"exploitation_value",max(0.1,self.exploitation_value-0.2))
        elif self.recent_information_value>=0.7:
            object.__setattr__(self,"saturation_state","active")
            object.__setattr__(self,"exploitation_value",min(1.0,self.exploitation_value+0.2))
        object.__setattr__(self,"last_updated_at",_utc())
    def to_dict(self): return asdict(self)

class EvidenceGraph:
    MAX_ENTITIES=10000; MAX_RELATIONS=50000; MAX_HYPOTHESES=1000; MAX_QUESTIONS=200
    def __init__(self,*,engagement_id):
        self.engagement_id=engagement_id; self._entities={}; self._relations=[]
        self._hypotheses={}; self._questions={}; self._experiment_signatures=[]; self._update_log=[]
    @property
    def entity_count(self): return len(self._entities)
    @property
    def relation_count(self): return len(self._relations)
    @property
    def hypothesis_count(self): return len(self._hypotheses)
    def add_entity(self,e):
        if len(self._entities)>=self.MAX_ENTITIES: raise RuntimeError("entity limit")
        if not e.provenance: raise ValueError("provenance required")
        self._entities[e.entity_id]=e; return e.entity_id
    def add_relation(self,r):
        if len(self._relations)>=self.MAX_RELATIONS: raise RuntimeError("relation limit")
        if r.provenance not in {"deterministic_recorder","validated_observation","existing_system","schema_derived"}:
            raise ValueError(f"provenance rejected:{r.provenance} — LLM cannot mutate truth")
        self._relations.append(r); return r.relation_id
    def register_hypothesis(self,hid,statement,branch_id="",proposed_by="llm_advisory"):
        if len(self._hypotheses)>=self.MAX_HYPOTHESES: raise RuntimeError("hypothesis limit")
        if hid in self._hypotheses: return self._hypotheses[hid]
        hs=HypothesisState(hypothesis_id=hid,statement=sanitize_text(statement),branch_id=branch_id)
        self._hypotheses[hid]=hs
        self._update_log.append({"event":"hypothesis_proposed","hypothesis_id":hid,"proposed_by":proposed_by,"timestamp":_utc()})
        return hs
    def record_observation_outcome(self,*,observation_id,hypothesis_id,supports,information_value):
        hs=self._hypotheses.get(hypothesis_id)
        if hs is None: raise ValueError(f"hypothesis not registered:{hypothesis_id}")
        if supports: hs.record_support(observation_id,information_value)
        else: hs.record_refutation(observation_id,information_value)
        rt=RelationType.OBSERVATION_SUPPORTED_HYPOTHESIS if supports else RelationType.OBSERVATION_REFUTED_HYPOTHESIS
        self.add_relation(Relation(_uid("rel"),rt,observation_id,hypothesis_id,{"info_val":float(information_value)},"deterministic_recorder"))
        self.add_relation(Relation(_uid("rel"),RelationType.EVIDENCE_CHANGED_PRIORITY,observation_id,hypothesis_id,{"new_priority":hs.priority},"deterministic_recorder"))
        self._update_log.append({"event":"observation_recorded","obs":observation_id,"hyp":hypothesis_id,"supports":supports,"info":information_value,"new_priority":hs.priority,"timestamp":_utc()})
    def get_hypothesis_state(self,hid): return self._hypotheses.get(hid)
    def register_unresolved_question(self,qid,text,hypothesis_refs=()):
        if len(self._questions)>=self.MAX_QUESTIONS: raise RuntimeError("question limit")
        self._questions[qid]={"question_id":qid,"text":sanitize_text(text),"hypothesis_refs":tuple(hypothesis_refs),"evidence_refs":(),"resolution_status":"open","candidate_refs":()}
        for hid in hypothesis_refs:
            if hid in self._hypotheses: object.__setattr__(self._hypotheses[hid],"open_question_count",self._hypotheses[hid].open_question_count+1)
        return self._questions[qid]
    def record_experiment(self,sig): self._experiment_signatures.append(sig)
    @property
    def past_experiment_signatures(self): return tuple(self._experiment_signatures)
    def candidate_context_projection(self,limit=20):
        hyps=sorted(self._hypotheses.values(),key=lambda h:-h.priority)[:limit]
        open_qs=[q for q in self._questions.values() if q["resolution_status"]=="open"][:10]
        return {"engagement_id":self.engagement_id,
                "hypotheses":[{"id":h.hypothesis_id,"statement":sanitize_text(h.statement),"support":h.support_count,"refutation":h.refutation_count,"confidence":h.confidence,"priority":h.priority,"branch":h.branch_id,"saturation":h.saturation_state,"open_questions":h.open_question_count} for h in hyps],
                "unresolved_questions":[{"id":q["question_id"],"text":q["text"],"hyps":list(q["hypothesis_refs"])} for q in open_qs],
                "refuted_retained":[h.hypothesis_id for h in self._hypotheses.values() if h.refutation_count>0],
                "experiment_count":len(self._experiment_signatures),"entity_count":self.entity_count,"relation_count":self.relation_count,
                "projection_sanitized":True,"secrets_redacted":True}
    def serialize(self):
        return json.dumps({"engagement_id":self.engagement_id,"entities":[e.to_sanitized_dict() for e in self._entities.values()],
                           "relations":[asdict(r) for r in self._relations],"hypotheses":[h.to_dict() for h in self._hypotheses.values()],
                           "questions":list(self._questions.values()),"experiment_signatures":self._experiment_signatures},sort_keys=True)
    def verify_no_secret_leakage(self): return not any(p.search(self.serialize()) for p in SECRET_PATTERNS)

__all__=["Entity","EntityType","Relation","RelationType","HypothesisState","EvidenceGraph","sanitize_text","SECRET_PATTERNS","_utc","_uid"]
