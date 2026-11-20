"""webpent.brain.payload_selector — U-16 S-6 Smart Payload Selection."""
from __future__ import annotations
from dataclasses import dataclass, field
@dataclass
class PayloadEntry:
    payload:str; family:str
    context_tags:list[str]=field(default_factory=list)
    effectiveness:float=0.5; times_used:int=0; times_succeeded:int=0
    def ev(self, context_match=1.0): return self.effectiveness*context_match
class PayloadSelector:
    DEFAULT_K=5
    def __init__(self, k=DEFAULT_K): self.k=k; self._index={}
    def register_payload(self, entry):
        f=entry.family.upper()
        if f not in self._index: self._index[f]=[]
        self._index[f].append(entry)
    def select(self,*,family,context_tags=None):
        f=family.upper(); entries=self._index.get(f,[])
        if not entries: return []
        context_tags=context_tags or []
        scored=[]
        for e in entries:
            if e.context_tags:
                match=sum(1 for t in e.context_tags if t in context_tags)/len(e.context_tags)
            else: match=0.5
            scored.append((e.ev(match),e))
        scored.sort(key=lambda x:(-x[0],x[1].payload))
        return [e for _,e in scored[:self.k]]
    def select_or_refuse(self,*,family,context_tags=None,unranked_list=None):
        if unranked_list is not None: raise ValueError("SPRAY-REFUSAL: selector refuses unranked exhaustive list")
        return self.select(family=family,context_tags=context_tags)
    def record_outcome(self, payload, family, success):
        for e in self._index.get(family.upper(),[]):
            if e.payload==payload:
                e.times_used+=1
                if success: e.times_succeeded+=1
                if e.times_used>0:
                    obs=e.times_succeeded/e.times_used
                    e.effectiveness=e.effectiveness*0.7+obs*0.3
                break
