from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field


def dg(x):return hashlib.sha256(json.dumps(x,sort_keys=True,default=str).encode()).hexdigest()[:16]
@dataclass
class StateNode:
    node_id:str;url:str;title:str='';forms:list[dict]=field(default_factory=list);links:list[str]=field(default_factory=list);api_calls:list[str]=field(default_factory=list);auth_required:bool=False;tech_detected:list[str]=field(default_factory=list);interesting_params:list[str]=field(default_factory=list);cookies_set:list[str]=field(default_factory=list);principal_alias:str='anonymous'
    def as_dict(self):return {'id':self.node_id,'url':self.url,'title':self.title[:200],'forms':self.forms[:40],'links':self.links[:80],'api_calls':self.api_calls[:80],'auth_required':self.auth_required,'tech_detected':self.tech_detected[:30],'interesting_params':self.interesting_params[:80],'cookies_set':self.cookies_set[:30],'principal_alias':self.principal_alias}
@dataclass(frozen=True)
class StateTransition:
    action:str;from_node:str;to_node:str;evidence_digest:str='';metadata:dict=field(default_factory=dict)
    def as_dict(self):return {'action':self.action,'from':self.from_node,'to':self.to_node,'evidence_digest':self.evidence_digest,'metadata':self.metadata}
@dataclass
class StateGraph:
    campaign_id:str;target_host:str;nodes:dict[str,StateNode]=field(default_factory=dict);transitions:list[StateTransition]=field(default_factory=list)
    def node_id_for(self,url,principal_alias='anonymous'):return 'page_'+dg({'url':url,'principal':principal_alias})
    def upsert_node(self,*,url,principal_alias='anonymous',title='',forms=(),links=(),api_calls=(),auth_required=False,tech_detected=(),interesting_params=(),cookies_set=()):
        i=self.node_id_for(url,principal_alias);n=self.nodes.setdefault(i,StateNode(i,url,principal_alias=principal_alias));n.title=title or n.title;n.auth_required|=bool(auth_required)
        for a,vals in [('links',links),('api_calls',api_calls),('tech_detected',tech_detected),('interesting_params',interesting_params),('cookies_set',cookies_set)]:
            q=getattr(n,a)
            for v in vals:
                if str(v)[:512] and str(v)[:512] not in q:q.append(str(v)[:512])
            setattr(n,a,q[:100])
        for x in forms:
            if isinstance(x,dict) and x not in n.forms:n.forms.append(x)
        return n
    def add_transition(self,*,action,from_node,to_node,evidence=None,metadata=None):self.transitions.append(StateTransition(str(action)[:80],from_node,to_node,dg(evidence) if evidence is not None else '',dict(metadata or {})))
    def api_endpoints(self):return sorted({x for n in self.nodes.values() for x in n.api_calls})
    def pages_with_forms(self):return [n for n in self.nodes.values() if n.forms]
    def auth_flows(self):return [x for x in self.transitions if 'auth' in x.action.lower() or 'login' in x.action.lower()]
    def as_dict(self):return {'campaign_id':self.campaign_id,'target_host':self.target_host,'nodes':[x.as_dict() for x in self.nodes.values()],'transitions':[x.as_dict() for x in self.transitions],'stats':{'nodes':len(self.nodes),'transitions':len(self.transitions),'api_endpoints':len(self.api_endpoints()),'forms':len(self.pages_with_forms())}}
    def to_markdown(self):return '# StateGraph\n\n'+json.dumps(self.as_dict(),indent=2,sort_keys=True)+'\n'
