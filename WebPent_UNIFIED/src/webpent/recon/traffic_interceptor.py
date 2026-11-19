from __future__ import annotations

import hashlib
import json
import time
from dataclasses import dataclass, field

from playwright.sync_api import Page

from webpent.shared.untrusted_content import wrap_target_content


def dg(x):return hashlib.sha256(str(x).encode('utf8','replace')).hexdigest()[:16]
def hdr(h):
    sensitive=('authorization','cookie','token','secret','password','api-key')
    return {str(k).lower():({'masked':True,'digest':dg(v),'length':len(str(v))} if any(x in str(k).lower() for x in sensitive) else str(v)[:200]) for k,v in (h or {}).items()}
def shape(x):
    try:v=json.loads(x or '')
    except Exception:return {'json':False,'length':len(x or '')}
    return {'json':True,'type':'object','keys':sorted(map(str,v))[:50]} if isinstance(v,dict) else {'json':True,'type':type(v).__name__}
@dataclass
class TrafficEvent:
    event_id:str;kind:str;timestamp:float;url:str;method:str='';resource_type:str='';from_page:str='';request_headers:dict=field(default_factory=dict);response_status:int|None=None;response_content:dict=field(default_factory=dict);_script:str=field(default='',repr=False)
    def as_dict(self):return {k:v for k,v in self.__dict__.items() if not k.startswith('_')}
class TrafficInterceptor:
    def __init__(self,*,max_events=2000,max_body_bytes=500000):self.max_events=max_events;self.max_body_bytes=max_body_bytes;self.events=[];self.n=0
    def attach(self,page:Page,*,page_label=''):
        page.on('request',lambda r:self._req(r,page_label));page.on('response',lambda r:self._resp(r,page_label))
    def _req(self,r,page_label=''):
        self.n+=1;self.events.append(TrafficEvent(f't_{self.n:05d}','request',time.time(),r.url,r.method,r.resource_type,page_label,request_headers=hdr(r.headers)))
    def _resp(self,r,page_label):
        self.n+=1;body=''
        try:body=r.body()[:self.max_body_bytes].decode('utf8','replace')
        except Exception:pass
        w=wrap_target_content(body,source='browser_response',headers=r.headers,status_code=r.status,content_type=r.headers.get('content-type',''));self.events.append(TrafficEvent(f't_{self.n:05d}','response',time.time(),r.url,r.request.method,r.request.resource_type,page_label, hdr(r.request.headers),r.status,{'placeholder':w.placeholder,'digest':w.raw_digest,'length':w.raw_length,'summary':w.summary,'json_shape':shape(body)},body if 'javascript' in r.headers.get('content-type','').lower() or r.request.resource_type=='script' else ''))
        self.events=self.events[-self.max_events:]
    def javascript_sources(self):return [(e.url,e._script) for e in self.events if e._script]
    def as_dict(self):return {'events':[e.as_dict() for e in self.events],'count':len(self.events),'javascript_count':len(self.javascript_sources())}
