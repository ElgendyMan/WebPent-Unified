from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field

_ENDPOINT=re.compile(r"[\"'`]((?:https?://|/)[^\"'`\s<>]{2,512})[\"'`]")
_SECRET=re.compile(r"(api[_-]?key|secret|token|password)\s*[:=]\s*[\"']([^\"']{8,})[\"']",re.I)
@dataclass
class JSAnalysis:
    bundles_analyzed:int=0;endpoints_found:list[str]=field(default_factory=list);fetch_calls:list[str]=field(default_factory=list);websocket_urls:list[str]=field(default_factory=list);source_maps:list[str]=field(default_factory=list);hidden_routes:list[str]=field(default_factory=list);tech_stack:list[str]=field(default_factory=list);secrets_found:list[dict]=field(default_factory=list);bundle_digests:dict[str,str]=field(default_factory=dict)
    def as_dict(self):return {'bundles_analyzed':self.bundles_analyzed,'endpoints_found':sorted(set(self.endpoints_found))[:300],'fetch_calls':sorted(set(self.fetch_calls))[:100],'websocket_urls':sorted(set(self.websocket_urls))[:100],'source_maps':self.source_maps[:100],'hidden_routes':sorted(set(self.hidden_routes))[:200],'tech_stack':sorted(set(self.tech_stack)),'secrets_found':self.secrets_found[:100],'bundle_digests':self.bundle_digests}
    def to_markdown(self):return '# JavaScript Analysis\n\n'+str(self.as_dict())+'\n'
def analyze_javascript(sources,*,observed_routes=()):
    r=JSAnalysis();seen={str(x).split('?',1)[0] for x in observed_routes}
    for url,text in list(sources)[:100]:
        text=str(text or '')[:2000000];r.bundles_analyzed+=1;r.bundle_digests[str(url)[:1000]]=hashlib.sha256(text.encode('utf8','replace')).hexdigest()[:16]
        for v in _ENDPOINT.findall(text):
            if v.startswith(('ws://','wss://')):r.websocket_urls.append(v)
            else:r.endpoints_found.append(v);r.hidden_routes.append(v) if v.split('?',1)[0] not in seen else None
        for k,v in _SECRET.findall(text):r.secrets_found.append({'type':k.lower(),'value_masked':'[MASKED]','digest':hashlib.sha256(v.encode()).hexdigest()[:16],'length':len(v)})
        if 'sourceMappingURL=' in text:r.source_maps.append('[SOURCE_MAP_REFERENCE]')
        lo=text.lower()
        for t,m in {'Angular':('angular','ng-version'),'React':('react','__next'),'Vue':('vue','data-v-'),'axios':('axios'),'Firebase':('firebase')}.items():
            if any(x in lo for x in m):r.tech_stack.append(t)
    return r
class JSAnalyzer:
    def analyze(self,sources,**kw):return analyze_javascript(sources,**kw)
