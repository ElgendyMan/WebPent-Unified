from __future__ import annotations

import time
from collections import deque
from dataclasses import dataclass, field
from urllib.parse import parse_qsl, urlencode, urljoin, urlsplit, urlunsplit

from playwright.sync_api import Error as PlaywrightError
from playwright.sync_api import TimeoutError as PlaywrightTimeoutError

from webpent.recon.browser_farm import BrowserFarm
from webpent.recon.js_analyzer import JSAnalysis, analyze_javascript
from webpent.recon.state_graph import StateGraph
from webpent.recon.traffic_interceptor import TrafficInterceptor


_SESSION_TERMINATION_SEGMENTS = frozenset({"logout", "logoff", "signout", "sign-off"})
_PRESENTATION_OR_SESSION_QUERY_KEYS = frozenset({"lang", "language", "locale", "username", "user", "session", "sessionid"})


def _safe_navigation_target(candidate: str, target_url: str) -> bool:
    """Keep browser discovery same-origin and never terminate an active session."""
    try:
        parsed = urlsplit(candidate)
        target = urlsplit(target_url)
        _ = parsed.port
    except (TypeError, ValueError):
        return False
    if (
        parsed.scheme not in {"http", "https"}
        or parsed.hostname is None
        or target.hostname is None
        or parsed.hostname.lower().rstrip(".") != target.hostname.lower().rstrip(".")
        or parsed.port != target.port
        or parsed.username is not None
        or parsed.password is not None
    ):
        return False
    return not any(segment.lower() in _SESSION_TERMINATION_SEGMENTS for segment in parsed.path.split("/") if segment)


def _navigation_state_key(url: str) -> str:
    """Deduplicate SPA views without collapsing functional query parameters."""
    parsed = urlsplit(url)
    if not parsed.fragment:
        return url
    query = [(key, value) for key, value in parse_qsl(parsed.query, keep_blank_values=True) if key.lower() not in _PRESENTATION_OR_SESSION_QUERY_KEYS]
    return urlunsplit((parsed.scheme, parsed.netloc, parsed.path, urlencode(query, doseq=True), parsed.fragment))


@dataclass(frozen=True)
class BrowserCrawlConfig:
    max_pages:int=20;max_depth:int=2;max_wall_time_seconds:float=180;max_links_per_page:int=80;max_events:int=2000;settle_time_ms:int=500
    def __post_init__(self):
        if self.max_pages < 1 or self.max_depth < 0 or self.max_links_per_page < 1 or self.max_events < 1:
            raise ValueError("invalid_browser_crawl_config")
        if self.max_wall_time_seconds < 0 or self.settle_time_ms < 0:
            raise ValueError("invalid_browser_crawl_config")
@dataclass
class BrowserCrawlResult:
    campaign_id:str;target_url:str;state_graph:StateGraph;traffic:TrafficInterceptor;js_analysis:JSAnalysis;pages_visited:int=0;stop_reason:str='';navigation_errors:list[dict]=field(default_factory=list);started_at:float=field(default_factory=time.time);completed_at:float|None=None;browser_metrics:dict=field(default_factory=dict)
    def as_dict(self):return {'campaign_id':self.campaign_id,'target_url':self.target_url,'pages_visited':self.pages_visited,'stop_reason':self.stop_reason,'navigation_errors':self.navigation_errors,'started_at':self.started_at,'completed_at':self.completed_at,'state_graph':self.state_graph.as_dict(),'traffic':self.traffic.as_dict(),'js_analysis':self.js_analysis.as_dict(),'browser_metrics':self.browser_metrics}
class BrowserCrawler:
    def __init__(self,*,farm:BrowserFarm,config:BrowserCrawlConfig|None=None,halt_check=None):self.farm=farm;self.config=config or BrowserCrawlConfig();self.halt_check=halt_check or (lambda _:False)
    def crawl(self,*,campaign_id,target_url,principal_alias='anonymous'):
        if not _safe_navigation_target(target_url, target_url):
            raise ValueError('target_url_must_be_same_origin_http')
        started=time.time();g=StateGraph(campaign_id,urlsplit(target_url).netloc);t=TrafficInterceptor(max_events=self.config.max_events);r=BrowserCrawlResult(campaign_id,target_url,g,t,JSAnalysis(),started_at=started);q=deque([(target_url,0,None)]);seen=set();scheduled={_navigation_state_key(target_url)}
        try:
            while q and r.pages_visited<self.config.max_pages:
                if self.halt_check(campaign_id):r.stop_reason='operator_halt';break
                if time.time()-started>=self.config.max_wall_time_seconds:r.stop_reason='wall_time_limit';break
                # Keep same-origin fragments: client-side routers commonly use
                # them as distinct application states (for example, a lesson
                # or view), even though the HTTP document path is unchanged.
                url,depth,parent=q.popleft()
                state_key=_navigation_state_key(url)
                if state_key in seen or urlsplit(url).netloc!=urlsplit(target_url).netloc:continue
                seen.add(state_key);p=self.farm.new_page(campaign_id,principal_alias,target_hosts={urlsplit(target_url).hostname});label=g.node_id_for(url,principal_alias);t.attach(p,page_label=label)
                try:
                    resp=self.farm.navigate(p,url,campaign_id=campaign_id);r.pages_visited+=1;settle_ms=max(0,min(int(self.config.settle_time_ms),5000));p.wait_for_timeout(settle_ms) if settle_ms else None;links=p.locator('a').evaluate_all("els=>els.map(e=>e.href||'').filter(Boolean).slice(0,80)");forms=p.locator('form').evaluate_all("els=>els.slice(0,40).map(f=>({action:f.action||'',method:(f.method||'GET').toUpperCase(),fields:Array.from(f.querySelectorAll('input,textarea,select')).slice(0,30).map(x=>({name:x.name||x.id||'',type:x.type||''}))}))");api=[f'{e.method} {e.url}' for e in t.events if e.kind=='response' and e.from_page==label and e.resource_type in ('xhr','fetch')];n=g.upsert_node(url=url,principal_alias=principal_alias,title=p.title(),forms=forms,links=links,api_calls=api,auth_required=getattr(resp,'status',200) in (401,403),interesting_params=[x.split('=',1)[0] for x in urlsplit(url).query.split('&') if x])
                    if parent:g.add_transition(action='navigate',from_node=g.node_id_for(parent,principal_alias),to_node=n.node_id,evidence=url)
                    if depth<self.config.max_depth:
                        for candidate in (urljoin(url, link) for link in links[:self.config.max_links_per_page]):
                            child_key=_navigation_state_key(candidate)
                            if _safe_navigation_target(candidate, target_url) and child_key not in seen and child_key not in scheduled:
                                scheduled.add(child_key);q.append((candidate, depth + 1, url))
                except (PlaywrightTimeoutError,PlaywrightError) as e:
                    detail = " ".join(str(e).split())[:240]
                    r.navigation_errors.append({"url": url[:2048], "error_type": type(e).__name__, "detail": detail})
                finally:
                    try:p.close()
                    except Exception:pass
            if not r.stop_reason:r.stop_reason='page_budget_exhausted' if r.pages_visited>=self.config.max_pages else 'queue_exhausted'
        finally:
            r.completed_at = time.time()
            r.browser_metrics = self.farm.metrics()
            # P1-16 (0.33.0): close the campaign BEFORE the fallible
            # js_analysis — the old order ran the analysis first inside the
            # same finally, so an analysis exception skipped close_campaign
            # (leaking the Chromium process) AND replaced the original error.
            self.farm.close_campaign(campaign_id)
            try:
                r.js_analysis = analyze_javascript(
                    t.javascript_sources(),
                    observed_routes=[n.url for n in g.nodes.values()],
                )
            except Exception as exc:
                r.navigation_errors.append({
                    "stage": "js_analysis",
                    "error_type": type(exc).__name__,
                    "detail": " ".join(str(exc).split())[:240],
                })
        return r
