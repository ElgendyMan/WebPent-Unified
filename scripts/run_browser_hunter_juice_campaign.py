#!/usr/bin/env python3
from __future__ import annotations

import json
import os
import secrets
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT/'src'));TARGET='http://127.0.0.1:3000'
os.environ.setdefault('LLM_ENABLED','true');os.environ.setdefault('OPENAI_MODEL','gpt-5-mini');os.environ.setdefault('WEBPENT_LLM_KEY_POOL_ENABLED','true');os.environ.setdefault('WEBPENT_AUDIT_SECRET_KEY',secrets.token_urlsafe(48));os.environ.setdefault('AUDIT_SECRET_KEY',os.environ['WEBPENT_AUDIT_SECRET_KEY']);os.environ.setdefault('CELERY_PAYLOAD_KEY',secrets.token_urlsafe(48));os.environ.setdefault('WEBPENT_CELERY_PAYLOAD_KEY',os.environ['CELERY_PAYLOAD_KEY'])
def put(p,v):p.write_text(json.dumps(v,indent=2,sort_keys=True,default=str)+'\n',encoding='utf8')
def browser_phase(cid,out):
    from webpent.recon.browser_crawler import BrowserCrawlConfig, BrowserCrawler
    from webpent.recon.browser_farm import BrowserFarm, BrowserFarmConfig
    from webpent.recon.js_analyzer import analyze_javascript
    iso=BrowserFarm(config=BrowserFarmConfig(max_browsers=1,navigation_interval_seconds=0));a=iso.new_page(cid+'-iso','owner');b=iso.new_page(cid+'-iso','foreign');isolation=a.context is not b.context;iso.close_all();put(out/'browser_context_isolation.json',{'isolated':isolation,'contexts':2})
    farm=BrowserFarm(config=BrowserFarmConfig(max_browsers=2,navigation_interval_seconds=2));r=BrowserCrawler(farm=farm,config=BrowserCrawlConfig(max_pages=10,max_depth=1,max_wall_time_seconds=120)).crawl(campaign_id=cid,target_url=TARGET);put(out/'browser_crawl_summary.json',{'pages_visited':r.pages_visited,'stop_reason':r.stop_reason,'duration_seconds':round((r.completed_at or time.time())-r.started_at,3),'browser_metrics':r.browser_metrics});put(out/'browser_state_graph.json',r.state_graph.as_dict());(out/'browser_state_graph.md').write_text(r.state_graph.to_markdown());put(out/'browser_js_analysis.json',r.js_analysis.as_dict());(out/'browser_traffic.json',r.traffic.as_dict());js=r.js_analysis.as_dict();g=r.state_graph.as_dict();return {'state_graph_stats':g['stats'],'state_nodes':g['nodes'][:30],'api_endpoints':r.state_graph.api_endpoints()[:100],'auth_flows':[x.as_dict() for x in r.state_graph.auth_flows()[:20]],'js_endpoints':js['endpoints_found'][:100],'hidden_routes':js['hidden_routes'][:50],'tech_stack':js['tech_stack'][:30],'traffic_stats':{'events':len(r.traffic.events),'javascript_bundles':len(r.traffic.javascript_sources())}}
def main():
    cid='browser-hunter-juice-'+datetime.now(timezone.utc).strftime('%Y%m%dt%H%M%SZ').lower();out=ROOT/'artifacts'/cid;out.mkdir(parents=True)
    with ThreadPoolExecutor(max_workers=1) as ex:projection=ex.submit(browser_phase,cid,out).result()
    from webpent.agents.hunter_runner import run_hunter_campaign
    from webpent.config.settings import get_settings
    from webpent.recon.autonomous_crawler import CrawlConfig
    get_settings.cache_clear();result=run_hunter_campaign(target_url=TARGET,engagement_id=cid,persona='stok',artifact_root=out,max_hypotheses=20,max_decisions=10,principal_count=0,max_llm_calls=36,max_cost_usd=5.0,crawl_config=CrawlConfig(max_pages=35,max_depth=2,per_host_min_interval_seconds=1.0,request_timeout_seconds=8.0),browser_intelligence=projection);summary=dict(result['summary']);b=json.loads((out/'browser_crawl_summary.json').read_text());g=json.loads((out/'browser_state_graph.json').read_text());j=json.loads((out/'browser_js_analysis.json').read_text());traffic_path=out/'browser_traffic.json';t=json.loads(traffic_path.read_text()) if traffic_path.exists() else {'events':[]};summary['browser_crawl']={'pages_visited':b['pages_visited'],'state_graph_nodes':len(g['nodes']),'state_graph_transitions':len(g['transitions']),'traffic_events':len(t['events']),'js_bundles':j['bundles_analyzed'],'js_endpoints':len(j['endpoints_found']),'hidden_routes':len(j['hidden_routes']),'stop_reason':b['stop_reason']};put(out/'campaign_summary.json',summary);print(json.dumps({'artifact_root':str(out),'summary':summary},indent=2,sort_keys=True));return 0
if __name__=='__main__':raise SystemExit(main())
