from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any, Callable

from playwright.sync_api import BrowserContext, Page, Playwright, sync_playwright


@dataclass(frozen=True)
class BrowserFarmConfig:
    max_browsers:int=5;headless:bool=True;page_timeout_ms:int=30000;navigation_interval_seconds:float=1.0;max_crash_retries:int=3
    def __post_init__(self):
        if self.max_browsers<1 or self.page_timeout_ms<1 or self.navigation_interval_seconds<0:raise ValueError('invalid_browser_config')
@dataclass
class BrowserRecord:
    browser_id:str;campaign_id:str;context:BrowserContext|None=None;crash_retries:int=0;launched_at:float=field(default_factory=time.time)
class BrowserFarm:
    def __init__(self,*,config:BrowserFarmConfig|None=None,halt_check:Callable[[str],bool]|None=None):self.config=config or BrowserFarmConfig();self.halt_check=halt_check or (lambda _:False);self._pw:Playwright|None=None;self._browsers={};self._records={};self._contexts={};self._pages={};self._last={};self._closed=False
    def _start(self):
        if self._closed:raise RuntimeError('browser_farm_closed')
        if self._pw is None:self._pw=sync_playwright().start()
        return self._pw
    def _record(self,cid):
        for r in self._records.values():
            if r.campaign_id==cid:return r
        if len(self._browsers)>=self.config.max_browsers:raise RuntimeError('browser_budget_exhausted')
        b=self._start().chromium.launch(headless=self.config.headless);bid=f'browser_{len(self._records)+1:03d}';self._browsers[bid]=b;r=BrowserRecord(bid,cid);self._records[bid]=r;return r
    def new_page(self,campaign_id:str,principal_alias='anonymous',*,target_hosts=None)->Page:
        if self.halt_check(campaign_id):raise RuntimeError('campaign_halted_before_browser')
        key=(campaign_id,str(principal_alias));c=self._contexts.get(key)
        if c is None:
            r=self._record(campaign_id);c=self._browsers[r.browser_id].new_context(viewport={'width':1920,'height':1080});c.set_default_timeout(self.config.page_timeout_ms);c.set_default_navigation_timeout(self.config.page_timeout_ms)
            # M1-A (L-1): every Playwright surface gets the SAME network
            # interception guard as the execution sandbox / validator —
            # without it the farm's browser is an SSRF proxy to internal
            # networks (169.254.169.254, redis:, loopback, ...).
            # UM-DR-26 wiring fix: the CAMPAIGN's own target origin rides the
            # allowlist (target_hosts) — a loopback lab target must be
            # navigable by its own crawl, while every other private/reserved
            # host stays blocked exactly as before.
            from webpent.shared.http import install_playwright_ssrf_guard

            install_playwright_ssrf_guard(c, target_hosts=target_hosts)
            self._contexts[key]=c;r.context=c
        p=c.new_page();self._pages[id(p)]=key;return p
    def navigate(self,page,url,*,campaign_id,wait_until='domcontentloaded'):
        if self.halt_check(campaign_id):raise RuntimeError('campaign_halted_before_navigation')
        delay=self.config.navigation_interval_seconds-(time.monotonic()-self._last.get(campaign_id,0))
        if delay>0:time.sleep(delay)
        self._last[campaign_id]=time.monotonic();return page.goto(url,wait_until=wait_until,timeout=self.config.page_timeout_ms)
    def close_campaign(self,cid):
        for k,c in list(self._contexts.items()):
            if k[0]==cid:
                try:c.close()
                except Exception:pass
                self._contexts.pop(k,None)
        for bid,r in list(self._records.items()):
            if r.campaign_id==cid:
                b=self._browsers.pop(bid,None);self._records.pop(bid,None)
                if b:
                    try:b.close()
                    except Exception:pass
        # A crawler owns no browser after its final campaign closes. Stop the
        # sync Playwright driver as well; leaving it alive leaks its greenlet
        # and can make subsequent asyncio-managed tests/runs fail with
        # "Sync API inside the asyncio loop".
        if not self._records and self._pw is not None:
            try:self._pw.stop()
            except Exception:pass
            self._pw=None
    def close_all(self):
        for cid in {r.campaign_id for r in self._records.values()}:self.close_campaign(cid)
        if self._pw:
            try:self._pw.stop()
            except Exception:pass
        self._pw=None;self._closed=True;self._pages.clear()
    def metrics(self)->dict[str,Any]:return {'browsers':len(self._browsers),'contexts':len(self._contexts),'pages':len(self._pages),'closed':self._closed}
    def active_counts(self):return {'browsers':len(self._browsers),'contexts':len(self._contexts),'pages':len(self._pages)}
