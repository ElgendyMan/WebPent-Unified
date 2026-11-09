from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable, Mapping

from webpent.recon.browser_farm import BrowserFarm
from webpent.recon.state_graph import StateGraph


@dataclass(frozen=True)
class AuthEvidence:
    principal_alias:str;success:bool;login_url:str;reason:str='';cookie_count:int=0
    def as_dict(self):return self.__dict__.copy()
class BrowserAuthHandler:
    def __init__(self,*,farm:BrowserFarm,state_graph:StateGraph,credential_provider:Callable[[str],Mapping[str,str]]|None=None,m4_attach=None):self.farm=farm;self.state_graph=state_graph;self.credential_provider=credential_provider;self.m4_attach=m4_attach;self.evidence=[]
    def login(self,*,campaign_id,principal_alias,login_url):
        if principal_alias not in {'owner','foreign','control'}:raise ValueError('unsupported_principal_alias')
        if not self.credential_provider:return AuthEvidence(principal_alias,False,login_url,'m4_credential_provider_not_configured')
        c=dict(self.credential_provider(principal_alias));
        if not c.get('username') or not c.get('password'):return AuthEvidence(principal_alias,False,login_url,'m4_credentials_unavailable')
        p=self.farm.new_page(campaign_id,principal_alias)
        try:
            self.farm.navigate(p,login_url,campaign_id=campaign_id);form=p.locator('form').filter(has=p.locator('input[type=password]')).first
            if form.count()==0:return AuthEvidence(principal_alias,False,login_url,'login_form_not_detected')
            _cookies_before = {ck['name'] for ck in p.context.cookies()}
            form.locator('input[type=password]').fill(c['password']);form.locator('input[type=email],input[name*=user i],input[name*=email i]').first.fill(c['username']);form.locator('button[type=submit],input[type=submit]').first.click();p.wait_for_load_state('domcontentloaded');
            _cookies_after = {ck['name'] for ck in p.context.cookies()}
            _new_cookies = _cookies_after - _cookies_before
            _url_changed = p.url != login_url
            _page_text = ''
            try: _page_text = p.inner_text('body')[:2000].lower()
            except Exception: pass  # P2-09 (0.33.0): bare except also swallowed KeyboardInterrupt/SystemExit
            _no_error = not any(m in _page_text for m in ('invalid','wrong password','failed','incorrect','error','unauthorized'))
            ok = bool(_new_cookies) and _url_changed and _no_error
            if ok and self.m4_attach:self.m4_attach(principal_alias,{'cookie_count':len(p.context.cookies())})
            e=AuthEvidence(principal_alias,ok,login_url,'',len(p.context.cookies()));self.evidence.append(e);return e
        except Exception as e:return AuthEvidence(principal_alias,False,login_url,type(e).__name__)
    def as_dict(self):return {'evidence':[e.as_dict() for e in self.evidence]}
